package ct

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/crtsh/ct_monitor/config"
	"github.com/crtsh/ct_monitor/logger"
	"github.com/crtsh/ct_monitor/msg"

	json "github.com/goccy/go-json"
	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"

	"go.uber.org/zap"
)

type getEntries struct {
	ctLogID        int
	start          int64
	end            int64
	chan_serialize chan struct{}
}

func (ge *getEntries) callGetEntries() {
	// Get relevant log details.
	syncMutex.RLock()
	if ctlog[ge.ctLogID] == nil {
		panic(fmt.Errorf("ctlog[%d] unexpectedly nil", ge.ctLogID))
	}
	logURL := ctlog[ge.ctLogID].Url
	start := ge.start
	end := ge.end
	chan_serialize := ge.chan_serialize
	syncMutex.RUnlock()

	var processedEntries []msg.NewLogEntry
	for retry := true; retry; {
		// Apply HTTP request rate-limiting.
		syncMutex.RLock()
		tt := ctlog[ge.ctLogID].rateLimiter
		syncMutex.RUnlock()
		if tt != nil {
			<-tt.C
		}

		// Call this log's /ct/v1/get-entries API.
		getEntriesURL := fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", logURL, start, end)
		var httpRequest *http.Request
		var httpResponse *http.Response
		var body []byte
		nextEntryNumber := int64(-1)
		var err error
		if httpRequest, err = http.NewRequest(http.MethodGet, getEntriesURL, nil); err != nil {
			logger.Logger.Error("http.NewRequest failed", zap.Error(err))
		} else {
			httpRequest.Header.Set("User-Agent", "github.com/crtsh/ct_monitor")
			if httpResponse, err = httpClient.Do(httpRequest); err != nil {
				logger.Logger.Error("httpClient.Do failed", zap.Error(err))
			} else {
				defer httpResponse.Body.Close()
				if httpResponse.StatusCode != http.StatusOK {
					logger.Logger.Error(fmt.Sprintf("HTTP %d", httpResponse.StatusCode), zap.Error(err), zap.String("logURL", logURL), zap.Int64("start", start), zap.Int64("end", end))
				} else if body, err = io.ReadAll(httpResponse.Body); err != nil {
					logger.Logger.Error("io.ReadAll failed", zap.Error(err), zap.String("logURL", logURL), zap.Int64("start", start), zap.Int64("end", end))
				} else {
					logger.Logger.Debug("New Entries", zap.String("logURL", logURL), zap.Int64("start", start), zap.Int64("end", end))
					nextEntryNumber = ge.processNewEntries(body, start, &processedEntries)
				}
			}
		}

		// Check if a retry is needed.
		if nextEntryNumber == end+1 { // get-entries request was successful.
			logger.Logger.Debug("Successful get-entries", zap.String("logURL", logURL), zap.Int64("start", start), zap.Int64("end", end))
			retry = false
		} else if nextEntryNumber == -1 { // get-entries request failed.
			logger.Logger.Debug("Failed get-entries", zap.String("logURL", logURL), zap.Int64("start", start), zap.Int64("end", end))
		} else if nextEntryNumber <= end { // get-entries request was truncated.
			start = nextEntryNumber
			logger.Logger.Debug("Truncated get-entries", zap.String("logURL", logURL), zap.Int64("start", start), zap.Int64("end", end))
		} else { // processNewEntries processed more entries than expected!
			panic("Too many entries found in get-entries response!")
		}
	}

	// Wait for serialized access, then write the newly processed entries to the newEntryWriter.
	<-chan_serialize
	for _, entry := range processedEntries {
		msg.WriterChan <- entry
	}

	// Signal the next get-entries call to proceed with serialized access.
	for {
		syncMutex.RLock()
		if geNext := ctlog[ge.ctLogID].getEntries[end+1]; geNext != nil {
			geNext.chan_serialize <- struct{}{}
			syncMutex.RUnlock()
			break
		} else if !ctlog[ge.ctLogID].isActive && len(ctlog[ge.ctLogID].getEntries) == 1 {
			// This is the last goroutine for a log that has just been deactivated, so we don't need to signal another get-entries call.
			syncMutex.RUnlock()
			break
		} else { // Next get-entries call not yet launched, so wait then retry.
			syncMutex.RUnlock()
			time.Sleep(config.Config.CTLogs.GetEntriesLauncherFrequency)
		}
	}

	// Remove this get-entries call from the map, so that further get-entries calls can be launched.
	syncMutex.Lock()
	delete(ctlog[ge.ctLogID].getEntries, ge.start)
	syncMutex.Unlock()
}

func isPrecertificate(cert *x509.Certificate, entry_type ctgo.LogEntryType) bool {
	if cert != nil {
		for _, ext := range cert.Extensions {
			if x509.OIDExtensionCTPoison.Equal(ext.Id) && ext.Critical {
				return true // Precertificate.
			}
		}
	} else if entry_type == ctgo.PrecertLogEntryType {
		return true // Precertificate.  (We can't parse it, so we have to assume that the log entry type is correct).
	}

	return false
}

func (ge *getEntries) processNewEntries(body []byte, start int64, processedEntries *[]msg.NewLogEntry) int64 {
	var getEntries ctgo.GetEntriesResponse
	var err error
	index := start

	if err = json.Unmarshal(body, &getEntries); err != nil {
		logger.Logger.Error("json.Unmarshal failed", zap.Error(err))
		return index
	}

	// Loop through the entries.
	for _, entry := range getEntries.Entries {
		// Construct log entry structure.
		rle, err := ctgo.RawLogEntryFromLeaf(index, &entry)
		if err != nil {
			logger.Logger.Error("Could not process entry", zap.Error(err), zap.String("logURL", ctlog[ge.ctLogID].Url), zap.Int64("index", index))
			return index
		}

		nle := msg.NewLogEntry{
			CtLogID: -1,
		}
		var issuerCert *x509.Certificate
		var cert *x509.Certificate
		for i := len(rle.Chain) - 1; i >= 0; i-- {
			nle.IssuerVerified = false
			nle.DerCert = rle.Chain[i].Data
			cert, err = x509.ParseCertificate(nle.DerCert)
			if err != nil {
				logger.Logger.Warn("Could not parse certificate", zap.Error(err), zap.String("logURL", ctlog[ge.ctLogID].Url), zap.Int64("index", rle.Index), zap.Time("timestamp", ctgo.TimestampToTime(rle.Leaf.TimestampedEntry.Timestamp)))
				cert = nil
			} else if issuerCert != nil {
				if cert.CheckSignatureFrom(issuerCert) == nil {
					// Signature is valid, so pass the parent certificate's SHA-256 hash.
					nle.Sha256IssuerCert = sha256.Sum256(issuerCert.Raw)
					nle.IssuerVerified = true
				}
			}

			nle.Sha256Cert = sha256.Sum256(nle.DerCert)
			nle.IsPrecertificate = isPrecertificate(cert, ctgo.X509LogEntryType)

			// This CA certificate is ready to be sent to the newEntriesWriter.
			*processedEntries = append(*processedEntries, nle)

			issuerCert = cert
		}

		// Process the certificate or precertificate entry.
		nle.CtLogID = ge.ctLogID
		nle.IssuerVerified = false
		nle.EntryID = rle.Index
		nle.EntryTimestamp = ctgo.TimestampToTime(rle.Leaf.TimestampedEntry.Timestamp)
		switch entryType := rle.Leaf.TimestampedEntry.EntryType; entryType {
		case ctgo.X509LogEntryType:
			nle.DerCert = rle.Leaf.TimestampedEntry.X509Entry.Data
		case ctgo.PrecertLogEntryType:
			nle.DerCert = rle.Cert.Data
		default:
			logger.Logger.Error("Unknown entry type", zap.String("logURL", ctlog[ge.ctLogID].Url), zap.Int64("index", rle.Index), zap.Uint64("entryType", uint64(entryType)))
			return index
		}

		cert, err = x509.ParseCertificate(nle.DerCert)
		if err != nil {
			logger.Logger.Warn("Could not parse certificate", zap.Error(err), zap.String("logURL", ctlog[ge.ctLogID].Url), zap.Int64("index", rle.Index), zap.Time("timestamp", nle.EntryTimestamp))
			cert = nil
		}

		nle.Sha256Cert = sha256.Sum256(nle.DerCert)
		nle.IsPrecertificate = isPrecertificate(cert, rle.Leaf.TimestampedEntry.EntryType)

		// Verify the certificate or precertificate's signature, if possible.
		if (cert != nil) && (issuerCert != nil) {
			if cert.CheckSignatureFrom(issuerCert) == nil {
				// Signature is valid, so pass the parent certificate's SHA-256 hash.
				nle.Sha256IssuerCert = sha256.Sum256(issuerCert.Raw)
				nle.IssuerVerified = true
			}
		}

		// TODO: Verify SCT signature.

		// This certificate or precertificate entry is ready to be sent to the newEntryWriter.
		*processedEntries = append(*processedEntries, nle)

		// Move to the next entry.
		index++
	}

	return index
}
