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

func (ge *getEntries) callRFC6962GetEntries() {
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
	for {
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
					nextEntryNumber = ge.processNewRFC6962Entries(body, start, &processedEntries)
				}
			}
		}

		// Check if a retry is needed.
		if nextEntryNumber == end+1 { // get-entries request was successful.
			logger.Logger.Debug("Successful get-entries", zap.String("logURL", logURL), zap.Int64("start", start), zap.Int64("end", end))
			break
		} else if nextEntryNumber == -1 { // get-entries request failed.
			logger.Logger.Debug("Failed get-entries", zap.String("logURL", logURL), zap.Int64("start", start), zap.Int64("end", end))
		} else if nextEntryNumber <= end { // get-entries request was truncated.
			start = nextEntryNumber
			logger.Logger.Debug("Truncated get-entries", zap.String("logURL", logURL), zap.Int64("start", start), zap.Int64("end", end), zap.Int64("next", nextEntryNumber))
		} else { // processNewRFC6962Entries processed more entries than expected!
			panic("Too many entries found in get-entries response!")
		}

		time.Sleep(10 * time.Second) // Wait 10s before retrying.
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

func (ge *getEntries) processNewRFC6962Entries(body []byte, start int64, processedEntries *[]msg.NewLogEntry) int64 {
	var ger ctgo.GetEntriesResponse
	var err error
	index := start

	if err = json.Unmarshal(body, &ger); err != nil {
		logger.Logger.Error("json.Unmarshal failed", zap.Error(err))
		return index
	}

	// Loop through the entries.
	for _, entry := range ger.Entries {
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
		for i := len(rle.Chain) - 1; i >= 0; i-- {
			nle.DerCert = rle.Chain[i].Data
			nle.Sha256Cert = sha256.Sum256(nle.DerCert)
			nle.IssuerVerified = false
			if nle.Cert, err = x509.ParseCertificate(nle.DerCert); err != nil {
				logger.Logger.Warn("Could not parse chain certificate", zap.Error(err), zap.String("logURL", ctlog[ge.ctLogID].Url), zap.Int64("index", rle.Index), zap.Time("timestamp", ctgo.TimestampToTime(rle.Leaf.TimestampedEntry.Timestamp).UTC()))
				nle.Cert = nil
			} else if issuerCert != nil {
				if nle.Cert.CheckSignatureFrom(issuerCert) == nil {
					// Signature is valid, so pass the parent certificate's SHA-256 hash.
					nle.Sha256IssuerCert = sha256.Sum256(issuerCert.Raw)
					nle.IssuerVerified = true
				}
			}

			// This CA certificate is ready to be sent to the newEntriesWriter.
			*processedEntries = append(*processedEntries, nle)

			issuerCert = nle.Cert
		}

		// Process the certificate or precertificate entry.
		nle.CtLogID = ge.ctLogID
		nle.EntryID = rle.Index
		nle.EntryTimestamp = ctgo.TimestampToTime(rle.Leaf.TimestampedEntry.Timestamp).UTC()
		switch entryType := rle.Leaf.TimestampedEntry.EntryType; entryType {
		case ctgo.X509LogEntryType:
			nle.DerCert = rle.Leaf.TimestampedEntry.X509Entry.Data
		case ctgo.PrecertLogEntryType:
			nle.DerCert = rle.Cert.Data
		default:
			logger.Logger.Error("Unknown entry type", zap.String("logURL", ctlog[ge.ctLogID].Url), zap.Int64("index", rle.Index), zap.Uint64("entryType", uint64(entryType)))
			return index
		}
		nle.Sha256Cert = sha256.Sum256(nle.DerCert)
		nle.IssuerVerified = false
		if nle.Cert, err = x509.ParseCertificate(nle.DerCert); err != nil {
			logger.Logger.Warn("Could not parse certificate", zap.Error(err), zap.String("logURL", ctlog[ge.ctLogID].Url), zap.Int64("index", rle.Index), zap.Time("timestamp", nle.EntryTimestamp))
			nle.Cert = nil
		} else if issuerCert != nil {
			if nle.Cert.CheckSignatureFrom(issuerCert) == nil {
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
