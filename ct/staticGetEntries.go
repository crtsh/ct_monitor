package ct

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/crtsh/ct_monitor/certwatch"
	"github.com/crtsh/ct_monitor/config"
	"github.com/crtsh/ct_monitor/logger"
	"github.com/crtsh/ct_monitor/msg"

	"filippo.io/sunlight"

	"github.com/google/certificate-transparency-go/x509"

	"go.uber.org/zap"
)

func (ge *getEntries) callStaticGetEntries() {
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

		// Call this log's tile data API.
		tileDataURL, tileStart := determineTileDataURL(logURL, start, end)
		var httpRequest *http.Request
		var httpResponse *http.Response
		var body []byte
		nextEntryNumber := int64(-1)
		var err error
		if httpRequest, err = http.NewRequest(http.MethodGet, tileDataURL, nil); err != nil {
			logger.Logger.Error("http.NewRequest failed", zap.Error(err))
		} else {
			httpRequest.Header.Set("User-Agent", "github.com/crtsh/ct_monitor")
			if httpResponse, err = httpClient.Do(httpRequest); err != nil {
				logger.Logger.Warn("Tile fetch failed", zap.String("tile_data_url", tileDataURL), zap.Error(err))
			} else {
				defer httpResponse.Body.Close()
				if httpResponse.StatusCode != http.StatusOK {
					logger.Logger.Error(fmt.Sprintf("HTTP %d", httpResponse.StatusCode), zap.Error(err), zap.String("logURL", logURL), zap.Int64("start", start), zap.Int64("end", end))
				} else if body, err = io.ReadAll(httpResponse.Body); err != nil {
					logger.Logger.Error("io.ReadAll failed", zap.Error(err), zap.String("logURL", logURL), zap.Int64("start", start), zap.Int64("end", end))
				} else {
					logger.Logger.Debug("New Entries", zap.String("logURL", logURL), zap.Int64("start", start), zap.Int64("end", end))
					nextEntryNumber = ge.processNewStaticEntries(body, start, tileStart, &processedEntries)
				}
			}
		}

		// Check if a retry is needed.
		if nextEntryNumber == end+1 { // Tile data fetch request was successful.
			logger.Logger.Debug("Successful tile data fetch", zap.String("tileDataURL", tileDataURL), zap.Int64("start", start), zap.Int64("end", end))
			break
		} else if nextEntryNumber == -1 { // Tile data fetch request failed.
			logger.Logger.Debug("Failed tile data fetch", zap.String("tileDataURL", tileDataURL), zap.Int64("start", start), zap.Int64("end", end))
		} else if nextEntryNumber <= end { // Tile data fetch request was truncated.
			start = nextEntryNumber
			logger.Logger.Debug("Truncated tile data fetch", zap.String("tileDataURL", tileDataURL), zap.Int64("start", start), zap.Int64("end", end))
		} else { // processNewStaticEntries processed more entries than expected!
			panic("Too many entries found in tile data response!")
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

const TILE_HEIGHT = 8
const ENTRIES_PER_TILE = 1 << TILE_HEIGHT

func determineTileDataURL(logURL string, start, end int64) (string, int64) {
	tileNumber := start / ENTRIES_PER_TILE
	tileStart := tileNumber * ENTRIES_PER_TILE
	if nEntriesToFetch := end + 1 - tileStart; nEntriesToFetch < ENTRIES_PER_TILE {
		return fmt.Sprintf("%s/tile/data/%s.p/%d", logURL, tilePath(tileNumber), nEntriesToFetch), tileStart
	} else {
		return fmt.Sprintf("%s/tile/data/%s", logURL, tilePath(tileNumber)), tileStart
	}
}

func tilePath(tileNumber int64) string {
	const base = 1000
	str := fmt.Sprintf("%03d", tileNumber%base)
	for tileNumber >= base {
		tileNumber = tileNumber / base
		str = fmt.Sprintf("x%03d/%s", tileNumber%base, str)
	}
	return str
}

func (ge *getEntries) processNewStaticEntries(body []byte, start, tileStart int64, processedEntries *[]msg.NewLogEntry) int64 {
	var err error
	var index int64

	// Loop through the entries.
	for index = tileStart; index < tileStart+ENTRIES_PER_TILE; index++ {
		var entry *sunlight.LogEntry
		if entry, body, err = sunlight.ReadTileLeaf(body); err != nil {
			logger.Logger.Error("Could not process entry", zap.Error(err), zap.String("logURL", ctlog[ge.ctLogID].Url), zap.Int64("index", index))
			return index
		} else if index < start {
			logger.Logger.Debug("Skipping previously processed entry", zap.Int64("index", index))
			continue
		} else if entry.LeafIndex != index {
			logger.Logger.Error("Unexpected entry index", zap.String("logURL", ctlog[ge.ctLogID].Url), zap.Int64("index", index), zap.Int64("entry.LeafIndex", entry.LeafIndex))
			return index
		}

		nle := msg.NewLogEntry{
			CtLogID: -1,
		}
		var issuerCert *x509.Certificate
		for i := len(entry.ChainFingerprints) - 1; i >= 0; i-- {
			// Look for the issuer certificate in the in-memory cache; if not found, look in the DB.
			addToCache := false
			nle.DerCert = certwatch.FetchIssuer(entry.ChainFingerprints[i])
			// If still not found, fetch the issuer certificate from the log.
			if nle.DerCert == nil {
				nle.DerCert = getChainCertificate(ctlog[ge.ctLogID].Url, entry.ChainFingerprints[i])
				addToCache = true
			}
			if nle.DerCert == nil {
				logger.Logger.Error("Could not find chain certificate", zap.String("logURL", ctlog[ge.ctLogID].Url), zap.Int64("index", entry.LeafIndex), zap.Time("timestamp", nle.EntryTimestamp))
				return index
			}
			nle.Sha256Cert = sha256.Sum256(nle.DerCert)
			nle.IssuerVerified = false
			if nle.Cert, err = x509.ParseCertificate(nle.DerCert); err != nil {
				logger.Logger.Warn("Could not parse chain certificate", zap.Error(err), zap.String("logURL", ctlog[ge.ctLogID].Url), zap.Int64("index", entry.LeafIndex), zap.Time("timestamp", nle.EntryTimestamp))
				nle.Cert = nil
			} else if issuerCert != nil {
				if nle.Cert.CheckSignatureFrom(issuerCert) == nil {
					// Signature is valid, so pass the parent certificate's SHA-256 hash.
					nle.Sha256IssuerCert = sha256.Sum256(issuerCert.Raw)
					nle.IssuerVerified = true
				}
			}

			// If getChainCertificate was called, then cache this issuer certificate.
			if addToCache {
				var issuer certwatch.CachedIssuer
				issuer.Cert = nle.Cert
				certwatch.SetCachedIssuer(issuer, nle.Sha256Cert)
			}

			// This CA certificate is ready to be sent to the newEntriesWriter.
			*processedEntries = append(*processedEntries, nle)

			issuerCert = nle.Cert
		}

		// Process the certificate or precertificate entry.
		nle.CtLogID = ge.ctLogID
		nle.EntryID = entry.LeafIndex
		nle.EntryTimestamp = time.UnixMilli(entry.Timestamp).UTC()
		if entry.IsPrecert {
			nle.DerCert = entry.PreCertificate
		} else {
			nle.DerCert = entry.Certificate
		}
		nle.Sha256Cert = sha256.Sum256(nle.DerCert)
		nle.IssuerVerified = false
		if nle.Cert, err = x509.ParseCertificate(nle.DerCert); err != nil {
			logger.Logger.Warn("Could not parse certificate", zap.Error(err), zap.String("logURL", ctlog[ge.ctLogID].Url), zap.Int64("index", nle.EntryID), zap.Time("timestamp", nle.EntryTimestamp))
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
	}

	return index
}

func getChainCertificate(logUrl string, sha256ChainCert [32]byte) []byte {
	var httpRequest *http.Request
	var httpResponse *http.Response
	var err error

	issuerURL := fmt.Sprintf("%s/issuer/%s", logUrl, hex.EncodeToString(sha256ChainCert[:]))
	if httpRequest, err = http.NewRequest(http.MethodGet, issuerURL, nil); err != nil {
		logger.Logger.Error("http.NewRequest failed", zap.Error(err))
	} else {
		httpRequest.Header.Set("User-Agent", "github.com/crtsh/ct_monitor")
		if httpResponse, err = httpClient.Do(httpRequest); err != nil {
			logger.Logger.Warn("Chain certificate fetch failed", zap.Error(err), zap.String("url", issuerURL))
		} else {
			defer httpResponse.Body.Close()
			var body []byte
			if httpResponse.StatusCode != http.StatusOK {
				logger.Logger.Error(fmt.Sprintf("HTTP %d", httpResponse.StatusCode), zap.Error(err), zap.String("url", issuerURL))
			} else if ct := strings.SplitN(httpResponse.Header.Get("Content-Type"), ";", 2)[0]; ct != "application/pkix-cert" && ct != "application/octet-stream" {
				logger.Logger.Error("Unexpected Content-Type", zap.String("wanted", "application/pkix-cert"), zap.String("got", ct))
			} else if body, err = io.ReadAll(httpResponse.Body); err != nil {
				logger.Logger.Error("io.ReadAll failed", zap.Error(err), zap.String("url", issuerURL))
			} else {
				logger.Logger.Debug("Chain certificate fetched", zap.Error(err), zap.String("url", issuerURL))
				return body
			}
		}
	}

	return nil
}
