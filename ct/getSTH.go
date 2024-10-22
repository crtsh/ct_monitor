package ct

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/crtsh/ct_monitor/config"
	"github.com/crtsh/ct_monitor/logger"

	"filippo.io/sunlight"

	json "github.com/goccy/go-json"
	ctgo "github.com/google/certificate-transparency-go"

	"go.uber.org/zap"

	"golang.org/x/mod/sumdb/note"
)

var httpClient http.Client

func init() {
	httpClient = http.Client{Timeout: config.Config.CTLogs.HTTPTimeout}
}

func GetSTHs() []Log {
	// Concurrently call each log's get-sth (RFC6962) or checkpoint (Static) endpoint.
	ch := make(chan Log, len(ctlog)) // Needs to be large enough to not block.
	var wg sync.WaitGroup
	wg.Add(len(ctlog))
	syncMutex.RLock()
	for i := range ctlog {
		go func(i int) {
			defer wg.Done()
			if updatedLog := getSTH(i); updatedLog.Id != -1 { // -1=Unchanged.
				ch <- updatedLog
			}
		}(i)
	}
	syncMutex.RUnlock()
	wg.Wait()
	close(ch)

	// Return details of new STHs.
	var updated []Log
	for ctl := range ch {
		updated = append(updated, ctl)
	}
	return updated
}

func getSTH(i int) Log {
	// Get relevant log details, and apply HTTP request rate-limiting.
	syncMutex.RLock()
	if ctlog[i] == nil {
		panic(fmt.Errorf("ctlog[%d] unexpectedly nil", i))
	} else if !ctlog[i].isActive {
		syncMutex.RUnlock()
		return Log{Id: -1} // No DB update required, so return a dummy record.
	}
	logURL := ctlog[i].Url
	logType := ctlog[i].Type
	latestSTHTimestamp := ctlog[i].LatestSTHTimestamp
	if ctlog[i].rateLimiter != nil {
		<-ctlog[i].rateLimiter.C
	}
	syncMutex.RUnlock()

	if logType == "rfc6962" {
		// Call this RFC6962 log's /ct/v1/get-sth API.
		if httpRequest, err := http.NewRequest(http.MethodGet, logURL+"/ct/v1/get-sth", nil); err != nil {
			logger.Logger.Error("http.NewRequest failed", zap.Error(err))
		} else {
			httpRequest.Header.Set("User-Agent", "github.com/crtsh/ct_monitor")
			var httpResponse *http.Response
			if httpResponse, err = httpClient.Do(httpRequest); err != nil {
				logger.Logger.Error("httpClient.Do failed", zap.Error(err))
			} else {
				defer httpResponse.Body.Close()
				var body []byte
				var getSTH ctgo.GetSTHResponse
				if body, err = io.ReadAll(httpResponse.Body); err != nil {
					logger.Logger.Error("io.ReadAll failed", zap.Error(err))
				} else if httpResponse.StatusCode != http.StatusOK {
					logger.Logger.Error(fmt.Sprintf("HTTP %d", httpResponse.StatusCode), zap.Error(err))
				} else if err = json.Unmarshal(body, &getSTH); err != nil {
					logger.Logger.Error("json.Unmarshal failed", zap.Error(err))
				} else {
					// Report if this STH is newer than the previous STH we observed.
					var thisSTHTimestamp time.Time
					if thisSTHTimestamp = time.Unix(0, int64(getSTH.Timestamp)*int64(time.Millisecond)).UTC(); thisSTHTimestamp.After(latestSTHTimestamp) {
						logger.Logger.Info(
							"New STH",
							zap.String("logURL", logURL),
							zap.Time("sthTimestamp", thisSTHTimestamp),
							zap.Uint64("treeSize", getSTH.TreeSize),
						)
					}

					var sth *ctgo.SignedTreeHead
					if sth, err = getSTH.ToSignedTreeHead(); err != nil {
						logger.Logger.Error(
							"ToSignedTreeHead failed",
						)
					}

					// Copy the updated get-sth details.
					syncMutex.Lock()
					updatedLog := ctlog[i]
					if updatedLog == nil {
						panic(fmt.Errorf("ctlog[%d] unexpectedly nil", i))
					}
					if thisSTHTimestamp.After(updatedLog.LatestSTHTimestamp) { // Only update these fields if this STH is newer than the latest STH we've previously observed.
						updatedLog.TreeSize = int64(getSTH.TreeSize)
						updatedLog.LatestSTHTimestamp = thisSTHTimestamp
					}
					updatedLog.LatestUpdate = time.Now().UTC() // We update this field every time we successfully complete a get-sth call.
					// Verify STH signature.
					if err = updatedLog.SigVer.VerifySTHSignature(*sth); err != nil {
						logger.Logger.Error(
							"Invalid STH Signature",
							zap.String("logURL", logURL),
							zap.Time("sthTimestamp", thisSTHTimestamp),
							zap.Uint64("treeSize", getSTH.TreeSize),
						)
					} else if time.Since(thisSTHTimestamp) > (time.Duration(updatedLog.MMDInSeconds) * time.Second) {
						logger.Logger.Error(
							"STH Timestamp older than MMD",
							zap.String("logURL", logURL),
							zap.Time("sthTimestamp", thisSTHTimestamp),
							zap.Uint64("treeSize", getSTH.TreeSize),
						)
					}
					ctlog[i] = updatedLog
					syncMutex.Unlock()

					// TODO: If the STH signature is invalid, or its timestamp has exceeded the log's MMD, record this in a logging table.

					return *updatedLog
				}
			}
		}

	} else if logType == "static" {
		// Call this Static log's /checkpoint API.
		if httpRequest, err := http.NewRequest(http.MethodGet, logURL+"/checkpoint", nil); err != nil {
			logger.Logger.Error("http.NewRequest failed", zap.Error(err))
		} else {
			httpRequest.Header.Set("User-Agent", "github.com/crtsh/ct_monitor")
			var httpResponse *http.Response
			if httpResponse, err = httpClient.Do(httpRequest); err != nil {
				logger.Logger.Error("httpClient.Do failed", zap.Error(err))
			} else {
				defer httpResponse.Body.Close()
				var body []byte
				if body, err = io.ReadAll(httpResponse.Body); err != nil {
					logger.Logger.Error("io.ReadAll failed", zap.Error(err))
				} else if httpResponse.StatusCode != http.StatusOK {
					logger.Logger.Error(fmt.Sprintf("HTTP %d", httpResponse.StatusCode), zap.Error(err))
				} else {
					// Copy the updated checkpoint details.
					syncMutex.Lock()
					updatedLog := ctlog[i]
					if updatedLog == nil {
						panic(fmt.Errorf("ctlog[%d] unexpectedly nil", i))
					} else if n, err := note.Open(body, ctlog[i].NoteVerifiers); err != nil {
						logger.Logger.Error("note.Open failed", zap.Error(err))
					} else if len(n.Sigs) < 1 {
						logger.Logger.Error("No verified STH note signatures")
					} else if checkpoint, err := sunlight.ParseCheckpoint(n.Text); err != nil {
						logger.Logger.Error("sunlight.ParseCheckpoint failed", zap.Error(err))
					} else if checkpoint.Origin != ctlog[i].KeyName {
						logger.Logger.Error("Unexpected checkpoint origin")
					} else if decodedSig, err := base64.StdEncoding.DecodeString(n.Sigs[0].Base64); err != nil {
						logger.Logger.Error("base64.StdEncoding.DecodeString failed", zap.Error(err))
					} else {
						thisSTHTimestamp := time.Unix(0, int64(binary.BigEndian.Uint64(decodedSig[4:12]))*int64(time.Millisecond)).UTC()
						if thisSTHTimestamp.After(latestSTHTimestamp) {
							logger.Logger.Info(
								"New STH",
								zap.String("logURL", logURL),
								zap.Time("sthTimestamp", thisSTHTimestamp),
								zap.Int64("treeSize", checkpoint.N),
							)
							updatedLog.TreeSize = checkpoint.N
							updatedLog.LatestSTHTimestamp = thisSTHTimestamp
						}
						updatedLog.LatestUpdate = time.Now().UTC() // We update this field every time we successfully complete a checkpoint call.
						if time.Since(thisSTHTimestamp) > (time.Duration(updatedLog.MMDInSeconds) * time.Second) {
							logger.Logger.Error(
								"STH Timestamp older than MMD",
								zap.String("logURL", logURL),
								zap.Time("sthTimestamp", thisSTHTimestamp),
								zap.Int64("treeSize", checkpoint.N),
							)
						}
					}
					ctlog[i] = updatedLog
					syncMutex.Unlock()

					// TODO: If the STH signature is invalid, or its timestamp has exceeded the log's MMD, record this in a logging table.

					return *updatedLog
				}
			}
		}
	}

	return Log{Id: -1} // No DB update required, so return a dummy record.
}
