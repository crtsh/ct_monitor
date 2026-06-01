package ct

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
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
var httpClientNoKeepAlive http.Client

func init() {
	// The default http.Transport caps idle keepalive connections at 2 per host,
	// which forces a fresh TCP+TLS handshake for nearly every get-entries call
	// when RequestsConcurrent for a log is larger than 2.  Build a tuned
	// transport so that get-entries workers can reuse connections and (where
	// the server supports it) multiplex over HTTP/2.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns = 0         // unlimited total idle conns
	tr.MaxIdleConnsPerHost = 64 // generous keepalive pool per log host
	tr.MaxConnsPerHost = 0      // don't cap in-flight conns at the transport layer
	tr.IdleConnTimeout = 90 * time.Second
	tr.ForceAttemptHTTP2 = true

	httpClient = http.Client{
		Timeout:   config.Config.CTLogs.HTTPTimeout,
		Transport: tr,
	}

	trNoKeepAlive := http.DefaultTransport.(*http.Transport).Clone()
	trNoKeepAlive.DisableKeepAlives = true
	trNoKeepAlive.ForceAttemptHTTP2 = true

	httpClientNoKeepAlive = http.Client{
		Timeout:   config.Config.CTLogs.HTTPTimeout,
		Transport: trNoKeepAlive,
	}
}

func httpClientForURL(url string) *http.Client {
	if strings.Contains(url, "digicert") {
		return &httpClientNoKeepAlive
	}
	return &httpClient
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

	switch logType {
	case "rfc6962":
		// Call this RFC6962 log's /ct/v1/get-sth API.
		if httpRequest, err := http.NewRequest(http.MethodGet, logURL+"/ct/v1/get-sth", nil); err != nil {
			logger.Logger.Error("http.NewRequest failed", zap.Error(err))
		} else {
			httpRequest.Header.Set("User-Agent", "github.com/crtsh/ct_monitor")
			var httpResponse *http.Response
			if httpResponse, err = httpClientForURL(logURL).Do(httpRequest); err != nil {
				logger.Logger.Warn("httpClient.Do failed", zap.Error(err))
			} else {
				defer httpResponse.Body.Close()
				var body []byte
				var getSTH ctgo.GetSTHResponse
				if body, err = io.ReadAll(httpResponse.Body); err != nil {
					logger.Logger.Warn("io.ReadAll failed", zap.Error(err))
				} else if httpResponse.StatusCode != http.StatusOK {
					logger.Logger.Warn(fmt.Sprintf("HTTP %d", httpResponse.StatusCode), zap.Error(err))
				} else if err = json.Unmarshal(body, &getSTH); err != nil {
					logger.Logger.Warn("json.Unmarshal failed", zap.Error(err))
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
						logger.Logger.Warn(
							"ToSignedTreeHead failed",
							zap.Error(err),
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
						logger.Logger.Warn(
							"Invalid STH Signature",
							zap.String("logURL", logURL),
							zap.Time("sthTimestamp", thisSTHTimestamp),
							zap.Uint64("treeSize", getSTH.TreeSize),
							zap.Error(err),
						)
					} else if time.Since(thisSTHTimestamp) > (time.Duration(updatedLog.MMDInSeconds) * time.Second) {
						logger.Logger.Warn(
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

	case "static":
		// Call this Static log's /checkpoint API.
		if httpRequest, err := http.NewRequest(http.MethodGet, logURL+"/checkpoint", nil); err != nil {
			logger.Logger.Error("http.NewRequest failed", zap.Error(err))
		} else {
			httpRequest.Header.Set("User-Agent", "github.com/crtsh/ct_monitor")
			var httpResponse *http.Response
			if httpResponse, err = httpClientForURL(logURL).Do(httpRequest); err != nil {
				logger.Logger.Warn("httpClient.Do failed", zap.Error(err))
			} else {
				defer httpResponse.Body.Close()
				var body []byte
				if body, err = io.ReadAll(httpResponse.Body); err != nil {
					logger.Logger.Warn("io.ReadAll failed", zap.Error(err))
				} else if httpResponse.StatusCode != http.StatusOK {
					logger.Logger.Warn(fmt.Sprintf("HTTP %d", httpResponse.StatusCode), zap.Error(err))
				} else {
					// Copy the updated checkpoint details.
					syncMutex.Lock()
					updatedLog := ctlog[i]
					if updatedLog == nil {
						panic(fmt.Errorf("ctlog[%d] unexpectedly nil", i))
					} else if n, err := note.Open(body, ctlog[i].NoteVerifiers); err != nil {
						logger.Logger.Warn("note.Open failed", zap.Error(err))
					} else if len(n.Sigs) < 1 {
						logger.Logger.Warn("No verified STH note signatures")
					} else if checkpoint, err := sunlight.ParseCheckpoint(n.Text); err != nil {
						logger.Logger.Warn("sunlight.ParseCheckpoint failed", zap.Error(err))
					} else if checkpoint.Origin != ctlog[i].KeyName {
						logger.Logger.Warn("Unexpected checkpoint origin")
					} else if decodedSig, err := base64.StdEncoding.DecodeString(n.Sigs[0].Base64); err != nil {
						logger.Logger.Warn("base64.StdEncoding.DecodeString failed", zap.Error(err))
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
							logger.Logger.Warn(
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
