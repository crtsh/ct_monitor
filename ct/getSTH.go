package ct

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/crtsh/ct_monitor/config"
	"github.com/crtsh/ct_monitor/logger"

	json "github.com/goccy/go-json"
	ctgo "github.com/google/certificate-transparency-go"

	"go.uber.org/zap"

)

var httpClient http.Client

func init() {
	httpClient = http.Client{Timeout: config.Config.CTLogs.HTTPTimeout}
}

func GetSTHs() []Log {
	// Concurrently call each log's get-sth endpoint.
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
	latestSTHTimestamp := ctlog[i].LatestSTHTimestamp
	if ctlog[i].rateLimiter != nil {
		<-ctlog[i].rateLimiter.C
	}
	syncMutex.RUnlock()

	// Call this log's /ct/v1/get-sth API.
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
			} else if thisSTHTimestamp := time.Unix(0, int64(getSTH.Timestamp)*int64(time.Millisecond)).UTC(); thisSTHTimestamp.After(latestSTHTimestamp) {
				logger.Logger.Info(
					"New STH",
					zap.String("logURL", logURL),
					zap.Time("sthTimestamp", thisSTHTimestamp),
					zap.Uint64("treeSize", getSTH.TreeSize),
				)
				// Copy the updated get-sth details.
				syncMutex.Lock()
				updatedLog := ctlog[i]
				if updatedLog == nil {
					panic(fmt.Errorf("ctlog[%d] unexpectedly nil", i))
				}
				updatedLog.TreeSize = int64(getSTH.TreeSize)
				updatedLog.LatestSTHTimestamp = thisSTHTimestamp
				updatedLog.LatestUpdate = time.Now().UTC()
				ctlog[i] = updatedLog
				syncMutex.Unlock()

				// TODO: Verify STH signature.
				// TODO: If the STH signature is invalid, or its timestamp has exceeded the log's MMD, record this in a logging table.

				return *updatedLog
			}
		}
	}

	return Log{Id: -1} // No DB update required, so return a dummy record.
}
