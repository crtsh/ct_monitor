package ct

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/crtsh/ct_monitor/config"
	"github.com/crtsh/ct_monitor/logger"
	"github.com/crtsh/ct_monitor/msg"
)

type getEntries struct {
	ctx            context.Context
	ctLogID        int
	start          int64
	end            int64
	chan_serialize chan struct{}
}

// getEntriesWG tracks all in-flight callRFC6962GetEntries /
// callStaticGetEntries goroutines so that GetEntriesLauncher can wait for
// them to finish before signalling shutdown.  Without this, child goroutines
// can still be mid-call on pgx connections (notably connIssuerFetcher via
// certwatch.FetchIssuer) when certwatch.Close() runs, which trips pgconn's
// "slow write timer already active" assertion.
var getEntriesWG sync.WaitGroup

func GetEntriesLauncher(ctx context.Context) {
	logger.Logger.Info("Started GetEntriesLauncher")

	for {
		select {
		// Launch get-entries calls as required, then fire a timer when it's time to do it again.
		case <-time.After(launchGetEntries(ctx)):
		// Respond to graceful shutdown requests.
		case <-ctx.Done():
			// Wait for all in-flight child goroutines to exit before signalling
			// shutdown, so that certwatch.Close() can close pgx connections
			// without racing in-flight DB calls.
			getEntriesWG.Wait()
			msg.ShutdownWG.Done()
			logger.Logger.Info("Stopped GetEntriesLauncher")
			return
		}
	}
}

func launchGetEntries(ctx context.Context) time.Duration {
	syncMutex.Lock()
	for id, ctl := range ctlog {
		if ctl.isActive && !ctl.isTestLog {
			for j := len(ctl.getEntries); j < ctl.RequestsConcurrent && (ctl.latestQueuedEntryID < (ctl.TreeSize - 1)); j++ {
				// Prepare a new get-entries call.
				ge := getEntries{
					ctx:            ctx,
					ctLogID:        id,
					start:          ctl.latestQueuedEntryID + 1,
					end:            ctl.latestQueuedEntryID + ctl.BatchSize, // ctl.BatchSize is hard-coded to 256 for Static logs.
					chan_serialize: make(chan struct{}, 1),
				}
				if ge.end%ctl.BatchSize != ctl.BatchSize-1 {
					ge.end -= (ge.end%ctl.BatchSize + 1)
					if ge.end-ge.start <= 0 {
						ge.end += ctl.BatchSize
					}
				}
				if ge.end > ctl.TreeSize-1 {
					ge.end = ctl.TreeSize - 1
				}
				ctl.getEntries[ge.start] = &ge
				ctl.latestQueuedEntryID = ge.end

				// Signal the first get-entries goroutine to proceed to entry writing.
				if !ctl.anyQueuedYet {
					ctl.anyQueuedYet = true // Each subsequent get-entries goroutine will need to wait to be signaled by the preceding one.
					ge.chan_serialize <- struct{}{}
				}
				getEntriesWG.Add(1)
				if ctl.Type == "static" || strings.Contains(ctl.Url, "trustasia.com/log2026") {
					go ge.callStaticGetEntries()
				} else {
					go ge.callRFC6962GetEntries()
				}
			}
		}
	}
	syncMutex.Unlock()

	return config.Config.CTLogs.GetEntriesLauncherFrequency
}

// ctxSleep sleeps for d or until ctx is canceled.  It returns true if the
// full duration elapsed, false if ctx was canceled first.
func ctxSleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
