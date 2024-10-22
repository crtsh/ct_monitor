package ct

import (
	"context"
	"time"

	"github.com/crtsh/ct_monitor/config"
	"github.com/crtsh/ct_monitor/logger"
	"github.com/crtsh/ct_monitor/msg"
)

type getEntries struct {
	ctLogID        int
	start          int64
	end            int64
	chan_serialize chan struct{}
}

func GetEntriesLauncher(ctx context.Context) {
	logger.Logger.Info("Started GetEntriesLauncher")

	for {
		select {
		// Launch get-entries calls as required, then fire a timer when it's time to do it again.
		case <-time.After(launchGetEntries()):
		// Respond to graceful shutdown requests.
		case <-ctx.Done():
			msg.ShutdownWG.Done()
			logger.Logger.Info("Stopped GetEntriesLauncher")
			return
		}
	}
}

func launchGetEntries() time.Duration {
	syncMutex.Lock()
	for id, ctl := range ctlog {
		if ctl.isActive {
			for j := len(ctl.getEntries); j < ctl.RequestsConcurrent && (ctl.latestQueuedEntryID < (ctl.TreeSize - 1)); j++ {
				// Prepare a new get-entries call.
				ge := getEntries{
					ctLogID:        id,
					start:          ctl.latestQueuedEntryID + 1,
					end:            ctl.latestQueuedEntryID + ctl.BatchSize,
					chan_serialize: make(chan struct{}, 1),
				}
				if ctl.Type == "static" && (ge.end%ENTRIES_PER_TILE != ENTRIES_PER_TILE-1) {
					ge.end -= (ge.end%ENTRIES_PER_TILE + 1)
					if ge.end-ge.start <= 0 {
						ge.end += ENTRIES_PER_TILE
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
				if ctl.Type == "rfc6962" {
					go ge.callRFC6962GetEntries()
				} else if ctl.Type == "static" {
					go ge.callStaticGetEntries()
				}
			}
		}
	}
	syncMutex.Unlock()

	return config.Config.CTLogs.GetEntriesLauncherFrequency
}
