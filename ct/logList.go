package ct

import (
	"bytes"
	"sync"
	"time"
)

type Log struct {
	Id                  int
	PublicKey           []byte
	Url                 string
	BatchSize           int64
	RequestsPerMinute   int
	RequestsConcurrent  int
	TreeSize            int64
	LatestSTHTimestamp  time.Time
	LatestUpdate        time.Time
	rateLimiter         *time.Ticker
	anyQueuedYet        bool
	latestQueuedEntryID int64
	LatestStoredEntryID int64
	getEntries          map[int64]*getEntries
	isActive            bool
}

var ctlog map[int]*Log
var syncMutex sync.RWMutex

func init() {
	ctlog = make(map[int]*Log)
}

func UpdateLogList(newctlog map[int]*Log) {
	syncMutex.Lock()

	// If any logs have been deactivated on the DB, deactivate them, then delete them from the map after any outstanding get-entries calls have completed.
	for i, ctl := range ctlog {
		if newctlog[i] == nil || !bytes.Equal(newctlog[i].PublicKey, ctl.PublicKey) {
			ctlog[i].isActive = false
			if len(ctlog[i].getEntries) == 0 {
				delete(ctlog, i)
			}
		}
	}

	// If any logs have been added, add them to the map.
	for i, newctl := range newctlog {
		if ctlog[i] == nil { // Add this new log.
			newctl.rateLimiter = time.NewTicker(time.Minute / time.Duration(newctl.RequestsPerMinute))
			newctl.latestQueuedEntryID = newctl.LatestStoredEntryID
			newctl.anyQueuedYet = false
			newctl.getEntries = make(map[int64]*getEntries)
			newctl.isActive = true
			ctlog[i] = newctl
		} else {
			ctlog[i].Url = newctl.Url // A log's URL could conceivably be updated but still refer to the exact same log.
			ctlog[i].isActive = true  // A log could conceivably be removed then added again on the DB before being removed from the log map.
			ctlog[i].TreeSize = newctl.TreeSize
			ctlog[i].LatestSTHTimestamp = newctl.LatestSTHTimestamp
			ctlog[i].LatestUpdate = newctl.LatestUpdate
		}
	}

	syncMutex.Unlock()
}
