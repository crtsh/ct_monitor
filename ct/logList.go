package ct

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"filippo.io/sunlight"

	ctgo "github.com/google/certificate-transparency-go"

	"golang.org/x/mod/sumdb/note"
)

type Log struct {
	Id                  int
	PublicKey           []byte
	PubKey              any
	KeyName             string
	SigVer              *ctgo.SignatureVerifier
	NoteVerifiers       note.Verifiers
	Url                 string
	SubmissionUrl       string
	Type                string
	MMDInSeconds        int
	BatchSize           int64
	RequestsThrottle    *string
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
			var err error
			if newctl.PubKey, err = x509.ParsePKIXPublicKey(newctl.PublicKey); err != nil {
				panic(fmt.Errorf("could not parse public key: %v", newctl.PublicKey))
			}
			if newctl.Type == "rfc6962" {
				if newctl.SigVer, err = ctgo.NewSignatureVerifier(newctl.PubKey); err != nil {
					panic(fmt.Errorf("could not create signature verifier: %v", newctl.PublicKey))
				}
			} else if newctl.Type == "static" {
				newctl.KeyName = strings.TrimRight(strings.TrimPrefix(newctl.SubmissionUrl, "https://"), "/")
				if verifier, err := sunlight.NewRFC6962Verifier(newctl.KeyName, newctl.PubKey); err != nil {
					panic(fmt.Errorf("could not create signature verifier: %v", newctl.PublicKey))
				} else {
					newctl.NoteVerifiers = note.VerifierList(verifier)
				}
			}

			if newctl.RequestsThrottle != nil {
				if s := strings.SplitN(*newctl.RequestsThrottle, "/", 2); len(s) != 2 {
					panic(fmt.Errorf("could not parse requests throttle ['%s']", *newctl.RequestsThrottle))
				} else if s0, err := strconv.Atoi(s[0]); err != nil {
					panic(fmt.Errorf("could not parse requests throttle ['%s' of '%s']", s[0], *newctl.RequestsThrottle))
				} else if s1, err := time.ParseDuration(s[1]); err != nil {
					panic(fmt.Errorf("could not parse requests throttle ['%s' of '%s']", s[1], *newctl.RequestsThrottle))
				} else {
					newctl.rateLimiter = time.NewTicker(s1 / time.Duration(s0))
				}
			}
			newctl.latestQueuedEntryID = newctl.LatestStoredEntryID
			newctl.anyQueuedYet = false
			newctl.getEntries = make(map[int64]*getEntries)
			newctl.isActive = true
			ctlog[i] = newctl
		} else {
			ctlog[i].Url = newctl.Url                     // A log's URL could conceivably be updated but still refer to the exact same log.
			ctlog[i].SubmissionUrl = newctl.SubmissionUrl // A static log's Submission URL could conceivably be updated but still refer to the exact same log.
			ctlog[i].Type = newctl.Type                   // A log's type could conceivably be updated but still refer to the exact same log.
			ctlog[i].isActive = true                      // A log could conceivably be removed then added again on the DB before being removed from the log map.
			ctlog[i].TreeSize = newctl.TreeSize
			ctlog[i].LatestSTHTimestamp = newctl.LatestSTHTimestamp
			ctlog[i].LatestUpdate = newctl.LatestUpdate
		}
	}

	syncMutex.Unlock()
}
