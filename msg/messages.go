package msg

import (
	"crypto/sha256"
	"sync"
	"time"
)

type NewLogEntry struct {
	CtLogID          int
	EntryID          int64
	EntryTimestamp   time.Time
	DerCert          []byte
	Sha256Cert       [sha256.Size]byte
	Sha256IssuerCert [sha256.Size]byte
	IssuerVerified   bool
	IsPrecertificate bool
}

var (
	ShutdownWG sync.WaitGroup
	WriterChan chan NewLogEntry
)

func init() {
	WriterChan = make(chan NewLogEntry, 32768)
}
