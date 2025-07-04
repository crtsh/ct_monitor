package msg

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/x509"
)

type NewLogEntry struct {
	CtLogID          int
	EntryID          int64
	EntryTimestamp   time.Time
	DerCert          []byte
	Cert             *x509.Certificate
	Sha256Cert       [sha256.Size]byte
	Sha256IssuerCert [sha256.Size]byte
	IssuerVerified   bool
}

var (
	ShutdownWG sync.WaitGroup
	WriterChan chan NewLogEntry
)

func init() {
	WriterChan = make(chan NewLogEntry, 32768*4)
}
