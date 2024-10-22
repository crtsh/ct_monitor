package certwatch

import (
	"crypto/sha256"
	"database/sql"
	"sync"

	"github.com/google/certificate-transparency-go/x509"
)

type CachedIssuer struct {
	certID     int64
	caID       sql.NullInt32
	Cert       *x509.Certificate
	storedInDB bool
}

var (
	sha256IssuerCache map[[sha256.Size]byte]CachedIssuer
	issuerCacheMutex  sync.RWMutex
)

func init() {
	sha256IssuerCache = make(map[[sha256.Size]byte]CachedIssuer)
}

func GetCachedIssuer(sha256Cert [sha256.Size]byte) (CachedIssuer, bool) {
	issuerCacheMutex.RLock()
	ci, ok := sha256IssuerCache[sha256Cert]
	issuerCacheMutex.RUnlock()
	return ci, ok
}

func SetCachedIssuer(ci CachedIssuer, sha256Cert [sha256.Size]byte) {
	issuerCacheMutex.Lock()
	sha256IssuerCache[sha256Cert] = ci
	issuerCacheMutex.Unlock()
}
