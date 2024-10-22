package certwatch

import (
	"context"
	"crypto/sha256"
	"sync"
)

var issuerFetcherMutex sync.Mutex

func FetchIssuer(sha256Cert [sha256.Size]byte) []byte {
	if ci, ok := GetCachedIssuer(sha256Cert); ok {
		return ci.Cert.Raw
	} else {
		var issuer []byte
		issuerFetcherMutex.Lock()
		_ = connIssuerFetcher.QueryRow(context.Background(), `
SELECT c.CERTIFICATE
	FROM certificate c
	WHERE digest(c.CERTIFICATE, 'sha256') = $1
`, sha256Cert[:]).Scan(&issuer)
		issuerFetcherMutex.Unlock()
		return issuer
	}
}
