package certwatch

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/crtsh/ct_monitor/config"
	"github.com/crtsh/ct_monitor/logger"
	"github.com/crtsh/ct_monitor/msg"

	"github.com/jackc/pgx/v5"

	"go.uber.org/zap"
)

type cachedIssuer struct {
	certID int64
	caID   sql.NullInt32
}

func NewEntriesWriter(ctx context.Context) {
	logger.Logger.Info("Started NewEntriesWriter")

	var entriesToCopy [][]msg.NewLogEntry
	var ctLogEntriesToCopy [][]any
	var err error
	sha256IssuerCache := make(map[[sha256.Size]byte]cachedIssuer)
	var nCertsIndividuallyImported int

	for {
		if entriesToCopy == nil {
			entriesToCopy = make([][]msg.NewLogEntry, config.Config.Writer.NumBackends)
			for i := 0; i < config.Config.Writer.NumBackends; i++ {
				entriesToCopy[i] = make([]msg.NewLogEntry, 0, config.Config.Writer.MaxBatchSize)
			}
			ctLogEntriesToCopy = [][]any{}
		}

		select {
		// Read an entry from the channel.
		case nle := <-msg.WriterChan:
			if (nle.CtLogID == -1) || (nle.Cert == nil) || nle.Cert.IsCA { // CA certificate from an entry's chain, or a (Leaf or CA) (pre)certificate that could not be parsed, or a CA certificate that is itself an entry.
				// If we found a valid issuer cert for this cert, let's see if we've already cached it.
				var issuer cachedIssuer
				if nle.IssuerVerified {
					issuer = sha256IssuerCache[nle.Sha256IssuerCert]
				}
				// If this certificate is not already cached, import it.
				var subject cachedIssuer
				var ok bool
				if subject, ok = sha256IssuerCache[nle.Sha256Cert]; !ok {
					if err = connNewEntriesWriter[0].QueryRow(context.Background(), "SELECT * FROM import_any_cert($1,$2)", nle.DerCert, issuer.caID).Scan(&subject.caID, &subject.certID); err == nil {
						// If this is a CA certificate, cache it now.
						if subject.caID.Valid {
							sha256IssuerCache[nle.Sha256Cert] = subject
						}
						nCertsIndividuallyImported++
					} else {
						logger.Logger.Fatal("import_any_cert failed", zap.Error(err), zap.Binary("derCert", nle.DerCert), zap.Int32("issuerCAID", issuer.caID.Int32))
					}
				}
				if nle.CtLogID != -1 {
					// Add this entry to the list of ct_log_entry records that we need to COPY.
					ctLogEntriesToCopy = append(ctLogEntriesToCopy, []any{subject.certID, nle.EntryID, nle.EntryTimestamp, nle.CtLogID})
				}
			} else { // Leaf (pre)certificate (that could be parsed) entry.
				// Shard entries by the first byte of each SHA-256(Certificate) % the number of backends, to ensure that multiple instances of the same leaf (pre)certificate will be handled by the same backend.
				backend := int(nle.Sha256Cert[0]) % config.Config.Writer.NumBackends

				// Queue this leaf (pre)certificate entry to be COPYed.
				entriesToCopy[backend] = append(entriesToCopy[backend], nle)

				// If this backend's queue is full, process the entries in all the backend queues now.
				if len(entriesToCopy[backend]) >= config.Config.Writer.MaxBatchSize {
					goto copy_certs
				}
			}

		// Limit how long we wait for a partial write batch to be filled.
		case <-time.After(config.Config.Writer.MaxBatchWait):
			// If any entries are queued, process them now.
			for i := 0; i < config.Config.Writer.NumBackends; i++ {
				if len(entriesToCopy[i]) > 0 {
					goto copy_certs
				}
			}

		// Respond to graceful shutdown requests.
		case <-ctx.Done():
			msg.ShutdownWG.Done()
			logger.Logger.Info("Stopped NewEntriesWriter")
			return
		}

		// Not ready to write a batch yet, so loop.
		continue

	copy_certs:
		chan_tx := make(chan pgx.Tx, config.Config.Writer.NumBackends)
		chan_logEntries := make(chan []any, config.Config.Writer.NumBackends*config.Config.Writer.MaxBatchSize)
		var backendWG sync.WaitGroup
		for i := 0; i < config.Config.Writer.NumBackends; i++ {
			if len(entriesToCopy[i]) > 0 {
				backendWG.Add(1)

				go func(backend int) {
					// Deduplicate the leaf certificates to import in this batch.
					certsCopied := make(map[[sha256.Size]byte]struct{})
					certsReturned := make(map[[sha256.Size]byte]int64)
					leafCertsToImport := [][]any{}
					for _, entry := range entriesToCopy[backend] {
						if _, ok := certsCopied[entry.Sha256Cert]; !ok {
							// If cached, get the issuer details.
							var issuer cachedIssuer
							if entry.IssuerVerified {
								issuer = sha256IssuerCache[entry.Sha256IssuerCert]
							}
							// Copy the SHA-256 fingerprint, because entry.Sha256Cert gets overwritten on each iteration of this loop.
							sha256Cert := make([]byte, 32)
							copy(sha256Cert, entry.Sha256Cert[:])
							// Add this certificate to the rows that will be COPYed.
							leafCertsToImport = append(leafCertsToImport, []any{issuer.caID, entry.DerCert, sha256Cert})
							// Add this certificate to the map, so that we can deduplicate any further instances of it in this batch.
							certsCopied[entry.Sha256Cert] = struct{}{}
						}
					}

					// Start a transaction.
					var rows pgx.Rows
					var tx pgx.Tx
					if tx, err = connNewEntriesWriter[backend].Begin(context.Background()); err != nil {
						goto done
					}

					// Create a temporary table.
					if _, err = tx.Exec(context.Background(), `
CREATE TEMP TABLE importleafcerts_temp (
	CERTIFICATE_ID bigint,
	ISSUER_CA_ID integer,
	IS_NEW_CERT bool			DEFAULT 't',
	DER_X509 bytea,
	SHA256_X509 bytea
) ON COMMIT DROP
`); err != nil {
						goto done
					}

					// Copy the leaf certificates to the temporary table.
					if _, err = tx.CopyFrom(context.Background(), pgx.Identifier{"importleafcerts_temp"}, []string{"issuer_ca_id", "der_x509", "sha256_x509"}, pgx.CopyFromRows(leafCertsToImport)); err != nil {
						goto done
					}

					// Create new certificate records, by processing the new leaf certificates in the temporary table.
					if rows, err = tx.Query(context.Background(), "SELECT * FROM import_leaf_certs()"); err != nil {
						goto done
					}
					// Construct a SHA-256(Certificate) -> Certificate ID map of all the leaf certificates (new and old) in the temporary table.
					for rows.Next() {
						var certID int64
						var certSHA256Slice []byte
						var certSHA256Array [sha256.Size]byte
						if err = rows.Scan(&certID, &certSHA256Slice); err != nil {
							break
						} else {
							copy(certSHA256Array[:], certSHA256Slice)
							certsReturned[certSHA256Array] = certID
						}
					}
					rows.Close()
					if err != nil {
						goto done
					}

					// Send details of required "ct_log_entry" records through a channel, to be dealt with after we've group-committed all of the writer backend transactions.
					for _, entry := range entriesToCopy[backend] {
						if certID, ok := certsReturned[entry.Sha256Cert]; !ok {
							err = fmt.Errorf("#%d: import_leaf_certs did not return certificate ID for %s", backend, hex.EncodeToString(entry.Sha256Cert[:]))
							goto done
						} else {
							chan_logEntries <- []any{certID, entry.EntryID, entry.EntryTimestamp, entry.CtLogID}
						}
					}

				done:
					if err == nil {
						logger.Logger.Debug(fmt.Sprintf("#%d Wrote/Read certificate records", backend), zap.Int("nEntries", len(entriesToCopy[backend])))
						chan_tx <- tx
					} else {
						LogPostgresError(err)
						if err = tx.Rollback(context.Background()); err != nil {
							LogPostgresError(err)
						}
						chan_tx <- nil
					}
					backendWG.Done()
				}(i)
			}
		}
		// Wait for all of the backends to complete.
		backendWG.Wait()
		close(chan_tx)

		// Check whether or not all of the backends completed successfully.  Create a slice of transactions that will either need to be group-committed or group-rolled-back.
		allSucceeded := true
		txSlice := make([]pgx.Tx, 0, len(chan_tx))
		for tx := range chan_tx {
			if tx == nil {
				allSucceeded = false
			} else {
				txSlice = append(txSlice, tx)
			}
		}

		// If all of the backends completed successfully, commit all of the transactions; otherwise, rollback all of the transactions.
		nErrors := 0
		for i := 0; i < len(txSlice); i++ {
			if allSucceeded {
				err = txSlice[i].Commit(context.Background())
			} else {
				err = txSlice[i].Rollback(context.Background())
				nErrors++
			}

			if err != nil {
				LogPostgresError(err)
				nErrors++
			}
		}

		if nErrors > 0 {
			panic("One or more writer backends failed")
		}

		// Read the details of the required new ct_log_entry records that the backends sent through a channel.
		close(chan_logEntries)
		for entry := range chan_logEntries {
			ctLogEntriesToCopy = append(ctLogEntriesToCopy, entry)
		}

		// Start a transaction.
		var tx pgx.Tx
		if tx, err = connNewEntriesWriter[0].Begin(context.Background()); err != nil {
			goto done
		}

		// Copy the new ct_log_entry rows.
		if _, err = tx.CopyFrom(context.Background(), pgx.Identifier{"ct_log_entry"}, []string{"certificate_id", "entry_id", "entry_timestamp", "ct_log_id"}, pgx.CopyFromRows(ctLogEntriesToCopy)); err != nil {
			goto done
		}

		err = tx.Commit(context.Background())

	done:
		if err == nil {
			// Empty the queue, now that we've processed it.
			entriesToCopy = nil
			logger.Logger.Info("Wrote ct_log_entry records", zap.Int("nEntries", len(ctLogEntriesToCopy)), zap.Int("nQueued", len(msg.WriterChan)), zap.Int("nCertsIndividuallyImported", nCertsIndividuallyImported))
			nCertsIndividuallyImported = 0
		} else {
			// An error occurred, and the application will need to be restarted so that no entries are missed.
			if err2 := tx.Rollback(context.Background()); err2 != nil {
				LogPostgresError(err2)
			}
			LogPostgresFatal(err)
		}
	}
}
