package certwatch

import (
	"context"
	"crypto/sha256"
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

// flushPayload is the unit of work handed from the accumulator goroutine to
// the flush goroutine. It carries one batch's worth of entries plus the
// bookkeeping that needs to be logged after the flush completes.
type flushPayload struct {
	entriesToCopy              [][]msg.NewLogEntry
	ctLogEntriesToCopy         [][]any
	nCertsIndividuallyInserted int
}

// ctLogEntryPayload is handed from the flush (leaf) goroutine to the
// ct_log_entry writer goroutine.  The leaf-cert transactions have already
// been committed at this point, so the certificate_id values referenced by
// these ct_log_entry rows are durable and the COPY can proceed independently
// of (and concurrently with) the next batch's leaf-cert work.
type ctLogEntryPayload struct {
	ctLogEntriesToCopy          [][]any
	nCertsIndividuallyInserted  int
	nCertsBulkInsertedTotal     int
	nCertsBulkDeduplicatedTotal int
	leafFlushDuration           time.Duration
	groupCommitDuration         time.Duration
}

func NewEntriesWriter(ctx context.Context) {
	logger.Logger.Info("Started NewEntriesWriter")

	// Spawn the ct_log_entry writer goroutine first; it consumes payloads
	// produced by the flush (leaf) goroutine below.  Buffered at 1 so the
	// leaf stage can prepare batch N+1 while batch N's ct_log_entry rows are
	// still being COPYed by this stage.
	ctLogEntryChan := make(chan ctLogEntryPayload, 1)
	ctLogEntryDone := make(chan struct{})
	go func() {
		for payload := range ctLogEntryChan {
			writeCtLogEntries(payload)
		}
		close(ctLogEntryDone)
	}()

	// Spawn a single, persistent flush (leaf-cert) goroutine. Buffered at 1
	// so that the accumulator can finish preparing batch N+1 while batch N is
	// still being written to the database.
	flushChan := make(chan flushPayload, 1)
	flushDone := make(chan struct{})
	go func() {
		for payload := range flushChan {
			flushBatch(payload, ctLogEntryChan)
		}
		close(flushDone)
	}()

	var entriesToCopy [][]msg.NewLogEntry
	var ctLogEntriesToCopy [][]any
	var nCertsIndividuallyInserted int

	// Partial-batch timer.  The timer is armed when the first entry is added to
	// the current batch and stopped at handoff, so that the maximum delay
	// between an entry joining a batch and that batch being handed off is
	// bounded by MaxBatchWait, regardless of whether further entries continue
	// arriving.  Reusing one Timer (vs. time.After per iteration) avoids the
	// allocation/GC cost of a fresh runtime timer on every WriterChan delivery.
	batchTimer := time.NewTimer(config.Config.Writer.MaxBatchWait)
	batchTimer.Stop()
	defer batchTimer.Stop()
	batchHasEntries := false

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
				var issuer CachedIssuer
				if nle.IssuerVerified {
					issuer, _ = GetCachedIssuer(nle.Sha256IssuerCert)
				}
				// If this certificate is not already cached, import it.
				var subject CachedIssuer
				var ok bool
				if subject, ok = GetCachedIssuer(nle.Sha256Cert); !ok || !subject.storedInDB {
					if err := connEntryAccumulator.QueryRow(context.Background(), "SELECT * FROM import_any_cert($1,$2)", nle.DerCert, issuer.caID).Scan(&subject.caID, &subject.certID); err == nil {
						// If this is a CA certificate, cache it now.
						if subject.caID.Valid {
							subject.Cert = nle.Cert
							subject.storedInDB = true
							SetCachedIssuer(subject, nle.Sha256Cert)
						}
						nCertsIndividuallyInserted++
					} else {
						logger.Logger.Fatal("import_any_cert failed", zap.Error(err), zap.Binary("derCert", nle.DerCert), zap.Int32("issuerCAID", issuer.caID.Int32))
					}
				}
				if nle.CtLogID != -1 {
					// Add this entry to the list of ct_log_entry records that we need to COPY.
					ctLogEntriesToCopy = append(ctLogEntriesToCopy, []any{subject.certID, nle.EntryID, nle.EntryTimestamp, nle.CtLogID})
					if !batchHasEntries {
						batchTimer.Reset(config.Config.Writer.MaxBatchWait)
						batchHasEntries = true
					}
				}
			} else { // Leaf (pre)certificate (that could be parsed) entry.
				// Shard entries by the first byte of each SHA-256(Certificate) % the number of backends, to ensure that multiple instances of the same leaf (pre)certificate will be handled by the same backend.
				backend := int(nle.Sha256Cert[0]) % config.Config.Writer.NumBackends

				// Queue this leaf (pre)certificate entry to be COPYed.
				entriesToCopy[backend] = append(entriesToCopy[backend], nle)
				if !batchHasEntries {
					batchTimer.Reset(config.Config.Writer.MaxBatchWait)
					batchHasEntries = true
				}

				// If this backend's queue is full, hand the batch off to the flush goroutine.
				if len(entriesToCopy[backend]) >= config.Config.Writer.MaxBatchSize {
					goto handoff
				}
			}

		// Limit how long we wait for a partial write batch to be filled.
		case <-batchTimer.C:
			// The timer is only armed when the batch is non-empty, so we can hand
			// off unconditionally.
			goto handoff

		// Respond to graceful shutdown requests.
		case <-ctx.Done():
			// Let any in-flight flush complete, then drain the ct_log_entry
			// stage, then exit.  Any entries currently buffered in entriesToCopy
			// or msg.WriterChan are dropped and will be re-fetched on restart
			// (the max(entry_id) per log on the DB is the resume point).
			close(flushChan)
			<-flushDone
			close(ctLogEntryChan)
			<-ctLogEntryDone
			msg.ShutdownWG.Done()
			logger.Logger.Info("Stopped NewEntriesWriter")
			return
		}

		// Not ready to hand off a batch yet, so loop.
		continue

	handoff:
		// Stop the partial-batch timer; the next batch starts empty and will arm
		// its own timer when its first entry arrives.
		batchTimer.Stop()
		batchHasEntries = false
		// Hand off the current batch to the flush goroutine.  This send blocks if
		// the flush goroutine is still processing the previous batch, providing
		// back-pressure that bounds memory use to at most ~2 batches in flight.
		flushChan <- flushPayload{
			entriesToCopy:              entriesToCopy,
			ctLogEntriesToCopy:         ctLogEntriesToCopy,
			nCertsIndividuallyInserted: nCertsIndividuallyInserted,
		}
		entriesToCopy = nil
		nCertsIndividuallyInserted = 0
	}
}

// flushBatch performs the leaf-cert database writes for one accumulated
// batch: concurrently COPYs each backend's leaf certs, group-commits the
// resulting transactions, and hands the assembled ct_log_entry rows off to
// the ct_log_entry writer stage.  It runs serialized in its own goroutine so
// that the accumulator can continue draining msg.WriterChan during the
// writes.
func flushBatch(payload flushPayload, ctLogEntryChan chan<- ctLogEntryPayload) {
	flushStart := time.Now()
	entriesToCopy := payload.entriesToCopy
	ctLogEntriesToCopy := payload.ctLogEntriesToCopy

	chan_tx := make(chan pgx.Tx, config.Config.Writer.NumBackends)
	chan_logEntries := make(chan []any, config.Config.Writer.NumBackends*config.Config.Writer.MaxBatchSize)
	nCertsBulkInserted := make([]int, config.Config.Writer.NumBackends)
	nCertsBulkDeduplicated := make([]int, config.Config.Writer.NumBackends)
	var backendWG sync.WaitGroup
	for i := 0; i < config.Config.Writer.NumBackends; i++ {
		if len(entriesToCopy[i]) > 0 {
			backendWG.Add(1)

			go func(backend int) {
				backendStart := time.Now()
				// Deduplicate the leaf certificates to import in this batch.
				certsCopied := make(map[[sha256.Size]byte]struct{})
				certsReturned := make(map[[sha256.Size]byte]int64)
				leafCertsToImport := [][]any{}
				for _, entry := range entriesToCopy[backend] {
					if _, ok := certsCopied[entry.Sha256Cert]; !ok {
						// If cached, get the issuer details.
						var issuer CachedIssuer
						if entry.IssuerVerified {
							issuer, _ = GetCachedIssuer(entry.Sha256IssuerCert)
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
				var err error
				var certID int64
				var certSHA256Slice []byte
				var isNewCert bool
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
				if _, err = pgx.ForEachRow(rows, []any{&certID, &certSHA256Slice, &isNewCert}, func() error {
					var certSHA256Array [sha256.Size]byte
					copy(certSHA256Array[:], certSHA256Slice)
					certsReturned[certSHA256Array] = certID
					if isNewCert {
						nCertsBulkInserted[backend]++
					} else {
						nCertsBulkDeduplicated[backend]++
					}
					return nil
				}); err != nil {
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
					logger.Logger.Debug(fmt.Sprintf("#%d Wrote/Read certificate records", backend), zap.Int("nEntries", len(entriesToCopy[backend])), zap.Int("nCertsInserted", nCertsBulkInserted[backend]), zap.Int("nCertsDeduplicated", nCertsBulkDeduplicated[backend]), zap.Duration("duration", time.Since(backendStart)))
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
	backendsDoneAt := time.Now()
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
	var err error
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
	groupCommitDuration := time.Since(backendsDoneAt)

	// Read the details of the required new ct_log_entry records that the backends sent through a channel.
	close(chan_logEntries)
	for entry := range chan_logEntries {
		ctLogEntriesToCopy = append(ctLogEntriesToCopy, entry)
	}

	// All leaf-cert transactions have committed, so the certificate_id values
	// referenced by these ct_log_entry rows are durable.  Hand the batch off
	// to the ct_log_entry writer stage and return immediately so that this
	// goroutine can start processing the next leaf-cert batch.  The send
	// blocks if the ct_log_entry stage is still busy with the previous batch,
	// providing back-pressure that bounds memory use.
	nCertsBulkInsertedTotal := 0
	nCertsBulkDeduplicatedTotal := 0
	for i := range nCertsBulkInserted {
		nCertsBulkInsertedTotal += nCertsBulkInserted[i]
		nCertsBulkDeduplicatedTotal += nCertsBulkDeduplicated[i]
	}
	ctLogEntryChan <- ctLogEntryPayload{
		ctLogEntriesToCopy:          ctLogEntriesToCopy,
		nCertsIndividuallyInserted:  payload.nCertsIndividuallyInserted,
		nCertsBulkInsertedTotal:     nCertsBulkInsertedTotal,
		nCertsBulkDeduplicatedTotal: nCertsBulkDeduplicatedTotal,
		leafFlushDuration:           time.Since(flushStart),
		groupCommitDuration:         groupCommitDuration,
	}
}

// writeCtLogEntries performs the final ct_log_entry COPY for one batch.  It
// runs on its own dedicated connection so that it can proceed in parallel
// with the next batch's leaf-cert work (which uses connNewEntriesWriter[...]
// connections).
func writeCtLogEntries(payload ctLogEntryPayload) {
	ctLogEntryStart := time.Now()

	// Start a transaction.
	var err error
	var tx pgx.Tx
	if tx, err = connCtLogEntryWriter.Begin(context.Background()); err != nil {
		goto done
	}

	// Copy the new ct_log_entry rows.
	if _, err = tx.CopyFrom(context.Background(), pgx.Identifier{"ct_log_entry"}, []string{"certificate_id", "entry_id", "entry_timestamp", "ct_log_id"}, pgx.CopyFromRows(payload.ctLogEntriesToCopy)); err != nil {
		goto done
	}

	err = tx.Commit(context.Background())

done:
	if err == nil {
		ctLogEntryDuration := time.Since(ctLogEntryStart)
		logger.Logger.Info("Records written",
			zap.Int("nEntries", len(payload.ctLogEntriesToCopy)),
			zap.Int("nQueued", len(msg.WriterChan)),
			zap.Int("nCertsIndividuallyInserted", payload.nCertsIndividuallyInserted),
			zap.Int("nCertsBulkInserted", payload.nCertsBulkInsertedTotal),
			zap.Int("nCertsBulkDeduplicated", payload.nCertsBulkDeduplicatedTotal),
			zap.Duration("leafFlushDuration", payload.leafFlushDuration),
			zap.Duration("groupCommitDuration", payload.groupCommitDuration),
			zap.Duration("ctLogEntryCopyDuration", ctLogEntryDuration),
		)
	} else {
		// An error occurred, and the application will need to be restarted so that no entries are missed.
		if err2 := tx.Rollback(context.Background()); err2 != nil {
			LogPostgresError(err2)
		}
		LogPostgresFatal(err)
	}
}
