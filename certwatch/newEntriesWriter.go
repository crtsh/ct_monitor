package certwatch

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/crtsh/ct_monitor/config"
	"github.com/crtsh/ct_monitor/logger"
	"github.com/crtsh/ct_monitor/msg"

	"github.com/jackc/pgx/v5"

	"go.uber.org/zap"
)

func NewEntriesWriter(ctx context.Context) {
	logger.Logger.Info("Started NewEntriesWriter")

	var entriesToCopy []msg.NewLogEntry
	var err error
	sha256IssuerCache := make(map[[sha256.Size]byte]*int64)
	var nChainCertsImported int

	for {
		if entriesToCopy == nil {
			entriesToCopy = make([]msg.NewLogEntry, 0, config.Config.Writer.MaxBatchSize)
		}

		select {
		// Read an entry from the channel.
		case nle := <-msg.WriterChan:
			// If we found a valid issuer cert for this cert, let's see if we've already cached its crt.sh CA ID.
			var issuerCAID *int64
			if nle.IssuerVerified {
				issuerCAID = sha256IssuerCache[nle.Sha256IssuerCert]
			}

			if nle.CtLogID == -1 { // CA certificate from the entry's chain.
				// Let's see if we've already cached this CA certificate's crt.sh CA ID.
				if caID := sha256IssuerCache[nle.Sha256Cert]; caID == nil { // It's not already cached, so import and cache it now.
					if err = connNewEntriesWriter.QueryRow(context.Background(), "SELECT import_chain_cert($1,$2)", nle.DerCert, issuerCAID).Scan(&caID); err == nil {
						sha256IssuerCache[nle.Sha256Cert] = caID
						nChainCertsImported++
					} else {
						logger.Logger.Error("Could not import chain cert", zap.Error(err), zap.Int64p("issuerCAID", issuerCAID), zap.Binary("derCert", nle.DerCert))
					}
				}
			} else { // Certificate or precertificate entry.
				// Queue this log entry to be COPYed.
				entriesToCopy = append(entriesToCopy, nle)

				// If the queue is full, process the entries now.
				if len(entriesToCopy) >= config.Config.Writer.MaxBatchSize {
					goto copy_certs
				}
			}

		// Limit how long we wait for a partial write batch to be filled.
		case <-time.After(config.Config.Writer.MaxBatchWait):
			// If any entries are queued, process them now.
			if len(entriesToCopy) > 0 {
				goto copy_certs
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
		// Start a transaction.
		var tx pgx.Tx
		if tx, err = connNewEntriesWriter.Begin(context.Background()); err != nil {
			goto next
		}

		if _, err = tx.Exec(context.Background(), `
CREATE TEMP TABLE newentries_temp (
	CT_LOG_ID integer,
	ENTRY_ID bigint,
	ENTRY_TIMESTAMP timestamp,
	DER_X509 bytea,
	SHA256_X509 bytea,
	CERTIFICATE_ID bigint,
	ISSUER_CA_ID integer,
	SUBJECT_CA_ID integer,
	LINTING_APPLIES bool			DEFAULT 'f',
	NUM_ISSUED_INDEX smallint,
	NEW_AND_CAN_ISSUE_CERTS bool	DEFAULT 'f',
	IS_NEW_CA bool					DEFAULT 'f'
) ON COMMIT DROP
`); err != nil {
			goto next
		}

		if _, err = tx.CopyFrom(
			context.Background(),
			pgx.Identifier{"newentries_temp"},
			[]string{"ct_log_id", "entry_id", "entry_timestamp", "der_x509", "sha256_x509", "issuer_ca_id", "num_issued_index"},
			pgx.CopyFromSlice(len(entriesToCopy), func(i int) ([]any, error) {
				var issuerCAID *int64
				if entriesToCopy[i].IssuerVerified {
					issuerCAID = sha256IssuerCache[entriesToCopy[i].Sha256IssuerCert]
				}
				numIssuedIndex := 1 // Certificate.
				if entriesToCopy[i].IsPrecertificate {
					numIssuedIndex = 2 // Precertificate.
				}
				return []any{entriesToCopy[i].CtLogID, entriesToCopy[i].EntryID, entriesToCopy[i].EntryTimestamp, entriesToCopy[i].DerCert, entriesToCopy[i].Sha256Cert[:], issuerCAID, numIssuedIndex}, nil
			}),
		); err == nil {
			if _, err = tx.Exec(context.Background(), "SELECT process_new_entries()"); err == nil {
				err = tx.Commit(context.Background())
			}
		}

	next:
		if err == nil {
			logger.Logger.Info("Wrote entries", zap.Int("nEntries", len(entriesToCopy)), zap.Int("nQueued", len(msg.WriterChan)), zap.Int("nChainCertsImported", nChainCertsImported))
		} else {
			LogPostgresError(err)
			if err = tx.Rollback(context.Background()); err != nil {
				LogPostgresFatal(err)
			}
		}

		// Empty the queue, now that we've processed it.
		entriesToCopy = nil
		nChainCertsImported = 0
	}
}
