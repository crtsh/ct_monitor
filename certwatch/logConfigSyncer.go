package certwatch

import (
	"context"
	"strings"
	"time"

	"github.com/crtsh/ct_monitor/config"
	"github.com/crtsh/ct_monitor/ct"
	"github.com/crtsh/ct_monitor/logger"
	"github.com/crtsh/ct_monitor/msg"

	"github.com/jackc/pgx/v5"

	"go.uber.org/zap"
)

func LogConfigSyncer(ctx context.Context) {
	logger.Logger.Info("Started LogConfigSyncer")

	for {
		select {
		// Sync log configuration information from the certwatch DB, then fire a timer when it's time to re-sync.
		case <-time.After(syncLogConfig()):
		// Respond to graceful shutdown requests.
		case <-ctx.Done():
			msg.ShutdownWG.Done()
			logger.Logger.Info("Stopped LogConfigSyncer")
			return
		}
	}
}

func syncLogConfig() time.Duration {
	// Query existing CT log configuration on the certwatch DB.
	if rows, err := connLogConfigSyncer.Query(context.Background(), `
SELECT ctl.ID, ctl.PUBLIC_KEY, ctl.URL, ctl.MMD_IN_SECONDS, coalesce(ctl.BATCH_SIZE, 32), ctl.REQUESTS_THROTTLE, coalesce(ctl.REQUESTS_CONCURRENT, 4), coalesce(latest.ENTRY_ID, -1)
	FROM ct_log ctl
			LEFT JOIN LATERAL (
				SELECT max(ctle.ENTRY_ID) ENTRY_ID
					FROM ct_log_entry ctle
					WHERE ctle.CT_LOG_ID = ctl.ID
			) latest ON TRUE
	WHERE ctl.IS_ACTIVE
`); err != nil {
		logger.Logger.Error(
			"connLogSyncer.Query failed",
			zap.Error(err),
		)
	} else {
		defer rows.Close()

		// Get rows and put them into a slice.
		newctlog := make(map[int]*ct.Log)
		for rows.Next() {
			var ctl ct.Log
			if err = rows.Scan(&ctl.Id, &ctl.PublicKey, &ctl.Url, &ctl.MMDInSeconds, &ctl.BatchSize, &ctl.RequestsThrottle, &ctl.RequestsConcurrent, &ctl.LatestStoredEntryID); err != nil {
				LogPostgresError(err)
				break
			} else {
				ctl.Url = strings.Replace(ctl.Url, "//ct.googleapis.com/", "//ct-fixed-ip.googleapis.com/", 1) // This seems to make it go faster!
				newctlog[ctl.Id] = &ctl
			}
		}

		// If any log has been added or removed to the DB, update the in-memory log list.
		ct.UpdateLogList(newctlog)

		// Query the logs for new STHs.
		if updatedLogs := ct.GetSTHs(); len(updatedLogs) > 0 {
			// For each new STH observed, update the corresponding CT log record on the DB.
			var tx pgx.Tx
			if tx, err = connLogConfigSyncer.Begin(context.Background()); err == nil {
				defer tx.Rollback(context.Background())

				if _, err = tx.Exec(context.Background(), `
CREATE TEMP TABLE getsth_update_temp (
	CT_LOG_ID integer,
	TREE_SIZE bigint,
	LATEST_STH_TIMESTAMP timestamp,
	LATEST_UPDATE timestamp
) ON COMMIT DROP
`); err == nil {
					if _, err = tx.CopyFrom(
						context.Background(),
						pgx.Identifier{"getsth_update_temp"},
						[]string{"ct_log_id", "tree_size", "latest_sth_timestamp", "latest_update"},
						pgx.CopyFromSlice(len(updatedLogs), func(i int) ([]any, error) {
							return []any{updatedLogs[i].Id, updatedLogs[i].TreeSize, updatedLogs[i].LatestSTHTimestamp, updatedLogs[i].LatestUpdate}, nil
						}),
					); err == nil {
						if _, err = tx.Exec(context.Background(), "SELECT getsth_update()"); err == nil {
							err = tx.Commit(context.Background())
						}
					}
				}
			}

			if err != nil {
				LogPostgresError(err)
			}
		}
	}

	return config.Config.CTLogs.GetSTHFrequency
}
