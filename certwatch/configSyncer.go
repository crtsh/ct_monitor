package certwatch

import (
	"context"
	"fmt"

	"github.com/crtsh/ct_monitor/config"

	"github.com/jackc/pgx/v5"
)

func GetConfig() (pgx.Rows, error) {
	return connLogConfigSyncer.Query(context.Background(), fmt.Sprintf(`
	SELECT ctl.ID, ctl.PUBLIC_KEY, ctl.URL, ctl.TYPE, ctl.MMD_IN_SECONDS,
			CASE WHEN ctl.TYPE = 'rfc6962' THEN coalesce(ctl.BATCH_SIZE, %d) ELSE 256 END,
			ctl.REQUESTS_THROTTLE, coalesce(ctl.REQUESTS_CONCURRENT, 8), coalesce(latest.ENTRY_ID, -1)
		FROM ct_log ctl
				LEFT JOIN LATERAL (
					SELECT max(ctle.ENTRY_ID) ENTRY_ID
						FROM ct_log_entry ctle
						WHERE ctle.CT_LOG_ID = ctl.ID
				) latest ON TRUE
		WHERE ctl.IS_ACTIVE
	`, config.Config.CTLogs.GetEntriesDefaultBatchSize))
}

func BeginUpdateConfig() (pgx.Tx, error) {
	return connLogConfigSyncer.Begin(context.Background())
}
