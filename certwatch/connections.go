package certwatch

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/crtsh/ct_monitor/config"
	"github.com/crtsh/ct_monitor/logger"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"go.uber.org/zap"
)

var (
	connectString        string
	connectStringToLog   string
	connLogConfigSyncer  *pgx.Conn
	connDatabaseWatcher  *pgx.Conn
	connNewEntriesWriter []*pgx.Conn
)

func init() {
	start := time.Now()

	// Construct the connect string URI for the "certwatch" PostgreSQL database.
	connectString = "postgresql:///certwatch?host=" + url.QueryEscape(config.Config.CertWatchDB.Host) + "&application_name=ct_monitor@" + url.QueryEscape(config.VcsRevision) + "&user=" + url.QueryEscape(config.Config.CertWatchDB.User)
	if !strings.Contains(config.Config.CertWatchDB.Host, "/") {
		connectString += fmt.Sprintf("&port=%d", config.Config.CertWatchDB.Port)
	}
	connectStringToLog = connectString
	if config.Config.CertWatchDB.Password != "" {
		connectString += "&password=" + url.QueryEscape(config.Config.CertWatchDB.Password)
		connectStringToLog += "&password=<redacted>"
	}

	// Parse the configuration, establish the database connections, and do some initialization.
	var err error
	var pgxConfig *pgx.ConnConfig
	if pgxConfig, err = pgx.ParseConfig(connectString); err != nil {
		LogPostgresFatal(err)
	} else if connLogConfigSyncer, err = pgx.ConnectConfig(context.Background(), pgxConfig); err != nil {
		LogPostgresFatal(err)
	} else if connDatabaseWatcher, err = pgx.ConnectConfig(context.Background(), pgxConfig); err != nil {
		LogPostgresFatal(err)
	}
	connNewEntriesWriter = make([]*pgx.Conn, config.Config.Writer.NumBackends)
	for i := 0; i < config.Config.Writer.NumBackends; i++ {
		if connNewEntriesWriter[i], err = pgx.ConnectConfig(context.Background(), pgxConfig); err != nil {
			LogPostgresFatal(err)
		}
	}

	logger.Logger.Info(
		"Connected to certwatch",
		zap.String("connect_string", connectStringToLog),
		zap.Int("connection_count", 2+config.Config.Writer.NumBackends), // LogConfigSyncer + DatabaseWatcher + N*NewEntriesWriter.
		zap.Duration("elapsed_ns", time.Since(start)),
	)
}

func Close() {
	n := 0
	if connLogConfigSyncer != nil {
		connLogConfigSyncer.Close(context.Background())
		n++
	}
	if connDatabaseWatcher != nil {
		connDatabaseWatcher.Close(context.Background())
		n++
	}
	if connNewEntriesWriter != nil {
		for i := 0; i < config.Config.Writer.NumBackends; i++ {
			connNewEntriesWriter[i].Close(context.Background())
			n++
		}
	}

	logger.Logger.Info(
		"Disconnected from certwatch",
		zap.String("connect_string", connectStringToLog),
		zap.Int("connection_count", n),
	)
}

func constructFields(pgErr *pgconn.PgError) []zap.Field {
	return []zap.Field{
		zap.String("severity", pgErr.Severity),
		zap.String("code", pgErr.Code),
		zap.String("detail", pgErr.Detail),
		zap.String("hint", pgErr.Hint),
		zap.Int32("position", pgErr.Position),
		zap.Int32("internal_position", pgErr.InternalPosition),
		zap.String("internal_query", pgErr.InternalQuery),
		zap.String("where", pgErr.Where),
		zap.String("schema_name", pgErr.SchemaName),
		zap.String("table_name", pgErr.TableName),
		zap.String("column_name", pgErr.ColumnName),
		zap.String("data_type_name", pgErr.DataTypeName),
		zap.String("constraint_name", pgErr.ConstraintName),
		zap.String("file", pgErr.File),
		zap.Int32("line", pgErr.Line),
		zap.String("routine", pgErr.Routine),
	}
}

func LogPostgresError(err error, debugCodes ...string) *pgconn.PgError {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		logger.Logger.Error("errors.As failed", zap.Error(err))
		return nil
	} else {
		for _, code := range debugCodes {
			if code == pgErr.Code {
				logger.Logger.Debug(pgErr.Message, constructFields(pgErr)...)
				return pgErr
			}
		}

		logger.Logger.Error(pgErr.Message, constructFields(pgErr)...)
		return pgErr
	}
}

func LogPostgresFatal(err error) {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		logger.Logger.Fatal("errors.As failed", zap.Error(err))
	} else {
		logger.Logger.Fatal(pgErr.Message, constructFields(pgErr)...)
	}
}
