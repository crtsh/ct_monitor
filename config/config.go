package config

import (
	"math"
	"os"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/crtsh/ct_monitor/logger"

	"github.com/spf13/viper"

	"go.uber.org/zap"
)

type config struct {
	CertWatchDB struct {
		Host     string `mapstructure:"host"`
		Port     int    `mapstructure:"port"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"`
	}
	CTLogs struct {
		GetSTHFrequency             time.Duration `mapstructure:"getSTHFrequency"`
		GetEntriesLauncherFrequency time.Duration `mapstructure:"getEntriesLauncherFrequency"`
		GetEntriesDefaultBatchSize  int           `mapstructure:"getEntriesDefaultBatchSize"`
		HTTPTimeout                 time.Duration `mapstructure:"httpTimeout"`
	}
	Writer struct {
		NumBackends  int           `mapstructure:"numBackends"`
		MaxBatchSize int           `mapstructure:"maxBatchSize"`
		MaxBatchWait time.Duration `mapstructure:"maxBatchWait"`
	}
	Server struct {
		MonitoringPort int `mapstructure:"monitoringPort"`
	}
	Logging struct {
		IsDevelopment      bool `mapstructure:"isDevelopment"`
		SamplingInitial    int  `mapstructure:"samplingInitial"`
		SamplingThereafter int  `mapstructure:"samplingThereafter"`
	}
}

var (
	Config                                      config
	BuildTimestamp                              string // Automatically populated (see Makefile / Dockerfile).
	Vcs, VcsModified, VcsRevision, VcsTimestamp string
)

func init() {
	if err := initViper(); err != nil {
		panic(err)
	} else if err = logger.InitLogger(Config.Logging.IsDevelopment, Config.Logging.SamplingInitial, Config.Logging.SamplingThereafter); err != nil {
		panic(err)
	}

	// Log build information.
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, bs := range bi.Settings {
			switch bs.Key {
			case "vcs":
				Vcs = bs.Value
			case "vcs.modified":
				VcsModified = bs.Value
			case "vcs.revision":
				VcsRevision = bs.Value
			case "vcs.time":
				VcsTimestamp = bs.Value
			}
		}
		logger.Logger.Info(
			"Build information",
			zap.String("build_timestamp", BuildTimestamp),
			zap.String("vcs", Vcs),
			zap.String("vcs_modified", VcsModified),
			zap.String("vcs_revision", VcsRevision),
			zap.String("vcs_timestamp", VcsTimestamp),
		)
	}

	// Log RLIMIT_NOFILE soft and hard limits.
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		logger.Logger.Error(
			"Getrlimit(RLIMIT_NOFILE) error",
			zap.Error(err),
		)
	} else {
		logger.Logger.Info(
			"Resource limits",
			zap.Uint64("rlimit_nofile_soft", rlimit.Cur),
			zap.Uint64("rlimit_nofile_hard", rlimit.Max),
			zap.String("gomemlimit", os.Getenv("GOMEMLIMIT")),
		)
	}
}

func initViper() error {
	// Import config file values from least to most specific.
	viper.SetConfigName("config.yaml")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/config")  // /config/config.yaml
	viper.AddConfigPath("./config") // ./config/config.yaml
	viper.AddConfigPath(".")        // ./config.yaml

	// Setup Viper to also look at environment variables.
	viper.SetEnvPrefix("ctmonitor")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_")) // Fix for nested struct references (https://github.com/spf13/viper/issues/160#issuecomment-189551355).
	viper.AutomaticEnv()

	// Enable environment variables to be unmarshalled to slices (https://stackoverflow.com/a/43241844).
	viper.SetTypeByDefaultValue(true)

	// Set defaults for all values in-order to use env config for all options
	viper.SetDefault("certwatchdb.host", "/var/run/postgresql")
	viper.SetDefault("certwatchdb.port", 5432)
	viper.SetDefault("certwatchdb.user", "certwatch")
	viper.SetDefault("certwatchdb.password", "")
	viper.SetDefault("ctlogs.getSTHFrequency", time.Minute)
	viper.SetDefault("ctlogs.getEntriesLauncherFrequency", 100*time.Millisecond)
	viper.SetDefault("ctlogs.getEntriesDefaultBatchSize", 256)
	viper.SetDefault("ctlogs.httpTimeout", 30*time.Second)
	viper.SetDefault("writer.numBackends", 4)
	viper.SetDefault("writer.maxBatchSize", 256)
	viper.SetDefault("writer.maxBatchWait", 5*time.Second)
	viper.SetDefault("server.monitoringPort", 8081)
	viper.SetDefault("logging.isDevelopment", false)
	viper.SetDefault("logging.samplingInitial", math.MaxInt)    // When both of these are set to MaxInt, sampling is disabled.
	viper.SetDefault("logging.samplingThereafter", math.MaxInt) // See https://pkg.go.dev/go.uber.org/zap/zapcore#NewSamplerWithOptions for more information.

	// Render results to Config Struct.
	_ = viper.ReadInConfig() // Ignore errors, because we also support reading config from environment variables.
	return viper.Unmarshal(&Config)
}
