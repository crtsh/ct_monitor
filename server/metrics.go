package server

import (
	"github.com/crtsh/ct_monitor/config"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"

	"go.uber.org/zap"
)

func init() {
	initFastHTTPMetrics()
}

var prometheusHandler = fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())

func metrics(ctx *fasthttp.RequestCtx) {
	ctx.SetUserValue("level", zap.InfoLevel)
	ctx.SetUserValue("msg", "Metrics")

	getFastHTTPMetrics()

	prometheusHandler(ctx)
}

// fasthttp metrics.
var serverLabel = [...]string{"monitoring"}
var fhConcurrency [len(serverLabel)]prometheus.Gauge
var fhOpenConnections [len(serverLabel)]prometheus.Gauge

func initFastHTTPMetrics() {
	// Configure prometheus gauges.
	for i := 0; i < len(serverLabel); i++ {
		fhConcurrency[i] = promauto.NewGauge(prometheus.GaugeOpts{
			Namespace:   config.ApplicationNamespace,
			Subsystem:   "fasthttp",
			Name:        "concurrency",
			Help:        "Number of currently served HTTP connections.",
			ConstLabels: map[string]string{"server": serverLabel[i]},
		})
		fhOpenConnections[i] = promauto.NewGauge(prometheus.GaugeOpts{
			Namespace:   config.ApplicationNamespace,
			Subsystem:   "fasthttp",
			Name:        "open",
			Help:        "Number of currently open HTTP connections.",
			ConstLabels: map[string]string{"server": serverLabel[i]},
		})
	}
}

func getFastHTTPMetrics() {
	// Get fasthttp metrics, and set the gauges.
	fhConcurrency[0].Set(float64(monitoringServer.GetCurrentConcurrency()))
	fhOpenConnections[0].Set(float64(monitoringServer.GetOpenConnectionsCount()))
}
