package server

import (
	"time"

	"github.com/crtsh/ct_monitor/certwatch"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

func healthz(ctx *fasthttp.RequestCtx) {
	ctx.SetUserValue("level", zap.InfoLevel)
	ctx.SetUserValue("msg", "Health check")

	statusCode := fasthttp.StatusOK

	// Test the health of a "certwatch" postgres database connection.
	start := time.Now()
	if err := certwatch.DatabaseWatcherPing(); err != nil {
		ctx.SetUserValue("error", err)
		statusCode = fasthttp.StatusServiceUnavailable
	}
	certwatchPingTime := time.Since(start)

	ctx.SetUserValue("zap_fields", []zap.Field{
		zap.Duration("certwatch_ping_ns", certwatchPingTime),
	})

	// Return a response.
	ctx.SetContentType("text/plain")
	ctx.SetStatusCode(statusCode)
	if string(ctx.Method()) != "HEAD" {
		if statusCode == fasthttp.StatusOK {
			ctx.SetBody([]byte("OK"))
		} else {
			ctx.SetBody([]byte("ERROR"))
		}
	}
}
