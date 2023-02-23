package server

import (
	"fmt"
	"time"

	"github.com/crtsh/ct_monitor/config"
	"github.com/crtsh/ct_monitor/logger"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

var monitoringServer *fasthttp.Server

func monitoringHandler(ctx *fasthttp.RequestCtx) {
	switch string(ctx.Path()) {
	case "/healthz":
		healthz(ctx)
	case "/metrics":
		metrics(ctx)
	default:
		if !profilingHandler(ctx) {
			ctx.NotFound()
		}
	}

	logger.LogRequest(ctx)
}

func Run() {
	logger.Logger.Info("Starting MonitoringServer")
	monitoringServer = &fasthttp.Server{
		Handler:               monitoringHandler,
		CloseOnShutdown:       true,
		ReadTimeout:           10 * time.Second,
		IdleTimeout:           10 * time.Second,
		NoDefaultServerHeader: true,
	}
	go func() {
		if err := monitoringServer.ListenAndServe(fmt.Sprintf(":%d", config.Config.Server.MonitoringPort)); err != nil {
			logger.Logger.Fatal("monitoringServer.ListenAndServe failed", zap.Error(err))
		}
	}()
}

func Shutdown() {
	logger.Logger.Info("Stopping MonitoringServer (gracefully)")
	if err := monitoringServer.Shutdown(); err != nil {
		logger.Logger.Error("monitoringServer.Shutdown failed", zap.Error(err))
	}
	logger.Logger.Info("Stopped MonitoringServer")
}
