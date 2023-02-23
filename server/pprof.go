package server

import (
	"bytes"
	"net/http"
	"net/http/pprof"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"

	"go.uber.org/zap"
)

// Adapted from https://github.com/dgryski/trifles/blob/master/fastpprof/main.go
var pprofHandler fasthttp.RequestHandler

func init() {
	pprofMux := http.NewServeMux()
	registerPProf(pprofMux.HandleFunc)
	pprofHandler = fasthttpadaptor.NewFastHTTPHandler(pprofMux)
}

func registerPProf(h func(string, func(http.ResponseWriter, *http.Request))) {
	h("/debug/pprof/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pprof.Index(w, r)
	})
	h("/debug/pprof/cmdline", pprof.Cmdline)
	h("/debug/pprof/profile", pprof.Profile)
	h("/debug/pprof/symbol", pprof.Symbol)
	h("/debug/pprof/block", pprof.Handler("block").ServeHTTP)
	h("/debug/pprof/heap", pprof.Handler("heap").ServeHTTP)
	h("/debug/pprof/goroutine", pprof.Handler("goroutine").ServeHTTP)
	h("/debug/pprof/threadcreate", pprof.Handler("threadcreate").ServeHTTP)
}

func profilingHandler(ctx *fasthttp.RequestCtx) bool {
	switch {
	case bytes.Equal(ctx.Path(), []byte("/debug/pprof")):
		ctx.Redirect("/debug/pprof/", fasthttp.StatusMovedPermanently)
	case bytes.HasPrefix(ctx.Path(), []byte("/debug/pprof/")):
		ctx.SetUserValue("level", zap.InfoLevel)
		ctx.SetUserValue("msg", "Profiling")
		pprofHandler(ctx)
	default:
		return false
	}

	return true
}
