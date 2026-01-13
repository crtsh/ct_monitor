package server

import (
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/crtsh/ct_monitor/config"
	"github.com/crtsh/ct_monitor/utils"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

func buildInfo(ctx *fasthttp.RequestCtx) {
	ctx.SetUserValue("level", zap.InfoLevel)
	ctx.SetUserValue("msg", "Build information")

	buildInfoString := "Build information unavailable"
	if bi, ok := debug.ReadBuildInfo(); ok {
		buildInfoString = strings.ReplaceAll(bi.String(), "\n", "<BR>")
	}

	ctx.SetContentType("text/html; charset=utf-8")
	ctx.SetBody(utils.S2B(fmt.Sprintf("<HTML><HEAD><TITLE>%s Build Information</TITLE></HEAD><BODY>%s</BODY></HTML>", config.ApplicationName, buildInfoString)))
}
