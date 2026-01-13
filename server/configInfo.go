package server

import (
	"fmt"
	"strings"

	"github.com/crtsh/ct_monitor/config"
	"github.com/crtsh/ct_monitor/utils"

	json "github.com/goccy/go-json"
	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

func configInfo(ctx *fasthttp.RequestCtx) {
	ctx.SetUserValue("level", zap.InfoLevel)
	ctx.SetUserValue("msg", "Configuration information")

	jsonString := ""
	if jmi, err := json.MarshalIndent(config.Config, "", "&nbsp; &nbsp; "); err != nil {
		jsonString = fmt.Sprintf("Error obtaining configuration information: %v", err)
	} else {
		jsonString = strings.ReplaceAll(utils.B2S(jmi), "\n", "<BR>")
	}

	ctx.SetContentType("text/html; charset=utf-8")
	ctx.SetBody(utils.S2B(fmt.Sprintf("<HTML><HEAD><TITLE>%s Configuration Information</TITLE></HEAD><BODY>%s</BODY></HTML>", config.ApplicationName, jsonString)))
}
