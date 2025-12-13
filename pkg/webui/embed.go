package webui

import (
	"embed"
)

//go:embed all:../../web
var WebFiles embed.FS
