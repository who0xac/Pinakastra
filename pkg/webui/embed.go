package webui

import (
	"embed"
)

//go:embed ../../web/templates ../../web/static
var WebFiles embed.FS
