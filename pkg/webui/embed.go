package webui

import (
	"embed"
)

//go:embed ../../web/templates/* ../../web/static/css/* ../../web/static/js/*
var WebFiles embed.FS
