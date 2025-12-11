package pinakastra

import "embed"

// Embed web UI files
//go:embed web/templates/* web/static/css/* web/static/js/*
var WebFiles embed.FS

// Embed wordlists
//go:embed wordlists/*
var WordlistFiles embed.FS
