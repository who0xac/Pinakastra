package main

import "embed"

// Embed web UI files (relative from cmd/pinakastra/)
//go:embed ../../web/templates ../../web/static
var WebFiles embed.FS

// Embed wordlists (relative from cmd/pinakastra/)
//go:embed ../../wordlists
var WordlistFiles embed.FS
