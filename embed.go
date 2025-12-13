package pinakastra

import "embed"

// WebFiles contains embedded web UI files
//go:embed web/templates web/static
var WebFiles embed.FS

// WordlistFiles contains embedded wordlist files
//go:embed wordlists
var WordlistFiles embed.FS
