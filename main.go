package main

import (
	"os"

	"github.com/who0xac/pinakastra/internal/cli"
	"github.com/who0xac/pinakastra/internal/config"
)

func init() {
	// Initialize embedded files
	config.EmbeddedResolvers = EmbeddedResolvers
	config.EmbeddedSubdomains = EmbeddedSubdomains
	config.EmbeddedDirectories = EmbeddedDirectories
}

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
