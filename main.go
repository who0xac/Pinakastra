package main

import (
	"os"

	"github.com/who0xac/pinakastra/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
