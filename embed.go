package main

import (
	_ "embed"
)

//go:embed configs/resolvers.txt
var EmbeddedResolvers []byte

//go:embed configs/wordlists/subdomains.txt
var EmbeddedSubdomains []byte

//go:embed configs/wordlists/directories.txt
var EmbeddedDirectories []byte
