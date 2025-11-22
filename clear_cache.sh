#!/bin/bash

echo "Clearing Go module cache..."
go clean -modcache

echo "Removing pinakastra from GOPATH/bin..."
rm -f $(go env GOPATH)/bin/pinakastra

echo "Cache cleared! Now install with:"
echo "go install github.com/who0xac/pinakastra@latest"
