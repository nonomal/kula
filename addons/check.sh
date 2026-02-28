#!/usr/bin/env bash

set -e

cd "$(dirname "$0")/.."

echo "Running go vet..."
go vet ./...

echo -e "\nRunning go test..."
go test -v -race ./...

if command -v golangci-lint &>/dev/null; then
    echo -e "\nRunning golangci-lint..."
    golangci-lint run ./...
else
    echo -e "\nSkipping golangci-lint (not installed)"
    echo "  Install: https://golangci-lint.run/welcome/install/"
fi

echo -e "\nAll checks passed!"
