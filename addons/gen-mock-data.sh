#!/bin/bash

set -e

cd "$(dirname "$0")/.."

echo "Building gen-mock-data..."

CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w" \
    -buildvcs=false \
    -o gen-mock-data \
    ./cmd/gen-mock-data/

echo "Done!"
