#!/usr/bin/env bash
set -euo pipefail

go test ./...
go vet ./...
go build -o bin/seavault ./cmd/seavault
./scripts/smoke-test.sh ./bin/seavault
./scripts/gui-api-smoke-test.sh ./bin/seavault
./scripts/rsync-put-smoke-test.sh ./bin/seavault
./scripts/rclone-local-smoke-test.sh ./bin/seavault
make cross
