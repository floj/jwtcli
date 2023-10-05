#!/usr/bin/env bash
set -euo pipefail
scriptDir=$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)

( (
	cd "$scriptDir"
	CGO_ENABLED=0 go build -v -trimpath -ldflags '-s -w' .
))
