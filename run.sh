#!/bin/bash
set -euo pipefail

TAGS="${GO_TAGS:-with_utls with_quic with_grpc with_wireguard with_gvisor}"

exec go run -tags "$TAGS" ./cmd/easy_proxies "$@"
