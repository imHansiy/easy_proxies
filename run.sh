#!/bin/bash
set -euo pipefail

TAGS="${EASY_PROXIES_GO_TAGS:-with_utls with_quic with_grpc with_wireguard with_gvisor}"

if [ "$#" -eq 0 ]; then
  set -- --config config.yaml
fi

exec go run -tags "$TAGS" ./cmd/easy_proxies "$@"
