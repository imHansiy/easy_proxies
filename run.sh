#!/bin/bash
set -euo pipefail

TAGS="${GO_TAGS:-with_utls with_quic with_grpc with_wireguard with_gvisor}"

if [ -z "${1:-}" ]; then
  echo "Running easy-proxies (local)" >&2
  echo "- Backend: go run ./cmd/easy_proxies" >&2
  echo "- Build frontend once: (cd web && npm install && npm run build)" >&2
  echo "- Open WebUI: http://127.0.0.1:9090" >&2
  echo >&2
fi

exec go run -tags "$TAGS" ./cmd/easy_proxies "$@"
