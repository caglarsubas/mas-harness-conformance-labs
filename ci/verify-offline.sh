#!/bin/bash
set -euo pipefail

refuse() {
  echo "offline wrapper refused: $1" >&2
  exit 2
}

readonly packet_path="${HARNESS_TASK_PACKET:-}"
[[ "${HARNESS_OFFLINE_ENFORCED:-}" == "1" ]] || refuse "OS isolation marker is absent"
[[ "${HARNESS_OFFLINE_BACKEND:-}" == "darwin-sandbox" ]] || refuse "unsupported isolation backend"
[[ -n "${HARNESS_OFFLINE_SESSION_ID:-}" ]] || refuse "offline session ID is absent"
[[ -n "$packet_path" && -f "$packet_path" && ! -L "$packet_path" ]] || refuse "packet path is unavailable"
[[ -z "${HARNESS_WARM_SOURCE_ROOTS:-}" ]] || refuse "warm-source authority reached repository code"
[[ "${UV_OFFLINE:-}" == "1" && "${UV_FROZEN:-}" == "1" && "${UV_NO_SYNC:-}" == "1" ]] || refuse "offline uv policy is absent"

unset HARNESS_TASK_PACKET
exec python3 ci/run_packet.py "$packet_path"
