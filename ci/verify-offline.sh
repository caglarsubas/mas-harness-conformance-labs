#!/bin/bash
set -euo pipefail

readonly expected_packet_sha256="2ad6741244eb83c152b0880ffb3518b10a02d5cc65bf2e1012b879866069de48"
readonly packet_path="${HARNESS_TASK_PACKET:-}"

refuse() {
  echo "offline wrapper refused: $1" >&2
  exit 2
}

packet_digest() {
  /usr/bin/shasum -a 256 "$packet_path" | /usr/bin/awk '{print $1}'
}

[[ "${HARNESS_OFFLINE_ENFORCED:-}" == "1" ]] || refuse "OS isolation marker is absent"
[[ "${HARNESS_OFFLINE_BACKEND:-}" == "darwin-sandbox" ]] || refuse "unsupported isolation backend"
[[ -n "${HARNESS_OFFLINE_SESSION_ID:-}" ]] || refuse "offline session ID is absent"
[[ -n "$packet_path" && -f "$packet_path" && ! -L "$packet_path" ]] || refuse "packet path is unavailable"
[[ "$(packet_digest)" == "$expected_packet_sha256" ]] || refuse "packet digest mismatch"
[[ -z "${HARNESS_WARM_SOURCE_ROOTS:-}" ]] || refuse "warm-source authority reached repository code"
[[ "${UV_OFFLINE:-}" == "1" && "${UV_FROZEN:-}" == "1" && "${UV_NO_SYNC:-}" == "1" ]] || refuse "offline uv policy is absent"

unset HARNESS_TASK_PACKET

run_phase() {
  "$@"
  [[ "$(packet_digest)" == "$expected_packet_sha256" ]] || refuse "packet changed during acceptance"
}

run_phase python3 ci/network_canary.py
run_phase make prefetch
run_phase make meta-conformance
run_phase make build-reproducible
run_phase make zero-bill
run_phase make acceptance-package-contract

echo "packet=$expected_packet_sha256 phases=prefetch,offline session=${HARNESS_OFFLINE_SESSION_ID}"
