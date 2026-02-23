#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORTCULLIS_BIN="${PROJECT_ROOT}/target/release/portcullis"

log() {
  printf '[e2e] %s\n' "$*"
}

require_tools() {
  command -v docker >/dev/null 2>&1 || { echo 'docker is required'; exit 1; }
  docker compose version >/dev/null 2>&1 || { echo 'docker compose is required'; exit 1; }
}

ensure_binary() {
  if [[ ! -x "${PORTCULLIS_BIN}" ]]; then
    log "building release binary"
    (cd "${PROJECT_ROOT}" && cargo build --release)
  fi
}

dc() {
  local compose_file="$1"
  shift
  docker compose -f "${compose_file}" "$@"
}

apply_policy() {
  local log_level="${1:-info}"
  log "applying firewall policy"
  "${PORTCULLIS_BIN}" --firewall-backend auto --log-level "${log_level}"
}

expect_cmd_succeeds() {
  local description="$1"
  shift
  if "$@"; then
    log "PASS: ${description}"
    return 0
  fi
  log "FAIL: ${description}"
  return 1
}

expect_cmd_fails() {
  local description="$1"
  shift
  if "$@"; then
    log "FAIL: ${description}"
    return 1
  fi
  log "PASS: ${description}"
  return 0
}

check_tcp() {
  local compose_file="$1"
  local host="$2"
  local port="$3"
  dc "${compose_file}" exec -T tester sh -lc "nc -z -w 2 ${host} ${port}"
}

check_udp_echo() {
  local compose_file="$1"
  local host="$2"
  local port="$3"
  dc "${compose_file}" exec -T tester sh -lc "printf 'ping' | socat -T2 - UDP:${host}:${port} | grep -q ping"
}

cleanup() {
  local compose_file="$1"
  dc "${compose_file}" down -v --remove-orphans || true
}
