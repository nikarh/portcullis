#!/usr/bin/env bash
# Runs every scenario. Runs as root inside the test VM; use e2e/run.sh from the host.
#
#   suite.sh
#   E2E_SCENARIOS="icc egress" suite.sh   only those scenarios
set -uo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SCENARIOS=(
  default-deny
  egress
  hostname
  icc
  dns-labels
  published-port
  invalid-labels
  restart
  spoofing
  fast-start
  dns-inspection
  monitor
  events
  alerts
)

# E2E_SCENARIOS="icc egress" runs only those.
if [[ -n "${E2E_SCENARIOS:-}" ]]; then
  read -ra SCENARIOS <<<"${E2E_SCENARIOS}"
fi

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

# Remove anything a previous, interrupted run may have left behind.
remove_leftovers() {
  nft delete table inet portcullis 2>/dev/null
  nft delete table bridge portcullis 2>/dev/null
  nft delete table inet pc_trace 2>/dev/null
  nft delete table bridge pc_trace 2>/dev/null
  return 0
}

setup() {
  remove_leftovers
  log "setting up the outside network"
  "${E2E_DIR}/outside.sh" up || exit 1

  # Hostname rules in lazy mode resolve on the Docker host.
  sed -i '/# portcullis-e2e$/d' /etc/hosts
  printf '198.51.100.3 api.test # portcullis-e2e\n198.51.100.4 other.test # portcullis-e2e\n' >>/etc/hosts

  log "building the tester image"
  docker build -q -t "${TESTER_IMAGE}" "${E2E_DIR}/images/tester" >/dev/null || exit 1
}

teardown() {
  stop_portcullis 2>/dev/null
  "${E2E_DIR}/outside.sh" down
  sed -i '/# portcullis-e2e$/d' /etc/hosts
}

assert_cleaned_up() {
  local leftovers=()
  nft list table inet portcullis >/dev/null 2>&1 && leftovers+=("inet table")
  nft list table bridge portcullis >/dev/null 2>&1 && leftovers+=("bridge table")
  if ((${#leftovers[@]})); then
    fail "rules removed on shutdown (left behind: ${leftovers[*]})"
  else
    pass "rules removed on shutdown"
  fi
}

setup
trap teardown EXIT

if start_portcullis; then
  for scenario in "${SCENARIOS[@]}"; do
    run_scenario "${scenario}"
  done
  stop_portcullis
  assert_cleaned_up
fi

log "deny action drop"
DENY_ACTION=drop
if start_portcullis; then
  for scenario in egress icc; do
    run_scenario "${scenario}"
  done
  stop_portcullis
  assert_cleaned_up
fi
DENY_ACTION=reject

if ((FAILURES > 0)); then
  log "${FAILURES} of ${CHECKS} checks failed; Portcullis log: ${PORTCULLIS_LOG}"
  exit 1
fi
log "all ${CHECKS} checks passed"
