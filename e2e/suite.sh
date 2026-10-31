#!/usr/bin/env bash
# Runs every scenario against each firewall backend. Runs as root inside the test VM;
# use e2e/run.sh from the host.
#
#   suite.sh [backend...]    backends: nftables iptables (default: both)
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
  iptables -D DOCKER-USER -j PORTCULLIS_EGRESS 2>/dev/null
  local chain
  for chain in $(iptables-save -t filter | sed -n 's/^:\(PORTCULLIS_[A-Z0-9_]*\) .*/\1/p'); do
    iptables -F "${chain}"
  done
  for chain in $(iptables-save -t filter | sed -n 's/^:\(PORTCULLIS_[A-Z0-9_]*\) .*/\1/p'); do
    iptables -X "${chain}"
  done
  ipset list -n 2>/dev/null | grep -E '^pc_[ht]4_' | xargs -r -n1 ipset destroy
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
  nft list table inet portcullis >/dev/null 2>&1 && leftovers+=("nftables table")
  iptables-save -t filter | grep -qE '^:PORTCULLIS_|-j PORTCULLIS_' && leftovers+=("iptables chains")
  ipset list -n 2>/dev/null | grep -qE '^pc_[ht]4_' && leftovers+=("ipsets")
  if ((${#leftovers[@]})); then
    fail "rules removed on shutdown (left behind: ${leftovers[*]})"
  else
    pass "rules removed on shutdown"
  fi
}

setup
trap teardown EXIT

BACKENDS=("$@")
((${#BACKENDS[@]})) || BACKENDS=(nftables iptables)

for BACKEND in "${BACKENDS[@]}"; do
  log "backend ${BACKEND}"

  start_portcullis || continue
  for scenario in "${SCENARIOS[@]}"; do
    run_scenario "${scenario}"
  done
  stop_portcullis
  assert_cleaned_up

  start_portcullis --dns-mode proxy --dns-proxy-bind 198.51.100.1:53 || continue
  run_scenario hostname-proxy
  stop_portcullis
  assert_cleaned_up
done

if ((FAILURES > 0)); then
  log "${FAILURES} of ${CHECKS} checks failed; Portcullis log: ${PORTCULLIS_LOG}"
  exit 1
fi
log "all ${CHECKS} checks passed"
