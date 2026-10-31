#!/usr/bin/env bash
# Helpers for e2e scenarios. Runs as root inside the test VM, see e2e/suite.sh.

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${E2E_DIR}/.." && pwd)"
PORTCULLIS_BIN="${PROJECT_ROOT}/target/release/portcullis"
TESTER_IMAGE=portcullis-e2e-tester

FAILURES=0
CHECKS=0

log() { printf '[e2e] %s\n' "$*" >&2; }

pass() {
  CHECKS=$((CHECKS + 1))
  printf '  \033[32mok\033[0m   %s\n' "$*" >&2
}

fail() {
  CHECKS=$((CHECKS + 1))
  FAILURES=$((FAILURES + 1))
  printf '  \033[31mFAIL\033[0m %s\n' "$*" >&2
}

# --- compose projects -------------------------------------------------------------------

# Current scenario's compose project, set by run_scenario.
PROJECT=""
COMPOSE_FILE=""

dc() {
  docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" "$@"
}

# Run a command in the first container of a service.
in_svc() {
  local service="$1"
  shift
  dc exec -T "${service}" "$@"
}

# IPv4 address of a container (by compose service and replica number) on a compose network.
svc_ip() {
  local service="$1" network="$2" number="${3:-1}"
  local id
  id="$(docker ps -q \
    --filter "label=com.docker.compose.project=${PROJECT}" \
    --filter "label=com.docker.compose.service=${service}" \
    --filter "label=com.docker.compose.container-number=${number}")"
  [[ -n "${id}" ]] || return 1
  docker inspect -f "{{(index .NetworkSettings.Networks \"${PROJECT}_${network}\").IPAddress}}" "${id}"
}

# --- connectivity probes, each succeeds only if the expected peer answered --------------

# tcp <service> <address> <port>: the listener echoes its own address back.
tcp() {
  local service="$1" address="$2" port="$3"
  in_svc "${service}" sh -c "nc -w 1 ${address} ${port} </dev/null" 2>/dev/null | grep . >/dev/null
}

# udp <service> <address> <port>
udp() {
  local service="$1" address="$2" port="$3"
  in_svc "${service}" sh -c "printf ping | socat -t1 -T1 - UDP:${address}:${port}" 2>/dev/null | grep . >/dev/null
}

# dns <service> <server> <name>: query a resolver directly.
dns() {
  local service="$1" server="$2" name="$3"
  in_svc "${service}" dig +time=1 +tries=1 +short "@${server}" "${name}" 2>/dev/null | grep . >/dev/null
}

# resolve <service> <name>: resolve through the container's configured resolver.
resolve() {
  local service="$1" name="$2"
  in_svc "${service}" sh -c "nslookup -timeout=3 ${name} 2>/dev/null | grep -A1 '^Name:' | grep -q Address"
}

# --- assertions ---------------------------------------------------------------------------

# Checks run in the background, in parallel; flush_checks waits for them and reports the
# results in the order the checks were declared.
RESULTS_DIR="$(mktemp -d)"
CHECK_SEQ=0
CHECK_PIDS=()

# check <description> <command...>: run in the background, record ok/FAIL.
check() {
  local description="$1"
  shift
  local file
  file="${RESULTS_DIR}/$(printf '%04d' "${CHECK_SEQ}")"
  CHECK_SEQ=$((CHECK_SEQ + 1))
  (
    if "$@"; then
      printf 'ok %s\n' "${description}" >"${file}"
    else
      printf 'FAIL %s\n' "${description}" >"${file}"
    fi
  ) &
  CHECK_PIDS+=($!)
}

flush_checks() {
  ((${#CHECK_PIDS[@]})) && wait "${CHECK_PIDS[@]}"
  CHECK_PIDS=()
  local file status description
  for file in "${RESULTS_DIR}"/*; do
    [[ -f "${file}" ]] || continue
    read -r status description <"${file}"
    if [[ "${status}" == ok ]]; then
      pass "${description}"
    else
      fail "${description}"
    fi
    rm -f "${file}"
  done
}

retry() {
  local attempt
  for attempt in $(seq 10); do
    "$@" && return 0
    sleep 1
  done
  return 1
}

negate() { ! "$@"; }

# allowed <description> <probe...>: retried for a while, since rules apply asynchronously.
allowed() {
  local description="$1"
  shift
  check "allowed: ${description}" retry "$@"
}

# blocked <description> <probe...>: run once; call wait_managed first so rules are in place.
blocked() {
  local description="$1"
  shift
  check "blocked: ${description}" negate "$@"
}

# Wait until Portcullis has installed rules for a container's address.
wait_managed() {
  local address="$1"
  if [[ -z "${address}" ]]; then
    fail "wait_managed: no address given"
    return 1
  fi
  local attempt
  for attempt in $(seq 30); do
    if ruleset | grep -F -- "${address}" >/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  fail "rules for ${address} were not installed"
  sed 's/\x1b\[[0-9;]*m//g' "${PORTCULLIS_LOG}" | grep -E 'ERROR|WARN' | tail -5 >&2
  return 1
}

ruleset() {
  case "${BACKEND}" in
    nftables) nft list table inet portcullis 2>/dev/null ;;
    iptables) iptables-save -t filter 2>/dev/null | grep -E '^-A PORTCULLIS_EGRESS ' ;;
  esac
}

# --- portcullis ----------------------------------------------------------------------------

PORTCULLIS_PID=""
PORTCULLIS_LOG=/tmp/portcullis-e2e.log

# start_portcullis [extra args...]: start in the background and wait for the first apply.
start_portcullis() {
  : >"${PORTCULLIS_LOG}"
  "${PORTCULLIS_BIN}" --firewall-backend "${BACKEND}" --log-level debug "$@" \
    >>"${PORTCULLIS_LOG}" 2>&1 &
  PORTCULLIS_PID=$!
  local attempt
  for attempt in $(seq 100); do
    if grep -q 'firewall rules applied' "${PORTCULLIS_LOG}"; then
      return 0
    fi
    if ! kill -0 "${PORTCULLIS_PID}" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  fail "portcullis did not start (${BACKEND})"
  tail -20 "${PORTCULLIS_LOG}" >&2
  return 1
}

stop_portcullis() {
  [[ -n "${PORTCULLIS_PID}" ]] || return 0
  if ! kill -0 "${PORTCULLIS_PID}" 2>/dev/null; then
    fail "portcullis exited unexpectedly"
    tail -20 "${PORTCULLIS_LOG}" >&2
  else
    kill -TERM "${PORTCULLIS_PID}"
    wait "${PORTCULLIS_PID}" || fail "portcullis exited with an error on SIGTERM"
  fi
  PORTCULLIS_PID=""
}

# --- scenarios -----------------------------------------------------------------------------

# run_scenario <name>: bring up e2e/scenarios/<name>/compose.yml, run its test.sh, tear down.
run_scenario() {
  local name="$1"
  local dir="${E2E_DIR}/scenarios/${name}"
  PROJECT="pc-${name}"
  COMPOSE_FILE="${dir}/compose.yml"
  log "scenario ${name} (${BACKEND})"

  dc down -v --remove-orphans >/dev/null 2>&1 || true
  if ! dc up -d --quiet-pull >/dev/null 2>&1; then
    fail "${name}: compose up failed"
    dc up -d
    return
  fi
  # shellcheck source=/dev/null
  source "${dir}/test.sh"
  flush_checks
  dc down -v --remove-orphans >/dev/null 2>&1 || true
}
