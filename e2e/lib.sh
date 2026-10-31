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

# --- probes --------------------------------------------------------------------------------
#
# A probe prints what the client saw (stdout and stderr). `allowed` and `blocked` judge that
# output: an allowed probe must show the peer's answer, a blocked one must show the
# rejection Portcullis sends ("Host is unreachable"). A timeout never passes either.

# tcp <service> <address> <port>
tcp() {
  in_svc "$1" nc -v -w 3 "$2" "$3" </dev/null 2>&1
}

# udp <service> <address> <port>: the server answers with its address or hostname.
udp() {
  in_svc "$1" sh -c "printf ping | socat -t3 -T3 - UDP:$2:$3" 2>&1
}

# dns <service> <server> <name>: query a resolver directly.
dns() {
  in_svc "$1" dig +time=3 +tries=1 +short "@$2" "$3" 2>&1
}

# resolve <service> <name>: resolve through Docker's DNS server in the container.
resolve() {
  in_svc "$1" nslookup -timeout=3 "$2" 2>&1
}

# from_outside <address> <port>: connect from the outside network.
from_outside() {
  ip netns exec pc-outside nc -v -w 3 "$1" "$2" </dev/null 2>&1
}

# answered <probe> <output>
answered() {
  case "$1" in
    tcp | from_outside) grep -q 'succeeded' <<<"$2" ;;
    udp) grep -v 'socat\[' <<<"$2" | grep -q . ;;
    dns) grep -Eq '^[0-9a-f.:]+$' <<<"$2" ;;
    resolve) grep -A1 '^Name:' <<<"$2" | grep -q '^Address' ;;
    *) return 1 ;;
  esac
}

# rejected <probe> <output>
rejected() {
  case "$1" in
    # Docker's DNS server answers SERVFAIL when its upstream rejects the query.
    resolve) grep -Eq 'SERVFAIL|unreachable' <<<"$2" ;;
    *) grep -Eqi 'unreachable|no route to host' <<<"$2" ;;
  esac
}

# --- assertions ---------------------------------------------------------------------------

# Checks run in the background, in parallel; flush_checks waits for them and reports the
# results in the order the checks were declared, with the probe output of failed ones.
RESULTS_DIR="$(mktemp -d)"
CHECK_SEQ=0
CHECK_PIDS=()
# drop mode verifies blocked checks through packet tracing, which needs one check at a time.
DENY_ACTION=reject

# check <description> <command...>: run, record ok/FAIL and the command's output.
check() {
  local description="$1"
  shift
  local file
  file="${RESULTS_DIR}/$(printf '%04d' "${CHECK_SEQ}")"
  CHECK_SEQ=$((CHECK_SEQ + 1))
  (
    if "$@" >"${file}.out" 2>&1; then
      printf 'ok %s\n' "${description}" >"${file}"
    else
      printf 'FAIL %s\n' "${description}" >"${file}"
    fi
  ) &
  CHECK_PIDS+=($!)
  if [[ "${DENY_ACTION}" == drop ]]; then
    wait "${CHECK_PIDS[-1]}"
  fi
}

flush_checks() {
  ((${#CHECK_PIDS[@]})) && wait "${CHECK_PIDS[@]}"
  CHECK_PIDS=()
  local file status description
  for file in "${RESULTS_DIR}"/[0-9]*; do
    [[ -f "${file}" && "${file}" != *.out ]] || continue
    read -r status description <"${file}"
    if [[ "${status}" == ok ]]; then
      pass "${description}"
    else
      fail "${description}"
      sed 's/^/         | /' "${file}.out" | tail -5 >&2
    fi
    rm -f "${file}" "${file}.out"
  done
}

expect_answer() {
  local output
  output="$("$@")"
  printf '%s\n' "${output}"
  answered "$1" "${output}"
}

expect_rejection() {
  local output
  output="$("$@")"
  printf '%s\n' "${output}"
  rejected "$1" "${output}"
}

# expect_drop <probe> <service> <args...>: send the probe until a packet trace shows
# Portcullis dropping it. Only for the routed and bridged probes of a container.
expect_drop() {
  local service="$2"
  local source
  source="$(in_svc "${service}" hostname -i | awk '{print $1}')"
  local family
  for family in inet bridge; do
    nft -f - <<NFT
table ${family} pc_trace {
  chain trace {
    type filter hook prerouting priority -500
    ip saddr ${source} meta nftrace set 1
  }
}
NFT
  done
  local found=1 attempt line
  coproc TRACE { exec nft monitor trace; }
  for attempt in $(seq 20); do
    "$@" >/dev/null 2>&1 &
    while IFS= read -r -t 0.5 line <&"${TRACE[0]}"; do
      if [[ "${line}" == *portcullis* && "${line}" == *"verdict drop"* ]]; then
        printf '%s\n' "${line}"
        found=0
        break 2
      fi
    done
  done
  kill "${TRACE_PID}" 2>/dev/null
  nft delete table inet pc_trace
  nft delete table bridge pc_trace
  return "${found}"
}

# allowed <description> <probe...>
allowed() {
  local description="$1"
  shift
  check "allowed: ${description}" expect_answer "$@"
}

# blocked <description> <probe...>: call wait_managed first so rules are in place.
blocked() {
  local description="$1"
  shift
  if [[ "${DENY_ACTION}" == drop && "$1" != resolve ]]; then
    check "blocked: ${description}" expect_drop "$@"
  else
    check "blocked: ${description}" expect_rejection "$@"
  fi
}

# wait_managed <address...>: block until Portcullis reports rules in place for them.
wait_managed() {
  local address
  for address in "$@"; do
    if [[ -z "${address}" ]]; then
      fail "wait_managed: empty address"
      return 1
    fi
  done
  if ! python3 "${E2E_DIR}/wait-applied.py" "${EVENTS_SOCKET}" 10 "$@"; then
    fail "rules for $* were not applied"
    sed 's/\x1b\[[0-9;]*m//g' "${PORTCULLIS_LOG}" | grep -E 'ERROR|WARN' | tail -5 >&2
    return 1
  fi
}

# --- portcullis ----------------------------------------------------------------------------

PORTCULLIS_PID=""
PORTCULLIS_LOG=/tmp/portcullis-e2e.log
EVENTS_SOCKET=/run/portcullis-e2e.sock

# start_portcullis [extra args...]: start in the background and wait for the first apply.
start_portcullis() {
  : >"${PORTCULLIS_LOG}"
  rm -f "${EVENTS_SOCKET}"
  # Watch for the socket before starting, so its creation can't be missed. Portcullis
  # creates it under a temporary name and renames it into place.
  local line
  coproc SOCKET_WATCH {
    exec inotifywait -q -t 10 -e moved_to --include "${EVENTS_SOCKET##*/}" \
      --format %f "${EVENTS_SOCKET%/*}" 2>&1
  }
  "${PORTCULLIS_BIN}" --log-level debug --events-socket "${EVENTS_SOCKET}" \
    --deny-action "${DENY_ACTION}" "$@" >>"${PORTCULLIS_LOG}" 2>&1 &
  PORTCULLIS_PID=$!
  # Then wait for the first apply on the event stream.
  if read -r line <&"${SOCKET_WATCH[0]}" && [[ -S "${EVENTS_SOCKET}" ]] \
    && python3 "${E2E_DIR}/wait-applied.py" "${EVENTS_SOCKET}" 10; then
    return 0
  fi
  fail "portcullis did not start"
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
  log "scenario ${name}"

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
