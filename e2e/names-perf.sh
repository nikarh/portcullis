#!/usr/bin/env bash
# Measures what name checks of host: rules cost. Runs as root inside the test VM (see
# vm.sh), next to nothing else; it removes what it starts.
#
#   e2e/vm.sh ssh sudo /home/debian/portcullis/e2e/names-perf.sh
#   NAMES_PERF_COUNT=5000 ... names-perf.sh
#
# Two containers reach the same servers of the outside network (outside.sh): one through a
# host: rule, whose connections are checked, one through an ip: rule, whose aren't. For
# each it prints the latency of TLS handshakes, of requests on a keep-alive HTTP
# connection, and of new QUIC flows (median, 90th and 99th percentile), with Portcullis's
# CPU time for them; the throughput of a TLS download, and of plain TCP with and without
# the test of the connection mark that every packet passes; and Portcullis's CPU time
# while many keep-alive connections idle, with connection tracking asked about them every
# NAMES_PERF_IDLE_CHECK seconds.
set -uo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${PORTCULLIS_BIN:-${E2E_DIR}/../target/release/portcullis}"
COUNT="${NAMES_PERF_COUNT:-2000}"
IDLE="${NAMES_PERF_IDLE:-1000}"
IDLE_CHECK="${NAMES_PERF_IDLE_CHECK:-5}"
TESTER_IMAGE=portcullis-e2e-tester
WORK="$(mktemp -d /tmp/portcullis-names-perf.XXXXXX)"
PREFIX="pcnamesperf"
NS=pc-outside
API=198.51.100.3
PID=""

log() { printf '[names-perf] %s\n' "$*" >&2; }

cleanup() {
  [[ -n "${PID}" ]] && kill -TERM "${PID}" 2>/dev/null && wait "${PID}" 2>/dev/null
  docker ps -aq --filter "label=${PREFIX}" | xargs -r docker rm -f >/dev/null
  docker network ls -q --filter "label=${PREFIX}" | xargs -r docker network rm >/dev/null
  "${BIN}" cleanup --state-dir "${WORK}/state" >/dev/null 2>&1
  "${E2E_DIR}/outside.sh" down >/dev/null 2>&1
  sed -i '/# portcullis-names-perf$/d' /etc/hosts
  [[ -n "${KEEP_WORK:-}" ]] || rm -rf "${WORK}"
}
trap cleanup EXIT

# Portcullis's CPU time so far, in milliseconds.
cpu() { awk '{print ($14 + $15) * 10}' "/proc/${PID}/stat"; }

# measure <container> <bench.py arguments...>: the measurement, and the CPU it took.
measure() {
  local container="$1" before result
  shift
  before="$(cpu)"
  result="$(docker exec "${container}" python3 /perf/bench.py "$@" 2>&1)"
  log "${container#"${PREFIX}-"}: ${result}; Portcullis CPU $(($(cpu) - before)) ms"
}

main() {
  [[ ${EUID} -eq 0 ]] || { log "run as root"; exit 1; }
  "${E2E_DIR}/outside.sh" up || exit 1
  printf '%s api.test # portcullis-names-perf\n' "${API}" >>/etc/hosts
  ip netns exec "${NS}" setsid socat "OPENSSL-LISTEN:9443,fork,reuseaddr,cert=/run/portcullis-e2e/tls.crt,key=/run/portcullis-e2e/tls.key,verify=0" \
    SYSTEM:'head -c 2G /dev/zero' >/dev/null 2>&1 &
  ip netns exec "${NS}" setsid socat TCP-LISTEN:9100,fork,reuseaddr SYSTEM:'head -c 4G /dev/zero' \
    >/dev/null 2>&1 &
  docker build -q -t "${TESTER_IMAGE}" "${E2E_DIR}/images/tester" >/dev/null || exit 1

  PORTCULLIS_NAME_IDLE_CHECK="${IDLE_CHECK}" "${BIN}" --log-level warn --log-allowed never \
    --state-dir "${WORK}/state" 2>"${WORK}/portcullis.log" >/dev/null &
  PID=$!
  docker network create --label "${PREFIX}" --label portcullis.enable=true "${PREFIX}" >/dev/null
  local container
  for container in checked:host:api.test address:ip:${API}; do
    docker run -d --name "${PREFIX}-${container%%:*}" --network "${PREFIX}" --label "${PREFIX}" \
      -v "${E2E_DIR}/perf:/perf:ro" \
      --label "portcullis.egress.api=${container#*:},tcp:8081,8443,9100,9443,udp:9000" \
      "${TESTER_IMAGE}" >/dev/null
  done
  sleep 3

  for container in address checked address checked; do
    measure "${PREFIX}-${container}" tls "${API}" 8443 api.test "${COUNT}"
  done
  for container in address checked; do
    measure "${PREFIX}-${container}" http "${API}" 8081 api.test "${COUNT}"
    measure "${PREFIX}-${container}" quic "${API}" 9000 api.test "${COUNT}"
  done
  for container in address checked address checked; do
    measure "${PREFIX}-${container}" bulk "${API}" 9443 api.test tls
  done
  for _ in 1 2 3; do
    measure "${PREFIX}-address" bulk "${API}" 9100 api.test tcp
  done
  local handle
  handle="$(nft -a list chain inet portcullis forward | awk '/jump name_check/ {print $NF}')"
  nft delete rule inet portcullis forward handle "${handle}"
  log "without the test of the connection mark:"
  for _ in 1 2 3; do
    measure "${PREFIX}-address" bulk "${API}" 9100 api.test tcp
  done
  measure "${PREFIX}-checked" idle "${API}" 8081 api.test "${IDLE}" 30
  grep -E 'WARN|ERROR' "${WORK}/portcullis.log" >&2
}

main "$@"
