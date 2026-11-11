#!/usr/bin/env bash
# Measures Portcullis under load: many containers on many networks, churn, and floods of
# denied connections and DNS lookups. Runs as root inside the test VM (see vm.sh), next to
# nothing else; it removes what it starts.
#
#   e2e/vm.sh ssh sudo /home/debian/portcullis/e2e/stress.sh
#   STRESS_CONTAINERS=1000 STRESS_NETWORKS=40 ... stress.sh
#
# Prints the time and number of updates, Portcullis's CPU time and memory, and the size of
# its rules after each phase.
set -uo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${PORTCULLIS_BIN:-${E2E_DIR}/../target/release/portcullis}"
NETWORKS="${STRESS_NETWORKS:-20}"
CONTAINERS="${STRESS_CONTAINERS:-500}"
CHURN_ROUNDS="${STRESS_CHURN_ROUNDS:-10}"
CHURN_BATCH="${STRESS_CHURN_BATCH:-20}"
PARALLEL="${STRESS_PARALLEL:-16}"
IMAGE="${STRESS_IMAGE:-busybox:latest}"
TESTER_IMAGE=portcullis-e2e-tester
FLOOD_SECONDS="${STRESS_FLOOD_SECONDS:-20}"
WORK="$(mktemp -d /tmp/portcullis-stress.XXXXXX)"
SOCKET="${WORK}/events.sock"
LOG="${WORK}/portcullis.log"
PREFIX="pcstress"
PID=""

log() { printf '[stress] %s\n' "$*" >&2; }

cleanup() {
  [[ -n "${PID}" ]] && kill -TERM "${PID}" 2>/dev/null && wait "${PID}" 2>/dev/null
  docker ps -aq --filter "label=${PREFIX}" | xargs -r docker rm -f >/dev/null
  docker network ls -q --filter "label=${PREFIX}" | xargs -r docker network rm >/dev/null
  "${BIN}" cleanup --state-dir "${WORK}/state" >/dev/null 2>&1
  "${E2E_DIR}/outside.sh" down >/dev/null 2>&1
  [[ -n "${KEEP_WORK:-}" ]] || rm -rf "${WORK}"
}
trap cleanup EXIT

# Counts updates and their duration from the log ("applying" to "applied").
updates_since() {
  local from="$1"
  tail -n "+${from}" "${LOG}" | python3 -c '
import json, sys, datetime
start = None; n = 0; total = 0.0; worst = 0.0
for line in sys.stdin:
    try: e = json.loads(line)
    except ValueError: continue
    msg = e.get("fields", {}).get("message", "")
    t = datetime.datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).timestamp()
    if msg == "applying nftables changes": start = t
    elif msg == "firewall rules applied" and start is not None:
        d = t - start; n += 1; total += d; worst = max(worst, d); start = None
avg = total / n * 1000 if n else 0
print(f"updates={n} total={total:.2f}s avg={avg:.1f}ms max={worst*1000:.1f}ms")
'
}

# CPU time (user+sys, seconds), current and peak resident memory (MiB).
usage() {
  local stat ticks
  read -ra stat <"/proc/${PID}/stat"
  ticks="$(getconf CLK_TCK)"
  awk -v u="${stat[13]}" -v s="${stat[14]}" -v t="${ticks}" \
    -v rss="$(awk '/VmRSS/{print $2}' "/proc/${PID}/status")" \
    -v hwm="$(awk '/VmHWM/{print $2}' "/proc/${PID}/status")" \
    'BEGIN { printf "cpu=%.2fs rss=%.1fMiB peak=%.1fMiB", (u+s)/t, rss/1024, hwm/1024 }'
}

rules() {
  printf 'rules: inet=%s lines, bridge=%s lines, saved=%s KiB' \
    "$(nft list table inet portcullis | wc -l)" "$(nft list table bridge portcullis | wc -l)" \
    "$(( $(stat -c %s "${WORK}/state/rules.nft") / 1024 ))"
}

report() {
  local phase="$1" from="$2" started="$3"
  log "${phase}: $(awk -v s="${started}" -v e="$(date +%s.%N)" 'BEGIN{printf "%.2fs", e-s}') $(updates_since "${from}")"
  log "${phase}: $(usage); $(rules)"
}

lines() { wc -l <"${LOG}"; }

# wait_applied <timeout> <address>...: until an update lists all of them.
wait_applied() {
  local timeout="$1"
  shift
  python3 "${E2E_DIR}/wait-applied.py" "${SOCKET}" "${timeout}" "$@"
}

address_of() {
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$@"
}

run_container() {
  local name="$1" net="$2" peer="$3"
  docker run -d -q --name "${name}" --label "${PREFIX}=1" --network "${net}" \
    --label portcullis.egress.api=ip:198.51.100.3,tcp:443,tcp:80 \
    --label portcullis.egress.ranges=ip:203.0.113.0/24,tcp:8000-8100,udp:9000 \
    --label portcullis.egress.name=host:example.invalid,tcp:443 \
    --label portcullis.icc.mode=allow-listed \
    --label "portcullis.icc.allow.peer=container:${peer},tcp:5432" \
    --label portcullis.limit.new-connections=50 \
    "${IMAGE}" sleep 1d >/dev/null
}
export -f run_container
export PREFIX IMAGE

main() {
  [[ ${EUID} -eq 0 ]] || { log "run as root"; exit 1; }
  docker image inspect "${IMAGE}" >/dev/null 2>&1 || docker pull -q "${IMAGE}" >/dev/null
  docker build -q -t "${TESTER_IMAGE}" "${E2E_DIR}/images/tester" >/dev/null || exit 1
  cleanup
  mkdir -p "${WORK}/state"

  log "creating ${NETWORKS} networks"
  for i in $(seq 1 "${NETWORKS}"); do
    docker network create -d bridge --subnet "10.$((100 + i)).0.0/16" \
      --label "${PREFIX}=1" --label portcullis.enable=true "${PREFIX}-net${i}" >/dev/null
  done

  "${BIN}" --log-format json --log-level info --events-socket "${SOCKET}" \
    --state-dir "${WORK}/state" --quarantine report >"${WORK}/events.log" 2>"${LOG}" &
  PID=$!
  until [[ -S "${SOCKET}" ]]; do sleep 0.1; done
  wait_applied 10 || exit 1
  log "started: $(usage)"
  # STRESS_PERF=1 records a profile of the updates (not the floods) to perf.data.
  local perf_pid=""
  if [[ -n "${STRESS_PERF:-}" ]]; then
    perf record -q -F 999 -g -p "${PID}" -o "${STRESS_PERF_OUT:-${WORK}/perf.data}" 2>/dev/null &
    perf_pid=$!
  fi

  # Phase 1: many containers at once.
  local from started
  from="$(lines)"
  started="$(date +%s.%N)"
  for i in $(seq 1 "${CONTAINERS}"); do
    echo "${PREFIX}-c${i} ${PREFIX}-net$(( (i % NETWORKS) + 1 )) ${PREFIX}-c$(( (i % CONTAINERS) + 1 ))"
  done | xargs -P "${PARALLEL}" -L 1 bash -c 'run_container "$@"' _
  local addresses
  read -ra addresses <<<"$(docker ps -q --filter "label=${PREFIX}" | xargs docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}')"
  wait_applied 600 "${addresses[@]}" || log "not all ${#addresses[@]} containers applied"
  report "start ${CONTAINERS}" "${from}" "${started}"

  # Phase 2: latency of one more container, from docker run returning to its rules.
  local total=0 one t0 t1
  for i in $(seq 1 10); do
    run_container "${PREFIX}-one${i}" "${PREFIX}-net1" "${PREFIX}-c1"
    t0="$(date +%s%N)"
    one="$(address_of "${PREFIX}-one${i}")"
    wait_applied 30 ${one}
    t1="$(date +%s%N)"
    total=$((total + (t1 - t0) / 1000000))
    docker rm -f "${PREFIX}-one${i}" >/dev/null
  done
  log "one container: average $((total / 10))ms from docker run to its rules"

  # Phase 3: churn.
  from="$(lines)"
  started="$(date +%s.%N)"
  for round in $(seq 1 "${CHURN_ROUNDS}"); do
    for i in $(seq 1 "${CHURN_BATCH}"); do
      echo "${PREFIX}-churn${i} ${PREFIX}-net$(( (i % NETWORKS) + 1 )) ${PREFIX}-c${i}"
    done | xargs -P "${PARALLEL}" -L 1 bash -c 'run_container "$@"' _
    docker ps -aq --filter "name=${PREFIX}-churn" | xargs -r docker rm -f >/dev/null
  done
  # Settle: one more update after the last event.
  run_container "${PREFIX}-settle" "${PREFIX}-net1" "${PREFIX}-c1"
  wait_applied 120 $(address_of "${PREFIX}-settle")
  report "churn ${CHURN_ROUNDS}x${CHURN_BATCH}" "${from}" "${started}"

  [[ -n "${perf_pid}" ]] && kill -INT "${perf_pid}" && wait "${perf_pid}"
  [[ -n "${STRESS_SKIP_FLOODS:-}" ]] && { log "end: $(usage)"; return; }

  # Phase 4: floods from one container: UDP to many destinations it may not reach, each a
  # new connection to deny and report, then DNS lookups, whose answers are inspected.
  local before after
  "${E2E_DIR}/outside.sh" up || exit 1
  docker run -d --name "${PREFIX}-flood" --label "${PREFIX}=1" --network "${PREFIX}-net1" \
    --dns 198.51.100.2 --label portcullis.quarantine=off --label portcullis.limit.connections=none \
    "${TESTER_IMAGE}" sleep 1d >/dev/null
  wait_applied 30 $(address_of "${PREFIX}-flood")
  before="$(usage)"
  docker exec "${PREFIX}-flood" python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
end = time.time() + ${FLOOD_SECONDS}; n = 0
while time.time() < end:
    for _ in range(100):
        try: s.sendto(b'x', ('203.0.%d.%d' % (n % 200, n // 200 % 250 + 1), n % 60000 + 1))
        except OSError: pass
        n += 1
    time.sleep(0.001)
print(n)" >"${WORK}/sent"
  after="$(usage)"
  log "denied flood ${FLOOD_SECONDS}s ($(cat "${WORK}/sent") packets): before ${before}; after ${after}; events $(grep -c '\"denied\"' "${WORK}/events.log")"

  before="$(usage)"
  docker exec "${PREFIX}-flood" python3 -c "
import socket, struct, threading, time
end = time.time() + ${FLOOD_SECONDS}; counts = []
def worker(w):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1); n = 0
    while time.time() < end:
        name = b''.join(bytes([len(p)]) + p for p in (b'n%d-%d' % (w, n), b'wild', b'test')) + b'\\0'
        s.sendto(struct.pack('>HHHHHH', n & 0xffff, 0x100, 1, 0, 0, 0) + name + b'\\0\\1\\0\\1', ('127.0.0.11', 53))
        try: s.recv(512); n += 1
        except OSError: pass
    counts.append(n)
ts = [threading.Thread(target=worker, args=(w,)) for w in range(8)]
[t.start() for t in ts]; [t.join() for t in ts]
print(sum(counts))" >"${WORK}/lookups"
  after="$(usage)"
  log "dns flood ${FLOOD_SECONDS}s ($(cat "${WORK}/lookups") answers): before ${before}; after ${after}"

  log "end: $(usage)"
}

main "$@"
