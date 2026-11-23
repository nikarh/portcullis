#!/usr/bin/env bash
# Measures how long a container that just started waits for its rules. Runs as root inside
# the test VM (see vm.sh), next to nothing else; it removes what it starts.
#
#   e2e/vm.sh ssh sudo /home/debian/portcullis/e2e/latency.sh
#   LATENCY_ROUNDS=50 LATENCY_MODE=monitor ... latency.sh
#
# First it starts LATENCY_BACKGROUND containers (default 50) on LATENCY_NETWORKS networks
# (default 5), with egress, ICC and hostname rules, for rules of a realistic size. Then, in
# each round, it starts one container that sends a UDP packet to an allowed destination as
# soon as it runs, and one that sends nothing. Each has a rule for a hostname no rule had
# before (LATENCY_HOST, with the round in it), as a container with new labels would, or one
# recreated with the same. The network is enforced (LATENCY_MODE=monitor: monitored).
#
# For each container it prints, in milliseconds from when its bridge port came up (the
# earliest it can send anything):
#   started   Docker's StartedAt (it comes before the port: Docker sets up the network after)
#   sent      when the first packet was sent (by the container's own clock)
#   found     when Portcullis found the container behind its port
#   applied   when the update that made it managed was in place
#   answered  when the answer to the first packet arrived
#   held      the first packet's round trip: how long it was held, plus the trip itself
# and the median and worst of each, and the number of rule updates.
set -uo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${PORTCULLIS_BIN:-${E2E_DIR}/../target/release/portcullis}"
ROUNDS="${LATENCY_ROUNDS:-20}"
MODE="${LATENCY_MODE:-enforce}"
BACKGROUND="${LATENCY_BACKGROUND:-50}"
NETWORKS="${LATENCY_NETWORKS:-5}"
# Unique to the run: a resolver that cached an earlier run's answer would answer at once.
HOST="${LATENCY_HOST:-portcullis-latency-%s-$(date +%s).example.com}"
TESTER_IMAGE=portcullis-e2e-tester
WORK="$(mktemp -d /tmp/portcullis-latency.XXXXXX)"
SOCKET="${WORK}/events.sock"
PREFIX="pclatency"
NETWORK="${PREFIX}-net0"
PID=""
MONITOR_PID=""

log() { printf '[latency] %s\n' "$*" >&2; }

cleanup() {
  [[ -n "${MONITOR_PID}" ]] && kill "${MONITOR_PID}" 2>/dev/null
  [[ -n "${PID}" ]] && kill -TERM "${PID}" 2>/dev/null && wait "${PID}" 2>/dev/null
  docker ps -aq --filter "label=${PREFIX}" | xargs -r docker rm -f >/dev/null
  docker network ls -q --filter "label=${PREFIX}" | xargs -r docker network rm >/dev/null
  "${BIN}" cleanup --state-dir "${WORK}/state" >/dev/null 2>&1
  "${E2E_DIR}/outside.sh" down >/dev/null 2>&1
  [[ -n "${KEEP_WORK:-}" ]] || rm -rf "${WORK}"
}
trap cleanup EXIT

address_of() {
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"
}

main() {
  [[ ${EUID} -eq 0 ]] || { log "run as root"; exit 1; }
  docker build -q -t "${TESTER_IMAGE}" "${E2E_DIR}/images/tester" >/dev/null || exit 1
  cleanup
  mkdir -p "${WORK}/state"
  "${E2E_DIR}/outside.sh" up || exit 1

  local i monitor_args=() options=()
  # LATENCY_QUIET=1: Docker doesn't announce a container's address (unsolicited ARP) as
  # its interface comes up, as before Docker 28, so nothing is sent before its process.
  [[ -n "${LATENCY_QUIET:-}" ]] && options=(-o com.docker.network.advertise_addr_nmsgs=0)
  for i in $(seq 0 "${NETWORKS}"); do
    docker network create -d bridge --subnet "10.$((200 + i)).0.0/16" --label "${PREFIX}=1" \
      "${options[@]}" --label portcullis.enable=true "${PREFIX}-net${i}" >/dev/null
    [[ "${MODE}" == monitor ]] && monitor_args+=(--monitor-network "${PREFIX}-net${i}")
  done
  # Keeps the measured network's rules in place between rounds.
  docker run -d -q --name "${PREFIX}-anchor" --label "${PREFIX}=1" --network "${NETWORK}" \
    "${TESTER_IMAGE}" >/dev/null
  for i in $(seq 1 "${BACKGROUND}"); do
    docker run -d -q --name "${PREFIX}-bg${i}" --label "${PREFIX}=1" \
      --network "${PREFIX}-net$(( (i % NETWORKS) + 1 ))" \
      --label portcullis.egress.api=ip:198.51.100.3,tcp:443,tcp:80 \
      --label portcullis.egress.ranges=ip:203.0.113.0/24,tcp:8000-8100,udp:9000 \
      --label "portcullis.egress.name=host:bg${i}.example.com,tcp:443" \
      --label portcullis.icc.mode=allow-listed \
      --label "portcullis.icc.allow.peer=container:${PREFIX}-bg$(( (i % BACKGROUND) + 1 )),tcp:5432" \
      "${TESTER_IMAGE}" sleep 1d >/dev/null
  done

  "${BIN}" --log-format json --log-level "${LATENCY_LOG_LEVEL:-debug}" \
    --events-socket "${SOCKET}" --state-dir "${WORK}/state" "${monitor_args[@]}" \
    >"${WORK}/events.log" 2>"${WORK}/portcullis.log" &
  PID=$!
  until [[ -S "${SOCKET}" ]]; do sleep 0.1; done
  # shellcheck disable=SC2046
  python3 "${E2E_DIR}/wait-applied.py" "${SOCKET}" 60 \
    $(docker ps -q --filter "label=${PREFIX}" | xargs docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}') || exit 1
  log "rules for $((BACKGROUND + 1)) containers in place; measuring ${ROUNDS} rounds"

  # When each container's port comes up.
  ip -ts -o monitor link >"${WORK}/links.log" &
  MONITOR_PID=$!
  sleep 0.5

  local name kind host
  for i in $(seq 1 "${ROUNDS}"); do
    for kind in send quiet; do
      name="${PREFIX}-${kind}${i}"
      # shellcheck disable=SC2059
      host="$(printf "${HOST}" "${kind}${i}")"
      local command=(sleep 1d)
      [[ ${kind} == send ]] && command=(python3 -c '
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
t0 = time.time(); s.sendto(b"x", ("198.51.100.3", 9000))
try: s.recv(512); t1 = time.time()
except OSError: t1 = 0
print(t0, t1, flush=True)
time.sleep(60)')
      docker run -d -q --name "${name}" --label "${PREFIX}=1" --network "${NETWORK}" \
        --label portcullis.egress.echo=ip:198.51.100.3,udp:9000 \
        --label "portcullis.egress.name=host:${host},tcp:443" \
        "${TESTER_IMAGE}" "${command[@]}" >/dev/null
      python3 "${E2E_DIR}/wait-applied.py" "${SOCKET}" 10 "$(address_of "${name}")" >/dev/null ||
        log "${name}: no rules within 10 s"
      if [[ ${kind} == send ]]; then
        local deadline=$((SECONDS + 10))
        until docker logs "${name}" 2>/dev/null | grep -q . || ((SECONDS > deadline)); do
          sleep 0.05
        done
      fi
      printf '%s %s %s %s\n' "${kind}" "${name}" \
        "$(docker inspect -f '{{.State.StartedAt}} {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${name}")" \
        "$(docker logs "${name}" 2>/dev/null | head -1)" >>"${WORK}/rounds"
      # Docker's events of this one pass before the next.
      sleep 0.5
      docker rm -f "${name}" >/dev/null
      sleep 0.3
    done
  done
  kill "${MONITOR_PID}" 2>/dev/null
  MONITOR_PID=""

  python3 - "${WORK}" <<'EOF'
import datetime, json, re, statistics, sys
work = sys.argv[1]

def parse(stamp):
    stamp = stamp.rstrip("Z").replace("+00:00", "")
    if "." in stamp:
        head, fraction = stamp.split(".")
        stamp = f"{head}.{fraction[:6]}"
    return datetime.datetime.fromisoformat(stamp).replace(tzinfo=datetime.timezone.utc).timestamp()

# When each interface first came up (ip monitor prints the VM's time, which is UTC).
up = {}
for line in open(f"{work}/links.log"):
    match = re.match(r"\[(\S+)\]\s+(\d+): \S+ <[^>]*LOWER_UP[^>]*>.* master ", line)
    if match and not line.split("]", 1)[1].lstrip().startswith("Deleted"):
        up.setdefault(int(match.group(2)), parse(match.group(1)))
logs = []
for line in open(f"{work}/portcullis.log"):
    try:
        entry = json.loads(line)
    except ValueError:
        continue
    logs.append((parse(entry["timestamp"]), entry.get("fields", {})))
managed = []
for line in open(f"{work}/events.log"):
    try:
        event = json.loads(line)
    except ValueError:
        continue
    if event.get("event") == "container" and event.get("action") == "managed":
        managed.append((parse(event["time"]), event["address"]))

rows = {"send": [], "quiet": []}
for line in open(f"{work}/rounds"):
    kind, name, started, address, *probe = line.split()
    started = parse(started)
    found, index = next(((t, f.get("port")) for t, f in logs if t > started - 1 and f.get("message", "").startswith("found a container") and f.get("container") == name), (None, None))
    # The port Portcullis found the container behind, or the first to come up after
    # StartedAt.
    port = up.get(index) if index is not None else min((t for t in up.values() if started - 0.2 < t < started + 3), default=None)
    origin = port if port is not None else started
    # The update that reported it managed: the first "firewall rules applied" at or after
    # the event (whose time has milliseconds only).
    event = next((t for t, a in managed if a == address and t > started - 1), None)
    applied = None
    if event is not None:
        applied = next((t for t, f in logs if f.get("message") == "firewall rules applied" and t >= event - 0.001), None)
    sent = answered = None
    if kind == "send" and len(probe) == 2:
        sent, answered = float(probe[0]), float(probe[1]) or None
    ms = lambda t: None if t is None else (t - origin) * 1000
    rows[kind].append({"started": ms(started), "found": ms(found), "applied": ms(applied),
                       "sent": ms(sent), "answered": ms(answered),
                       "held": None if not (sent and answered) else (answered - sent) * 1000})

def show(value):
    return f"{value:9.1f}" if value is not None else "        -"
for kind, columns in (("send", ["started", "sent", "found", "applied", "answered", "held"]),
                       ("quiet", ["started", "found", "applied"])):
    print(f"\n{kind}: ms from the bridge port coming up")
    print(" ".join(f"{c:>9}" for c in columns))
    for row in rows[kind]:
        print(" ".join(show(row[c]) for c in columns))
    for label, pick in (("median", statistics.median), ("max", max)):
        values = []
        for c in columns:
            known = [row[c] for row in rows[kind] if row[c] is not None]
            values.append(show(pick(known)) if known else show(None))
        print(" ".join(values) + f"  {label}")
EOF
  log "rule updates while measuring: $(grep -c '"firewall rules applied"' "${WORK}/portcullis.log") (with the first), for $((ROUNDS * 2)) containers started and removed"
}

main "$@"
