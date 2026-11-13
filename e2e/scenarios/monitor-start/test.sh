# Containers that start while Docker's API doesn't answer are found without it, from their
# bridge ports, the kernel and Docker's files: their first packets are held until their rules
# are in place, and reported with the container. On monitored networks nothing is denied:
# a source that is no container's is let through once its hold expires, and nothing is
# held while Portcullis is stopped.

# --- Docker's API paused ------------------------------------------------------------------

stop_portcullis
start_docker_proxy
start_portcullis --docker-socket "${DOCKER_PROXY}"
peer_ip="$(svc_ip peer watched)"
wait_managed "${peer_ip}" "$(svc_ip anchor enforced)" "$(svc_ip spoofer watched)"

kill -STOP -- "-${DOCKER_PROXY_PID}"
# Every event while the monitored container runs, up to its last probe.
STARTED_EVENTS="${RESULTS_DIR}/monitor-start-events.jsonl"
: >"${STARTED_EVENTS}"
start_late() { dc --profile late up -d --no-deps "$1" >/dev/null 2>&1; }
# Long enough for its probes to finish even if each waited out a hold: what wasn't seen
# can't be checked.
EVENT_SAVE="${STARTED_EVENTS}" EVENT_TIMEOUT=30 expect_event \
  "event=connection destination=198.51.100.5 destination_port=443" \
  start_late fast-watched >/dev/null 2>&1
start_late fast-enforced
late_output() {
  local id
  id="$(dc --profile late ps -aq "$1")"
  [[ -n "${id}" ]] || return 1
  docker wait "${id}" >/dev/null
  docker logs "${id}" 2>&1
}
WATCHED_OUTPUT="$(late_output fast-watched)"
ENFORCED_OUTPUT="$(late_output fast-enforced)"

# found_without_docker <service>: Portcullis logged finding its container.
found_without_docker() {
  grep -E "found a container behind a bridge port.*${PROJECT}-$1-1" "${PORTCULLIS_LOG}"
}
# started_event <filters...>: one of the saved events matches all filters.
started_event() {
  python3 - "${STARTED_EVENTS}" "$@" <<'EOF'
import json, sys
path, *filters = sys.argv[1:]
events = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
def matches(event):
    for item in filters:
        key, operator, expected = (item.partition("~") if "~" in item else item.partition("="))
        text = "null" if event.get(key) is None else str(event.get(key))
        if (operator == "~" and expected not in text) or (operator == "=" and text != expected):
            return False
    return True
found = [event for event in events if matches(event)]
print(found[0] if found else f"none of {len(events)} events matches {filters}")
sys.exit(0 if found else 1)
EOF
}
no_started_event() { ! started_event "$@"; }
output_line() { grep "^$2: " <<<"$1" | sed "s/^$2: //" | grep . || printf '%s\n' "$1"; }
watched_line_succeeded() { output_line "${WATCHED_OUTPUT}" "$1" | grep succeeded; }
enforced_allowed() { output_line "${ENFORCED_OUTPUT}" allowed | grep succeeded; }
enforced_denied() { output_line "${ENFORCED_OUTPUT}" denied | grep -Ei 'unreachable|no route to host'; }

check "monitored: found without Docker" found_without_docker fast-watched
check "monitored: ICC sent before Docker reported the container passes" watched_line_succeeded icc
check "monitored: egress sent before Docker reported the container passes" watched_line_succeeded egress
check "monitored: its first ICC is reported with the container" \
  started_event event=connection reason=icc "container~fast-watched" "destination_container~peer" destination_port=5432
check "monitored: its first egress is reported with the container" \
  started_event event=connection verdict=would_deny reason=egress "container~fast-watched" destination=198.51.100.3
check "monitored: its events were seen up to its last probe" \
  started_event event=connection destination=198.51.100.5 destination_port=443
check "monitored: none of it is reported as an unknown source" no_started_event reason=source
check "enforced: found without Docker" found_without_docker fast-enforced
check "enforced: its labels from Docker's files allow what they list" enforced_allowed
check "enforced: and deny the rest" enforced_denied
flush_checks

kill -CONT -- "-${DOCKER_PROXY_PID}"
stop_portcullis
stop_docker_proxy
start_portcullis
wait_managed "${peer_ip}" "$(svc_ip spoofer watched)"

# --- sources that are no container's --------------------------------------------------------

# A veth on the monitored network's bridge whose other end is in a namespace without a
# container, with an unused address of the network.
watched_bridge="br-$(docker network inspect -f '{{.Id}}' "${PROJECT}_watched" | cut -c1-12)"
watched_subnet="$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "${PROJECT}_watched")"
rogue_ip="$(python3 -c 'import ipaddress, sys; print(list(ipaddress.ip_network(sys.argv[1]).hosts())[-2])' "${watched_subnet}")"
ip netns add pc-rogue
ip link add pc-rogue0 type veth peer name pc-rogue1
ip link set pc-rogue1 netns pc-rogue
ip link set pc-rogue0 master "${watched_bridge}" up
ip -n pc-rogue addr add "${rogue_ip}/${watched_subnet#*/}" dev pc-rogue1
ip -n pc-rogue link set pc-rogue1 up

rogue_tcp() { ip netns exec pc-rogue nc -v -w 8 "${peer_ip}" 5432 </dev/null 2>&1; }
expect_rogue_through() {
  local output
  output="$(rogue_tcp)"
  printf '%s\n' "${output}"
  grep -q succeeded <<<"${output}"
}
check "monitored: a source that is no container's is let through after its hold" expect_rogue_through
event "monitored: and reported as an unknown source" \
  "event=connection verdict=would_deny reason=source container=null source=${rogue_ip} detail~unknown" rogue_tcp
# A container sending with an address that isn't its own is named.
event "monitored: a spoofed address is reported with the sender" \
  'event=connection verdict=would_deny reason=source container~spoofer source=10.99.0.5 detail~instead' \
  spoof_tcp spoofer 10.99.0.5 198.51.100.5 80
flush_checks
ip netns del pc-rogue
ip link del pc-rogue0 2>/dev/null

# --- Portcullis stopped ---------------------------------------------------------------------

stop_portcullis
# The rules stay, but the monitored network's hold has no reader: its packets pass.
late_watched() {
  docker run --rm --network "${PROJECT}_watched" "${TESTER_IMAGE}" \
    nc -v -w 3 198.51.100.3 80 </dev/null 2>&1
}
expect_late_watched_through() {
  local output
  output="$(late_watched)"
  printf '%s\n' "${output}"
  grep -q succeeded <<<"${output}"
}
check "monitored: a container that starts while Portcullis is stopped isn't held" expect_late_watched_through
flush_checks
start_portcullis
