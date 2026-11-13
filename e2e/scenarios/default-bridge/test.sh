# Docker's default bridge can only be monitored. The host connecting to a container on it,
# and the container's answers, must be told as that container's traffic, before and after
# the container restarts: never as traffic of an unknown source.

stop_portcullis
start_portcullis --monitor-network bridge
docker rm -f pc-default-bridge >/dev/null 2>&1
docker run -d --name pc-default-bridge "${TESTER_IMAGE}" >/dev/null
bridge_ip() { docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' pc-default-bridge; }
wait_managed "$(bridge_ip)"

BRIDGE_EVENTS="${RESULTS_DIR}/default-bridge-events.jsonl"
: >"${BRIDGE_EVENTS}"
# from_host: the host connects to the container a few times, then the container connects
# out: its event ends what is saved.
from_host() {
  local address i
  address="$(bridge_ip)"
  for i in 1 2 3; do nc -v -w 3 "${address}" 8080 </dev/null 2>&1; done
  docker exec pc-default-bridge nc -w 3 198.51.100.3 80 </dev/null
}
restarted_from_host() {
  docker restart -t 1 pc-default-bridge >/dev/null
  from_host
}
host_answered() { nc -v -w 3 "$(bridge_ip)" 8080 </dev/null 2>&1 | grep succeeded; }
seen() {
  EVENT_SAVE="${BRIDGE_EVENTS}" EVENT_TIMEOUT=20 expect_event \
    "event=connection destination=198.51.100.3 container~pc-default-bridge" "$@"
}
no_unknown_source() { ! grep '"reason":"source"' "${BRIDGE_EVENTS}"; }

check "the host's connections are answered" host_answered
flush_checks
check "the container's egress is reported with the container" seen from_host
flush_checks
check "restarted: its egress is reported with the container" seen restarted_from_host
flush_checks
check "nothing of the host's connections is reported as an unknown source" no_unknown_source
check "restarted: the host's connections are answered" host_answered
flush_checks

docker rm -f pc-default-bridge >/dev/null 2>&1
stop_portcullis
start_portcullis
