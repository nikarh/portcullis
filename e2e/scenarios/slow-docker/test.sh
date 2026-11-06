# Docker answers an inspect of a container that is starting only once it has attached all
# its networks, which takes seconds on a busy host; its `connect` events come right away.
# Portcullis must still find the container behind each of its ports before the packets it
# holds for them run out of time, and not take any of them for spoofing: a container
# quarantined for its own first packets would be cut off at every start.

SLOW_DOCKER=/run/portcullis-e2e-slow-docker.sock
SLOW_DOCKER_ARM=/run/portcullis-e2e-slow-docker.arm
rm -f "${SLOW_DOCKER_ARM}"
python3 "${E2E_DIR}/slow-docker.py" "${SLOW_DOCKER}" /var/run/docker.sock "${SLOW_DOCKER_ARM}" 3 &
SLOW_DOCKER_PID=$!
deadline=$((SECONDS + 10))
until [[ -S "${SLOW_DOCKER}" ]] || ((SECONDS >= deadline)); do sleep 0.1; done

stop_portcullis
start_portcullis --docker-socket "${SLOW_DOCKER}"
wait_managed "$(svc_ip anchor one)" "$(svc_ip anchor four)"

# Longer than the hold of packets from unknown sources (2 seconds).
touch "${SLOW_DOCKER_ARM}"
SLOW_EVENTS="${RESULTS_DIR}/slow-docker-events.jsonl"
: >"${SLOW_EVENTS}"
start_multi() { dc --profile late up -d --no-deps multi >/dev/null 2>&1; }
EVENT_SAVE="${SLOW_EVENTS}" EVENT_TIMEOUT=30 expect_event \
  "event=connection verdict=denied reason=egress destination=198.51.100.4" \
  start_multi >/dev/null 2>&1
multi_id="$(dc --profile late ps -aq multi)"
[[ -n "${multi_id}" ]] && docker wait "${multi_id}" >/dev/null
MULTI_OUTPUT="$(docker logs "${multi_id}" 2>&1)"
rm -f "${SLOW_DOCKER_ARM}"

multi_line() { grep "^$1: " <<<"${MULTI_OUTPUT}" | sed "s/^$1: //" | grep . || printf '%s\n' "${MULTI_OUTPUT}"; }
multi_allowed() { multi_line allowed | grep succeeded; }
multi_denied() { multi_line denied | grep -Ei 'unreachable|no route to host'; }
found_multi() { grep -E "found a container behind a bridge port.*${PROJECT}-multi-1" "${PORTCULLIS_LOG}"; }
no_source_events() {
  ! grep '"reason":"source"' "${SLOW_EVENTS}" && grep -q . "${SLOW_EVENTS}"
}
not_quarantined() { ! grep -E 'quarantined|cut off' "${ALERT_LOG}"; }

check "found without Docker" found_multi
check "its labels allow what they list" multi_allowed
check "and deny the rest" multi_denied
check "none of its packets is taken for a spoofed source" no_source_events
check "it isn't quarantined" not_quarantined
flush_checks

stop_portcullis
kill "${SLOW_DOCKER_PID}" 2>/dev/null
wait "${SLOW_DOCKER_PID}" 2>/dev/null
rm -f "${SLOW_DOCKER}"
start_portcullis
