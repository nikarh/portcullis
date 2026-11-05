# shellcheck shell=bash
# While an update is committed, the kernel must not misjudge traffic that passes: lookups in
# sets the update replaces can miss, which reports (and denies) established traffic as from
# an unknown source, or as not allowed. Containers that start and stop make Portcullis
# update the rules each time; meanwhile, ping floods go between the containers and out, and
# nothing of them may be lost or reported.
client_ip="$(svc_ip client net)"
server_ip="$(svc_ip server net)"
wait_managed "${client_ip}" "${server_ip}"

UPDATES=40
updates_log="$(mktemp)"
churn() {
  local index
  for index in $(seq "${UPDATES}"); do
    docker run -d --rm --name "${PROJECT}-churn-${index}" --network "${PROJECT}_net" \
      -l portcullis.icc.mode=deny "${TESTER_IMAGE}" >/dev/null
    docker rm -f "${PROJECT}-churn-$((index - 1))" >/dev/null 2>&1
  done
  docker rm -f "${PROJECT}-churn-${UPDATES}" >/dev/null 2>&1
}

unwanted_events() {
  python3 - "${EVENTS_SOCKET}" "${client_ip}" "${server_ip}" >"${updates_log}" <<'PY' &
import json, socket, sys
path, *addresses = sys.argv[1:]
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(40)
    client.connect(path)
    try:
        for line in client.makefile("r", encoding="utf-8"):
            event = json.loads(line)
            if (event.get("event") == "connection" and event.get("verdict") != "allowed"
                    and event.get("source") in addresses):
                print(line.strip(), flush=True)
    except (socket.timeout, OSError):
        pass
PY
}

log_start="$(wc -l <"${PORTCULLIS_LOG}")"
unwanted_events
watcher=$!
sleep 1
started="$(grep -c 'applied rules' "${PORTCULLIS_LOG}")"
to_server="$(mktemp)"
outside="$(mktemp)"
# Floods for as long as the churn takes, stopped with SIGINT so they report.
in_svc client ping -q -f -w 300 "${server_ip}" >"${to_server}" 2>&1 &
icc_flood=$!
in_svc client ping -q -f -w 300 198.51.100.3 >"${outside}" 2>&1 &
out_flood=$!
churn
in_svc client pkill -INT ping
wait "${icc_flood}" "${out_flood}"
kill "${watcher}" 2>/dev/null
wait "${watcher}" 2>/dev/null
updates=$(($(grep -c 'applied rules' "${PORTCULLIS_LOG}") - started))

# At most the requests in flight when the flood stopped are unanswered.
lossless() {
  cat "$1"
  local sent received
  read -r sent received < <(sed -En 's/^([0-9]+) packets transmitted, ([0-9]+) received.*/\1 \2/p' "$1")
  [[ -n "${sent}" ]] && ((sent > 1000 && sent - received <= 2))
}
check "rules were updated at least ${UPDATES} times meanwhile (${updates})" test "${updates}" -ge "${UPDATES}"
check "no request between the containers lost" lossless "${to_server}"
check "no request out lost" lossless "${outside}"
nothing_reported() {
  cat "${updates_log}"
  [[ ! -s "${updates_log}" ]]
}
check "nothing of theirs reported as denied" nothing_reported
# Containers stopping lose their ports before Docker reports them gone; that isn't worth a
# warning. Stopped together, each one's stop updates the rules while the others are in
# the middle of theirs.
batch=()
for index in $(seq 12); do
  batch+=("${PROJECT}-batch-${index}")
  docker run -d --name "${PROJECT}-batch-${index}" --network "${PROJECT}_net" \
    -l portcullis.icc.mode=deny "${TESTER_IMAGE}" >/dev/null
done
wait_managed "$(docker inspect -f "{{(index .NetworkSettings.Networks \"${PROJECT}_net\").IPAddress}}" "${batch[-1]}")"
stops=()
for name in "${batch[@]}"; do
  docker stop -t 1 "${name}" >/dev/null &
  stops+=($!)
done
wait "${stops[@]}"
docker rm -f "${batch[@]}" >/dev/null
no_port_warnings() {
  ! tail -n "+$((log_start + 1))" "${PORTCULLIS_LOG}" | sed 's/\x1b\[[0-9;]*m//g' \
    | grep -E 'WARN.*(port on|network namespace)'
}
check "no warnings about the ports of containers that stop" no_port_warnings
flush_checks
rm -f "${updates_log}" "${to_server}" "${outside}"
