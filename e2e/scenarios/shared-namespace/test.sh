# A container others share the network namespace of is recreated together with them. The
# new one's first packets (ARP for its neighbours included) are held until its rules are in
# place, never denied as coming from a source the rules don't know; its connections and
# those of the containers in its namespace are judged by its rules.

peer_ip="$(svc_ip peer net)"
wait_managed "$(svc_ip vpn net)" "${peer_ip}"

# events_until_marker <file> <command...>: save every event while the command runs, until
# the marker container's rules are in place (every Docker event before is handled by then).
events_until_marker() {
  local file="$1" line
  shift
  : >"${file}"
  coproc CAPTURE {
    exec python3 "${E2E_DIR}/expect-event.py" "${EVENTS_SOCKET}" 60 --save "${file}" \
      event=never 2>&1
  }
  read -r line <&"${CAPTURE[0]}"
  "$@" >/dev/null 2>&1
  dc --profile late up -d --no-deps --force-recreate marker >/dev/null 2>&1
  wait_managed "$(svc_ip marker net)"
  kill "${CAPTURE_PID}" 2>/dev/null
  wait "${CAPTURE_PID}" 2>/dev/null
}

# no_source_denials <file>: the events were read (rules were applied meanwhile), and none
# denies a source.
no_source_denials() {
  grep -Eq '"event": ?"applied"' "$1" && ! grep -E '"reason": ?"source' "$1"
}

for run in 1 2 3; do
  events="/tmp/shared-namespace-events-${run}"
  events_until_marker "${events}" dc up -d --no-deps --force-recreate vpn app proxy
  check "recreated (${run}): nothing of the new container is denied as an unknown source" \
    no_source_denials "${events}"
  allowed "recreated (${run}): the container to the peer" tcp vpn "${peer_ip}" 8080
  allowed "recreated (${run}): a container in its namespace to the peer" \
    tcp app "${peer_ip}" 8080
  blocked "recreated (${run}): the container to the peer, on a port it may not use" \
    tcp vpn "${peer_ip}" 5432
  flush_checks
done
