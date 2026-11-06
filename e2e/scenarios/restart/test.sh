# Containers that exist before Portcullis starts are picked up at startup.
wait_managed "$(svc_ip app net)"
stop_portcullis

# By default the rules stay in force while Portcullis is stopped.
blocked "still restricted while Portcullis is stopped" tcp app 198.51.100.5 80
allowed "listed address while Portcullis is stopped" tcp app 198.51.100.3 80
# A container that starts meanwhile has no rules yet: it can't send at all, even where its
# labels would allow it.
late_container() {
  docker run --rm --network "${PROJECT}_net" \
    --label portcullis.egress.tcp=ip:198.51.100.3,tcp:80 \
    "${TESTER_IMAGE}" nc -v -w 3 198.51.100.3 80 </dev/null 2>&1
}
expect_late_container_cut_off() {
  local output
  output="$(late_container)"
  printf '%s\n' "${output}"
  ! grep -q succeeded <<<"${output}"
}
check "cut off: a container that starts while Portcullis is stopped" expect_late_container_cut_off
flush_checks

# `portcullis cleanup` removes the rules.
"${PORTCULLIS_BIN}" cleanup >/dev/null
allowed "unrestricted after portcullis cleanup" tcp app 198.51.100.5 80
flush_checks

start_portcullis
wait_managed "$(svc_ip app net)"
allowed "listed address after restart" tcp app 198.51.100.3 80
blocked "unlisted address after restart" tcp app 198.51.100.5 80

# A container removed while Portcullis is stopped, and its address given to a new one:
# the new one doesn't get its connections when Portcullis starts again.
donor_ip="$(svc_ip donor net)"
wait_managed "${donor_ip}"
in_svc donor sh -c 'printf flow | socat -t2 -T2 - UDP:198.51.100.4:9000,sourceport=5557' >/dev/null
stop_portcullis
dc rm -sf donor >/dev/null 2>&1
heir="${PROJECT}-heir"
docker run -d --name "${heir}" --network "${PROJECT}_net" --ip "${donor_ip}" "${TESTER_IMAGE}" >/dev/null
start_portcullis
wait_managed "${donor_ip}"
heir_flow() {
  local output
  output="$(docker exec "${heir}" sh -c 'printf flow | socat -t3 -T3 - UDP:198.51.100.4:9000,sourceport=5557' 2>&1)"
  printf 'answer: %s\n' "${output}"
  [[ "${output}" != *198.51.100.4* ]]
}
check "unanswered: a connection of a container removed while Portcullis was stopped, from the next one with its address" heir_flow
flush_checks
docker rm -f "${heir}" >/dev/null
