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
