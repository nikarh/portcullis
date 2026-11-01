# A reboot: the kernel forgets every rule, and Docker starts containers with a restart
# policy by itself. Portcullis, started before Docker (as its systemd unit orders it), must
# have the last rules back in place before any of them sends.
app_ip="$(svc_ip app net)"
wait_managed "${app_ip}"
stop_portcullis
nft delete table inet portcullis
nft delete table bridge portcullis
systemctl stop docker.socket docker.service

start_portcullis_before_docker
restored() {
  nft list table bridge portcullis >/dev/null && nft list table inet portcullis >/dev/null \
    && ! docker info >/dev/null 2>&1
}
check "rules restored before Docker starts" restored
flush_checks

since="$(date +%s)"
systemctl start docker.service
first_tries() {
  timeout 30 docker logs -f --since "${since}" "${PROJECT}-app-1" 2>&1 | grep -m 2 -E '^(listed|unlisted)-'
}
boot_output="$(first_tries)"
tried() {
  printf '%s\n' "${boot_output}"
  grep -qx "$1" <<<"${boot_output}"
}
check "a container's first packets at boot wait for its rules, and pass them" tried listed-ok
check "a container's first packets at boot don't get past its rules" tried unlisted-blocked
check "Portcullis waited for Docker" grep -q 'waiting for Docker' "${PORTCULLIS_LOG}"
flush_checks
