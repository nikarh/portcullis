# Configuration warnings raise alerts; Portcullis runs with --alert-exec appending them to
# ALERT_LOG. Containers are checked when they start.
wait_managed "$(svc_ip twonets net)" "$(svc_ip escape net)" "$(svc_ip acknowledged net)"
dc restart -t 0 acknowledged hostnet sidecar twonets escape >/dev/null 2>&1
warned() {
  wait_for_line "${ALERT_LOG}" "\"kind\":\"$1\",\"container\":\"$2\""
}
check "warning: a second network that isn't enforced" warned unenforced_network pc-checks-twonets-1
check "warning: labels on a container using the host's network" warned unused_labels pc-checks-hostnet-1
check "warning: sharing a restricted container's network" warned shared_network pc-checks-sidecar-1
check "warning: the Docker socket" warned docker_socket pc-checks-escape-1
check "warning: NET_ADMIN" warned net_admin pc-checks-escape-1
check "warning: IPv6 on an enforced network" wait_for_line "${ALERT_LOG}" '"kind":"ipv6_network".*network pc-checks_v6:'
flush_checks
# Alerts run in order, and the acknowledged container restarted first.
quiet() {
  ! grep -E "$1" "${ALERT_LOG}"
}
check "acknowledged warnings aren't reported" quiet '"container":"pc-checks-acknowledged-1"'
check "acknowledged network warnings aren't reported" quiet 'network pc-checks_v6acknowledged:'
