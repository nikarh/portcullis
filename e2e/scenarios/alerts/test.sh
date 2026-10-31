# Portcullis runs with --alert-exec appending each alert to ALERT_LOG.
wait_managed "$(svc_ip app net)"
first='"container":"pc-alerts-app-1".*"destination_port":81[,}]'
second='"container":"pc-alerts-app-1".*"destination_port":82[,}]'
event "first denial" 'event=connection verdict=denied container~alerts-app destination_port=81' tcp app 198.51.100.5 81
flush_checks
check "alert raised for a denial" wait_for_line "${ALERT_LOG}" "${first}"
flush_checks
event "same denial again" 'event=connection verdict=denied container~alerts-app destination_port=81' tcp app 198.51.100.5 81
flush_checks
event "another denial" 'event=connection verdict=denied container~alerts-app destination_port=82' tcp app 198.51.100.5 82
flush_checks
check "alert raised for another denial" wait_for_line "${ALERT_LOG}" "${second}"
flush_checks
# Alerts run in order, so the repeated one would have been raised before the second.
alerted_once() {
  local count
  count="$(grep -Ec -- "${first}" "${ALERT_LOG}")"
  echo "alerts for the first denial: ${count}"
  ((count == 1))
}
check "the same denial alerts only once" alerted_once
