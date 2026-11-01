spoofer_ip="$(svc_ip spoofer net)"
wait_managed "${spoofer_ip}" "$(svc_ip scanner net)" "$(svc_ip limited net)" "$(svc_ip rated net)"
allowed "spoofer: its listed address, before" tcp spoofer 198.51.100.3 80
flush_checks

# One packet with someone else's address cuts a container off.
event "quarantined for a spoofed packet" "event=warning kind=quarantined container~spoofer message~10.99.0.9" \
  craft spoofer udp --dst 198.51.100.3 --dport 80 --src 10.99.0.9 --wait 0
flush_checks
# Nothing it sends gets anywhere, not even ARP.
cut_off() {
  local output
  output="$(tcp spoofer 198.51.100.3 80)"
  printf '%s\n' "${output}"
  ! grep -q succeeded <<<"${output}"
}
check "cut off: spoofer's listed address, while quarantined" cut_off
flush_checks
# A restart lets it back.
dc restart -t 0 spoofer >/dev/null 2>&1
allowed "spoofer: its listed address, after a restart" tcp spoofer 198.51.100.3 80

# So do too many denials.
event "quarantined for too many denials" "event=warning kind=quarantined container~scanner message~denied" \
  craft scanner scan --dst 198.51.100.9 --count 2000

# Limits.
open_flows() {
  local port
  for port in $(seq 40001 40010); do
    in_svc limited sh -c "printf x | socat -t1 -T1 - UDP:198.51.100.3:9000,sourceport=${port}" >/dev/null 2>&1
  done
}
event "more open connections than the limit" "event=connection verdict=denied reason=limit container~limited detail~open" open_flows
event "more new connections per second than the limit" "event=connection verdict=denied reason=limit container~rated detail~faster" \
  craft rated scan --dst 198.51.100.9 --count 50
