lookup_and_connect() {
  in_svc "$1" nslookup -timeout=3 "$2" >/dev/null 2>&1
  tcp "$1" "$3" "$4"
}
peer_ip="$(svc_ip peer net)"
wait_managed "$(svc_ip app net)" "${peer_ip}" "$(svc_ip spoofer net)"
event "denied egress with the domain the container looked up" 'event=connection verdict=denied reason=egress container~app domain=other.test domain_source=dns destination=198.51.100.4 destination_port=443' lookup_and_connect app other.test 198.51.100.4 443
event "denied ICC names the destination container" 'event=connection verdict=denied reason=icc container~app destination_container~peer destination_port=5432' tcp app "${peer_ip}" 5432
event "denied DNS names the query" 'event=connection verdict=denied reason=dns container~app destination=198.51.100.3 query=blocked.test' dns app 198.51.100.3 blocked.test
# Not the spoofing scenario's flow: that was reported less than a minute ago.
event "spoofed sources name the sender" 'event=connection verdict=denied reason=source container~spoofer source=10.99.0.6 detail~instead' spoof_tcp spoofer 10.99.0.6 198.51.100.5 80
# The same flow is reported once per minute: after the second flow's event arrives, a
# repeat of the first would have arrived before it.
repeat_then_other() {
  tcp peer 198.51.100.5 81
  tcp peer 198.51.100.5 81
  tcp peer 198.51.100.5 82
}
reported_once() {
  local count
  count="$(grep -c '"container":"pc-events-peer-1".*"destination_port":81[,}]' "${EVENT_SAVE}")"
  echo "events for the repeated flow: ${count}"
  ((count == 1))
}
EVENT_SAVE="${RESULTS_DIR}/events-dedup.jsonl"
: >"${EVENT_SAVE}"
dedup_check() {
  expect_event 'event=connection container~events-peer destination_port=82' repeat_then_other \
    && reported_once
}
check "a repeated flow is reported once" dedup_check
unset EVENT_SAVE
event "containers without observable DNS are reported" 'event=warning kind=dns_not_observable container~late' dc --profile late up -d late
flush_checks
dc --profile late down -v >/dev/null 2>&1
