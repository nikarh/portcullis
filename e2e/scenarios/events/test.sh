lookup_and_connect() {
  in_svc "$1" nslookup -timeout=3 "$2" >/dev/null 2>&1
  tcp "$1" "$3" "$4"
}
peer_ip="$(svc_ip peer net)"
wait_managed "$(svc_ip app net)" "${peer_ip}" "$(svc_ip spoofer net)"
event "denied egress with the domain the container looked up" 'event=connection verdict=denied reason=egress container~app domain=other.test domain_source=dns destination=198.51.100.4 destination_port=443' lookup_and_connect app other.test 198.51.100.4 443
event "denied ICC names the destination container" 'event=connection verdict=denied reason=icc container~app destination_container~peer destination_port=5432' tcp app "${peer_ip}" 5432
event "denied DNS names the query" 'event=connection verdict=denied reason=dns container~app destination=198.51.100.3 query=blocked.test' dns app 198.51.100.3 blocked.test
event "spoofed sources name the sender" 'event=connection verdict=denied reason=source container~spoofer source=10.99.0.5 detail~instead' spoof_tcp spoofer 10.99.0.5 198.51.100.5 80
event "containers without observable DNS are reported" 'event=warning kind=dns_not_observable container~late' dc --profile late up -d late
flush_checks
dc --profile late down -v >/dev/null 2>&1
