# Plain HTTP connections are kept while connection tracking has them: with a check every 2
# seconds, an idle keep-alive connection outlives many of them.
stop_portcullis
PORTCULLIS_NAME_IDLE_CHECK=2 start_portcullis ${NAMES_FLAGS:-}
wait_managed "$(svc_ip lenient net)" "$(svc_ip strict net)" "$(svc_ip monitored monitored)"
api=198.51.100.3

allowed "TLS naming the rule's host" name_probe lenient tls "${api}" 8443 api.test
allowed "a ClientHello sent in four segments" name_probe lenient tls "${api}" 8443 api.test --pieces 4
blocked "TLS naming another site on the rule's address" name_probe lenient tls "${api}" 8443 other.test
blocked "TLS naming another site, in four segments" name_probe lenient tls "${api}" 8443 other.test --pieces 4
blocked "a ClientHello that never arrives whole" name_probe lenient tls "${api}" 8443 api.test --partial
blocked "the rule's host at an address that isn't its" name_probe lenient tls 198.51.100.4 8443 api.test
event "the other site is reported, with its name" \
  "event=connection verdict=denied reason=egress container~lenient destination=${api} destination_port=8443 name=shared.test detail~host:" \
  name_probe lenient tls "${api}" 8443 shared.test

allowed "HTTP naming the rule's host" name_probe lenient http "${api}" 8081 api.test
blocked "HTTP naming another site" name_probe lenient http "${api}" 8081 other.test
blocked "a second request, for another site, on the same connection" \
  name_probe lenient http "${api}" 8081 api.test other.test
allowed "a keep-alive connection that idles past the idle check" \
  name_probe lenient http "${api}" 8081 api.test api.test --pause 5

allowed "QUIC naming the rule's host, its ClientHello over three packets" \
  name_probe lenient quic "${api}" 9000 api.test
blocked "QUIC naming another site" name_probe lenient quic "${api}" 9000 other.test

allowed "TLS without a server name, by address" name_probe lenient tls "${api}" 8443 -
allowed "TCP that names nothing, by address" name_probe lenient raw "${api}" 8081 hello
allowed "UDP that isn't QUIC, by address" udp lenient "${api}" 9000
blocked "strict: TLS without a server name" name_probe strict tls "${api}" 8443 -
blocked "strict: TCP that names nothing" name_probe strict raw "${api}" 8081 hello
blocked "strict: UDP that isn't QUIC" udp strict "${api}" 9000
allowed "strict: TLS naming the rule's host" name_probe strict tls "${api}" 8443 api.test

allowed "monitor mode lets another site through" name_probe monitored tls "${api}" 8443 other.test
event "and reports it" \
  "event=connection verdict=would_deny reason=egress container~monitored name=monitored.test" \
  name_probe monitored tls "${api}" 8443 monitored.test
flush_checks

stop_portcullis
start_portcullis
