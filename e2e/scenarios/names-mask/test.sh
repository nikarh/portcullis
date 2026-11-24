# Name checks with other bits of connection marks than the default.
stop_portcullis
start_portcullis --ct-mark-mask 0x0000f000
wait_managed "$(svc_ip lenient net)" "$(svc_ip strict net)" "$(svc_ip monitored monitored)"
api=198.51.100.3

allowed "TLS naming the rule's host" name_probe lenient tls "${api}" 8443 api.test
blocked "TLS naming another site on the rule's address" name_probe lenient tls "${api}" 8443 other.test
blocked "a second request, for another site, on the same connection" \
  name_probe lenient http "${api}" 8081 api.test other.test
allowed "TCP that names nothing, by address" name_probe lenient raw "${api}" 8081 hello
blocked "strict: TCP that names nothing" name_probe strict raw "${api}" 8081 hello
check "the connection marks use the bits asked for" \
  sh -c "nft list chain inet portcullis forward | grep -q 'ct mark & 0x0000f000'"
flush_checks

stop_portcullis
start_portcullis
