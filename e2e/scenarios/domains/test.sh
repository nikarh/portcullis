wait_managed "$(svc_ip filtered net)" "$(svc_ip control net)"
allowed "a listed name" resolve filtered api.test
allowed "the name of a host: rule" resolve filtered other.test
allowed "a listed name, asking the resolver directly" dns filtered 198.51.100.2 api.test
allowed "a listed name, over TCP" in_svc filtered dig +tcp +time=3 +tries=1 +short @198.51.100.2 api.test
allowed "control: any name" resolve control dyn.test
blocked "a name that isn't listed" resolve filtered dyn.test
blocked "a name that isn't listed, asking the resolver directly" dns filtered 198.51.100.2 secret.dyn.test
event "reported, with the name" "event=connection verdict=denied reason=dns container~filtered query=data.exfil.test detail~portcullis.domains" \
  dns filtered 198.51.100.2 data.exfil.test
# Port 53 only carries DNS queries.
check "rejected: something else than DNS to port 53" expect_rejection craft filtered udp --dst 198.51.100.2 --dport 53
