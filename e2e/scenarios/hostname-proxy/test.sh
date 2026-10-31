wait_managed "$(svc_ip app net)"
allowed "lookup through the proxy" resolve app api.test
# The proxy installs the rules before it answers, so the address is allowed once the
# lookup has completed.
flush_checks
allowed "address returned by the proxy" tcp app 198.51.100.3 443
blocked "address of another hostname" tcp app 198.51.100.4 443
