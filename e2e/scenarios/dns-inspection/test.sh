wait_managed "$(svc_ip app net)"
blocked "before the container looked the name up" tcp app 198.51.100.5 80
flush_checks
allowed "the lookup" resolve app dyn.test
# The answer is only released after its address is allowed.
flush_checks
allowed "the address from the answer" tcp app 198.51.100.5 80
event "the connection is labelled with the name" 'event=connection verdict=denied container~app domain=dyn.test domain_source=dns destination_port=443' tcp app 198.51.100.5 443
