wait_managed "$(svc_ip app net)"
blocked "before the container looked the name up" tcp app 198.51.100.5 80
flush_checks
event "the lookup is reported" 'event=dns container~app name=dyn.test answers~198.51.100.5' resolve app dyn.test
# The answer is only released after its address is allowed.
flush_checks
allowed "the address from the answer" tcp app 198.51.100.5 80
event "the connection is labelled with the name" 'event=connection verdict=denied container~app domain=dyn.test domain_source=dns destination_port=443' tcp app 198.51.100.5 443
