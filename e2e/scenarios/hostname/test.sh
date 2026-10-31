wait_managed "$(svc_ip app net)"
allowed "address of a listed hostname" tcp app 198.51.100.3 443
blocked "address of another hostname" tcp app 198.51.100.4 443
allowed "other rules still apply next to an unresolvable hostname" tcp app 198.51.100.5 80
