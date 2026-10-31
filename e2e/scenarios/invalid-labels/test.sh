wait_managed "$(svc_ip app net)"
allowed "valid label next to invalid ones" tcp app 198.51.100.3 80
blocked "invalid icc mode falls back to deny" tcp app "$(svc_ip peer net)" 5432
blocked "nothing else is opened" tcp app 198.51.100.5 80
