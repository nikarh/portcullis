wait_managed "$(svc_ip app net)"
allowed "published port answers clients outside" from_outside 198.51.100.1 18080
blocked "the container still can't open outbound connections" tcp app 198.51.100.5 80
