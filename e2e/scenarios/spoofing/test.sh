victim_ip="$(svc_ip victim net)"
wait_managed "$(svc_ip spoofer net)" "${victim_ip}"
allowed "the real container uses its policy" tcp victim 198.51.100.3 80
blocked "spoofer: its own address" tcp spoofer 198.51.100.3 80
blocked "spoofer: an address outside the network" spoof_tcp spoofer 10.99.0.5 198.51.100.5 80
blocked "spoofer: another container's address" spoof_tcp spoofer "${victim_ip}" 198.51.100.3 80
