victim_ip="$(svc_ip victim net)"
wait_managed "$(svc_ip spoofer net)" "${victim_ip}"
allowed "the real container uses its policy" tcp victim 198.51.100.3 80
blocked "spoofer: its own address" tcp spoofer 198.51.100.3 80
# Spoofed traffic is dropped (a rejection would go to the address it claims), and reported
# by the rule that drops it, naming the sender.
event "spoofer: an address outside the network" 'event=connection verdict=denied reason=source container~spoofer source=10.99.0.5 detail~instead' spoof_tcp spoofer 10.99.0.5 198.51.100.5 80
event "spoofer: another container's address" "event=connection verdict=denied reason=source container~spoofer source=${victim_ip} detail~victim" spoof_tcp spoofer "${victim_ip}" 198.51.100.3 80
