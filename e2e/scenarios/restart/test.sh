# Containers that exist before Portcullis starts are picked up at startup.
wait_managed "$(svc_ip app net)"
stop_portcullis
allowed "unrestricted while Portcullis is stopped" tcp app 198.51.100.5 80
flush_checks
start_portcullis
wait_managed "$(svc_ip app net)"
allowed "listed address after restart" tcp app 198.51.100.3 80
blocked "unlisted address after restart" tcp app 198.51.100.5 80
