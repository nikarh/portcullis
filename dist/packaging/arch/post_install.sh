#!/bin/sh
# Arch packages don't enable services; say how.
cat <<'NOTE'
==> Portcullis is configured in /etc/portcullis/config.toml. Start it, and at every boot,
    with: systemctl enable --now portcullis
NOTE
