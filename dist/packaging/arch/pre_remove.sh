#!/bin/sh
# Stop the service and remove its firewall rules: once the binary is gone, nothing would
# remove them, and containers on enforced networks would stay cut off. (Upgrades run
# post_upgrade instead.)
if [ -d /run/systemd/system ]; then
  systemctl disable --now portcullis.service || true
fi
/usr/bin/portcullis cleanup || true
