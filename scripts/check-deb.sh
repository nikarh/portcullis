#!/usr/bin/env bash
# Installs a .deb of Portcullis on this machine as a user would, checks the service runs
# in monitor mode, and purges it again. For CI runners (systemd, Docker, sudo).
#
#   scripts/check-deb.sh <package.deb>
set -euo pipefail

deb=$(realpath "$1")
dpkg-deb --info "${deb}"
sudo apt-get install -y "${deb}"
portcullis --version
systemctl is-enabled portcullis
systemctl is-active portcullis
grep -x 'monitor = true' /etc/portcullis/config.toml
sudo apt-get purge -y portcullis
if systemctl is-active --quiet portcullis || [[ -e /etc/portcullis || -e /var/lib/portcullis ]]; then
  echo "portcullis is still running or left files behind after purge" >&2
  exit 1
fi
