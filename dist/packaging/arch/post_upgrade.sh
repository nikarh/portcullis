#!/bin/sh
# Restart the service if it runs; its rules stay in place meanwhile.
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  systemctl try-restart portcullis.service || true
fi
