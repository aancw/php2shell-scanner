#!/bin/sh
# Installs the mounted public key, sets the lab password, serves PHP over http
# and runs sshd.
set -e

if [ -s /run/authorized_keys ]; then
  install -m 600 -o root -g root /run/authorized_keys /root/.ssh/authorized_keys
fi

if [ -n "$P2S_ROOT_PASSWORD" ]; then
  echo "root:$P2S_ROOT_PASSWORD" | chpasswd
fi

apache2-foreground &

exec /usr/sbin/sshd -D -e
