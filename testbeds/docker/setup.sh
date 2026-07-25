#!/bin/sh
# testbeds/docker/setup.sh - create a fake world-writable docker.sock Unix socket.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
python3 -c "
import socket, os
path = '/var/run/docker.sock'
if os.path.exists(path):
    os.unlink(path)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(1)
os.chmod(path, 0o666)
print('docker.sock created and listening')
"
echo "docker testbed ready: /var/run/docker.sock (mode 0666, unix socket)"
