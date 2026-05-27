#!/bin/sh
# testbeds/polkit/setup.sh - install a vulnerable polkit config (mock).
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
mkdir -p /usr/share/polkit-1
echo "0.96" > /usr/share/polkit-1/version
mkdir -p /usr/bin
[ -e /usr/bin/pkexec ] || printf '#!/bin/sh\necho mock\n' > /usr/bin/pkexec
chmod 0755 /usr/bin/pkexec
chmod 04755 /usr/bin/pkexec
echo "polkit testbed ready"
