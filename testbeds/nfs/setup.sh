#!/bin/sh
# testbeds/nfs/setup.sh - create an /etc/exports with no_root_squash.
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
[ -f /etc/exports ] && cp -f /etc/exports /etc/exports.zprivesc-bak || true
cat > /etc/exports <<'EOF'
/tmp *(rw,sync,no_root_squash,insecure)
EOF
echo "nfs testbed ready: /etc/exports -> *(rw,no_root_squash)"
