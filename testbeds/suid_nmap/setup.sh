#!/bin/bash
# Setup for suid_nmap testbed
set -e
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
TB=/root/zp/testbeds/suid_nmap
cp /usr/bin/nmap $TB/nmap 2>/dev/null || cp /usr/bin/find $TB/nmap
chmod 4755 $TB/nmap; chown root:root $TB/nmap
echo "suid_nmap ready: $TB/nmap (SUID root)"
