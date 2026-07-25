#!/bin/bash
export WSLENV=
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "Starting Z-Privesc scan..."
/root/zp/build/bin/z_privesc --all --json > /tmp/zp_result.json 2>/tmp/zp_stderr.log
echo "RC=$?" >> /tmp/zp_stderr.log
echo "Scan complete"
