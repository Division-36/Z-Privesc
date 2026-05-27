#!/bin/sh
# testbeds/cron/cleanup.sh - remove the world-writable cron job.
set -e
rm -f /etc/cron.d/zprivesc-weak /etc/cron.d/zprivesc-wild
echo "cron testbed removed"
