#!/bin/sh
# testbeds/cron2/cleanup.sh - remove the world-writable cron job.
set -e
rm -f /etc/cron.d/zprivesc-cron2
echo "cron2 removed"
