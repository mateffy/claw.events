#!/bin/bash
set -e

# Setup cron jobs for backup and cleanup

# Create cron entries
echo "0 2 * * * /usr/local/bin/backup.sh >> /var/log/backup.log 2>&1" > /etc/crontabs/root
echo "0 3 1 * * /usr/local/bin/cleanup.sh >> /var/log/cleanup.log 2>&1" >> /etc/crontabs/root

# Ensure backup directory exists
mkdir -p /backups

# Start crond in foreground
echo "Starting cron daemon..."
exec crond -f -l 2
