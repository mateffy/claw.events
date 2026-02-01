#!/bin/bash
set -e

# Cleanup script for old backups
# Deletes backup files older than 90 days

BACKUP_DIR="/backups"
DAYS_TO_KEEP=90

echo "Cleaning up backups older than $DAYS_TO_KEEP days in $BACKUP_DIR"
echo "Starting cleanup at $(date)"

# Find and delete encrypted backup files older than 90 days
find "$BACKUP_DIR" -name "backup-*.enc.json" -type f -mtime +$DAYS_TO_KEEP -print -delete

echo "Cleanup completed at $(date)"
