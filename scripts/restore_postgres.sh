#!/usr/bin/env bash
# Restores a backup produced by backup_postgres.sh.
# Usage: ./restore_postgres.sh path/to/track1_backup_TIMESTAMP.sql.gz

set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL must be set}"

if [ $# -ne 1 ]; then
  echo "Usage: $0 <backup_file.sql.gz>"
  exit 1
fi

BACKUP_FILE="$1"
if [ ! -f "$BACKUP_FILE" ]; then
  echo "Backup file not found: $BACKUP_FILE"
  exit 1
fi

echo "WARNING: this will overwrite the current contents of the target database."
read -p "Type the database name to confirm: " confirm

echo "[$(date)] Restoring $BACKUP_FILE ..."
gunzip -c "$BACKUP_FILE" | psql "$DATABASE_URL"
echo "[$(date)] Restore complete."
