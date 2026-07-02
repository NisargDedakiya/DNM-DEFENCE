#!/usr/bin/env bash
# Postgres backup script -- run via cron (or a docker-compose scheduled
# service) rather than relying on manual backups. This is the "backup
# strategy" the audit flagged; it's a script, not app code, because
# backup destinations/retention vary per deployment.
#
# Usage: ./backup_postgres.sh
# Cron example (daily at 2:15 AM): 15 2 * * * /path/to/backup_postgres.sh >> /var/log/track1-backup.log 2>&1

set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL must be set}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

echo "[$(date)] Starting backup..."
pg_dump "$DATABASE_URL" | gzip > "$BACKUP_DIR/track1_backup_${TIMESTAMP}.sql.gz"
echo "[$(date)] Backup written to $BACKUP_DIR/track1_backup_${TIMESTAMP}.sql.gz"

# Verify the backup is actually restorable, not just present on disk.
# A backup file that exists but is corrupt/incomplete is worse than no
# backup at all -- it creates false confidence. This spins up a throwaway
# Postgres container, restores into it, and checks the expected tables
# came back with data, then discards it.
if command -v docker >/dev/null 2>&1; then
  echo "[$(date)] Verifying backup is restorable..."
  VERIFY_CONTAINER="track1_backup_verify_${TIMESTAMP}"
  docker run -d --name "$VERIFY_CONTAINER" -e POSTGRES_PASSWORD=verify -p 15432:5432 postgres:15 > /dev/null
  sleep 5  # wait for postgres to accept connections

  if gunzip -c "$BACKUP_DIR/track1_backup_${TIMESTAMP}.sql.gz" | \
     PGPASSWORD=verify psql -h localhost -p 15432 -U postgres -d postgres > /dev/null 2>&1; then
    TABLE_COUNT=$(PGPASSWORD=verify psql -h localhost -p 15432 -U postgres -d postgres -tAc \
      "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
    if [ "$TABLE_COUNT" -ge 10 ]; then
      echo "[$(date)] Backup verified: restored successfully with $TABLE_COUNT tables."
    else
      echo "[$(date)] WARNING: backup restored but only found $TABLE_COUNT tables (expected 10+). Investigate."
    fi
  else
    echo "[$(date)] ERROR: backup failed to restore into a clean database. This backup may be corrupt."
  fi

  docker rm -f "$VERIFY_CONTAINER" > /dev/null 2>&1
else
  echo "[$(date)] Docker not available -- skipping restore verification. Run this manually periodically: gunzip -c <backup> | psql <test-db-url>"
fi

# Prune backups older than RETENTION_DAYS
find "$BACKUP_DIR" -name "track1_backup_*.sql.gz" -mtime "+${RETENTION_DAYS}" -delete
echo "[$(date)] Pruned backups older than ${RETENTION_DAYS} days."

# For production, replace/augment the local find/delete above with an
# upload step to S3/GCS/Azure Blob and rely on that bucket's lifecycle
# policy for retention instead of local disk. Example (uncomment and set):
# aws s3 cp "$BACKUP_DIR/track1_backup_${TIMESTAMP}.sql.gz" "s3://your-backup-bucket/"

echo "[$(date)] Done."
