#!/usr/bin/env bash
# SecureGuard database backup — Day 9.
#
# Takes a logical backup of the production PostgreSQL database (Supabase)
# with pg_dump (custom format, gzipped) and verifies the archive before
# calling it done. Run on a host that has BOTH the DATABASE_URL env var
# and pg_dump installed (Render shell, or a laptop) — this VM has neither,
# so the script is statically verified here (bash -n) and the first real
# run is a HIS STEP (see docs/BACKUP_AND_RESTORE.md).
#
#   DATABASE_URL='postgres://...' BACKUP_DIR=./backups ./backup-db.sh
#
# The connection string is NEVER printed or written to any file. The
# archive contains full production data: keep BACKUP_DIR private and
# never commit it (backend/.gitignore covers backups/).
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL must be set (PostgreSQL connection string)}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"

for tool in pg_dump gzip pg_restore; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool is not installed" >&2; exit 1; }
done

mkdir -p "$BACKUP_DIR"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
OUT="$BACKUP_DIR/secureguard-$STAMP.dump.gz"
MANIFEST="$BACKUP_DIR/secureguard-$STAMP.manifest.txt"

# Custom format (-Fc) so a trial restore can use pg_restore selectively.
pg_dump --dbname="$DATABASE_URL" --format=custom --no-owner --no-privileges \
  | gzip -9 > "$OUT"

# Verify: gzip integrity + the archive lists real database objects.
gzip -t "$OUT"
gzip -dc "$OUT" | pg_restore --list - > "$MANIFEST"
TABLES="$(grep -c '^.*; .* TABLE ' "$MANIFEST" || true)"
[ "$TABLES" -gt 0 ] || { echo "error: backup manifest lists no tables — refusing to keep a hollow backup" >&2; rm -f "$OUT" "$MANIFEST"; exit 1; }

# Prune archives older than the retention window (manifests go with them).
find "$BACKUP_DIR" -name 'secureguard-*.dump.gz' -mtime "+$RETENTION_DAYS" -delete
find "$BACKUP_DIR" -name 'secureguard-*.manifest.txt' -mtime "+$RETENTION_DAYS" -delete

echo "backup OK: $OUT ($(du -h "$OUT" | cut -f1), $TABLES tables)"
echo "manifest: $MANIFEST"
