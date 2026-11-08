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
#
# Permissions + encryption are intrinsic to this script, not delegated to
# the operator's umask or storage choice: archives are created owner-only
# (umask 077 + chmod 600) and, when BACKUP_ENCRYPTION_PASSPHRASE is set,
# encrypted with openssl AES-256-CBC (PBKDF2) — the plaintext archive is
# deleted after the encrypted copy verifies. Without the passphrase the
# backup is still written, but unencrypted (loud warning below).
set -euo pipefail

# Owner-only from the first byte, regardless of the ambient umask.
umask 077

: "${DATABASE_URL:?DATABASE_URL must be set (PostgreSQL connection string)}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"

# RETENTION_DAYS feeds `find -mtime -delete`: reject anything that is not
# a non-negative integer before it can become a find predicate.
case "$RETENTION_DAYS" in
  ''|*[!0-9]*)
    echo "error: RETENTION_DAYS must be a non-negative integer, got '$RETENTION_DAYS'" >&2
    exit 1
    ;;
esac

# Never prune from an empty or root BACKUP_DIR: -delete must stay anchored
# to the intended backup directory.
if [ -z "$BACKUP_DIR" ] || [ "$BACKUP_DIR" = "/" ]; then
  echo "error: BACKUP_DIR must be a non-empty path below the filesystem root" >&2
  exit 1
fi

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

# Owner-only, even if the ambient umask was permissive (umask 077 above
# already makes new files 600/700; chmod pins it explicitly).
chmod 600 "$OUT" "$MANIFEST"

# Encrypt at rest when a passphrase is configured. The passphrase is
# passed via the environment (openssl -pass env:...), never on the
# command line, so it does not appear in process listings. The encrypted
# archive replaces the plaintext one only after a decrypt round-trip
# proves it is readable; its name gains a .enc suffix so the format is
# explicit (see docs/BACKUP_AND_RESTORE.md for the restore command).
if [ -n "${BACKUP_ENCRYPTION_PASSPHRASE:-}" ]; then
  command -v openssl >/dev/null 2>&1 || { echo "error: openssl is required when BACKUP_ENCRYPTION_PASSPHRASE is set" >&2; exit 1; }
  ENC_OUT="$OUT.enc"
  openssl enc -aes-256-cbc -pbkdf2 -salt -pass env:BACKUP_ENCRYPTION_PASSPHRASE -in "$OUT" -out "$ENC_OUT"
  chmod 600 "$ENC_OUT"
  openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_ENCRYPTION_PASSPHRASE -in "$ENC_OUT" | gzip -t -
  rm -f "$OUT"
  OUT="$ENC_OUT"
else
  echo "WARNING: BACKUP_ENCRYPTION_PASSPHRASE is not set — this backup is UNENCRYPTED." >&2
  echo "WARNING: anyone who obtains the archive can read full production data. Set BACKUP_ENCRYPTION_PASSPHRASE to encrypt future backups." >&2
fi

# Prune archives older than the retention window (manifests go with them).
# -mindepth 1 -maxdepth 1 anchors the prune to BACKUP_DIR itself: only
# files directly in that directory are ever deleted.
find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -name 'secureguard-*.dump.gz' -mtime "+$RETENTION_DAYS" -delete
find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -name 'secureguard-*.dump.gz.enc' -mtime "+$RETENTION_DAYS" -delete
find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -name 'secureguard-*.manifest.txt' -mtime "+$RETENTION_DAYS" -delete

echo "backup OK: $OUT ($(du -h "$OUT" | cut -f1), $TABLES tables)"
echo "manifest: $MANIFEST"
