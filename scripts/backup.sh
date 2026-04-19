#!/usr/bin/env bash
#
# backup.sh — safe online backup of the Cloud Connect SQLite database.
#
# Uses the SQLite online backup API (`.backup`) rather than `cp` so we never
# capture a torn state while writes are in flight. Output is gzipped and old
# backups are rotated.
#
# Usage:
#   ./scripts/backup.sh
#   BACKUP_DIR=/mnt/backups ./scripts/backup.sh
#   BACKUP_RETENTION_DAYS=7 ./scripts/backup.sh
#
# Env:
#   DATABASE_PATH           Path to the source DB. Default: <repo>/database.sqlite
#   BACKUP_DIR              Output directory. Default: <repo>/backups
#   BACKUP_RETENTION_DAYS   Delete backups older than this. Default: 14
#   BACKUP_SKIP_INTEGRITY   Set to "1" to skip PRAGMA integrity_check. Default: unset.
#
# Exit codes:
#   0 on success, non-zero on any failure (missing sqlite3, backup error,
#   integrity check failure, write failure).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DATABASE_PATH="${DATABASE_PATH:-$REPO_ROOT/database.sqlite}"
BACKUP_DIR="${BACKUP_DIR:-$REPO_ROOT/backups}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "ERROR: sqlite3 CLI is not installed or not on PATH" >&2
    exit 1
fi

if [[ ! -f "$DATABASE_PATH" ]]; then
    echo "ERROR: source database not found: $DATABASE_PATH" >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
TMP_SNAPSHOT="$BACKUP_DIR/.pending-$TIMESTAMP.sqlite"
FINAL_PATH="$BACKUP_DIR/database-$TIMESTAMP.sqlite.gz"

# Ensure we don't leave a partial snapshot behind on failure.
cleanup() {
    rm -f "$TMP_SNAPSHOT" "$TMP_SNAPSHOT-journal" "$TMP_SNAPSHOT-wal" "$TMP_SNAPSHOT-shm"
}
trap cleanup EXIT

echo "[$(date -u +%FT%TZ)] Backing up $DATABASE_PATH -> $FINAL_PATH"

# Online backup: safe against concurrent writes. Produces a single file
# (no WAL/SHM sidecars) representing a consistent snapshot.
sqlite3 "$DATABASE_PATH" ".backup '$TMP_SNAPSHOT'"

# Integrity check on the snapshot, not the live DB — confirms the copy is
# readable and internally consistent. Skip with BACKUP_SKIP_INTEGRITY=1 if
# you have a very large DB and want to keep backups fast.
if [[ "${BACKUP_SKIP_INTEGRITY:-}" != "1" ]]; then
    INTEGRITY="$(sqlite3 "$TMP_SNAPSHOT" 'PRAGMA integrity_check' | head -n1)"
    if [[ "$INTEGRITY" != "ok" ]]; then
        echo "ERROR: integrity check on snapshot failed: $INTEGRITY" >&2
        exit 1
    fi
fi

gzip -c "$TMP_SNAPSHOT" > "$FINAL_PATH"

# Resolve paths without `realpath` (not on stock macOS).
SIZE_BYTES="$(wc -c < "$FINAL_PATH" | tr -d ' ')"
echo "[$(date -u +%FT%TZ)] Snapshot OK: $FINAL_PATH (${SIZE_BYTES} bytes)"

# Rotation — delete gzipped snapshots older than retention window.
# Tolerates an empty BACKUP_DIR (no matches → find exits 0 with no output).
find "$BACKUP_DIR" -maxdepth 1 -name 'database-*.sqlite.gz' -type f \
    -mtime "+${BACKUP_RETENTION_DAYS}" -print -delete | \
    sed 's/^/[rotated] /' || true

echo "[$(date -u +%FT%TZ)] Backup complete."
