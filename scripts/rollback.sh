#!/usr/bin/env bash
#
# rollback.sh — roll the deployment back to an earlier git ref, undoing any
# DB schema migrations introduced after that ref, in the correct order.
#
# WHY THIS EXISTS
#   `git reset --hard <ref>` reverts CODE only. It does not touch the database,
#   so a schema migration shipped in the commit you're rolling away stays
#   applied (its tables/columns linger). Conversely, our migrate-down tool
#   reads each migration's `-- @DOWN` section FROM THE FILE ON DISK — so if you
#   reset the code first, the migration file vanishes and the rollback can no
#   longer find its @DOWN. This script enforces the only correct order:
#
#       1. Work out which migrations exist in HEAD but NOT in the target ref.
#       2. Roll the DB DOWN to the target's schema floor (files still on disk).
#       3. THEN git reset --hard the code to the target ref.
#       4. Reinstall deps and restart the service.
#
# This is a DELIBERATE, DESTRUCTIVE, GUARDED operation:
#   - git reset --hard discards commits and any uncommitted TRACKED changes.
#   - rolling a migration down DELETES data accumulated in its structures.
#   migrate-down.js takes a DB backup and prints row counts before dropping;
#   this script refuses to run over uncommitted tracked changes unless --force.
#
# Note: database.sqlite and .env are gitignored, so `git reset --hard` never
# touches them — only the schema rollback in step 2 changes the DB.
#
# Usage:
#   ./scripts/rollback.sh <ref>              # roll back to a tag or commit SHA
#   ./scripts/rollback.sh v1.4.0
#   ./scripts/rollback.sh --dry-run <ref>    # show the full plan, change nothing
#   ./scripts/rollback.sh --force <ref>      # proceed despite a dirty work tree
#   ./scripts/rollback.sh --no-restart <ref> # skip npm ci + pm2 restart
#   ./scripts/rollback.sh --yes <ref>        # skip the final confirmation prompt
#
# A target ref is REQUIRED — there is no implicit default, by design.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ---- arg parsing -----------------------------------------------------------
DRY_RUN=0
FORCE=0
DO_RESTART=1
ASSUME_YES=0
TARGET=""

usage() {
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --force) FORCE=1 ;;
        --no-restart) DO_RESTART=0 ;;
        --yes | -y) ASSUME_YES=1 ;;
        --help | -h) usage 0 ;;
        -*) echo "Unknown option: $1" >&2; usage 1 ;;
        *)
            if [[ -n "$TARGET" ]]; then
                echo "ERROR: more than one target ref given ('$TARGET' and '$1')." >&2
                exit 1
            fi
            TARGET="$1"
            ;;
    esac
    shift
done

if [[ -z "$TARGET" ]]; then
    echo "ERROR: a target ref (tag or commit SHA) is required." >&2
    echo "       e.g. ./scripts/rollback.sh v1.4.0" >&2
    exit 1
fi

# ---- preflight: sane git state --------------------------------------------
if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "ERROR: not inside a git repository." >&2
    exit 1
fi

# Resolve the target to a concrete commit; fail clearly if it doesn't exist.
if ! TARGET_SHA="$(git rev-parse --verify --quiet "${TARGET}^{commit}")"; then
    echo "ERROR: target ref '$TARGET' does not resolve to a commit." >&2
    echo "       Fetch first if it's a new tag:  git fetch --all --tags" >&2
    exit 1
fi
HEAD_SHA="$(git rev-parse HEAD)"

if [[ "$TARGET_SHA" == "$HEAD_SHA" ]]; then
    echo "Nothing to do: HEAD is already at $TARGET ($TARGET_SHA)."
    exit 0
fi

# Ensure target is actually an ancestor of HEAD — we roll BACK, not sideways
# or forward onto an unrelated branch. (A non-ancestor target would mean the
# migration diff below is meaningless.)
if ! git merge-base --is-ancestor "$TARGET_SHA" "$HEAD_SHA"; then
    echo "ERROR: '$TARGET' ($TARGET_SHA) is not an ancestor of HEAD ($HEAD_SHA)." >&2
    echo "       This tool only rolls backward along the current history." >&2
    exit 1
fi

# Guard against nuking uncommitted TRACKED changes. Defined here but called
# only on a REAL run (a --dry-run changes nothing, so it must never be blocked).
# Untracked/gitignored files (database.sqlite, .env) are unaffected by
# git reset --hard, so we only guard tracked modifications.
assert_clean_tree_or_force() {
    if git diff --quiet && git diff --cached --quiet; then
        return 0
    fi
    echo "WARNING: you have uncommitted changes to TRACKED files:" >&2
    git --no-pager status --short -- $(git diff --name-only; git diff --cached --name-only) >&2 || true
    if [[ "$FORCE" -ne 1 ]]; then
        echo "" >&2
        echo "Refusing to 'git reset --hard' over them (they would be lost)." >&2
        echo "Commit/stash them, or re-run with --force to discard them." >&2
        exit 1
    fi
    echo "(--force given: these tracked changes WILL be discarded.)" >&2
}

# ---- compute the migration floor ------------------------------------------
# Migration versions present in a given ref's migrations/ directory.
migration_versions_at() {
    local ref="$1"
    git ls-tree -r --name-only "$ref" -- migrations/ 2>/dev/null \
        | grep -E 'migrations/[0-9]{3,}_.+\.sql$' \
        | sed -E 's#.*/([0-9]{3,})_.*#\1#' \
        | sed 's/^0*//' \
        | sort -n
}

HEAD_VERSIONS="$(migration_versions_at "$HEAD_SHA" || true)"
TARGET_VERSIONS="$(migration_versions_at "$TARGET_SHA" || true)"

# Migrations to undo = present in HEAD but absent in target.
TO_REVERT="$(comm -23 \
    <(printf '%s\n' "$HEAD_VERSIONS" | sed '/^$/d') \
    <(printf '%s\n' "$TARGET_VERSIONS" | sed '/^$/d') || true)"

# The schema floor we roll DOWN to = highest version still present in target.
# If target has no migrations at all, floor is 0 (roll everything back).
FLOOR="$(printf '%s\n' "$TARGET_VERSIONS" | sed '/^$/d' | tail -n1)"
FLOOR="${FLOOR:-0}"

echo "=========================================================="
echo " Rollback plan"
echo "=========================================================="
echo "  Current HEAD : $HEAD_SHA  ($(git log -1 --format=%s "$HEAD_SHA"))"
echo "  Target ref   : $TARGET -> $TARGET_SHA  ($(git log -1 --format=%s "$TARGET_SHA"))"
echo ""
if [[ -z "$(printf '%s' "$TO_REVERT" | tr -d '[:space:]')" ]]; then
    echo "  DB schema    : no migrations to undo (target and HEAD share the same"
    echo "                 migration set). Only the code will move."
else
    echo "  DB schema    : will roll DOWN to version $FLOOR, undoing migration(s):"
    printf '                   %s\n' $TO_REVERT
    echo "                 (migrate-down will back up the DB and show row counts"
    echo "                  for any populated tables before dropping anything.)"
fi
echo ""
echo "  Then         : git reset --hard $TARGET_SHA"
if [[ "$DO_RESTART" -eq 1 ]]; then
    echo "                 npm ci --omit=dev && pm2 restart server"
else
    echo "                 (--no-restart: deps/service left untouched)"
fi
echo "=========================================================="

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo ""
    echo "--dry-run: no changes made."
    exit 0
fi

# Now that we're past the dry-run gate, this is a real, destructive run:
# enforce a clean working tree (or honour --force).
assert_clean_tree_or_force

# ---- confirm ---------------------------------------------------------------
if [[ "$ASSUME_YES" -ne 1 ]]; then
    echo ""
    read -r -p "Type 'rollback' to proceed: " ANSWER
    if [[ "$ANSWER" != "rollback" ]]; then
        echo "Aborted. No changes made."
        exit 0
    fi
fi

# ---- step 1: roll the DB DOWN (BEFORE touching the code) -------------------
if [[ -n "$(printf '%s' "$TO_REVERT" | tr -d '[:space:]')" ]]; then
    echo ""
    echo ">> Rolling database schema down to version $FLOOR ..."
    # migrate-down.js takes its own backup and reverts every applied migration
    # with version > FLOOR, highest first, each in a transaction.
    node "$SCRIPT_DIR/migrate-down.js" --to "$FLOOR" --yes
else
    echo ""
    echo ">> No DB schema rollback needed."
fi

# ---- step 2: move the code -------------------------------------------------
echo ""
echo ">> Resetting code to $TARGET_SHA ..."
git reset --hard "$TARGET_SHA"

# ---- step 3: deps + restart ------------------------------------------------
if [[ "$DO_RESTART" -eq 1 ]]; then
    echo ""
    echo ">> Reinstalling production dependencies ..."
    npm ci --omit=dev

    echo ""
    echo ">> Restarting service ..."
    if command -v pm2 >/dev/null 2>&1; then
        pm2 restart server
    else
        echo "WARNING: pm2 not found on PATH — restart the service manually." >&2
    fi
fi

echo ""
echo "Rollback complete. Now at: $(git rev-parse HEAD) ($(git log -1 --format=%s HEAD))"
