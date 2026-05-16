#!/usr/bin/env bash
#
# check-migration-immutability.sh
#
# Fails the build if the diff against a base ref MODIFIES or DELETES any file
# under migrations/ that exists in the base ref. New files (additions) are
# always allowed. This is the single rule whose absence cost us roughly two
# weeks during the v1 Alexa attempt — old migration 003 was edited in place
# while production already had it stamped, requiring an entire reconciliation
# migration (deleted 004) to drag the schema back to a known shape.
#
# CONVENTION: once a migration file is merged to main, it is immutable.
# If you need to change the schema, write a new NNN_*.sql file with a higher
# version. Editing or deleting a merged migration is a forward-only-migrator
# violation and will cause prod schemas to diverge silently.
#
# Usage (locally):     bash scripts/check-migration-immutability.sh origin/main
# Usage (CI / no arg): defaults to origin/main, fetches if not present.
#
# Exit codes:
#   0  no offending changes
#   1  one or more migrations were modified or deleted
#   2  invocation / git error

set -euo pipefail

BASE_REF="${1:-origin/main}"

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "ERROR: not in a git repository" >&2
    exit 2
fi

# Make sure we have the base ref locally; on CI runners that did a shallow
# clone, fetch enough history to diff against it.
if ! git rev-parse --verify --quiet "${BASE_REF}" >/dev/null; then
    echo "Base ref '${BASE_REF}' not present locally; attempting to fetch..."
    if ! git fetch --no-tags --depth=50 origin "${BASE_REF#origin/}" >/dev/null 2>&1; then
        echo "ERROR: could not resolve or fetch base ref '${BASE_REF}'" >&2
        exit 2
    fi
fi

# git diff --name-status emits one line per changed path:
#   A<TAB>path   added
#   M<TAB>path   modified
#   D<TAB>path   deleted
#   R100<TAB>old<TAB>new  renamed
# We treat M, D, and R as forbidden for anything under migrations/.
OFFENDERS=$(git diff --name-status "${BASE_REF}"...HEAD -- migrations/ \
            | awk '$1 ~ /^[MDR]/ { print }')

if [ -n "${OFFENDERS}" ]; then
    echo "ERROR: migration files are immutable once merged."
    echo
    echo "The following migrations/ entries were modified, deleted, or renamed"
    echo "in this branch versus ${BASE_REF}:"
    echo
    echo "${OFFENDERS}" | sed 's/^/    /'
    echo
    echo "If you need to change the schema, ADD a new NNN_*.sql file with the"
    echo "next-highest version. Do not edit a merged migration — the runner"
    echo "will not re-apply it on environments that already stamped it, and"
    echo "the prod schema will silently diverge from this repo. (See the"
    echo "v1 Alexa post-mortem for the canonical example.)"
    exit 1
fi

echo "Migration immutability check passed (no edits to existing migrations)."
