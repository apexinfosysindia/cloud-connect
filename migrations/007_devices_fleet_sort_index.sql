-- 007_devices_fleet_sort_index.sql
--
-- Composite index backing the admin fleet list's sort order. GET /api/admin/fleet
-- orders by last_seen_at DESC, updated_at DESC, created_at DESC and pages with
-- LIMIT/OFFSET. Without a matching index SQLite materializes the full sorted set
-- into a temp B-tree on every request (and re-walks it for deep OFFSETs); this
-- three-column index lets the planner satisfy the ORDER BY + LIMIT directly.
--
-- Idempotency / reconciliation note: like 006, this was applied to live
-- databases before its on-disk copy was lost, so production already records
-- version 7 in schema_migrations and the index already exists there. The runner
-- skips already-recorded versions, so this file is a no-op on those databases
-- and only creates the index on a fresh one. CREATE/DROP are IF (NOT) EXISTS so
-- the file is independently idempotent. The runner owns the transaction.

-- @UP

CREATE INDEX IF NOT EXISTS idx_devices_fleet_sort
    ON devices(last_seen_at DESC, updated_at DESC, created_at DESC);

-- @DOWN

DROP INDEX IF EXISTS idx_devices_fleet_sort;
