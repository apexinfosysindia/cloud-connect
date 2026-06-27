-- 006_fleet_denormalize.sql
--
-- Denormalize each device's log summary onto the devices row so the admin
-- fleet list can paginate cheaply. Before this, GET /api/admin/fleet computed
-- log_count + the latest event (level/type/message/at) with five correlated
-- subqueries PER device row — fine for a handful of devices, but the cost grows
-- with fleet size and is incompatible with LIMIT/OFFSET paging (the subqueries
-- run for every row the sort considers, not just the page returned).
--
-- These five columns are kept current on the write path by device.insertDeviceLog
-- (lib/device.js), which recomputes log_count after its prune-to-250 and writes
-- the newest event in the same transaction as the INSERT. The paginated read
-- then just does SELECT d.* — no per-row subqueries.
--
-- Column names deliberately match the old subquery aliases (log_count,
-- last_event_level, last_event_type, last_event_message, last_event_at) so the
-- existing row -> serialized-device mapping is unchanged.
--
-- Idempotency / reconciliation note: this file was applied to live databases
-- before its on-disk copy was lost, so production already records version 6 in
-- schema_migrations. The runner (lib/migrator.js runPending) skips any version
-- already recorded, so re-introducing this file is a no-op there and only runs
-- on a fresh database. The migration runner owns the BEGIN/COMMIT boundary, so
-- this file contains pure DDL/DML only — no inline BEGIN/COMMIT.

-- @UP

ALTER TABLE devices ADD COLUMN log_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN last_event_level TEXT;
ALTER TABLE devices ADD COLUMN last_event_type TEXT;
ALTER TABLE devices ADD COLUMN last_event_message TEXT;
ALTER TABLE devices ADD COLUMN last_event_at DATETIME;

-- One-time backfill for devices that already have logs. The per-device lookups
-- are backed by idx_device_logs_device_created; ORDER BY id DESC LIMIT 1 picks
-- the newest row to mirror what insertDeviceLog writes going forward.
UPDATE devices SET
    log_count = (SELECT COUNT(*) FROM device_logs WHERE device_id = devices.id),
    last_event_level = (SELECT level FROM device_logs WHERE device_id = devices.id ORDER BY id DESC LIMIT 1),
    last_event_type = (SELECT event_type FROM device_logs WHERE device_id = devices.id ORDER BY id DESC LIMIT 1),
    last_event_message = (SELECT message FROM device_logs WHERE device_id = devices.id ORDER BY id DESC LIMIT 1),
    last_event_at = (SELECT created_at FROM device_logs WHERE device_id = devices.id ORDER BY id DESC LIMIT 1);

-- @DOWN
--
-- Reverses EXACTLY what @UP added: drops the five denormalized columns (reverse
-- order). The source data lives in device_logs and is untouched, so the summary
-- can be rebuilt by re-running @UP. No durable data loss.

ALTER TABLE devices DROP COLUMN last_event_at;
ALTER TABLE devices DROP COLUMN last_event_message;
ALTER TABLE devices DROP COLUMN last_event_type;
ALTER TABLE devices DROP COLUMN last_event_level;
ALTER TABLE devices DROP COLUMN log_count;
