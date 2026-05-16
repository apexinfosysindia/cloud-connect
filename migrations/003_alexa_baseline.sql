-- 003_alexa_baseline.sql
--
-- Recreate the Alexa schema "residue" that lib/alexa/schema-baseline.js
-- adopted from the v1 Alexa attempt. See the decision record at the top of
-- that file for the original context.
--
-- Why this migration exists, even though Phase 2's decision record said "do
-- not write one":
--   The original decision rested on the assumption that every database we
--   would deploy against already had the v1 residue. That assumption held
--   for the boxes we inspected at v2 kickoff, but it does NOT hold in two
--   real cases:
--     1. A fresh database (a new staging box, a developer's first checkout,
--        a restored backup from before the v1 attempt was ever deployed).
--     2. An environment where the alexa_* tables were manually dropped after
--        the v1 revert (cleanup that "looked right" at the time).
--   The Phase 9 production bring-up hit case (1) on 2026-05-16: the
--   schema-baseline check threw on every boot ("missing tables
--   [alexa_entities, alexa_command_queue, alexa_sync_snapshots]") and pm2
--   gave up after 47 restarts.
--
-- Forward compatibility:
--   The migrator already accepts (3, 'alexa_integration') as the
--   schema_migrations row for "Alexa schema is present" — that's exactly
--   what the schema-baseline check verifies. On a database that ALREADY has
--   the residue from v1, schema_migrations.version=3 is also already there,
--   so this whole file no-ops twice over: every CREATE/ALTER below is
--   IF NOT EXISTS, and the migrator skips the file outright because the
--   tracking row already says version 3 is applied.
--
-- IF NOT EXISTS on every DDL means this file is safe to run against:
--   - a fresh database (creates everything from scratch)
--   - a half-recreated database where some tables exist and others don't
--   - the v1-residue database (no-op; nothing is created)
--
-- Column unions:
--   The table shapes below are the UNION of every column referenced by the
--   v2 codebase (routes/alexa-*.js, lib/alexa/*.js) and the test fixtures.
--   Where a test fixture used a minimal column set (e.g. admin.test.js's
--   4-column alexa_tokens stub), we use the broader shape so production
--   matches what the route code actually writes.

-- ─── users: Alexa preference + link-status columns ────────────────────────
-- The schema-baseline check requires these three on the users table. They
-- mirror the google_home_* columns added in 001 so the portal UI can show
-- consistent on/off + linked state across the two integrations.
ALTER TABLE users ADD COLUMN alexa_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN alexa_linked INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN alexa_security_pin TEXT;

-- ─── alexa_auth_codes ────────────────────────────────────────────────────
-- Short-lived OAuth authorization codes issued by /api/alexa/oauth and
-- exchanged at /api/alexa/token. code_hash is sha256(code) — we never
-- store the raw code. Rows are consumed on first exchange (consumed_at set)
-- and pruned by TTL.
CREATE TABLE IF NOT EXISTS alexa_auth_codes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL,
    code_hash    TEXT NOT NULL UNIQUE,
    redirect_uri TEXT NOT NULL,
    scopes       TEXT,
    expires_at   DATETIME NOT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    consumed_at  DATETIME
);

-- ─── alexa_tokens ────────────────────────────────────────────────────────
-- One row per linked user. Holds two token pairs:
--   - access_token_hash / refresh_token_hash + expires_at:
--       the tokens WE issue to Amazon (Amazon sends them back in the
--       Authorization header of every directive). Stored as sha256 hashes.
--   - lwa_access_token_encrypted / lwa_refresh_token_encrypted +
--     lwa_expires_at + lwa_scopes:
--       the tokens AMAZON issued to us (so we can post ChangeReports to the
--       Event Gateway as that user). Stored encrypted with AES-256-GCM
--       (see lib/alexa/crypto.js) because the refresh token is a long-lived
--       credential.
-- UNIQUE(user_id) means re-linking overwrites; force-unlink deletes the row.
CREATE TABLE IF NOT EXISTS alexa_tokens (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id                     INTEGER NOT NULL UNIQUE,
    access_token_hash           TEXT,
    refresh_token_hash          TEXT,
    expires_at                  DATETIME,
    lwa_access_token_encrypted  TEXT,
    lwa_refresh_token_encrypted TEXT,
    lwa_expires_at              DATETIME,
    lwa_scopes                  TEXT,
    created_at                  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at                  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─── alexa_entities ──────────────────────────────────────────────────────
-- The addon's last reported entity inventory for each user. exposed=1 means
-- the user opted to expose it to Alexa; the Discovery dispatcher filters on
-- this. state_json is the most recent attributes snapshot from HA, used by
-- ReportState and as the diff source for ChangeReport. state_hash lets the
-- event-gateway dedupe redundant ChangeReports cheaply.
CREATE TABLE IF NOT EXISTS alexa_entities (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL,
    device_id    INTEGER NOT NULL,
    entity_id    TEXT NOT NULL,
    display_name TEXT NOT NULL,
    entity_type  TEXT NOT NULL,
    room_hint    TEXT,
    exposed      INTEGER NOT NULL DEFAULT 1,
    online       INTEGER NOT NULL DEFAULT 1,
    state_json   TEXT,
    state_hash   TEXT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, entity_id)
);

-- ─── alexa_command_queue ─────────────────────────────────────────────────
-- Rendezvous between routes/alexa-smarthome.js (writer) and
-- routes/alexa-device-api.js (drained by the addon). Each row is one
-- Alexa.PowerController / Alexa.BrightnessController / etc. directive
-- waiting to be executed on the HA instance. status moves:
--   'pending' (queued) → 'dispatched' (addon polled it) →
--   'completed' | 'failed' | 'expired'
-- expires_at is set on insert (default 45s, tunable via
-- ALEXA_COMMAND_TTL_SECONDS) so the row times out if the addon is offline.
CREATE TABLE IF NOT EXISTS alexa_command_queue (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL,
    device_id    INTEGER NOT NULL,
    entity_id    TEXT NOT NULL,
    action       TEXT NOT NULL,
    payload_json TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',
    result_json  TEXT,
    expires_at   DATETIME NOT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─── alexa_sync_snapshots ────────────────────────────────────────────────
-- Last snapshot of (user, device) → entity_id list received from the addon's
-- /entities/sync call. Used by the sync route to compute the set of entities
-- to delete (those present in the previous snapshot but absent from the
-- current sync). UNIQUE(user_id, device_id) means one row per addon.
CREATE TABLE IF NOT EXISTS alexa_sync_snapshots (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id                  INTEGER NOT NULL,
    device_id                INTEGER NOT NULL,
    snapshot_entity_ids_json TEXT,
    updated_at               DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, device_id)
);

-- ─── Indices ─────────────────────────────────────────────────────────────
-- Hot paths only. The UNIQUE constraints above already cover the
-- (user_id, entity_id) and (user_id, device_id) lookups; these add the
-- two access patterns that aren't naturally indexed:
--   - alexa_auth_codes by expiry, for the TTL pruner sweep
--   - alexa_command_queue by (status, expires_at) for the addon's poll
CREATE INDEX IF NOT EXISTS idx_alexa_auth_codes_expires_at
    ON alexa_auth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_alexa_command_queue_status_expires
    ON alexa_command_queue(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_alexa_command_queue_user_device
    ON alexa_command_queue(user_id, device_id);
