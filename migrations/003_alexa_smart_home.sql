-- 003_alexa_smart_home.sql
--
-- Amazon Alexa Smart Home integration schema (fresh build — does NOT reuse the
-- previously-reverted Alexa attempt). Mirrors the google_home_* tables so the
-- lib/alexa/* code can reuse the same query patterns lib/google-home/* uses,
-- differing only in the protocol-translation layer.
--
-- Every DDL is IF NOT EXISTS so this file is idempotent. The migration runner
-- (lib/migrator.js) owns the BEGIN/COMMIT transaction boundary, so this file
-- contains pure DDL only — no inline BEGIN/COMMIT.
--
-- Table parallels:
--   google_home_auth_codes      -> alexa_auth_codes
--   google_home_tokens          -> alexa_tokens          (portal-issued, hashed)
--   (no Google analog)          -> alexa_lwa_tokens      (LWA, AES-256-GCM cipher)
--   google_home_entities        -> alexa_endpoints
--   google_home_command_queue   -> alexa_command_queue
--   google_home_sync_snapshots  -> alexa_sync_snapshots
--
-- users.alexa_* mirror the google_home_* user columns exactly so the portal UI
-- and lib/auth.js can apply the same gating logic symmetrically per channel.

-- @UP

-- ── users: Alexa preference + link-status columns ─────────────────────────
ALTER TABLE users ADD COLUMN alexa_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN alexa_linked INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN alexa_security_pin TEXT;

-- ── alexa_auth_codes ──────────────────────────────────────────────────────
-- Short-lived OAuth authorization codes issued by /api/alexa/oauth and
-- exchanged at /api/alexa/token. code_hash = sha256(code); the raw code is
-- never stored. Consumed on first exchange (consumed_at set), pruned by TTL.
CREATE TABLE IF NOT EXISTS alexa_auth_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL UNIQUE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    consumed_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ── alexa_tokens ──────────────────────────────────────────────────────────
-- Portal-issued OAuth tokens that Amazon presents back to us on directive
-- traffic (Bearer in endpoint.scope.token). One-way hashed; we never need the
-- plaintext back (we only compare incoming bearer hashes).
CREATE TABLE IF NOT EXISTS alexa_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    access_token_hash TEXT NOT NULL UNIQUE,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ── alexa_lwa_tokens ──────────────────────────────────────────────────────
-- Login with Amazon tokens AMAZON issues to us (via Alexa.Authorization
-- AcceptGrant). We must REPLAY these outbound when posting ChangeReport /
-- AddOrUpdateReport to the Event Gateway as that end user, so they cannot be
-- hashed — they are stored as AES-256-GCM ciphertext (see lib/alexa/crypto.js;
-- key in env ALEXA_LWA_TOKEN_ENC_KEY). UNIQUE(user_id): re-link overwrites,
-- unlink deletes the row.
CREATE TABLE IF NOT EXISTS alexa_lwa_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    access_token_encrypted TEXT,
    refresh_token_encrypted TEXT,
    region TEXT,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ── alexa_endpoints ───────────────────────────────────────────────────────
-- Device-pushed endpoint registry. Mirrors google_home_entities exactly (the
-- clean shape). entity_id is the stable per-user endpoint identifier; the
-- device bridge upserts these via /api/internal/devices/alexa/endpoints.
CREATE TABLE IF NOT EXISTS alexa_endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    entity_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    room_hint TEXT,
    exposed INTEGER NOT NULL DEFAULT 1,
    online INTEGER NOT NULL DEFAULT 1,
    entity_last_seen_at DATETIME,
    state_json TEXT,
    state_hash TEXT,
    last_reported_state_hash TEXT,
    last_reported_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, entity_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

-- ── alexa_command_queue ───────────────────────────────────────────────────
-- Directive-driven control commands queued for the physical device to poll.
CREATE TABLE IF NOT EXISTS alexa_command_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    entity_id TEXT NOT NULL,
    action TEXT NOT NULL,
    payload_json TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'dispatched', 'completed', 'failed', 'expired')),
    result_json TEXT,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

-- ── alexa_sync_snapshots ──────────────────────────────────────────────────
-- Per user+device baseline inventory so partial device deltas don't
-- false-offline endpoints not present in a partial push.
CREATE TABLE IF NOT EXISTS alexa_sync_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    snapshot_entity_ids_json TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, device_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alexa_auth_codes_expiry ON alexa_auth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_alexa_endpoints_user_exposed ON alexa_endpoints(user_id, exposed);
CREATE INDEX IF NOT EXISTS idx_alexa_endpoints_user_reported_hash ON alexa_endpoints(user_id, last_reported_state_hash);
CREATE INDEX IF NOT EXISTS idx_alexa_endpoints_user_last_seen ON alexa_endpoints(user_id, entity_last_seen_at);
CREATE INDEX IF NOT EXISTS idx_alexa_command_queue_device_status_expiry ON alexa_command_queue(device_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_alexa_command_queue_user_status ON alexa_command_queue(user_id, status);
CREATE INDEX IF NOT EXISTS idx_alexa_command_queue_dedup ON alexa_command_queue(device_id, entity_id, action, status);
CREATE INDEX IF NOT EXISTS idx_alexa_sync_snapshots_user_device ON alexa_sync_snapshots(user_id, device_id);
CREATE INDEX IF NOT EXISTS idx_alexa_lwa_tokens_user ON alexa_lwa_tokens(user_id);

-- @DOWN
--
-- Reverses EXACTLY what @UP added and nothing more. Drops the six Alexa tables
-- (their indexes go with them) and the three users.alexa_* columns. Everything
-- that existed before this migration — users' other columns and rows,
-- google_home_entities, devices, billing, etc. — is left completely untouched.
--
-- DATA NOTE: dropping these tables/columns destroys any Alexa data accumulated
-- AFTER this migration was applied (linked accounts, synced endpoints). That is
-- the correct meaning of "return to the state before this commit" — before it,
-- none of this existed. The migrate-down command backs up the DB and shows row
-- counts before running this, so a populated rollback is a deliberate choice.
--
-- DROP COLUMN requires SQLite 3.35.0+ (2021). Both prod (3.45) and dev (3.51)
-- exceed this; the runner wraps everything in one transaction.

DROP TABLE IF EXISTS alexa_command_queue;
DROP TABLE IF EXISTS alexa_sync_snapshots;
DROP TABLE IF EXISTS alexa_endpoints;
DROP TABLE IF EXISTS alexa_lwa_tokens;
DROP TABLE IF EXISTS alexa_tokens;
DROP TABLE IF EXISTS alexa_auth_codes;

ALTER TABLE users DROP COLUMN alexa_enabled;
ALTER TABLE users DROP COLUMN alexa_linked;
ALTER TABLE users DROP COLUMN alexa_security_pin;
