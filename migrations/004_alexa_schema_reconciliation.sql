-- 004_alexa_schema_reconciliation.sql
--
-- Reconciles prod databases where migration 003 was previously applied
-- under the name "alexa_tables" (an earlier abandoned Alexa attempt) and
-- left the schema in a partial state that does not match what today's
-- lib/alexa/* code expects.
--
-- WHY A NEW MIGRATION AND NOT EDITING 003?
--   Forward-only migrators (like ours) never re-run a file whose version
--   is already stamped in schema_migrations. On prod we see:
--     schema_migrations: 3 | alexa_tables | 2026-04-20
--   but the file at 003_alexa_integration.sql has a completely different
--   shape than what actually ran. The clean path is a NEW version that
--   idempotently brings prod up to the shape the current codebase needs,
--   without disturbing databases that somehow never ran the old 003.
--
-- WHAT CHANGED BETWEEN THE OLD AND NEW SHAPE
--
-- alexa_tokens (OLD → NEW):
--   amazon_refresh_token TEXT              → lwa_refresh_token_encrypted TEXT
--   amazon_access_token TEXT               → lwa_access_token_encrypted TEXT
--   amazon_access_token_expires_at DATETIME → lwa_expires_at DATETIME
--   event_endpoint TEXT                    → (dropped — region derived from config)
--   (none)                                 → lwa_scopes TEXT
--
--   The old design stored LWA tokens as plaintext. The new design encrypts
--   them with AES-256-GCM using ALEXA_LWA_TOKEN_ENC_KEY. We do NOT attempt
--   to re-encrypt in-place: (a) the existing rows never completed the full
--   AcceptGrant cycle anyway (linking was broken at the time they were
--   written), (b) plaintext → ciphertext transformation inside a SQL
--   migration is ugly. Instead we PRESERVE the bearer-token half of the
--   row (access_token_hash, refresh_token_hash, expires_at — what Alexa
--   currently holds) and leave the LWA columns NULL. Next AcceptGrant
--   populates them properly.
--
-- alexa_auth_codes: identical. No change.
--
-- alexa_entity_state_hashes: deprecated. The new design folds
--   last_reported_state_hash + last_reported_at directly into
--   alexa_entities, so the side-table is dropped.
--
-- alexa_entities, alexa_command_queue, alexa_sync_snapshots: never
--   existed on the old schema. Created fresh here.
--
-- users.alexa_enabled / alexa_linked / alexa_security_pin: the old
--   migration already added these with the same column shape as the
--   current spec, so they are LEFT UNTOUCHED here.

-- ── 1. Rebuild alexa_tokens with the LWA-encrypted column shape ─────────
-- Rename-copy-drop pattern is the safe way to change column shape in
-- SQLite. Inside the migrator's single-transaction wrapper this is atomic.

ALTER TABLE alexa_tokens RENAME TO alexa_tokens_old_v3;

CREATE TABLE alexa_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    access_token_hash TEXT NOT NULL UNIQUE,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    lwa_access_token_encrypted TEXT,
    lwa_refresh_token_encrypted TEXT,
    lwa_expires_at DATETIME,
    lwa_scopes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Carry over the Cloud-Connect-side token state (what Alexa currently
-- holds a bearer for). Drop the old plaintext Amazon tokens — the first
-- AcceptGrant after this migration will repopulate the LWA half.
INSERT INTO alexa_tokens (
    id,
    user_id,
    access_token_hash,
    refresh_token_hash,
    expires_at,
    lwa_access_token_encrypted,
    lwa_refresh_token_encrypted,
    lwa_expires_at,
    lwa_scopes,
    created_at,
    updated_at
)
SELECT
    id,
    user_id,
    access_token_hash,
    refresh_token_hash,
    expires_at,
    NULL,
    NULL,
    NULL,
    NULL,
    created_at,
    updated_at
FROM alexa_tokens_old_v3;

DROP TABLE alexa_tokens_old_v3;

-- ── 2. Drop the deprecated state-hashes side-table ──────────────────────

DROP TABLE IF EXISTS alexa_entity_state_hashes;

-- ── 3. Create the tables that never existed on the old schema ───────────

CREATE TABLE IF NOT EXISTS alexa_entities (
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

-- ── 4. Indexes ──────────────────────────────────────────────────────────
-- idx_alexa_auth_codes_expiry is already present on prod from migration 3;
--   the IF NOT EXISTS below is a no-op there and creates it on greenfield.
-- idx_alexa_tokens_user: the old migration created one on alexa_tokens, but
--   our rename-copy-drop above DROPPED it along with alexa_tokens_old_v3
--   (SQLite drops all indexes attached to a dropped table). We deliberately
--   do NOT recreate it: the new alexa_tokens has `user_id INTEGER NOT NULL
--   UNIQUE`, which SQLite auto-indexes (sqlite_autoindex_alexa_tokens_N).
--   That autoindex already covers every query the current code does by
--   user_id. Adding a second explicit index would be dead weight on every
--   insert/update for zero read benefit.
-- Everything below matches what 003_alexa_integration.sql would have
-- created on a greenfield database.

CREATE INDEX IF NOT EXISTS idx_alexa_auth_codes_expiry ON alexa_auth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_alexa_entities_user_exposed ON alexa_entities(user_id, exposed);
CREATE INDEX IF NOT EXISTS idx_alexa_entities_user_reported_hash ON alexa_entities(user_id, last_reported_state_hash);
CREATE INDEX IF NOT EXISTS idx_alexa_entities_user_last_seen ON alexa_entities(user_id, entity_last_seen_at);
CREATE INDEX IF NOT EXISTS idx_alexa_command_queue_device_status_expiry ON alexa_command_queue(device_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_alexa_command_queue_user_status ON alexa_command_queue(user_id, status);
CREATE INDEX IF NOT EXISTS idx_alexa_command_queue_dedup ON alexa_command_queue(device_id, entity_id, action, status);
CREATE INDEX IF NOT EXISTS idx_alexa_sync_snapshots_user_device ON alexa_sync_snapshots(user_id, device_id);
