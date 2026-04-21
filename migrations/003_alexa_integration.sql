-- 003_alexa_integration.sql
--
-- Introduces first-class Alexa Smart Home support alongside the existing
-- Google Home integration. The column shapes intentionally mirror the
-- google_home_* tables so lib/alexa/* can reuse the same query patterns
-- that lib/google-home/* established, differing only in the protocol
-- translation layer.
--
-- Key design decisions baked into this schema:
--
-- 1. alexa_tokens holds BOTH sides of the account link:
--      - the portal-issued token the Alexa skill presents to Cloud Connect
--        (access_token_hash / refresh_token_hash), and
--      - the Login with Amazon (LWA) token Cloud Connect presents to the
--        Alexa Event Gateway when pushing proactive ChangeReport events
--        (lwa_access_token / lwa_refresh_token / lwa_expires_at).
--    LWA tokens are per-user (not service-wide) because ChangeReport must
--    be authenticated as the end user whose device changed state, so each
--    row stores one user's LWA bearer pair.
--
--    Unlike the portal-issued tokens, LWA tokens are stored as ciphertext
--    rather than hashes: we must be able to REPLAY them on outbound calls
--    to api.amazonalexa.com, which a one-way hash would prevent. The
--    column names are _encrypted to make that contract explicit. Encryption
--    key lives in ALEXA_LWA_TOKEN_ENC_KEY (set via lib/config.js).
--
-- 2. alexa_command_queue is a separate table from google_home_command_queue
--    (rather than a unified device_command_queue with a channel column) to
--    keep the existing Google flow strictly untouched by this migration.
--    The addon polls both queues on each cycle. If we later decide to
--    unify, it will be its own migration.
--
-- 3. users.alexa_enabled / alexa_linked / alexa_security_pin mirror the
--    google_home_* user columns exactly so lib/auth.js and the portal UI
--    can apply the same gating logic symmetrically per channel.
--
-- 4. Indexes mirror the Google ones: (user_id, exposed) for discovery
--    filtering, (user_id, last_reported_state_hash) for dedup during
--    ChangeReport, (device_id, status, expires_at) for addon poll, etc.
--    If a query pattern is fast on google_home_entities today, the
--    equivalent query will be fast on alexa_entities after this migration.

ALTER TABLE users ADD COLUMN alexa_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN alexa_linked INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN alexa_security_pin TEXT;

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

CREATE TABLE IF NOT EXISTS alexa_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    -- Cloud Connect-issued tokens presented by the Alexa skill / Lambda
    -- forwarder on directive traffic. One-way hashed.
    access_token_hash TEXT NOT NULL UNIQUE,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    -- Login with Amazon tokens Cloud Connect must replay outbound when
    -- pushing ChangeReport / AddOrUpdateReport to the Event Gateway.
    -- Stored as ciphertext (AES-GCM, key in env) because we need the
    -- plaintext at send time; NULL until the user completes LWA linking.
    lwa_access_token_encrypted TEXT,
    lwa_refresh_token_encrypted TEXT,
    lwa_expires_at DATETIME,
    lwa_scopes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alexa_entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    entity_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    -- entity_type stores the HA-style domain (light, switch, climate, ...)
    -- EXACTLY as google_home_entities does, so lib/alexa/entity-mapping.js
    -- can share the same domain vocabulary as lib/google-home/entity-mapping.js.
    -- The Alexa-specific translation (domain -> capability interfaces) is
    -- computed at read time, not stored here.
    entity_type TEXT NOT NULL,
    room_hint TEXT,
    exposed INTEGER NOT NULL DEFAULT 1,
    online INTEGER NOT NULL DEFAULT 1,
    entity_last_seen_at DATETIME,
    state_json TEXT,
    state_hash TEXT,
    -- last_reported_* powers ChangeReport dedup: we only emit when the
    -- hash of the new state differs from last_reported_state_hash.
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
    -- action stores the normalized intent (e.g. 'power.on', 'brightness.set',
    -- 'thermostat.setpoint') that the addon knows how to translate to a
    -- Home Assistant service call. Normalization happens in
    -- routes/alexa-smarthome.js at directive-dispatch time so the addon
    -- stays protocol-agnostic.
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

CREATE INDEX IF NOT EXISTS idx_alexa_auth_codes_expiry ON alexa_auth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_alexa_entities_user_exposed ON alexa_entities(user_id, exposed);
CREATE INDEX IF NOT EXISTS idx_alexa_entities_user_reported_hash ON alexa_entities(user_id, last_reported_state_hash);
CREATE INDEX IF NOT EXISTS idx_alexa_entities_user_last_seen ON alexa_entities(user_id, entity_last_seen_at);
CREATE INDEX IF NOT EXISTS idx_alexa_command_queue_device_status_expiry ON alexa_command_queue(device_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_alexa_command_queue_user_status ON alexa_command_queue(user_id, status);
CREATE INDEX IF NOT EXISTS idx_alexa_command_queue_dedup ON alexa_command_queue(device_id, entity_id, action, status);
CREATE INDEX IF NOT EXISTS idx_alexa_sync_snapshots_user_device ON alexa_sync_snapshots(user_id, device_id);
