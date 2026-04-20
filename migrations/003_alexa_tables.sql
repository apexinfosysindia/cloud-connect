-- 003_alexa_tables.sql
--
-- Adds Amazon Alexa Smart Home skill integration schema, mirroring the
-- google_home_* tables. Reuses the existing google_home_entities and
-- google_home_command_queue tables (they are already voice-assistant-neutral
-- in their semantics: entity registry + internal action queue).
--
-- Every DDL is IF NOT EXISTS so this migration is idempotent.

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
    access_token_hash TEXT NOT NULL UNIQUE,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    -- Amazon-issued LWA refresh token (from Alexa.Authorization.AcceptGrant)
    -- used to push proactive ChangeReport / AddOrUpdateReport events to
    -- https://api.amazonalexa.com/v3/events
    amazon_refresh_token TEXT,
    amazon_access_token TEXT,
    amazon_access_token_expires_at DATETIME,
    event_endpoint TEXT,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alexa_entity_state_hashes (
    user_id INTEGER NOT NULL,
    entity_id TEXT NOT NULL,
    last_reported_state_hash TEXT,
    last_reported_at DATETIME,
    PRIMARY KEY (user_id, entity_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alexa_auth_codes_expiry ON alexa_auth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_alexa_tokens_user ON alexa_tokens(user_id);
