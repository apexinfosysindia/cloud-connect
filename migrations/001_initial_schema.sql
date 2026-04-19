-- 001_initial_schema.sql
--
-- Baseline schema migration. Captures everything that previously lived in
-- db.js as CREATE TABLE / ALTER TABLE / CREATE INDEX statements, plus the
-- trial_consumed_at backfill.
--
-- Uses IF NOT EXISTS on every DDL so this file is a no-op against a legacy
-- database that already has the tables. The migration runner detects legacy
-- databases (users table present, schema_migrations absent) and stamps this
-- migration as applied without re-running it, but even if it were run it
-- would not error.
--
-- Every subsequent schema change goes in a new 00N_*.sql file.

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    subdomain TEXT UNIQUE,
    access_token TEXT UNIQUE,
    status TEXT NOT NULL CHECK(status IN ('payment_pending', 'active', 'trial', 'expired', 'suspended')),
    email_verified INTEGER NOT NULL DEFAULT 0,
    google_home_enabled INTEGER NOT NULL DEFAULT 0,
    google_home_linked INTEGER NOT NULL DEFAULT 0,
    google_home_security_pin TEXT,
    razorpay_customer_id TEXT,
    razorpay_subscription_id TEXT,
    razorpay_payment_id TEXT,
    razorpay_subscription_status TEXT,
    trial_ends_at DATETIME,
    trial_approved_at DATETIME,
    trial_consumed_at DATETIME,
    payment_fingerprint TEXT,
    activated_at DATETIME,
    session_epoch INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_uid TEXT NOT NULL,
    device_name TEXT,
    admin_name_override INTEGER NOT NULL DEFAULT 0,
    hostname TEXT,
    local_ips TEXT,
    ssh_port INTEGER DEFAULT 22,
    remote_user TEXT DEFAULT 'root',
    tunnel_host TEXT,
    tunnel_port INTEGER,
    addon_version TEXT,
    agent_state TEXT,
    device_token_hash TEXT NOT NULL UNIQUE,
    last_seen_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, device_uid),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS device_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    payload TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS admin_access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    admin_email TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS google_home_auth_codes (
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

CREATE TABLE IF NOT EXISTS google_home_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    access_token_hash TEXT NOT NULL UNIQUE,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS google_home_entities (
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

CREATE TABLE IF NOT EXISTS google_home_command_queue (
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

CREATE TABLE IF NOT EXISTS google_home_sync_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    snapshot_entity_ids_json TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, device_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    used_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    used_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Persistent record of trial consumption keyed on normalized email.
-- Survives account deletion so the same email (or gmail dot/+tag variant)
-- cannot claim another free trial after delete-and-resignup.
CREATE TABLE IF NOT EXISTS trial_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_normalized TEXT NOT NULL,
    email_original TEXT NOT NULL,
    source TEXT NOT NULL,
    user_id_at_time INTEGER,
    payment_fingerprint TEXT,
    consumed_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_device_logs_device_created ON device_logs(device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_device_created ON admin_access_logs(device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_google_home_auth_codes_expiry ON google_home_auth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_google_home_entities_user_exposed ON google_home_entities(user_id, exposed);
CREATE INDEX IF NOT EXISTS idx_google_home_entities_user_reported_hash ON google_home_entities(user_id, last_reported_state_hash);
CREATE INDEX IF NOT EXISTS idx_google_home_entities_user_last_seen ON google_home_entities(user_id, entity_last_seen_at);
CREATE INDEX IF NOT EXISTS idx_google_home_command_queue_device_status_expiry ON google_home_command_queue(device_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_google_home_command_queue_user_status ON google_home_command_queue(user_id, status);
CREATE INDEX IF NOT EXISTS idx_google_home_command_queue_dedup ON google_home_command_queue(device_id, entity_id, action, status);
CREATE INDEX IF NOT EXISTS idx_google_home_sync_snapshots_user_device ON google_home_sync_snapshots(user_id, device_id);
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user ON email_verification_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_expiry ON email_verification_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expiry ON password_reset_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_trial_history_email_normalized ON trial_history(email_normalized);
CREATE INDEX IF NOT EXISTS idx_trial_history_payment_fingerprint ON trial_history(payment_fingerprint);
CREATE INDEX IF NOT EXISTS idx_users_payment_fingerprint ON users(payment_fingerprint);

-- One-time backfill for trial_consumed_at on rows that predate the column.
-- Idempotent: only fills rows where trial_consumed_at IS NULL.
UPDATE users
SET trial_consumed_at = COALESCE(trial_approved_at, activated_at, created_at, CURRENT_TIMESTAMP)
WHERE trial_consumed_at IS NULL
  AND (
      trial_approved_at IS NOT NULL
      OR trial_ends_at IS NOT NULL
      OR razorpay_subscription_id IS NOT NULL
  );
