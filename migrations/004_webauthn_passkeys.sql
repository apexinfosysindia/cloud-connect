-- 004_webauthn_passkeys.sql
--
-- WebAuthn / FIDO2 passkey two-factor authentication for both portals
-- (Oasis customer + Vista admin). A passkey is a REQUIRED second factor after
-- the password once an account enrolls at least one — opt-in per account.
--
-- Two isolated credential namespaces share these tables, distinguished by
-- account_kind:
--   'customer' -> keyed by users.id (FK, ON DELETE CASCADE)
--   'admin'    -> keyed by admin_email (the env ADMIN_EMAIL; there is no admin
--                 users row, mirroring how lib/auth.js treats admin identity)
--
-- Every DDL is IF NOT EXISTS so this file is idempotent. The migration runner
-- (lib/migrator.js) owns the BEGIN/COMMIT transaction boundary, so this file
-- contains pure DDL only — no inline BEGIN/COMMIT.

-- @UP

-- ── users: passkey 2FA enforcement flag ───────────────────────────────────
-- Flipped to 1 when the user enrolls their first passkey, back to 0 when they
-- remove their last one OR complete an email password reset (the lockout
-- escape hatch — see routes/auth.js reset-password handler).
ALTER TABLE users ADD COLUMN passkey_2fa_enabled INTEGER NOT NULL DEFAULT 0;

-- ── webauthn_credentials ──────────────────────────────────────────────────
-- One row per enrolled authenticator. credential_id + public_key are stored
-- base64url-encoded (the format @simplewebauthn/server's isoBase64URL helper
-- produces/consumes). sign_count is the FIDO signature counter used for cloned-
-- authenticator detection; bumped on every successful assertion.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    account_kind TEXT NOT NULL CHECK(account_kind IN ('customer', 'admin')),
    admin_email TEXT,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports TEXT,
    aaguid TEXT,
    nickname TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ── webauthn_challenges ───────────────────────────────────────────────────
-- A WebAuthn ceremony is two round-trips: the server issues options containing
-- a random challenge, the authenticator signs it, and the server verifies the
-- signed challenge matches. We persist the in-flight challenge here (rather
-- than an in-memory Map) so it survives restarts and works across workers,
-- mirroring the email_verification_tokens precedent. Single-use: consumed on
-- verify, pruned by TTL (expires_at).
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject TEXT NOT NULL,
    account_kind TEXT NOT NULL CHECK(account_kind IN ('customer', 'admin')),
    ceremony TEXT NOT NULL CHECK(ceremony IN ('registration', 'authentication')),
    challenge TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_admin_email ON webauthn_credentials(admin_email);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_lookup ON webauthn_credentials(account_kind, user_id, admin_email);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_subject ON webauthn_challenges(subject, account_kind, ceremony);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expiry ON webauthn_challenges(expires_at);

-- @DOWN
--
-- Reverses EXACTLY what @UP added: drops the two passkey tables (their indexes
-- go with them) and the users.passkey_2fa_enabled column. Everything that
-- existed before — users' other columns and rows, the integration tables,
-- billing, devices — is left completely untouched.
--
-- DATA NOTE: dropping these destroys any enrolled passkeys and resets 2FA
-- enforcement. That is the correct meaning of "return to the state before this
-- commit". The migrate-down command backs up the DB and shows row counts first.
--
-- DROP COLUMN requires SQLite 3.35.0+ (2021); both prod and dev exceed this.

DROP TABLE IF EXISTS webauthn_challenges;
DROP TABLE IF EXISTS webauthn_credentials;

ALTER TABLE users DROP COLUMN passkey_2fa_enabled;
