-- 005_login_otp.sql
--
-- Email one-time-code (OTP) for the passwordless-login emergency fallback.
--
-- Oasis login is identifier-first + passkey-primary. When a customer who HAS a
-- passkey deliberately falls back to "use your password" (lost/forgotten the
-- passkey device), a correct password is necessary but not sufficient: the
-- server emails a 6-digit code that must also be entered. This table holds the
-- in-flight codes, mirroring the email_verification_tokens / password_reset_tokens
-- precedent: the raw 6-digit code is shown to the user only, and we persist only
-- its sha256 (utils.hashSecret), single-use, TTL-pruned.
--
-- `attempts` hard-locks a single code after 5 wrong guesses. A 6-digit code is a
-- 1,000,000-value space, so this per-code lock backs up the per-IP rate limiter:
-- even an attacker who is under the IP cap cannot grind a single issued code.
--
-- Every DDL is IF NOT EXISTS so this file is idempotent. The migration runner
-- (lib/migrator.js) owns the BEGIN/COMMIT transaction boundary, so this file
-- contains pure DDL only — no inline BEGIN/COMMIT.

-- @UP

CREATE TABLE IF NOT EXISTS login_otp_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    used_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_login_otp_tokens_user ON login_otp_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_login_otp_tokens_expiry ON login_otp_tokens(expires_at);

-- @DOWN
--
-- Reverses EXACTLY what @UP added: drops the login_otp_tokens table (its indexes
-- go with it). Everything that existed before is left untouched. Dropping this
-- destroys any in-flight sign-in codes, which are short-lived (10-minute TTL)
-- and re-issued on demand, so there is no durable data loss.

DROP TABLE IF EXISTS login_otp_tokens;
