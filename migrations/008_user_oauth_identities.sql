-- 008_user_oauth_identities.sql
--
-- SSO / social sign-in (Google, Microsoft, Apple) for the Oasis customer portal.
--
-- An OAuth/OIDC identity is stored in its OWN table rather than as columns on
-- `users`, for two reasons: (1) one account can link several providers (Google
-- AND Microsoft AND Apple) without widening `users`; (2) it keeps the SSO
-- feature fully additive — no risky SQLite rebuild of `users` just to relax the
-- `password NOT NULL` constraint (pure-SSO users get an unusable sentinel hash
-- instead, see lib/sso.js resolveOrCreateUser).
--
-- `subject` is the IdP's stable, opaque per-user id (the OIDC `sub` claim) — the
-- canonical key we re-resolve a returning user by, since it never changes even
-- if the user later changes their email at the provider. `email` is captured at
-- link time for audit/debugging only (Apple in particular only returns the email
-- on the FIRST consent, so later logins must resolve by subject, never email).
--
-- UNIQUE(provider, subject) is the anti-collision guard: a given provider
-- identity can map to exactly one local account, so concurrent first-logins race
-- safely (the loser hits the constraint and re-selects the winner).
--
-- Every DDL is IF NOT EXISTS so this file is idempotent. The migration runner
-- (lib/migrator.js) owns the BEGIN/COMMIT transaction boundary, so this file
-- contains pure DDL only — no inline BEGIN/COMMIT.

-- @UP

CREATE TABLE IF NOT EXISTS user_oauth_identities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    email TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (provider, subject),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_oauth_identities_user ON user_oauth_identities(user_id);

-- @DOWN
--
-- Reverses EXACTLY what @UP added: drops user_oauth_identities (its index goes
-- with it). `users` is left untouched. Dropping this unlinks every SSO identity;
-- the underlying user rows survive and can still sign in by password (if set) or
-- re-link via SSO, so there is no durable account loss.

DROP INDEX IF EXISTS idx_oauth_identities_user;
DROP TABLE IF EXISTS user_oauth_identities;
