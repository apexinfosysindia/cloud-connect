const crypto = require('crypto');
const config = require('../config');
const utils = require('../utils');
const state = require('./state');

// Alexa auth-code / access-token lifecycle. Mirrors lib/google-home/core.js.
// Uses prefix aac_/aat_/art_ so stored tokens are distinguishable from the
// Google flavour (gac_/gat_/grt_).

module.exports = function ({ dbGet, dbRun }) {
    // ── TTL helpers ─────────────────────────────────────────────────────
    function getAlexaAuthCodeTtlSeconds() {
        if (!Number.isFinite(config.ALEXA_AUTH_CODE_TTL_SECONDS)) return 600;
        return Math.max(120, Math.min(1800, Math.round(config.ALEXA_AUTH_CODE_TTL_SECONDS)));
    }

    function getAlexaAccessTokenTtlSeconds() {
        if (!Number.isFinite(config.ALEXA_ACCESS_TOKEN_TTL_SECONDS)) return 3600;
        return Math.max(300, Math.min(7200, Math.round(config.ALEXA_ACCESS_TOKEN_TTL_SECONDS)));
    }

    // ── Token generation ────────────────────────────────────────────────
    function generateAlexaOAuthCode() {
        return 'aac_' + crypto.randomBytes(24).toString('hex');
    }

    function generateAlexaAccessToken() {
        return 'aat_' + crypto.randomBytes(24).toString('hex');
    }

    function generateAlexaRefreshToken() {
        return 'art_' + crypto.randomBytes(24).toString('hex');
    }

    // ── Token lookup / auth ─────────────────────────────────────────────
    async function findUserByAlexaAccessToken(accessToken) {
        if (!accessToken) return null;
        const tokenHash = utils.hashSecret(accessToken);
        return await dbGet(
            `
                SELECT u.*
                FROM users u
                INNER JOIN alexa_tokens at ON at.user_id = u.id
                WHERE at.access_token_hash = ?
                  AND at.expires_at > ?
            `,
            [tokenHash, new Date().toISOString()]
        );
    }

    async function findAlexaRefreshTokenRow(refreshToken) {
        if (!refreshToken) return null;
        const tokenHash = utils.hashSecret(refreshToken);
        return await dbGet(
            `SELECT * FROM alexa_tokens WHERE refresh_token_hash = ? LIMIT 1`,
            [tokenHash]
        );
    }

    async function findUserByAlexaAuthCode(authCode, redirectUri) {
        if (!authCode) return null;
        const codeHash = utils.hashSecret(authCode);
        return await dbGet(
            `
                SELECT
                    u.*,
                    ac.id AS oauth_code_id,
                    ac.redirect_uri AS oauth_redirect_uri
                FROM alexa_auth_codes ac
                INNER JOIN users u ON u.id = ac.user_id
                WHERE ac.code_hash = ?
                  AND ac.expires_at > ?
                  AND ac.consumed_at IS NULL
                  AND ac.redirect_uri = ?
                LIMIT 1
            `,
            [codeHash, new Date().toISOString(), redirectUri]
        );
    }

    // Issues a fresh access+refresh token pair for the user. Preserves
    // the Amazon LWA refresh token (used to push events) on UPSERT.
    async function issueAlexaTokensForUser(userId, existingRefreshToken = null) {
        const accessToken = generateAlexaAccessToken();
        const refreshToken = existingRefreshToken || generateAlexaRefreshToken();
        const accessTokenHash = utils.hashSecret(accessToken);
        const refreshTokenHash = utils.hashSecret(refreshToken);
        const expiresAt = new Date(Date.now() + getAlexaAccessTokenTtlSeconds() * 1000).toISOString();
        const nowIso = new Date().toISOString();

        await dbRun(
            `
                INSERT INTO alexa_tokens (
                    user_id,
                    access_token_hash,
                    refresh_token_hash,
                    expires_at,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    access_token_hash = excluded.access_token_hash,
                    refresh_token_hash = excluded.refresh_token_hash,
                    expires_at = excluded.expires_at,
                    updated_at = excluded.updated_at
            `,
            [userId, accessTokenHash, refreshTokenHash, expiresAt, nowIso, nowIso]
        );

        return {
            access_token: accessToken,
            refresh_token: refreshToken,
            expires_in: getAlexaAccessTokenTtlSeconds(),
            token_type: 'Bearer'
        };
    }

    // ── Auth data cleanup (called on unlink / DISCONNECT) ───────────────
    async function cleanupAlexaAuthDataForUser(userId) {
        await dbRun(`DELETE FROM alexa_auth_codes WHERE user_id = ?`, [userId]);
        await dbRun(`DELETE FROM alexa_tokens WHERE user_id = ?`, [userId]);
        await dbRun(
            `UPDATE users SET alexa_linked = 0, alexa_enabled = 0 WHERE id = ?`,
            [userId]
        );

        const normalizedUserId = Number(userId);
        const crEntry = state.alexaChangeReportQueue.get(normalizedUserId);
        if (crEntry?.timer) clearTimeout(crEntry.timer);
        state.alexaChangeReportQueue.delete(normalizedUserId);

        const discEntry = state.alexaDiscoveryQueue.get(normalizedUserId);
        if (discEntry?.timer) clearTimeout(discEntry.timer);
        state.alexaDiscoveryQueue.delete(normalizedUserId);

        state.alexaLwaTokenCache.delete(normalizedUserId);
    }

    // ── Runtime schema migration ────────────────────────────────────────
    //
    // Applied on boot alongside ensureGoogleRuntimeSchemaReady. All
    // statements are idempotent and tolerate "duplicate column" errors
    // (SQLite raises those when a column already exists).
    async function ensureAlexaRuntimeSchemaReady() {
        if (state.alexaRuntimeSchemaReadyPromise) {
            return await state.alexaRuntimeSchemaReadyPromise;
        }

        state.alexaRuntimeSchemaReadyPromise = (async () => {
            const statements = [
                'ALTER TABLE users ADD COLUMN alexa_enabled INTEGER NOT NULL DEFAULT 0',
                'ALTER TABLE users ADD COLUMN alexa_linked INTEGER NOT NULL DEFAULT 0',
                'ALTER TABLE users ADD COLUMN alexa_security_pin TEXT',
                `CREATE TABLE IF NOT EXISTS alexa_auth_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    code_hash TEXT NOT NULL UNIQUE,
                    redirect_uri TEXT NOT NULL,
                    scopes TEXT,
                    expires_at DATETIME NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    consumed_at DATETIME,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )`,
                `CREATE TABLE IF NOT EXISTS alexa_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    access_token_hash TEXT NOT NULL UNIQUE,
                    refresh_token_hash TEXT NOT NULL UNIQUE,
                    amazon_refresh_token TEXT,
                    amazon_access_token TEXT,
                    amazon_access_token_expires_at DATETIME,
                    event_endpoint TEXT,
                    expires_at DATETIME NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )`,
                `CREATE TABLE IF NOT EXISTS alexa_entity_state_hashes (
                    user_id INTEGER NOT NULL,
                    entity_id TEXT NOT NULL,
                    last_reported_state_hash TEXT,
                    last_reported_at DATETIME,
                    PRIMARY KEY (user_id, entity_id),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )`,
                'CREATE INDEX IF NOT EXISTS idx_alexa_auth_codes_expiry ON alexa_auth_codes(expires_at)',
                'CREATE INDEX IF NOT EXISTS idx_alexa_tokens_user ON alexa_tokens(user_id)'
            ];

            for (const statement of statements) {
                try {
                    await dbRun(statement);
                } catch (error) {
                    if (utils.isIgnorableSqliteMigrationError(error)) continue;
                    // "duplicate column" for the ALTER TABLE statements
                    if (/duplicate column/i.test(error?.message || '')) continue;
                    throw error;
                }
            }
        })().catch((error) => {
            state.alexaRuntimeSchemaReadyPromise = null;
            throw error;
        });

        return await state.alexaRuntimeSchemaReadyPromise;
    }

    // ── redirect-uri trust ──────────────────────────────────────────────
    function isTrustedAlexaRedirectUri(redirectUri) {
        const normalized = utils.sanitizeString(redirectUri, 1000);
        if (!normalized) return false;
        let parsed;
        try {
            parsed = new URL(normalized);
        } catch (_error) {
            return false;
        }
        if (parsed.protocol !== 'https:') return false;
        const host = (parsed.hostname || '').toLowerCase();
        return config.ALEXA_REDIRECT_URI_HOSTS.includes(host);
    }

    return {
        getAlexaAuthCodeTtlSeconds,
        getAlexaAccessTokenTtlSeconds,
        generateAlexaOAuthCode,
        generateAlexaAccessToken,
        generateAlexaRefreshToken,
        findUserByAlexaAccessToken,
        findAlexaRefreshTokenRow,
        findUserByAlexaAuthCode,
        issueAlexaTokensForUser,
        cleanupAlexaAuthDataForUser,
        ensureAlexaRuntimeSchemaReady,
        isTrustedAlexaRedirectUri
    };
};
