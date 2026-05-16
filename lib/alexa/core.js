/**
 * Alexa core: token issuance / lookup / refresh + AcceptGrant handling.
 *
 * Mirrors lib/google-home/core.js shape so the OAuth and SmartHome routes
 * can use the same query patterns. Differences from the Google twin are
 * concentrated here, NOT scattered across routes:
 *
 *   - Token prefixes: aac_ (auth code), aat_ (access), art_ (refresh)
 *   - LWA bearer pair stored alongside the portal-issued tokens, encrypted
 *     via lib/alexa/crypto.js (see that file for why encrypted not hashed)
 *   - storeAcceptGrantTokens(userId, lwa) is the AcceptGrant landing strip:
 *     this is the call that v1 mishandled and ultimately caused "linking
 *     broken in prod". Treat its tests as the most important in this module.
 *
 * Factory inputs:
 *   { dbGet, dbRun, dbAll, lwaCrypto }
 *
 * lwaCrypto is injected (rather than required at module top) so unit tests
 * can swap in a fake without env-var gymnastics.
 */

const crypto = require('node:crypto');
const config = require('../config');
const utils = require('../utils');

module.exports = function createAlexaCore({ dbGet, dbRun, dbAll, lwaCrypto }) {
    if (!lwaCrypto) {
        // Soft default — production wiring in server.js will pass the real
        // module; tests that don't exercise LWA paths can omit it.
        lwaCrypto = require('./crypto');
    }

    // ── TTL helpers (clamped) ───────────────────────────────────────────────

    function getAlexaAuthCodeTtlSeconds() {
        if (!Number.isFinite(config.ALEXA_AUTH_CODE_TTL_SECONDS)) return 600;
        return Math.max(120, Math.min(1800, Math.round(config.ALEXA_AUTH_CODE_TTL_SECONDS)));
    }

    function getAlexaAccessTokenTtlSeconds() {
        if (!Number.isFinite(config.ALEXA_ACCESS_TOKEN_TTL_SECONDS)) return 3600;
        return Math.max(300, Math.min(7200, Math.round(config.ALEXA_ACCESS_TOKEN_TTL_SECONDS)));
    }

    function getAlexaCommandTtlSeconds() {
        if (!Number.isFinite(config.ALEXA_COMMAND_TTL_SECONDS)) return 45;
        return Math.max(10, Math.min(180, Math.round(config.ALEXA_COMMAND_TTL_SECONDS)));
    }

    // ── Token generation ────────────────────────────────────────────────────

    function generateAlexaOAuthCode() {
        return 'aac_' + crypto.randomBytes(24).toString('hex');
    }
    function generateAlexaAccessToken() {
        return 'aat_' + crypto.randomBytes(24).toString('hex');
    }
    function generateAlexaRefreshToken() {
        return 'art_' + crypto.randomBytes(24).toString('hex');
    }

    // ── Lookup helpers ──────────────────────────────────────────────────────

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
                    aac.id AS oauth_code_id,
                    aac.redirect_uri AS oauth_redirect_uri
                FROM alexa_auth_codes aac
                INNER JOIN users u ON u.id = aac.user_id
                WHERE aac.code_hash = ?
                  AND aac.expires_at > ?
                  AND aac.consumed_at IS NULL
                  AND aac.redirect_uri = ?
                LIMIT 1
            `,
            [codeHash, new Date().toISOString(), redirectUri]
        );
    }

    // ── Issuance ────────────────────────────────────────────────────────────

    async function issueAlexaAuthCode({ userId, redirectUri, scopes = null }) {
        const code = generateAlexaOAuthCode();
        const codeHash = utils.hashSecret(code);
        const expiresAt = new Date(
            Date.now() + getAlexaAuthCodeTtlSeconds() * 1000
        ).toISOString();
        await dbRun(
            `
                INSERT INTO alexa_auth_codes
                    (user_id, code_hash, redirect_uri, scopes, expires_at)
                VALUES (?, ?, ?, ?, ?)
            `,
            [userId, codeHash, redirectUri, scopes, expiresAt]
        );
        return { code, expiresAt };
    }

    async function consumeAlexaAuthCode(oauthCodeId) {
        await dbRun(
            `UPDATE alexa_auth_codes SET consumed_at = ? WHERE id = ?`,
            [new Date().toISOString(), oauthCodeId]
        );
    }

    /**
     * Issue or rotate the portal-side bearer pair for a user. If
     * `existingRefreshToken` is supplied (refresh-token grant), reuse it —
     * Alexa keeps the original refresh token across access-token rotations.
     * If omitted (authorization_code grant), a fresh refresh token is minted.
     *
     * The LWA columns are NOT touched here; storeAcceptGrantTokens owns those.
     * That separation matters: AcceptGrant happens on a different request
     * lifecycle (a Smart Home directive) than `/api/alexa/token`, so smashing
     * them together is what got the v1 ordering wrong.
     */
    async function issueAlexaTokensForUser(userId, existingRefreshToken = null) {
        const accessToken = generateAlexaAccessToken();
        const refreshToken = existingRefreshToken || generateAlexaRefreshToken();
        const accessTokenHash = utils.hashSecret(accessToken);
        const refreshTokenHash = utils.hashSecret(refreshToken);
        const ttlSeconds = getAlexaAccessTokenTtlSeconds();
        const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
        const nowIso = new Date().toISOString();

        // UPSERT keyed on user_id (UNIQUE in the schema). Re-link by the same
        // user replaces the row rather than failing on the unique constraint.
        await dbRun(
            `
                INSERT INTO alexa_tokens
                    (user_id, access_token_hash, refresh_token_hash, expires_at,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    access_token_hash  = excluded.access_token_hash,
                    refresh_token_hash = excluded.refresh_token_hash,
                    expires_at         = excluded.expires_at,
                    updated_at         = excluded.updated_at
            `,
            [userId, accessTokenHash, refreshTokenHash, expiresAt, nowIso, nowIso]
        );

        return { accessToken, refreshToken, expiresIn: ttlSeconds, expiresAt };
    }

    // ── AcceptGrant — the v1 weak point ─────────────────────────────────────

    /**
     * Persist the LWA bearer pair Alexa hands us in an AcceptGrant directive.
     *
     * Flow (per the Alexa Smart Home docs):
     *   1. User links the skill in the Alexa app.
     *   2. Alexa generates an LWA AUTH CODE for our skill.
     *   3. Alexa POSTs an Alexa.Authorization / AcceptGrant directive to us
     *      containing { code, redirectUri }.
     *   4. We POST that code to api.amazon.com/auth/o2/token (LWA endpoint)
     *      using our skill's LWA client_id / client_secret to exchange it
     *      for { access_token, refresh_token, expires_in }.
     *   5. We store the result here, encrypted, against the user we
     *      identified from the directive's bearer (handled by route layer).
     *
     * What v1 got wrong (from the deleted-history audit): step 4 was attempted
     * synchronously inside step 3 on the same request, with all error paths
     * silently returning AcceptGrant.Response so Alexa thought linking
     * succeeded — even when LWA exchange failed and we never actually stored
     * a refresh token. Subsequent ChangeReports then 401'd against the Event
     * Gateway, with no diagnostic anywhere. Lesson:
     *
     *   - This function MUST throw if it can't persist. The route's job is
     *     to surface the failure as Alexa.ErrorResponse(INTERNAL_ERROR), not
     *     paper over it as AcceptGrant.Response.
     *   - It MUST be transactional with the LWA exchange — never mark the
     *     user "linked" without a stored refresh token.
     *
     * Inputs:
     *   userId            - resolved from the bearer on the directive
     *   lwa.accessToken   - plaintext from LWA (will be encrypted at rest)
     *   lwa.refreshToken  - plaintext from LWA (will be encrypted at rest)
     *   lwa.expiresIn     - seconds, from LWA response (used to compute expiry)
     *   lwa.scopes        - space-delimited string from LWA, optional
     */
    async function storeAcceptGrantTokens(userId, lwa) {
        if (!Number.isInteger(userId) || userId <= 0) {
            throw new Error('storeAcceptGrantTokens: invalid userId');
        }
        if (!lwa || typeof lwa !== 'object') {
            throw new Error('storeAcceptGrantTokens: lwa payload required');
        }
        if (typeof lwa.refreshToken !== 'string' || lwa.refreshToken.length === 0) {
            // The refresh token is the only thing we MUST have. Without it
            // we cannot mint future access tokens, which means proactive
            // ChangeReport will silently 401 forever. Refuse to persist a
            // half-linked state.
            throw new Error(
                'storeAcceptGrantTokens: lwa.refreshToken missing — refusing ' +
                    'to persist a half-linked Alexa account (this was the v1 failure mode)'
            );
        }

        const expiresInSeconds = Number.isFinite(lwa.expiresIn) ? Math.max(60, Math.round(lwa.expiresIn)) : 3600;
        const expiresAtIso = new Date(Date.now() + expiresInSeconds * 1000).toISOString();
        const nowIso = new Date().toISOString();

        // encryptLwaToken throws if ALEXA_LWA_TOKEN_ENC_KEY is missing/invalid.
        // Let it propagate — that's a deployment bug we want the operator to
        // see immediately, not a runtime warning the user-flow can swallow.
        const encryptedAccess = lwaCrypto.encryptLwaToken(lwa.accessToken || null);
        const encryptedRefresh = lwaCrypto.encryptLwaToken(lwa.refreshToken);

        // Update the existing alexa_tokens row (created during /api/alexa/token
        // exchange) with the LWA half. We do NOT INSERT here: if there is no
        // matching row, the user-resolution step in the route layer is broken
        // and we would rather fail than create an orphaned token row.
        const result = await dbRun(
            `
                UPDATE alexa_tokens SET
                    lwa_access_token_encrypted  = ?,
                    lwa_refresh_token_encrypted = ?,
                    lwa_expires_at              = ?,
                    lwa_scopes                  = ?,
                    updated_at                  = ?
                WHERE user_id = ?
            `,
            [encryptedAccess, encryptedRefresh, expiresAtIso, lwa.scopes || null, nowIso, userId]
        );

        // sqlite3's `this.changes` surfaces via the dbRun helper — the rest
        // of the codebase reads it via the same pattern.
        if (!result || result.changes === 0) {
            throw new Error(
                `storeAcceptGrantTokens: no alexa_tokens row exists for user ${userId}; ` +
                    `AcceptGrant arrived before /api/alexa/token completed (route ordering bug)`
            );
        }

        // Mark the user as linked only AFTER we've successfully stored the
        // LWA pair. Same fail-loud-rather-than-silent reasoning as above.
        await dbRun(
            `UPDATE users SET alexa_linked = 1 WHERE id = ?`,
            [userId]
        );

        return { storedAt: nowIso, expiresAt: expiresAtIso };
    }

    /**
     * Decrypt and return a user's stored LWA tokens, or null if the user has
     * never completed AcceptGrant. Used by the (Phase 11) event gateway.
     */
    async function getDecryptedLwaTokensForUser(userId) {
        const row = await dbGet(
            `
                SELECT lwa_access_token_encrypted, lwa_refresh_token_encrypted,
                       lwa_expires_at, lwa_scopes
                FROM alexa_tokens
                WHERE user_id = ?
            `,
            [userId]
        );
        if (!row || !row.lwa_refresh_token_encrypted) {
            return null;
        }
        return {
            accessToken: lwaCrypto.decryptLwaToken(row.lwa_access_token_encrypted),
            refreshToken: lwaCrypto.decryptLwaToken(row.lwa_refresh_token_encrypted),
            expiresAt: row.lwa_expires_at,
            scopes: row.lwa_scopes
        };
    }

    /**
     * Unlink: blow away the entire alexa_tokens row + reset the user flag.
     * Called when a user clicks "disconnect" in the portal or when Amazon
     * sends a Revoke directive. Pending entities/queued commands are left
     * intact — the cascade from users.id is the safety net, not this call.
     */
    async function unlinkAlexaForUser(userId) {
        await dbRun(`DELETE FROM alexa_tokens WHERE user_id = ?`, [userId]);
        await dbRun(`UPDATE users SET alexa_linked = 0 WHERE id = ?`, [userId]);
    }

    return {
        // TTL helpers (also exported so the route layer can echo expires_in)
        getAlexaAuthCodeTtlSeconds,
        getAlexaAccessTokenTtlSeconds,
        getAlexaCommandTtlSeconds,
        // Token generators (rarely used directly outside core)
        generateAlexaOAuthCode,
        generateAlexaAccessToken,
        generateAlexaRefreshToken,
        // Lookups
        findUserByAlexaAccessToken,
        findAlexaRefreshTokenRow,
        findUserByAlexaAuthCode,
        // Issuance + lifecycle
        issueAlexaAuthCode,
        consumeAlexaAuthCode,
        issueAlexaTokensForUser,
        storeAcceptGrantTokens,
        getDecryptedLwaTokensForUser,
        unlinkAlexaForUser,
        // For tests + audit
        _internal: { dbAll }
    };
};
