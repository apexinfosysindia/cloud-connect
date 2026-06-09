const crypto = require('crypto');
const config = require('../config');
const utils = require('../utils');
const state = require('./state');
const entityMapping = require('./entity-mapping');

/**
 * Alexa core: OAuth codes, portal-issued tokens (hashed), LWA tokens
 * (encrypted), endpoint registry, command queue, sync snapshots.
 *
 * Mirrors lib/google-home/core.js, but the schema is guaranteed present by
 * migration 003 so the legacy column-fallback branches are dropped.
 */
module.exports = function ({ dbGet, dbRun, dbAll, eventGateway, alexaCrypto }) {
    // ── TTL helpers ─────────────────────────────────────────────────────

    function getAlexaAuthCodeTtlSeconds() {
        if (!Number.isFinite(config.ALEXA_AUTH_CODE_TTL_SECONDS)) {
            return 600;
        }
        return Math.max(120, Math.min(1800, Math.round(config.ALEXA_AUTH_CODE_TTL_SECONDS)));
    }

    function getAlexaAccessTokenTtlSeconds() {
        if (!Number.isFinite(config.ALEXA_ACCESS_TOKEN_TTL_SECONDS)) {
            return 3600;
        }
        return Math.max(300, Math.min(7200, Math.round(config.ALEXA_ACCESS_TOKEN_TTL_SECONDS)));
    }

    function getAlexaCommandTtlSeconds() {
        if (!Number.isFinite(config.ALEXA_COMMAND_TTL_SECONDS)) {
            return 45;
        }
        return Math.max(10, Math.min(180, Math.round(config.ALEXA_COMMAND_TTL_SECONDS)));
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

    // ── State hashing (canonical, order-independent) ─────────────────────

    function computeAlexaStateHash(stateObject) {
        const canonical = JSON.stringify(stateObject, Object.keys(stateObject || {}).sort());
        return crypto.createHash('sha1').update(canonical || '').digest('hex');
    }

    // ── Token lookup / auth ─────────────────────────────────────────────

    async function findUserByAlexaAccessToken(accessToken) {
        if (!accessToken) {
            return null;
        }
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
        if (!refreshToken) {
            return null;
        }
        const tokenHash = utils.hashSecret(refreshToken);
        return await dbGet(`SELECT * FROM alexa_tokens WHERE refresh_token_hash = ? LIMIT 1`, [tokenHash]);
    }

    async function findUserByAlexaAuthCode(authCode, redirectUri) {
        if (!authCode) {
            return null;
        }
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
                    user_id, access_token_hash, refresh_token_hash, expires_at, created_at, updated_at
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

    // ── LWA tokens (encrypted at rest) ──────────────────────────────────

    async function storeAlexaLwaTokens(userId, { accessToken, refreshToken, region, expiresInSeconds }) {
        const accessEnc = alexaCrypto.encryptToken(accessToken);
        const refreshEnc = alexaCrypto.encryptToken(refreshToken);
        const expiresAt = Number.isFinite(expiresInSeconds)
            ? new Date(Date.now() + expiresInSeconds * 1000).toISOString()
            : null;
        const nowIso = new Date().toISOString();
        const normalizedRegion = utils.sanitizeString(region, 40);

        await dbRun(
            `
                INSERT INTO alexa_lwa_tokens (
                    user_id, access_token_encrypted, refresh_token_encrypted, region, expires_at, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    access_token_encrypted = excluded.access_token_encrypted,
                    refresh_token_encrypted = excluded.refresh_token_encrypted,
                    region = excluded.region,
                    expires_at = excluded.expires_at,
                    updated_at = excluded.updated_at
            `,
            [userId, accessEnc, refreshEnc, normalizedRegion, expiresAt, nowIso, nowIso]
        );

        // Invalidate cache so the next outbound call re-reads.
        state.alexaLwaAccessTokenCache.delete(Number(userId));
    }

    async function getAlexaLwaTokenRow(userId) {
        const row = await dbGet(`SELECT * FROM alexa_lwa_tokens WHERE user_id = ? LIMIT 1`, [userId]);
        if (!row) {
            return null;
        }
        return {
            ...row,
            access_token: row.access_token_encrypted ? alexaCrypto.decryptToken(row.access_token_encrypted) : null,
            refresh_token: row.refresh_token_encrypted ? alexaCrypto.decryptToken(row.refresh_token_encrypted) : null
        };
    }

    // ── Endpoints ───────────────────────────────────────────────────────

    async function getAlexaEndpointsForUser(userId, options = {}) {
        const includeDisabled = Boolean(options.includeDisabled);
        const sql = includeDisabled
            ? `
                SELECT ae.*, d.addon_version, d.last_seen_at
                FROM alexa_endpoints ae
                INNER JOIN devices d ON d.id = ae.device_id
                WHERE ae.user_id = ?
                ORDER BY ae.updated_at DESC
            `
            : `
                SELECT ae.*, d.addon_version, d.last_seen_at
                FROM alexa_endpoints ae
                INNER JOIN devices d ON d.id = ae.device_id
                WHERE ae.user_id = ? AND ae.exposed = 1
                ORDER BY ae.updated_at DESC
            `;
        const rows = await dbAll(sql, [userId]);
        return rows || [];
    }

    async function upsertAlexaEndpointFromDevice(userId, deviceId, payload) {
        const entityId = utils.sanitizeEntityId(payload?.entity_id);
        if (!entityId) {
            return null;
        }

        const displayName = utils.sanitizeString(payload?.display_name, 120) || entityId;
        const entityType = entityMapping.normalizeAlexaEntityType(payload?.entity_type, entityId);
        const roomHint = utils.sanitizeString(payload?.room_hint, 120);
        const online = payload?.online === false ? 0 : 1;
        const stateObj = payload?.state || {};
        if (payload?.manufacturer) stateObj._manufacturer = String(payload.manufacturer).slice(0, 120);
        if (payload?.model) stateObj._model = String(payload.model).slice(0, 120);
        const stateJson = JSON.stringify(stateObj).slice(0, 8000);
        const endpointState = entityMapping.parseAlexaEndpointState({
            entity_type: entityType,
            online,
            state_json: stateJson
        });
        const stateHash = computeAlexaStateHash(endpointState);
        const nowIso = new Date().toISOString();

        const existing = await dbGet(
            `SELECT id, device_id, display_name, entity_type, room_hint FROM alexa_endpoints WHERE user_id = ? AND entity_id = ? LIMIT 1`,
            [userId, entityId]
        );

        const syncChanged =
            !existing ||
            Number(existing.device_id) !== Number(deviceId) ||
            (existing.display_name || '') !== displayName ||
            (existing.entity_type || '') !== entityType ||
            (existing.room_hint || '') !== (roomHint || '');

        if (existing) {
            await dbRun(
                `
                    UPDATE alexa_endpoints
                    SET device_id = ?, display_name = ?, entity_type = ?, room_hint = ?,
                        online = ?, entity_last_seen_at = ?, state_json = ?, state_hash = ?, updated_at = ?
                    WHERE id = ?
                `,
                [deviceId, displayName, entityType, roomHint, online, nowIso, stateJson, stateHash, nowIso, existing.id]
            );
        } else {
            await dbRun(
                `
                    INSERT INTO alexa_endpoints (
                        user_id, device_id, entity_id, display_name, entity_type, room_hint,
                        exposed, online, entity_last_seen_at, state_json, state_hash, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
                `,
                [userId, deviceId, entityId, displayName, entityType, roomHint, online, nowIso, stateJson, stateHash, nowIso, nowIso]
            );
        }

        const endpoint = await dbGet(`SELECT * FROM alexa_endpoints WHERE user_id = ? AND entity_id = ? LIMIT 1`, [
            userId,
            entityId
        ]);

        return { endpoint, syncChanged };
    }

    // ── Sync snapshots ──────────────────────────────────────────────────

    async function saveAlexaDeviceSnapshotEntityIds(userId, deviceId, entityIds = []) {
        const normalizedUserId = utils.parsePositiveInt(userId);
        const normalizedDeviceId = utils.parsePositiveInt(deviceId);
        if (!normalizedUserId || !normalizedDeviceId) {
            return;
        }
        const normalizedEntityIds = Array.from(
            new Set((Array.isArray(entityIds) ? entityIds : []).map((e) => utils.sanitizeEntityId(e)).filter(Boolean))
        );
        const nowIso = new Date().toISOString();
        const payload = JSON.stringify(normalizedEntityIds).slice(0, 120000);

        await dbRun(
            `
                INSERT INTO alexa_sync_snapshots (user_id, device_id, snapshot_entity_ids_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id, device_id) DO UPDATE SET
                    snapshot_entity_ids_json = excluded.snapshot_entity_ids_json,
                    updated_at = excluded.updated_at
            `,
            [normalizedUserId, normalizedDeviceId, payload, nowIso]
        );
    }

    async function getAlexaDeviceSnapshotEntityIds(userId, deviceId) {
        const normalizedUserId = utils.parsePositiveInt(userId);
        const normalizedDeviceId = utils.parsePositiveInt(deviceId);
        if (!normalizedUserId || !normalizedDeviceId) {
            return [];
        }
        const row = await dbGet(
            `SELECT snapshot_entity_ids_json FROM alexa_sync_snapshots WHERE user_id = ? AND device_id = ? LIMIT 1`,
            [normalizedUserId, normalizedDeviceId]
        );
        const parsed = utils.parseJsonSafe(row?.snapshot_entity_ids_json, []);
        return Array.from(
            new Set((Array.isArray(parsed) ? parsed : []).map((e) => utils.sanitizeEntityId(e)).filter(Boolean))
        );
    }

    // ── Command queue ───────────────────────────────────────────────────

    async function queueAlexaCommandForEndpoint(userId, deviceId, entityId, action, payload) {
        const nowIso = new Date().toISOString();
        const expiresAt = new Date(Date.now() + getAlexaCommandTtlSeconds() * 1000).toISOString();
        const normalizedAction = utils.sanitizeActionName(action) || 'set';
        const normalizedEntityId = utils.sanitizeEntityId(entityId);
        if (!normalizedEntityId) {
            return null;
        }

        // Supersede any pending command for the same endpoint+action (slider dedup).
        await dbRun(
            `
                UPDATE alexa_command_queue
                SET status = 'expired', updated_at = ?
                WHERE device_id = ? AND entity_id = ? AND action = ? AND status = 'pending'
            `,
            [nowIso, deviceId, normalizedEntityId, normalizedAction]
        );

        const insertResult = await dbRun(
            `
                INSERT INTO alexa_command_queue (
                    user_id, device_id, entity_id, action, payload_json, status, expires_at, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)
            `,
            [userId, deviceId, normalizedEntityId, normalizedAction, JSON.stringify(payload || {}).slice(0, 2000), expiresAt, nowIso, nowIso]
        );

        return dbGet(`SELECT * FROM alexa_command_queue WHERE id = ? LIMIT 1`, [insertResult.lastID]);
    }

    // ── Auth data cleanup ───────────────────────────────────────────────

    async function cleanupAlexaAuthDataForUser(userId) {
        // Auth tables — the link itself. Wiping alexa_tokens (Amazon's refresh
        // token) is what makes Amazon's next refresh fail → skill disables.
        await dbRun(`DELETE FROM alexa_auth_codes WHERE user_id = ?`, [userId]);
        await dbRun(`DELETE FROM alexa_tokens WHERE user_id = ?`, [userId]);
        await dbRun(`DELETE FROM alexa_lwa_tokens WHERE user_id = ?`, [userId]);
        // Data tables — leave a clean slate on unlink. Endpoints are repopulated
        // by Discovery on the next re-link; the command queue is stale history;
        // the sync snapshot is the last-reported delta baseline. None hold tokens.
        // Callers that need the endpoints (portal unlink → DeleteReport) read them
        // BEFORE invoking this, so deleting here is safe.
        await dbRun(`DELETE FROM alexa_endpoints WHERE user_id = ?`, [userId]);
        await dbRun(`DELETE FROM alexa_command_queue WHERE user_id = ?`, [userId]);
        await dbRun(`DELETE FROM alexa_sync_snapshots WHERE user_id = ?`, [userId]);
        await dbRun(`UPDATE users SET alexa_linked = 0, alexa_enabled = 0 WHERE id = ?`, [userId]);

        const normalizedUserId = Number(userId);
        state.alexaLwaAccessTokenCache.delete(normalizedUserId);
        state.alexaLivenessProbeAt.delete(normalizedUserId);
        for (const queue of [state.alexaAddOrUpdateQueue, state.alexaChangeReportQueue, state.alexaDeleteReportQueue]) {
            const entry = queue.get(normalizedUserId);
            if (entry?.timer) {
                clearTimeout(entry.timer);
            }
            queue.delete(normalizedUserId);
        }
    }

    return {
        getAlexaAuthCodeTtlSeconds,
        getAlexaAccessTokenTtlSeconds,
        getAlexaCommandTtlSeconds,
        generateAlexaOAuthCode,
        generateAlexaAccessToken,
        generateAlexaRefreshToken,
        computeAlexaStateHash,
        findUserByAlexaAccessToken,
        findAlexaRefreshTokenRow,
        findUserByAlexaAuthCode,
        issueAlexaTokensForUser,
        storeAlexaLwaTokens,
        getAlexaLwaTokenRow,
        getAlexaEndpointsForUser,
        upsertAlexaEndpointFromDevice,
        saveAlexaDeviceSnapshotEntityIds,
        getAlexaDeviceSnapshotEntityIds,
        queueAlexaCommandForEndpoint,
        cleanupAlexaAuthDataForUser
    };
};
