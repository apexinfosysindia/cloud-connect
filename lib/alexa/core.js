const crypto = require('node:crypto');
const config = require('../config');
const utils = require('../utils');
const state = require('./state');
const entityMapping = require('./entity-mapping');

module.exports = function ({ dbGet, dbRun, dbAll, eventGateway }) {
    // ── Alexa TTL helpers ───────────────────────────────────────────────

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
        return await dbGet(
            `
                SELECT *
                FROM alexa_tokens
                WHERE refresh_token_hash = ?
                LIMIT 1
            `,
            [tokenHash]
        );
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

    // ── Command waiting ─────────────────────────────────────────────────

    async function waitForAlexaCommandResult(commandId, timeoutMs = 10000) {
        const pollInterval = 250;
        const maxAttempts = Math.ceil(timeoutMs / pollInterval);
        for (let i = 0; i < maxAttempts; i++) {
            const cmd = await dbGet(
                `SELECT status, result_json FROM alexa_command_queue WHERE id = ? LIMIT 1`,
                [commandId]
            );
            if (cmd && cmd.status === 'completed' && cmd.result_json) {
                try {
                    return JSON.parse(cmd.result_json);
                } catch (_) {
                    return null;
                }
            }
            if (cmd && (cmd.status === 'failed' || cmd.status === 'error')) {
                return null;
            }
            await new Promise((r) => {
                setTimeout(r, pollInterval);
            });
        }
        return null;
    }

    // ── Entity helpers ──────────────────────────────────────────────────

    function withEffectiveAlexaOnline(entity) {
        return entityMapping.withEffectiveAlexaOnline(entity);
    }

    async function getAlexaEntitiesForUser(userId, options = {}) {
        const includeDisabled = Boolean(options.includeDisabled);
        const rows = includeDisabled
            ? await dbAll(
                  `
                    SELECT
                        ae.*,
                        d.addon_version,
                        d.last_seen_at
                    FROM alexa_entities ae
                    INNER JOIN devices d ON d.id = ae.device_id
                    WHERE ae.user_id = ?
                    ORDER BY ae.updated_at DESC
                `,
                  [userId]
              )
            : await dbAll(
                  `
                    SELECT
                        ae.*,
                        d.addon_version,
                        d.last_seen_at
                    FROM alexa_entities ae
                    INNER JOIN devices d ON d.id = ae.device_id
                    WHERE ae.user_id = ?
                      AND ae.exposed = 1
                    ORDER BY ae.updated_at DESC
                `,
                  [userId]
              );

        return (rows || []).map((row) => {
            const normalizedRow = {
                ...row,
                entity_last_seen_at: state.alexaEntityLastSeenColumnSupported
                    ? row.entity_last_seen_at
                    : row.updated_at
            };
            return withEffectiveAlexaOnline(normalizedRow);
        });
    }

    // ── Entity upsert ───────────────────────────────────────────────────

    async function upsertAlexaEntityFromDevice(userId, deviceId, payload) {
        const entityId = utils.sanitizeEntityId(payload?.entity_id);
        if (!entityId) {
            return null;
        }

        const displayName = utils.sanitizeString(payload?.display_name, 120) || entityId;
        const entityType = entityMapping.mapAlexaDomainToEntityType(
            entityId,
            entityMapping.normalizeAlexaEntityType(payload?.entity_type)
        );
        const roomHint = utils.sanitizeString(payload?.room_hint, 120);
        const online = payload?.online === false ? 0 : 1;
        const stateObj = payload?.state || {};
        if (payload?.manufacturer) stateObj._manufacturer = String(payload.manufacturer).slice(0, 120);
        if (payload?.model) stateObj._model = String(payload.model).slice(0, 120);
        if (payload?.sw_version) stateObj._sw_version = String(payload.sw_version).slice(0, 60);
        const stateJson = JSON.stringify(stateObj).slice(0, 8000);
        const properties = entityMapping.translateAlexaEntityState({
            entity_type: entityType,
            online,
            state_json: stateJson
        });
        const stateHash = eventGateway.computeAlexaStateHash(properties);
        const nowIso = new Date().toISOString();

        const existing = await dbGet(
            `
                SELECT id, exposed, device_id, display_name, entity_type, room_hint
                FROM alexa_entities
                WHERE user_id = ? AND entity_id = ?
                LIMIT 1
            `,
            [userId, entityId]
        );

        const syncChanged =
            !existing ||
            Number(existing.device_id) !== Number(deviceId) ||
            (existing.display_name || '') !== displayName ||
            (existing.entity_type || '') !== entityType ||
            (existing.room_hint || '') !== (roomHint || '');

        if (existing) {
            const updateFullSql = `
                UPDATE alexa_entities
                SET device_id = ?,
                    display_name = ?,
                    entity_type = ?,
                    room_hint = ?,
                    online = ?,
                    entity_last_seen_at = ?,
                    state_json = ?,
                    state_hash = ?,
                    updated_at = ?
                WHERE id = ?
            `;
            const updateFallbackSql = `
                UPDATE alexa_entities
                SET device_id = ?,
                    display_name = ?,
                    entity_type = ?,
                    room_hint = ?,
                    online = ?,
                    state_json = ?,
                    updated_at = ?
                WHERE id = ?
            `;

            try {
                await dbRun(updateFullSql, [
                    deviceId,
                    displayName,
                    entityType,
                    roomHint,
                    online,
                    nowIso,
                    stateJson,
                    stateHash,
                    nowIso,
                    existing.id
                ]);
            } catch (error) {
                if (
                    utils.isMissingGoogleEntityLastSeenColumnError(error) ||
                    utils.isMissingGoogleStateHashColumnError(error)
                ) {
                    state.alexaEntityLastSeenColumnSupported = false;
                    state.alexaStateHashColumnSupported = false;
                    await dbRun(updateFallbackSql, [
                        deviceId,
                        displayName,
                        entityType,
                        roomHint,
                        online,
                        stateJson,
                        nowIso,
                        existing.id
                    ]);
                } else {
                    throw error;
                }
            }
        } else {
            const defaultExposed = entityType === 'automation' || entityType === 'script' ? 0 : 1;

            const insertFullSql = `
                INSERT INTO alexa_entities (
                    user_id,
                    device_id,
                    entity_id,
                    display_name,
                    entity_type,
                    room_hint,
                    exposed,
                    online,
                    entity_last_seen_at,
                    state_json,
                    state_hash,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;
            const insertFallbackSql = `
                INSERT INTO alexa_entities (
                    user_id,
                    device_id,
                    entity_id,
                    display_name,
                    entity_type,
                    room_hint,
                    exposed,
                    online,
                    state_json,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;

            try {
                await dbRun(insertFullSql, [
                    userId,
                    deviceId,
                    entityId,
                    displayName,
                    entityType,
                    roomHint,
                    defaultExposed,
                    online,
                    nowIso,
                    stateJson,
                    stateHash,
                    nowIso,
                    nowIso
                ]);
            } catch (error) {
                if (
                    utils.isMissingGoogleEntityLastSeenColumnError(error) ||
                    utils.isMissingGoogleStateHashColumnError(error)
                ) {
                    state.alexaEntityLastSeenColumnSupported = false;
                    state.alexaStateHashColumnSupported = false;
                    await dbRun(insertFallbackSql, [
                        userId,
                        deviceId,
                        entityId,
                        displayName,
                        entityType,
                        roomHint,
                        defaultExposed,
                        online,
                        stateJson,
                        nowIso,
                        nowIso
                    ]);
                } else {
                    throw error;
                }
            }
        }

        const entity = await dbGet(
            `
                SELECT *
                FROM alexa_entities
                WHERE user_id = ? AND entity_id = ?
                LIMIT 1
            `,
            [userId, entityId]
        );

        return {
            entity,
            syncChanged
        };
    }

    // ── Sync snapshots ──────────────────────────────────────────────────

    async function saveAlexaDeviceSnapshotEntityIds(userId, deviceId, entityIds = []) {
        if (!state.alexaSyncSnapshotsTableSupported) {
            return;
        }

        const normalizedUserId = utils.parsePositiveInt(userId);
        const normalizedDeviceId = utils.parsePositiveInt(deviceId);
        if (!normalizedUserId || !normalizedDeviceId) {
            return;
        }

        const normalizedEntityIds = Array.from(
            new Set(
                (Array.isArray(entityIds) ? entityIds : [])
                    .map((entityId) => utils.sanitizeEntityId(entityId))
                    .filter(Boolean)
            )
        );

        const nowIso = new Date().toISOString();
        const payload = JSON.stringify(normalizedEntityIds).slice(0, 120000);

        try {
            if (state.alexaSyncSnapshotsUpsertSupported) {
                await dbRun(
                    `
                        INSERT INTO alexa_sync_snapshots (
                            user_id,
                            device_id,
                            snapshot_entity_ids_json,
                            updated_at
                        )
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(user_id, device_id) DO UPDATE SET
                            snapshot_entity_ids_json = excluded.snapshot_entity_ids_json,
                            updated_at = excluded.updated_at
                    `,
                    [normalizedUserId, normalizedDeviceId, payload, nowIso]
                );
                return;
            }
        } catch (error) {
            // Fall through to existence-check + UPDATE/INSERT
            if (utils.isMissingGoogleSyncSnapshotsTableError?.(error)) {
                state.alexaSyncSnapshotsTableSupported = false;
                return;
            }
            state.alexaSyncSnapshotsUpsertSupported = false;
        }

        const existing = await dbGet(
            `
                SELECT id
                FROM alexa_sync_snapshots
                WHERE user_id = ?
                  AND device_id = ?
                LIMIT 1
            `,
            [normalizedUserId, normalizedDeviceId]
        );

        if (existing) {
            await dbRun(
                `
                    UPDATE alexa_sync_snapshots
                    SET snapshot_entity_ids_json = ?,
                        updated_at = ?
                    WHERE id = ?
                `,
                [payload, nowIso, existing.id]
            );
        } else {
            await dbRun(
                `
                    INSERT INTO alexa_sync_snapshots (
                        user_id,
                        device_id,
                        snapshot_entity_ids_json,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?)
                `,
                [normalizedUserId, normalizedDeviceId, payload, nowIso]
            );
        }
    }

    async function getAlexaDeviceSnapshotEntityIds(userId, deviceId) {
        if (!state.alexaSyncSnapshotsTableSupported) {
            return [];
        }

        const normalizedUserId = utils.parsePositiveInt(userId);
        const normalizedDeviceId = utils.parsePositiveInt(deviceId);
        if (!normalizedUserId || !normalizedDeviceId) {
            return [];
        }

        const row = await dbGet(
            `
                SELECT snapshot_entity_ids_json
                FROM alexa_sync_snapshots
                WHERE user_id = ?
                  AND device_id = ?
                LIMIT 1
            `,
            [normalizedUserId, normalizedDeviceId]
        );

        const parsed = utils.parseJsonSafe(row?.snapshot_entity_ids_json, []);
        return Array.from(
            new Set(
                (Array.isArray(parsed) ? parsed : [])
                    .map((entityId) => utils.sanitizeEntityId(entityId))
                    .filter(Boolean)
            )
        );
    }

    // ── Command queue ───────────────────────────────────────────────────

    async function queueAlexaCommandForEntity(userId, deviceId, entityId, action, payload) {
        const nowIso = new Date().toISOString();
        const expiresAt = new Date(Date.now() + getAlexaCommandTtlSeconds() * 1000).toISOString();
        const normalizedAction = utils.sanitizeActionName(action) || 'set';
        const normalizedEntityId = utils.sanitizeEntityId(entityId);

        if (!normalizedEntityId) {
            return null;
        }

        // Slider-dedupe: supersede any pending command for the same entity+action
        await dbRun(
            `
                UPDATE alexa_command_queue
                SET status = 'expired',
                    updated_at = ?
                WHERE device_id = ?
                  AND entity_id = ?
                  AND action = ?
                  AND status = 'pending'
            `,
            [nowIso, deviceId, normalizedEntityId, normalizedAction]
        );

        const insertResult = await dbRun(
            `
                INSERT INTO alexa_command_queue (
                    user_id,
                    device_id,
                    entity_id,
                    action,
                    payload_json,
                    status,
                    expires_at,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)
            `,
            [
                userId,
                deviceId,
                normalizedEntityId,
                normalizedAction,
                JSON.stringify(payload || {}).slice(0, 2000),
                expiresAt,
                nowIso,
                nowIso
            ]
        );

        return dbGet(
            `
                SELECT *
                FROM alexa_command_queue
                WHERE id = ?
                LIMIT 1
            `,
            [insertResult.lastID]
        );
    }

    // ── Auth data cleanup ───────────────────────────────────────────────

    async function cleanupAlexaAuthDataForUser(userId) {
        await dbRun(`DELETE FROM alexa_auth_codes WHERE user_id = ?`, [userId]);
        await dbRun(`DELETE FROM alexa_tokens WHERE user_id = ?`, [userId]);
        await dbRun(
            `
                UPDATE users
                SET alexa_linked = 0,
                    alexa_enabled = 0
                WHERE id = ?
            `,
            [userId]
        );

        const normalizedUserId = Number(userId);
        const changeEntry = state.alexaChangeReportQueue.get(normalizedUserId);
        if (changeEntry?.timer) {
            clearTimeout(changeEntry.timer);
        }
        state.alexaChangeReportQueue.delete(normalizedUserId);

        const addEntry = state.alexaAddOrUpdateReportQueue.get(normalizedUserId);
        if (addEntry?.timer) {
            clearTimeout(addEntry.timer);
        }
        state.alexaAddOrUpdateReportQueue.delete(normalizedUserId);
    }

    // ── Runtime schema migration ────────────────────────────────────────

    async function ensureAlexaRuntimeSchemaReady() {
        if (state.alexaRuntimeSchemaReadyPromise) {
            return await state.alexaRuntimeSchemaReadyPromise;
        }

        state.alexaRuntimeSchemaReadyPromise = (async () => {
            // The canonical schema lives in migrations/003_alexa_integration.sql.
            // These idempotent statements mirror Google's runtime-migration safety
            // net so older deployments can upgrade without a full migrator run.
            const statements = [
                'ALTER TABLE alexa_entities ADD COLUMN entity_last_seen_at DATETIME',
                'ALTER TABLE alexa_entities ADD COLUMN state_hash TEXT',
                'ALTER TABLE alexa_entities ADD COLUMN last_reported_state_hash TEXT',
                'ALTER TABLE alexa_entities ADD COLUMN last_reported_at DATETIME',
                `
                    CREATE TABLE IF NOT EXISTS alexa_sync_snapshots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        device_id INTEGER NOT NULL,
                        snapshot_entity_ids_json TEXT,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(user_id, device_id),
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                    )
                `,
                'CREATE INDEX IF NOT EXISTS idx_alexa_entities_user_last_seen ON alexa_entities(user_id, entity_last_seen_at)',
                'CREATE INDEX IF NOT EXISTS idx_alexa_sync_snapshots_user_device ON alexa_sync_snapshots(user_id, device_id)'
            ];

            for (const statement of statements) {
                try {
                    await dbRun(statement);
                } catch (error) {
                    if (utils.isIgnorableSqliteMigrationError(error)) {
                        continue;
                    }
                    throw error;
                }
            }
        })().catch((error) => {
            state.alexaRuntimeSchemaReadyPromise = null;
            throw error;
        });

        return await state.alexaRuntimeSchemaReadyPromise;
    }

    // ── Stale entity marking interval ───────────────────────────────────

    function startStaleEntityInterval() {
        setInterval(() => {
            eventGateway.markAlexaEntitiesStaleByFreshness().catch((error) => {
                console.error('ALEXA ENTITY STALE MARK ERROR:', error);
            });
        }, 30000).unref?.();
    }

    return {
        getAlexaAuthCodeTtlSeconds,
        getAlexaAccessTokenTtlSeconds,
        getAlexaCommandTtlSeconds,
        generateAlexaOAuthCode,
        generateAlexaAccessToken,
        generateAlexaRefreshToken,
        findUserByAlexaAccessToken,
        findAlexaRefreshTokenRow,
        findUserByAlexaAuthCode,
        issueAlexaTokensForUser,
        waitForAlexaCommandResult,
        withEffectiveAlexaOnline,
        getAlexaEntitiesForUser,
        upsertAlexaEntityFromDevice,
        saveAlexaDeviceSnapshotEntityIds,
        getAlexaDeviceSnapshotEntityIds,
        queueAlexaCommandForEntity,
        cleanupAlexaAuthDataForUser,
        ensureAlexaRuntimeSchemaReady,
        startStaleEntityInterval
    };
};
