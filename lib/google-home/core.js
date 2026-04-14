const crypto = require('crypto');
const config = require('../config');
const utils = require('../utils');
const state = require('./state');
const entityMapping = require('./entity-mapping');

module.exports = function ({ dbGet, dbRun, dbAll, homegraph }) {
    // ── Google TTL helpers ──────────────────────────────────────────────

    function getGoogleAuthCodeTtlSeconds() {
        if (!Number.isFinite(config.GOOGLE_HOME_AUTH_CODE_TTL_SECONDS)) {
            return 600;
        }

        return Math.max(120, Math.min(1800, Math.round(config.GOOGLE_HOME_AUTH_CODE_TTL_SECONDS)));
    }

    function getGoogleAccessTokenTtlSeconds() {
        if (!Number.isFinite(config.GOOGLE_HOME_ACCESS_TOKEN_TTL_SECONDS)) {
            return 3600;
        }

        return Math.max(300, Math.min(7200, Math.round(config.GOOGLE_HOME_ACCESS_TOKEN_TTL_SECONDS)));
    }

    function getGoogleCommandTtlSeconds() {
        if (!Number.isFinite(config.GOOGLE_HOME_COMMAND_TTL_SECONDS)) {
            return 45;
        }

        return Math.max(10, Math.min(180, Math.round(config.GOOGLE_HOME_COMMAND_TTL_SECONDS)));
    }

    // ── Token generation ────────────────────────────────────────────────

    function generateGoogleOAuthCode() {
        return 'gac_' + crypto.randomBytes(24).toString('hex');
    }

    function generateGoogleAccessToken() {
        return 'gat_' + crypto.randomBytes(24).toString('hex');
    }

    function generateGoogleRefreshToken() {
        return 'grt_' + crypto.randomBytes(24).toString('hex');
    }

    // ── Token lookup / auth ─────────────────────────────────────────────

    async function findUserByGoogleAccessToken(accessToken) {
        if (!accessToken) {
            return null;
        }

        const tokenHash = utils.hashSecret(accessToken);
        return await dbGet(
            `
                SELECT u.*
                FROM users u
                INNER JOIN google_home_tokens ght ON ght.user_id = u.id
                WHERE ght.access_token_hash = ?
                  AND ght.expires_at > ?
            `,
            [tokenHash, new Date().toISOString()]
        );
    }

    async function findGoogleRefreshTokenRow(refreshToken) {
        if (!refreshToken) {
            return null;
        }

        const tokenHash = utils.hashSecret(refreshToken);
        return await dbGet(
            `
                SELECT *
                FROM google_home_tokens
                WHERE refresh_token_hash = ?
                LIMIT 1
            `,
            [tokenHash]
        );
    }

    async function findUserByGoogleAuthCode(authCode, redirectUri) {
        if (!authCode) {
            return null;
        }

        const codeHash = utils.hashSecret(authCode);
        return await dbGet(
            `
                SELECT
                    u.*,
                    ghac.id AS oauth_code_id,
                    ghac.redirect_uri AS oauth_redirect_uri
                FROM google_home_auth_codes ghac
                INNER JOIN users u ON u.id = ghac.user_id
                WHERE ghac.code_hash = ?
                  AND ghac.expires_at > ?
                  AND ghac.consumed_at IS NULL
                  AND ghac.redirect_uri = ?
                LIMIT 1
            `,
            [codeHash, new Date().toISOString(), redirectUri]
        );
    }

    async function issueGoogleTokensForUser(userId, existingRefreshToken = null) {
        const accessToken = generateGoogleAccessToken();
        const refreshToken = existingRefreshToken || generateGoogleRefreshToken();
        const accessTokenHash = utils.hashSecret(accessToken);
        const refreshTokenHash = utils.hashSecret(refreshToken);
        const expiresAt = new Date(Date.now() + getGoogleAccessTokenTtlSeconds() * 1000).toISOString();
        const nowIso = new Date().toISOString();

        await dbRun(
            `
                INSERT INTO google_home_tokens (
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
            expires_in: getGoogleAccessTokenTtlSeconds(),
            token_type: 'Bearer'
        };
    }

    // ── Command waiting ─────────────────────────────────────────────────

    async function waitForGoogleCommandResult(commandId, timeoutMs = 10000) {
        const pollInterval = 250;
        const maxAttempts = Math.ceil(timeoutMs / pollInterval);
        for (let i = 0; i < maxAttempts; i++) {
            const cmd = await dbGet(`SELECT status, result_json FROM google_home_command_queue WHERE id = ? LIMIT 1`, [
                commandId
            ]);
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

    // Delegate to entity-mapping (canonical location after refactor)
    function withEffectiveGoogleOnline(entity) {
        return entityMapping.withEffectiveGoogleOnline(entity);
    }

    async function getGoogleEntitiesForUser(userId, options = {}) {
        const includeDisabled = Boolean(options.includeDisabled);
        const rows = includeDisabled
            ? await dbAll(
                  `
                    SELECT
                        ge.*,
                        d.addon_version,
                        d.last_seen_at
                    FROM google_home_entities ge
                    INNER JOIN devices d ON d.id = ge.device_id
                    WHERE ge.user_id = ?
                    ORDER BY ge.updated_at DESC
                `,
                  [userId]
              )
            : await dbAll(
                  `
                    SELECT
                        ge.*,
                        d.addon_version,
                        d.last_seen_at
                    FROM google_home_entities ge
                    INNER JOIN devices d ON d.id = ge.device_id
                    WHERE ge.user_id = ?
                      AND ge.exposed = 1
                    ORDER BY ge.updated_at DESC
                `,
                  [userId]
              );

        return (rows || []).map((row) => {
            const normalizedRow = {
                ...row,
                entity_last_seen_at: state.googleEntityLastSeenColumnSupported
                    ? row.entity_last_seen_at
                    : row.updated_at
            };
            return withEffectiveGoogleOnline(normalizedRow);
        });
    }

    // ── Entity upsert ───────────────────────────────────────────────────

    async function upsertGoogleEntityFromDevice(userId, deviceId, payload) {
        const entityId = utils.sanitizeEntityId(payload?.entity_id);
        if (!entityId) {
            return null;
        }

        const displayName = utils.sanitizeString(payload?.display_name, 120) || entityId;
        const entityType = entityMapping.mapGoogleDomainToEntityType(
            entityId,
            entityMapping.normalizeGoogleEntityType(payload?.entity_type)
        );
        const roomHint = utils.sanitizeString(payload?.room_hint, 120);
        const online = payload?.online === false ? 0 : 1;
        const stateObj = payload?.state || {};
        // Merge device registry info into state for storage
        if (payload?.manufacturer) stateObj._manufacturer = String(payload.manufacturer).slice(0, 120);
        if (payload?.model) stateObj._model = String(payload.model).slice(0, 120);
        if (payload?.sw_version) stateObj._sw_version = String(payload.sw_version).slice(0, 60);
        const stateJson = JSON.stringify(stateObj).slice(0, 8000);
        const entityState = entityMapping.parseGoogleEntityState({
            entity_type: entityType,
            online,
            state_json: stateJson
        });
        const stateHash = homegraph.computeGoogleStateHash(entityState);
        const nowIso = new Date().toISOString();

        const existing = await dbGet(
            `
                SELECT id, exposed, device_id, display_name, entity_type, room_hint
                FROM google_home_entities
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
            const updateWithLastSeenSql = `
                UPDATE google_home_entities
                SET device_id = ?,
                    display_name = ?,
                    entity_type = ?,
                    room_hint = ?,
                    online = ?,
                    entity_last_seen_at = ?,
                    state_json = ?,
                    updated_at = ?
                WHERE id = ?
            `;

            const updateFallbackSql = `
                UPDATE google_home_entities
                SET device_id = ?,
                    display_name = ?,
                    entity_type = ?,
                    room_hint = ?,
                    online = ?,
                    state_json = ?,
                    updated_at = ?
                WHERE id = ?
            `;

            const updateWithLastSeenAndHashSql = `
                UPDATE google_home_entities
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

            const updateFallbackAndHashSql = `
                UPDATE google_home_entities
                SET device_id = ?,
                    display_name = ?,
                    entity_type = ?,
                    room_hint = ?,
                    online = ?,
                    state_json = ?,
                    state_hash = ?,
                    updated_at = ?
                WHERE id = ?
            `;

            try {
                if (state.googleEntityLastSeenColumnSupported && state.googleStateHashColumnSupported) {
                    await dbRun(updateWithLastSeenAndHashSql, [
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
                } else if (state.googleEntityLastSeenColumnSupported && !state.googleStateHashColumnSupported) {
                    await dbRun(updateWithLastSeenSql, [
                        deviceId,
                        displayName,
                        entityType,
                        roomHint,
                        online,
                        nowIso,
                        stateJson,
                        nowIso,
                        existing.id
                    ]);
                } else if (!state.googleEntityLastSeenColumnSupported && state.googleStateHashColumnSupported) {
                    await dbRun(updateFallbackAndHashSql, [
                        deviceId,
                        displayName,
                        entityType,
                        roomHint,
                        online,
                        stateJson,
                        stateHash,
                        nowIso,
                        existing.id
                    ]);
                } else {
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
                }
            } catch (error) {
                if (
                    utils.isMissingGoogleEntityLastSeenColumnError(error) ||
                    utils.isMissingGoogleStateHashColumnError(error)
                ) {
                    state.googleEntityLastSeenColumnSupported = false;
                    state.googleStateHashColumnSupported = false;
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

            const insertWithLastSeenSql = `
                INSERT INTO google_home_entities (
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
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;

            const insertFallbackSql = `
                INSERT INTO google_home_entities (
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

            const insertWithLastSeenAndHashSql = `
                INSERT INTO google_home_entities (
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

            const insertFallbackAndHashSql = `
                INSERT INTO google_home_entities (
                    user_id,
                    device_id,
                    entity_id,
                    display_name,
                    entity_type,
                    room_hint,
                    exposed,
                    online,
                    state_json,
                    state_hash,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;

            try {
                if (state.googleEntityLastSeenColumnSupported && state.googleStateHashColumnSupported) {
                    await dbRun(insertWithLastSeenAndHashSql, [
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
                } else if (state.googleEntityLastSeenColumnSupported && !state.googleStateHashColumnSupported) {
                    await dbRun(insertWithLastSeenSql, [
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
                        nowIso,
                        nowIso
                    ]);
                } else if (!state.googleEntityLastSeenColumnSupported && state.googleStateHashColumnSupported) {
                    await dbRun(insertFallbackAndHashSql, [
                        userId,
                        deviceId,
                        entityId,
                        displayName,
                        entityType,
                        roomHint,
                        defaultExposed,
                        online,
                        stateJson,
                        stateHash,
                        nowIso,
                        nowIso
                    ]);
                } else {
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
                }
            } catch (error) {
                if (
                    utils.isMissingGoogleEntityLastSeenColumnError(error) ||
                    utils.isMissingGoogleStateHashColumnError(error)
                ) {
                    state.googleEntityLastSeenColumnSupported = false;
                    state.googleStateHashColumnSupported = false;
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
                FROM google_home_entities
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

    async function saveGoogleDeviceSnapshotEntityIds(userId, deviceId, entityIds = []) {
        if (!state.googleSyncSnapshotsTableSupported) {
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
            if (state.googleSyncSnapshotsUpsertSupported) {
                await dbRun(
                    `
                        INSERT INTO google_home_sync_snapshots (
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
            if (utils.isGoogleSyncSnapshotsUpsertUnsupportedError(error)) {
                state.googleSyncSnapshotsUpsertSupported = false;
            } else if (utils.isMissingGoogleSyncSnapshotsTableError(error)) {
                state.googleSyncSnapshotsTableSupported = false;
                return;
            } else {
                throw error;
            }
        }

        if (!state.googleSyncSnapshotsTableSupported) {
            return;
        }

        const existing = await dbGet(
            `
                SELECT id
                FROM google_home_sync_snapshots
                WHERE user_id = ?
                  AND device_id = ?
                LIMIT 1
            `,
            [normalizedUserId, normalizedDeviceId]
        );

        if (existing) {
            await dbRun(
                `
                    UPDATE google_home_sync_snapshots
                    SET snapshot_entity_ids_json = ?,
                        updated_at = ?
                    WHERE id = ?
                `,
                [payload, nowIso, existing.id]
            );
        } else {
            await dbRun(
                `
                    INSERT INTO google_home_sync_snapshots (
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

    async function getGoogleDeviceSnapshotEntityIds(userId, deviceId) {
        if (!state.googleSyncSnapshotsTableSupported) {
            return [];
        }

        const normalizedUserId = utils.parsePositiveInt(userId);
        const normalizedDeviceId = utils.parsePositiveInt(deviceId);
        if (!normalizedUserId || !normalizedDeviceId) {
            return [];
        }

        let row;
        try {
            row = await dbGet(
                `
                    SELECT snapshot_entity_ids_json
                    FROM google_home_sync_snapshots
                    WHERE user_id = ?
                      AND device_id = ?
                    LIMIT 1
                `,
                [normalizedUserId, normalizedDeviceId]
            );
        } catch (error) {
            if (utils.isMissingGoogleSyncSnapshotsTableError(error)) {
                state.googleSyncSnapshotsTableSupported = false;
                return [];
            }
            throw error;
        }

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

    async function queueGoogleCommandForEntity(userId, deviceId, entityId, action, payload) {
        const nowIso = new Date().toISOString();
        const expiresAt = new Date(Date.now() + getGoogleCommandTtlSeconds() * 1000).toISOString();
        const normalizedAction = utils.sanitizeActionName(action) || 'set';
        const normalizedEntityId = utils.sanitizeEntityId(entityId);

        if (!normalizedEntityId) {
            return null;
        }

        // Supersede any pending commands for the same entity+action (slider deduplication)
        // This prevents rapid slider adjustments from queueing multiple obsolete commands
        // Uses 'expired' status (allowed by DB CHECK constraint) to mark obsolete pending commands
        await dbRun(
            `
                UPDATE google_home_command_queue
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
                INSERT INTO google_home_command_queue (
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
                FROM google_home_command_queue
                WHERE id = ?
                LIMIT 1
            `,
            [insertResult.lastID]
        );
    }

    // ── Auth data cleanup ───────────────────────────────────────────────

    async function cleanupGoogleAuthDataForUser(userId) {
        await dbRun(`DELETE FROM google_home_auth_codes WHERE user_id = ?`, [userId]);
        await dbRun(`DELETE FROM google_home_tokens WHERE user_id = ?`, [userId]);
        await dbRun(
            `
                UPDATE users
                SET google_home_linked = 0,
                    google_home_enabled = 0
                WHERE id = ?
            `,
            [userId]
        );

        const normalizedUserId = Number(userId);
        const requestSyncEntry = state.googleHomegraphRequestSyncQueue.get(normalizedUserId);
        if (requestSyncEntry?.timer) {
            clearTimeout(requestSyncEntry.timer);
        }
        state.googleHomegraphRequestSyncQueue.delete(normalizedUserId);

        const reportStateEntry = state.googleHomegraphReportStateQueue.get(normalizedUserId);
        if (reportStateEntry?.timer) {
            clearTimeout(reportStateEntry.timer);
        }
        state.googleHomegraphReportStateQueue.delete(normalizedUserId);
    }

    // ── Runtime schema migration ────────────────────────────────────────

    async function ensureGoogleRuntimeSchemaReady() {
        if (state.googleRuntimeSchemaReadyPromise) {
            return await state.googleRuntimeSchemaReadyPromise;
        }

        state.googleRuntimeSchemaReadyPromise = (async () => {
            const statements = [
                'ALTER TABLE google_home_entities ADD COLUMN entity_last_seen_at DATETIME',
                'ALTER TABLE google_home_entities ADD COLUMN state_hash TEXT',
                'ALTER TABLE google_home_entities ADD COLUMN last_reported_state_hash TEXT',
                'ALTER TABLE google_home_entities ADD COLUMN last_reported_at DATETIME',
                `
                    CREATE TABLE IF NOT EXISTS google_home_sync_snapshots (
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
                'CREATE INDEX IF NOT EXISTS idx_google_home_entities_user_last_seen ON google_home_entities(user_id, entity_last_seen_at)',
                'CREATE INDEX IF NOT EXISTS idx_google_home_sync_snapshots_user_device ON google_home_sync_snapshots(user_id, device_id)'
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
            state.googleRuntimeSchemaReadyPromise = null;
            throw error;
        });

        return await state.googleRuntimeSchemaReadyPromise;
    }

    // ── Stale entity marking interval ───────────────────────────────────

    function startStaleEntityInterval() {
        setInterval(() => {
            homegraph.markGoogleEntitiesStaleByFreshness().catch((error) => {
                console.error('GOOGLE ENTITY STALE MARK ERROR:', error);
            });
        }, 30000).unref?.();
    }

    return {
        getGoogleAuthCodeTtlSeconds,
        getGoogleAccessTokenTtlSeconds,
        getGoogleCommandTtlSeconds,
        generateGoogleOAuthCode,
        generateGoogleAccessToken,
        generateGoogleRefreshToken,
        findUserByGoogleAccessToken,
        findGoogleRefreshTokenRow,
        findUserByGoogleAuthCode,
        issueGoogleTokensForUser,
        waitForGoogleCommandResult,
        withEffectiveGoogleOnline,
        getGoogleEntitiesForUser,
        upsertGoogleEntityFromDevice,
        saveGoogleDeviceSnapshotEntityIds,
        getGoogleDeviceSnapshotEntityIds,
        queueGoogleCommandForEntity,
        cleanupGoogleAuthDataForUser,
        ensureGoogleRuntimeSchemaReady,
        startStaleEntityInterval
    };
};
