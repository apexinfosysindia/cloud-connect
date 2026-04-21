const express = require('express');

module.exports = function ({
    dbGet,
    dbRun,
    dbAll,
    dbTransaction,
    utils,
    auth,
    alexaCore,
    alexaEventGateway,
    alexaState
}) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.post('/api/internal/devices/alexa/entities', auth.requireDeviceAuth, async (req, res) => {
        try {
            try {
                await alexaCore.ensureAlexaRuntimeSchemaReady();
            } catch (schemaError) {
                console.warn('ALEXA RUNTIME SCHEMA LAZY CHECK FAILED:', schemaError?.message || schemaError);
            }
            const device = req.device;
            const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [device.user_id]);
            const nowIso = new Date().toISOString();
            await alexaEventGateway.markAlexaEntitiesStaleByFreshness();
            if (!user || !user.alexa_enabled) {
                await dbRun(
                    `
                        UPDATE alexa_entities
                        SET online = 0,
                            updated_at = ?
                        WHERE user_id = ?
                          AND device_id = ?
                    `,
                    [nowIso, device.user_id, device.id]
                );
                await alexaCore.saveAlexaDeviceSnapshotEntityIds(device.user_id, device.id, []);

                return res.status(200).json({
                    message: 'Alexa integration is disabled for this account',
                    synced_count: 0,
                    synced_entities: []
                });
            }

            const entitiesPayload = Array.isArray(req.body?.entities) ? req.body.entities : [];
            const fullSnapshot = req.body?.full_snapshot !== false;
            const snapshotEntityIds = Array.isArray(req.body?.snapshot_entity_ids)
                ? req.body.snapshot_entity_ids
                : null;

            const assignEntityLastSeen = alexaState.alexaEntityLastSeenColumnSupported
                ? 'entity_last_seen_at = ?,'
                : '';
            const assignEntityLastSeenParams = alexaState.alexaEntityLastSeenColumnSupported ? [nowIso] : [];

            if (entitiesPayload.length === 0) {
                if (fullSnapshot && snapshotEntityIds) {
                    const normalizedSnapshotIds = Array.from(
                        new Set(snapshotEntityIds.map((item) => utils.sanitizeEntityId(item)).filter(Boolean))
                    );
                    const placeholders = normalizedSnapshotIds.map(() => '?').join(',');
                    try {
                        if (normalizedSnapshotIds.length > 0) {
                            await dbRun(
                                `
                                    UPDATE alexa_entities
                                    SET online = 0,
                                        ${assignEntityLastSeen}
                                        updated_at = ?
                                    WHERE user_id = ?
                                      AND device_id = ?
                                      AND entity_id NOT IN (${placeholders})
                                `,
                                [...assignEntityLastSeenParams, nowIso, device.user_id, device.id, ...normalizedSnapshotIds]
                            );
                        } else {
                            await dbRun(
                                `
                                    UPDATE alexa_entities
                                    SET online = 0,
                                        ${assignEntityLastSeen}
                                        updated_at = ?
                                    WHERE user_id = ?
                                      AND device_id = ?
                                `,
                                [...assignEntityLastSeenParams, nowIso, device.user_id, device.id]
                            );
                        }
                    } catch (error) {
                        if (utils.isMissingGoogleEntityLastSeenColumnError(error)) {
                            alexaState.alexaEntityLastSeenColumnSupported = false;
                        } else {
                            throw error;
                        }
                    }

                    await alexaCore.saveAlexaDeviceSnapshotEntityIds(
                        device.user_id,
                        device.id,
                        normalizedSnapshotIds
                    );
                    alexaEventGateway.queueAlexaAddOrUpdateReport(
                        device.user_id,
                        device.id,
                        'entity_inventory_snapshot_commit'
                    );

                    return res.status(200).json({
                        message: 'Snapshot inventory committed',
                        synced_count: 0,
                        synced_entities: []
                    });
                }

                return res.status(200).json({
                    message: 'No entities received, inventory update skipped',
                    synced_count: 0,
                    synced_entities: []
                });
            }

            const synced = [];
            const incomingEntityIds = [];
            let shouldAddOrUpdate = false;

            for (const entityPayload of entitiesPayload) {
                const normalizedEntityId = utils.sanitizeEntityId(entityPayload?.entity_id);
                if (normalizedEntityId) {
                    incomingEntityIds.push(normalizedEntityId);
                }

                const upserted = await alexaCore.upsertAlexaEntityFromDevice(
                    device.user_id,
                    device.id,
                    entityPayload
                );
                if (upserted?.entity) {
                    synced.push(upserted.entity.entity_id);
                    if (upserted.syncChanged) {
                        shouldAddOrUpdate = true;
                    }
                    // Per-entity ChangeReport for state deltas.
                    alexaEventGateway.queueAlexaChangeReport(
                        device.user_id,
                        upserted.entity.entity_id,
                        'device_sync'
                    );
                }
            }

            const uniqueIncomingEntityIds = Array.from(new Set(incomingEntityIds));
            if (uniqueIncomingEntityIds.length === 0) {
                return res.status(200).json({
                    message: 'No valid entities in payload, inventory update skipped',
                    synced_count: synced.length,
                    synced_entities: synced
                });
            }

            if (fullSnapshot && uniqueIncomingEntityIds.length > 0) {
                const baselineIds = snapshotEntityIds
                    ? Array.from(
                          new Set(snapshotEntityIds.map((item) => utils.sanitizeEntityId(item)).filter(Boolean))
                      )
                    : await alexaCore.getAlexaDeviceSnapshotEntityIds(device.user_id, device.id);
                const snapshotIdsSet = new Set(baselineIds);
                for (const entityId of uniqueIncomingEntityIds) {
                    snapshotIdsSet.add(entityId);
                }
                const effectiveSnapshotIds = Array.from(snapshotIdsSet);
                const placeholders = effectiveSnapshotIds.map(() => '?').join(',');
                try {
                    await dbRun(
                        `
                            UPDATE alexa_entities
                            SET online = 0,
                                ${assignEntityLastSeen}
                                updated_at = ?
                            WHERE user_id = ?
                              AND device_id = ?
                              AND entity_id NOT IN (${placeholders})
                        `,
                        [
                            ...assignEntityLastSeenParams,
                            nowIso,
                            device.user_id,
                            device.id,
                            ...effectiveSnapshotIds
                        ]
                    );
                } catch (error) {
                    if (utils.isMissingGoogleEntityLastSeenColumnError(error)) {
                        alexaState.alexaEntityLastSeenColumnSupported = false;
                    } else {
                        throw error;
                    }
                }

                await alexaCore.saveAlexaDeviceSnapshotEntityIds(
                    device.user_id,
                    device.id,
                    effectiveSnapshotIds
                );
            }

            if (shouldAddOrUpdate) {
                alexaEventGateway.queueAlexaAddOrUpdateReport(device.user_id, device.id, 'entity_inventory_changed');
            }

            return res.status(200).json({
                message: 'Entities synced',
                synced_count: synced.length,
                synced_entities: synced
            });
        } catch (error) {
            console.error('DEVICE ALEXA ENTITIES SYNC ERROR:', error);
            return res.status(500).json({ error: 'Unable to sync Alexa entities' });
        }
    });

    router.post(
        '/api/internal/devices/alexa/commands',
        auth.requireDeviceAuth,
        asyncHandler(async (req, res) => {
            const device = req.device;
            const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [device.user_id]);
            if (!user || !user.alexa_enabled) {
                return res.status(200).json({ commands: [] });
            }

            const nowIso = new Date().toISOString();
            await dbRun(
                `
                    UPDATE alexa_command_queue
                    SET status = 'expired',
                        updated_at = ?
                    WHERE device_id = ?
                      AND status IN ('pending', 'dispatched')
                      AND expires_at <= ?
                `,
                [nowIso, device.id, nowIso]
            );

            const rows = await dbTransaction(async (tx) => {
                const pending = await tx.dbAll(
                    `
                        SELECT *
                        FROM alexa_command_queue
                        WHERE device_id = ?
                          AND status = 'pending'
                          AND expires_at > ?
                        ORDER BY id ASC
                        LIMIT 20
                    `,
                    [device.id, nowIso]
                );

                const commandIds = (pending || []).map((row) => row.id);
                if (commandIds.length > 0) {
                    const placeholders = commandIds.map(() => '?').join(',');
                    await tx.dbRun(
                        `
                            UPDATE alexa_command_queue
                            SET status = 'dispatched',
                                updated_at = ?
                            WHERE id IN (${placeholders})
                        `,
                        [nowIso, ...commandIds]
                    );
                }

                return pending;
            });

            return res.status(200).json({
                commands: (rows || []).map((row) => ({
                    id: row.id,
                    entity_id: row.entity_id,
                    action: row.action,
                    payload: utils.parseJsonSafe(row.payload_json, {})
                }))
            });
        })
    );

    router.post(
        '/api/internal/devices/alexa/commands/:id/result',
        auth.requireDeviceAuth,
        async (req, res) => {
            const commandId = utils.parsePositiveInt(req.params.id);
            if (!commandId) {
                return res.status(400).json({ error: 'Invalid command id' });
            }

            try {
                const device = req.device;
                const command = await dbGet(
                    `
                        SELECT *
                        FROM alexa_command_queue
                        WHERE id = ? AND device_id = ?
                        LIMIT 1
                    `,
                    [commandId, device.id]
                );

                if (!command) {
                    return res.status(404).json({ error: 'Command not found' });
                }

                const success = req.body?.success !== false;
                const errorMessage = utils.sanitizeString(req.body?.error, 240);
                const nowIso = new Date().toISOString();
                await dbRun(
                    `
                        UPDATE alexa_command_queue
                        SET status = ?,
                            result_json = ?,
                            updated_at = ?
                        WHERE id = ?
                    `,
                    [
                        success ? 'completed' : 'failed',
                        JSON.stringify({
                            success,
                            error: errorMessage || null,
                            state: req.body?.state || null
                        }).slice(0, 2500),
                        nowIso,
                        command.id
                    ]
                );

                if (success && req.body?.state) {
                    const normalizedState = req.body.state || {};
                    const existingEntity = await dbGet(
                        `SELECT state_json FROM alexa_entities WHERE user_id = ? AND device_id = ? AND entity_id = ? LIMIT 1`,
                        [command.user_id, command.device_id, command.entity_id]
                    );
                    const existingState = utils.parseJsonSafe(existingEntity?.state_json, {}) || {};
                    const mergedState = { ...existingState, ...normalizedState };
                    const stateJson = JSON.stringify(mergedState).slice(0, 8000);

                    try {
                        await dbRun(
                            `
                                UPDATE alexa_entities
                                SET state_json = ?,
                                    online = 1,
                                    entity_last_seen_at = ?,
                                    updated_at = ?
                                WHERE user_id = ?
                                  AND device_id = ?
                                  AND entity_id = ?
                            `,
                            [stateJson, nowIso, nowIso, command.user_id, device.id, command.entity_id]
                        );
                    } catch (error) {
                        if (utils.isMissingGoogleEntityLastSeenColumnError(error)) {
                            alexaState.alexaEntityLastSeenColumnSupported = false;
                            await dbRun(
                                `
                                    UPDATE alexa_entities
                                    SET state_json = ?,
                                        online = 1,
                                        updated_at = ?
                                    WHERE user_id = ?
                                      AND device_id = ?
                                      AND entity_id = ?
                                `,
                                [stateJson, nowIso, command.user_id, device.id, command.entity_id]
                            );
                        } else {
                            throw error;
                        }
                    }

                    alexaEventGateway.queueAlexaChangeReport(command.user_id, command.entity_id, 'command_result');
                }

                return res.status(200).json({ message: 'Command result recorded' });
            } catch (error) {
                console.error('DEVICE ALEXA COMMAND RESULT ERROR:', error);
                return res.status(500).json({ error: 'Unable to store command result' });
            }
        }
    );

    // Silence unused-var lint for imports that are ready for future use
    void dbAll;

    return router;
};
