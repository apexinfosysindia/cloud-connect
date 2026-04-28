const express = require('express');

module.exports = function ({ dbGet, dbRun, dbAll, dbTransaction, utils, auth, googleCore, homegraph, state }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.post('/api/internal/devices/google-home/entities', auth.requireDeviceAuth, async (req, res) => {
        try {
            try {
                await googleCore.ensureGoogleRuntimeSchemaReady();
            } catch (schemaError) {
                console.warn('GOOGLE RUNTIME SCHEMA LAZY CHECK FAILED:', schemaError?.message || schemaError);
            }
            const device = req.device;
            const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [device.user_id]);
            const nowIso = new Date().toISOString();
            await homegraph.markGoogleEntitiesStaleByFreshness();
            if (!user || !user.google_home_enabled) {
                await dbRun(
                    `
                        UPDATE google_home_entities
                        SET online = 0,
                            updated_at = ?
                        WHERE user_id = ?
                          AND device_id = ?
                    `,
                    [nowIso, device.user_id, device.id]
                );
                await googleCore.saveGoogleDeviceSnapshotEntityIds(device.user_id, device.id, []);

                return res.status(200).json({
                    message: 'Google Home integration is disabled for this account',
                    synced_count: 0,
                    synced_entities: []
                });
            }

            const entitiesPayload = Array.isArray(req.body?.entities) ? req.body.entities : [];
            const fullSnapshot = req.body?.full_snapshot !== false;
            const snapshotEntityIds = Array.isArray(req.body?.snapshot_entity_ids)
                ? req.body.snapshot_entity_ids
                : null;

            const assignEntityLastSeen = state.googleEntityLastSeenColumnSupported ? 'entity_last_seen_at = ?,' : '';
            const assignEntityLastSeenParams = state.googleEntityLastSeenColumnSupported ? [nowIso] : [];

            if (entitiesPayload.length === 0) {
                if (fullSnapshot && snapshotEntityIds) {
                    const normalizedSnapshotIds = Array.from(
                        new Set(snapshotEntityIds.map((item) => utils.sanitizeEntityId(item)).filter(Boolean))
                    );
                    const placeholders = normalizedSnapshotIds.map(() => '?').join(',');

                    if (normalizedSnapshotIds.length > 0) {
                        try {
                            await dbRun(
                                `
                                    UPDATE google_home_entities
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
                                    ...normalizedSnapshotIds
                                ]
                            );
                        } catch (error) {
                            if (utils.isMissingGoogleEntityLastSeenColumnError(error)) {
                                state.googleEntityLastSeenColumnSupported = false;
                                await dbRun(
                                    `
                                        UPDATE google_home_entities
                                        SET online = 0,
                                            updated_at = ?
                                        WHERE user_id = ?
                                          AND device_id = ?
                                          AND entity_id NOT IN (${placeholders})
                                    `,
                                    [nowIso, device.user_id, device.id, ...normalizedSnapshotIds]
                                );
                            } else {
                                throw error;
                            }
                        }
                    } else {
                        try {
                            await dbRun(
                                `
                                    UPDATE google_home_entities
                                    SET online = 0,
                                        ${assignEntityLastSeen}
                                        updated_at = ?
                                    WHERE user_id = ?
                                      AND device_id = ?
                                `,
                                [...assignEntityLastSeenParams, nowIso, device.user_id, device.id]
                            );
                        } catch (error) {
                            if (utils.isMissingGoogleEntityLastSeenColumnError(error)) {
                                state.googleEntityLastSeenColumnSupported = false;
                                await dbRun(
                                    `
                                        UPDATE google_home_entities
                                        SET online = 0,
                                            updated_at = ?
                                        WHERE user_id = ?
                                          AND device_id = ?
                                    `,
                                    [nowIso, device.user_id, device.id]
                                );
                            } else {
                                throw error;
                            }
                        }
                    }

                    await googleCore.saveGoogleDeviceSnapshotEntityIds(
                        device.user_id,
                        device.id,
                        normalizedSnapshotIds
                    );
                    homegraph.scheduleGoogleRequestSyncForUser(device.user_id, 'entity_inventory_snapshot_commit');
                    homegraph.scheduleGoogleReportStateForUser(device.user_id, { force: false });

                    return res.status(200).json({
                        message: 'Snapshot inventory committed',
                        synced_count: 0,
                        synced_entities: []
                    });
                }

                console.warn('DEVICE GOOGLE ENTITIES SYNC: EMPTY PAYLOAD, SKIPPING INVENTORY UPDATE', {
                    user_id: device.user_id,
                    device_id: device.id
                });

                return res.status(200).json({
                    message: 'No entities received, inventory update skipped',
                    synced_count: 0,
                    synced_entities: []
                });
            }

            const synced = [];
            const incomingEntityIds = [];
            let shouldRequestSync = false;

            for (const entityPayload of entitiesPayload) {
                const normalizedEntityId = utils.sanitizeEntityId(entityPayload?.entity_id);
                if (normalizedEntityId) {
                    incomingEntityIds.push(normalizedEntityId);
                }

                const upserted = await googleCore.upsertGoogleEntityFromDevice(
                    device.user_id,
                    device.id,
                    entityPayload
                );
                if (upserted?.entity) {
                    synced.push(upserted.entity.entity_id);
                    if (upserted.syncChanged) {
                        shouldRequestSync = true;
                    }
                }
            }

            const uniqueIncomingEntityIds = Array.from(new Set(incomingEntityIds));
            if (uniqueIncomingEntityIds.length === 0) {
                console.warn('DEVICE GOOGLE ENTITIES SYNC: NO VALID ENTITY IDS, SKIPPING INVENTORY UPDATE', {
                    user_id: device.user_id,
                    device_id: device.id,
                    received_count: entitiesPayload.length
                });

                return res.status(200).json({
                    message: 'No valid entities in payload, inventory update skipped',
                    synced_count: synced.length,
                    synced_entities: synced
                });
            }

            const beforeRows = await dbAll(
                `
                    SELECT entity_id
                    FROM google_home_entities
                    WHERE user_id = ?
                      AND device_id = ?
                      AND online = 1
                `,
                [device.user_id, device.id]
            );
            const beforeSet = new Set(
                (beforeRows || []).map((row) => utils.sanitizeEntityId(row.entity_id)).filter(Boolean)
            );

            if (fullSnapshot && uniqueIncomingEntityIds.length > 0) {
                const baselineIds = snapshotEntityIds
                    ? Array.from(new Set(snapshotEntityIds.map((item) => utils.sanitizeEntityId(item)).filter(Boolean)))
                    : await googleCore.getGoogleDeviceSnapshotEntityIds(device.user_id, device.id);
                const snapshotIdsSet = new Set(baselineIds);
                for (const entityId of uniqueIncomingEntityIds) {
                    snapshotIdsSet.add(entityId);
                }
                const effectiveSnapshotIds = Array.from(snapshotIdsSet);
                const placeholders = effectiveSnapshotIds.map(() => '?').join(',');
                try {
                    await dbRun(
                        `
                            UPDATE google_home_entities
                            SET online = 0,
                                ${assignEntityLastSeen}
                                updated_at = ?
                            WHERE user_id = ?
                              AND device_id = ?
                              AND entity_id NOT IN (${placeholders})
                        `,
                        [...assignEntityLastSeenParams, nowIso, device.user_id, device.id, ...effectiveSnapshotIds]
                    );
                } catch (error) {
                    if (utils.isMissingGoogleEntityLastSeenColumnError(error)) {
                        state.googleEntityLastSeenColumnSupported = false;
                        await dbRun(
                            `
                                UPDATE google_home_entities
                                SET online = 0,
                                    updated_at = ?
                                WHERE user_id = ?
                                  AND device_id = ?
                                  AND entity_id NOT IN (${placeholders})
                            `,
                            [nowIso, device.user_id, device.id, ...effectiveSnapshotIds]
                        );
                    } else {
                        throw error;
                    }
                }

                await googleCore.saveGoogleDeviceSnapshotEntityIds(device.user_id, device.id, effectiveSnapshotIds);
            } else if (fullSnapshot) {
                try {
                    await dbRun(
                        `
                            UPDATE google_home_entities
                            SET online = 0,
                                ${assignEntityLastSeen}
                                updated_at = ?
                            WHERE user_id = ?
                              AND device_id = ?
                        `,
                        [...assignEntityLastSeenParams, nowIso, device.user_id, device.id]
                    );
                } catch (error) {
                    if (utils.isMissingGoogleEntityLastSeenColumnError(error)) {
                        state.googleEntityLastSeenColumnSupported = false;
                        await dbRun(
                            `
                                UPDATE google_home_entities
                                SET online = 0,
                                    updated_at = ?
                                WHERE user_id = ?
                                  AND device_id = ?
                            `,
                            [nowIso, device.user_id, device.id]
                        );
                    } else {
                        throw error;
                    }
                }
                await googleCore.saveGoogleDeviceSnapshotEntityIds(device.user_id, device.id, []);
            }

            const afterRows = await dbAll(
                `
                    SELECT entity_id
                    FROM google_home_entities
                    WHERE user_id = ?
                      AND device_id = ?
                      AND online = 1
                `,
                [device.user_id, device.id]
            );
            const afterSet = new Set(
                (afterRows || []).map((row) => utils.sanitizeEntityId(row.entity_id)).filter(Boolean)
            );
            if (!shouldRequestSync && beforeSet.size !== afterSet.size) {
                shouldRequestSync = true;
            }

            if (!shouldRequestSync) {
                for (const id of beforeSet) {
                    if (!afterSet.has(id)) {
                        shouldRequestSync = true;
                        break;
                    }
                }
            }

            if (shouldRequestSync) {
                homegraph.scheduleGoogleRequestSyncForUser(device.user_id, 'entity_inventory_changed');
            }
            homegraph.scheduleGoogleReportStateForUser(device.user_id, { force: false });

            return res.status(200).json({
                message: 'Entities synced',
                synced_count: synced.length,
                synced_entities: synced
            });
        } catch (error) {
            console.error('DEVICE GOOGLE ENTITIES SYNC ERROR:', error);
            return res.status(500).json({ error: 'Unable to sync Google entities' });
        }
    });

    router.post(
        '/api/internal/devices/google-home/commands',
        auth.requireDeviceAuth,
        asyncHandler(async (req, res) => {
            const device = req.device;
            const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [device.user_id]);
            if (!user || !user.google_home_enabled) {
                return res.status(200).json({ commands: [] });
            }

            const nowIso = new Date().toISOString();
            await dbRun(
                `
                UPDATE google_home_command_queue
                SET status = 'expired',
                    updated_at = ?
                WHERE device_id = ?
                  AND status IN ('pending', 'dispatched')
                  AND expires_at <= ?
            `,
                [nowIso, device.id, nowIso]
            );

            // Atomic "fetch-and-mark-dispatched" so a crash (or concurrent
            // poll) between the SELECT and the UPDATE cannot cause the same
            // commands to be handed out twice.
            const rows = await dbTransaction(async (tx) => {
                const pending = await tx.dbAll(
                    `
                SELECT *
                FROM google_home_command_queue
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
                    UPDATE google_home_command_queue
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
        '/api/internal/devices/google-home/commands/cleanup',
        auth.requireDeviceAuth,
        asyncHandler(async (req, res) => {
            const device = req.device;
            const nowIso = new Date().toISOString();
            await dbRun(
                `
                UPDATE google_home_command_queue
                SET status = 'expired',
                    updated_at = ?
                WHERE device_id = ?
                  AND status IN ('pending', 'dispatched')
                  AND expires_at <= ?
            `,
                [nowIso, device.id, nowIso]
            );

            return res.status(200).json({ message: 'Command queue cleaned' });
        })
    );

    router.post('/api/internal/devices/google-home/commands/:id/result', auth.requireDeviceAuth, async (req, res) => {
        const commandId = utils.parsePositiveInt(req.params.id);
        if (!commandId) {
            return res.status(400).json({ error: 'Invalid command id' });
        }

        try {
            const device = req.device;
            const command = await dbGet(
                `
                    SELECT *
                    FROM google_home_command_queue
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
                    UPDATE google_home_command_queue
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
                    `SELECT state_json FROM google_home_entities WHERE user_id = ? AND device_id = ? AND entity_id = ? LIMIT 1`,
                    [command.user_id, command.device_id, command.entity_id]
                );
                const existingState = utils.parseJsonSafe(existingEntity?.state_json, {}) || {};
                const mergedState = { ...existingState, ...normalizedState };
                const stateJson = JSON.stringify(mergedState).slice(0, 8000);
                const stateHash = homegraph.computeGoogleStateHash({
                    online: true,
                    ...mergedState
                });
                const updateWithLastSeenSql = `
                    UPDATE google_home_entities
                    SET state_json = ?,
                        online = 1,
                        entity_last_seen_at = ?,
                        updated_at = ?
                    WHERE user_id = ?
                      AND device_id = ?
                      AND entity_id = ?
                `;

                const updateFallbackSql = `
                    UPDATE google_home_entities
                    SET state_json = ?,
                        online = 1,
                        updated_at = ?
                    WHERE user_id = ?
                      AND device_id = ?
                      AND entity_id = ?
                `;

                const updateWithLastSeenAndHashSql = `
                    UPDATE google_home_entities
                    SET state_json = ?,
                        online = 1,
                        entity_last_seen_at = ?,
                        state_hash = ?,
                        updated_at = ?
                    WHERE user_id = ?
                      AND device_id = ?
                      AND entity_id = ?
                `;

                const updateFallbackAndHashSql = `
                    UPDATE google_home_entities
                    SET state_json = ?,
                        online = 1,
                        state_hash = ?,
                        updated_at = ?
                    WHERE user_id = ?
                      AND device_id = ?
                      AND entity_id = ?
                `;

                try {
                    if (state.googleEntityLastSeenColumnSupported && state.googleStateHashColumnSupported) {
                        await dbRun(updateWithLastSeenAndHashSql, [
                            stateJson,
                            nowIso,
                            stateHash,
                            nowIso,
                            command.user_id,
                            device.id,
                            command.entity_id
                        ]);
                    } else if (state.googleEntityLastSeenColumnSupported && !state.googleStateHashColumnSupported) {
                        await dbRun(updateWithLastSeenSql, [
                            stateJson,
                            nowIso,
                            nowIso,
                            command.user_id,
                            device.id,
                            command.entity_id
                        ]);
                    } else if (!state.googleEntityLastSeenColumnSupported && state.googleStateHashColumnSupported) {
                        await dbRun(updateFallbackAndHashSql, [
                            stateJson,
                            stateHash,
                            nowIso,
                            command.user_id,
                            device.id,
                            command.entity_id
                        ]);
                    } else {
                        await dbRun(updateFallbackSql, [
                            stateJson,
                            nowIso,
                            command.user_id,
                            device.id,
                            command.entity_id
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
                            stateJson,
                            nowIso,
                            command.user_id,
                            device.id,
                            command.entity_id
                        ]);
                    } else {
                        throw error;
                    }
                }

                homegraph.scheduleGoogleReportStateForUser(command.user_id, { force: false });
            }

            return res.status(200).json({ message: 'Command result recorded' });
        } catch (error) {
            console.error('DEVICE GOOGLE COMMAND RESULT ERROR:', error);
            return res.status(500).json({ error: 'Unable to store command result' });
        }
    });

    return router;
};
