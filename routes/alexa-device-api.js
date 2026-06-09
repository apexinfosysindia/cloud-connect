const express = require('express');

/**
 * Alexa device-side API — the on-device bridge pushes endpoints + polls for
 * commands here. Mirror of routes/google-home-device-api.js, simplified
 * because migration 003 guarantees the full schema (no column fallbacks).
 *
 *   POST /api/internal/devices/alexa/endpoints           upsert + snapshot prune
 *   POST /api/internal/devices/alexa/commands            atomic poll
 *   POST /api/internal/devices/alexa/commands/:id/result record result + state
 */
module.exports = function ({ dbGet, dbRun, dbAll, dbTransaction, utils, auth, core, eventGateway }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.post(
        '/api/internal/devices/alexa/endpoints',
        auth.requireDeviceAuth,
        asyncHandler(async (req, res) => {
            const device = req.device;
            const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [device.user_id]);
            const nowIso = new Date().toISOString();

            if (!user || !user.alexa_enabled) {
                await dbRun(`UPDATE alexa_endpoints SET online = 0, updated_at = ? WHERE user_id = ? AND device_id = ?`, [
                    nowIso,
                    device.user_id,
                    device.id
                ]);
                // Do NOT write a snapshot row here. alexa_enabled=0 only happens
                // via cleanupAlexaAuthDataForUser (portal unlink / Amazon revoke),
                // which deletes alexa_sync_snapshots for a clean slate. A device
                // inventory push lands within seconds of unlink; writing an empty
                // snapshot here would resurrect the row and defeat the clean slate.
                // There is nothing to snapshot while unlinked, so skip the write.
                return res.status(200).json({ message: 'Alexa integration is disabled for this account', synced_count: 0, synced_entities: [] });
            }

            const entitiesPayload = Array.isArray(req.body?.entities) ? req.body.entities : [];
            const fullSnapshot = req.body?.full_snapshot !== false;
            const snapshotEntityIds = Array.isArray(req.body?.snapshot_entity_ids) ? req.body.snapshot_entity_ids : null;

            if (entitiesPayload.length === 0) {
                if (fullSnapshot && snapshotEntityIds) {
                    const normalizedSnapshotIds = Array.from(
                        new Set(snapshotEntityIds.map((i) => utils.sanitizeEntityId(i)).filter(Boolean))
                    );
                    if (normalizedSnapshotIds.length > 0) {
                        const placeholders = normalizedSnapshotIds.map(() => '?').join(',');
                        await dbRun(
                            `UPDATE alexa_endpoints SET online = 0, entity_last_seen_at = ?, updated_at = ?
                             WHERE user_id = ? AND device_id = ? AND entity_id NOT IN (${placeholders})`,
                            [nowIso, nowIso, device.user_id, device.id, ...normalizedSnapshotIds]
                        );
                    } else {
                        await dbRun(
                            `UPDATE alexa_endpoints SET online = 0, entity_last_seen_at = ?, updated_at = ? WHERE user_id = ? AND device_id = ?`,
                            [nowIso, nowIso, device.user_id, device.id]
                        );
                    }
                    await core.saveAlexaDeviceSnapshotEntityIds(device.user_id, device.id, normalizedSnapshotIds);
                    eventGateway.scheduleAlexaAddOrUpdateReportForUser(device.user_id, 'inventory_snapshot_commit');
                    eventGateway.scheduleAlexaChangeReportForUser(device.user_id, { force: false });
                    return res.status(200).json({ message: 'Snapshot inventory committed', synced_count: 0, synced_entities: [] });
                }
                return res.status(200).json({ message: 'No entities received, inventory update skipped', synced_count: 0, synced_entities: [] });
            }

            const synced = [];
            const incomingEntityIds = [];
            let shouldReport = false;

            for (const entityPayload of entitiesPayload) {
                const normalizedEntityId = utils.sanitizeEntityId(entityPayload?.entity_id);
                if (normalizedEntityId) incomingEntityIds.push(normalizedEntityId);
                const upserted = await core.upsertAlexaEndpointFromDevice(device.user_id, device.id, entityPayload);
                if (upserted?.endpoint) {
                    synced.push(upserted.endpoint.entity_id);
                    if (upserted.syncChanged) shouldReport = true;
                }
            }

            const uniqueIncoming = Array.from(new Set(incomingEntityIds));
            if (uniqueIncoming.length === 0) {
                return res.status(200).json({ message: 'No valid entities in payload, inventory update skipped', synced_count: synced.length, synced_entities: synced });
            }

            const beforeRows = await dbAll(`SELECT entity_id FROM alexa_endpoints WHERE user_id = ? AND device_id = ? AND online = 1`, [device.user_id, device.id]);
            const beforeSet = new Set((beforeRows || []).map((r) => utils.sanitizeEntityId(r.entity_id)).filter(Boolean));

            if (fullSnapshot) {
                const baselineIds = snapshotEntityIds
                    ? Array.from(new Set(snapshotEntityIds.map((i) => utils.sanitizeEntityId(i)).filter(Boolean)))
                    : await core.getAlexaDeviceSnapshotEntityIds(device.user_id, device.id);
                const snapshotIdsSet = new Set(baselineIds);
                for (const id of uniqueIncoming) snapshotIdsSet.add(id);
                const effectiveSnapshotIds = Array.from(snapshotIdsSet);
                const placeholders = effectiveSnapshotIds.map(() => '?').join(',');
                await dbRun(
                    `UPDATE alexa_endpoints SET online = 0, entity_last_seen_at = ?, updated_at = ?
                     WHERE user_id = ? AND device_id = ? AND entity_id NOT IN (${placeholders})`,
                    [nowIso, nowIso, device.user_id, device.id, ...effectiveSnapshotIds]
                );
                await core.saveAlexaDeviceSnapshotEntityIds(device.user_id, device.id, effectiveSnapshotIds);
            }

            const afterRows = await dbAll(`SELECT entity_id FROM alexa_endpoints WHERE user_id = ? AND device_id = ? AND online = 1`, [device.user_id, device.id]);
            const afterSet = new Set((afterRows || []).map((r) => utils.sanitizeEntityId(r.entity_id)).filter(Boolean));
            if (!shouldReport && beforeSet.size !== afterSet.size) shouldReport = true;
            if (!shouldReport) {
                for (const id of beforeSet) {
                    if (!afterSet.has(id)) { shouldReport = true; break; }
                }
            }

            if (shouldReport) {
                eventGateway.scheduleAlexaAddOrUpdateReportForUser(device.user_id, 'inventory_changed');
            }
            eventGateway.scheduleAlexaChangeReportForUser(device.user_id, { force: false });

            return res.status(200).json({ message: 'Endpoints synced', synced_count: synced.length, synced_entities: synced });
        })
    );

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
                `UPDATE alexa_command_queue SET status = 'expired', updated_at = ?
                 WHERE device_id = ? AND status IN ('pending','dispatched') AND expires_at <= ?`,
                [nowIso, device.id, nowIso]
            );

            const rows = await dbTransaction(async (tx) => {
                const pending = await tx.dbAll(
                    `SELECT * FROM alexa_command_queue WHERE device_id = ? AND status = 'pending' AND expires_at > ? ORDER BY id ASC LIMIT 20`,
                    [device.id, nowIso]
                );
                const ids = (pending || []).map((r) => r.id);
                if (ids.length > 0) {
                    const placeholders = ids.map(() => '?').join(',');
                    await tx.dbRun(`UPDATE alexa_command_queue SET status = 'dispatched', updated_at = ? WHERE id IN (${placeholders})`, [nowIso, ...ids]);
                }
                return pending;
            });

            return res.status(200).json({
                commands: (rows || []).map((r) => ({
                    id: r.id,
                    entity_id: r.entity_id,
                    action: r.action,
                    payload: utils.parseJsonSafe(r.payload_json, {})
                }))
            });
        })
    );

    router.post(
        '/api/internal/devices/alexa/commands/:id/result',
        auth.requireDeviceAuth,
        asyncHandler(async (req, res) => {
            const commandId = utils.parsePositiveInt(req.params.id);
            if (!commandId) {
                return res.status(400).json({ error: 'Invalid command id' });
            }
            const device = req.device;
            const command = await dbGet(`SELECT * FROM alexa_command_queue WHERE id = ? AND device_id = ? LIMIT 1`, [commandId, device.id]);
            if (!command) {
                return res.status(404).json({ error: 'Command not found' });
            }

            const success = req.body?.success !== false;
            const errorMessage = utils.sanitizeString(req.body?.error, 240);
            const nowIso = new Date().toISOString();
            await dbRun(
                `UPDATE alexa_command_queue SET status = ?, result_json = ?, updated_at = ? WHERE id = ?`,
                [
                    success ? 'completed' : 'failed',
                    JSON.stringify({ success, error: errorMessage || null, state: req.body?.state || null }).slice(0, 2500),
                    nowIso,
                    command.id
                ]
            );

            if (success && req.body?.state) {
                const normalizedState = req.body.state || {};
                const existing = await dbGet(
                    `SELECT state_json FROM alexa_endpoints WHERE user_id = ? AND device_id = ? AND entity_id = ? LIMIT 1`,
                    [command.user_id, command.device_id, command.entity_id]
                );
                const existingState = utils.parseJsonSafe(existing?.state_json, {}) || {};
                const mergedState = { ...existingState, ...normalizedState };
                const stateJson = JSON.stringify(mergedState).slice(0, 8000);
                const stateHash = core.computeAlexaStateHash({ online: true, ...mergedState });
                await dbRun(
                    `UPDATE alexa_endpoints SET state_json = ?, online = 1, entity_last_seen_at = ?, state_hash = ?, updated_at = ?
                     WHERE user_id = ? AND device_id = ? AND entity_id = ?`,
                    [stateJson, nowIso, stateHash, nowIso, command.user_id, device.id, command.entity_id]
                );
                eventGateway.scheduleAlexaChangeReportForUser(command.user_id, { force: false });
            }

            return res.status(200).json({ message: 'Command result recorded' });
        })
    );

    return router;
};
