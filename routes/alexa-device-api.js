/**
 * Alexa addon ↔ Cloud Connect internal API.
 *
 *   POST /api/internal/devices/alexa/entities/sync
 *     - addon pushes its full current entity list; we diff vs. the last
 *       snapshot, upsert new/changed rows in alexa_entities, and mark
 *       removed rows exposed=0.
 *
 *   GET  /api/internal/devices/alexa/commands/poll
 *     - addon polls for queued directives; we return any with status
 *       'pending', flip them to 'dispatched' atomically, and let the addon
 *       do the work.
 *
 *   POST /api/internal/devices/alexa/commands/:id/result
 *     - addon reports execution outcome; we flip the row to 'completed' or
 *       'failed'. The smart-home directive handler is busy-polling that
 *       row, so this unblocks the user-facing Alexa response within ~100ms.
 *
 * All three live under /api/internal — they bypass the general-API rate
 * limiter (see server.js: `skip: req.path.startsWith('/internal/')`) and
 * authenticate with the existing `auth.requireDeviceAuth` middleware that
 * the apex-cloud-link addon already uses for the Google flow.
 *
 * ─── Why the addon, not Cloud Connect, owns entity selection ───────────────
 *
 * v1 tried to keep an authoritative entity list server-side and let the
 * portal toggle individual entities on/off. Result: every HA restart on
 * the customer's side re-emitted slightly different entity_ids (HA's
 * entity_registry can rename things during boot) and the server's "last
 * known good" list silently rotted. Linking looked fine, ChangeReports
 * went out for entities the customer didn't actually have anymore.
 *
 * In v2, the addon is the source of truth: each sync REPLACES the exposed
 * set for that device. Per-entity portal toggles go away — if you don't
 * want it in Alexa, exclude it on the addon side. Simpler, harder to drift.
 *
 * ─── Sync diff semantics ──────────────────────────────────────────────────
 *
 * The diff is computed against the most recent alexa_sync_snapshots row for
 * (user_id, device_id):
 *
 *   added   : in payload, not in snapshot   → INSERT
 *   updated : in both, state_hash differs   → UPDATE state_json + state_hash
 *   removed : in snapshot, not in payload   → UPDATE alexa_entities SET exposed = 0
 *
 * Removed rows are NOT deleted. We need them around so that any in-flight
 * commands targeting them can resolve cleanly (queue rows reference
 * entity_id by string, not FK). They become invisible to Discovery via
 * the exposed=0 flag.
 *
 * After the diff we replace the snapshot with the new entity_id list. The
 * snapshot is just JSON — small, gets rewritten every sync, no historical
 * value beyond the next diff.
 */

const express = require('express');
const crypto = require('node:crypto');

function hashEntityState(stateJson) {
    // Stable hash over the serialized state. The addon sends already-
    // canonicalized JSON (sorted keys etc.) so a string hash is enough —
    // we don't need to re-parse and re-canonicalize here.
    return crypto.createHash('sha256').update(stateJson || '').digest('hex');
}

function asValidEntityId(s) {
    // Keep this aligned with entity-mapping.js's encodeEndpointId() input
    // contract — anything that wouldn't survive endpoint encoding gets
    // rejected here so the addon sees the error, not Alexa.
    return typeof s === 'string' && /^[a-z][a-z0-9_]*\.[a-z0-9_]+$/.test(s);
}

module.exports = function createAlexaDeviceApiRoute({ dbGet, dbRun, dbAll, auth, alexaCore, utils, eventGateway }) {
    const router = express.Router();
    const { asyncHandler, sanitizeString } = utils;

    // ── POST /entities/sync ─────────────────────────────────────────────

    router.post(
        '/api/internal/devices/alexa/entities/sync',
        auth.requireDeviceAuth,
        asyncHandler(async (req, res) => {
            const device = req.device;
            const userId = device.user_id;
            const deviceId = device.id;

            const entities = Array.isArray(req.body?.entities) ? req.body.entities : null;
            if (!entities) {
                return res.status(400).json({ error: 'invalid_payload', detail: '`entities` array required' });
            }

            // Normalize + validate. Anything malformed is reported back so
            // the addon can log and skip — we do NOT silently drop these,
            // they were a debugging nightmare in v1.
            const normalized = [];
            const skipped = [];
            for (const raw of entities) {
                const entityId = sanitizeString(raw?.entity_id, 255);
                const displayName = sanitizeString(raw?.display_name, 255);
                const entityType = sanitizeString(raw?.entity_type, 64);
                if (!asValidEntityId(entityId)) {
                    skipped.push({ entity_id: raw?.entity_id || null, reason: 'invalid_entity_id' });
                    continue;
                }
                if (!displayName) {
                    skipped.push({ entity_id: entityId, reason: 'missing_display_name' });
                    continue;
                }
                if (!entityType) {
                    skipped.push({ entity_id: entityId, reason: 'missing_entity_type' });
                    continue;
                }
                // state may be null/undefined for stateless entities (scenes,
                // scripts in Phase 10). For now we always serialize it.
                const stateJson = raw?.state !== undefined && raw?.state !== null
                    ? JSON.stringify(raw.state)
                    : null;
                normalized.push({
                    entity_id: entityId,
                    display_name: displayName,
                    entity_type: entityType,
                    room_hint: sanitizeString(raw?.room_hint, 255) || null,
                    online: raw?.online === false ? 0 : 1,
                    state_json: stateJson,
                    state_hash: stateJson ? hashEntityState(stateJson) : null
                });
            }

            // Load previous snapshot. First-time sync gets an empty set,
            // so every normalized entity counts as "added".
            const snapRow = await dbGet(
                `SELECT snapshot_entity_ids_json FROM alexa_sync_snapshots WHERE user_id = ? AND device_id = ?`,
                [userId, deviceId]
            );
            let prevIds = new Set();
            if (snapRow?.snapshot_entity_ids_json) {
                try {
                    const parsed = JSON.parse(snapRow.snapshot_entity_ids_json);
                    if (Array.isArray(parsed)) prevIds = new Set(parsed);
                } catch (_e) {
                    // Corrupt snapshot is treated as "no snapshot" — every
                    // entity becomes an add. Slightly noisy but harmless.
                }
            }

            const seenIds = new Set(normalized.map((n) => n.entity_id));
            const removedIds = [...prevIds].filter((id) => !seenIds.has(id));

            const nowIso = new Date().toISOString();
            let added = 0;
            let updated = 0;

            for (const n of normalized) {
                // UPSERT keyed on (user_id, entity_id) — the UNIQUE we have.
                // We track add vs. update by checking existence first; one
                // extra dbGet per entity is fine for the sync cadence
                // (typically ≤ once per minute, ≤ a few hundred entities).
                const existing = await dbGet(
                    `SELECT id, state_hash FROM alexa_entities WHERE user_id = ? AND entity_id = ?`,
                    [userId, n.entity_id]
                );
                if (!existing) {
                    await dbRun(
                        `INSERT INTO alexa_entities
                            (user_id, device_id, entity_id, display_name, entity_type, room_hint,
                             exposed, online, state_json, state_hash, created_at, updated_at)
                         VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`,
                        [
                            userId,
                            deviceId,
                            n.entity_id,
                            n.display_name,
                            n.entity_type,
                            n.room_hint,
                            n.online,
                            n.state_json,
                            n.state_hash,
                            nowIso,
                            nowIso
                        ]
                    );
                    added++;
                } else if (existing.state_hash !== n.state_hash) {
                    // Existing entity, state changed. Re-expose if previously
                    // hidden (the customer un-excluded it on the addon side).
                    await dbRun(
                        `UPDATE alexa_entities SET
                            display_name = ?, entity_type = ?, room_hint = ?,
                            exposed = 1, online = ?, state_json = ?, state_hash = ?,
                            updated_at = ?
                         WHERE id = ?`,
                        [
                            n.display_name,
                            n.entity_type,
                            n.room_hint,
                            n.online,
                            n.state_json,
                            n.state_hash,
                            nowIso,
                            existing.id
                        ]
                    );
                    updated++;
                    // Proactive ChangeReport. Only on a real state-hash
                    // delta — we'd otherwise spam the gateway every sync.
                    // Optional dep: tests + early bring-up don't pass it.
                    if (eventGateway && typeof eventGateway.scheduleChangeReportForEntity === 'function') {
                        // Re-fetch the row so the gateway sees the new state_json,
                        // not the pre-update version.
                        const fresh = await dbGet(
                            `SELECT * FROM alexa_entities WHERE id = ?`,
                            [existing.id]
                        );
                        if (fresh) {
                            eventGateway.scheduleChangeReportForEntity(fresh, {
                                cause: 'PHYSICAL_INTERACTION'
                            });
                        }
                    }
                } else {
                    // Existing entity, state unchanged — still ensure
                    // exposed=1 + online flag in case those drifted.
                    await dbRun(
                        `UPDATE alexa_entities SET exposed = 1, online = ?, updated_at = ? WHERE id = ?`,
                        [n.online, nowIso, existing.id]
                    );
                }
            }

            // Mark removed entities as hidden (do NOT delete — see header).
            for (const id of removedIds) {
                await dbRun(
                    `UPDATE alexa_entities SET exposed = 0, updated_at = ? WHERE user_id = ? AND entity_id = ?`,
                    [nowIso, userId, id]
                );
            }

            // Replace the snapshot with the new entity_id list.
            const snapshotJson = JSON.stringify([...seenIds]);
            if (snapRow) {
                await dbRun(
                    `UPDATE alexa_sync_snapshots SET snapshot_entity_ids_json = ?, updated_at = ?
                     WHERE user_id = ? AND device_id = ?`,
                    [snapshotJson, nowIso, userId, deviceId]
                );
            } else {
                await dbRun(
                    `INSERT INTO alexa_sync_snapshots (user_id, device_id, snapshot_entity_ids_json, updated_at)
                     VALUES (?, ?, ?, ?)`,
                    [userId, deviceId, snapshotJson, nowIso]
                );
            }

            return res.json({
                ok: true,
                added,
                updated,
                removed: removedIds.length,
                skipped
            });
        })
    );

    // ── GET /commands/poll ─────────────────────────────────────────────

    router.get(
        '/api/internal/devices/alexa/commands/poll',
        auth.requireDeviceAuth,
        asyncHandler(async (req, res) => {
            const device = req.device;
            const nowIso = new Date().toISOString();
            const limitRaw = parseInt(req.query?.limit, 10);
            const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(50, limitRaw)) : 10;

            // First, expire anything past its TTL so we don't hand stale
            // commands to the addon. Cheap because of the
            // idx_alexa_command_queue_device_status_expiry index.
            await dbRun(
                `UPDATE alexa_command_queue
                 SET status = 'expired', updated_at = ?
                 WHERE device_id = ? AND status IN ('pending','dispatched') AND expires_at < ?`,
                [nowIso, device.id, nowIso]
            );

            // Then claim up to `limit` pending rows. We use a two-step
            // (SELECT ids → UPDATE WHERE id IN ids) because SQLite doesn't
            // support `UPDATE ... LIMIT` without a build flag, and we need
            // the IDs to return to the addon anyway.
            const candidates = await dbAll(
                `SELECT id, entity_id, action, payload_json
                 FROM alexa_command_queue
                 WHERE device_id = ? AND status = 'pending'
                 ORDER BY id ASC
                 LIMIT ?`,
                [device.id, limit]
            );

            if (candidates.length === 0) {
                return res.json({ pending: [] });
            }

            const ids = candidates.map((c) => c.id);
            // Inline the IDs (they're integers from our own SELECT — safe)
            // because sqlite3's variadic placeholder for IN is awkward.
            const placeholders = ids.map(() => '?').join(',');
            await dbRun(
                `UPDATE alexa_command_queue SET status = 'dispatched', updated_at = ?
                 WHERE id IN (${placeholders}) AND status = 'pending'`,
                [nowIso, ...ids]
            );

            const pending = candidates.map((c) => ({
                id: c.id,
                entity_id: c.entity_id,
                action: c.action,
                payload: c.payload_json ? JSON.parse(c.payload_json) : {}
            }));

            return res.json({ pending });
        })
    );

    // ── POST /commands/:id/result ──────────────────────────────────────

    router.post(
        '/api/internal/devices/alexa/commands/:id/result',
        auth.requireDeviceAuth,
        asyncHandler(async (req, res) => {
            const device = req.device;
            const commandId = parseInt(req.params.id, 10);
            if (!Number.isFinite(commandId) || commandId <= 0) {
                return res.status(400).json({ error: 'invalid_command_id' });
            }

            const success = req.body?.success === true;
            const errorMsg = sanitizeString(req.body?.error, 1024) || null;

            // Scope by device_id so a compromised addon can't acknowledge
            // commands for other customers' devices.
            const row = await dbGet(
                `SELECT id, status FROM alexa_command_queue WHERE id = ? AND device_id = ?`,
                [commandId, device.id]
            );
            if (!row) {
                return res.status(404).json({ error: 'unknown_command' });
            }

            // Only act on commands the addon has actually been handed. If
            // the smart-home route already gave up and marked it 'expired',
            // accept the late ack quietly so we don't accumulate retries.
            if (row.status !== 'dispatched' && row.status !== 'pending') {
                return res.json({ ok: true, no_op: true, prior_status: row.status });
            }

            const newStatus = success ? 'completed' : 'failed';
            const resultJson = success ? 'ok' : errorMsg || 'unknown_failure';

            await dbRun(
                `UPDATE alexa_command_queue
                 SET status = ?, result_json = ?, updated_at = ?
                 WHERE id = ?`,
                [newStatus, resultJson, new Date().toISOString(), commandId]
            );
            return res.json({ ok: true });
        })
    );

    // alexaCore is unused right now but accepting it keeps the deps shape
    // identical to the smart-home route, which simplifies bootstrap.
    void alexaCore;

    return router;
};

module.exports._test = { hashEntityState, asValidEntityId };
