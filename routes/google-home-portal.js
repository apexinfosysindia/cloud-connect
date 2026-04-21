const express = require('express');

module.exports = function ({ dbGet, dbRun, utils, auth, googleCore, homegraph }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.post(
        '/api/account/google-home/enable',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            const enable = req.body?.enabled !== false;

            if (!enable) {
                await googleCore.cleanupGoogleAuthDataForUser(req.portalUser.id);
            }

            await dbRun(
                `
                UPDATE users
                SET google_home_enabled = ?
                WHERE id = ?
            `,
                [enable ? 1 : 0, req.portalUser.id]
            );

            const updatedUser = await dbGet(`SELECT * FROM users WHERE id = ?`, [req.portalUser.id]);
            const portalSessionToken = auth.createPortalSessionToken(updatedUser.email);
            auth.setPortalSessionCookie(res, portalSessionToken);
            if (enable) {
                homegraph.scheduleGoogleRequestSyncForUser(req.portalUser.id, 'google_home_enabled');
                homegraph.scheduleGoogleReportStateForUser(req.portalUser.id, { force: true });
            }
            return res.status(200).json({
                message: enable ? 'Google Home integration enabled' : 'Google Home integration disabled',
                data: auth.serializeUserWithPortalSession(updatedUser, portalSessionToken)
            });
        })
    );

    router.post(
        '/api/account/google-home/entities',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            if (!req.portalUser.google_home_enabled || !req.portalUser.google_home_linked) {
                return res.status(200).json({ entities: [] });
            }

            const entities = await googleCore.getGoogleEntitiesForUser(req.portalUser.id, { includeDisabled: true });
            return res.status(200).json({
                entities: entities.map((entity) => ({
                    id: entity.id,
                    entity_id: entity.entity_id,
                    display_name: entity.display_name,
                    entity_type: entity.entity_type,
                    room_hint: entity.room_hint,
                    exposed: Boolean(entity.exposed),
                    online: Boolean(entity.online),
                    device_online: Boolean(entity.device_online),
                    entity_fresh: Boolean(entity.entity_fresh),
                    state: utils.parseJsonSafe(entity.state_json, {}),
                    device_id: entity.device_id,
                    updated_at: entity.updated_at
                }))
            });
        })
    );

    router.post(
        '/api/account/google-home/entities/:entityId/expose',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            const entityId = utils.sanitizeEntityId(req.params.entityId);
            if (!entityId) {
                return res.status(400).json({ error: 'Invalid entity id' });
            }

            if (!req.portalUser.google_home_enabled || !req.portalUser.google_home_linked) {
                return res.status(403).json({ error: 'Google Home integration is disabled for this account' });
            }

            const exposed = req.body?.exposed !== false;

            const entity = await dbGet(
                `
                SELECT *
                FROM google_home_entities
                WHERE user_id = ? AND entity_id = ?
                LIMIT 1
            `,
                [req.portalUser.id, entityId]
            );

            if (!entity) {
                return res.status(404).json({ error: 'Entity not found' });
            }

            await dbRun(
                `
                UPDATE google_home_entities
                SET exposed = ?,
                    updated_at = ?
                WHERE id = ?
            `,
                [exposed ? 1 : 0, new Date().toISOString(), entity.id]
            );

            homegraph.scheduleGoogleRequestSyncForUser(req.portalUser.id, 'entity_exposure_changed');
            homegraph.scheduleGoogleReportStateForUser(req.portalUser.id, { force: true });

            return res.status(200).json({
                message: exposed ? 'Entity exposed to Google Home' : 'Entity hidden from Google Home'
            });
        })
    );

    // Bulk expose/hide endpoint. Dashboard fan-out operations (e.g. "expose all
    // lights in this room") previously hit the per-minute rate limit by issuing
    // one request per entity. This endpoint accepts an array of updates and
    // processes them server-side in batches of 10 with a 150ms delay between
    // batches so any downstream work (DB writes, homegraph scheduling) is
    // paced rather than bursted. The two homegraph schedule calls are issued
    // once at the end of the request rather than per-entity.
    const BULK_EXPOSE_BATCH_SIZE = 10;
    const BULK_EXPOSE_BATCH_DELAY_MS = 150;
    const BULK_EXPOSE_MAX_ITEMS = 200;

    router.post(
        '/api/account/google-home/entities/expose-bulk',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            if (!req.portalUser.google_home_enabled || !req.portalUser.google_home_linked) {
                return res.status(403).json({ error: 'Google Home integration is disabled for this account' });
            }

            const updates = Array.isArray(req.body?.updates) ? req.body.updates : null;
            if (!updates || updates.length === 0) {
                return res.status(400).json({ error: 'Body must include a non-empty "updates" array' });
            }
            if (updates.length > BULK_EXPOSE_MAX_ITEMS) {
                return res.status(400).json({
                    error: `Too many updates in one request (max ${BULK_EXPOSE_MAX_ITEMS})`
                });
            }

            const results = [];
            let anySucceeded = false;

            for (let i = 0; i < updates.length; i += BULK_EXPOSE_BATCH_SIZE) {
                const batch = updates.slice(i, i + BULK_EXPOSE_BATCH_SIZE);

                // Process the batch concurrently. Each item resolves to a
                // per-entity result so one bad entity id doesn't fail the batch.
                const batchResults = await Promise.all(
                    batch.map(async (update) => {
                        const entityId = utils.sanitizeEntityId(update?.entity_id);
                        if (!entityId) {
                            return { entity_id: update?.entity_id ?? null, ok: false, error: 'Invalid entity id' };
                        }
                        const exposed = update?.exposed !== false;

                        const entity = await dbGet(
                            `
                            SELECT id
                            FROM google_home_entities
                            WHERE user_id = ? AND entity_id = ?
                            LIMIT 1
                        `,
                            [req.portalUser.id, entityId]
                        );

                        if (!entity) {
                            return { entity_id: entityId, ok: false, error: 'Entity not found' };
                        }

                        await dbRun(
                            `
                            UPDATE google_home_entities
                            SET exposed = ?,
                                updated_at = ?
                            WHERE id = ?
                        `,
                            [exposed ? 1 : 0, new Date().toISOString(), entity.id]
                        );

                        return { entity_id: entityId, ok: true, exposed };
                    })
                );

                for (const r of batchResults) {
                    results.push(r);
                    if (r.ok) anySucceeded = true;
                }

                // Pace subsequent batches. Skip the delay after the final batch
                // so the response isn't padded with 150ms of dead time.
                const hasMore = i + BULK_EXPOSE_BATCH_SIZE < updates.length;
                if (hasMore) {
                    await new Promise((resolve) => setTimeout(resolve, BULK_EXPOSE_BATCH_DELAY_MS));
                }
            }

            // Schedule homegraph work once for the whole batch rather than
            // per-entity. These schedulers are designed to coalesce, so this
            // is both cheaper and more correct than N individual calls.
            if (anySucceeded) {
                homegraph.scheduleGoogleRequestSyncForUser(req.portalUser.id, 'entity_exposure_changed');
                homegraph.scheduleGoogleReportStateForUser(req.portalUser.id, { force: true });
            }

            return res.status(200).json({
                processed: results.length,
                succeeded: results.filter((r) => r.ok).length,
                failed: results.filter((r) => !r.ok).length,
                results
            });
        })
    );


    router.get('/api/account/google-home/security-pin', auth.requirePortalUser, (req, res) => {
        try {
            const hasPin = Boolean(req.portalUser.google_home_security_pin);
            return res.status(200).json({ has_pin: hasPin });
        } catch (error) {
            console.error('ACCOUNT GOOGLE HOME SECURITY PIN GET ERROR:', error);
            return res.status(500).json({ error: 'Unable to check security PIN' });
        }
    });

    router.post(
        '/api/account/google-home/security-pin',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            const pin = utils.sanitizeString(req.body?.pin, 20);

            if (!pin) {
                await dbRun(`UPDATE users SET google_home_security_pin = NULL WHERE id = ?`, [req.portalUser.id]);
                homegraph.scheduleGoogleRequestSyncForUser(req.portalUser.id, 'security_pin_cleared');
                return res.status(200).json({ message: 'Security PIN cleared', has_pin: false });
            }

            if (!/^\d{4,8}$/.test(pin)) {
                return res.status(400).json({ error: 'PIN must be 4 to 8 digits' });
            }

            await dbRun(`UPDATE users SET google_home_security_pin = ? WHERE id = ?`, [pin, req.portalUser.id]);

            homegraph.scheduleGoogleRequestSyncForUser(req.portalUser.id, 'security_pin_set');
            return res.status(200).json({ message: 'Security PIN saved', has_pin: true });
        })
    );

    return router;
};
