const express = require('express');

module.exports = function ({ dbGet, dbRun, utils, auth, alexaCore, alexaEventGateway }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.post(
        '/api/account/alexa/enable',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            const enable = req.body?.enabled !== false;

            if (!enable) {
                await alexaCore.cleanupAlexaAuthDataForUser(req.portalUser.id);
            }

            await dbRun(`UPDATE users SET alexa_enabled = ? WHERE id = ?`, [enable ? 1 : 0, req.portalUser.id]);

            const updatedUser = await dbGet(`SELECT * FROM users WHERE id = ?`, [req.portalUser.id]);
            const portalSessionToken = auth.createPortalSessionToken(updatedUser.email);
            auth.setPortalSessionCookie(res, portalSessionToken);
            if (enable) {
                alexaEventGateway.queueAlexaAddOrUpdateReport(req.portalUser.id, null, 'alexa_enabled');
            }
            return res.status(200).json({
                message: enable ? 'Alexa integration enabled' : 'Alexa integration disabled',
                data: auth.serializeUserWithPortalSession(updatedUser, portalSessionToken)
            });
        })
    );

    router.post(
        '/api/account/alexa/entities',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            if (!req.portalUser.alexa_enabled || !req.portalUser.alexa_linked) {
                return res.status(200).json({ entities: [] });
            }

            const entities = await alexaCore.getAlexaEntitiesForUser(req.portalUser.id, { includeDisabled: true });
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
        '/api/account/alexa/entities/:entityId/expose',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            const entityId = utils.sanitizeEntityId(req.params.entityId);
            if (!entityId) {
                return res.status(400).json({ error: 'Invalid entity id' });
            }

            if (!req.portalUser.alexa_enabled || !req.portalUser.alexa_linked) {
                return res.status(403).json({ error: 'Alexa integration is disabled for this account' });
            }

            const exposed = req.body?.exposed !== false;

            const entity = await dbGet(
                `SELECT * FROM alexa_entities WHERE user_id = ? AND entity_id = ? LIMIT 1`,
                [req.portalUser.id, entityId]
            );

            if (!entity) {
                return res.status(404).json({ error: 'Entity not found' });
            }

            await dbRun(
                `UPDATE alexa_entities SET exposed = ?, updated_at = ? WHERE id = ?`,
                [exposed ? 1 : 0, new Date().toISOString(), entity.id]
            );

            alexaEventGateway.queueAlexaAddOrUpdateReport(req.portalUser.id, entity.device_id, 'entity_exposure_changed');
            if (exposed) {
                alexaEventGateway.queueAlexaChangeReport(req.portalUser.id, entity.entity_id, 'entity_exposed');
            }

            return res.status(200).json({
                message: exposed ? 'Entity exposed to Alexa' : 'Entity hidden from Alexa'
            });
        })
    );

    const BULK_EXPOSE_BATCH_SIZE = 10;
    const BULK_EXPOSE_BATCH_DELAY_MS = 150;
    const BULK_EXPOSE_MAX_ITEMS = 200;

    router.post(
        '/api/account/alexa/entities/expose-bulk',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            if (!req.portalUser.alexa_enabled || !req.portalUser.alexa_linked) {
                return res.status(403).json({ error: 'Alexa integration is disabled for this account' });
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

                const batchResults = await Promise.all(
                    batch.map(async (update) => {
                        const entityId = utils.sanitizeEntityId(update?.entity_id);
                        if (!entityId) {
                            return { entity_id: update?.entity_id ?? null, ok: false, error: 'Invalid entity id' };
                        }
                        const exposed = update?.exposed !== false;

                        const entity = await dbGet(
                            `SELECT id FROM alexa_entities WHERE user_id = ? AND entity_id = ? LIMIT 1`,
                            [req.portalUser.id, entityId]
                        );

                        if (!entity) {
                            return { entity_id: entityId, ok: false, error: 'Entity not found' };
                        }

                        await dbRun(
                            `UPDATE alexa_entities SET exposed = ?, updated_at = ? WHERE id = ?`,
                            [exposed ? 1 : 0, new Date().toISOString(), entity.id]
                        );

                        return { entity_id: entityId, ok: true, exposed };
                    })
                );

                for (const r of batchResults) {
                    results.push(r);
                    if (r.ok) anySucceeded = true;
                }

                const hasMore = i + BULK_EXPOSE_BATCH_SIZE < updates.length;
                if (hasMore) {
                    await new Promise((resolve) => setTimeout(resolve, BULK_EXPOSE_BATCH_DELAY_MS));
                }
            }

            if (anySucceeded) {
                alexaEventGateway.queueAlexaAddOrUpdateReport(req.portalUser.id, null, 'entity_exposure_changed');
            }

            return res.status(200).json({
                processed: results.length,
                succeeded: results.filter((r) => r.ok).length,
                failed: results.filter((r) => !r.ok).length,
                results
            });
        })
    );

    router.get('/api/account/alexa/security-pin', auth.requirePortalUser, (req, res) => {
        try {
            const hasPin = Boolean(req.portalUser.alexa_security_pin);
            return res.status(200).json({ has_pin: hasPin });
        } catch (error) {
            console.error('ACCOUNT ALEXA SECURITY PIN GET ERROR:', error);
            return res.status(500).json({ error: 'Unable to check security PIN' });
        }
    });

    router.post(
        '/api/account/alexa/security-pin',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            const pin = utils.sanitizeString(req.body?.pin, 20);

            if (!pin) {
                await dbRun(`UPDATE users SET alexa_security_pin = NULL WHERE id = ?`, [req.portalUser.id]);
                return res.status(200).json({ message: 'Security PIN cleared', has_pin: false });
            }

            if (!/^\d{4,8}$/.test(pin)) {
                return res.status(400).json({ error: 'PIN must be 4 to 8 digits' });
            }

            await dbRun(`UPDATE users SET alexa_security_pin = ? WHERE id = ?`, [pin, req.portalUser.id]);
            return res.status(200).json({ message: 'Security PIN saved', has_pin: true });
        })
    );

    return router;
};
