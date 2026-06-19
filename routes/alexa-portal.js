const express = require('express');

/**
 * Alexa portal APIs — the account-management surface, mirror of
 * routes/google-home-portal.js. All endpoints require a portal session.
 */
module.exports = function ({ dbGet, dbRun, utils, auth, core, eventGateway }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    const BULK_EXPOSE_BATCH_SIZE = 10;
    const BULK_EXPOSE_BATCH_DELAY_MS = 150;
    const BULK_EXPOSE_MAX_ITEMS = 200;

    router.post(
        '/api/account/alexa/enable',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            const enable = req.body?.enabled !== false;

            // Cancel any in-flight unlink-retry timer for this user: a fresh manual
            // unlink (or a re-enable) supersedes a pending background retry.
            if (eventGateway?.cancelAlexaUnlinkRetry) {
                eventGateway.cancelAlexaUnlinkRetry(req.portalUser.id);
            }

            if (!enable) {
                // Unlink ordering matters and is GATED. We must drop the device tiles
                // from Alexa (DeleteReport) BEFORE disabling the skill, because Amazon
                // rejects DeleteReports for a disabled skill ("no valid enablement") —
                // disabling first would orphan the tiles forever with no way to retry.
                // runGatedUnlinkOnce enforces this gate AND is single-flight: two
                // simultaneous Unlink clicks join ONE operation instead of racing
                // (a race let one click's token-wipe land under the other's in-flight
                // DeleteReport → orphaned tiles). It returns tiles_cleared:false when
                // the DeleteReport didn't land (Amazon's transient INTERNAL_SERVICE_
                // EXCEPTION), in which case we keep the link and retry in the background.
                const unlinkResult = await eventGateway.runGatedUnlinkOnce(req.portalUser.id, 'portal_unlink');

                if (!unlinkResult?.tiles_cleared) {
                    // DeleteReport did not land. The gate held: skill NOT disabled and
                    // tokens NOT wiped, so the orphaned tiles stay recoverable. Leave the
                    // link intact (alexa_linked stays 1) for a future retry; just pause it
                    // (enabled=0) so the dashboard reflects "paused". Tell the user.
                    console.warn('ALEXA UNLINK: DeleteReport failed; keeping link for retry, NOT disabling skill. user', req.portalUser.id);
                    await dbRun(`UPDATE users SET alexa_enabled = 0 WHERE id = ?`, [req.portalUser.id]);
                    // Schedule a background retry with backoff — Amazon's gateway flap is
                    // transient and the delete usually lands within seconds-to-minutes, so
                    // the tiles clear without the user re-clicking. On success the retry
                    // finishes the unlink (disable skill + cleanup). In-memory; lost on
                    // restart, in which case the manual Unlink button still works.
                    if (eventGateway?.scheduleAlexaUnlinkRetry) {
                        eventGateway.scheduleAlexaUnlinkRetry(req.portalUser.id, 0);
                    }
                    const pausedUser = await dbGet(`SELECT * FROM users WHERE id = ?`, [req.portalUser.id]);
                    // Preserve the session epoch — omitting it stamps the token epoch 0,
                    // which fails requirePortalUser's epoch check and logs the user out.
                    const pausedToken = auth.createPortalSessionToken(pausedUser.email, pausedUser.session_epoch);
                    auth.setPortalSessionCookie(res, pausedToken);
                    return res.status(200).json({
                        message: 'alexa_unlink_tiles_pending',
                        tiles_cleared: false,
                        data: auth.serializeUserWithPortalSession(pausedUser, pausedToken)
                    });
                }
                // tiles_cleared:true — runGatedUnlinkOnce already disabled the skill at
                // Amazon and wiped our Alexa tokens. Fall through to set alexa_enabled=0.
            }

            await dbRun(`UPDATE users SET alexa_enabled = ? WHERE id = ?`, [enable ? 1 : 0, req.portalUser.id]);

            const updatedUser = await dbGet(`SELECT * FROM users WHERE id = ?`, [req.portalUser.id]);
            // Preserve the session epoch — omitting it stamps the token epoch 0, which
            // fails requirePortalUser's epoch check and logs the user out on unlink.
            const portalSessionToken = auth.createPortalSessionToken(updatedUser.email, updatedUser.session_epoch);
            auth.setPortalSessionCookie(res, portalSessionToken);
            if (enable) {
                eventGateway.scheduleAlexaAddOrUpdateReportForUser(req.portalUser.id, 'alexa_enabled');
                eventGateway.scheduleAlexaChangeReportForUser(req.portalUser.id, { force: true });
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

            const entities = await core.getAlexaEndpointsForUser(req.portalUser.id, { includeDisabled: true });
            return res.status(200).json({
                entities: entities.map((entity) => ({
                    id: entity.id,
                    entity_id: entity.entity_id,
                    display_name: entity.display_name,
                    entity_type: entity.entity_type,
                    room_hint: entity.room_hint,
                    exposed: Boolean(entity.exposed),
                    online: Boolean(entity.online),
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
            const entity = await dbGet(`SELECT * FROM alexa_endpoints WHERE user_id = ? AND entity_id = ? LIMIT 1`, [
                req.portalUser.id,
                entityId
            ]);
            if (!entity) {
                return res.status(404).json({ error: 'Entity not found' });
            }

            await dbRun(`UPDATE alexa_endpoints SET exposed = ?, updated_at = ? WHERE id = ?`, [
                exposed ? 1 : 0,
                new Date().toISOString(),
                entity.id
            ]);

            if (exposed) {
                eventGateway.scheduleAlexaAddOrUpdateReportForUser(req.portalUser.id, 'entity_exposure_changed');
                eventGateway.scheduleAlexaChangeReportForUser(req.portalUser.id, { force: true });
            } else {
                // Hidden: AddOrUpdateReport is additive-only and won't remove the
                // endpoint from Alexa — a DeleteReport is required.
                eventGateway.scheduleAlexaDeleteReportForUser(req.portalUser.id, [entityId], 'entity_hidden');
            }

            return res.status(200).json({
                message: exposed ? 'Entity exposed to Alexa' : 'Entity hidden from Alexa'
            });
        })
    );

    // Bulk expose/hide — batched server-side so a room-wide fan-out doesn't
    // burst the rate limiter (mirror of the Google bulk endpoint).
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
                return res.status(400).json({ error: `Too many updates in one request (max ${BULK_EXPOSE_MAX_ITEMS})` });
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
                            `SELECT id FROM alexa_endpoints WHERE user_id = ? AND entity_id = ? LIMIT 1`,
                            [req.portalUser.id, entityId]
                        );
                        if (!entity) {
                            return { entity_id: entityId, ok: false, error: 'Entity not found' };
                        }
                        await dbRun(`UPDATE alexa_endpoints SET exposed = ?, updated_at = ? WHERE id = ?`, [
                            exposed ? 1 : 0,
                            new Date().toISOString(),
                            entity.id
                        ]);
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
                const hiddenIds = results.filter((r) => r.ok && r.exposed === false).map((r) => r.entity_id);
                const anyExposed = results.some((r) => r.ok && r.exposed === true);
                if (anyExposed) {
                    eventGateway.scheduleAlexaAddOrUpdateReportForUser(req.portalUser.id, 'entity_exposure_changed');
                }
                eventGateway.scheduleAlexaChangeReportForUser(req.portalUser.id, { force: true });
                if (hiddenIds.length > 0) {
                    eventGateway.scheduleAlexaDeleteReportForUser(req.portalUser.id, hiddenIds, 'entities_hidden');
                }
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
            return res.status(200).json({ has_pin: Boolean(req.portalUser.alexa_security_pin) });
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
