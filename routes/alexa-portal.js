const express = require('express');

// Portal-side settings endpoints for Alexa linking toggle, entity exposure,
// and security PIN management. Mirrors routes/google-home-portal.js.
// Entity exposure is shared with the Google Home integration — the
// `exposed` flag on google_home_entities gates both.

module.exports = function ({ dbGet, dbRun, utils, auth, googleCore, alexaCore, alexaEvents }) {
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

            await dbRun(
                `
                UPDATE users
                SET alexa_enabled = ?
                WHERE id = ?
                `,
                [enable ? 1 : 0, req.portalUser.id]
            );

            const updatedUser = await dbGet(`SELECT * FROM users WHERE id = ?`, [req.portalUser.id]);
            const portalSessionToken = auth.createPortalSessionToken(updatedUser.email);
            auth.setPortalSessionCookie(res, portalSessionToken);

            if (enable && alexaEvents) {
                try {
                    alexaEvents.scheduleAlexaDiscoveryUpdateForUser(req.portalUser.id, 'alexa_enabled');
                    alexaEvents.scheduleAlexaChangeReportForUser(req.portalUser.id, { force: true });
                } catch (scheduleErr) {
                    console.error('ALEXA ENABLE SCHEDULE ERROR:', scheduleErr);
                }
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

            const entities = await googleCore.getGoogleEntitiesForUser(req.portalUser.id, {
                includeDisabled: true
            });
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

            if (alexaEvents) {
                try {
                    alexaEvents.scheduleAlexaDiscoveryUpdateForUser(req.portalUser.id, 'entity_exposure_changed');
                    alexaEvents.scheduleAlexaChangeReportForUser(req.portalUser.id, { force: true });
                } catch (_scheduleErr) {
                    /* best effort */
                }
            }

            return res.status(200).json({
                message: exposed ? 'Entity exposed to Alexa' : 'Entity hidden from Alexa'
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
                if (alexaEvents) {
                    try {
                        alexaEvents.scheduleAlexaDiscoveryUpdateForUser(req.portalUser.id, 'security_pin_cleared');
                    } catch (_scheduleErr) {
                        /* best effort */
                    }
                }
                return res.status(200).json({ message: 'Security PIN cleared', has_pin: false });
            }

            if (!/^\d{4,8}$/.test(pin)) {
                return res.status(400).json({ error: 'PIN must be 4 to 8 digits' });
            }

            await dbRun(`UPDATE users SET alexa_security_pin = ? WHERE id = ?`, [pin, req.portalUser.id]);

            if (alexaEvents) {
                try {
                    alexaEvents.scheduleAlexaDiscoveryUpdateForUser(req.portalUser.id, 'security_pin_set');
                } catch (_scheduleErr) {
                    /* best effort */
                }
            }

            return res.status(200).json({ message: 'Security PIN saved', has_pin: true });
        })
    );

    return router;
};
