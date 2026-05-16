/**
 * Portal-facing Alexa endpoints.
 *
 *   POST /api/account/alexa/enable           — toggle integration on/off
 *   GET  /api/account/alexa/status           — summary card payload
 *   POST /api/account/alexa/unlink           — revoke LWA + Alexa tokens
 *   GET  /api/account/alexa/security-pin     — PIN presence
 *   POST /api/account/alexa/security-pin     — set/clear PIN
 *
 * ─── Why no /entities endpoints (parity diff vs. google-home-portal) ──────
 *
 * Phase 8 puts entity ownership in the Home Assistant addon. The addon syncs
 * an authoritative entity list via /api/internal/devices/alexa/entities/sync
 * and Alexa Discovery just reflects that. Surfacing per-entity expose toggles
 * here would let the portal and the addon disagree about who's the source of
 * truth — exactly the situation that produced v1's "ghost entities" bug,
 * where a portal-hidden entity kept showing up in Alexa Discovery because the
 * addon kept resyncing it.
 */

const express = require('express');

module.exports = function ({ dbGet, dbRun, utils, auth, alexaCore }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    // ── enable / disable ─────────────────────────────────────────────────

    router.post(
        '/api/account/alexa/enable',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            const enable = req.body?.enabled !== false;

            // Disabling implies a full unlink — otherwise we'd hold orphaned
            // LWA refresh tokens that would silently keep working if the user
            // re-enabled. v1 leaked tokens this way for months.
            if (!enable) {
                await alexaCore.unlinkAlexaForUser(req.portalUser.id);
            }

            await dbRun(`UPDATE users SET alexa_enabled = ? WHERE id = ?`, [
                enable ? 1 : 0,
                req.portalUser.id
            ]);

            const updatedUser = await dbGet(`SELECT * FROM users WHERE id = ?`, [req.portalUser.id]);
            const portalSessionToken = auth.createPortalSessionToken(updatedUser.email);
            auth.setPortalSessionCookie(res, portalSessionToken);

            return res.status(200).json({
                message: enable ? 'Alexa integration enabled' : 'Alexa integration disabled',
                data: auth.serializeUserWithPortalSession(updatedUser, portalSessionToken)
            });
        })
    );

    // ── status card ──────────────────────────────────────────────────────

    router.get(
        '/api/account/alexa/status',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            const user = req.portalUser;

            // Aggregate counts come from alexa_entities; the addon may not
            // have synced anything yet, so a 0 is normal.
            const counts = await dbGet(
                `
                    SELECT
                        COUNT(*)                       AS total,
                        SUM(CASE WHEN exposed = 1 THEN 1 ELSE 0 END) AS exposed,
                        MAX(updated_at)                AS last_synced_at
                    FROM alexa_entities
                    WHERE user_id = ?
                `,
                [user.id]
            );

            return res.status(200).json({
                enabled: Boolean(user.alexa_enabled),
                linked: Boolean(user.alexa_linked),
                security_pin_set: Boolean(user.alexa_security_pin),
                last_synced_at: counts?.last_synced_at || null,
                total_entity_count: Number(counts?.total || 0),
                exposed_entity_count: Number(counts?.exposed || 0)
            });
        })
    );

    // ── unlink (idempotent) ──────────────────────────────────────────────

    router.post(
        '/api/account/alexa/unlink',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            // unlinkAlexaForUser blows away alexa_tokens AND flips
            // users.alexa_linked → 0. Idempotent: safe to call when already
            // unlinked. Leaves alexa_enabled untouched so the user keeps
            // their preference for "I want to use Alexa, just relink it."
            await alexaCore.unlinkAlexaForUser(req.portalUser.id);

            const updatedUser = await dbGet(`SELECT * FROM users WHERE id = ?`, [req.portalUser.id]);
            const portalSessionToken = auth.createPortalSessionToken(updatedUser.email);
            auth.setPortalSessionCookie(res, portalSessionToken);

            return res.status(200).json({
                message: 'Alexa account unlinked',
                data: auth.serializeUserWithPortalSession(updatedUser, portalSessionToken)
            });
        })
    );

    // ── security PIN ─────────────────────────────────────────────────────

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
                await dbRun(`UPDATE users SET alexa_security_pin = NULL WHERE id = ?`, [
                    req.portalUser.id
                ]);
                return res.status(200).json({ message: 'Security PIN cleared', has_pin: false });
            }

            if (!/^\d{4,8}$/.test(pin)) {
                return res.status(400).json({ error: 'PIN must be 4 to 8 digits' });
            }

            await dbRun(`UPDATE users SET alexa_security_pin = ? WHERE id = ?`, [
                pin,
                req.portalUser.id
            ]);
            return res.status(200).json({ message: 'Security PIN saved', has_pin: true });
        })
    );

    return router;
};
