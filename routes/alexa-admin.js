const express = require('express');

module.exports = function ({ dbGet, dbAll, config, utils, auth, alexaCore, alexaEventGateway, alexaState }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    function requireAlexaDebugAdmin(req, res, next) {
        if (!config.ALEXA_DEBUG_ENDPOINTS_ENABLED) {
            return res.status(404).json({ error: 'not_found' });
        }
        const authHeader = req.get('authorization') || '';
        const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
        const adminToken =
            utils.sanitizeString(config.ALEXA_DEBUG_ADMIN_TOKEN || process.env.GOOGLE_HOMEGRAPH_ADMIN_TOKEN || '', 512) || '';

        if (!adminToken) {
            return res.status(503).json({ error: 'alexa_debug_admin_token_not_configured' });
        }
        if (!bearerToken || bearerToken !== adminToken) {
            return res.status(401).json({ error: 'invalid_admin_token' });
        }
        return next();
    }

    router.post(
        '/api/internal/alexa/change-report',
        requireAlexaDebugAdmin,
        asyncHandler(async (req, res) => {
            const userId = utils.parsePositiveInt(req.body?.user_id);
            const entityId = utils.sanitizeEntityId(req.body?.entity_id);
            if (!userId || !entityId) {
                return res.status(400).json({ error: 'user_id and entity_id are required' });
            }

            const user = await dbGet(
                `SELECT id, alexa_enabled, alexa_linked FROM users WHERE id = ?`,
                [userId]
            );
            if (!user || !user.alexa_enabled || !user.alexa_linked) {
                return res.status(404).json({ error: 'eligible_alexa_user_not_found' });
            }

            const result = await alexaEventGateway.sendAlexaChangeReport(userId, entityId);
            return res.status(result?.ok ? 200 : 502).json({
                message: result?.ok ? 'change_report_sent' : result?.skipped ? 'change_report_skipped' : 'change_report_failed',
                details: result
            });
        })
    );

    router.post(
        '/api/internal/alexa/add-or-update-report',
        requireAlexaDebugAdmin,
        asyncHandler(async (req, res) => {
            const userId = utils.parsePositiveInt(req.body?.user_id);
            if (!userId) {
                return res.status(400).json({ error: 'user_id is required' });
            }

            const user = await dbGet(
                `SELECT id, alexa_enabled, alexa_linked FROM users WHERE id = ?`,
                [userId]
            );
            if (!user || !user.alexa_enabled || !user.alexa_linked) {
                return res.status(404).json({ error: 'eligible_alexa_user_not_found' });
            }

            const result = await alexaEventGateway.sendAlexaAddOrUpdateReport(userId);
            return res.status(result?.ok ? 200 : 502).json({
                message: result?.ok
                    ? 'add_or_update_report_sent'
                    : result?.skipped
                    ? 'add_or_update_report_skipped'
                    : 'add_or_update_report_failed',
                details: result
            });
        })
    );

    router.get(
        '/api/alexa/debug',
        asyncHandler(async (req, res) => {
            if (!config.ALEXA_DEBUG_ENDPOINTS_ENABLED) {
                return res.status(404).json({ error: 'not_found' });
            }

            try {
                await alexaCore.ensureAlexaRuntimeSchemaReady();
            } catch (error) {
                console.warn('ALEXA RUNTIME SCHEMA CHECK FAILED:', error?.message || error);
            }

            return res.status(200).json({
                ok: true,
                event_gateway_enabled: config.ALEXA_EVENT_GATEWAY_ENABLED,
                event_gateway_url: alexaEventGateway.getAlexaEventGatewayUrl(),
                lwa_token_url: alexaEventGateway.getLwaTokenUrl(),
                has_lwa_client_id: Boolean(alexaEventGateway.getLwaClientId()),
                has_lwa_client_secret: Boolean(alexaEventGateway.getLwaClientSecret()),
                has_forwarder_secret: Boolean(config.ALEXA_FORWARDER_SHARED_SECRET),
                change_report_debounce_ms: alexaEventGateway.getAlexaChangeReportDebounceMs(),
                add_or_update_debounce_ms: alexaEventGateway.getAlexaAddOrUpdateReportDebounceMs(),
                entity_fresh_window_seconds: utils.getEntityFreshWindowSeconds(),
                runtime_flags: {
                    entity_last_seen_supported: alexaState.alexaEntityLastSeenColumnSupported,
                    state_hash_supported: alexaState.alexaStateHashColumnSupported,
                    last_reported_supported: alexaState.alexaLastReportedColumnsSupported,
                    sync_snapshots_table_supported: alexaState.alexaSyncSnapshotsTableSupported,
                    sync_snapshots_upsert_supported: alexaState.alexaSyncSnapshotsUpsertSupported
                },
                queued_change_report_keys: Array.from(alexaState.alexaChangeReportQueue.keys()),
                queued_add_or_update_users: Array.from(alexaState.alexaAddOrUpdateReportQueue.keys()),
                metrics: alexaState.eventGatewayMetrics
            });
        })
    );

    router.get(
        '/api/alexa/entity-debug',
        asyncHandler(async (req, res) => {
            if (!config.ALEXA_DEBUG_ENDPOINTS_ENABLED) {
                return res.status(404).json({ error: 'not_found' });
            }

            const email = utils.sanitizeString(req.query?.email, 255);
            const userId = utils.parsePositiveInt(req.query?.user_id);
            if (!email && !userId) {
                return res.status(400).json({ error: 'email or user_id is required' });
            }

            const user = email
                ? await dbGet(
                      `SELECT id, email, alexa_enabled, alexa_linked FROM users WHERE email = ? LIMIT 1`,
                      [email]
                  )
                : await dbGet(
                      `SELECT id, email, alexa_enabled, alexa_linked FROM users WHERE id = ? LIMIT 1`,
                      [userId]
                  );
            if (!user) {
                return res.status(404).json({ error: 'user_not_found' });
            }

            const rows = await dbAll(
                `
                    SELECT ae.entity_id, ae.display_name, ae.entity_type, ae.exposed,
                           ae.online AS stored_entity_online, ae.entity_last_seen_at, ae.updated_at,
                           ae.last_reported_at,
                           d.id AS device_id, d.device_uid, d.last_seen_at
                    FROM alexa_entities ae
                    INNER JOIN devices d ON d.id = ae.device_id
                    WHERE ae.user_id = ?
                    ORDER BY ae.updated_at DESC
                    LIMIT 120
                `,
                [user.id]
            );

            return res.status(200).json({
                user: {
                    id: user.id,
                    email: user.email,
                    alexa_enabled: Boolean(user.alexa_enabled),
                    alexa_linked: Boolean(user.alexa_linked)
                },
                entities: rows || []
            });
        })
    );

    // Accept admin middleware for unused lints (reserved for /api/admin/* variants)
    void auth;

    return router;
};
