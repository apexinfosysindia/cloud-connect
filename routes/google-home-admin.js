const express = require('express');

module.exports = function ({ dbGet, dbAll, config, utils, auth, googleCore, homegraph, state }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.post('/api/internal/google/homegraph/request-sync', auth.requireGoogleHomegraphAdmin, async (req, res) => {
        const userId = utils.parsePositiveInt(req.body?.user_id);
        if (!userId) {
            return res.status(400).json({ error: 'user_id is required' });
        }

        try {
            const user = await dbGet(`SELECT id, google_home_enabled, google_home_linked FROM users WHERE id = ?`, [
                userId
            ]);
            if (!user || !user.google_home_enabled || !user.google_home_linked) {
                return res.status(404).json({ error: 'eligible_google_user_not_found' });
            }

            const result = await homegraph.sendGoogleRequestSync(String(userId));
            if (!result.ok && !result.skipped) {
                homegraph.markHomegraphMetricFailure(
                    'request_sync',
                    String(userId),
                    result.statusCode || null,
                    result.error || null
                );
                return res.status(502).json({ error: 'request_sync_failed', details: result });
            }

            if (result.skipped) {
                homegraph.markHomegraphMetricSkipped('request_sync', String(userId), result.reason || null);
            } else {
                homegraph.markHomegraphMetricSuccess('request_sync', String(userId), result.statusCode || null);
            }

            return res.status(200).json({
                message: result.skipped ? 'request_sync_skipped' : 'request_sync_sent',
                details: result
            });
        } catch (error) {
            console.error('GOOGLE HOMEGRAPH REQUEST SYNC INTERNAL ERROR:', error);
            return res.status(500).json({ error: 'unable_to_send_request_sync' });
        }
    });

    router.post('/api/internal/google/homegraph/report-state', auth.requireGoogleHomegraphAdmin, async (req, res) => {
        const userId = utils.parsePositiveInt(req.body?.user_id);
        if (!userId) {
            return res.status(400).json({ error: 'user_id is required' });
        }

        const force = req.body?.force !== false;

        try {
            const user = await dbGet(`SELECT id, google_home_enabled, google_home_linked FROM users WHERE id = ?`, [
                userId
            ]);
            if (!user || !user.google_home_enabled || !user.google_home_linked) {
                return res.status(404).json({ error: 'eligible_google_user_not_found' });
            }

            const reportable = await homegraph.collectGoogleReportableStateChangesForUser(userId, { force });
            const entityIds = Object.keys(reportable.states);
            if (entityIds.length === 0) {
                return res.status(200).json({ message: 'no_state_changes' });
            }

            const result = await homegraph.sendGoogleReportState(String(userId), reportable.states);
            if (!result.ok && !result.skipped) {
                homegraph.markHomegraphMetricFailure(
                    'report_state',
                    String(userId),
                    result.statusCode || null,
                    result.error || null
                );
                return res.status(502).json({ error: 'report_state_failed', details: result });
            }

            if (!result.ok) {
                homegraph.markHomegraphMetricSkipped('report_state', String(userId), result.reason || null);
                return res.status(200).json({ message: 'report_state_skipped', details: result });
            }

            await homegraph.markGoogleReportedStateHashes(userId, reportable.hashes);
            homegraph.markHomegraphMetricSuccess('report_state', String(userId), result.statusCode || null);
            return res.status(200).json({
                message: result.skipped ? 'report_state_skipped' : 'report_state_sent',
                entity_count: entityIds.length,
                details: result
            });
        } catch (error) {
            console.error('GOOGLE HOMEGRAPH REPORT STATE INTERNAL ERROR:', error);
            return res.status(500).json({ error: 'unable_to_send_report_state' });
        }
    });

    router.get(
        '/api/google/home/homegraph-debug',
        asyncHandler(async (req, res) => {
            if (!config.GOOGLE_DEBUG_ENDPOINTS_ENABLED) {
                return res.status(404).json({ error: 'not_found' });
            }

            try {
                await googleCore.ensureGoogleRuntimeSchemaReady();
            } catch (error) {
                console.warn('GOOGLE RUNTIME SCHEMA CHECK FAILED:', error?.message || error);
            }

            const hasCredentials = homegraph.hasGoogleHomegraphCredentials();
            const clientEmail = homegraph.getGoogleServiceAccountClientEmail();
            const tokenCacheValid = Boolean(
                state.googleHomegraphAccessTokenCache.token &&
                state.googleHomegraphAccessTokenCache.expiresAt > Date.now()
            );

            return res.status(200).json({
                ok: true,
                report_state_enabled: config.GOOGLE_HOMEGRAPH_REPORT_STATE_ENABLED,
                has_service_account_email: Boolean(clientEmail),
                has_service_account_private_key: Boolean(homegraph.getGoogleServiceAccountPrivateKey()),
                has_credentials: hasCredentials,
                token_uri: homegraph.getGoogleHomegraphTokenUri(),
                api_base_url: homegraph.getGoogleHomegraphApiBaseUrl(),
                request_sync_debounce_ms: homegraph.getGoogleHomegraphRequestSyncDebounceMs(),
                report_state_debounce_ms: homegraph.getGoogleHomegraphReportStateDebounceMs(),
                entity_fresh_window_seconds: utils.getEntityFreshWindowSeconds(),
                token_cache_valid: tokenCacheValid,
                runtime_flags: {
                    entity_last_seen_supported: state.googleEntityLastSeenColumnSupported,
                    state_hash_supported: state.googleStateHashColumnSupported,
                    last_reported_supported: state.googleLastReportedColumnsSupported,
                    sync_snapshots_table_supported: state.googleSyncSnapshotsTableSupported,
                    sync_snapshots_upsert_supported: state.googleSyncSnapshotsUpsertSupported
                },
                queued_request_sync_users: Array.from(state.googleHomegraphRequestSyncQueue.keys()),
                queued_report_state_users: Array.from(state.googleHomegraphReportStateQueue.keys()),
                metrics: state.homegraphMetrics
            });
        })
    );

    router.get('/api/google/home/entity-debug', async (req, res) => {
        if (!config.GOOGLE_DEBUG_ENDPOINTS_ENABLED) {
            return res.status(404).json({ error: 'not_found' });
        }

        try {
            await googleCore.ensureGoogleRuntimeSchemaReady();
        } catch (error) {
            console.warn('GOOGLE ENTITY SCHEMA CHECK FAILED:', error?.message || error);
        }

        const email = utils.sanitizeString(req.query?.email, 255);
        const userId = utils.parsePositiveInt(req.query?.user_id);

        if (!email && !userId) {
            return res.status(400).json({ error: 'email or user_id is required' });
        }

        try {
            const user = email
                ? await dbGet(
                      `SELECT id, email, google_home_enabled, google_home_linked FROM users WHERE email = ? LIMIT 1`,
                      [email]
                  )
                : await dbGet(
                      `SELECT id, email, google_home_enabled, google_home_linked FROM users WHERE id = ? LIMIT 1`,
                      [userId]
                  );

            if (!user) {
                return res.status(404).json({ error: 'user_not_found' });
            }

            await homegraph.markGoogleEntitiesStaleByFreshness();

            let rows;
            try {
                rows = await dbAll(
                    `
                        SELECT
                            ge.entity_id,
                            ge.display_name,
                            ge.entity_type,
                            ge.exposed,
                            ge.online AS stored_entity_online,
                            ge.entity_last_seen_at,
                            ge.updated_at,
                            ge.last_reported_at,
                            d.id AS device_id,
                            d.device_uid,
                            d.last_seen_at,
                            d.agent_state
                        FROM google_home_entities ge
                        INNER JOIN devices d ON d.id = ge.device_id
                        WHERE ge.user_id = ?
                        ORDER BY ge.updated_at DESC
                        LIMIT 120
                    `,
                    [user.id]
                );
            } catch (queryError) {
                if (utils.isMissingGoogleEntityLastSeenColumnError(queryError)) {
                    state.googleEntityLastSeenColumnSupported = false;
                    rows = await dbAll(
                        `
                            SELECT
                                ge.entity_id,
                                ge.display_name,
                                ge.entity_type,
                                ge.exposed,
                                ge.online AS stored_entity_online,
                                NULL AS entity_last_seen_at,
                                ge.updated_at,
                                ge.last_reported_at,
                                d.id AS device_id,
                                d.device_uid,
                                d.last_seen_at,
                                d.agent_state
                            FROM google_home_entities ge
                            INNER JOIN devices d ON d.id = ge.device_id
                            WHERE ge.user_id = ?
                            ORDER BY ge.updated_at DESC
                            LIMIT 120
                        `,
                        [user.id]
                    );
                } else {
                    throw queryError;
                }
            }

            const entities = (rows || []).map((row) => ({
                entity_id: row.entity_id,
                display_name: row.display_name,
                entity_type: row.entity_type,
                exposed: Boolean(row.exposed),
                stored_entity_online: Boolean(row.stored_entity_online),
                device_online: utils.isDeviceOnline(row.last_seen_at),
                entity_last_seen_at: row.entity_last_seen_at,
                entity_fresh: utils.isEntityFresh(row.entity_last_seen_at || row.updated_at),
                effective_online: utils.isEntityEffectivelyOnline({
                    online: row.stored_entity_online,
                    last_seen_at: row.last_seen_at,
                    entity_last_seen_at: row.entity_last_seen_at,
                    updated_at: row.updated_at,
                    entity_type: row.entity_type
                }),
                device_id: row.device_id,
                device_uid: row.device_uid,
                device_last_seen_at: row.last_seen_at,
                device_agent_state: row.agent_state,
                entity_updated_at: row.updated_at,
                last_reported_at: row.last_reported_at
            }));

            const onlineCount = entities.filter((entity) => entity.effective_online).length;
            const availableCount = entities.filter((entity) => entity.stored_entity_online).length;
            const staleCount = entities.filter((entity) => !entity.entity_fresh).length;

            return res.status(200).json({
                user: {
                    id: user.id,
                    email: user.email,
                    google_home_enabled: Boolean(user.google_home_enabled),
                    google_home_linked: Boolean(user.google_home_linked)
                },
                totals: {
                    entities: entities.length,
                    online: onlineCount,
                    offline: Math.max(0, entities.length - onlineCount),
                    entity_available: availableCount,
                    entity_stale: staleCount
                },
                entities
            });
        } catch (error) {
            console.error('GOOGLE ENTITY ERROR:', error);
            return res.status(500).json({ error: 'unable_to_load_entity_debug' });
        }
    });

    return router;
};
