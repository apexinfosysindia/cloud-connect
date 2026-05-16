/**
 * Admin-facing Alexa endpoints.
 *
 *   GET  /api/admin/alexa/users                 — list users with link status
 *   POST /api/admin/alexa/users/:id/force-unlink — operator escape hatch
 *
 * Why these two and no more right now:
 *   - Phase 11 (proactive ChangeReport / event gateway) hasn't shipped, so
 *     there's no "request-sync" or "report-state" admin trigger to expose.
 *   - The forced-unlink endpoint mirrors the v1 incident response: when a
 *     customer's account ends up in the "linked-but-broken" state Amazon
 *     considers active, the only recovery is to wipe LWA tokens server-side
 *     so the customer's next attempt re-runs AcceptGrant cleanly.
 *
 * Both endpoints sit behind `auth.requireAdmin`, the existing bcrypt-gated
 * admin session token. We deliberately do NOT reuse `requireGoogleHomegraphAdmin`
 * (the static env-var token) because that one is meant for inter-service
 * automation, not interactive operators.
 */

const express = require('express');

module.exports = function ({ dbGet, dbRun, dbAll, utils, auth, alexaCore, eventGateway }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    // GET /api/admin/alexa/users
    //
    // Paginated-ish list. We cap at 200 rows because operators reach for
    // this via the admin UI; if you need to bulk-export, write a script.
    router.get(
        '/api/admin/alexa/users',
        auth.requireAdmin,
        asyncHandler(async (_req, res) => {
            const rows = await dbAll(
                `
                    SELECT
                        u.id,
                        u.email,
                        u.subdomain,
                        u.alexa_enabled,
                        u.alexa_linked,
                        (CASE WHEN u.alexa_security_pin IS NULL OR u.alexa_security_pin = ''
                              THEN 0 ELSE 1 END) AS alexa_security_pin_set,
                        (SELECT COUNT(*) FROM alexa_entities ae WHERE ae.user_id = u.id) AS total_entities,
                        (SELECT COUNT(*) FROM alexa_entities ae WHERE ae.user_id = u.id AND ae.exposed = 1) AS exposed_entities,
                        (SELECT MAX(ae.updated_at) FROM alexa_entities ae WHERE ae.user_id = u.id) AS last_synced_at,
                        (SELECT at.lwa_expires_at FROM alexa_tokens at WHERE at.user_id = u.id) AS lwa_expires_at
                    FROM users u
                    WHERE u.alexa_enabled = 1 OR u.alexa_linked = 1
                    ORDER BY u.id ASC
                    LIMIT 200
                `,
                []
            );

            return res.status(200).json({
                users: rows.map((r) => ({
                    id: r.id,
                    email: r.email,
                    subdomain: r.subdomain,
                    alexa_enabled: Boolean(r.alexa_enabled),
                    alexa_linked: Boolean(r.alexa_linked),
                    alexa_security_pin_set: Boolean(r.alexa_security_pin_set),
                    total_entities: Number(r.total_entities || 0),
                    exposed_entities: Number(r.exposed_entities || 0),
                    last_synced_at: r.last_synced_at || null,
                    lwa_expires_at: r.lwa_expires_at || null
                }))
            });
        })
    );

    // POST /api/admin/alexa/users/:id/force-unlink
    //
    // Operator escape hatch: blow away the user's alexa_tokens row and clear
    // alexa_linked. Idempotent. Does NOT clear alexa_enabled — leaving that
    // alone preserves the user's preference so the portal still says "Alexa
    // is on, but you need to re-link it".
    router.post(
        '/api/admin/alexa/users/:id/force-unlink',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const userId = utils.parsePositiveInt(req.params.id);
            if (!userId) {
                return res.status(400).json({ error: 'invalid_user_id' });
            }
            const user = await dbGet(`SELECT id, email FROM users WHERE id = ?`, [userId]);
            if (!user) {
                return res.status(404).json({ error: 'user_not_found' });
            }
            await alexaCore.unlinkAlexaForUser(userId);
            // Audit trail: surface in admin logs which operator did this.
            console.warn(
                `ADMIN ALEXA FORCE-UNLINK: user ${user.email} (id=${userId}) unlinked by ${req.admin?.email || 'unknown'}`
            );
            return res.status(200).json({
                message: 'alexa_unlinked',
                user_id: userId,
                email: user.email
            });
        })
    );

    // GET /api/admin/alexa/health
    //
    // Read-only summary of event-gateway dispatch outcomes since process
    // start. Returns counts + first/last timestamps per reason code, plus
    // current debounce queue depth.
    //
    // Why this exists: during Phase 9 hardware bring-up an operator needs
    // to see whether ChangeReports are landing without tailing CloudWatch.
    // The post-mortem case we're guarding against is the v1 silent-401 loop
    // — counters here would have shown a single user's `gateway_error` count
    // climbing while every other user's `ok` count stayed flat. Easy diff.
    //
    // Counters are process-local, so a Cloud Connect restart resets them.
    // That's the right tradeoff for a single-instance deploy: we don't want
    // to add a metrics dependency for one debug endpoint, and "since last
    // restart" is the natural window for an operator anyway.
    //
    // The endpoint degrades gracefully if eventGateway isn't wired (e.g.
    // during early bring-up before Phase 11 was merged) — returns an empty
    // snapshot rather than 500'ing.
    router.get(
        '/api/admin/alexa/health',
        auth.requireAdmin,
        asyncHandler(async (_req, res) => {
            if (!eventGateway || typeof eventGateway.getHealthSnapshot !== 'function') {
                return res.status(200).json({
                    available: false,
                    reason: 'event_gateway_not_wired'
                });
            }
            const snapshot = eventGateway.getHealthSnapshot();
            return res.status(200).json({
                available: true,
                ...snapshot
            });
        })
    );

    // GET /api/admin/alexa/users/:id/preview-change-report?entity_id=<ha_id>
    //
    // Diagnostic dry-run for Phase 9 bring-up. Returns the exact ChangeReport
    // envelope event-gateway.js would have POSTed for this (user, entity)
    // pair, but does not touch the network and does not mint a real LWA
    // access token (the bearer in the rendered envelope is a fixed
    // placeholder string).
    //
    // Why a query param for entity_id and not a path segment: HA entity IDs
    // contain a dot (e.g. light.kitchen), and Express path-param dot-handling
    // depends on the configured router strict mode + the leading-character
    // rules. A query param sidesteps the entire question and produces a
    // clean URL like:
    //
    //   GET /api/admin/alexa/users/42/preview-change-report?entity_id=light.kitchen
    //
    // 404 paths are split into two reasons:
    //   - user_not_found:   the :id doesn't resolve to a row in users
    //   - entity_not_found: the user exists but the (user_id, entity_id)
    //                       pair has no row in alexa_entities OR the row
    //                       has exposed=0
    //
    // Distinguishing them helps the operator triage quickly during bring-up:
    // user_not_found means the wrong ID is in the URL; entity_not_found
    // typically means the addon's last sync didn't include the entity
    // (which is a separate diagnostic path).
    router.get(
        '/api/admin/alexa/users/:id/preview-change-report',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            if (!eventGateway || typeof eventGateway.previewChangeReportForUserEntity !== 'function') {
                return res.status(503).json({
                    error: 'event_gateway_not_wired'
                });
            }
            const userId = utils.parsePositiveInt(req.params.id);
            if (!userId) {
                return res.status(400).json({ error: 'invalid_user_id' });
            }
            const entityId = utils.sanitizeString(req.query?.entity_id, 255);
            if (!entityId) {
                return res.status(400).json({ error: 'missing_entity_id' });
            }

            const user = await dbGet(`SELECT id FROM users WHERE id = ?`, [userId]);
            if (!user) {
                return res.status(404).json({ error: 'user_not_found' });
            }

            const result = await eventGateway.previewChangeReportForUserEntity(userId, entityId);
            if (!result.ok) {
                // Map the gateway's structured reasons to HTTP statuses.
                // entity_not_found → 404. no_properties (out-of-scope HA
                // domain like fan/climate before Phase 10) → 422 because
                // the request was well-formed but cannot be fulfilled at
                // the current Walking Skeleton coverage.
                if (result.reason === 'entity_not_found') {
                    return res.status(404).json({ error: 'entity_not_found' });
                }
                if (result.reason === 'no_properties') {
                    return res.status(422).json({ error: 'no_reportable_properties' });
                }
                return res.status(500).json({ error: 'preview_failed', reason: result.reason });
            }

            return res.status(200).json({
                user_id: userId,
                entity_id: entityId,
                event: result.event,
                context: result.context
            });
        })
    );

    // POST /api/admin/alexa/users/:id/commands/:cmd_id/replay
    //
    // Operator escape hatch: re-fire a queue row that finished in a
    // terminal state (failed / expired / completed). Inserts a NEW
    // alexa_command_queue row with the same (user_id, device_id, entity_id,
    // action, payload_json) and status='pending'. The addon picks it up via
    // the normal /commands/poll loop.
    //
    // Why a NEW row instead of UPDATE on the old one:
    //   - audit trail: the old row's terminal status + result_json must
    //     stay queryable. Promoting failed→pending rewrites history.
    //   - TTL: the old row's expires_at is in the past. Resetting it on
    //     the same row conflates "queued just now" with "originally queued
    //     at <time>" in any future investigation.
    //   - operator double-click: two new rows is the obviously-correct
    //     outcome. Two UPDATEs of the same row is ambiguous.
    //
    // Replay is REFUSED if the source row is still in flight ('pending' or
    // 'dispatched'). Doubling up an active command would risk double-firing
    // non-idempotent actions (locks, scenes). 409 with reason='command_in_flight'.
    //
    // Cross-user safety: the URL carries both :id and :cmd_id; we verify
    // the queue row's user_id matches the URL :id and 404 otherwise. An
    // operator who knew a queue ID alone must not be able to resurrect an
    // action against a different user's device.
    //
    // No idempotency key. The two real "double-click" cases — operator hits
    // the button twice, or replays from a stale tab — are both handled
    // adequately by the TTL on the new row (addon expires it within seconds
    // if no longer relevant).
    router.post(
        '/api/admin/alexa/users/:id/commands/:cmd_id/replay',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const userId = utils.parsePositiveInt(req.params.id);
            const cmdId = utils.parsePositiveInt(req.params.cmd_id);
            if (!userId) return res.status(400).json({ error: 'invalid_user_id' });
            if (!cmdId) return res.status(400).json({ error: 'invalid_command_id' });

            const user = await dbGet(`SELECT id, email FROM users WHERE id = ?`, [userId]);
            if (!user) return res.status(404).json({ error: 'user_not_found' });

            const source = await dbGet(
                `SELECT id, user_id, device_id, entity_id, action, payload_json, status
                 FROM alexa_command_queue WHERE id = ?`,
                [cmdId]
            );
            // Same 404 for "no such command" and "command for different
            // user" — don't leak existence of queue rows across users.
            if (!source || source.user_id !== userId) {
                return res.status(404).json({ error: 'command_not_found' });
            }

            // Refuse to replay an in-flight row. The addon is about to
            // execute (pending) or already executing (dispatched).
            if (source.status === 'pending' || source.status === 'dispatched') {
                return res.status(409).json({
                    error: 'command_in_flight',
                    current_status: source.status
                });
            }

            const ttlSeconds =
                alexaCore && typeof alexaCore.getAlexaCommandTtlSeconds === 'function'
                    ? alexaCore.getAlexaCommandTtlSeconds()
                    : 45;
            const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();

            const insert = await dbRun(
                `INSERT INTO alexa_command_queue
                    (user_id, device_id, entity_id, action, payload_json, status, expires_at)
                 VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
                [
                    source.user_id,
                    source.device_id,
                    source.entity_id,
                    source.action,
                    source.payload_json,
                    expiresAt
                ]
            );

            // Audit trail. Replays are operator-initiated by definition, so
            // logging the operator email + before/after IDs is exactly the
            // record we want during incident review.
            console.warn(
                `ADMIN ALEXA REPLAY: user=${user.email} (id=${userId}) ` +
                    `source_cmd=${source.id} (${source.status}) → new_cmd=${insert.lastID} ` +
                    `entity=${source.entity_id} action=${source.action} ` +
                    `by=${req.admin?.email || 'unknown'}`
            );

            return res.status(200).json({
                ok: true,
                new_command_id: insert.lastID,
                source_command_id: source.id,
                source_status: source.status,
                entity_id: source.entity_id,
                action: source.action,
                expires_at: expiresAt
            });
        })
    );

    return router;
};
