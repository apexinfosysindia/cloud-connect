const config = require('../config');
const utils = require('../utils');
const state = require('./state');
const entityMapping = require('./entity-mapping');

/**
 * Alexa Event Gateway client — the Alexa analog of lib/google-home/homegraph.js.
 *
 * Two proactive reports, both posted to config.ALEXA_EVENT_GATEWAY_URL
 * authenticated with the user's Login with Amazon access token:
 *
 *   scheduleAlexaAddOrUpdateReportForUser  ≈ HomeGraph requestSync
 *       Alexa.Discovery / AddOrUpdateReport — tells Alexa the endpoint
 *       inventory changed (added/removed/renamed devices).
 *
 *   scheduleAlexaChangeReportForUser       ≈ HomeGraph reportStateAndNotification
 *       Alexa.ChangeReport — tells Alexa a property value changed (on→off,
 *       brightness, etc.), one event per changed endpoint.
 *
 * Replicated invariants from the Google integration:
 *   (1) per-user debounce/coalesce Map + setTimeout
 *   (2) state-hash skip-on-equal (only report endpoints whose state changed)
 *   (3) 8s post-command suppression so optimistic directive replies aren't
 *       reverted by a ChangeReport that fires before the device confirms
 */
module.exports = function ({ dbGet, dbRun, dbAll, core }) {
    function metric(type) {
        return state.alexaEventGatewayMetrics[type];
    }

    function markSuccess(type, userId, statusCode) {
        const m = metric(type);
        if (!m) return;
        m.sent += 1;
        m.last_success_at = new Date().toISOString();
        m.last_status = statusCode || null;
        m.last_user_id = String(userId);
    }

    function markFailure(type, userId, statusCode, reason) {
        const m = metric(type);
        if (!m) return;
        m.failed += 1;
        m.last_failure_at = new Date().toISOString();
        m.last_status = statusCode || null;
        m.last_failure_reason = utils.sanitizeString(reason, 300) || 'unknown_error';
        m.last_user_id = String(userId);
    }

    function markSkipped(type, userId, reason) {
        const m = metric(type);
        if (!m) return;
        m.skipped += 1;
        m.last_user_id = String(userId);
        if (reason) m.last_failure_reason = utils.sanitizeString(reason, 300);
    }

    function hasAlexaCredentials() {
        return Boolean(
            config.ALEXA_LWA_CLIENT_ID &&
                config.ALEXA_LWA_CLIENT_SECRET &&
                config.ALEXA_LWA_TOKEN_ENC_KEY &&
                config.ALEXA_REPORT_STATE_ENABLED
        );
    }

    function getAddOrUpdateDebounceMs() {
        const v = config.ALEXA_ADD_OR_UPDATE_DEBOUNCE_MS;
        return Number.isFinite(v) ? Math.max(250, Math.min(30000, Math.round(v))) : 2500;
    }

    function getChangeReportDebounceMs() {
        const v = config.ALEXA_CHANGE_REPORT_DEBOUNCE_MS;
        return Number.isFinite(v) ? Math.max(250, Math.min(10000, Math.round(v))) : 1200;
    }

    // ── LWA access token (refresh + cache) ──────────────────────────────

    async function getLwaAccessTokenForUser(userId) {
        const normalizedUserId = Number(userId);
        const cached = state.alexaLwaAccessTokenCache.get(normalizedUserId);
        if (cached && cached.token && cached.expiresAt > Date.now() + 30000) {
            return cached.token;
        }

        const lwa = await core.getAlexaLwaTokenRow(normalizedUserId);
        if (!lwa || !lwa.refresh_token) {
            return null;
        }

        const body = new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: lwa.refresh_token,
            client_id: config.ALEXA_LWA_CLIENT_ID,
            client_secret: config.ALEXA_LWA_CLIENT_SECRET
        });

        const res = await fetch(config.ALEXA_LWA_TOKEN_URI, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
            body: body.toString()
        });
        const json = await res.json().catch(() => null);
        if (!res.ok || !json?.access_token) {
            throw new Error(`LWA token refresh failed: ${json?.error_description || json?.error || res.status}`);
        }

        const token = json.access_token;
        const ttlMs = Math.max(60, Math.min(3600, Number(json.expires_in) || 3300)) * 1000;
        state.alexaLwaAccessTokenCache.set(normalizedUserId, { token, expiresAt: Date.now() + ttlMs });
        return token;
    }

    // ── Outbound Event Gateway POST ─────────────────────────────────────

    async function postEvent(accessToken, event) {
        const res = await fetch(config.ALEXA_EVENT_GATEWAY_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${accessToken}`
            },
            body: JSON.stringify(event)
        });
        let parsed = null;
        if (res.status !== 202 && res.status !== 204) {
            parsed = await res.json().catch(() => null);
        }
        return { ok: res.status >= 200 && res.status < 300, statusCode: res.status, body: parsed };
    }

    // Lazy revocation detection. Amazon sends NO Smart Home directive when a
    // customer disables the skill / unlinks the account in the Alexa app — the
    // only signal is a 403 (SKILL_DISABLED_EXCEPTION) when we POST a proactive
    // event. When we see that, treat the link as revoked: clean up auth data so
    // the portal dashboard reflects the unlink (alexa_linked → 0) on next load.
    async function handleGatewayAuthError(userId, response) {
        const status = response?.statusCode;
        const code = response?.body?.payload?.code || response?.body?.header?.name;
        const revoked = status === 403 || code === 'SKILL_DISABLED_EXCEPTION';
        if (!revoked) {
            return false;
        }
        try {
            await core.cleanupAlexaAuthDataForUser(userId);
            console.warn('ALEXA GATEWAY REVOKED: cleaned up auth data for user', userId, 'status', status);
        } catch (error) {
            console.error('ALEXA GATEWAY REVOKE CLEANUP ERROR:', error);
        }
        return true;
    }

    function newMessageId() {
        // crypto.randomUUID is available Node 16+; avoid Date for determinism in tests.
        return require('crypto').randomUUID();
    }

    function nowIso() {
        return new Date().toISOString();
    }

    function buildProperties(propsObject) {
        // Map a flat {name: value} object to Alexa context.properties entries.
        const namespaceFor = {
            powerState: 'Alexa.PowerController',
            brightness: 'Alexa.BrightnessController',
            color: 'Alexa.ColorController',
            colorTemperatureInKelvin: 'Alexa.ColorTemperatureController',
            connectivity: 'Alexa.EndpointHealth'
        };
        const ts = nowIso();
        return Object.entries(propsObject).map(([name, value]) => ({
            namespace: namespaceFor[name] || 'Alexa',
            name,
            value: name === 'connectivity' ? { value } : value,
            timeOfSample: ts,
            uncertaintyInMilliseconds: 0
        }));
    }

    // ── AddOrUpdateReport (inventory changed) ───────────────────────────

    async function sendAddOrUpdateReport(userId) {
        if (!hasAlexaCredentials()) {
            return { skipped: true, reason: 'credentials_disabled' };
        }
        const user = await dbGet(`SELECT id, alexa_enabled, alexa_linked FROM users WHERE id = ?`, [userId]);
        if (!user || !user.alexa_enabled || !user.alexa_linked) {
            return { skipped: true, reason: 'not_linked' };
        }
        const accessToken = await getLwaAccessTokenForUser(userId);
        if (!accessToken) {
            return { skipped: true, reason: 'no_lwa_token' };
        }

        const rows = await core.getAlexaEndpointsForUser(userId);
        const endpoints = (rows || []).map((r) => entityMapping.buildAlexaEndpoint(r)).filter(Boolean);
        if (endpoints.length === 0) {
            return { skipped: true, reason: 'no_endpoints' };
        }

        const event = {
            event: {
                header: {
                    namespace: 'Alexa.Discovery',
                    name: 'AddOrUpdateReport',
                    payloadVersion: '3',
                    messageId: newMessageId()
                },
                payload: {
                    endpoints,
                    scope: { type: 'BearerToken', token: accessToken }
                }
            }
        };
        return await postEvent(accessToken, event);
    }

    function scheduleAlexaAddOrUpdateReportForUser(userId, reason = 'change') {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId || !hasAlexaCredentials()) {
            return;
        }
        const existing = state.alexaAddOrUpdateQueue.get(normalizedUserId);
        if (existing?.timer) {
            clearTimeout(existing.timer);
        }
        const timer = setTimeout(async () => {
            state.alexaAddOrUpdateQueue.delete(normalizedUserId);
            try {
                const response = await sendAddOrUpdateReport(normalizedUserId);
                if (response?.skipped) {
                    markSkipped('add_or_update_report', normalizedUserId, response.reason);
                    return;
                }
                if (!response?.ok) {
                    markFailure('add_or_update_report', normalizedUserId, response?.statusCode, response?.body?.payload?.message);
                    console.warn('ALEXA ADD_OR_UPDATE FAILED:', { user_id: normalizedUserId, reason, status: response?.statusCode });
                    await handleGatewayAuthError(normalizedUserId, response);
                    return;
                }
                markSuccess('add_or_update_report', normalizedUserId, response.statusCode);
            } catch (error) {
                markFailure('add_or_update_report', normalizedUserId, null, error?.message);
                console.error('ALEXA ADD_OR_UPDATE ERROR:', error);
            }
        }, getAddOrUpdateDebounceMs());
        if (typeof timer.unref === 'function') timer.unref();
        state.alexaAddOrUpdateQueue.set(normalizedUserId, { reason, timer });
    }

    // ── ChangeReport (property values changed) ──────────────────────────

    async function collectAlexaChangeReportsForUser(userId, options = {}) {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId) {
            return { reports: [], hashes: {} };
        }
        const force = Boolean(options.force);

        // 8s post-command suppression (see file header invariant 3).
        let recentCommandEntityIds = new Set();
        try {
            const recentCutoff = new Date(Date.now() - 8000).toISOString();
            const recentCmdRows = await dbAll(
                `SELECT DISTINCT entity_id FROM alexa_command_queue
                 WHERE user_id = ? AND status IN ('pending','dispatched') AND created_at >= ?`,
                [normalizedUserId, recentCutoff]
            );
            recentCommandEntityIds = new Set((recentCmdRows || []).map((r) => utils.sanitizeEntityId(r.entity_id)).filter(Boolean));
        } catch (_) {
            // non-critical
        }

        const rows = await dbAll(
            `SELECT entity_id, entity_type, online, state_json, last_reported_state_hash, exposed
             FROM alexa_endpoints WHERE user_id = ?`,
            [normalizedUserId]
        );

        const reports = [];
        const hashes = {};
        for (const row of rows || []) {
            if (!row.exposed) continue;
            if (recentCommandEntityIds.has(row.entity_id)) continue;
            const props = entityMapping.parseAlexaEndpointState(row);
            const hash = core.computeAlexaStateHash(props);
            if (!force && hash === row.last_reported_state_hash) {
                continue;
            }
            hashes[row.entity_id] = hash;
            reports.push({ entityId: row.entity_id, props });
        }
        return { reports, hashes };
    }

    async function markAlexaReportedStateHashes(userId, hashesByEntityId) {
        const nowIsoVal = nowIso();
        for (const [entityId, hash] of Object.entries(hashesByEntityId || {})) {
            await dbRun(
                `UPDATE alexa_endpoints SET last_reported_state_hash = ?, last_reported_at = ? WHERE user_id = ? AND entity_id = ?`,
                [hash, nowIsoVal, userId, entityId]
            );
        }
    }

    async function sendChangeReports(userId, options = {}) {
        if (!hasAlexaCredentials()) {
            return { skipped: true, reason: 'credentials_disabled' };
        }
        const user = await dbGet(`SELECT id, alexa_enabled, alexa_linked FROM users WHERE id = ?`, [userId]);
        if (!user || !user.alexa_enabled || !user.alexa_linked) {
            return { skipped: true, reason: 'not_linked' };
        }
        const { reports, hashes } = await collectAlexaChangeReportsForUser(userId, options);
        if (reports.length === 0) {
            return { skipped: true, reason: 'no_changes' };
        }
        const accessToken = await getLwaAccessTokenForUser(userId);
        if (!accessToken) {
            return { skipped: true, reason: 'no_lwa_token' };
        }

        let anyFailed = false;
        let lastStatus = null;
        for (const report of reports) {
            const allProps = buildProperties(report.props);
            const changeProps = allProps.filter((p) => p.name !== 'connectivity');
            const event = {
                event: {
                    header: {
                        namespace: 'Alexa',
                        name: 'ChangeReport',
                        payloadVersion: '3',
                        messageId: newMessageId()
                    },
                    endpoint: {
                        scope: { type: 'BearerToken', token: accessToken },
                        endpointId: report.entityId
                    },
                    payload: {
                        change: {
                            cause: { type: 'APP_INTERACTION' },
                            properties: changeProps
                        }
                    }
                },
                context: {
                    properties: allProps.filter((p) => p.name === 'connectivity')
                }
            };
            const res = await postEvent(accessToken, event);
            lastStatus = res.statusCode;
            if (!res.ok) {
                anyFailed = true;
            }
        }

        // Only persist hashes for endpoints we successfully reported (all-or-nothing
        // is acceptable here: a failed batch will re-report next tick since hashes
        // weren't advanced).
        if (!anyFailed) {
            await markAlexaReportedStateHashes(userId, hashes);
        }
        return { ok: !anyFailed, statusCode: lastStatus };
    }

    function scheduleAlexaChangeReportForUser(userId, options = {}) {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId || !hasAlexaCredentials()) {
            return;
        }
        const force = Boolean(options.force);
        const existing = state.alexaChangeReportQueue.get(normalizedUserId);
        if (existing?.timer) {
            clearTimeout(existing.timer);
        }
        const delay = force ? 200 : getChangeReportDebounceMs();
        const timer = setTimeout(async () => {
            state.alexaChangeReportQueue.delete(normalizedUserId);
            try {
                const response = await sendChangeReports(normalizedUserId, { force });
                if (response?.skipped) {
                    markSkipped('change_report', normalizedUserId, response.reason);
                    return;
                }
                if (!response?.ok) {
                    markFailure('change_report', normalizedUserId, response?.statusCode, 'change_report_failed');
                    await handleGatewayAuthError(normalizedUserId, response);
                    return;
                }
                markSuccess('change_report', normalizedUserId, response.statusCode);
            } catch (error) {
                markFailure('change_report', normalizedUserId, null, error?.message);
                console.error('ALEXA CHANGE_REPORT ERROR:', error);
            }
        }, delay);
        if (typeof timer.unref === 'function') timer.unref();
        state.alexaChangeReportQueue.set(normalizedUserId, { timer });
    }

    // ── DeleteReport (endpoints removed/hidden/unlinked) ────────────────

    async function sendDeleteReport(userId, endpointIds) {
        if (!hasAlexaCredentials()) {
            return { skipped: true, reason: 'credentials_disabled' };
        }
        const ids = Array.from(new Set((endpointIds || []).filter(Boolean)));
        if (ids.length === 0) {
            return { skipped: true, reason: 'no_endpoints' };
        }
        // Note: intentionally NOT gated on alexa_linked — a delete fired during
        // unlink/cleanup must still reach Alexa to drop the endpoints.
        const accessToken = await getLwaAccessTokenForUser(userId);
        if (!accessToken) {
            return { skipped: true, reason: 'no_lwa_token' };
        }

        const event = {
            event: {
                header: {
                    namespace: 'Alexa.Discovery',
                    name: 'DeleteReport',
                    payloadVersion: '3',
                    messageId: newMessageId()
                },
                payload: {
                    endpoints: ids.map((endpointId) => ({ endpointId })),
                    scope: { type: 'BearerToken', token: accessToken }
                }
            }
        };
        return await postEvent(accessToken, event);
    }

    // Awaitable, NON-debounced DeleteReport. Used at unlink time: the caller
    // must drop the endpoints from Alexa *before* cleanupAlexaAuthDataForUser
    // wipes the LWA token (the debounced scheduler would fire too late, after
    // the token is gone). Best-effort — records metrics, never throws.
    async function deleteEndpointsNow(userId, endpointIds, reason = 'unlink') {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId || !hasAlexaCredentials()) {
            return { skipped: true, reason: 'credentials_disabled' };
        }
        try {
            const response = await sendDeleteReport(normalizedUserId, endpointIds);
            if (response?.skipped) {
                markSkipped('delete_report', normalizedUserId, response.reason);
                return response;
            }
            if (!response?.ok) {
                markFailure('delete_report', normalizedUserId, response?.statusCode, response?.body?.payload?.message);
                console.warn('ALEXA DELETE_REPORT (now) FAILED:', { user_id: normalizedUserId, reason, status: response?.statusCode });
                return response;
            }
            markSuccess('delete_report', normalizedUserId, response.statusCode);
            return response;
        } catch (error) {
            markFailure('delete_report', normalizedUserId, null, error?.message);
            console.error('ALEXA DELETE_REPORT (now) ERROR:', error);
            return { ok: false, error: error?.message };
        }
    }

    function scheduleAlexaDeleteReportForUser(userId, endpointIds, reason = 'delete') {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId || !hasAlexaCredentials()) {
            return;
        }
        const incoming = (Array.isArray(endpointIds) ? endpointIds : [endpointIds]).filter(Boolean);
        if (incoming.length === 0) {
            return;
        }
        const existing = state.alexaDeleteReportQueue.get(normalizedUserId);
        // Accumulate endpointIds across coalesced calls — unlike AddOrUpdate, the
        // sender cannot re-read the rows (they may already be deleted/hidden).
        const ids = existing?.endpointIds || new Set();
        for (const id of incoming) ids.add(id);
        if (existing?.timer) {
            clearTimeout(existing.timer);
        }
        const timer = setTimeout(async () => {
            const entry = state.alexaDeleteReportQueue.get(normalizedUserId);
            state.alexaDeleteReportQueue.delete(normalizedUserId);
            const toDelete = Array.from(entry?.endpointIds || []);
            try {
                const response = await sendDeleteReport(normalizedUserId, toDelete);
                if (response?.skipped) {
                    markSkipped('delete_report', normalizedUserId, response.reason);
                    return;
                }
                if (!response?.ok) {
                    markFailure('delete_report', normalizedUserId, response?.statusCode, response?.body?.payload?.message);
                    await handleGatewayAuthError(normalizedUserId, response);
                    return;
                }
                markSuccess('delete_report', normalizedUserId, response.statusCode);
            } catch (error) {
                markFailure('delete_report', normalizedUserId, null, error?.message);
                console.error('ALEXA DELETE_REPORT ERROR:', error);
            }
        }, getAddOrUpdateDebounceMs());
        if (typeof timer.unref === 'function') timer.unref();
        state.alexaDeleteReportQueue.set(normalizedUserId, { reason, timer, endpointIds: ids });
    }

    // Liveness probe used by the dashboard to detect an Alexa-app skill-disable
    // promptly. Amazon sends no directive on disable; the only signal is a 403
    // (SKILL_DISABLED_EXCEPTION) on a proactive POST. We fire one idempotent
    // AddOrUpdateReport and let handleGatewayAuthError flip alexa_linked → 0 on
    // 403. Returns { revoked: true } when the link was found dead.
    async function probeAlexaLinkLiveness(userId) {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId || !hasAlexaCredentials()) {
            return { skipped: true, reason: 'credentials_disabled' };
        }
        try {
            const response = await sendAddOrUpdateReport(normalizedUserId);
            if (response?.skipped) {
                markSkipped('add_or_update_report', normalizedUserId, response.reason);
                return { skipped: true, reason: response.reason };
            }
            if (!response?.ok) {
                markFailure('add_or_update_report', normalizedUserId, response?.statusCode, response?.body?.payload?.message);
                const revoked = await handleGatewayAuthError(normalizedUserId, response);
                return { ok: false, revoked, statusCode: response?.statusCode };
            }
            markSuccess('add_or_update_report', normalizedUserId, response.statusCode);
            return { ok: true, revoked: false };
        } catch (error) {
            markFailure('add_or_update_report', normalizedUserId, null, error?.message);
            return { ok: false, revoked: false, error: error?.message };
        }
    }

    // Fire-and-forget wrapper for the dashboard poll (/api/account/me, ~5s).
    // Throttled to once per LIVENESS_PROBE_THROTTLE_MS per user so we don't POST
    // to Amazon on every poll — one probe a minute is plenty to catch a
    // skill-disable. Never blocks the request: returns immediately.
    const LIVENESS_PROBE_THROTTLE_MS = 60000;
    function probeAlexaLinkLivenessThrottled(userId) {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId || !hasAlexaCredentials()) {
            return;
        }
        const last = state.alexaLivenessProbeAt.get(normalizedUserId) || 0;
        const now = Date.now();
        if (now - last < LIVENESS_PROBE_THROTTLE_MS) {
            return;
        }
        state.alexaLivenessProbeAt.set(normalizedUserId, now);
        // Detached — do not await; errors are swallowed inside probeAlexaLinkLiveness.
        void probeAlexaLinkLiveness(normalizedUserId);
    }

    return {
        hasAlexaCredentials,
        getLwaAccessTokenForUser,
        buildProperties,
        scheduleAlexaAddOrUpdateReportForUser,
        scheduleAlexaChangeReportForUser,
        scheduleAlexaDeleteReportForUser,
        deleteEndpointsNow,
        probeAlexaLinkLiveness,
        probeAlexaLinkLivenessThrottled,
        collectAlexaChangeReportsForUser,
        markAlexaReportedStateHashes
    };
};
