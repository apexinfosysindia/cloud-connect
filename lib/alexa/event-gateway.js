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

    async function getLwaAccessTokenForUser(userId, options = {}) {
        const normalizedUserId = Number(userId);
        const forceRefresh = Boolean(options.forceRefresh);
        const cached = state.alexaLwaAccessTokenCache.get(normalizedUserId);
        if (!forceRefresh && cached && cached.token && cached.expiresAt > Date.now() + 30000) {
            return cached.token;
        }
        if (forceRefresh) {
            // Drop any cached access token so we actually hit the LWA refresh
            // endpoint — used when the gateway rejected our cached token (401) and
            // we need to learn whether the underlying grant is still valid.
            state.alexaLwaAccessTokenCache.delete(normalizedUserId);
        }

        // Single-flight: coalesce concurrent refreshes for the same user onto ONE
        // LWA POST. Without this a bulk hide (many concurrent sends) would fire N
        // refreshes at once and get throttled by Amazon. A forceRefresh still joins
        // an in-flight refresh if one is already running (it would produce the same
        // fresh token), avoiding a thundering herd on the 401-reverify path too.
        const inflight = state.alexaLwaRefreshInflight.get(normalizedUserId);
        if (inflight) {
            return inflight;
        }
        const refreshPromise = (async () => doLwaRefresh(normalizedUserId))();
        state.alexaLwaRefreshInflight.set(normalizedUserId, refreshPromise);
        try {
            return await refreshPromise;
        } finally {
            // Clear so the NEXT cache-miss (or a later forceRefresh) starts fresh.
            state.alexaLwaRefreshInflight.delete(normalizedUserId);
        }
    }

    // The actual LWA refresh_token → access_token exchange. Throws on failure
    // (invalid_grant carries .alexaRevoked). Only ever invoked via the single-flight
    // wrapper above, so at most one runs per user at a time.
    async function doLwaRefresh(normalizedUserId) {
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
            const errCode = json?.error || '';
            const error = new Error(`LWA token refresh failed: ${json?.error_description || errCode || res.status}`);
            // invalid_grant on a refresh_token means Amazon revoked the LWA grant
            // (skill disabled / account unlinked in the Alexa app). Surface it as a
            // typed flag so callers can treat it as a revocation and clean up — the
            // refresh throws here instead of returning a 403, so the gateway-response
            // 403 path never sees it.
            if (errCode === 'invalid_grant') {
                error.alexaRevoked = true;
            }
            throw error;
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

    // DeleteReport chunking. MEASURED behavior (user's controlled testing): deleting a
    // SMALL set of endpoints succeeds every time, but a LARGE set (e.g. their 134-tile
    // inventory) in one DeleteReport makes Amazon 500 with INTERNAL_SERVICE_EXCEPTION —
    // a backend *processing* failure (unwiring many devices from groups/routines at
    // once), not a payload-size rejection. (DeleteReport payloads are tiny — just
    // {endpointId} strings — so this is a per-message endpoint-COUNT ceiling, not bytes.)
    // We split a delete into small batches, each its own DeleteReport. ONLY the delete
    // path is chunked: bulk AddOrUpdate/expose works fine and is intentionally untouched.
    const ALEXA_DELETE_MAX_ENDPOINTS_PER_MESSAGE = 30;
    const ALEXA_DELETE_INTER_BATCH_DELAY_MS = 150;

    function chunkArray(arr, size) {
        const out = [];
        for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
        return out;
    }

    // Lazy revocation detection. Amazon sends NO Smart Home directive when a
    // customer disables the skill / unlinks the account in the Alexa app. The
    // revocation surfaces in one of two ways:
    //   (1) a 403 (SKILL_DISABLED_EXCEPTION) when we POST a proactive event, or
    //   (2) an `invalid_grant` thrown while refreshing the LWA access token
    //       (the refresh_token itself was revoked) — this never reaches postEvent,
    //       so it shows up in the senders' catch blocks, not here.
    // Either way we treat the link as revoked and clean up auth data so the portal
    // dashboard reflects the unlink (alexa_linked → 0) on the next load.
    // Revocation detection from a gateway POST response. Amazon signals a
    // disabled/unlinked skill in more than one shape, and NOT always as a 403:
    //   • 403 SKILL_DISABLED_EXCEPTION — the documented disable signal.
    //   • 401 INVALID_ACCESS_TOKEN_EXCEPTION — what we actually observed on a
    //     real Alexa-app skill-disable. BUT a 401 can also just mean our cached
    //     access token went stale, which is recoverable. So on a 401 we don't
    //     nuke the link blindly: we force a fresh LWA refresh. If the refresh
    //     succeeds the token was merely stale (no revocation — caller can ignore);
    //     if it throws invalid_grant the grant is truly gone and we clean up.
    async function handleGatewayAuthError(userId, response) {
        const status = response?.statusCode;
        const code = response?.body?.payload?.code || response?.body?.header?.name;

        // A CONFIRMED disable signal — Amazon explicitly named SKILL_DISABLED_EXCEPTION
        // in the payload — is unambiguous: clean up immediately.
        if (code === 'SKILL_DISABLED_EXCEPTION') {
            return await cleanupRevokedAlexaUser(userId, `status ${status} ${code}`.trim());
        }

        // A BARE 403 (or 401) is ambiguous: it can mean a genuine revocation, but also
        // a wrong-region gateway, throttling, or a transient/stale-token hiccup — none
        // of which should nuke a live link. So for both, re-verify by forcing an LWA
        // refresh and only clean up when that CONFIRMS the grant is gone (invalid_grant).
        // (Previously a bare 403 was treated as an unconditional disable, which let a
        // single transient/misrouted 403 permanently wipe the user's endpoints + tokens.)
        if (status === 403 || status === 401 || code === 'INVALID_ACCESS_TOKEN_EXCEPTION') {
            try {
                // Force a refresh past the cache. Success ⇒ token/grant still valid.
                await getLwaAccessTokenForUser(userId, { forceRefresh: true });
                console.warn(`ALEXA GATEWAY ${status}: token refreshed OK, link still valid for user`, userId);
                return false;
            } catch (error) {
                if (isAlexaRevocationError(error)) {
                    return await cleanupRevokedAlexaUser(userId, `${status} then invalid_grant on refresh`);
                }
                // Some other refresh failure — don't unlink on an ambiguous error.
                console.error(`ALEXA GATEWAY ${status} refresh error (not unlinking):`, error?.message);
                return false;
            }
        }

        return false;
    }

    // Shared cleanup used by both the 403-response path and the invalid_grant
    // (thrown) path. Idempotent — safe to call repeatedly.
    async function cleanupRevokedAlexaUser(userId, reason) {
        try {
            await core.cleanupAlexaAuthDataForUser(userId);
            console.warn('ALEXA GATEWAY REVOKED: cleaned up auth data for user', userId, '-', reason);
        } catch (error) {
            console.error('ALEXA GATEWAY REVOKE CLEANUP ERROR:', error);
        }
        return true;
    }

    // True when a thrown error represents an LWA grant revocation (skill disabled
    // / unlinked in the Alexa app), surfaced as invalid_grant during token refresh.
    function isAlexaRevocationError(error) {
        return Boolean(error?.alexaRevoked);
    }

    function newMessageId() {
        // crypto.randomUUID is available Node 16+; avoid Date for determinism in tests.
        return require('crypto').randomUUID();
    }

    function nowIso() {
        return new Date().toISOString();
    }

    function buildProperties(props) {
        // Stamp each structured AlexaProp tuple {namespace, instance?, name,
        // value} with the Alexa context envelope fields. The namespace/instance
        // are carried in the tuple itself (no namespaceFor lookup) and `value`
        // is already in final wire shape (connectivity pre-wrapped as {value}).
        //
        // Back-compat: a legacy flat {name: value} object is still accepted and
        // mapped via the old namespace table, so older callers/tests keep working.
        const ts = nowIso();
        if (!Array.isArray(props)) {
            const namespaceFor = {
                powerState: 'Alexa.PowerController',
                brightness: 'Alexa.BrightnessController',
                color: 'Alexa.ColorController',
                colorTemperatureInKelvin: 'Alexa.ColorTemperatureController',
                connectivity: 'Alexa.EndpointHealth'
            };
            return Object.entries(props || {}).map(([name, value]) => ({
                namespace: namespaceFor[name] || 'Alexa',
                name,
                value: name === 'connectivity' ? { value } : value,
                timeOfSample: ts,
                uncertaintyInMilliseconds: 0
            }));
        }
        return props.map((p) => ({
            namespace: p.namespace,
            ...(p.instance ? { instance: p.instance } : {}),
            name: p.name,
            value: p.value,
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
                    console.warn('ALEXA ADD_OR_UPDATE FAILED:', {
                        user_id: normalizedUserId,
                        reason,
                        status: response?.statusCode,
                        // Amazon's validation detail (which endpoint/field is malformed) lives
                        // in the response body — log it so a 400 is diagnosable, not opaque.
                        amazonBody: JSON.stringify(response?.body || null)
                    });
                    await handleGatewayAuthError(normalizedUserId, response);
                    return;
                }
                markSuccess('add_or_update_report', normalizedUserId, response.statusCode);
            } catch (error) {
                markFailure('add_or_update_report', normalizedUserId, null, error?.message);
                console.error('ALEXA ADD_OR_UPDATE ERROR:', error);
                if (isAlexaRevocationError(error)) {
                    await cleanupRevokedAlexaUser(normalizedUserId, 'invalid_grant on add_or_update');
                }
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
            // Exclusion gate: only endpoints that Discovery would surface can be
            // change-reported. Drops unmapped/Tier-D types that may linger in the
            // table (e.g. pushed before the gate existed) instead of emitting
            // ChangeReports for endpoints Alexa never received.
            if (!entityMapping.buildAlexaEndpoint(row)) continue;
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
            const changeProps = allProps.filter((p) => p.namespace !== 'Alexa.EndpointHealth');
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
                    properties: allProps.filter((p) => p.namespace === 'Alexa.EndpointHealth')
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
                if (isAlexaRevocationError(error)) {
                    await cleanupRevokedAlexaUser(normalizedUserId, 'invalid_grant on change_report');
                }
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

        // Chunked: a large delete (bulk hide / unlink of a big inventory) in ONE
        // DeleteReport overwhelms Amazon's bulk-delete processing → 500
        // INTERNAL_SERVICE_EXCEPTION, while small deletes always land. Split into
        // batches of ALEXA_DELETE_MAX_ENDPOINTS_PER_MESSAGE, each its own event, with a
        // short gap between. Token is fetched ONCE above and reused for every chunk.
        const batches = chunkArray(ids, ALEXA_DELETE_MAX_ENDPOINTS_PER_MESSAGE);
        const buildEvent = (batch) => ({
            event: {
                header: {
                    namespace: 'Alexa.Discovery',
                    name: 'DeleteReport',
                    payloadVersion: '3',
                    messageId: newMessageId()
                },
                payload: {
                    endpoints: batch.map((endpointId) => ({ endpointId })),
                    scope: { type: 'BearerToken', token: accessToken }
                }
            }
        });

        // Fast path: a single batch (≤ max, incl. the common one-endpoint hide) behaves
        // byte-for-byte like the old single-payload send.
        if (batches.length === 1) {
            return await postEvent(accessToken, buildEvent(batches[0]));
        }

        // AND-gate: the overall delete is ok ONLY if EVERY chunk lands. We still post
        // all chunks (clear the maximum number of tiles this pass), but remember the
        // FIRST failure to return — so the existing retry path + metrics react exactly
        // as for a single failed send, and (critically) the unlink gate in
        // runGatedUnlinkOnce keys off ok=false and will NOT disable the skill until a
        // pass deletes every tile. Re-deleting already-gone tiles on a retry is a
        // harmless no-op at Amazon.
        let allOk = true;
        let firstFailure = null;
        for (let i = 0; i < batches.length; i += 1) {
            const resp = await postEvent(accessToken, buildEvent(batches[i]));
            if (!resp.ok) {
                allOk = false;
                if (!firstFailure) firstFailure = resp;
            }
            if (i < batches.length - 1) {
                await new Promise((r) => setTimeout(r, ALEXA_DELETE_INTER_BATCH_DELAY_MS));
            }
        }
        return allOk ? { ok: true, statusCode: 202, body: null } : firstFailure;
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

    // Read ALL of a user's current Alexa endpoint ids and DeleteReport them to Amazon,
    // NOW (awaited, best-effort). Used right before something deletes the underlying
    // rows — e.g. "sign out of all devices" cascade-deletes alexa_endpoints via the
    // devices FK, which would otherwise orphan those tiles in the Alexa app forever
    // (no later report can name an entity_id we no longer have). Must run while the
    // rows AND the LWA token still exist. Returns the deleteEndpointsNow result/skip.
    async function deleteAllEndpointsForUserNow(userId, reason = 'bulk_delete') {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId || !hasAlexaCredentials()) {
            return { skipped: true, reason: 'credentials_disabled' };
        }
        let endpointIds = [];
        try {
            const rows = await core.getAlexaEndpointsForUser(normalizedUserId, { includeDisabled: true });
            endpointIds = (rows || []).map((r) => r.entity_id).filter(Boolean);
        } catch (error) {
            console.warn('ALEXA deleteAllEndpointsForUserNow read failed:', error?.message);
            return { skipped: true, reason: 'read_failed' };
        }
        if (endpointIds.length === 0) {
            return { skipped: true, reason: 'no_endpoints' };
        }
        return await deleteEndpointsNow(normalizedUserId, endpointIds, reason);
    }

    // Derive the Skill Management host (e.g. https://api.eu.amazonalexa.com) from the
    // configured Event Gateway URL, so the disable-enablement call hits the SAME region
    // the skill is published in (NA/EU/FE). Amazon requires the same regional endpoint
    // used for enable/link.
    function alexaApiOrigin() {
        try {
            return new URL(config.ALEXA_EVENT_GATEWAY_URL).origin;
        } catch (_e) {
            return 'https://api.amazonalexa.com';
        }
    }

    // Disable the skill + unlink the account for THIS customer at Amazon, using the
    // customer's own LWA access token (the AcceptGrant token, scope
    // alexa::skills:account_linking). DELETE /v1/users/~current/skills/{id}/enablement.
    // This is what actually stops Amazon's "relink your account" nag — revoking only our
    // own tokens leaves the skill enabled, so Amazon's failed refresh prompts a relink.
    // Best-effort, never throws. MUST run before cleanupAlexaAuthDataForUser wipes the
    // LWA token. Returns { ok, status } | { skipped, reason }.
    async function disableSkillForUser(userId, reason = 'portal_unlink') {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId || !hasAlexaCredentials()) {
            return { skipped: true, reason: 'credentials_disabled' };
        }
        if (!config.ALEXA_SKILL_ID) {
            return { skipped: true, reason: 'no_skill_id' };
        }
        let accessToken;
        try {
            accessToken = await getLwaAccessTokenForUser(normalizedUserId);
        } catch (error) {
            // invalid_grant here just means the grant is already gone — nothing to disable.
            return { skipped: true, reason: 'no_lwa_token', detail: error?.message };
        }
        if (!accessToken) {
            return { skipped: true, reason: 'no_lwa_token' };
        }
        const url = `${alexaApiOrigin()}/v1/users/~current/skills/${encodeURIComponent(config.ALEXA_SKILL_ID)}/enablement`;
        try {
            const res = await fetch(url, {
                method: 'DELETE',
                headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' }
            });
            // 204 = disabled+unlinked. 401/403 = token lacks the account_linking scope
            // (fall back to the in-app instruction). 404 = already not enabled (fine).
            const ok = res.status === 204 || res.status === 404;
            if (ok) {
                console.warn('ALEXA SKILL DISABLE: ok for user', normalizedUserId, 'status', res.status, 'reason', reason);
            } else {
                console.warn('ALEXA SKILL DISABLE: non-ok for user', normalizedUserId, 'status', res.status, '(falling back to in-app unlink instruction)');
            }
            return { ok, status: res.status };
        } catch (error) {
            console.error('ALEXA SKILL DISABLE ERROR:', error?.message);
            return { ok: false, error: error?.message };
        }
    }

    // Try to COMPLETE a gated unlink once: DeleteReport all the user's endpoints;
    // only if that lands do we disable the skill at Amazon + wipe our tokens. This
    // is the same gated sequence the portal unlink route runs inline, factored out
    // so the retry timer can reuse it. Returns { done:true } when the unlink fully
    // completed, or { done:false, reason } when the delete didn't land (caller may
    // retry later). Best-effort; never throws.
    async function completeUnlinkNow(userId, reason = 'unlink_retry') {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId) {
            return { done: false, reason: 'bad_user' };
        }
        const del = await deleteAllEndpointsForUserNow(normalizedUserId, reason);
        // A skip with no endpoints means there's nothing left to delete → treat as done.
        if (del?.skipped && del.reason === 'no_endpoints') {
            await disableSkillForUser(normalizedUserId, reason).catch(() => {});
            await core.cleanupAlexaAuthDataForUser(normalizedUserId);
            cancelAlexaUnlinkRetry(normalizedUserId);
            return { done: true, reason: 'no_endpoints' };
        }
        if (!del?.ok) {
            return { done: false, reason: del?.reason || `status_${del?.statusCode || 'unknown'}` };
        }
        // Tiles gone — finish the unlink.
        await disableSkillForUser(normalizedUserId, reason).catch(() => {});
        await core.cleanupAlexaAuthDataForUser(normalizedUserId);
        cancelAlexaUnlinkRetry(normalizedUserId);
        return { done: true };
    }

    // Single-flight, GATED unlink for ONE portal click. Enforces the invariant the
    // user cares about: NEVER disable the skill or wipe tokens until Amazon has
    // CONFIRMED (HTTP 202) the DeleteReport — so no orphaned tiles can linger in the
    // Alexa app. Two simultaneous Unlink clicks JOIN the same in-flight promise
    // instead of racing: without this lock, one click's cleanup (token wipe) can
    // land mid-flight under the other click's DeleteReport, which both fails the
    // delete (the 401-token-aged-under-flight we observed) AND orphans the tiles.
    //
    //   (1) DeleteReport all endpoints → if NOT confirmed ok, STOP (keep link, no disable)
    //   (2) disableSkillForUser        → only reached once (1) is confirmed
    //   (3) cleanupAlexaAuthDataForUser → wipe our tokens LAST
    //
    // Returns { tiles_cleared:true } on a full clean unlink, or
    // { tiles_cleared:false, reason } when the delete didn't land (caller keeps the
    // link, pauses it, and schedules a background retry). Never throws.
    function runGatedUnlinkOnce(userId, reason = 'portal_unlink') {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId) {
            return Promise.resolve({ tiles_cleared: false, reason: 'bad_user' });
        }
        // Single-flight: a second simultaneous click rides the first click's promise.
        const inflight = state.alexaUnlinkInflight.get(normalizedUserId);
        if (inflight) {
            return inflight;
        }
        const op = (async () => {
            let deleteOk = true; // default true so a no-endpoints unlink still disables+cleans
            try {
                const rows = await core.getAlexaEndpointsForUser(normalizedUserId, { includeDisabled: true });
                const endpointIds = (rows || []).map((r) => r.entity_id).filter(Boolean);
                if (endpointIds.length > 0) {
                    // One immediate attempt + one short retry — a transient gateway 5xx
                    // (Amazon's INTERNAL_SERVICE_EXCEPTION) often clears on the next try.
                    let resp = await deleteEndpointsNow(normalizedUserId, endpointIds, reason);
                    if (!resp?.ok && !resp?.skipped) {
                        await new Promise((r) => setTimeout(r, 750));
                        resp = await deleteEndpointsNow(normalizedUserId, endpointIds, `${reason}_retry`);
                    }
                    // A skip (no creds / no token) is NOT a delivered delete → not-ok.
                    deleteOk = Boolean(resp?.ok);
                }
            } catch (error) {
                console.warn('ALEXA UNLINK DELETE_REPORT error:', error?.message);
                deleteOk = false;
            }
            if (!deleteOk) {
                // GATE: the delete did NOT land. Do NOT disable the skill or wipe
                // tokens — that would orphan the tiles permanently. Keep the link.
                return { tiles_cleared: false, reason: 'delete_not_landed' };
            }
            // Tiles confirmed gone — safe to disable the skill + wipe our tokens.
            try {
                await disableSkillForUser(normalizedUserId, reason);
            } catch (error) {
                console.warn('ALEXA UNLINK skill-disable skipped:', error?.message);
            }
            try {
                await core.cleanupAlexaAuthDataForUser(normalizedUserId);
            } catch (error) {
                // Tiles ARE gone from Alexa (the gate passed); only our local cleanup
                // failed. Report not-cleared so the caller keeps the link + schedules a
                // retry, which re-runs cleanup (delete is a no-op by then). Self-heals.
                console.warn('ALEXA UNLINK cleanup failed; will retry:', error?.message);
                return { tiles_cleared: false, reason: 'cleanup_failed' };
            }
            cancelAlexaUnlinkRetry(normalizedUserId);
            return { tiles_cleared: true };
        })();
        state.alexaUnlinkInflight.set(normalizedUserId, op);
        // Clear the single-flight slot once settled, regardless of outcome.
        const clearSlot = () => state.alexaUnlinkInflight.delete(normalizedUserId);
        op.then(clearSlot, clearSlot);
        return op;
    }

    // Backoff schedule (ms) for retrying a stuck unlink. The DeleteReport failure
    // is Amazon's transient INTERNAL_SERVICE_EXCEPTION (their gateway flaking under
    // rapid/simultaneous load — confirmed via captured response bodies), which
    // clears on its own within seconds-to-minutes. Front-loaded so a single click
    // recovers fast (first retry at 5s, not 60s — the old 60s start felt dead and
    // drove users to re-click), with a long tail (3m) to outlast a longer flap.
    // ~5.4 min total across 4 attempts, then give up (manual Unlink still works).
    const ALEXA_UNLINK_RETRY_DELAYS_MS = [5_000, 20_000, 60_000, 180_000];

    function cancelAlexaUnlinkRetry(userId) {
        const id = utils.parsePositiveInt(userId);
        if (!id) return;
        const existing = state.alexaUnlinkRetryQueue.get(id);
        if (existing?.timer) clearTimeout(existing.timer);
        state.alexaUnlinkRetryQueue.delete(id);
    }

    // Schedule (or re-schedule) a background attempt to finish a gated unlink whose
    // DeleteReport didn't land. In-memory + unref'd, mirroring the other Alexa
    // schedulers; lost on restart (acceptable — the manual Unlink button still works).
    function scheduleAlexaUnlinkRetry(userId, attempt = 0) {
        const id = utils.parsePositiveInt(userId);
        if (!id || !hasAlexaCredentials()) return;
        if (attempt >= ALEXA_UNLINK_RETRY_DELAYS_MS.length) {
            console.warn('ALEXA UNLINK RETRY: gave up after', attempt, 'attempts for user', id, '(link kept; user can retry manually)');
            state.alexaUnlinkRetryQueue.delete(id);
            return;
        }
        const existing = state.alexaUnlinkRetryQueue.get(id);
        if (existing?.timer) clearTimeout(existing.timer);
        const delay = ALEXA_UNLINK_RETRY_DELAYS_MS[attempt];
        const timer = setTimeout(async () => {
            state.alexaUnlinkRetryQueue.delete(id);
            try {
                // Only retry if the link is still in the "pending unlink" shape: kept
                // linked but paused (enabled=0). If the user re-linked or it was already
                // cleaned, abort.
                const user = await dbGet(`SELECT alexa_linked, alexa_enabled FROM users WHERE id = ?`, [id]);
                if (!user || !user.alexa_linked || user.alexa_enabled) {
                    return; // no longer pending-unlink
                }
                const res = await completeUnlinkNow(id, `unlink_retry_${attempt + 1}`);
                if (res.done) {
                    console.warn('ALEXA UNLINK RETRY: completed on attempt', attempt + 1, 'for user', id);
                } else {
                    console.warn('ALEXA UNLINK RETRY: attempt', attempt + 1, 'still failing for user', id, '-', res.reason, '— rescheduling');
                    scheduleAlexaUnlinkRetry(id, attempt + 1);
                }
            } catch (error) {
                console.error('ALEXA UNLINK RETRY ERROR for user', id, error?.message);
                scheduleAlexaUnlinkRetry(id, attempt + 1);
            }
        }, delay);
        if (typeof timer.unref === 'function') timer.unref();
        state.alexaUnlinkRetryQueue.set(id, { timer, attempt });
    }

    // Awaitable, NON-debounced DoorbellPress. A doorbell press is instantaneous
    // and must reach Alexa immediately (the debounced schedulers would coalesce
    // and delay it), so this posts directly like deleteEndpointsNow. Best-effort:
    // records metrics, never throws. Returns the postEvent result or a skip.
    async function sendDoorbellPressEvent(userId, endpointId) {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId || !endpointId || !hasAlexaCredentials()) {
            return { skipped: true, reason: 'credentials_disabled' };
        }
        try {
            const user = await dbGet(`SELECT id, alexa_enabled, alexa_linked FROM users WHERE id = ?`, [
                normalizedUserId
            ]);
            if (!user || !user.alexa_enabled || !user.alexa_linked) {
                markSkipped('doorbell_event', normalizedUserId, 'not_linked');
                return { skipped: true, reason: 'not_linked' };
            }
            const accessToken = await getLwaAccessTokenForUser(normalizedUserId);
            if (!accessToken) {
                markSkipped('doorbell_event', normalizedUserId, 'no_lwa_token');
                return { skipped: true, reason: 'no_lwa_token' };
            }
            const event = {
                event: {
                    header: {
                        namespace: 'Alexa.DoorbellEventSource',
                        name: 'DoorbellPress',
                        payloadVersion: '3',
                        messageId: newMessageId()
                    },
                    endpoint: {
                        scope: { type: 'BearerToken', token: accessToken },
                        endpointId
                    },
                    payload: {
                        cause: { type: 'PHYSICAL_INTERACTION' },
                        timestamp: nowIso()
                    }
                }
            };
            const response = await postEvent(accessToken, event);
            if (!response?.ok) {
                markFailure('doorbell_event', normalizedUserId, response?.statusCode, response?.body?.payload?.message);
                console.warn('ALEXA DOORBELL FAILED:', { user_id: normalizedUserId, endpointId, status: response?.statusCode });
                await handleGatewayAuthError(normalizedUserId, response);
                return response;
            }
            markSuccess('doorbell_event', normalizedUserId, response.statusCode);
            return response;
        } catch (error) {
            markFailure('doorbell_event', normalizedUserId, null, error?.message);
            console.error('ALEXA DOORBELL ERROR:', error);
            if (isAlexaRevocationError(error)) {
                await cleanupRevokedAlexaUser(normalizedUserId, 'invalid_grant on doorbell');
            }
            return { ok: false, error: error?.message };
        }
    }

    // Backoff for retrying a hide/expose DeleteReport that didn't land. Same reason
    // as the unlink retry: Amazon's enablement state is eventually-consistent, so a
    // bulk-hide during churn can 500/SKILL_DISABLED and needs a few retries to clear.
    const ALEXA_DELETE_RETRY_DELAYS_MS = [45_000, 120_000, 300_000];

    function scheduleAlexaDeleteReportForUser(userId, endpointIds, reason = 'delete', attempt = 0) {
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
            const retryDelete = () => {
                if (attempt + 1 >= ALEXA_DELETE_RETRY_DELAYS_MS.length) {
                    console.warn('ALEXA DELETE_REPORT: gave up after', attempt + 1, 'attempts for user', normalizedUserId, '(', toDelete.length, 'tiles may linger; user can re-hide)');
                    return;
                }
                console.warn('ALEXA DELETE_REPORT: attempt', attempt + 1, 'did not land for user', normalizedUserId, '— retrying', toDelete.length, 'tiles');
                // Re-schedule the SAME ids. Pass attempt+1 and let the scheduler set a
                // backoff timer; merge with any ids hidden in the meantime.
                const rt = setTimeout(() => {
                    scheduleAlexaDeleteReportForUser(normalizedUserId, toDelete, reason, attempt + 1);
                }, ALEXA_DELETE_RETRY_DELAYS_MS[attempt]);
                if (typeof rt.unref === 'function') rt.unref();
            };
            try {
                const response = await sendDeleteReport(normalizedUserId, toDelete);
                if (response?.skipped) {
                    markSkipped('delete_report', normalizedUserId, response.reason);
                    // A 'no_lwa_token' skip is TRANSIENT — the LWA token refresh failed
                    // (throttle / temporary auth hiccup), which is the real reason a bulk
                    // hide leaves tiles uncleared. The token usually recovers, so retry.
                    // Other skips (credentials_disabled, no_endpoints) are terminal.
                    if (response.reason === 'no_lwa_token') {
                        retryDelete();
                    }
                    return;
                }
                if (!response?.ok) {
                    markFailure('delete_report', normalizedUserId, response?.statusCode, response?.body?.payload?.message);
                    // NOTE: do NOT route this through handleGatewayAuthError. A failed
                    // DeleteReport during hide/expose is usually Amazon's enablement
                    // state still converging (SKILL_DISABLED) — treating it as a
                    // revocation would wipe the whole link. Just retry the delete.
                    retryDelete();
                    return;
                }
                markSuccess('delete_report', normalizedUserId, response.statusCode);
            } catch (error) {
                markFailure('delete_report', normalizedUserId, null, error?.message);
                console.error('ALEXA DELETE_REPORT ERROR:', error);
                retryDelete();
            }
        }, getAddOrUpdateDebounceMs());
        if (typeof timer.unref === 'function') timer.unref();
        state.alexaDeleteReportQueue.set(normalizedUserId, { reason, timer, endpointIds: ids });
    }

    // Liveness probe used by the dashboard to detect an Alexa-app skill-disable
    // promptly. Amazon sends no directive on disable; the signal is an auth error
    // on a proactive POST — observed in practice as 401 INVALID_ACCESS_TOKEN_EXCEPTION
    // (and documented as 403 SKILL_DISABLED_EXCEPTION). We fire one idempotent
    // AddOrUpdateReport and let handleGatewayAuthError verify + flip alexa_linked → 0.
    // Returns { revoked: true } when the link was found dead.
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
            // A skill-disable surfaces as invalid_grant thrown during the LWA token
            // refresh (it never reaches postEvent, so the 403 response path inside
            // handleGatewayAuthError never sees it). This catch is the dashboard's
            // actual detection path — clean up here so alexa_linked flips to 0.
            if (isAlexaRevocationError(error)) {
                await cleanupRevokedAlexaUser(normalizedUserId, 'invalid_grant on liveness_probe');
                return { ok: false, revoked: true, error: error?.message };
            }
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
        deleteAllEndpointsForUserNow,
        disableSkillForUser,
        completeUnlinkNow,
        runGatedUnlinkOnce,
        scheduleAlexaUnlinkRetry,
        cancelAlexaUnlinkRetry,
        sendDoorbellPressEvent,
        probeAlexaLinkLiveness,
        probeAlexaLinkLivenessThrottled,
        collectAlexaChangeReportsForUser,
        markAlexaReportedStateHashes
    };
};
