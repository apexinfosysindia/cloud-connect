const https = require('https');
const crypto = require('crypto');
const { recordAppEvent } = require('../server-state');

module.exports = function ({ dbGet, dbRun, dbAll, config, utils, state, entityMapping }) {
    // Append one event to the recent-events ring buffer (newest last), capped so it
    // never grows unbounded. In-memory + volatile — a debugging log stream for the
    // admin card, NOT durable history.
    const HOMEGRAPH_RECENT_EVENTS_CAP = 200;
    function pushHomegraphRecent(type, outcome, userId, statusCode, detail) {
        const buf = state.homegraphRecent;
        if (!buf) return;
        buf.push({
            at: new Date().toISOString(),
            type,
            outcome,
            user_id: userId != null ? utils.sanitizeString(String(userId), 120) : null,
            status: statusCode || null,
            detail: detail ? utils.sanitizeString(detail, 300) : null
        });
        if (buf.length > HOMEGRAPH_RECENT_EVENTS_CAP) buf.splice(0, buf.length - HOMEGRAPH_RECENT_EVENTS_CAP);
    }

    function markHomegraphMetricSuccess(metricType, userId, statusCode = null) {
        const metric = state.homegraphMetrics[metricType];
        if (!metric) {
            return;
        }

        metric.sent += 1;
        metric.last_success_at = new Date().toISOString();
        metric.last_status = statusCode;
        metric.last_user_id = utils.sanitizeString(userId, 120) || null;
        pushHomegraphRecent(metricType, 'sent', userId, statusCode, null);
    }

    function markHomegraphMetricFailure(metricType, userId, statusCode = null, reason = null) {
        const metric = state.homegraphMetrics[metricType];
        if (!metric) {
            return;
        }

        metric.failed += 1;
        metric.last_failure_at = new Date().toISOString();
        metric.last_status = statusCode;
        metric.last_failure_reason = utils.sanitizeString(reason, 300) || 'unknown_error';
        metric.last_user_id = utils.sanitizeString(userId, 120) || null;
        pushHomegraphRecent(metricType, 'failed', userId, statusCode, reason || 'unknown_error');
        recordAppEvent('warn', 'google-homegraph', `${metricType} failed`, { user_id: utils.sanitizeString(String(userId), 120), status: statusCode || null, reason: reason || 'unknown_error' });
    }

    function markHomegraphMetricSkipped(metricType, userId, reason = null) {
        const metric = state.homegraphMetrics[metricType];
        if (!metric) {
            return;
        }

        metric.skipped += 1;
        metric.last_status = null;
        metric.last_user_id = utils.sanitizeString(userId, 120) || null;
        if (reason) {
            metric.last_failure_reason = utils.sanitizeString(reason, 300) || metric.last_failure_reason;
        }
        pushHomegraphRecent(metricType, 'skipped', userId, null, reason || null);
    }

    function getGoogleHomegraphDebounceMs(value, fallback, min, max) {
        if (!Number.isFinite(value)) {
            return fallback;
        }

        return Math.max(min, Math.min(max, Math.round(value)));
    }

    function getGoogleHomegraphRequestSyncDebounceMs() {
        return getGoogleHomegraphDebounceMs(config.GOOGLE_HOMEGRAPH_REQUEST_SYNC_DEBOUNCE_MS, 2500, 250, 30000);
    }

    function getGoogleHomegraphReportStateDebounceMs() {
        return getGoogleHomegraphDebounceMs(config.GOOGLE_HOMEGRAPH_REPORT_STATE_DEBOUNCE_MS, 1200, 250, 10000);
    }

    // Backoff (ms) for re-attempting a ReportState that got a 404 ("Device ID cannot
    // be found") — HomeGraph hasn't finished registering the devices yet after the
    // initial RequestSync. Registration is eventually-consistent and can take a few
    // seconds, so we re-fire a RequestSync and re-schedule the report after a growing
    // delay rather than retrying immediately (which just 404s again). After the last
    // attempt we give up and record the failure honestly.
    const GOOGLE_REPORT_STATE_404_BACKOFF_MS = [5000, 15000, 30000];

    function getGoogleServiceAccountClientEmail() {
        return utils.sanitizeString(
            process.env.GOOGLE_SERVICE_ACCOUNT_CLIENT_EMAIL || process.env.GOOGLE_HOMEGRAPH_CLIENT_EMAIL || '',
            320
        );
    }

    function getGoogleServiceAccountPrivateKey() {
        const direct = utils.sanitizeString(
            process.env.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY || process.env.GOOGLE_HOMEGRAPH_PRIVATE_KEY || '',
            8192
        );
        if (direct) {
            return direct.replace(/\\n/g, '\n');
        }

        const base64Value = utils.sanitizeString(
            process.env.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY_B64 || process.env.GOOGLE_HOMEGRAPH_PRIVATE_KEY_B64 || '',
            12000
        );
        if (!base64Value) {
            return null;
        }

        try {
            return Buffer.from(base64Value, 'base64').toString('utf8').replace(/\\n/g, '\n');
        } catch (_error) {
            return null;
        }
    }

    function getGoogleHomegraphTokenUri() {
        const configured = utils.sanitizeString(process.env.GOOGLE_HOMEGRAPH_TOKEN_URI || '', 800);
        return configured || config.GOOGLE_HOMEGRAPH_DEFAULT_TOKEN_URI;
    }

    function getGoogleHomegraphApiBaseUrl() {
        const configured = utils.sanitizeString(process.env.GOOGLE_HOMEGRAPH_API_BASE_URL || '', 800);
        return configured || config.GOOGLE_HOMEGRAPH_API_BASE_URL;
    }

    function hasGoogleHomegraphCredentials() {
        return Boolean(getGoogleServiceAccountClientEmail() && getGoogleServiceAccountPrivateKey());
    }

    function getGoogleHomegraphJwtLifetimeSeconds() {
        return 3600;
    }

    function base64UrlEncodeJson(value) {
        return Buffer.from(JSON.stringify(value)).toString('base64url');
    }

    function generateGoogleServiceJwtAssertion() {
        const clientEmail = getGoogleServiceAccountClientEmail();
        const privateKey = getGoogleServiceAccountPrivateKey();
        if (!clientEmail || !privateKey) {
            return null;
        }

        const tokenUri = getGoogleHomegraphTokenUri();
        const now = Math.floor(Date.now() / 1000);
        const iat = now - 5;
        const exp = iat + getGoogleHomegraphJwtLifetimeSeconds();

        const header = {
            alg: 'RS256',
            typ: 'JWT'
        };

        const payload = {
            iss: clientEmail,
            scope: config.GOOGLE_HOMEGRAPH_SCOPE,
            aud: tokenUri,
            iat,
            exp
        };

        const encodedHeader = base64UrlEncodeJson(header);
        const encodedPayload = base64UrlEncodeJson(payload);
        const signingInput = `${encodedHeader}.${encodedPayload}`;
        const signer = crypto.createSign('RSA-SHA256');
        signer.update(signingInput);
        signer.end();
        const signature = signer.sign(privateKey, 'base64url');
        return `${signingInput}.${signature}`;
    }

    function normalizeJsonForHash(value) {
        if (value === null || value === undefined) {
            return value;
        }

        if (Array.isArray(value)) {
            return value.map((item) => normalizeJsonForHash(item));
        }

        if (typeof value === 'object') {
            const sorted = {};
            const keys = Object.keys(value).sort();
            for (const key of keys) {
                sorted[key] = normalizeJsonForHash(value[key]);
            }
            return sorted;
        }

        return value;
    }

    function computeGoogleStateHash(value) {
        const normalized = normalizeJsonForHash(value || {});
        return crypto.createHash('sha1').update(JSON.stringify(normalized)).digest('hex');
    }

    async function fetchGoogleAccessTokenForHomegraph() {
        const now = Date.now();
        if (
            state.googleHomegraphAccessTokenCache.token &&
            state.googleHomegraphAccessTokenCache.expiresAt > now + 60 * 1000
        ) {
            return state.googleHomegraphAccessTokenCache.token;
        }

        const assertion = generateGoogleServiceJwtAssertion();
        if (!assertion) {
            return null;
        }

        const tokenUri = new URL(getGoogleHomegraphTokenUri());
        const postBody = new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            assertion
        }).toString();

        const tokenPayload = await new Promise((resolve, reject) => {
            const request = https.request(
                {
                    protocol: tokenUri.protocol,
                    hostname: tokenUri.hostname,
                    port: tokenUri.port || (tokenUri.protocol === 'https:' ? 443 : 80),
                    path: `${tokenUri.pathname}${tokenUri.search || ''}`,
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Content-Length': Buffer.byteLength(postBody),
                        Accept: 'application/json'
                    },
                    // Force IPv4 — see note in postToGoogleHomegraph. The token
                    // endpoint (oauth2.googleapis.com) has the same broken-IPv6
                    // path on this host, so the JWT exchange would hang too.
                    family: 4,
                    timeout: 10000
                },
                (response) => {
                    const chunks = [];
                    response.on('data', (chunk) => chunks.push(chunk));
                    response.on('end', () => {
                        const raw = Buffer.concat(chunks).toString('utf8');
                        const parsed = utils.parseJsonSafe(raw, null);
                        const isSuccess = response.statusCode >= 200 && response.statusCode < 300;
                        if (!isSuccess) {
                            const errorText =
                                parsed?.error_description || parsed?.error || `status_${response.statusCode || 0}`;
                            reject(new Error(`HOMEGRAPH TOKEN ERROR: ${errorText}`));
                            return;
                        }

                        resolve(parsed || {});
                    });
                }
            );

            request.on('error', reject);
            request.on('timeout', () => request.destroy(new Error('HOMEGRAPH TOKEN REQUEST TIMEOUT')));
            request.write(postBody);
            request.end();
        });

        const accessToken = utils.sanitizeString(tokenPayload?.access_token, 4000);
        if (!accessToken) {
            return null;
        }

        const expiresIn = Number(tokenPayload?.expires_in);
        const ttlMs = Number.isFinite(expiresIn)
            ? Math.max(60, Math.min(3600, Math.round(expiresIn))) * 1000
            : 3300 * 1000;
        state.googleHomegraphAccessTokenCache = {
            token: accessToken,
            expiresAt: Date.now() + ttlMs
        };

        return accessToken;
    }

    async function postToGoogleHomegraph(pathname, payload) {
        if (!hasGoogleHomegraphCredentials()) {
            return { ok: false, skipped: true, reason: 'missing_credentials' };
        }

        const accessToken = await fetchGoogleAccessTokenForHomegraph();
        if (!accessToken) {
            return { ok: false, skipped: true, reason: 'missing_access_token' };
        }

        const baseUrl = new URL(getGoogleHomegraphApiBaseUrl());
        const endpoint = new URL(pathname, `${baseUrl.origin}/`);
        endpoint.search = baseUrl.search;
        const bodyText = JSON.stringify(payload || {});

        return new Promise((resolve, reject) => {
            const request = https.request(
                {
                    protocol: endpoint.protocol,
                    hostname: endpoint.hostname,
                    port: endpoint.port || (endpoint.protocol === 'https:' ? 443 : 80),
                    path: `${endpoint.pathname}${endpoint.search || ''}`,
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Content-Length': Buffer.byteLength(bodyText),
                        Authorization: `Bearer ${accessToken}`,
                        Accept: 'application/json'
                    },
                    // Force IPv4: the production host has broken IPv6 egress to
                    // googleapis.com (AAAA resolves but the route blackholes), and
                    // Node's https resolver tries IPv6 first → every request hung
                    // until the 10s timeout. IPv4 connects in ~0.35s.
                    family: 4,
                    timeout: 10000
                },
                (response) => {
                    const chunks = [];
                    response.on('data', (chunk) => chunks.push(chunk));
                    response.on('end', () => {
                        const raw = Buffer.concat(chunks).toString('utf8');
                        const parsed = utils.parseJsonSafe(raw, null);
                        const isSuccess = response.statusCode >= 200 && response.statusCode < 300;

                        if (!isSuccess && response.statusCode === 401) {
                            state.googleHomegraphAccessTokenCache = { token: null, expiresAt: 0 };
                        }

                        if (!isSuccess) {
                            const apiError =
                                parsed?.error?.message ||
                                parsed?.error_description ||
                                parsed?.error ||
                                `status_${response.statusCode || 0}`;
                            resolve({ ok: false, statusCode: response.statusCode, error: apiError });
                            return;
                        }

                        resolve({ ok: true, statusCode: response.statusCode, payload: parsed || {} });
                    });
                }
            );

            request.on('error', reject);
            request.on('timeout', () => request.destroy(new Error('HOMEGRAPH API REQUEST TIMEOUT')));
            request.write(bodyText);
            request.end();
        });
    }

    async function sendGoogleRequestSync(agentUserId, options = {}) {
        const normalized = utils.sanitizeString(agentUserId, 120);
        if (!normalized) {
            return { ok: false, skipped: true, reason: 'invalid_agent_user_id' };
        }

        // async:false makes Google deliver the SYNC to our fulfillment before the
        // requestSync HTTP call returns. The unlink flow relies on this so it can
        // await the empty-device SYNC (devices removed) BEFORE revoking the token.
        const useAsync = options.sync ? false : true;
        return await postToGoogleHomegraph('/v1/devices:requestSync', {
            agentUserId: normalized,
            async: useAsync
        });
    }

    async function sendGoogleReportState(agentUserId, statesByEntityId, requestId = null) {
        const normalized = utils.sanitizeString(agentUserId, 120);
        if (!normalized) {
            return { ok: false, skipped: true, reason: 'invalid_agent_user_id' };
        }

        const payload = {
            requestId:
                utils.sanitizeGoogleRequestId(requestId) || `rs_${Date.now()}_${Math.floor(Math.random() * 10000)}`,
            agentUserId: normalized,
            payload: {
                devices: {
                    states: statesByEntityId || {}
                }
            }
        };

        // NOTE: a 404 here ("Device ID cannot be found") means HomeGraph hasn't
        // finished registering the devices yet — it races ahead of the initial
        // RequestSync after a link/restart. We do NOT retry inline: HomeGraph
        // registration is eventually-consistent (it can take seconds), so an
        // immediate re-send just 404s again. The scheduler
        // (scheduleGoogleReportStateForUser) handles a 404 by firing a RequestSync
        // and RE-SCHEDULING this report with a backoff delay, so Google has time to
        // catch up before we try again.
        return await postToGoogleHomegraph('/v1/devices:reportStateAndNotification', payload);
    }

    function scheduleGoogleRequestSyncForUser(userId, reason = 'change') {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId || !hasGoogleHomegraphCredentials()) {
            return;
        }

        const existing = state.googleHomegraphRequestSyncQueue.get(normalizedUserId);
        const now = Date.now();
        if (existing?.timer) {
            clearTimeout(existing.timer);
        }

        const scheduledAt = now;
        const timer = setTimeout(async () => {
            state.googleHomegraphRequestSyncQueue.delete(normalizedUserId);

            try {
                const user = await dbGet(`SELECT id, google_home_enabled, google_home_linked FROM users WHERE id = ?`, [
                    normalizedUserId
                ]);
                if (!user || !user.google_home_enabled || !user.google_home_linked) {
                    return;
                }

                const response = await sendGoogleRequestSync(String(normalizedUserId));
                if (!response?.ok && !response?.skipped) {
                    markHomegraphMetricFailure(
                        'request_sync',
                        String(normalizedUserId),
                        response.statusCode || null,
                        response.error || null
                    );
                    console.warn('GOOGLE REQUEST SYNC FAILED:', {
                        user_id: normalizedUserId,
                        reason,
                        error: response.error || null,
                        status: response.statusCode || null
                    });
                    return;
                }

                if (response?.skipped) {
                    markHomegraphMetricSkipped('request_sync', String(normalizedUserId), response.reason || null);
                    return;
                }

                markHomegraphMetricSuccess('request_sync', String(normalizedUserId), response?.statusCode || null);

                console.log('GOOGLE REQUEST SYNC SENT:', {
                    user_id: normalizedUserId,
                    reason,
                    queued_for_ms: Date.now() - scheduledAt
                });
            } catch (error) {
                markHomegraphMetricFailure('request_sync', String(normalizedUserId), null, error?.message || null);
                console.error('GOOGLE REQUEST SYNC ERROR:', error);
            }
        }, getGoogleHomegraphRequestSyncDebounceMs());

        if (typeof timer.unref === 'function') {
            timer.unref();
        }

        state.googleHomegraphRequestSyncQueue.set(normalizedUserId, {
            reason,
            timer,
            queuedAt: scheduledAt
        });
    }

    async function collectGoogleReportableStateChangesForUser(userId, options = {}) {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId) {
            return {
                states: {},
                hashes: {}
            };
        }

        const force = Boolean(options.force);

        // Collect entity IDs with recent active commands to suppress stale Report State.
        // When a command is queued, the EXECUTE handler returns optimistic state to Google.
        // If Report State fires before the device updates, it would revert Google to the old state.
        // Suppress Report State for entities with pending/dispatched commands (within last 8 seconds).
        let recentCommandEntityIds = new Set();
        try {
            const recentCutoff = new Date(Date.now() - 8000).toISOString();
            const recentCmdRows = await dbAll(
                `
                    SELECT DISTINCT entity_id
                    FROM google_home_command_queue
                    WHERE user_id = ?
                      AND status IN ('pending', 'dispatched')
                      AND created_at >= ?
                `,
                [normalizedUserId, recentCutoff]
            );
            recentCommandEntityIds = new Set(
                (recentCmdRows || []).map((r) => utils.sanitizeEntityId(r.entity_id)).filter(Boolean)
            );
        } catch (_) {
            // Non-critical — proceed without suppression
        }

        let rows;
        try {
            rows = await dbAll(
                `
                    SELECT
                        ge.entity_id,
                        ge.entity_type,
                        ge.online,
                        ge.state_json,
                        ge.last_reported_state_hash,
                        ge.exposed,
                        ge.entity_last_seen_at,
                        ge.updated_at,
                        d.last_seen_at
                    FROM google_home_entities ge
                    INNER JOIN devices d ON d.id = ge.device_id
                    WHERE ge.user_id = ?
                `,
                [normalizedUserId]
            );
        } catch (error) {
            if (utils.isMissingGoogleLastReportedColumnsError(error)) {
                state.googleLastReportedColumnsSupported = false;
                rows = await dbAll(
                    `
                        SELECT
                            ge.entity_id,
                            ge.entity_type,
                            ge.online,
                            ge.state_json,
                            NULL AS last_reported_state_hash,
                            ge.exposed,
                            ge.entity_last_seen_at,
                            ge.updated_at,
                            d.last_seen_at
                        FROM google_home_entities ge
                        INNER JOIN devices d ON d.id = ge.device_id
                        WHERE ge.user_id = ?
                    `,
                    [normalizedUserId]
                );
            } else {
                throw error;
            }
        }

        const states = {};
        const hashes = {};
        for (const row of rows || []) {
            const entityId = utils.sanitizeEntityId(row.entity_id);
            if (!entityId) {
                continue;
            }

            const parsedState = {
                ...entityMapping.parseGoogleEntityState(entityMapping.withEffectiveGoogleOnline(row))
            };
            const stateHash = computeGoogleStateHash(parsedState);
            const lastReportedHash = row.last_reported_state_hash || null;

            if (
                row.exposed === 1 &&
                (force || stateHash !== lastReportedHash) &&
                !recentCommandEntityIds.has(entityId)
            ) {
                states[entityId] = parsedState;
                hashes[entityId] = stateHash;
            }
        }

        return { states, hashes };
    }

    async function markGoogleReportedStateHashes(userId, stateHashesByEntityId) {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (
            !normalizedUserId ||
            !stateHashesByEntityId ||
            typeof stateHashesByEntityId !== 'object' ||
            !state.googleLastReportedColumnsSupported
        ) {
            return;
        }

        const nowIso = new Date().toISOString();
        const entries = Object.entries(stateHashesByEntityId)
            .map(([entityId, hash]) => [utils.sanitizeEntityId(entityId), utils.sanitizeString(hash, 80)])
            .filter(([entityId, hash]) => Boolean(entityId && hash));

        if (entries.length === 0) {
            return;
        }

        const byEntityId = new Map(entries);
        const entityIds = Array.from(byEntityId.keys());
        const placeholders = entityIds.map(() => '?').join(',');
        const caseClauses = entityIds.map(() => 'WHEN ? THEN ?').join(' ');
        const args = [];
        for (const entityId of entityIds) {
            args.push(entityId, byEntityId.get(entityId));
        }

        try {
            await dbRun(
                `
                    UPDATE google_home_entities
                    SET last_reported_state_hash = CASE entity_id ${caseClauses} ELSE last_reported_state_hash END,
                        last_reported_at = ?
                    WHERE user_id = ?
                      AND entity_id IN (${placeholders})
                `,
                [...args, nowIso, normalizedUserId, ...entityIds]
            );
        } catch (error) {
            if (utils.isMissingGoogleLastReportedColumnsError(error)) {
                state.googleLastReportedColumnsSupported = false;
                return;
            }
            throw error;
        }
    }

    async function markGoogleEntitiesStaleByFreshness() {
        const freshnessThresholdIso = new Date(Date.now() - utils.getEntityFreshWindowSeconds() * 1000).toISOString();
        const nowIso = new Date().toISOString();

        const staleClause = state.googleEntityLastSeenColumnSupported
            ? '(entity_last_seen_at IS NULL OR entity_last_seen_at < ?)'
            : 'updated_at < ?';

        try {
            await dbRun(
                `
                    UPDATE google_home_entities
                    SET online = 0,
                        updated_at = ?
                    WHERE online = 1
                      AND ${staleClause}
                `,
                [nowIso, freshnessThresholdIso]
            );
        } catch (error) {
            if (utils.isMissingGoogleEntityLastSeenColumnError(error)) {
                state.googleEntityLastSeenColumnSupported = false;
                await dbRun(
                    `
                        UPDATE google_home_entities
                        SET online = 0,
                            updated_at = ?
                        WHERE online = 1
                          AND updated_at < ?
                    `,
                    [nowIso, freshnessThresholdIso]
                );
                return;
            }

            throw error;
        }
    }

    function scheduleGoogleReportStateForUser(userId, options = {}) {
        if (!config.GOOGLE_HOMEGRAPH_REPORT_STATE_ENABLED || !hasGoogleHomegraphCredentials()) {
            return;
        }

        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId) {
            return;
        }

        const force = Boolean(options.force);
        // Which 404-backoff attempt this is (0 = first normal report). Set by the
        // 404-recovery path below when it re-schedules after a registration miss.
        const retry404Attempt = Number(options.retry404Attempt) || 0;
        const existing = state.googleHomegraphReportStateQueue.get(normalizedUserId);

        if (existing?.timer) {
            clearTimeout(existing.timer);
        }

        const timer = setTimeout(
            async () => {
                state.googleHomegraphReportStateQueue.delete(normalizedUserId);

                try {
                    const user = await dbGet(
                        `SELECT id, google_home_enabled, google_home_linked FROM users WHERE id = ?`,
                        [normalizedUserId]
                    );
                    if (!user || !user.google_home_enabled || !user.google_home_linked) {
                        return;
                    }

                    await markGoogleEntitiesStaleByFreshness();

                    const reportable = await collectGoogleReportableStateChangesForUser(normalizedUserId, { force });
                    const entityIds = Object.keys(reportable.states);
                    if (entityIds.length === 0) {
                        return;
                    }

                    const response = await sendGoogleReportState(String(normalizedUserId), reportable.states);
                    if (!response?.ok && !response?.skipped) {
                        // A 404 means HomeGraph hasn't registered the devices yet (the
                        // report raced ahead of the initial RequestSync). Don't count
                        // this as a failure yet — re-fire a RequestSync to (re)register,
                        // then re-schedule THIS report after a backoff so Google has time
                        // to catch up. Only after the backoff attempts are exhausted do we
                        // record a real failure.
                        if (response.statusCode === 404 && retry404Attempt < GOOGLE_REPORT_STATE_404_BACKOFF_MS.length) {
                            const delay = GOOGLE_REPORT_STATE_404_BACKOFF_MS[retry404Attempt];
                            console.warn('GOOGLE REPORT STATE 404 (devices not registered yet) — RequestSync + retry', {
                                user_id: normalizedUserId,
                                attempt: retry404Attempt + 1,
                                retry_in_ms: delay
                            });
                            // Register (or re-register) the inventory, then re-schedule.
                            scheduleGoogleRequestSyncForUser(normalizedUserId, 'report_state_404_recovery');
                            const retryTimer = setTimeout(() => {
                                scheduleGoogleReportStateForUser(normalizedUserId, {
                                    force: true,
                                    retry404Attempt: retry404Attempt + 1
                                });
                            }, delay);
                            if (typeof retryTimer.unref === 'function') retryTimer.unref();
                            return;
                        }

                        markHomegraphMetricFailure(
                            'report_state',
                            String(normalizedUserId),
                            response.statusCode || null,
                            response.error || null
                        );
                        console.warn('GOOGLE REPORT STATE FAILED:', {
                            user_id: normalizedUserId,
                            entities: entityIds.length,
                            error: response.error || null,
                            status: response.statusCode || null,
                            after_404_attempts: retry404Attempt
                        });
                        return;
                    }

                    if (!response?.ok) {
                        markHomegraphMetricSkipped('report_state', String(normalizedUserId), response?.reason || null);
                        return;
                    }

                    await markGoogleReportedStateHashes(normalizedUserId, reportable.hashes);
                    markHomegraphMetricSuccess('report_state', String(normalizedUserId), response?.statusCode || null);
                    console.log('GOOGLE REPORT STATE SENT:', {
                        user_id: normalizedUserId,
                        entities: entityIds.length,
                        force
                    });
                } catch (error) {
                    markHomegraphMetricFailure('report_state', String(normalizedUserId), null, error?.message || null);
                    console.error('GOOGLE REPORT STATE ERROR:', error);
                }
            },
            force ? 200 : getGoogleHomegraphReportStateDebounceMs()
        );

        if (typeof timer.unref === 'function') {
            timer.unref();
        }

        state.googleHomegraphReportStateQueue.set(normalizedUserId, {
            timer,
            force,
            queuedAt: Date.now()
        });
    }

    return {
        markHomegraphMetricSuccess,
        markHomegraphMetricFailure,
        markHomegraphMetricSkipped,
        getGoogleHomegraphDebounceMs,
        getGoogleHomegraphRequestSyncDebounceMs,
        getGoogleHomegraphReportStateDebounceMs,
        getGoogleServiceAccountClientEmail,
        getGoogleServiceAccountPrivateKey,
        getGoogleHomegraphTokenUri,
        getGoogleHomegraphApiBaseUrl,
        hasGoogleHomegraphCredentials,
        getGoogleHomegraphJwtLifetimeSeconds,
        base64UrlEncodeJson,
        generateGoogleServiceJwtAssertion,
        normalizeJsonForHash,
        computeGoogleStateHash,
        fetchGoogleAccessTokenForHomegraph,
        postToGoogleHomegraph,
        sendGoogleRequestSync,
        sendGoogleReportState,
        scheduleGoogleRequestSyncForUser,
        collectGoogleReportableStateChangesForUser,
        markGoogleReportedStateHashes,
        markGoogleEntitiesStaleByFreshness,
        scheduleGoogleReportStateForUser
    };
};
