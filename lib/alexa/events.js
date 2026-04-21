const https = require('https');
const crypto = require('crypto');

// Alexa event gateway integration. Mirrors lib/google-home/homegraph.js:
//   - scheduleAlexaChangeReportForUser: debounced proactive state push
//   - scheduleAlexaDiscoveryUpdateForUser: debounced AddOrUpdateReport
// LWA access tokens (for the event gateway) are cached per-user.
//
// Amazon's event gateway expects an Alexa-formatted event envelope POSTed to
// https://api.amazonalexa.com/v3/events with a Bearer token obtained by
// exchanging the grantee_code received in Alexa.Authorization.AcceptGrant
// for an LWA refresh token, then refreshing that for access tokens.

module.exports = function ({ dbGet, dbRun, dbAll, config, utils, state, directiveMapping }) {
    function getDebounceMs(value, fallback, min, max) {
        if (!Number.isFinite(value)) {
            return fallback;
        }
        return Math.max(min, Math.min(max, Math.round(value)));
    }

    function getAlexaChangeReportDebounceMs() {
        return getDebounceMs(config.ALEXA_CHANGE_REPORT_DEBOUNCE_MS, 1200, 250, 10000);
    }

    function getAlexaDiscoveryDebounceMs() {
        return getDebounceMs(config.ALEXA_DISCOVERY_DEBOUNCE_MS, 2500, 250, 30000);
    }

    function hasAlexaLwaCredentials() {
        return Boolean(config.ALEXA_LWA_CLIENT_ID && config.ALEXA_LWA_CLIENT_SECRET);
    }

    // ── Metrics ────────────────────────────────────────────────────────────
    function markMetricSuccess(metricType, userId, statusCode = null) {
        const metric = state.alexaMetrics[metricType];
        if (!metric) return;
        metric.sent += 1;
        metric.last_success_at = new Date().toISOString();
        metric.last_status = statusCode;
        metric.last_user_id = utils.sanitizeString(String(userId || ''), 120) || null;
    }

    function markMetricFailure(metricType, userId, statusCode = null, reason = null) {
        const metric = state.alexaMetrics[metricType];
        if (!metric) return;
        metric.failed += 1;
        metric.last_failure_at = new Date().toISOString();
        metric.last_status = statusCode;
        metric.last_failure_reason = utils.sanitizeString(reason, 300) || 'unknown_error';
        metric.last_user_id = utils.sanitizeString(String(userId || ''), 120) || null;
    }

    function markMetricSkipped(metricType, userId, reason = null) {
        const metric = state.alexaMetrics[metricType];
        if (!metric) return;
        metric.skipped += 1;
        metric.last_user_id = utils.sanitizeString(String(userId || ''), 120) || null;
        if (reason) {
            metric.last_failure_reason = utils.sanitizeString(reason, 300) || metric.last_failure_reason;
        }
    }

    // ── Hash helper (reused from homegraph) ────────────────────────────────
    function normalizeJsonForHash(value) {
        if (value === null || value === undefined) return value;
        if (Array.isArray(value)) return value.map((item) => normalizeJsonForHash(item));
        if (typeof value === 'object') {
            const sorted = {};
            for (const key of Object.keys(value).sort()) {
                sorted[key] = normalizeJsonForHash(value[key]);
            }
            return sorted;
        }
        return value;
    }

    function computeAlexaStateHash(value) {
        const normalized = normalizeJsonForHash(value || {});
        return crypto.createHash('sha1').update(JSON.stringify(normalized)).digest('hex');
    }

    // ── Raw HTTP POST helper ───────────────────────────────────────────────
    function postJson(urlString, headers, body) {
        return new Promise((resolve, reject) => {
            const url = new URL(urlString);
            const bodyText = typeof body === 'string' ? body : JSON.stringify(body || {});
            const req = https.request(
                {
                    protocol: url.protocol,
                    hostname: url.hostname,
                    port: url.port || (url.protocol === 'https:' ? 443 : 80),
                    path: `${url.pathname}${url.search || ''}`,
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Content-Length': Buffer.byteLength(bodyText),
                        Accept: 'application/json',
                        ...headers
                    },
                    timeout: 10000
                },
                (response) => {
                    const chunks = [];
                    response.on('data', (chunk) => chunks.push(chunk));
                    response.on('end', () => {
                        const raw = Buffer.concat(chunks).toString('utf8');
                        const parsed = utils.parseJsonSafe(raw, null);
                        const ok = response.statusCode >= 200 && response.statusCode < 300;
                        resolve({
                            ok,
                            statusCode: response.statusCode,
                            payload: parsed,
                            raw
                        });
                    });
                }
            );
            req.on('error', reject);
            req.on('timeout', () => req.destroy(new Error('ALEXA HTTP TIMEOUT')));
            req.write(bodyText);
            req.end();
        });
    }

    function postForm(urlString, formFields) {
        return new Promise((resolve, reject) => {
            const url = new URL(urlString);
            const body = new URLSearchParams(formFields).toString();
            const req = https.request(
                {
                    protocol: url.protocol,
                    hostname: url.hostname,
                    port: url.port || (url.protocol === 'https:' ? 443 : 80),
                    path: `${url.pathname}${url.search || ''}`,
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Content-Length': Buffer.byteLength(body),
                        Accept: 'application/json'
                    },
                    timeout: 10000
                },
                (response) => {
                    const chunks = [];
                    response.on('data', (chunk) => chunks.push(chunk));
                    response.on('end', () => {
                        const raw = Buffer.concat(chunks).toString('utf8');
                        const parsed = utils.parseJsonSafe(raw, null);
                        const ok = response.statusCode >= 200 && response.statusCode < 300;
                        resolve({ ok, statusCode: response.statusCode, payload: parsed, raw });
                    });
                }
            );
            req.on('error', reject);
            req.on('timeout', () => req.destroy(new Error('ALEXA LWA TIMEOUT')));
            req.write(body);
            req.end();
        });
    }

    // ── LWA token exchange ─────────────────────────────────────────────────
    //
    // Called when Alexa.Authorization.AcceptGrant arrives with a code. We
    // exchange it for a refresh_token + access_token tied to the user, and
    // store the refresh_token (encrypted-at-rest would be ideal; stored
    // plaintext here mirroring how google_home_tokens stores its hashes).
    async function exchangeAlexaGrantCodeForTokens(userId, grantCode) {
        if (!hasAlexaLwaCredentials()) {
            return { ok: false, reason: 'missing_lwa_credentials' };
        }
        if (!grantCode) {
            return { ok: false, reason: 'missing_grant_code' };
        }

        let response;
        try {
            response = await postForm(config.ALEXA_LWA_TOKEN_URL, {
                grant_type: 'authorization_code',
                code: grantCode,
                client_id: config.ALEXA_LWA_CLIENT_ID,
                client_secret: config.ALEXA_LWA_CLIENT_SECRET
            });
        } catch (error) {
            return { ok: false, reason: error?.message || 'lwa_request_failed' };
        }

        if (!response.ok || !response.payload?.refresh_token) {
            return {
                ok: false,
                reason:
                    response.payload?.error_description ||
                    response.payload?.error ||
                    `status_${response.statusCode || 0}`
            };
        }

        const refreshToken = response.payload.refresh_token;
        const accessToken = response.payload.access_token || null;
        const expiresInSec = Number(response.payload.expires_in) || 3600;
        const expiresAtIso = new Date(Date.now() + expiresInSec * 1000).toISOString();
        const nowIso = new Date().toISOString();

        await dbRun(
            `
                UPDATE alexa_tokens
                SET amazon_refresh_token = ?,
                    amazon_access_token = ?,
                    amazon_access_token_expires_at = ?,
                    updated_at = ?
                WHERE user_id = ?
            `,
            [
                utils.encryptAtRest(refreshToken),
                utils.encryptAtRest(accessToken),
                expiresAtIso,
                nowIso,
                userId
            ]
        );

        if (accessToken) {
            state.alexaLwaTokenCache.set(Number(userId), {
                token: accessToken,
                expiresAt: Date.now() + expiresInSec * 1000
            });
        }

        return { ok: true };
    }

    // Fetch (from cache or LWA) a fresh access token for a specific user.
    async function getAlexaLwaAccessTokenForUser(userId) {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId) return null;
        if (!hasAlexaLwaCredentials()) return null;

        const cached = state.alexaLwaTokenCache.get(normalizedUserId);
        const now = Date.now();
        if (cached?.token && cached.expiresAt > now + 60 * 1000) {
            return cached.token;
        }

        const row = await dbGet(
            `SELECT amazon_refresh_token FROM alexa_tokens WHERE user_id = ? LIMIT 1`,
            [normalizedUserId]
        );
        if (!row?.amazon_refresh_token) return null;
        const decryptedRefresh = utils.decryptAtRest(row.amazon_refresh_token);
        if (!decryptedRefresh) return null;

        let response;
        try {
            response = await postForm(config.ALEXA_LWA_TOKEN_URL, {
                grant_type: 'refresh_token',
                refresh_token: decryptedRefresh,
                client_id: config.ALEXA_LWA_CLIENT_ID,
                client_secret: config.ALEXA_LWA_CLIENT_SECRET
            });
        } catch (error) {
            console.error('ALEXA LWA REFRESH ERROR:', error?.message || error);
            return null;
        }

        if (!response.ok || !response.payload?.access_token) {
            return null;
        }

        const accessToken = response.payload.access_token;
        const expiresInSec = Number(response.payload.expires_in) || 3600;
        const ttlMs = Math.max(60, Math.min(3600, expiresInSec)) * 1000;
        state.alexaLwaTokenCache.set(normalizedUserId, {
            token: accessToken,
            expiresAt: Date.now() + ttlMs
        });

        await dbRun(
            `
                UPDATE alexa_tokens
                SET amazon_access_token = ?,
                    amazon_access_token_expires_at = ?,
                    updated_at = ?
                WHERE user_id = ?
            `,
            [
                utils.encryptAtRest(accessToken),
                new Date(Date.now() + ttlMs).toISOString(),
                new Date().toISOString(),
                normalizedUserId
            ]
        );

        return accessToken;
    }

    // ── Send event envelope ────────────────────────────────────────────────
    async function postAlexaEvent(userId, envelope) {
        const accessToken = await getAlexaLwaAccessTokenForUser(userId);
        if (!accessToken) {
            return { ok: false, skipped: true, reason: 'missing_access_token' };
        }

        let response;
        try {
            response = await postJson(
                config.ALEXA_EVENT_GATEWAY_URL,
                { Authorization: `Bearer ${accessToken}` },
                envelope
            );
        } catch (error) {
            return { ok: false, error: error?.message || 'request_failed' };
        }

        // Amazon returns 202 Accepted on success; 401/403 means token rot.
        if (response.statusCode === 401 || response.statusCode === 403) {
            state.alexaLwaTokenCache.delete(Number(userId));
        }

        if (!response.ok) {
            return {
                ok: false,
                statusCode: response.statusCode,
                error: response.payload?.payload?.description || response.payload?.message || `status_${response.statusCode}`
            };
        }
        return { ok: true, statusCode: response.statusCode };
    }

    function uuid() {
        return crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
    }

    // ── Collect reportable state diff ──────────────────────────────────────
    //
    // Identical strategy to collectGoogleReportableStateChangesForUser:
    //   - pull all google_home_entities for user
    //   - convert state via directiveMapping.buildAlexaProperties
    //   - compare hash against alexa_entity_state_hashes
    //   - suppress entities with pending/dispatched commands in the last 8s
    async function collectAlexaReportableChangesForUser(userId, options = {}) {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId) return { changes: [], hashes: {} };

        const force = Boolean(options.force);
        const recentCutoff = new Date(Date.now() - 8000).toISOString();
        let recentCommandEntityIds = new Set();
        try {
            const rows = await dbAll(
                `
                    SELECT DISTINCT entity_id
                    FROM google_home_command_queue
                    WHERE user_id = ?
                      AND status IN ('pending', 'dispatched')
                      AND created_at >= ?
                `,
                [normalizedUserId, recentCutoff]
            );
            recentCommandEntityIds = new Set((rows || []).map((r) => utils.sanitizeEntityId(r.entity_id)).filter(Boolean));
        } catch (_) {
            // Non-critical
        }

        const entityRows = await dbAll(
            `
                SELECT ge.*, d.last_seen_at
                FROM google_home_entities ge
                INNER JOIN devices d ON d.id = ge.device_id
                WHERE ge.user_id = ?
                  AND ge.exposed = 1
            `,
            [normalizedUserId]
        );

        let hashRows = [];
        try {
            hashRows = await dbAll(
                `SELECT entity_id, last_reported_state_hash FROM alexa_entity_state_hashes WHERE user_id = ?`,
                [normalizedUserId]
            );
        } catch (error) {
            if (error?.message && /no such table/i.test(error.message)) {
                state.alexaStateHashTableSupported = false;
            } else {
                throw error;
            }
        }

        const lastReportedByEntityId = new Map();
        for (const row of hashRows || []) {
            lastReportedByEntityId.set(row.entity_id, row.last_reported_state_hash || null);
        }

        const changes = [];
        const hashes = {};

        for (const row of entityRows || []) {
            const entityId = utils.sanitizeEntityId(row.entity_id);
            if (!entityId) continue;
            if (recentCommandEntityIds.has(entityId)) continue;

            const statePayload = utils.parseJsonSafe(row.state_json, {}) || {};
            const properties = directiveMapping.buildAlexaProperties({
                entity_type: row.entity_type,
                online: row.online,
                state: statePayload
            });

            if (!properties || properties.length === 0) continue;

            const hash = computeAlexaStateHash(properties);
            const lastHash = lastReportedByEntityId.get(entityId) || null;

            if (force || hash !== lastHash) {
                changes.push({ entityId, properties });
                hashes[entityId] = hash;
            }
        }

        return { changes, hashes };
    }

    async function markAlexaReportedHashes(userId, hashesByEntityId) {
        if (!state.alexaStateHashTableSupported) return;
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId) return;
        const entries = Object.entries(hashesByEntityId || {}).filter(([k, v]) => k && v);
        if (entries.length === 0) return;

        const nowIso = new Date().toISOString();
        for (const [entityId, hash] of entries) {
            try {
                await dbRun(
                    `
                        INSERT INTO alexa_entity_state_hashes (user_id, entity_id, last_reported_state_hash, last_reported_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(user_id, entity_id) DO UPDATE SET
                            last_reported_state_hash = excluded.last_reported_state_hash,
                            last_reported_at = excluded.last_reported_at
                    `,
                    [normalizedUserId, entityId, hash, nowIso]
                );
            } catch (error) {
                if (error?.message && /no such table/i.test(error.message)) {
                    state.alexaStateHashTableSupported = false;
                    return;
                }
                throw error;
            }
        }
    }

    // ── Public: ChangeReport scheduling ────────────────────────────────────
    function scheduleAlexaChangeReportForUser(userId, options = {}) {
        if (!config.ALEXA_PROACTIVE_EVENTS_ENABLED) return;
        if (!hasAlexaLwaCredentials()) return;

        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId) return;

        const force = Boolean(options.force);
        const existing = state.alexaChangeReportQueue.get(normalizedUserId);
        if (existing?.timer) clearTimeout(existing.timer);

        const timer = setTimeout(
            async () => {
                state.alexaChangeReportQueue.delete(normalizedUserId);

                try {
                    const user = await dbGet(
                        `SELECT id, alexa_enabled, alexa_linked FROM users WHERE id = ?`,
                        [normalizedUserId]
                    );
                    if (!user || !user.alexa_enabled || !user.alexa_linked) return;

                    const { changes, hashes } = await collectAlexaReportableChangesForUser(normalizedUserId, { force });
                    if (changes.length === 0) return;

                    const succeededEntityIds = [];
                    for (const change of changes) {
                        const envelope = {
                            event: {
                                header: {
                                    namespace: 'Alexa',
                                    name: 'ChangeReport',
                                    messageId: uuid(),
                                    payloadVersion: '3'
                                },
                                endpoint: {
                                    scope: {
                                        type: 'BearerToken',
                                        token: await getAlexaLwaAccessTokenForUser(normalizedUserId)
                                    },
                                    endpointId: change.entityId
                                },
                                payload: {
                                    change: {
                                        cause: { type: 'PHYSICAL_INTERACTION' },
                                        properties: change.properties
                                    }
                                }
                            },
                            context: {
                                properties: []
                            }
                        };

                        const response = await postAlexaEvent(normalizedUserId, envelope);
                        if (response?.ok) {
                            succeededEntityIds.push(change.entityId);
                        } else if (response?.skipped) {
                            markMetricSkipped('change_report', normalizedUserId, response.reason || null);
                        } else {
                            markMetricFailure(
                                'change_report',
                                normalizedUserId,
                                response?.statusCode || null,
                                response?.error || null
                            );
                            console.warn('ALEXA CHANGE REPORT FAILED:', {
                                user_id: normalizedUserId,
                                entity: change.entityId,
                                error: response?.error || null,
                                status: response?.statusCode || null
                            });
                        }
                    }

                    if (succeededEntityIds.length > 0) {
                        const succeededHashes = {};
                        for (const entityId of succeededEntityIds) {
                            if (hashes[entityId]) succeededHashes[entityId] = hashes[entityId];
                        }
                        await markAlexaReportedHashes(normalizedUserId, succeededHashes);
                        markMetricSuccess('change_report', normalizedUserId, 202);
                        console.log('ALEXA CHANGE REPORT SENT:', {
                            user_id: normalizedUserId,
                            entities: succeededEntityIds.length,
                            force
                        });
                    }
                } catch (error) {
                    markMetricFailure('change_report', normalizedUserId, null, error?.message || null);
                    console.error('ALEXA CHANGE REPORT ERROR:', error);
                }
            },
            force ? 200 : getAlexaChangeReportDebounceMs()
        );

        if (typeof timer.unref === 'function') timer.unref();

        state.alexaChangeReportQueue.set(normalizedUserId, { timer, queuedAt: Date.now(), force });
    }

    // ── Public: AddOrUpdateReport (discovery update) ──────────────────────
    //
    // Alexa equivalent of Google RequestSync. Informs Amazon that the
    // endpoint list has changed so Alexa re-discovers devices.
    function scheduleAlexaDiscoveryUpdateForUser(userId, reason = 'change') {
        if (!config.ALEXA_PROACTIVE_EVENTS_ENABLED) return;
        if (!hasAlexaLwaCredentials()) return;

        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId) return;

        const existing = state.alexaDiscoveryQueue.get(normalizedUserId);
        if (existing?.timer) clearTimeout(existing.timer);

        const timer = setTimeout(async () => {
            state.alexaDiscoveryQueue.delete(normalizedUserId);

            try {
                const user = await dbGet(
                    `SELECT id, alexa_enabled, alexa_linked, alexa_security_pin FROM users WHERE id = ?`,
                    [normalizedUserId]
                );
                if (!user || !user.alexa_enabled || !user.alexa_linked) return;

                // Fetch all exposed entities
                const rows = await dbAll(
                    `
                        SELECT ge.*, d.addon_version, d.last_seen_at
                        FROM google_home_entities ge
                        INNER JOIN devices d ON d.id = ge.device_id
                        WHERE ge.user_id = ?
                          AND ge.exposed = 1
                    `,
                    [normalizedUserId]
                );

                const endpoints = (rows || [])
                    .map((row) => directiveMapping.buildAlexaEndpoint(row, user.alexa_security_pin))
                    .filter(Boolean);

                if (endpoints.length === 0) return;

                const token = await getAlexaLwaAccessTokenForUser(normalizedUserId);
                if (!token) {
                    markMetricSkipped('discovery', normalizedUserId, 'missing_access_token');
                    return;
                }

                const envelope = {
                    event: {
                        header: {
                            namespace: 'Alexa.Discovery',
                            name: 'AddOrUpdateReport',
                            messageId: uuid(),
                            payloadVersion: '3'
                        },
                        payload: {
                            endpoints,
                            scope: { type: 'BearerToken', token }
                        }
                    }
                };

                const response = await postAlexaEvent(normalizedUserId, envelope);
                if (!response?.ok && !response?.skipped) {
                    markMetricFailure('discovery', normalizedUserId, response?.statusCode || null, response?.error || null);
                    console.warn('ALEXA DISCOVERY UPDATE FAILED:', {
                        user_id: normalizedUserId,
                        reason,
                        error: response?.error || null,
                        first_endpoint: JSON.stringify(endpoints[0] || null).slice(0, 2000),
                        endpoint_count: endpoints.length
                    });
                    return;
                }
                if (response?.skipped) {
                    markMetricSkipped('discovery', normalizedUserId, response.reason || null);
                    return;
                }
                markMetricSuccess('discovery', normalizedUserId, response?.statusCode || null);
                console.log('ALEXA DISCOVERY UPDATE SENT:', {
                    user_id: normalizedUserId,
                    reason,
                    endpoints: endpoints.length
                });
            } catch (error) {
                markMetricFailure('discovery', normalizedUserId, null, error?.message || null);
                console.error('ALEXA DISCOVERY UPDATE ERROR:', error);
            }
        }, getAlexaDiscoveryDebounceMs());

        if (typeof timer.unref === 'function') timer.unref();

        state.alexaDiscoveryQueue.set(normalizedUserId, { timer, queuedAt: Date.now(), reason });
    }

    return {
        getAlexaChangeReportDebounceMs,
        getAlexaDiscoveryDebounceMs,
        hasAlexaLwaCredentials,
        computeAlexaStateHash,
        exchangeAlexaGrantCodeForTokens,
        getAlexaLwaAccessTokenForUser,
        postAlexaEvent,
        collectAlexaReportableChangesForUser,
        markAlexaReportedHashes,
        scheduleAlexaChangeReportForUser,
        scheduleAlexaDiscoveryUpdateForUser
    };
};
