const crypto = require('node:crypto');
const alexaCrypto = require('./crypto');

module.exports = function ({ dbGet, dbRun, dbAll, config, utils, state, entityMapping }) {
    // ── Metrics ─────────────────────────────────────────────────────────

    function markMetricSuccess(metricType, userId, statusCode = null) {
        const metric = state.eventGatewayMetrics[metricType];
        if (!metric) return;
        metric.sent += 1;
        metric.last_success_at = new Date().toISOString();
        metric.last_status = statusCode;
        metric.last_user_id = utils.sanitizeString(userId, 120) || null;
    }

    function markMetricFailure(metricType, userId, statusCode = null, reason = null) {
        const metric = state.eventGatewayMetrics[metricType];
        if (!metric) return;
        metric.failed += 1;
        metric.last_failure_at = new Date().toISOString();
        metric.last_status = statusCode;
        metric.last_failure_reason = utils.sanitizeString(reason, 300) || 'unknown_error';
        metric.last_user_id = utils.sanitizeString(userId, 120) || null;
    }

    function markMetricSkipped(metricType, userId, reason = null) {
        const metric = state.eventGatewayMetrics[metricType];
        if (!metric) return;
        metric.skipped += 1;
        metric.last_status = null;
        metric.last_user_id = utils.sanitizeString(userId, 120) || null;
        if (reason) {
            metric.last_failure_reason = utils.sanitizeString(reason, 300) || metric.last_failure_reason;
        }
    }

    // ── Debounce helpers ────────────────────────────────────────────────

    function clampDebounce(value, fallback, min, max) {
        if (!Number.isFinite(value)) return fallback;
        return Math.max(min, Math.min(max, Math.round(value)));
    }

    function getAlexaChangeReportDebounceMs() {
        return clampDebounce(config.ALEXA_CHANGE_REPORT_DEBOUNCE_MS, 1200, 250, 10000);
    }

    function getAlexaAddOrUpdateReportDebounceMs() {
        return clampDebounce(config.ALEXA_ADD_OR_UPDATE_DEBOUNCE_MS, 2500, 250, 30000);
    }

    // ── URLs / env ──────────────────────────────────────────────────────

    function getAlexaEventGatewayUrl() {
        const configured = utils.sanitizeString(
            process.env.ALEXA_EVENT_GATEWAY_URL || config.ALEXA_EVENT_GATEWAY_URL || '',
            800
        );
        return configured || 'https://api.amazonalexa.com/v3/events';
    }

    function getLwaTokenUrl() {
        return (
            utils.sanitizeString(process.env.ALEXA_LWA_TOKEN_URL || config.ALEXA_LWA_TOKEN_URL || '', 800) ||
            'https://api.amazon.com/auth/o2/token'
        );
    }

    function getLwaClientId() {
        return utils.sanitizeString(process.env.LWA_CLIENT_ID || config.LWA_CLIENT_ID || '', 320);
    }

    function getLwaClientSecret() {
        return utils.sanitizeString(process.env.LWA_CLIENT_SECRET || config.LWA_CLIENT_SECRET || '', 320);
    }

    function hasLwaClientCredentials() {
        return Boolean(getLwaClientId() && getLwaClientSecret() && alexaCrypto.hasEncryptionKey());
    }

    // ── Hashing ─────────────────────────────────────────────────────────

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
        // Strip timeOfSample from properties before hashing so wall-clock drift
        // doesn't produce a fresh hash on every poll.
        const stripped = Array.isArray(value)
            ? value.map((p) => {
                  const { timeOfSample: _tos, uncertaintyInMilliseconds: _u, ...rest } = p || {};
                  return rest;
              })
            : value;
        const normalized = normalizeJsonForHash(stripped || {});
        return crypto.createHash('sha1').update(JSON.stringify(normalized)).digest('hex');
    }

    // ── LWA token refresh ───────────────────────────────────────────────

    async function loadUserLwaTokens(userId) {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId) return null;

        return await dbGet(
            `
                SELECT user_id,
                       lwa_access_token_encrypted,
                       lwa_refresh_token_encrypted,
                       lwa_expires_at,
                       lwa_scopes
                FROM alexa_tokens
                WHERE user_id = ?
                LIMIT 1
            `,
            [normalizedUserId]
        );
    }

    async function persistRefreshedLwaTokens(userId, accessTokenPlain, refreshTokenPlain, expiresInSeconds) {
        const accessTokenEnc = accessTokenPlain ? alexaCrypto.encryptLwaToken(accessTokenPlain) : null;
        const refreshTokenEnc = refreshTokenPlain ? alexaCrypto.encryptLwaToken(refreshTokenPlain) : null;
        const expiresAtIso = new Date(Date.now() + Math.max(60, Number(expiresInSeconds) || 3600) * 1000).toISOString();
        const nowIso = new Date().toISOString();

        if (refreshTokenEnc) {
            await dbRun(
                `
                    UPDATE alexa_tokens
                    SET lwa_access_token_encrypted = ?,
                        lwa_refresh_token_encrypted = ?,
                        lwa_expires_at = ?,
                        updated_at = ?
                    WHERE user_id = ?
                `,
                [accessTokenEnc, refreshTokenEnc, expiresAtIso, nowIso, userId]
            );
        } else {
            await dbRun(
                `
                    UPDATE alexa_tokens
                    SET lwa_access_token_encrypted = ?,
                        lwa_expires_at = ?,
                        updated_at = ?
                    WHERE user_id = ?
                `,
                [accessTokenEnc, expiresAtIso, nowIso, userId]
            );
        }
    }

    async function fetchValidLwaAccessTokenForUser(userId) {
        if (!hasLwaClientCredentials()) {
            return { ok: false, skipped: true, reason: 'missing_lwa_credentials' };
        }

        const row = await loadUserLwaTokens(userId);
        if (!row || !row.lwa_refresh_token_encrypted) {
            return { ok: false, skipped: true, reason: 'missing_lwa_tokens' };
        }

        const refreshToken = alexaCrypto.decryptLwaToken(row.lwa_refresh_token_encrypted);
        if (!refreshToken) {
            return { ok: false, skipped: true, reason: 'lwa_decrypt_failed' };
        }

        const expiresEpoch = row.lwa_expires_at ? new Date(row.lwa_expires_at).getTime() : 0;
        const stillValid = Number.isFinite(expiresEpoch) && expiresEpoch - Date.now() > 60_000;
        if (stillValid && row.lwa_access_token_encrypted) {
            const cached = alexaCrypto.decryptLwaToken(row.lwa_access_token_encrypted);
            if (cached) {
                return { ok: true, accessToken: cached };
            }
        }

        const body = new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
            client_id: getLwaClientId(),
            client_secret: getLwaClientSecret()
        }).toString();

        let response;
        try {
            response = await fetch(getLwaTokenUrl(), {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    Accept: 'application/json'
                },
                body
            });
        } catch (error) {
            return { ok: false, error: error?.message || 'lwa_fetch_error' };
        }

        const raw = await response.text();
        const parsed = utils.parseJsonSafe(raw, null);
        if (!response.ok) {
            const errorText = parsed?.error_description || parsed?.error || `status_${response.status}`;
            return { ok: false, statusCode: response.status, error: errorText };
        }

        const newAccess = utils.sanitizeString(parsed?.access_token, 4000);
        const newRefresh = utils.sanitizeString(parsed?.refresh_token, 4000) || refreshToken;
        const expiresIn = Number(parsed?.expires_in) || 3600;

        if (!newAccess) {
            return { ok: false, error: 'lwa_missing_access_token' };
        }

        try {
            await persistRefreshedLwaTokens(userId, newAccess, newRefresh, expiresIn);
        } catch (error) {
            return { ok: false, error: error?.message || 'lwa_persist_failed' };
        }

        return { ok: true, accessToken: newAccess };
    }

    // ── Outbound POST to Event Gateway ──────────────────────────────────

    async function postToAlexaEventGateway(userId, payload) {
        if (!hasLwaClientCredentials()) {
            return { ok: false, skipped: true, reason: 'missing_lwa_credentials' };
        }

        const tokenResult = await fetchValidLwaAccessTokenForUser(userId);
        if (!tokenResult.ok) {
            return tokenResult.skipped
                ? { ok: false, skipped: true, reason: tokenResult.reason }
                : { ok: false, error: tokenResult.error || 'lwa_error', statusCode: tokenResult.statusCode || null };
        }

        const bodyText = JSON.stringify(payload || {});

        let response;
        try {
            response = await fetch(getAlexaEventGatewayUrl(), {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json;charset=UTF-8',
                    Authorization: `Bearer ${tokenResult.accessToken}`
                },
                body: bodyText
            });
        } catch (error) {
            return { ok: false, error: error?.message || 'fetch_error' };
        }

        const raw = await response.text();
        const parsed = utils.parseJsonSafe(raw, null);

        if (response.status === 401 || response.status === 403) {
            // Clear cached access token by zeroing expiry so the next call refreshes.
            try {
                await dbRun(
                    `UPDATE alexa_tokens SET lwa_access_token_encrypted = NULL, lwa_expires_at = ? WHERE user_id = ?`,
                    [new Date(0).toISOString(), userId]
                );
            } catch (_) {
                // Non-fatal
            }
        }

        if (!response.ok) {
            const apiError =
                parsed?.payload?.message ||
                parsed?.message ||
                parsed?.error_description ||
                parsed?.error ||
                `status_${response.status}`;
            return { ok: false, statusCode: response.status, error: apiError };
        }

        return { ok: true, statusCode: response.status, payload: parsed || {} };
    }

    // ── Event builders ──────────────────────────────────────────────────

    function buildMessageId() {
        return crypto.randomUUID();
    }

    async function buildChangeReportPayload(userId, entity, cause = 'PHYSICAL_INTERACTION') {
        const tokenResult = await fetchValidLwaAccessTokenForUser(userId);
        const bearer = tokenResult.ok ? tokenResult.accessToken : null;
        const properties = entityMapping.translateAlexaEntityState(entity);
        if (properties.length === 0) {
            return null;
        }

        const changed = properties.filter((p) => p.namespace !== 'Alexa.EndpointHealth');
        const unchanged = properties.filter((p) => p.namespace === 'Alexa.EndpointHealth');

        return {
            event: {
                header: {
                    namespace: 'Alexa',
                    name: 'ChangeReport',
                    messageId: buildMessageId(),
                    payloadVersion: '3'
                },
                endpoint: {
                    scope: { type: 'BearerToken', token: bearer || '' },
                    endpointId: entity.entity_id
                },
                payload: {
                    change: {
                        cause: { type: cause },
                        properties: changed
                    }
                }
            },
            context: {
                properties: unchanged
            }
        };
    }

    async function buildAddOrUpdateReportPayload(userId, endpoints) {
        const tokenResult = await fetchValidLwaAccessTokenForUser(userId);
        const bearer = tokenResult.ok ? tokenResult.accessToken : null;

        return {
            event: {
                header: {
                    namespace: 'Alexa.Discovery',
                    name: 'AddOrUpdateReport',
                    messageId: buildMessageId(),
                    payloadVersion: '3'
                },
                payload: {
                    endpoints,
                    scope: { type: 'BearerToken', token: bearer || '' }
                }
            }
        };
    }

    // ── Public: ChangeReport ────────────────────────────────────────────

    async function sendAlexaChangeReport(userId, entityId) {
        const normalizedUserId = utils.parsePositiveInt(userId);
        const normalizedEntityId = utils.sanitizeEntityId(entityId);
        if (!normalizedUserId || !normalizedEntityId) {
            return { ok: false, skipped: true, reason: 'invalid_args' };
        }

        const entity = await dbGet(
            `
                SELECT ae.*, d.last_seen_at
                FROM alexa_entities ae
                INNER JOIN devices d ON d.id = ae.device_id
                WHERE ae.user_id = ? AND ae.entity_id = ?
                LIMIT 1
            `,
            [normalizedUserId, normalizedEntityId]
        );
        if (!entity || entity.exposed !== 1) {
            return { ok: false, skipped: true, reason: 'entity_not_exposed' };
        }

        const enriched = entityMapping.withEffectiveAlexaOnline(entity);
        const payload = await buildChangeReportPayload(normalizedUserId, enriched);
        if (!payload) {
            return { ok: false, skipped: true, reason: 'empty_properties' };
        }

        const response = await postToAlexaEventGateway(normalizedUserId, payload);

        if (response.ok) {
            // Dedup: write last_reported_state_hash.
            try {
                const hash = computeAlexaStateHash(payload.event.payload.change.properties);
                await dbRun(
                    `UPDATE alexa_entities SET last_reported_state_hash = ?, last_reported_at = ? WHERE id = ?`,
                    [hash, new Date().toISOString(), entity.id]
                );
            } catch (_) {
                // Non-fatal
            }
        }

        return response;
    }

    async function sendAlexaAddOrUpdateReport(userId) {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId) {
            return { ok: false, skipped: true, reason: 'invalid_user_id' };
        }

        const rows = await dbAll(
            `
                SELECT ae.*, d.addon_version, d.last_seen_at
                FROM alexa_entities ae
                INNER JOIN devices d ON d.id = ae.device_id
                WHERE ae.user_id = ? AND ae.exposed = 1
            `,
            [normalizedUserId]
        );

        const endpoints = (rows || [])
            .map((row) => entityMapping.withEffectiveAlexaOnline(row))
            .map((row) => entityMapping.buildAlexaDiscoveryEndpoint(row));

        if (endpoints.length === 0) {
            return { ok: false, skipped: true, reason: 'no_endpoints' };
        }

        const payload = await buildAddOrUpdateReportPayload(normalizedUserId, endpoints);
        return await postToAlexaEventGateway(normalizedUserId, payload);
    }

    // ── Debounced queueing ──────────────────────────────────────────────

    function queueAlexaChangeReport(userId, entityId, reason = 'change') {
        const normalizedUserId = utils.parsePositiveInt(userId);
        const normalizedEntityId = utils.sanitizeEntityId(entityId);
        if (!normalizedUserId || !normalizedEntityId || !hasLwaClientCredentials()) {
            return;
        }

        // Per-(user,entity) debounce key: rapid updates to the same entity coalesce,
        // but updates to different entities do NOT block each other.
        const queueKey = `${normalizedUserId}:${normalizedEntityId}`;
        const existing = state.alexaChangeReportQueue.get(queueKey);
        if (existing?.timer) {
            clearTimeout(existing.timer);
        }

        const scheduledAt = Date.now();
        const timer = setTimeout(async () => {
            state.alexaChangeReportQueue.delete(queueKey);
            try {
                const user = await dbGet(
                    `SELECT id, alexa_enabled, alexa_linked FROM users WHERE id = ?`,
                    [normalizedUserId]
                );
                if (!user || !user.alexa_enabled || !user.alexa_linked) {
                    return;
                }

                const response = await sendAlexaChangeReport(normalizedUserId, normalizedEntityId);
                if (response?.skipped) {
                    markMetricSkipped('change_report', String(normalizedUserId), response.reason || null);
                    return;
                }
                if (!response?.ok) {
                    markMetricFailure(
                        'change_report',
                        String(normalizedUserId),
                        response?.statusCode || null,
                        response?.error || null
                    );
                    console.warn('ALEXA CHANGE REPORT FAILED:', {
                        user_id: normalizedUserId,
                        entity_id: normalizedEntityId,
                        reason,
                        error: response?.error || null,
                        status: response?.statusCode || null
                    });
                    return;
                }

                markMetricSuccess('change_report', String(normalizedUserId), response?.statusCode || null);
                console.log('ALEXA CHANGE REPORT SENT:', {
                    user_id: normalizedUserId,
                    entity_id: normalizedEntityId,
                    reason,
                    queued_for_ms: Date.now() - scheduledAt
                });
            } catch (error) {
                markMetricFailure('change_report', String(normalizedUserId), null, error?.message || null);
                console.error('ALEXA CHANGE REPORT ERROR:', error);
            }
        }, getAlexaChangeReportDebounceMs());

        if (typeof timer.unref === 'function') {
            timer.unref();
        }

        state.alexaChangeReportQueue.set(queueKey, {
            reason,
            timer,
            queuedAt: scheduledAt
        });
    }

    function queueAlexaAddOrUpdateReport(userId, deviceId = null, reason = 'device_linked') {
        const normalizedUserId = utils.parsePositiveInt(userId);
        if (!normalizedUserId || !hasLwaClientCredentials()) {
            return;
        }

        const existing = state.alexaAddOrUpdateReportQueue.get(normalizedUserId);
        if (existing?.timer) {
            clearTimeout(existing.timer);
        }

        const scheduledAt = Date.now();
        const timer = setTimeout(async () => {
            state.alexaAddOrUpdateReportQueue.delete(normalizedUserId);
            try {
                const user = await dbGet(
                    `SELECT id, alexa_enabled, alexa_linked FROM users WHERE id = ?`,
                    [normalizedUserId]
                );
                if (!user || !user.alexa_enabled || !user.alexa_linked) {
                    return;
                }

                const response = await sendAlexaAddOrUpdateReport(normalizedUserId);
                if (response?.skipped) {
                    markMetricSkipped('add_or_update_report', String(normalizedUserId), response.reason || null);
                    return;
                }
                if (!response?.ok) {
                    markMetricFailure(
                        'add_or_update_report',
                        String(normalizedUserId),
                        response?.statusCode || null,
                        response?.error || null
                    );
                    console.warn('ALEXA ADDORUPDATE REPORT FAILED:', {
                        user_id: normalizedUserId,
                        device_id: deviceId,
                        reason,
                        error: response?.error || null,
                        status: response?.statusCode || null
                    });
                    return;
                }

                markMetricSuccess('add_or_update_report', String(normalizedUserId), response?.statusCode || null);
                console.log('ALEXA ADDORUPDATE REPORT SENT:', {
                    user_id: normalizedUserId,
                    device_id: deviceId,
                    reason,
                    queued_for_ms: Date.now() - scheduledAt
                });
            } catch (error) {
                markMetricFailure('add_or_update_report', String(normalizedUserId), null, error?.message || null);
                console.error('ALEXA ADDORUPDATE REPORT ERROR:', error);
            }
        }, getAlexaAddOrUpdateReportDebounceMs());

        if (typeof timer.unref === 'function') {
            timer.unref();
        }

        state.alexaAddOrUpdateReportQueue.set(normalizedUserId, {
            reason,
            deviceId,
            timer,
            queuedAt: scheduledAt
        });
    }

    // ── Freshness marker (mirrors Google) ───────────────────────────────

    async function markAlexaEntitiesStaleByFreshness() {
        const freshnessThresholdIso = new Date(
            Date.now() - utils.getEntityFreshWindowSeconds() * 1000
        ).toISOString();
        const nowIso = new Date().toISOString();

        const staleClause = state.alexaEntityLastSeenColumnSupported
            ? '(entity_last_seen_at IS NULL OR entity_last_seen_at < ?)'
            : 'updated_at < ?';

        try {
            await dbRun(
                `
                    UPDATE alexa_entities
                    SET online = 0,
                        updated_at = ?
                    WHERE online = 1
                      AND ${staleClause}
                `,
                [nowIso, freshnessThresholdIso]
            );
        } catch (error) {
            if (utils.isMissingGoogleEntityLastSeenColumnError(error)) {
                state.alexaEntityLastSeenColumnSupported = false;
                await dbRun(
                    `
                        UPDATE alexa_entities
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

    return {
        markMetricSuccess,
        markMetricFailure,
        markMetricSkipped,
        getAlexaChangeReportDebounceMs,
        getAlexaAddOrUpdateReportDebounceMs,
        getAlexaEventGatewayUrl,
        getLwaTokenUrl,
        getLwaClientId,
        getLwaClientSecret,
        hasLwaClientCredentials,
        computeAlexaStateHash,
        fetchValidLwaAccessTokenForUser,
        postToAlexaEventGateway,
        sendAlexaChangeReport,
        sendAlexaAddOrUpdateReport,
        queueAlexaChangeReport,
        queueAlexaAddOrUpdateReport,
        markAlexaEntitiesStaleByFreshness
    };
};
