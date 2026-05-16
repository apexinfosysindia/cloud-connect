/**
 * lib/alexa/event-gateway.js
 *
 * Proactive ChangeReport delivery to the Alexa Event Gateway.
 *
 * ─── What this module owns ─────────────────────────────────────────────────
 *
 *   1. buildChangeReportEvent(entity, opts)
 *        Pure function. Turns a row from `alexa_entities` into the JSON
 *        envelope Alexa expects at https://api.amazonalexa.com/v3/events.
 *        Tested without any I/O.
 *
 *   2. getValidAccessTokenForUser(userId)
 *        Returns a non-expired plaintext LWA access token, refreshing via
 *        api.amazon.com/auth/o2/token when expired (or about to expire) and
 *        persisting the rotated pair. Throws when the user is unlinked or
 *        when the refresh attempt fails — callers MUST treat the throw as a
 *        permanent failure for that user, not a transient retry.
 *
 *   3. sendChangeReportForEntity(entity)
 *        End-to-end: build payload, get access token, POST to gateway,
 *        translate response into a structured result. NEVER throws — every
 *        failure mode is returned as `{ ok: false, reason }` so the caller
 *        loop survives one bad user.
 *
 *   4. scheduleChangeReportForUser(userId)  +  flushScheduledChangeReports()
 *        Tiny in-memory debouncer. The addon's sync route can fire-and-forget
 *        a schedule call after writing entity state; the actual gateway POST
 *        happens once per debounce window per (user, entity).
 *
 * ─── What this module DOES NOT own ─────────────────────────────────────────
 *
 *   - AddOrUpdateReport (Discovery refresh after entity set changes). The
 *     addon's sync route already maintains alexa_sync_snapshots; we'll wire
 *     a separate function once #10 lands more domains.
 *   - DeleteReport. Same reason.
 *   - Cross-region routing. Until users get a `region` column, every event
 *     goes to the NA gateway (api.amazonalexa.com). That covers the only
 *     skill region we plan to register first; #9 will validate.
 *
 * ─── Lessons encoded ──────────────────────────────────────────────────────
 *
 *   - The v1 silent-401 loop: one user's expired refresh token triggered an
 *     LWA error, the catch swallowed it, and we kept POSTing the same dead
 *     access token forever. Here, refresh failure throws AND we mark the
 *     user as needing relink (caller's responsibility) — there is no path
 *     where we keep using a dead token.
 *
 *   - The cross-user blast radius: one user's network error must not block
 *     others. Every public function returns/throws cleanly per-user; the
 *     debounce loop catches and logs each error in isolation.
 *
 *   - LWA decryption failure: lib/alexa/crypto.js explicitly throws on key
 *     mismatch / corrupt ciphertext. We let that propagate up to the caller
 *     because a global key error is a deployment bug, not a per-user issue.
 */

const crypto = require('node:crypto');

// Default gateway endpoint. Region routing isn't supported yet (see header).
const DEFAULT_GATEWAY_URL = 'https://api.amazonalexa.com/v3/events';

// Refresh access tokens this many ms before their stated expiry — gives us
// headroom against clock skew + a slow network on the refresh request itself.
const REFRESH_LEEWAY_MS = 60_000;

// Default debounce window. The addon often produces a flurry of state
// updates (e.g. light fade) and we don't want to ChangeReport each one.
const DEFAULT_DEBOUNCE_MS = 1500;

function makeHeader(name, namespace = 'Alexa', overrides = {}) {
    return {
        namespace,
        name,
        messageId: crypto.randomUUID(),
        payloadVersion: '3',
        ...overrides
    };
}

/**
 * Pure: build the ChangeReport event envelope for a single entity.
 *
 * `entityMapping` is injected so we don't carry a require cycle.
 *
 * Returns null when the entity has no reportable properties (out-of-scope
 * domain, etc.) — caller MUST treat null as "skip, no error".
 */
function buildChangeReportEvent({ entity, entityMapping, accessToken, cause = 'PHYSICAL_INTERACTION', nowIso = null }) {
    if (!entity || !entityMapping) return null;
    const properties = entityMapping.buildPropertyState(entity, nowIso || new Date().toISOString());
    if (!properties || properties.length === 0) return null;

    const endpointId = entityMapping.encodeEndpointId(entity.entity_id);

    // The "changed" property is the trigger; the rest are emitted in
    // `context.properties`. For the Walking Skeleton we treat the FIRST
    // non-EndpointHealth property as the trigger and ship everything in
    // context. This is conservative but valid — Alexa explicitly allows
    // duplicate properties between change.properties and context.properties.
    const changed = properties.find((p) => p.namespace !== 'Alexa.EndpointHealth') || properties[0];

    return {
        event: {
            header: makeHeader('ChangeReport'),
            endpoint: {
                scope: { type: 'BearerToken', token: accessToken },
                endpointId,
                cookie: { ha_entity_id: entity.entity_id }
            },
            payload: {
                change: {
                    cause: { type: cause },
                    properties: [changed]
                }
            }
        },
        context: {
            properties: properties.filter((p) => p !== changed)
        }
    };
}

module.exports = function createEventGateway({
    dbGet,
    dbRun,
    alexaCore,
    lwaCrypto,
    entityMapping,
    config = {},
    // Injectable so tests can stub the network without touching global fetch.
    fetchImpl = global.fetch,
    // Injectable clock for deterministic tests.
    now = () => Date.now(),
    debounceMs = DEFAULT_DEBOUNCE_MS,
    gatewayUrl = DEFAULT_GATEWAY_URL
}) {
    // ── Token management ─────────────────────────────────────────────────

    /**
     * Return a valid plaintext LWA access token for `userId`, refreshing
     * against api.amazon.com/auth/o2/token when expired.
     *
     * Throws on:
     *   - user not linked (no alexa_tokens row)
     *   - refresh attempt fails (network or 4xx from LWA)
     *   - decryption error (almost certainly a deployment bug)
     */
    async function getValidAccessTokenForUser(userId) {
        const tokens = await alexaCore.getDecryptedLwaTokensForUser(userId);
        if (!tokens) {
            // Caller layer should treat this as "user has unlinked, drop
            // any pending events for them."
            throw new Error(`event-gateway: user ${userId} has no LWA tokens (unlinked)`);
        }

        const expiresAtMs = tokens.expiresAt ? new Date(tokens.expiresAt).getTime() : 0;
        if (Number.isFinite(expiresAtMs) && expiresAtMs - REFRESH_LEEWAY_MS > now() && tokens.accessToken) {
            return tokens.accessToken;
        }

        // Need to refresh. Pre-flight the env vars before the network call.
        const clientId = process.env.ALEXA_LWA_CLIENT_ID || '';
        const clientSecret = process.env.ALEXA_LWA_CLIENT_SECRET || '';
        if (!clientId || !clientSecret) {
            throw new Error('event-gateway: ALEXA_LWA_CLIENT_ID / ALEXA_LWA_CLIENT_SECRET not configured');
        }

        const body = new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: tokens.refreshToken,
            client_id: clientId,
            client_secret: clientSecret
        });
        const res = await fetchImpl('https://api.amazon.com/auth/o2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body.toString()
        });
        if (!res.ok) {
            const text = await res.text().catch(() => '');
            throw new Error(`event-gateway: LWA refresh failed (HTTP ${res.status}) ${text}`);
        }
        const refreshed = await res.json();
        if (typeof refreshed.access_token !== 'string' || !refreshed.access_token) {
            throw new Error('event-gateway: LWA refresh returned no access_token');
        }

        // Persist the new pair. Amazon may return the same refresh_token or
        // rotate it — we always write whatever they returned (falling back
        // to the old refresh token if not rotated, which keeps things
        // consistent if rotation policy changes).
        const newRefresh = typeof refreshed.refresh_token === 'string' && refreshed.refresh_token
            ? refreshed.refresh_token
            : tokens.refreshToken;
        const expiresInSeconds = Number.isFinite(refreshed.expires_in)
            ? Math.max(60, Math.round(refreshed.expires_in))
            : 3600;
        const newExpiresAt = new Date(now() + expiresInSeconds * 1000).toISOString();

        await dbRun(
            `
                UPDATE alexa_tokens SET
                    lwa_access_token_encrypted  = ?,
                    lwa_refresh_token_encrypted = ?,
                    lwa_expires_at              = ?,
                    updated_at                  = ?
                WHERE user_id = ?
            `,
            [
                lwaCrypto.encryptLwaToken(refreshed.access_token),
                lwaCrypto.encryptLwaToken(newRefresh),
                newExpiresAt,
                new Date(now()).toISOString(),
                userId
            ]
        );
        return refreshed.access_token;
    }

    // ── Debounce queue (declared early so health snapshot can read queue.size) ──
    //
    // queue:  Map<string `${userId}:${entityId}`, { entity, scheduledAt }>
    // The flush runs every `debounceMs / 2` and processes any entry whose
    // scheduledAt has elapsed. Coalescing happens because schedule() on the
    // same key just bumps scheduledAt forward. The actual schedule/flush
    // functions are defined further down — only the Map itself needs to
    // live up here so getHealthSnapshot can read queue.size.
    const queue = new Map();
    let flushInterval = null;

    // ── Per-entity dispatch ──────────────────────────────────────────────

    // Reason counters. One bucket per result kind (`ok` for success, plus the
    // failure reasons returned below). Process-local — fine for a single
    // Cloud Connect instance, which is what we run today. If we ever shard,
    // these need to move to the DB or a metrics sink, but that's not the
    // shape of the bug we're trying to surface here.
    //
    // We track firstAt/lastAt so the admin UI can answer "are gateway errors
    // *currently* happening?" rather than "have they ever happened?" — the
    // v1 muscle memory is that an alert that says "ever" is the alert
    // everyone learns to ignore.
    const counters = new Map();
    const startedAt = new Date(now()).toISOString();

    function recordResult(reason) {
        const nowIso = new Date(now()).toISOString();
        const cur = counters.get(reason);
        if (cur) {
            cur.count += 1;
            cur.lastAt = nowIso;
        } else {
            counters.set(reason, { count: 1, firstAt: nowIso, lastAt: nowIso });
        }
    }

    function getHealthSnapshot() {
        const out = {};
        for (const [reason, v] of counters.entries()) {
            out[reason] = { count: v.count, firstAt: v.firstAt, lastAt: v.lastAt };
        }
        return {
            startedAt,
            queueDepth: queue.size,
            counters: out
        };
    }

    /**
     * Fire one ChangeReport for one entity. Never throws.
     *
     * Returns one of:
     *   { ok: true,  statusCode }                 — gateway accepted it
     *   { ok: false, reason: 'no_properties' }    — entity has nothing reportable
     *   { ok: false, reason: 'unlinked' }         — user has no LWA tokens
     *   { ok: false, reason: 'lwa_refresh_failed', error }
     *   { ok: false, reason: 'gateway_error', statusCode, body }
     *   { ok: false, reason: 'network_error', error }
     *
     * Each return path also increments a counter (`ok` or the reason). Read
     * the aggregate via `getHealthSnapshot()`. We wrap the inner function so
     * the recording happens in exactly one place — easier than threading
     * recordResult() into five return statements and getting it wrong on the
     * sixth one we add later.
     */
    async function sendChangeReportForEntity(entity, opts = {}) {
        const result = await sendChangeReportForEntityImpl(entity, opts);
        recordResult(result.ok ? 'ok' : result.reason || 'unknown');
        return result;
    }

    async function sendChangeReportForEntityImpl(entity, { cause = 'PHYSICAL_INTERACTION' } = {}) {
        if (!entity) return { ok: false, reason: 'no_entity' };

        let accessToken;
        try {
            accessToken = await getValidAccessTokenForUser(entity.user_id);
        } catch (err) {
            const reason = /unlinked/.test(err.message) ? 'unlinked' : 'lwa_refresh_failed';
            return { ok: false, reason, error: err.message };
        }

        const event = buildChangeReportEvent({
            entity,
            entityMapping,
            accessToken,
            cause,
            nowIso: new Date(now()).toISOString()
        });
        if (!event) return { ok: false, reason: 'no_properties' };

        let res;
        try {
            res = await fetchImpl(gatewayUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${accessToken}`
                },
                body: JSON.stringify(event)
            });
        } catch (err) {
            return { ok: false, reason: 'network_error', error: err.message };
        }

        if (res.ok) {
            return { ok: true, statusCode: res.status };
        }

        // 401 / 403 mean the access token Amazon just gave us is somehow
        // wrong. We do NOT retry-with-refresh here — that path is owned by
        // getValidAccessTokenForUser via the leeway window. A 401 at this
        // point is a real "user must relink" signal.
        const bodyText = await res.text().catch(() => '');
        return {
            ok: false,
            reason: 'gateway_error',
            statusCode: res.status,
            body: bodyText
        };
    }

    /**
     * Convenience: load entity by (userId, haEntityId) and dispatch.
     */
    async function sendChangeReportForUserEntity(userId, haEntityId, opts = {}) {
        const entity = await dbGet(
            `SELECT * FROM alexa_entities WHERE user_id = ? AND entity_id = ? AND exposed = 1`,
            [userId, haEntityId]
        );
        if (!entity) return { ok: false, reason: 'entity_not_found' };
        return sendChangeReportForEntity(entity, opts);
    }

    // ── Dry-run preview (admin diagnostic) ──────────────────────────────
    //
    // Returns the exact envelope shape sendChangeReportForEntity would have
    // posted, but never touches the network and never mints a real LWA
    // access token. The bearer token in the rendered envelope is a fixed
    // placeholder so:
    //
    //   - the dry-run cannot trigger an LWA refresh as a side effect
    //     (an operator hammering this endpoint must not invalidate live
    //     refresh tokens)
    //   - the JSON is safe to paste into a chat / ticket without leaking
    //     a usable credential.
    //
    // Counters are NOT incremented — this is a debug primitive, not a
    // dispatch. If you want the counter, send the report for real.
    //
    // Returns one of:
    //   { ok: true,  event, context }
    //   { ok: false, reason: 'no_entity' }
    //   { ok: false, reason: 'no_properties' }   — out-of-scope domain
    function previewChangeReportForEntity(entity, { cause = 'PHYSICAL_INTERACTION' } = {}) {
        if (!entity) return { ok: false, reason: 'no_entity' };
        const envelope = buildChangeReportEvent({
            entity,
            entityMapping,
            accessToken: '<dry-run-placeholder>',
            cause,
            nowIso: new Date(now()).toISOString()
        });
        if (!envelope) return { ok: false, reason: 'no_properties' };
        return { ok: true, event: envelope.event, context: envelope.context };
    }

    async function previewChangeReportForUserEntity(userId, haEntityId, opts = {}) {
        const entity = await dbGet(
            `SELECT * FROM alexa_entities WHERE user_id = ? AND entity_id = ? AND exposed = 1`,
            [userId, haEntityId]
        );
        if (!entity) return { ok: false, reason: 'entity_not_found' };
        return previewChangeReportForEntity(entity, opts);
    }

    // ── Debounced scheduling ─────────────────────────────────────────────
    //
    // The `queue` Map and `flushInterval` are declared above (so the health
    // snapshot can read queue depth). The scheduling/flushing functions
    // operate on those same identifiers — JS closure scope, not magic.
    //
    // Coalescing rule: schedule() on the same (user, entity) key just bumps
    // scheduledAt forward. Net effect: a flurry of state updates produces
    // one POST per debounce window.

    function keyFor(userId, entityId) {
        return `${userId}:${entityId}`;
    }

    function scheduleChangeReportForEntity(entity, opts = {}) {
        if (!entity || !entity.user_id || !entity.entity_id) return;
        const k = keyFor(entity.user_id, entity.entity_id);
        queue.set(k, {
            entity,
            opts,
            scheduledAt: now() + (Number.isFinite(opts.delayMs) ? opts.delayMs : debounceMs)
        });
    }

    async function flushScheduledChangeReports() {
        const due = [];
        const t = now();
        for (const [k, v] of queue.entries()) {
            if (v.scheduledAt <= t) {
                due.push([k, v]);
            }
        }
        for (const [k, v] of due) {
            queue.delete(k);
            try {
                const result = await sendChangeReportForEntity(v.entity, v.opts);
                if (!result.ok) {
                    // One user's failure does NOT abort the loop. We log
                    // structured info so an operator can scrub by reason.
                    console.warn(
                        `alexa-event-gateway: ChangeReport not delivered ` +
                            `user=${v.entity.user_id} entity=${v.entity.entity_id} reason=${result.reason}` +
                            (result.statusCode ? ` status=${result.statusCode}` : '')
                    );
                }
            } catch (err) {
                // sendChangeReportForEntity is "never throws" by contract,
                // but defend against future regressions anyway.
                console.error(
                    `alexa-event-gateway: unexpected throw user=${v.entity.user_id} entity=${v.entity.entity_id}: ${err.message}`
                );
            }
        }
    }

    function startFlushLoop() {
        if (flushInterval) return;
        flushInterval = setInterval(() => {
            void flushScheduledChangeReports();
        }, Math.max(100, Math.floor(debounceMs / 2)));
        // Don't keep Node alive just for this — operator processes already
        // run forever, tests need a clean exit.
        if (typeof flushInterval.unref === 'function') flushInterval.unref();
    }

    function stopFlushLoop() {
        if (flushInterval) {
            clearInterval(flushInterval);
            flushInterval = null;
        }
    }

    // Auto-start unless the test explicitly disables.
    if (config.ALEXA_EVENT_GATEWAY_AUTO_START !== false) {
        startFlushLoop();
    }

    return {
        // pure
        buildChangeReportEvent: (opts) => buildChangeReportEvent(opts),
        // I/O
        getValidAccessTokenForUser,
        sendChangeReportForEntity,
        sendChangeReportForUserEntity,
        // Dry-run / preview (admin diagnostic). Same envelope shape, no
        // network, no LWA refresh, no counter increment.
        previewChangeReportForEntity,
        previewChangeReportForUserEntity,
        scheduleChangeReportForEntity,
        flushScheduledChangeReports,
        startFlushLoop,
        stopFlushLoop,
        // Inspection (tests + admin debug)
        _queueSize: () => queue.size,
        // Observability — read-only snapshot of dispatch counters + queue
        // depth. Used by GET /api/admin/alexa/health.
        getHealthSnapshot
    };
};

// Pure helpers exposed for unit tests.
module.exports._pure = {
    buildChangeReportEvent,
    REFRESH_LEEWAY_MS,
    DEFAULT_GATEWAY_URL,
    DEFAULT_DEBOUNCE_MS
};
