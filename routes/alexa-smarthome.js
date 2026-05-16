/**
 * Alexa Smart Home directive handler.
 *
 *   POST /api/alexa/smarthome
 *
 * Single endpoint that accepts every Alexa Smart Home directive forwarded
 * from our Lambda (lambda/alexa-forwarder/index.mjs). Dispatches by
 * `directive.header.namespace` + `directive.header.name`.
 *
 * ─── Why one endpoint, not many ────────────────────────────────────────────
 *
 * Alexa always POSTs the directive envelope to a single skill URL — there is
 * no per-namespace routing on Amazon's side. Splitting this into multiple
 * Express routes would mean re-parsing the envelope and duplicating bearer
 * resolution. One handler, one dispatcher, well-formed Alexa.ErrorResponse
 * on every failure path.
 *
 * ─── Lessons from the v1 post-mortem encoded here ──────────────────────────
 *
 * 1. AcceptGrant: v1 returned AcceptGrant.Response from a try/catch that
 *    swallowed the LWA exchange failure. Subsequent ChangeReports then 401'd
 *    because no LWA refresh token was actually stored. Here, AcceptGrant
 *    explicitly throws on partial state and the dispatcher wraps that as
 *    Alexa.ErrorResponse(ACCEPT_GRANT_FAILED) — Alexa surfaces this to the
 *    customer as "Couldn't link" rather than the silent "linked but broken".
 *
 * 2. Discovery payloads are validated before they leave this file. If
 *    `validateDiscoveryPayload` rejects what we built, we send back a small
 *    empty Discover.Response rather than 500 — Alexa retries Discovery on
 *    its own cadence and a clean empty response gives the customer a clear
 *    "no devices yet" message instead of a hard error.
 *
 * 3. Bearer resolution is done EXACTLY ONCE per directive, before dispatch.
 *    The token's location varies by directive type (payload.scope.token vs.
 *    payload.grantee.token vs. endpoint.scope.token); centralizing that
 *    extraction means we don't sprinkle the same `?? ?? ??` chain through
 *    every handler.
 *
 * ─── Synchronous-over-queue control flow ───────────────────────────────────
 *
 * Alexa expects a Response/ErrorResponse within ~8s. The addon polls our
 * command queue on a ~1s cadence and posts the result back when it lands.
 * Inside the directive handler we:
 *
 *   1. Insert into alexa_command_queue (status='pending')
 *   2. Poll for status in ('completed', 'failed', 'expired') with a budget
 *      (default 5s, configurable via ALEXA_CONTROL_RESPONSE_TIMEOUT_MS)
 *   3. Translate the row's status into Response or ErrorResponse
 *
 * If the budget elapses we mark the row 'expired' (so the addon doesn't
 * later execute a stale command) and return ENDPOINT_UNREACHABLE. The
 * alternative — letting Alexa time out the HTTP call — looks identical to
 * the customer but leaves the addon free to flip the bulb 30s late.
 *
 * ─── Factory inputs ────────────────────────────────────────────────────────
 *
 *   { dbGet, dbRun, dbAll, config, utils, alexaCore, entityMapping,
 *     lwaExchange? }
 *
 * `lwaExchange(code, redirectUri)` is injectable so the AcceptGrant tests
 * don't need to mock global fetch. Defaults to a real fetch against
 * api.amazon.com/auth/o2/token. Returns
 * `{ access_token, refresh_token, expires_in, scope }` or throws.
 */

const express = require('express');
const crypto = require('node:crypto');
const { validateDiscoveryPayload } = require('../lib/alexa/discovery-validator');

// Default LWA exchange. Pulled out so tests can inject a stub.
async function defaultLwaExchange(code, redirectUri) {
    const clientId = process.env.ALEXA_LWA_CLIENT_ID || '';
    const clientSecret = process.env.ALEXA_LWA_CLIENT_SECRET || '';
    if (!clientId || !clientSecret) {
        // Treat config gaps as the same hard failure as a network error —
        // Alexa just sees ACCEPT_GRANT_FAILED, operator sees the cause in
        // logs.
        throw new Error('LWA client credentials missing (set ALEXA_LWA_CLIENT_ID / ALEXA_LWA_CLIENT_SECRET)');
    }
    const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri || ''
    });
    const res = await fetch('https://api.amazon.com/auth/o2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString()
    });
    if (!res.ok) {
        const text = await res.text().catch(() => '');
        throw new Error(`LWA exchange failed: HTTP ${res.status} ${text}`);
    }
    return await res.json();
}

// Header builder shared across every response shape.
function makeHeader(directive, name, overrides = {}) {
    const inHeader = directive?.header || {};
    return {
        namespace: overrides.namespace || inHeader.namespace,
        name,
        messageId: crypto.randomUUID(),
        correlationToken: inHeader.correlationToken,
        payloadVersion: '3'
    };
}

function errorResponse(directive, type, message, extras = {}) {
    return {
        event: {
            header: makeHeader(directive, 'ErrorResponse', { namespace: 'Alexa' }),
            // Echo endpoint when present (control/state directives) so Alexa
            // surfaces the error against the right device card.
            ...(directive?.endpoint
                ? { endpoint: { endpointId: directive.endpoint.endpointId } }
                : {}),
            payload: { type, message, ...extras }
        }
    };
}

// Pull the bearer token out of the directive — location depends on the
// namespace. Returns null if not found.
function extractBearer(directive) {
    return (
        directive?.endpoint?.scope?.token ||
        directive?.payload?.scope?.token ||
        directive?.payload?.grantee?.token ||
        null
    );
}

module.exports = function createAlexaSmarthomeRoute({
    dbGet,
    dbRun,
    dbAll,
    config,
    utils,
    alexaCore,
    entityMapping,
    lwaExchange
}) {
    const router = express.Router();
    const { asyncHandler, isAccessEnabled } = utils;
    const exchange = typeof lwaExchange === 'function' ? lwaExchange : defaultLwaExchange;

    // ── Internal helpers ──────────────────────────────────────────────────

    async function resolveUserFromBearer(token) {
        if (!token) return null;
        const user = await alexaCore.findUserByAlexaAccessToken(token);
        if (!user) return null;
        if (!user.alexa_enabled) return { user: null, reason: 'disabled' };
        if (!isAccessEnabled(user.status)) return { user: null, reason: 'inactive' };
        return { user, reason: null };
    }

    // Lookup an exposed entity by (user_id, decoded entity_id). Returns null
    // if not found OR if found but not exposed — caller emits NO_SUCH_ENDPOINT.
    async function lookupEntity(userId, encodedEndpointId) {
        const haEntityId = entityMapping.decodeEndpointId(encodedEndpointId);
        if (!haEntityId) return null;
        const row = await dbGet(
            `SELECT * FROM alexa_entities WHERE user_id = ? AND entity_id = ? AND exposed = 1`,
            [userId, haEntityId]
        );
        return row || null;
    }

    function controlResponseTimeoutMs() {
        const v = Number(config.ALEXA_CONTROL_RESPONSE_TIMEOUT_MS);
        if (!Number.isFinite(v)) return 5000;
        return Math.max(500, Math.min(7500, Math.round(v)));
    }

    // ── Directive handlers ────────────────────────────────────────────────

    async function handleDiscovery(directive, user) {
        const rows = await dbAll(
            `SELECT * FROM alexa_entities WHERE user_id = ? AND exposed = 1`,
            [user.id]
        );

        const endpoints = [];
        for (const row of rows) {
            try {
                const ep = entityMapping.buildAlexaEndpoint(row);
                if (ep) endpoints.push(ep);
            } catch (err) {
                // One bad entity must not poison the whole Discovery payload —
                // log it so the operator can investigate, skip it from the
                // response. v1 sometimes returned the whole batch as 500.
                console.error(
                    `Alexa Discovery: skipping entity ${row.entity_id} for user ${user.id}: ${err.message}`
                );
            }
        }

        const payload = {
            event: {
                header: {
                    namespace: 'Alexa.Discovery',
                    name: 'Discover.Response',
                    messageId: crypto.randomUUID(),
                    payloadVersion: '3'
                },
                payload: { endpoints }
            }
        };

        // Hard contract: if we somehow built something the validator hates,
        // strip endpoints and return an empty Discover.Response. Alexa will
        // poll Discovery again later; an empty response is recoverable, a
        // 500 is not.
        const v = validateDiscoveryPayload(payload);
        if (!v.ok) {
            console.error(
                `Alexa Discovery: validator rejected built payload for user ${user.id}: ` +
                    v.errors.map((e) => `${e.path}: ${e.message}`).join('; ')
            );
            payload.event.payload.endpoints = [];
        }
        return payload;
    }

    async function handleAcceptGrant(directive, user) {
        // The grant code is a short-lived LWA auth code; exchange it for an
        // LWA refresh token + access token. Anything that fails here MUST
        // surface as ACCEPT_GRANT_FAILED, not AcceptGrant.Response — that
        // was the v1 mistake.
        const code = directive?.payload?.grant?.code;
        if (typeof code !== 'string' || !code) {
            return errorResponse(directive, 'INVALID_AUTHORIZATION_CREDENTIAL', 'missing grant.code', {});
        }

        let lwa;
        try {
            // No redirect_uri at AcceptGrant — Amazon docs say omit it for
            // skill linking grants.
            lwa = await exchange(code, '');
        } catch (err) {
            console.error(`AcceptGrant: LWA exchange failed for user ${user.id}: ${err.message}`);
            return errorResponse(
                directive,
                'ACCEPT_GRANT_FAILED',
                'Could not exchange the grant code with Login with Amazon',
                {}
            );
        }

        try {
            await alexaCore.storeAcceptGrantTokens(user.id, {
                accessToken: lwa.access_token,
                refreshToken: lwa.refresh_token,
                expiresIn: lwa.expires_in,
                scopes: lwa.scope || lwa.scopes || null
            });
        } catch (err) {
            console.error(`AcceptGrant: storeAcceptGrantTokens threw for user ${user.id}: ${err.message}`);
            return errorResponse(
                directive,
                'ACCEPT_GRANT_FAILED',
                'Could not persist the linked Alexa account credentials',
                {}
            );
        }

        return {
            event: {
                header: makeHeader(directive, 'AcceptGrant.Response'),
                payload: {}
            }
        };
    }

    async function handleReportState(directive, user) {
        const epId = directive?.endpoint?.endpointId;
        const entity = await lookupEntity(user.id, epId);
        if (!entity) {
            return errorResponse(directive, 'NO_SUCH_ENDPOINT', `unknown endpoint ${epId}`);
        }
        const properties = entityMapping.buildPropertyState(entity);
        return {
            event: {
                header: makeHeader(directive, 'StateReport', { namespace: 'Alexa' }),
                endpoint: { endpointId: epId },
                payload: {}
            },
            context: { properties }
        };
    }

    async function handleControl(directive, user) {
        const epId = directive?.endpoint?.endpointId;
        const entity = await lookupEntity(user.id, epId);
        if (!entity) {
            return errorResponse(directive, 'NO_SUCH_ENDPOINT', `unknown endpoint ${epId}`);
        }

        const resolved = entityMapping.resolveDirective(directive, entity);
        if (!resolved) {
            return errorResponse(
                directive,
                'INVALID_DIRECTIVE',
                `cannot map ${directive.header.namespace}/${directive.header.name} for ${entity.entity_id}`
            );
        }

        // Enqueue the command for the addon to pick up.
        const ttlSeconds = alexaCore.getAlexaCommandTtlSeconds();
        const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
        const insert = await dbRun(
            `INSERT INTO alexa_command_queue
                (user_id, device_id, entity_id, action, payload_json, status, expires_at)
             VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
            [
                user.id,
                entity.device_id,
                entity.entity_id,
                resolved.service,
                JSON.stringify(resolved.payload || {}),
                expiresAt
            ]
        );
        const commandId = insert.lastID;

        // Poll for completion within the response budget. Sleep + re-check
        // is dumb but predictable; an event-driven solution would need a
        // cross-process notifier (Redis pub/sub etc.) that the project
        // doesn't otherwise need.
        const deadline = Date.now() + controlResponseTimeoutMs();
        const POLL_MS = 100;
        let row = null;
        while (Date.now() < deadline) {
            row = await dbGet(`SELECT status, result_json FROM alexa_command_queue WHERE id = ?`, [
                commandId
            ]);
            if (row && row.status !== 'pending' && row.status !== 'dispatched') break;
            await new Promise((r) => {
                setTimeout(r, POLL_MS);
            });
        }

        if (!row || row.status === 'pending' || row.status === 'dispatched') {
            // Mark as expired so the addon doesn't fire it late.
            await dbRun(
                `UPDATE alexa_command_queue SET status = 'expired', updated_at = ? WHERE id = ? AND status IN ('pending','dispatched')`,
                [new Date().toISOString(), commandId]
            );
            return errorResponse(directive, 'ENDPOINT_UNREACHABLE', 'device did not respond in time');
        }

        if (row.status === 'failed' || row.status === 'expired') {
            return errorResponse(
                directive,
                'INTERNAL_ERROR',
                `command failed: ${row.result_json || row.status}`
            );
        }

        // Optimistic property emission: the addon also updates state_json
        // shortly after, but for the immediate response we synthesize the
        // expected new state from the directive itself.
        const nowIso = new Date().toISOString();
        const properties = optimisticPropertiesFromDirective(directive, entity, nowIso);

        return {
            event: {
                header: makeHeader(directive, 'Response', { namespace: 'Alexa' }),
                endpoint: { endpointId: epId },
                payload: {}
            },
            context: { properties }
        };
    }

    function optimisticPropertiesFromDirective(directive, entity, nowIso) {
        const ns = directive.header.namespace;
        const name = directive.header.name;
        const props = [
            {
                namespace: 'Alexa.EndpointHealth',
                name: 'connectivity',
                value: { value: 'OK' },
                timeOfSample: nowIso,
                uncertaintyInMilliseconds: 1000
            }
        ];
        if (ns === 'Alexa.PowerController') {
            props.push({
                namespace: 'Alexa.PowerController',
                name: 'powerState',
                value: name === 'TurnOn' ? 'ON' : 'OFF',
                timeOfSample: nowIso,
                uncertaintyInMilliseconds: 1000
            });
        }
        if (ns === 'Alexa.BrightnessController' && name === 'SetBrightness') {
            const b = directive?.payload?.brightness;
            if (Number.isFinite(b)) {
                props.push({
                    namespace: 'Alexa.BrightnessController',
                    name: 'brightness',
                    value: Math.round(b),
                    timeOfSample: nowIso,
                    uncertaintyInMilliseconds: 1000
                });
            }
        }
        // Defensive use of `entity` so lint sees it; it's reserved for
        // future per-entity property synthesis (color temp, etc).
        void entity;
        return props;
    }

    // ── Dispatcher ────────────────────────────────────────────────────────

    async function dispatch(directive) {
        const ns = directive?.header?.namespace;
        const name = directive?.header?.name;

        // Bearer-less directives are not a thing in Smart Home v3, but be
        // explicit so a missing token gives a real error not a TypeError.
        const token = extractBearer(directive);
        const resolved = await resolveUserFromBearer(token);

        if (!resolved) {
            return errorResponse(directive, 'INVALID_AUTHORIZATION_CREDENTIAL', 'invalid bearer token');
        }
        if (resolved.reason === 'disabled' || resolved.reason === 'inactive') {
            return errorResponse(
                directive,
                'INVALID_AUTHORIZATION_CREDENTIAL',
                `account ${resolved.reason} for Alexa integration`
            );
        }

        const user = resolved.user;

        if (ns === 'Alexa.Discovery' && name === 'Discover') return handleDiscovery(directive, user);
        if (ns === 'Alexa.Authorization' && name === 'AcceptGrant') return handleAcceptGrant(directive, user);
        if (ns === 'Alexa' && name === 'ReportState') return handleReportState(directive, user);
        if (ns === 'Alexa.PowerController' || ns === 'Alexa.BrightnessController') {
            return handleControl(directive, user);
        }

        return errorResponse(directive, 'INVALID_DIRECTIVE', `unsupported directive ${ns}/${name}`);
    }

    // ── HTTP route ────────────────────────────────────────────────────────

    router.post(
        '/api/alexa/smarthome',
        asyncHandler(async (req, res) => {
            const directive = req.body?.directive;
            if (!directive || typeof directive !== 'object') {
                // No directive envelope — return ErrorResponse anyway so the
                // forwarder Lambda can pass it through as-is.
                return res.status(200).json(
                    errorResponse(
                        { header: {} },
                        'INVALID_DIRECTIVE',
                        'request body must contain a `directive` object'
                    )
                );
            }
            try {
                const out = await dispatch(directive);
                return res.status(200).json(out);
            } catch (err) {
                console.error('Alexa Smart Home: unhandled dispatcher error:', err);
                return res
                    .status(200)
                    .json(errorResponse(directive, 'INTERNAL_ERROR', 'unhandled error processing directive'));
            }
        })
    );

    return router;
};

// Export internals so unit tests can exercise the helpers directly.
module.exports._test = {
    extractBearer,
    errorResponse,
    makeHeader,
    defaultLwaExchange
};
