const express = require('express');

/**
 * Alexa Smart Home directive dispatcher.
 *
 * POST /api/alexa/fulfillment — the single endpoint the AWS Lambda forwarder
 * targets. Dispatches on directive.header.namespace.
 *
 * Auth model note: Alexa.Authorization/AcceptGrant carries the bearer in
 * directive.payload.grantee.token, while every other directive carries it in
 * directive.endpoint.scope.token (or payload.scope.token for Discovery). We
 * resolve the user from whichever is present rather than relying on the
 * requireAlexaBearer middleware, because AcceptGrant must run before the link
 * is fully established.
 */
module.exports = function ({ dbGet, dbRun, config, utils, core, eventGateway, entityMapping }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    function header(namespace, name, correlationToken) {
        const h = {
            namespace,
            name,
            payloadVersion: '3',
            messageId: require('crypto').randomUUID()
        };
        if (correlationToken) {
            h.correlationToken = correlationToken;
        }
        return h;
    }

    function errorResponse(res, type, message, correlationToken, endpointId) {
        const event = {
            event: {
                header: header('Alexa', 'ErrorResponse', correlationToken),
                payload: { type, message }
            }
        };
        if (endpointId) {
            event.event.endpoint = { endpointId };
        }
        return res.status(200).json(event);
    }

    function extractBearer(directive) {
        return (
            directive?.endpoint?.scope?.token ||
            directive?.payload?.scope?.token ||
            directive?.payload?.grantee?.token ||
            null
        );
    }

    function buildContextProperties(endpointRow) {
        const props = entityMapping.parseAlexaEndpointState(endpointRow);
        return eventGateway.buildProperties(props);
    }

    router.post(
        '/api/alexa/fulfillment',
        asyncHandler(async (req, res) => {
            const directive = req.body?.directive;
            if (!directive || !directive.header) {
                return errorResponse(res, 'INVALID_DIRECTIVE', 'Missing directive');
            }

            const namespace = directive.header.namespace;
            const name = directive.header.name;
            const correlationToken = directive.header.correlationToken;

            // ── AcceptGrant: establish the LWA link ─────────────────────
            if (namespace === 'Alexa.Authorization' && name === 'AcceptGrant') {
                const grantCode = directive?.payload?.grant?.code;
                const granteeToken = directive?.payload?.grantee?.token;
                if (!grantCode || !granteeToken) {
                    return res.status(200).json({
                        event: {
                            header: header('Alexa.Authorization', 'ErrorResponse'),
                            payload: { type: 'ACCEPT_GRANT_FAILED', message: 'Missing grant code or grantee token' }
                        }
                    });
                }

                const user = await core.findUserByAlexaAccessToken(granteeToken);
                if (!user) {
                    return res.status(200).json({
                        event: {
                            header: header('Alexa.Authorization', 'ErrorResponse'),
                            payload: { type: 'ACCEPT_GRANT_FAILED', message: 'Unknown grantee token' }
                        }
                    });
                }

                try {
                    // Exchange the authorization_code grant for LWA tokens.
                    const body = new URLSearchParams({
                        grant_type: 'authorization_code',
                        code: grantCode,
                        client_id: config.ALEXA_LWA_CLIENT_ID,
                        client_secret: config.ALEXA_LWA_CLIENT_SECRET
                    });
                    const lwaRes = await fetch(config.ALEXA_LWA_TOKEN_URI, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
                        body: body.toString()
                    });
                    const lwaJson = await lwaRes.json().catch(() => null);
                    if (!lwaRes.ok || !lwaJson?.access_token || !lwaJson?.refresh_token) {
                        return res.status(200).json({
                            event: {
                                header: header('Alexa.Authorization', 'ErrorResponse'),
                                payload: {
                                    type: 'ACCEPT_GRANT_FAILED',
                                    message: lwaJson?.error_description || 'LWA token exchange failed'
                                }
                            }
                        });
                    }

                    await core.storeAlexaLwaTokens(user.id, {
                        accessToken: lwaJson.access_token,
                        refreshToken: lwaJson.refresh_token,
                        expiresInSeconds: Number(lwaJson.expires_in) || 3600
                    });
                    await dbRun(`UPDATE users SET alexa_linked = 1 WHERE id = ?`, [user.id]);

                    // Proactively send the initial inventory now that we can reach the gateway.
                    eventGateway.scheduleAlexaAddOrUpdateReportForUser(user.id, 'accept_grant');

                    return res.status(200).json({
                        event: {
                            header: header('Alexa.Authorization', 'AcceptGrant.Response'),
                            payload: {}
                        }
                    });
                } catch (error) {
                    console.error('ALEXA ACCEPT_GRANT ERROR:', error);
                    return res.status(200).json({
                        event: {
                            header: header('Alexa.Authorization', 'ErrorResponse'),
                            payload: { type: 'ACCEPT_GRANT_FAILED', message: 'Internal error during grant' }
                        }
                    });
                }
            }

            // ── All other directives: resolve user from bearer ──────────
            const bearer = extractBearer(directive);
            if (!bearer) {
                return errorResponse(res, 'INVALID_AUTHORIZATION_CREDENTIAL', 'Missing bearer token', correlationToken);
            }
            const user = await core.findUserByAlexaAccessToken(bearer);
            if (!user) {
                return errorResponse(
                    res,
                    'INVALID_AUTHORIZATION_CREDENTIAL',
                    'Invalid or expired access token',
                    correlationToken
                );
            }
            if (!user.alexa_enabled || !utils.isAccessEnabled(user.status)) {
                return errorResponse(res, 'INTERNAL_ERROR', 'Alexa integration disabled', correlationToken);
            }

            // ── Discovery ───────────────────────────────────────────────
            if (namespace === 'Alexa.Discovery' && name === 'Discover') {
                const rows = await core.getAlexaEndpointsForUser(user.id);
                const endpoints = (rows || []).map((r) => entityMapping.buildAlexaEndpoint(r)).filter(Boolean);
                return res.status(200).json({
                    event: {
                        header: header('Alexa.Discovery', 'Discover.Response'),
                        payload: { endpoints }
                    }
                });
            }

            // ── ReportState ─────────────────────────────────────────────
            if (namespace === 'Alexa' && name === 'ReportState') {
                const endpointId = directive?.endpoint?.endpointId;
                const row = await dbGet(`SELECT * FROM alexa_endpoints WHERE user_id = ? AND entity_id = ? LIMIT 1`, [
                    user.id,
                    utils.sanitizeEntityId(endpointId)
                ]);
                if (!row) {
                    return errorResponse(res, 'NO_SUCH_ENDPOINT', 'Unknown endpoint', correlationToken, endpointId);
                }
                return res.status(200).json({
                    event: {
                        header: header('Alexa', 'StateReport', correlationToken),
                        endpoint: { endpointId },
                        payload: {}
                    },
                    context: { properties: buildContextProperties(row) }
                });
            }

            // ── Control directives ──────────────────────────────────────
            const controlNamespaces = [
                'Alexa.PowerController',
                'Alexa.BrightnessController',
                'Alexa.ColorController',
                'Alexa.ColorTemperatureController'
            ];
            if (controlNamespaces.includes(namespace)) {
                const endpointId = directive?.endpoint?.endpointId;
                const row = await dbGet(`SELECT * FROM alexa_endpoints WHERE user_id = ? AND entity_id = ? LIMIT 1`, [
                    user.id,
                    utils.sanitizeEntityId(endpointId)
                ]);
                if (!row) {
                    return errorResponse(res, 'NO_SUCH_ENDPOINT', 'Unknown endpoint', correlationToken, endpointId);
                }

                // Translate the directive into an internal action + optimistic state.
                const { action, payload, optimisticState } = translateControlDirective(namespace, name, directive, row);
                if (!action) {
                    return errorResponse(res, 'INVALID_DIRECTIVE', `Unsupported directive ${namespace}/${name}`, correlationToken, endpointId);
                }

                await core.queueAlexaCommandForEndpoint(user.id, row.device_id, row.entity_id, action, payload);

                // Build an optimistic context from the merged state.
                const mergedRow = {
                    ...row,
                    state_json: JSON.stringify({ ...utils.parseJsonSafe(row.state_json, {}), ...optimisticState })
                };
                return res.status(200).json({
                    event: {
                        header: header('Alexa', 'Response', correlationToken),
                        endpoint: { scope: { type: 'BearerToken', token: bearer }, endpointId },
                        payload: {}
                    },
                    context: { properties: buildContextProperties(mergedRow) }
                });
            }

            return errorResponse(res, 'INVALID_DIRECTIVE', `Unhandled namespace ${namespace}`, correlationToken);
        })
    );

    function translateControlDirective(namespace, name, directive, row) {
        const payload = directive?.payload || {};
        if (namespace === 'Alexa.PowerController') {
            const on = name === 'TurnOn';
            return { action: on ? 'turn_on' : 'turn_off', payload: { on }, optimisticState: { on } };
        }
        if (namespace === 'Alexa.BrightnessController') {
            if (name === 'SetBrightness') {
                const brightness = Math.max(0, Math.min(100, Math.round(Number(payload.brightness) || 0)));
                return { action: 'set_brightness', payload: { brightness }, optimisticState: { on: brightness > 0, brightness } };
            }
            if (name === 'AdjustBrightness') {
                const current = Number(utils.parseJsonSafe(row.state_json, {}).brightness) || 0;
                const delta = Number(payload.brightnessDelta) || 0;
                const brightness = Math.max(0, Math.min(100, Math.round(current + delta)));
                return { action: 'set_brightness', payload: { brightness }, optimisticState: { on: brightness > 0, brightness } };
            }
        }
        if (namespace === 'Alexa.ColorController' && name === 'SetColor') {
            const color = payload.color || {};
            const hue = Number(color.hue) || 0;
            const saturation = Number(color.saturation) || 0;
            return {
                action: 'set_color',
                payload: { hs_color: [hue, Math.round(saturation * 100)] },
                optimisticState: { on: true, hs_color: [hue, Math.round(saturation * 100)] }
            };
        }
        if (namespace === 'Alexa.ColorTemperatureController' && name === 'SetColorTemperature') {
            const kelvin = Number(payload.colorTemperatureInKelvin) || 3000;
            return {
                action: 'set_color_temp',
                payload: { color_temp_kelvin: kelvin },
                optimisticState: { on: true, color_temp_kelvin: kelvin }
            };
        }
        return { action: null };
    }

    return router;
};
