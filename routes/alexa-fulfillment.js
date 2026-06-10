const express = require('express');
const { translateControlDirective, CONTROL_NAMESPACES } = require('../lib/alexa/directives');

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

    // Defense in depth: when ALEXA_FORWARDER_SECRET is configured, every
    // directive must arrive with a matching X-Alexa-Forwarder-Secret header
    // (set by alexa-lambda/index.js). This rejects directives POSTed to the
    // portal directly, bypassing the Lambda. Skipped entirely when unset so an
    // un-provisioned deployment is unaffected. Timing-safe to avoid leaking the
    // secret via response-time analysis.
    function forwarderSecretOk(req) {
        const expected = config.ALEXA_FORWARDER_SECRET || '';
        if (!expected) {
            return true; // not configured → check disabled
        }
        const received = req.get('x-alexa-forwarder-secret') || '';
        const expectedBuffer = Buffer.from(expected);
        const receivedBuffer = Buffer.from(received);
        if (expectedBuffer.length !== receivedBuffer.length) {
            return false;
        }
        return require('crypto').timingSafeEqual(expectedBuffer, receivedBuffer);
    }

    function buildContextProperties(endpointRow) {
        const props = entityMapping.parseAlexaEndpointState(endpointRow);
        return eventGateway.buildProperties(props);
    }

    router.post(
        '/api/alexa/fulfillment',
        asyncHandler(async (req, res) => {
            if (!forwarderSecretOk(req)) {
                return errorResponse(res, 'INVALID_AUTHORIZATION_CREDENTIAL', 'Invalid forwarder secret');
            }

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
                const discoverOptions = { userHasSecurityPin: Boolean(user.alexa_security_pin) };
                const endpoints = (rows || []).map((r) => entityMapping.buildAlexaEndpoint(r, discoverOptions)).filter(Boolean);
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
                if (!row || !row.exposed) {
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

            // ── CameraStreamController (camera) ─────────────────────────
            // InitializeCameraStreams must return a stream URI SYNCHRONOUSLY
            // (≤6s). Execution is async (queue → add-on polls → result), so we
            // queue get_camera_stream then block briefly on the result. The
            // add-on returns public absolute stream/image URLs (HA HLS via the
            // customer subdomain). Best-effort: some Echo Show models want RTSP.
            if (namespace === 'Alexa.CameraStreamController') {
                const endpointId = directive?.endpoint?.endpointId;
                const row = await dbGet(`SELECT * FROM alexa_endpoints WHERE user_id = ? AND entity_id = ? LIMIT 1`, [
                    user.id,
                    utils.sanitizeEntityId(endpointId)
                ]);
                if (!row || !row.exposed) {
                    return errorResponse(res, 'NO_SUCH_ENDPOINT', 'Unknown endpoint', correlationToken, endpointId);
                }
                if (name !== 'InitializeCameraStreams') {
                    return errorResponse(res, 'INVALID_DIRECTIVE', `Unsupported camera directive ${name}`, correlationToken, endpointId);
                }
                const cmd = await core.queueAlexaCommandForEndpoint(user.id, row.device_id, row.entity_id, 'get_camera_stream', {});
                const outcome = cmd ? await core.waitForAlexaCommandResult(cmd.id, 5000) : null;
                const camState = outcome?.status === 'completed' ? outcome.result?.state : null;
                const streamUrl = camState?.stream_url;
                if (!streamUrl) {
                    // Timed out, failed, or device offline.
                    return errorResponse(res, 'ENDPOINT_UNREACHABLE', 'Camera stream unavailable', correlationToken, endpointId);
                }
                const expirationTime = new Date(Date.now() + 5 * 60 * 1000).toISOString();
                return res.status(200).json({
                    event: {
                        header: header('Alexa.CameraStreamController', 'Response', correlationToken),
                        endpoint: { scope: { type: 'BearerToken', token: bearer }, endpointId },
                        payload: {
                            cameraStreams: [
                                {
                                    uri: streamUrl,
                                    protocol: 'HLS',
                                    resolution: { width: 1280, height: 720 },
                                    authorizationType: 'NONE',
                                    videoCodec: 'H264',
                                    audioCodec: 'AAC',
                                    expirationTime,
                                    idleTimeoutSeconds: 30
                                }
                            ],
                            imageUri: camState?.image_url || streamUrl
                        }
                    }
                });
            }

            // ── SceneController (scene/script/button/input_button) ──────
            // Stateless activation with a NON-standard response envelope
            // (Alexa.SceneController/ActivationStarted), distinct from the
            // generic Alexa/Response used by stateful controllers.
            if (namespace === 'Alexa.SceneController') {
                const endpointId = directive?.endpoint?.endpointId;
                const row = await dbGet(`SELECT * FROM alexa_endpoints WHERE user_id = ? AND entity_id = ? LIMIT 1`, [
                    user.id,
                    utils.sanitizeEntityId(endpointId)
                ]);
                if (!row || !row.exposed) {
                    return errorResponse(res, 'NO_SUCH_ENDPOINT', 'Unknown endpoint', correlationToken, endpointId);
                }
                if (name !== 'Activate' && name !== 'Deactivate') {
                    return errorResponse(res, 'INVALID_DIRECTIVE', `Unsupported scene directive ${name}`, correlationToken, endpointId);
                }
                const activate = name === 'Activate';
                await core.queueAlexaCommandForEndpoint(
                    user.id,
                    row.device_id,
                    row.entity_id,
                    activate ? 'activate_scene' : 'deactivate_scene',
                    {}
                );
                return res.status(200).json({
                    event: {
                        header: header('Alexa.SceneController', activate ? 'ActivationStarted' : 'DeactivationStarted', correlationToken),
                        endpoint: { scope: { type: 'BearerToken', token: bearer }, endpointId },
                        payload: {
                            cause: { type: 'VOICE_INTERACTION' },
                            timestamp: new Date().toISOString()
                        }
                    }
                });
            }

            // ── SecurityPanelController (alarm_control_panel) ───────────
            // Arm needs no PIN; Disarm requires the user's 4-digit PIN when one
            // is configured. Uses bespoke Arm.Response / ErrorResponse envelopes.
            if (namespace === 'Alexa.SecurityPanelController') {
                const endpointId = directive?.endpoint?.endpointId;
                const row = await dbGet(`SELECT * FROM alexa_endpoints WHERE user_id = ? AND entity_id = ? LIMIT 1`, [
                    user.id,
                    utils.sanitizeEntityId(endpointId)
                ]);
                if (!row || !row.exposed) {
                    return errorResponse(res, 'NO_SUCH_ENDPOINT', 'Unknown endpoint', correlationToken, endpointId);
                }

                if (name === 'Disarm') {
                    const pin = user.alexa_security_pin ? String(user.alexa_security_pin) : '';
                    if (pin) {
                        const auth = directive?.payload?.authorization;
                        const provided = auth && auth.type === 'FOUR_DIGIT_PIN' ? String(auth.value || '') : '';
                        if (!provided || provided !== pin) {
                            // UNAUTHORIZED → Alexa prompts the user for the PIN and re-sends.
                            return res.status(200).json({
                                event: {
                                    header: header('Alexa.SecurityPanelController', 'ErrorResponse', correlationToken),
                                    endpoint: { endpointId },
                                    payload: { type: 'UNAUTHORIZED', message: 'PIN required or incorrect' }
                                }
                            });
                        }
                    }
                    await core.queueAlexaCommandForEndpoint(user.id, row.device_id, row.entity_id, 'arm_disarm', { arm: false });
                    return res.status(200).json({
                        event: {
                            header: header('Alexa', 'Response', correlationToken),
                            endpoint: { scope: { type: 'BearerToken', token: bearer }, endpointId },
                            payload: {}
                        },
                        context: {
                            properties: [
                                {
                                    namespace: 'Alexa.SecurityPanelController',
                                    name: 'armState',
                                    value: 'DISARMED',
                                    timeOfSample: new Date().toISOString(),
                                    uncertaintyInMilliseconds: 0
                                }
                            ]
                        }
                    });
                }

                if (name === 'Arm') {
                    const armState = directive?.payload?.armState || 'ARMED_STAY';
                    const armLevel =
                        armState === 'ARMED_AWAY' ? 'arm_away' : armState === 'ARMED_NIGHT' ? 'arm_night' : 'arm_home';
                    await core.queueAlexaCommandForEndpoint(user.id, row.device_id, row.entity_id, 'arm_disarm', {
                        arm: true,
                        arm_level: armLevel
                    });
                    return res.status(200).json({
                        event: {
                            header: header('Alexa.SecurityPanelController', 'Arm.Response', correlationToken),
                            endpoint: { scope: { type: 'BearerToken', token: bearer }, endpointId },
                            payload: { armState }
                        }
                    });
                }

                return errorResponse(res, 'INVALID_DIRECTIVE', `Unsupported alarm directive ${name}`, correlationToken, endpointId);
            }

            // ── Control directives ──────────────────────────────────────
            if (CONTROL_NAMESPACES.includes(namespace)) {
                const endpointId = directive?.endpoint?.endpointId;
                const row = await dbGet(`SELECT * FROM alexa_endpoints WHERE user_id = ? AND entity_id = ? LIMIT 1`, [
                    user.id,
                    utils.sanitizeEntityId(endpointId)
                ]);
                if (!row || !row.exposed) {
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

    return router;
};
