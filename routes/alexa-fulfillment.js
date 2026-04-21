const express = require('express');
const crypto = require('crypto');

// Alexa Smart Home skill fulfillment endpoint.
// Mirrors routes/google-home-fulfillment.js — dispatches Alexa directives
// to internal action strings and queues them in google_home_command_queue
// via googleCore.queueGoogleCommandForEntity (the queue is voice-agent-neutral).

module.exports = function ({
    config,
    utils,
    auth,
    googleCore,
    alexaEvents,
    alexaDirectiveMapping
}) {
    const router = express.Router();

    function makeMessageId() {
        return crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
    }

    function buildErrorResponse(directive, type, message) {
        const header = directive?.header || {};
        return {
            event: {
                header: {
                    namespace: 'Alexa',
                    name: 'ErrorResponse',
                    messageId: makeMessageId(),
                    correlationToken: header.correlationToken,
                    payloadVersion: '3'
                },
                endpoint: directive?.endpoint
                    ? { endpointId: directive.endpoint.endpointId }
                    : undefined,
                payload: { type, message }
            }
        };
    }

    function buildDeferredResponse(directive, properties = []) {
        const header = directive?.header || {};
        const endpoint = directive?.endpoint || {};
        return {
            context: { properties },
            event: {
                header: {
                    namespace: 'Alexa',
                    name: 'Response',
                    messageId: makeMessageId(),
                    correlationToken: header.correlationToken,
                    payloadVersion: '3'
                },
                endpoint: {
                    scope: endpoint.scope,
                    endpointId: endpoint.endpointId
                },
                payload: {}
            }
        };
    }

    router.post('/api/alexa/fulfillment', auth.requireAlexaBearer, async (req, res) => {
        const directive = req.body?.directive;
        if (!directive || !directive.header) {
            return res.status(400).json({ error: 'invalid_directive' });
        }

        const namespace = directive.header.namespace || '';
        const name = directive.header.name || '';

        try {
            // ── Alexa.Discovery ─────────────────────────────────────────
            if (namespace === 'Alexa.Discovery' && name === 'Discover') {
                const entities = await googleCore.getGoogleEntitiesForUser(req.alexaUser.id, {
                    includeDisabled: false
                });
                const userPin = req.alexaUser.alexa_security_pin || null;
                const endpoints = entities
                    .map((entity) => alexaDirectiveMapping.buildAlexaEndpoint(entity, userPin))
                    .filter(Boolean);

                return res.status(200).json({
                    event: {
                        header: {
                            namespace: 'Alexa.Discovery',
                            name: 'Discover.Response',
                            messageId: makeMessageId(),
                            payloadVersion: '3'
                        },
                        payload: { endpoints }
                    }
                });
            }

            // ── Alexa.Authorization.AcceptGrant (skill linking LWA handshake) ──
            if (namespace === 'Alexa.Authorization' && name === 'AcceptGrant') {
                const grantCode = directive?.payload?.grant?.code;
                const result = await alexaEvents.exchangeAlexaGrantCodeForTokens(req.alexaUser.id, grantCode);
                if (!result?.ok) {
                    console.error('ALEXA ACCEPT_GRANT FAILED:', result?.reason);
                    return res.status(200).json({
                        event: {
                            header: {
                                namespace: 'Alexa.Authorization',
                                name: 'ErrorResponse',
                                messageId: makeMessageId(),
                                payloadVersion: '3'
                            },
                            payload: {
                                type: 'ACCEPT_GRANT_FAILED',
                                message: result?.reason || 'Unable to exchange grant code'
                            }
                        }
                    });
                }

                // Kick off an initial discovery + state push now that we can reach the event gateway.
                try {
                    alexaEvents.scheduleAlexaDiscoveryUpdateForUser(req.alexaUser.id, 'accept_grant');
                    alexaEvents.scheduleAlexaChangeReportForUser(req.alexaUser.id, { force: true });
                } catch (_scheduleErr) {
                    /* best effort */
                }

                return res.status(200).json({
                    event: {
                        header: {
                            namespace: 'Alexa.Authorization',
                            name: 'AcceptGrant.Response',
                            messageId: makeMessageId(),
                            payloadVersion: '3'
                        },
                        payload: {}
                    }
                });
            }

            // Everything below targets a specific endpoint.
            const endpointId = directive?.endpoint?.endpointId;
            if (!endpointId) {
                return res.status(200).json(
                    buildErrorResponse(directive, 'INVALID_DIRECTIVE', 'Missing endpointId')
                );
            }

            const entities = await googleCore.getGoogleEntitiesForUser(req.alexaUser.id, {
                includeDisabled: false
            });
            const decodedEndpointId = alexaDirectiveMapping.decodeAlexaEndpointId(endpointId);
            const entity = entities.find((e) => e.entity_id === decodedEndpointId);
            if (!entity) {
                return res.status(200).json(
                    buildErrorResponse(directive, 'NO_SUCH_ENDPOINT', 'Endpoint not found')
                );
            }

            if (!utils.isEntityEffectivelyOnline(entity)) {
                return res.status(200).json(
                    buildErrorResponse(directive, 'ENDPOINT_UNREACHABLE', 'Endpoint is offline')
                );
            }

            // ── Alexa ReportState ───────────────────────────────────────
            if (namespace === 'Alexa' && name === 'ReportState') {
                const statePayload = utils.parseJsonSafe(entity.state_json, {}) || {};
                const properties = alexaDirectiveMapping.buildAlexaProperties({
                    entity_type: entity.entity_type,
                    online: entity.online === 1,
                    state: statePayload
                });

                const header = directive.header || {};
                const endpoint = directive.endpoint || {};
                return res.status(200).json({
                    context: { properties },
                    event: {
                        header: {
                            namespace: 'Alexa',
                            name: 'StateReport',
                            messageId: makeMessageId(),
                            correlationToken: header.correlationToken,
                            payloadVersion: '3'
                        },
                        endpoint: {
                            scope: endpoint.scope,
                            endpointId: endpoint.endpointId
                        },
                        payload: {}
                    }
                });
            }

            // ── Directive → internal action ─────────────────────────────
            const mapping = alexaDirectiveMapping.mapDirectiveToInternalAction(directive, entity);
            if (!mapping || !mapping.action) {
                return res.status(200).json(
                    buildErrorResponse(directive, 'INVALID_DIRECTIVE', `Unsupported directive ${namespace}.${name}`)
                );
            }

            // PIN challenge for locks / security panels.
            const userPin = req.alexaUser.alexa_security_pin || null;
            const pinSensitive =
                namespace === 'Alexa.LockController' ||
                namespace === 'Alexa.SecurityPanelController';
            if (userPin && pinSensitive) {
                const payloadPin =
                    directive?.payload?.authorization?.value ||
                    directive?.payload?.pin ||
                    null;
                if (!payloadPin) {
                    return res.status(200).json(
                        buildErrorResponse(directive, 'UNAUTHORIZED', 'PIN is required for this action')
                    );
                }
                if (String(payloadPin) !== String(userPin)) {
                    return res.status(200).json(
                        buildErrorResponse(directive, 'UNAUTHORIZED', 'Invalid PIN')
                    );
                }
            }

            // Camera stream — wait for the add-on to return a stream URL.
            if (mapping.cameraStream) {
                try {
                    const queuedCmd = await googleCore.queueGoogleCommandForEntity(
                        req.alexaUser.id,
                        entity.device_id,
                        entity.entity_id,
                        'get_camera_stream',
                        {}
                    );
                    if (!queuedCmd?.id) {
                        return res.status(200).json(
                            buildErrorResponse(directive, 'INTERNAL_ERROR', 'Unable to queue stream request')
                        );
                    }

                    const result = await googleCore.waitForGoogleCommandResult(queuedCmd.id, 10000);
                    const streamPath = result?.state?.stream_path;
                    if (!streamPath) {
                        return res.status(200).json(
                            buildErrorResponse(directive, 'INTERNAL_ERROR', 'Unable to start camera stream')
                        );
                    }

                    const subdomain = req.alexaUser.subdomain;
                    const streamUrl = `https://${subdomain}.${config.CLOUD_BASE_DOMAIN}${streamPath}`;
                    const header = directive.header || {};
                    const endpoint = directive.endpoint || {};
                    return res.status(200).json({
                        event: {
                            header: {
                                namespace: 'Alexa.CameraStreamController',
                                name: 'Response',
                                messageId: makeMessageId(),
                                correlationToken: header.correlationToken,
                                payloadVersion: '3'
                            },
                            endpoint: {
                                scope: endpoint.scope,
                                endpointId: endpoint.endpointId
                            },
                            payload: {
                                cameraStreams: [
                                    {
                                        uri: streamUrl,
                                        protocol: 'HLS',
                                        resolution: { width: 1280, height: 720 },
                                        authorizationType: 'NONE',
                                        videoCodec: 'H264',
                                        audioCodec: 'AAC'
                                    }
                                ],
                                imageUri: streamUrl
                            }
                        }
                    });
                } catch (camErr) {
                    console.error('ALEXA CAMERA STREAM ERROR:', camErr);
                    return res.status(200).json(
                        buildErrorResponse(directive, 'INTERNAL_ERROR', 'Camera stream failure')
                    );
                }
            }

            // Normal directive → queue command + synthetic success response.
            await googleCore.queueGoogleCommandForEntity(
                req.alexaUser.id,
                entity.device_id,
                entity.entity_id,
                mapping.action,
                mapping.payload || {}
            );

            // Scene activation uses a different response envelope.
            if (mapping.sceneActivation) {
                const header = directive.header || {};
                const endpoint = directive.endpoint || {};
                return res.status(200).json({
                    context: { properties: [] },
                    event: {
                        header: {
                            namespace: 'Alexa.SceneController',
                            name: mapping.deactivation ? 'DeactivationStarted' : 'ActivationStarted',
                            messageId: makeMessageId(),
                            correlationToken: header.correlationToken,
                            payloadVersion: '3'
                        },
                        endpoint: {
                            scope: endpoint.scope,
                            endpointId: endpoint.endpointId
                        },
                        payload: {
                            cause: { type: 'VOICE_INTERACTION' },
                            timestamp: new Date().toISOString()
                        }
                    }
                });
            }

            return res.status(200).json(buildDeferredResponse(directive, mapping.responseProps || []));
        } catch (error) {
            console.error('ALEXA FULFILLMENT ERROR:', error);
            return res.status(200).json(
                buildErrorResponse(directive, 'INTERNAL_ERROR', 'Unable to process directive')
            );
        }
    });

    return router;
};
