const crypto = require('node:crypto');
const express = require('express');
const alexaCryptoLib = require('../lib/alexa/crypto');
const { translateAlexaActionToAddonAction } = require('../lib/alexa/addon-action-map');

// POST /api/alexa/smarthome — receives Alexa directives from a Lambda
// forwarder. The forwarder MUST set X-Alexa-Forwarder-Secret; the bearer
// token is the per-user Alexa access token issued by this server's
// account-linking OAuth flow.

module.exports = function ({ dbRun, config, utils, auth, alexaCore, alexaEntityMapping, alexaEventGateway }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    function buildHeader(sourceHeader, overrides = {}) {
        return {
            namespace: overrides.namespace || 'Alexa',
            name: overrides.name || 'Response',
            messageId: crypto.randomUUID(),
            payloadVersion: '3',
            ...(sourceHeader?.correlationToken ? { correlationToken: sourceHeader.correlationToken } : {}),
            ...(overrides.instance ? { instance: overrides.instance } : {})
        };
    }

    function endpointScope(directive) {
        const token = directive?.endpoint?.scope?.token || directive?.payload?.scope?.token || '';
        return { type: 'BearerToken', token: String(token || '') };
    }

    function errorResponse(directive, type, message) {
        return {
            event: {
                header: buildHeader(directive?.header, { namespace: 'Alexa', name: 'ErrorResponse' }),
                endpoint: directive?.endpoint
                    ? {
                          endpointId: directive.endpoint.endpointId,
                          scope: endpointScope(directive)
                      }
                    : undefined,
                payload: {
                    type,
                    message: String(message || type)
                }
            }
        };
    }

    async function handleDiscovery(req, directive) {
        const entities = await alexaCore.getAlexaEntitiesForUser(req.alexaUser.id, { includeDisabled: false });
        const endpoints = entities.map((entity) => alexaEntityMapping.buildAlexaDiscoveryEndpoint(entity));

        return {
            event: {
                header: buildHeader(directive?.header, {
                    namespace: 'Alexa.Discovery',
                    name: 'Discover.Response'
                }),
                payload: { endpoints }
            }
        };
    }

    async function handleReportState(req, directive) {
        const endpointId = utils.sanitizeEntityId(directive?.endpoint?.endpointId);
        if (!endpointId) {
            return errorResponse(directive, 'INVALID_DIRECTIVE', 'Missing endpointId');
        }

        const entities = await alexaCore.getAlexaEntitiesForUser(req.alexaUser.id, { includeDisabled: false });
        const entity = entities.find((item) => item.entity_id === endpointId);
        if (!entity) {
            return errorResponse(directive, 'NO_SUCH_ENDPOINT', `Unknown endpoint ${endpointId}`);
        }

        const properties = alexaEntityMapping.translateAlexaEntityState(entity);
        return {
            event: {
                header: buildHeader(directive?.header, { namespace: 'Alexa', name: 'StateReport' }),
                endpoint: {
                    endpointId,
                    scope: endpointScope(directive)
                },
                payload: {}
            },
            context: { properties }
        };
    }

    async function handleAcceptGrant(req, directive) {
        const code = directive?.payload?.grant?.code;
        if (!code) {
            return errorResponse(directive, 'ACCEPT_GRANT_FAILED', 'missing_grant_code');
        }

        const lwaClientId = config.LWA_CLIENT_ID;
        const lwaClientSecret = config.LWA_CLIENT_SECRET;
        if (!lwaClientId || !lwaClientSecret) {
            return errorResponse(directive, 'ACCEPT_GRANT_FAILED', 'lwa_not_configured');
        }

        let response;
        try {
            const body = new URLSearchParams({
                grant_type: 'authorization_code',
                code: String(code),
                client_id: lwaClientId,
                client_secret: lwaClientSecret
            }).toString();

            response = await fetch(config.ALEXA_LWA_TOKEN_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    Accept: 'application/json'
                },
                body
            });
        } catch (error) {
            console.error('ALEXA ACCEPTGRANT FETCH ERROR:', error);
            return errorResponse(directive, 'ACCEPT_GRANT_FAILED', 'lwa_fetch_error');
        }

        const raw = await response.text();
        const parsed = utils.parseJsonSafe(raw, null);
        if (!response.ok || !parsed?.access_token || !parsed?.refresh_token) {
            console.warn('ALEXA ACCEPTGRANT LWA FAILURE:', response.status, parsed?.error || parsed);
            return errorResponse(directive, 'ACCEPT_GRANT_FAILED', parsed?.error_description || parsed?.error || 'lwa_exchange_failed');
        }

        try {
            const accessEnc = alexaCryptoLib.encryptLwaToken(String(parsed.access_token));
            const refreshEnc = alexaCryptoLib.encryptLwaToken(String(parsed.refresh_token));
            const expiresIn = Number(parsed.expires_in) || 3600;
            const expiresAtIso = new Date(Date.now() + Math.max(60, expiresIn) * 1000).toISOString();
            const scopes = utils.sanitizeString(parsed.scope, 500) || null;
            const nowIso = new Date().toISOString();

            await dbRun(
                `
                    UPDATE alexa_tokens
                    SET lwa_access_token_encrypted = ?,
                        lwa_refresh_token_encrypted = ?,
                        lwa_expires_at = ?,
                        lwa_scopes = ?,
                        updated_at = ?
                    WHERE user_id = ?
                `,
                [accessEnc, refreshEnc, expiresAtIso, scopes, nowIso, req.alexaUser.id]
            );
        } catch (error) {
            console.error('ALEXA ACCEPTGRANT PERSIST ERROR:', error);
            return errorResponse(directive, 'ACCEPT_GRANT_FAILED', 'persist_failed');
        }

        try {
            alexaEventGateway.queueAlexaAddOrUpdateReport(req.alexaUser.id, null, 'accept_grant');
        } catch (error) {
            console.warn('ALEXA ACCEPTGRANT QUEUE ADDORUPDATE ERROR:', error?.message || error);
        }

        return {
            event: {
                header: buildHeader(directive?.header, {
                    namespace: 'Alexa.Authorization',
                    name: 'AcceptGrant.Response'
                }),
                payload: {}
            }
        };
    }

    async function handleDirectiveWithCommand(req, directive) {
        const endpointId = utils.sanitizeEntityId(directive?.endpoint?.endpointId);
        if (!endpointId) {
            return errorResponse(directive, 'INVALID_DIRECTIVE', 'Missing endpointId');
        }

        const entities = await alexaCore.getAlexaEntitiesForUser(req.alexaUser.id, { includeDisabled: false });
        const entity = entities.find((item) => item.entity_id === endpointId);
        if (!entity) {
            return errorResponse(directive, 'NO_SUCH_ENDPOINT', `Unknown endpoint ${endpointId}`);
        }

        const translated = alexaEntityMapping.translateAlexaDirective(directive, directive?.payload);
        if (!translated || !translated.action) {
            return errorResponse(directive, 'INVALID_DIRECTIVE', 'Unsupported directive');
        }

        // Translate the Alexa-normalized action into the addon's Google-
        // dialect action so `execute_google_command` can dispatch it without
        // duplicating the whole HA-service case-switch.
        const mapped = translateAlexaActionToAddonAction(
            translated.action,
            translated.payload || {},
            entity
        );
        if (!mapped || !mapped.addonAction) {
            return errorResponse(
                directive,
                'INVALID_VALUE',
                `Unsupported action ${translated.action} for endpoint ${endpointId}`
            );
        }

        const queued = await alexaCore.queueAlexaCommandForEntity(
            req.alexaUser.id,
            entity.device_id,
            entity.entity_id,
            mapped.addonAction,
            mapped.addonPayload || {}
        );

        if (!queued?.id) {
            return errorResponse(directive, 'INTERNAL_ERROR', 'Unable to queue command');
        }

        const result = await alexaCore.waitForAlexaCommandResult(queued.id, 9000);
        if (!result || result.success === false) {
            return errorResponse(
                directive,
                'ENDPOINT_UNREACHABLE',
                result?.error || 'Command did not complete in time'
            );
        }

        // Merge reported state into entity snapshot for the response.
        const mergedState = {
            ...(utils.parseJsonSafe(entity.state_json, {}) || {}),
            ...(result.state || {})
        };
        const enriched = { ...entity, state_json: JSON.stringify(mergedState) };
        const properties = alexaEntityMapping.translateAlexaEntityState(enriched);

        const ns = directive?.header?.namespace;
        const name = directive?.header?.name;

        // Scene directives get their own event name.
        if (ns === 'Alexa.SceneController') {
            return {
                event: {
                    header: buildHeader(directive?.header, {
                        namespace: 'Alexa.SceneController',
                        name: name === 'Deactivate' ? 'DeactivationStarted' : 'ActivationStarted'
                    }),
                    endpoint: {
                        endpointId,
                        scope: endpointScope(directive)
                    },
                    payload: {
                        cause: { type: 'VOICE_INTERACTION' },
                        timestamp: new Date().toISOString()
                    }
                }
            };
        }

        return {
            context: { properties },
            event: {
                header: buildHeader(directive?.header, { namespace: 'Alexa', name: 'Response' }),
                endpoint: {
                    endpointId,
                    scope: endpointScope(directive)
                },
                payload: {}
            }
        };
    }

    router.post(
        '/api/alexa/smarthome',
        auth.requireAlexaForwarderSecret,
        auth.requireAlexaBearer,
        asyncHandler(async (req, res) => {
            const directive = req.body?.directive;
            if (!directive || !directive.header || !directive.header.namespace || !directive.header.name) {
                return res.status(400).json(errorResponse(directive || {}, 'INVALID_DIRECTIVE', 'missing_directive'));
            }

            const ns = directive.header.namespace;
            const name = directive.header.name;

            try {
                if (ns === 'Alexa.Discovery' && name === 'Discover') {
                    return res.status(200).json(await handleDiscovery(req, directive));
                }

                if (ns === 'Alexa' && name === 'ReportState') {
                    return res.status(200).json(await handleReportState(req, directive));
                }

                if (ns === 'Alexa.Authorization' && name === 'AcceptGrant') {
                    return res.status(200).json(await handleAcceptGrant(req, directive));
                }

                const actionableNamespaces = new Set([
                    'Alexa.PowerController',
                    'Alexa.BrightnessController',
                    'Alexa.ColorController',
                    'Alexa.ColorTemperatureController',
                    'Alexa.ThermostatController',
                    'Alexa.LockController',
                    'Alexa.SceneController',
                    'Alexa.RangeController',
                    'Alexa.ModeController',
                    'Alexa.ToggleController',
                    'Alexa.Speaker',
                    'Alexa.PlaybackController'
                ]);

                if (actionableNamespaces.has(ns)) {
                    return res.status(200).json(await handleDirectiveWithCommand(req, directive));
                }

                return res.status(200).json(errorResponse(directive, 'INVALID_DIRECTIVE', `Unsupported ${ns}.${name}`));
            } catch (error) {
                console.error('ALEXA SMARTHOME ERROR:', error);
                return res.status(200).json(errorResponse(directive, 'INTERNAL_ERROR', error?.message || 'internal_error'));
            }
        })
    );

    return router;
};
