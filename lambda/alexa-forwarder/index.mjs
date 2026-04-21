// Alexa Smart Home skill Lambda forwarder.
// Forwards the raw directive to Cloud Connect's /api/alexa/smarthome and
// returns the JSON body verbatim. On non-2xx or network error, returns a
// well-formed Alexa.ErrorResponse envelope so Alexa logs remain useful.

import { randomUUID } from 'node:crypto';

export const handler = async (event) => {
    const url = process.env.CLOUD_CONNECT_URL;
    const secret = process.env.FORWARDER_SECRET;

    if (!url || !secret) {
        return buildError(event, 'INTERNAL_ERROR', 'forwarder_not_configured');
    }

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Alexa-Forwarder-Secret': secret
            },
            body: JSON.stringify(event)
        });

        const text = await response.text();
        if (!response.ok) {
            return buildError(event, 'INTERNAL_ERROR', `upstream_status_${response.status}`);
        }

        try {
            return JSON.parse(text);
        } catch (_parseError) {
            return buildError(event, 'INTERNAL_ERROR', 'invalid_upstream_json');
        }
    } catch (error) {
        return buildError(event, 'INTERNAL_ERROR', error?.message || 'fetch_error');
    }
};

function buildError(event, type, message) {
    const directive = event?.directive || {};
    return {
        event: {
            header: {
                namespace: 'Alexa',
                name: 'ErrorResponse',
                messageId: randomUUID(),
                payloadVersion: '3',
                ...(directive.header?.correlationToken ? { correlationToken: directive.header.correlationToken } : {})
            },
            endpoint: directive.endpoint ? { endpointId: directive.endpoint.endpointId } : undefined,
            payload: { type, message: String(message || type) }
        }
    };
}
