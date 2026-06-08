'use strict';

/**
 * Apex Oasis — Alexa Smart Home skill Lambda forwarder.
 *
 * Amazon requires a Smart Home skill's endpoint to be an AWS Lambda ARN. This
 * Lambda does NO business logic — it forwards every directive verbatim to the
 * Cloud Connect portal's HTTPS fulfillment endpoint and returns the portal's
 * JSON response unchanged. All real work (Discovery, control, AcceptGrant,
 * ChangeReport bookkeeping) lives in routes/alexa-fulfillment.js on the portal.
 *
 * Configure via Lambda environment variables:
 *   FULFILLMENT_URL   e.g. https://oasis.apexinfosys.in/api/alexa/fulfillment
 *   FORWARDER_SECRET  shared secret echoed in the X-Alexa-Forwarder-Secret
 *                     header. The portal rejects mismatching directives ONLY
 *                     when its ALEXA_FORWARDER_SECRET env is also set (must be
 *                     byte-identical to this value); otherwise the header is
 *                     ignored. Defense in depth — the bearer token in each
 *                     directive is the primary auth either way.
 *
 * Runtime: nodejs18.x or later (uses global fetch).
 */

const FULFILLMENT_URL = process.env.FULFILLMENT_URL;
const FORWARDER_SECRET = process.env.FORWARDER_SECRET || '';

exports.handler = async (event) => {
    if (!FULFILLMENT_URL) {
        return errorResponse(event, 'INTERNAL_ERROR', 'FULFILLMENT_URL not configured');
    }

    try {
        const res = await fetch(FULFILLMENT_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Alexa-Forwarder-Secret': FORWARDER_SECRET
            },
            body: JSON.stringify(event)
        });

        const text = await res.text();
        if (!res.ok) {
            return errorResponse(event, 'INTERNAL_ERROR', `Portal returned ${res.status}`);
        }
        // The portal already returns a fully-formed Alexa response envelope.
        return JSON.parse(text);
    } catch (err) {
        return errorResponse(event, 'INTERNAL_ERROR', `Forwarder error: ${err.message}`);
    }
};

function errorResponse(event, type, message) {
    const header = (event && event.directive && event.directive.header) || {};
    return {
        event: {
            header: {
                namespace: 'Alexa',
                name: 'ErrorResponse',
                payloadVersion: '3',
                messageId: header.messageId || 'forwarder-error',
                correlationToken: header.correlationToken
            },
            payload: { type, message }
        }
    };
}
