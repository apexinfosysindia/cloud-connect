/* eslint-env node, es2022 */
/* global fetch, setTimeout, clearTimeout, AbortController, process */
/**
 * Alexa Smart Home → Cloud Connect forwarder Lambda.
 *
 *   Runtime:  Node.js 20.x
 *   Timeout:  8 seconds (matches Alexa's directive response budget)
 *   Memory:   128 MB
 *
 * What it does:
 *   1. Receives an Alexa Smart Home directive on its `handler(event)`.
 *   2. POSTs the directive (verbatim) to https://<host>/api/alexa/smarthome
 *      with the bearer extracted from the directive (Amazon already attached
 *      it; we just include it for clarity in upstream logs).
 *   3. Returns the JSON body from our endpoint as the Lambda result, or a
 *      well-formed Alexa.ErrorResponse if anything between Lambda and our
 *      origin breaks.
 *
 * Why this file exists at all:
 *   Alexa Smart Home skills MUST be backed by a Lambda. We deliberately keep
 *   the Lambda dumb so that the entirety of business logic lives in our
 *   versioned Express app, not in a JavaScript blob copy-pasted into the
 *   AWS console. Every dispatch decision (Discovery, AcceptGrant, control)
 *   is made server-side; the Lambda is a network hop and an error wrapper.
 *
 * v1 lesson encoded here:
 *   The previous Lambda did light JSON munging "to make Alexa happy" before
 *   forwarding. That hid bugs in the upstream payload — when Discovery
 *   broke in prod, the post-mortem couldn't tell whether the bug was in our
 *   server or in the Lambda's well-meaning rewrite. This forwarder does
 *   ZERO mutation. The directive Amazon sent is the directive our route
 *   sees.
 *
 * Required Lambda environment variables:
 *   CLOUD_CONNECT_ORIGIN     e.g. https://cloud.apexinfosys.in
 *   CLOUD_CONNECT_PATH       defaults to /api/alexa/smarthome
 *
 * The handler MUST always return a valid Alexa response object (Response,
 * StateReport, Discover.Response, AcceptGrant.Response, or ErrorResponse).
 * Throwing causes Alexa to display a generic "Hmm, something went wrong"
 * with no diagnostic — we'd rather always send a typed error.
 */

import { randomUUID } from 'node:crypto';

const ORIGIN = process.env.CLOUD_CONNECT_ORIGIN || '';
const PATH = process.env.CLOUD_CONNECT_PATH || '/api/alexa/smarthome';
// Per-request timeout. Stay well under the Lambda's own 8s ceiling so we
// always have room to return a typed error rather than letting Lambda kill
// us mid-fetch.
const FETCH_TIMEOUT_MS = 6500;

function errorResponse(directive, type, message) {
    const inHeader = directive?.header || {};
    return {
        event: {
            header: {
                namespace: 'Alexa',
                name: 'ErrorResponse',
                messageId: randomUUID(),
                correlationToken: inHeader.correlationToken,
                payloadVersion: '3'
            },
            ...(directive?.endpoint
                ? { endpoint: { endpointId: directive.endpoint.endpointId } }
                : {}),
            payload: { type, message }
        }
    };
}

export const handler = async (event) => {
    const directive = event?.directive;

    if (!ORIGIN) {
        return errorResponse(
            directive,
            'INTERNAL_ERROR',
            'forwarder misconfigured: CLOUD_CONNECT_ORIGIN env var not set'
        );
    }
    if (!directive) {
        return errorResponse(
            { header: {} },
            'INVALID_DIRECTIVE',
            'event missing `directive` envelope'
        );
    }

    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    try {
        const res = await fetch(`${ORIGIN}${PATH}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ directive }),
            signal: controller.signal
        });
        clearTimeout(t);

        // Non-2xx is treated as INTERNAL_ERROR — our Express route is
        // designed to always return 200 with a typed body (success OR
        // ErrorResponse), so a non-2xx means something at the network
        // layer is wrong (origin down, TLS failure, 502 from Caddy, ...)
        if (!res.ok) {
            return errorResponse(
                directive,
                'INTERNAL_ERROR',
                `origin returned HTTP ${res.status}`
            );
        }
        // Accept any JSON the origin returns. We do NOT validate the shape
        // here — that's the origin's job — but we must not crash if it's
        // malformed JSON.
        try {
            return await res.json();
        } catch {
            return errorResponse(directive, 'INTERNAL_ERROR', 'origin returned non-JSON body');
        }
    } catch (err) {
        clearTimeout(t);
        const isAbort = err?.name === 'AbortError';
        return errorResponse(
            directive,
            'BRIDGE_UNREACHABLE',
            isAbort
                ? `origin did not respond within ${FETCH_TIMEOUT_MS}ms`
                : `origin fetch failed: ${err?.message || 'unknown'}`
        );
    }
};
