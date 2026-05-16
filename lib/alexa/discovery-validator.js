/**
 * Alexa Discovery payload validator.
 *
 * Codifies every Alexa schema rule that bit us during the v1 attempt. If a
 * payload built by lib/alexa/entity-mapping.js can pass this validator in a
 * unit test, Alexa will not reject it for a schema-shape reason at runtime.
 * (Alexa can still reject for *semantic* reasons — wrong skill ID, missing
 * permission, etc. — but those aren't payload-shape problems.)
 *
 * The rules below were each derived from a fix commit in the v1 history:
 *
 *   8005202 / 5508690  endpointId may not contain "."  → encode dots as "__"
 *   218e0d4 / 7dde9cd  friendlyName regex /^[A-Za-z0-9& ]+$/, max 128
 *                      mode value regex  /^[A-Za-z0-9_\-.]+$/, max 128
 *   72217c8            ModeController inputs.supportedModes values must be
 *                      unique within a single ModeController instance
 *   d31e90e / 6211249  manufacturerName must be sanitized too
 *   2138b2e / 7163738  EndpointHealth interface version is "3.2", not "3"
 *   561afa7 / 189c6cd  ColorTemperature/RangeController/ThermostatController
 *                      need configuration / capabilityResources blocks
 *
 * Public API:
 *   validateEndpoint(endpoint)             → { ok: true } | { ok: false, errors: [...] }
 *   validateDiscoveryPayload(payload)      → same shape, validates the full
 *                                            Alexa Discovery.Response envelope
 *
 * The validator returns ALL errors, not just the first, so a developer
 * iterating in tests can fix everything in one pass instead of N runs.
 */

const ENDPOINT_ID_RE = /^[A-Za-z0-9_\-=#;:?@&]+$/;
const FRIENDLY_NAME_RE = /^[A-Za-z0-9& ]+$/;
const MODE_VALUE_RE = /^[A-Za-z0-9_\-.]+$/;
const MAX_NAME_LEN = 128;

// Interface name → required version. Anything not listed defaults to '3'.
const INTERFACE_VERSIONS = {
    'Alexa.EndpointHealth': '3.2'
    // Note: most controllers are '3'; we only enumerate exceptions here so a
    // future "this interface needs 3.x" rule lands in one place.
};

function pushErr(errors, path, message) {
    errors.push({ path, message });
}

function validateName(value, fieldPath, errors) {
    if (typeof value !== 'string' || value.length === 0) {
        pushErr(errors, fieldPath, 'must be a non-empty string');
        return;
    }
    if (value.length > MAX_NAME_LEN) {
        pushErr(errors, fieldPath, `exceeds ${MAX_NAME_LEN} chars (got ${value.length})`);
    }
    if (!FRIENDLY_NAME_RE.test(value)) {
        pushErr(errors, fieldPath, `does not match ${FRIENDLY_NAME_RE} (got ${JSON.stringify(value)})`);
    }
}

function validateModeValue(value, fieldPath, errors) {
    if (typeof value !== 'string' || value.length === 0) {
        pushErr(errors, fieldPath, 'must be a non-empty string');
        return;
    }
    if (value.length > MAX_NAME_LEN) {
        pushErr(errors, fieldPath, `exceeds ${MAX_NAME_LEN} chars`);
    }
    if (!MODE_VALUE_RE.test(value)) {
        pushErr(errors, fieldPath, `does not match ${MODE_VALUE_RE} (got ${JSON.stringify(value)})`);
    }
}

function validateCapability(cap, capPath, errors) {
    if (!cap || typeof cap !== 'object') {
        pushErr(errors, capPath, 'capability must be an object');
        return;
    }
    if (cap.type !== 'AlexaInterface') {
        pushErr(errors, `${capPath}.type`, `must be "AlexaInterface" (got ${JSON.stringify(cap.type)})`);
    }
    if (typeof cap.interface !== 'string' || !cap.interface.startsWith('Alexa')) {
        pushErr(errors, `${capPath}.interface`, 'must be a string starting with "Alexa"');
        return;
    }
    const expectedVersion = INTERFACE_VERSIONS[cap.interface] || '3';
    if (cap.version !== expectedVersion) {
        pushErr(
            errors,
            `${capPath}.version`,
            `${cap.interface} requires version "${expectedVersion}" (got ${JSON.stringify(cap.version)})`
        );
    }

    // ModeController: enforce per-instance uniqueness of supportedModes values.
    // (v1 commit 72217c8 — duplicates passed local checks but Alexa rejected
    // the whole Discovery, hiding every other endpoint behind one bad one.)
    if (cap.interface === 'Alexa.ModeController') {
        const modes = cap?.configuration?.supportedModes;
        if (Array.isArray(modes)) {
            const seen = new Set();
            modes.forEach((m, i) => {
                const v = m?.value;
                validateModeValue(v, `${capPath}.configuration.supportedModes[${i}].value`, errors);
                if (typeof v === 'string') {
                    if (seen.has(v)) {
                        pushErr(
                            errors,
                            `${capPath}.configuration.supportedModes[${i}].value`,
                            `duplicate mode value "${v}" within the same ModeController instance`
                        );
                    }
                    seen.add(v);
                }
            });
        }
    }
}

function validateEndpoint(endpoint) {
    const errors = [];
    if (!endpoint || typeof endpoint !== 'object') {
        return { ok: false, errors: [{ path: '', message: 'endpoint must be an object' }] };
    }

    if (typeof endpoint.endpointId !== 'string' || endpoint.endpointId.length === 0) {
        pushErr(errors, 'endpointId', 'must be a non-empty string');
    } else if (endpoint.endpointId.length > 256) {
        pushErr(errors, 'endpointId', 'exceeds 256 chars');
    } else if (!ENDPOINT_ID_RE.test(endpoint.endpointId)) {
        // Most common offender: a literal "." from a Home Assistant entity_id.
        // Hint at the documented fix from v1.
        pushErr(
            errors,
            'endpointId',
            `does not match ${ENDPOINT_ID_RE} (got ${JSON.stringify(endpoint.endpointId)}). ` +
                `Encode dots as "__" via encodeEndpointId() before emitting.`
        );
    }

    validateName(endpoint.friendlyName, 'friendlyName', errors);
    validateName(endpoint.manufacturerName, 'manufacturerName', errors);

    if (typeof endpoint.description !== 'string' || endpoint.description.length === 0) {
        pushErr(errors, 'description', 'must be a non-empty string');
    } else if (endpoint.description.length > 128) {
        pushErr(errors, 'description', 'exceeds 128 chars');
    }

    if (!Array.isArray(endpoint.displayCategories) || endpoint.displayCategories.length === 0) {
        pushErr(errors, 'displayCategories', 'must be a non-empty array');
    }

    if (!Array.isArray(endpoint.capabilities) || endpoint.capabilities.length === 0) {
        pushErr(errors, 'capabilities', 'must be a non-empty array');
    } else {
        endpoint.capabilities.forEach((cap, i) => {
            validateCapability(cap, `capabilities[${i}]`, errors);
        });

        // Every well-formed endpoint should expose Alexa.EndpointHealth. v1
        // shipped some without it and Alexa flagged the entire batch.
        const hasHealth = endpoint.capabilities.some((c) => c?.interface === 'Alexa.EndpointHealth');
        if (!hasHealth) {
            pushErr(errors, 'capabilities', 'must include Alexa.EndpointHealth (version 3.2)');
        }
    }

    return errors.length === 0 ? { ok: true } : { ok: false, errors };
}

function validateDiscoveryPayload(payload) {
    const errors = [];
    if (!payload || typeof payload !== 'object') {
        return { ok: false, errors: [{ path: '', message: 'payload must be an object' }] };
    }

    const header = payload?.event?.header;
    if (!header || header.namespace !== 'Alexa.Discovery' || header.name !== 'Discover.Response') {
        pushErr(errors, 'event.header', 'must be Alexa.Discovery / Discover.Response');
    }
    if (header && header.payloadVersion !== '3') {
        pushErr(errors, 'event.header.payloadVersion', 'must be "3"');
    }

    const endpoints = payload?.event?.payload?.endpoints;
    if (!Array.isArray(endpoints)) {
        pushErr(errors, 'event.payload.endpoints', 'must be an array');
    } else {
        endpoints.forEach((ep, i) => {
            const r = validateEndpoint(ep);
            if (!r.ok) {
                r.errors.forEach((e) => {
                    pushErr(errors, `event.payload.endpoints[${i}].${e.path}`, e.message);
                });
            }
        });
    }

    return errors.length === 0 ? { ok: true } : { ok: false, errors };
}

module.exports = {
    validateEndpoint,
    validateDiscoveryPayload,
    // Exposed for unit tests + other modules (e.g. entity-mapping.js sanitizers
    // can reuse the same regexes so behavior stays in lockstep).
    ENDPOINT_ID_RE,
    FRIENDLY_NAME_RE,
    MODE_VALUE_RE,
    MAX_NAME_LEN,
    INTERFACE_VERSIONS
};
