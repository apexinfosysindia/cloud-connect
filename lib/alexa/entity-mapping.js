/**
 * Alexa entity mapping — Walking Skeleton (switch + light only).
 *
 * This module is the single source of truth for converting a Home Assistant
 * entity (as the addon syncs it into `alexa_entities`) into the three Alexa
 * payload shapes we ever emit:
 *
 *   1. Discovery endpoint        — buildAlexaEndpoint(entity)
 *   2. ReportState properties    — buildPropertyState(entity, nowIso)
 *   3. Directive resolution      — resolveDirective(directive, entity)
 *
 * ─── Why this file is intentionally small ──────────────────────────────────
 *
 * v1's entity-mapping.js tried to cover every Home Assistant domain on day
 * one. It compiled, the unit tests passed, and then Amazon rejected the
 * Discovery payload in prod because (a) endpointIds contained dots, (b) some
 * ModeController instances reused the same value across modes, (c) several
 * endpoints were missing Alexa.EndpointHealth. The team chased the symptoms
 * across nine domains at once and never converged.
 *
 * This rewrite supports ONLY:
 *   - switch.*  → SWITCH       (PowerController + EndpointHealth)
 *   - light.*   → LIGHT        (PowerController + EndpointHealth, plus
 *                               BrightnessController when the entity reports
 *                               a numeric `brightness` attribute)
 *
 * Phase 10 adds the rest of the domains, one PR at a time, each riding on
 * the same validator-gated emit path that this file establishes.
 *
 * ─── The endpointId encoding rule ──────────────────────────────────────────
 *
 * Home Assistant entity_ids look like `switch.living_room_lamp`. Alexa's
 * endpointId regex (see lib/alexa/discovery-validator.js) does NOT permit
 * `.`. v1 paid for this with broken Discovery in prod.
 *
 * Encoding rule (chosen for grep-ability, not elegance):
 *   raw "switch.living_room_lamp"   ↔   encoded "switch__living_room_lamp"
 *
 * The `__` separator is unambiguous because Home Assistant entity_ids
 * cannot themselves contain `__` (HA normalizes consecutive underscores).
 * That gives us a clean reverse mapping in decodeEndpointId().
 *
 * Every emitted endpointId is checked against ENDPOINT_ID_RE before return.
 * If the regex ever rejects an encoded id, that's a bug here — not in the
 * route layer — and the assertion makes the cause obvious.
 *
 * ─── Factory inputs ────────────────────────────────────────────────────────
 *
 *   ({ utils }) — utils only used for parseJsonSafe today; kept as a factory
 *                 input so future callers can inject a stub in tests.
 */

const {
    ENDPOINT_ID_RE,
    FRIENDLY_NAME_RE,
    MODE_VALUE_RE,
    MAX_NAME_LEN,
    INTERFACE_VERSIONS,
    validateEndpoint
} = require('./discovery-validator');

// ─── Constants ──────────────────────────────────────────────────────────────

const MANUFACTURER_NAME = 'ApexOS';
const ENDPOINT_DESCRIPTION_PREFIX = 'ApexOS Cloud Connect';

// HA domain → Alexa display category. Anything not in this map is unsupported
// in the Walking Skeleton and gets filtered out before Discovery emits.
const DOMAIN_TO_DISPLAY_CATEGORY = {
    switch: 'SWITCH',
    light: 'LIGHT'
};

// HA domain → ordered list of Alexa interface namespaces this domain may
// expose. Per-entity capability detection (e.g. brightness) further narrows
// this list inside buildAlexaEndpoint.
const DOMAIN_TO_INTERFACES = {
    switch: ['Alexa.PowerController'],
    light: ['Alexa.PowerController', 'Alexa.BrightnessController']
};

// ─── Encoding ───────────────────────────────────────────────────────────────

/**
 * Encode a Home Assistant entity_id (e.g. "light.kitchen") into an Alexa-safe
 * endpointId (e.g. "light__kitchen"). Round-trip-safe with decodeEndpointId.
 *
 * Rejects anything that doesn't look like an HA entity_id rather than
 * silently producing garbage — silent garbage was a v1 root cause.
 */
function encodeEndpointId(haEntityId) {
    if (typeof haEntityId !== 'string' || haEntityId.length === 0) {
        throw new Error('encodeEndpointId: entity_id must be a non-empty string');
    }
    // HA entity_ids are exactly "<domain>.<object_id>" — one dot, both halves
    // [a-z0-9_]. Be strict so we fail on the source, not on Alexa's reject.
    const m = /^([a-z][a-z0-9_]*)\.([a-z0-9_]+)$/.exec(haEntityId);
    if (!m) {
        throw new Error(
            `encodeEndpointId: ${JSON.stringify(haEntityId)} is not a valid Home Assistant entity_id`
        );
    }
    const encoded = `${m[1]}__${m[2]}`;
    // Belt and braces — guarantee the result satisfies the same regex the
    // validator will check. If this ever throws it's a bug here.
    if (!ENDPOINT_ID_RE.test(encoded)) {
        throw new Error(`encodeEndpointId: produced "${encoded}" which fails ENDPOINT_ID_RE`);
    }
    return encoded;
}

/**
 * Reverse of encodeEndpointId. Returns null (not throws) on bad input
 * because the directive layer needs a soft "didn't recognize this" path
 * to respond with NO_SUCH_ENDPOINT instead of crashing.
 */
function decodeEndpointId(endpointId) {
    if (typeof endpointId !== 'string' || endpointId.length === 0) return null;
    const idx = endpointId.indexOf('__');
    if (idx <= 0 || idx === endpointId.length - 2) return null;
    const domain = endpointId.slice(0, idx);
    const object = endpointId.slice(idx + 2);
    // Re-validate against HA entity_id shape to refuse a tampered/unknown
    // endpointId before we try to look it up in the DB.
    if (!/^[a-z][a-z0-9_]*$/.test(domain)) return null;
    if (!/^[a-z0-9_]+$/.test(object)) return null;
    return `${domain}.${object}`;
}

// ─── Sanitizers ─────────────────────────────────────────────────────────────

/**
 * Strip an arbitrary user-supplied display string down to the FRIENDLY_NAME_RE
 * charset and clamp to MAX_NAME_LEN. If nothing survives, returns null — the
 * caller falls back to a synthesized name (see buildAlexaEndpoint).
 */
function sanitizeAlexaName(input) {
    if (input === null || input === undefined) return null;
    const s = String(input);
    // FRIENDLY_NAME_RE = /^[A-Za-z0-9& ]+$/
    // Replace anything outside that with a space, then collapse runs.
    const stripped = s
        .replace(/[^A-Za-z0-9& ]+/g, ' ')
        .replace(/ {2,}/g, ' ')
        .trim();
    if (stripped.length === 0) return null;
    const clamped = stripped.length > MAX_NAME_LEN ? stripped.slice(0, MAX_NAME_LEN).trim() : stripped;
    if (!FRIENDLY_NAME_RE.test(clamped)) return null;
    return clamped;
}

/**
 * Sanitize a ModeController value to MODE_VALUE_RE charset, then suffix with
 * `_2`, `_3`, ... if the candidate collides with a value already taken
 * within the same ModeController instance. Required because Alexa's mode
 * uniqueness is per-instance, not global.
 *
 * NOT exercised by switch/light in this phase. Exported now so the contract
 * is locked and Phase 10 (fan, cover, climate) doesn't drift it.
 */
function sanitizeModeValue(input, takenSet = new Set()) {
    if (input === null || input === undefined) return null;
    const base = String(input)
        .replace(/[^A-Za-z0-9_\-.]+/g, '_')
        .replace(/_{2,}/g, '_')
        .replace(/^[._-]+|[._-]+$/g, '');
    if (base.length === 0 || !MODE_VALUE_RE.test(base)) return null;
    if (!takenSet.has(base)) {
        takenSet.add(base);
        return base;
    }
    // Collision: suffix _2, _3, ... up to a sane bound to avoid an infinite
    // loop on a pathologically crafted set.
    for (let i = 2; i < 1000; i++) {
        const candidate = `${base}_${i}`;
        if (!takenSet.has(candidate)) {
            takenSet.add(candidate);
            return candidate;
        }
    }
    return null;
}

// ─── Capability builders ────────────────────────────────────────────────────

function capabilityAlexa() {
    // The "Alexa" interface itself — required to be advertised. Per Amazon
    // docs this should appear on every endpoint.
    return { type: 'AlexaInterface', interface: 'Alexa', version: '3' };
}

function capabilityEndpointHealth() {
    return {
        type: 'AlexaInterface',
        interface: 'Alexa.EndpointHealth',
        version: INTERFACE_VERSIONS['Alexa.EndpointHealth'], // '3.2'
        properties: {
            supported: [{ name: 'connectivity' }],
            proactivelyReported: true,
            retrievable: true
        }
    };
}

function capabilityPowerController() {
    return {
        type: 'AlexaInterface',
        interface: 'Alexa.PowerController',
        version: '3',
        properties: {
            supported: [{ name: 'powerState' }],
            proactivelyReported: true,
            retrievable: true
        }
    };
}

function capabilityBrightnessController() {
    return {
        type: 'AlexaInterface',
        interface: 'Alexa.BrightnessController',
        version: '3',
        properties: {
            supported: [{ name: 'brightness' }],
            proactivelyReported: true,
            retrievable: true
        }
    };
}

// ─── Entity → state shape ───────────────────────────────────────────────────

/**
 * Parse an `alexa_entities.state_json` blob into a normalized snapshot.
 *
 *   { state: 'on' | 'off' | <other>, attributes: { brightness?: 0..255, ... } }
 *
 * `state_json` is whatever the addon last pushed — we expect a JSON object
 * shaped like Home Assistant's state object: `{ state, attributes }`.
 */
function parseEntityState(entity) {
    if (!entity) return { state: null, attributes: {} };
    let raw;
    try {
        raw = entity.state_json ? JSON.parse(entity.state_json) : null;
    } catch (_e) {
        // Malformed JSON in the DB shouldn't take the whole route down —
        // surface as "unknown state" so EndpointHealth flips to UNREACHABLE.
        return { state: null, attributes: {} };
    }
    if (!raw || typeof raw !== 'object') return { state: null, attributes: {} };
    const state = typeof raw.state === 'string' ? raw.state : null;
    const attributes =
        raw.attributes && typeof raw.attributes === 'object' && !Array.isArray(raw.attributes)
            ? raw.attributes
            : {};
    return { state, attributes };
}

/**
 * Map HA `state` ("on" | "off" | "unavailable" | ...) to Alexa powerState.
 * Returns null when the state is neither on nor off so the caller can decide
 * whether to omit the property (Discovery) or report UNREACHABLE (ReportState).
 */
function mapPowerState(haState) {
    if (haState === 'on') return 'ON';
    if (haState === 'off') return 'OFF';
    return null;
}

/**
 * Map HA `brightness` attribute (0..255) to Alexa brightness (0..100).
 * Returns null when not a finite number in range.
 */
function mapBrightness(haBrightness) {
    if (!Number.isFinite(haBrightness)) return null;
    if (haBrightness < 0 || haBrightness > 255) return null;
    // Alexa wants integer 0..100. Round half-up.
    return Math.round((haBrightness / 255) * 100);
}

function mapConnectivity(entity, parsedState) {
    // entity.online is the addon's last-known transport state for the device
    // bridge. parsedState.state === 'unavailable' is HA's per-entity signal.
    // EITHER one being bad means UNREACHABLE.
    if (entity?.online === 0 || parsedState.state === 'unavailable' || parsedState.state === null) {
        return 'UNREACHABLE';
    }
    return 'OK';
}

// ─── Endpoint builder ───────────────────────────────────────────────────────

/**
 * Translate one `alexa_entities` row into an Alexa Discovery endpoint
 * descriptor. Returns null for rows whose domain isn't in the Walking
 * Skeleton's allow-list (the caller filters those out of the Discovery
 * payload — they're not an error, just out of scope this phase).
 *
 * Throws on inputs that ARE in scope but fail validation. That's intentional:
 * a switch row that can't be encoded into a valid endpoint is a bug we want
 * to see in tests / logs, not a silent omission that breaks Discovery.
 */
function buildAlexaEndpoint(entity) {
    if (!entity || typeof entity !== 'object') {
        throw new Error('buildAlexaEndpoint: entity must be an object');
    }
    const haEntityId = entity.entity_id;
    if (typeof haEntityId !== 'string' || haEntityId.length === 0) {
        throw new Error('buildAlexaEndpoint: entity.entity_id required');
    }

    const domain = haEntityId.split('.')[0];
    const displayCategory = DOMAIN_TO_DISPLAY_CATEGORY[domain];
    if (!displayCategory) {
        // Out-of-scope domain for this phase. Return null so the route layer
        // can drop it from the Discovery payload without raising.
        return null;
    }

    const endpointId = encodeEndpointId(haEntityId);

    // friendlyName: prefer the DB's display_name, fall back to a sanitized
    // version of the object_id, fall back finally to the encoded endpointId.
    // The fallbacks exist because Alexa rejects empty / non-conforming names
    // and we'd rather show the user "Living Room Lamp" → garbled-but-visible
    // than silently drop the device.
    const friendlyName =
        sanitizeAlexaName(entity.display_name) ||
        sanitizeAlexaName(haEntityId.split('.')[1]?.replace(/_/g, ' ')) ||
        sanitizeAlexaName(endpointId.replace(/__/g, ' '));
    if (!friendlyName) {
        // Truly nothing usable — refuse to emit. The validator would reject
        // this anyway; throwing here gives a clearer trace.
        throw new Error(`buildAlexaEndpoint: cannot derive a valid friendlyName for ${haEntityId}`);
    }

    const description = `${ENDPOINT_DESCRIPTION_PREFIX} ${displayCategory.toLowerCase()}`;

    // Capabilities: always Alexa + EndpointHealth + PowerController.
    // BrightnessController only when the entity reports a numeric brightness.
    const parsed = parseEntityState(entity);
    const interfaces = DOMAIN_TO_INTERFACES[domain] || [];
    const capabilities = [capabilityAlexa(), capabilityEndpointHealth()];

    if (interfaces.includes('Alexa.PowerController')) {
        capabilities.push(capabilityPowerController());
    }
    if (
        interfaces.includes('Alexa.BrightnessController') &&
        Number.isFinite(parsed.attributes?.brightness)
    ) {
        capabilities.push(capabilityBrightnessController());
    }

    const endpoint = {
        endpointId,
        manufacturerName: MANUFACTURER_NAME,
        friendlyName,
        description,
        displayCategories: [displayCategory],
        capabilities,
        cookie: {
            // Carrying the raw HA entity_id back in the cookie means the
            // directive layer doesn't need to decode the endpointId every
            // time — but we still validate the cookie before trusting it.
            ha_entity_id: haEntityId
        }
    };

    // Hard contract: every endpoint we emit MUST validate. If this ever
    // throws, the regression is here, not in the route. Catching it at the
    // boundary is the whole point of the validator existing.
    const result = validateEndpoint(endpoint);
    if (!result.ok) {
        const reason = result.errors.map((e) => `${e.path}: ${e.message}`).join('; ');
        throw new Error(`buildAlexaEndpoint: validator rejected endpoint for ${haEntityId} — ${reason}`);
    }

    return endpoint;
}

// ─── ReportState property builder ───────────────────────────────────────────

/**
 * Build the `context.properties` array for an Alexa.ReportState response or
 * a ChangeReport event for a single entity. Only emits properties whose
 * value we can confidently determine — Alexa is lenient about omitted
 * properties as long as connectivity is present.
 *
 * Returns [] (not null) when nothing can be reported, so the caller can
 * blindly concatenate.
 */
function buildPropertyState(entity, nowIso = new Date().toISOString()) {
    if (!entity) return [];
    const domain = (entity.entity_id || '').split('.')[0];
    if (!DOMAIN_TO_DISPLAY_CATEGORY[domain]) return [];

    const parsed = parseEntityState(entity);
    const props = [];

    // Connectivity is always reported — Amazon's docs explicitly recommend
    // this and v1 was missing it on a fraction of endpoints.
    props.push({
        namespace: 'Alexa.EndpointHealth',
        name: 'connectivity',
        value: { value: mapConnectivity(entity, parsed) },
        timeOfSample: nowIso,
        uncertaintyInMilliseconds: 1000
    });

    const power = mapPowerState(parsed.state);
    if (power !== null) {
        props.push({
            namespace: 'Alexa.PowerController',
            name: 'powerState',
            value: power,
            timeOfSample: nowIso,
            uncertaintyInMilliseconds: 1000
        });
    }

    if (domain === 'light') {
        const brightness = mapBrightness(parsed.attributes?.brightness);
        if (brightness !== null) {
            props.push({
                namespace: 'Alexa.BrightnessController',
                name: 'brightness',
                value: brightness,
                timeOfSample: nowIso,
                uncertaintyInMilliseconds: 1000
            });
        }
    }

    return props;
}

// ─── Directive resolver ─────────────────────────────────────────────────────

/**
 * Translate an inbound Alexa directive into the addon-side action shape.
 *
 *   directive.header.namespace + directive.header.name
 *     → { service, payload }
 *
 * The returned shape is what routes/alexa-device-api.js (Phase 8) will
 * write into alexa_command_queue for the addon to poll. Keeping the mapping
 * here (not in the route) means Phase 10 can add domains by extending this
 * function alone.
 *
 * Returns null for directives this phase doesn't yet support — the route
 * layer responds with INVALID_DIRECTIVE in that case rather than 500.
 */
function resolveDirective(directive, entity) {
    if (!directive || typeof directive !== 'object') return null;
    const header = directive.header || {};
    const ns = header.namespace;
    const name = header.name;
    if (!ns || !name) return null;

    const haEntityId = entity?.entity_id;
    if (!haEntityId) return null;
    const domain = haEntityId.split('.')[0];
    if (!DOMAIN_TO_DISPLAY_CATEGORY[domain]) return null;

    if (ns === 'Alexa.PowerController') {
        if (name === 'TurnOn') {
            return {
                service: `${domain}.turn_on`,
                payload: { entity_id: haEntityId }
            };
        }
        if (name === 'TurnOff') {
            return {
                service: `${domain}.turn_off`,
                payload: { entity_id: haEntityId }
            };
        }
    }

    if (ns === 'Alexa.BrightnessController' && domain === 'light') {
        if (name === 'SetBrightness') {
            // Alexa sends 0..100; HA's light.turn_on expects brightness 0..255.
            const pct = directive?.payload?.brightness;
            if (!Number.isFinite(pct) || pct < 0 || pct > 100) return null;
            return {
                service: 'light.turn_on',
                payload: {
                    entity_id: haEntityId,
                    brightness: Math.round((pct / 100) * 255)
                }
            };
        }
        if (name === 'AdjustBrightness') {
            const delta = directive?.payload?.brightnessDelta;
            if (!Number.isFinite(delta)) return null;
            return {
                service: 'light.turn_on',
                payload: {
                    entity_id: haEntityId,
                    // HA accepts brightness_step_pct natively; pass as-is.
                    brightness_step_pct: Math.round(delta)
                }
            };
        }
    }

    return null;
}

// ─── Exports ────────────────────────────────────────────────────────────────

module.exports = function createEntityMapping(_deps = {}) {
    return {
        // Encoding
        encodeEndpointId,
        decodeEndpointId,
        // Sanitizers
        sanitizeAlexaName,
        sanitizeModeValue,
        // Builders
        buildAlexaEndpoint,
        buildPropertyState,
        // Directive
        resolveDirective,
        // Constants exposed for the route layer + tests
        DOMAIN_TO_DISPLAY_CATEGORY,
        DOMAIN_TO_INTERFACES,
        MANUFACTURER_NAME
    };
};

// Pure-function exports for tests that don't want to construct the factory.
module.exports._pure = {
    encodeEndpointId,
    decodeEndpointId,
    sanitizeAlexaName,
    sanitizeModeValue,
    buildAlexaEndpoint,
    buildPropertyState,
    resolveDirective,
    parseEntityState,
    mapPowerState,
    mapBrightness,
    mapConnectivity
};
