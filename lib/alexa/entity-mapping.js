const utils = require('../utils');

/**
 * Alexa Smart Home entity mapping (MVP subset).
 *
 * Translates the device-pushed entity_type + state_json (the SAME shape the
 * Google Home bridge already produces) into Alexa Discovery endpoint
 * definitions and ReportState/ChangeReport property reports.
 *
 * MVP interface coverage:
 *   - Alexa.PowerController                (all light + switch types)  on/off
 *   - Alexa.BrightnessController           (dimmable lights)           0-100
 *   - Alexa.ColorController                (color lights)              HSB
 *   - Alexa.ColorTemperatureController     (tunable-white lights)      Kelvin
 *   - Alexa.EndpointHealth                 (all)                       OK/UNREACHABLE
 *   - Alexa                                (all, base interface)
 *
 * Unsupported entity_types are simply not exposed in MVP (fans, locks,
 * thermostats, covers, sensors, scenes are follow-ups).
 */

const SUPPORTED_ENTITY_TYPES = new Set(['light', 'switch', 'outlet', 'fan', 'input_boolean']);

// Map an internal entity_type to an Alexa displayCategory.
const DISPLAY_CATEGORY = {
    light: 'LIGHT',
    switch: 'SWITCH',
    outlet: 'SMARTPLUG',
    fan: 'FAN',
    input_boolean: 'SWITCH'
};

function parseJsonSafe(value, fallback) {
    return utils.parseJsonSafe(value, fallback);
}

function mapDomainToEntityType(entityId) {
    if (typeof entityId === 'string' && entityId.includes('.')) {
        const domain = entityId.split('.')[0].toLowerCase();
        if (domain === 'light') return 'light';
        if (domain === 'switch') return 'switch';
        if (domain === 'fan') return 'fan';
        if (domain === 'input_boolean') return 'input_boolean';
    }
    return null;
}

function normalizeAlexaEntityType(rawType, entityId) {
    const normalized = utils.sanitizeString(rawType, 40);
    if (normalized) {
        const lower = normalized.toLowerCase();
        if (SUPPORTED_ENTITY_TYPES.has(lower)) {
            return lower;
        }
        // Treat any unknown controllable type as a generic switch so it is at
        // least on/off controllable rather than silently dropped.
        const fromDomain = mapDomainToEntityType(entityId);
        if (fromDomain) return fromDomain;
        return 'switch';
    }
    return mapDomainToEntityType(entityId) || 'switch';
}

function isLight(entityType) {
    return entityType === 'light';
}

function lightColorSupport(statePayload) {
    const colorModes = Array.isArray(statePayload?.supported_color_modes)
        ? statePayload.supported_color_modes
        : [];
    const hasBrightness = colorModes.length > 0 && !colorModes.every((m) => m === 'onoff');
    const hasColor = colorModes.some((m) => ['hs', 'xy', 'rgb', 'rgbw', 'rgbww'].includes(m));
    const hasColorTemp = colorModes.includes('color_temp');
    return { hasBrightness, hasColor, hasColorTemp };
}

// ── Discovery: build a single Alexa endpoint definition ─────────────────

function capability(iface, version, properties) {
    const cap = { type: 'AlexaInterface', interface: iface, version: version || '3' };
    if (properties) {
        cap.properties = {
            supported: properties.map((name) => ({ name })),
            proactivelyReported: true,
            retrievable: true
        };
    }
    return cap;
}

function buildAlexaEndpoint(endpoint) {
    const entityType = endpoint.entity_type;
    if (!SUPPORTED_ENTITY_TYPES.has(entityType)) {
        return null;
    }

    const statePayload = parseJsonSafe(endpoint.state_json, {}) || {};
    const capabilities = [
        capability('Alexa', '3'),
        capability('Alexa.PowerController', '3', ['powerState']),
        capability('Alexa.EndpointHealth', '3.2', ['connectivity'])
    ];

    if (isLight(entityType)) {
        const { hasBrightness, hasColor, hasColorTemp } = lightColorSupport(statePayload);
        if (hasBrightness) {
            capabilities.push(capability('Alexa.BrightnessController', '3', ['brightness']));
        }
        if (hasColor) {
            capabilities.push(capability('Alexa.ColorController', '3', ['color']));
        }
        if (hasColorTemp) {
            capabilities.push(capability('Alexa.ColorTemperatureController', '3', ['colorTemperatureInKelvin']));
        }
    }

    return {
        endpointId: endpoint.entity_id,
        manufacturerName: utils.sanitizeString(statePayload._manufacturer, 120) || 'Apex Oasis',
        description: `${endpoint.display_name} (Apex Oasis Cloud Connect)`,
        friendlyName: endpoint.display_name,
        displayCategories: [DISPLAY_CATEGORY[entityType] || 'OTHER'],
        cookie: {},
        capabilities
    };
}

// ── ReportState / ChangeReport: build context property reports ──────────

function clampPercent(value) {
    return Math.max(0, Math.min(100, Math.round(Number(value) || 0)));
}

/**
 * Returns a plain object of Alexa property values (NOT yet wrapped in the
 * timestamped context envelope). The event-gateway / fulfillment layer wraps
 * these into { namespace, name, value, timeOfSample, uncertaintyInMilliseconds }.
 */
function parseAlexaEndpointState(endpoint) {
    const statePayload = parseJsonSafe(endpoint.state_json, {}) || {};
    const online = endpoint.online !== 0;
    const props = {
        connectivity: online ? 'OK' : 'UNREACHABLE',
        powerState: statePayload.on ? 'ON' : 'OFF'
    };

    if (isLight(endpoint.entity_type)) {
        const { hasBrightness, hasColor, hasColorTemp } = lightColorSupport(statePayload);
        if (hasBrightness) {
            const raw = clampPercent(statePayload.brightness);
            // A light that's ON shouldn't report 0% (stale off-state brightness).
            props.brightness = statePayload.on && raw === 0 ? 100 : raw;
        }
        if (hasColor && Array.isArray(statePayload.hs_color) && statePayload.hs_color.length >= 2) {
            const hue = Number(statePayload.hs_color[0]) || 0;
            const saturation = (Number(statePayload.hs_color[1]) || 0) / 100;
            const brightnessFraction = clampPercent(statePayload.brightness) / 100;
            props.color = {
                hue: Math.max(0, Math.min(360, hue)),
                saturation: Math.max(0, Math.min(1, saturation)),
                brightness: Math.max(0, Math.min(1, brightnessFraction || 1))
            };
        }
        if (hasColorTemp && statePayload.color_temp_kelvin) {
            props.colorTemperatureInKelvin = Number(statePayload.color_temp_kelvin) || 3000;
        }
    }

    return props;
}

module.exports = {
    SUPPORTED_ENTITY_TYPES,
    DISPLAY_CATEGORY,
    normalizeAlexaEntityType,
    mapDomainToEntityType,
    buildAlexaEndpoint,
    parseAlexaEndpointState
};
