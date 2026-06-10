const utils = require('../utils');

/**
 * Alexa Smart Home entity mapping.
 *
 * Translates the device-pushed entity_type + state_json (the SAME shape the
 * Google Home bridge produces) into Alexa Discovery endpoint definitions and
 * ReportState/ChangeReport property reports.
 *
 * ── Architecture: the capability plan ──────────────────────────────────
 * A single function, buildCapabilityPlan(entityType, statePayload), returns an
 * ordered list of CapabilitySpec objects — the ONE source of truth for an
 * endpoint. It is projected two ways so Discovery and State can never drift:
 *
 *   - buildAlexaEndpoint()      → maps each spec to an `AlexaInterface` object.
 *   - parseAlexaEndpointState() → flatMaps each spec's readState() into
 *                                 structured AlexaProp tuples.
 *
 * CapabilitySpec = {
 *   iface:       'Alexa.RangeController',     // the Alexa interface namespace
 *   instance?:   'Fan.Speed',                 // only for instanced controllers
 *   version:     '3',
 *   properties?: ['rangeValue'],              // supported/reportable prop names
 *   proactive?:  true,  retrievable?: true,   // default true
 *   discovery?:  { capabilityResources, configuration, semantics, ... },
 *   readState?:  (statePayload, online) => [{ name, value }]   // value = wire shape
 * }
 *
 * AlexaProp = { namespace, instance?, name, value }   // value = final wire shape
 *
 * ── Exclusion gate ─────────────────────────────────────────────────────
 * An endpoint is exposed to Alexa IFF its plan yields at least one capability
 * beyond the base `Alexa` + `Alexa.EndpointHealth`. buildAlexaEndpoint returns
 * null otherwise, so unmapped domains (and Tier-D device classes that share a
 * supported domain, e.g. air-quality sensors) are EXCLUDED rather than coerced
 * into broken on/off switches.
 *
 * Current interface coverage (grows per phase):
 *   - light  → Power (+ Brightness/Color/ColorTemperature by color mode)
 *   - switch/outlet/input_boolean → Power
 *   - fan    → Power            (speed/oscillate/preset are a follow-up phase)
 *   - all    → EndpointHealth + base Alexa
 */

// Entity types we currently expose. Grows as phases land. Anything outside this
// set (or inside it but yielding an empty plan) is excluded at Discovery.
const SUPPORTED_ENTITY_TYPES = new Set([
    'light',
    'switch',
    'outlet',
    'fan',
    'input_boolean',
    'automation',
    'group',
    'scene',
    'script',
    'button',
    'input_button',
    'lock',
    'cover',
    'valve',
    'sensor',
    'binary_sensor',
    'select',
    'input_select',
    'humidifier',
    'water_heater',
    'climate',
    'vacuum',
    'lawn_mower',
    'media_player',
    'alarm_control_panel'
]);

// device_class subsets we expose per sensor domain. Anything outside these is
// Tier-D (no Alexa custom-skill equivalent) → excluded at Discovery.
const SENSOR_TEMPERATURE_CLASS = 'temperature';
const SENSOR_HUMIDITY_CLASS = 'humidity';
const BINARY_CONTACT_CLASSES = new Set(['door', 'window', 'garage_door', 'opening']);
const BINARY_MOTION_CLASSES = new Set(['motion', 'occupancy', 'presence']);

// Map an internal entity_type to an Alexa displayCategory.
const DISPLAY_CATEGORY = {
    light: 'LIGHT',
    switch: 'SWITCH',
    outlet: 'SMARTPLUG',
    fan: 'FAN',
    input_boolean: 'SWITCH',
    automation: 'SWITCH',
    group: 'SWITCH',
    scene: 'SCENE_TRIGGER',
    script: 'ACTIVITY_TRIGGER',
    button: 'ACTIVITY_TRIGGER',
    input_button: 'ACTIVITY_TRIGGER',
    lock: 'SMARTLOCK',
    cover: 'INTERIOR_BLIND',
    valve: 'OTHER',
    sensor: 'TEMPERATURE_SENSOR',
    binary_sensor: 'CONTACT_SENSOR',
    select: 'OTHER',
    input_select: 'OTHER',
    humidifier: 'OTHER',
    water_heater: 'WATER_HEATER',
    climate: 'THERMOSTAT',
    vacuum: 'VACUUM_CLEANER',
    lawn_mower: 'OTHER',
    media_player: 'TV',
    alarm_control_panel: 'SECURITY_PANEL'
};

// media_player device_class → displayCategory override.
const MEDIA_PLAYER_DISPLAY_CATEGORY = {
    tv: 'TV',
    speaker: 'SPEAKER',
    receiver: 'STREAMING_DEVICE'
};

// Cover device_class → Alexa displayCategory override.
const COVER_DISPLAY_CATEGORY = {
    garage: 'GARAGE_DOOR',
    door: 'DOOR',
    gate: 'GARAGE_DOOR',
    window: 'INTERIOR_BLIND',
    blind: 'INTERIOR_BLIND',
    curtain: 'INTERIOR_BLIND',
    shade: 'INTERIOR_BLIND',
    shutter: 'EXTERIOR_BLIND',
    awning: 'EXTERIOR_BLIND'
};

// Amazon's authoritative set of valid Discover.Response displayCategories.
// An invalid value can cause Alexa to silently reject the ENTIRE Discovery
// batch (0 devices), so resolveDisplayCategories coerces any unknown to OTHER.
// Source: developer.amazon.com Alexa Discovery display categories.
const VALID_DISPLAY_CATEGORIES = new Set([
    'ACTIVITY_TRIGGER', 'AIR_CONDITIONER', 'AIR_FRESHENER', 'AIR_PURIFIER', 'AIR_QUALITY_MONITOR',
    'ALEXA_VOICE_ENABLED', 'AUTO_ACCESSORY', 'BLUETOOTH_SPEAKER', 'CAMERA', 'CHRISTMAS_TREE',
    'COFFEE_MAKER', 'COMPUTER', 'CONTACT_SENSOR', 'DISHWASHER', 'DOOR', 'DOORBELL', 'DRYER',
    'EXTERIOR_BLIND', 'FAN', 'GAME_CONSOLE', 'GARAGE_DOOR', 'HEADPHONES', 'HUB', 'INTERIOR_BLIND',
    'LAPTOP', 'LIGHT', 'MICROWAVE', 'MOBILE_PHONE', 'MOTION_SENSOR', 'MUSIC_SYSTEM',
    'NETWORK_HARDWARE', 'OTHER', 'OVEN', 'PHONE', 'PRINTER', 'REMOTE', 'ROUTER', 'SCENE_TRIGGER',
    'SCREEN', 'SECURITY_PANEL', 'SECURITY_SYSTEM', 'SLOW_COOKER', 'SMARTLOCK', 'SMARTPLUG',
    'SPEAKER', 'STREAMING_DEVICE', 'SWITCH', 'TABLET', 'TEMPERATURE_SENSOR', 'THERMOSTAT', 'TV',
    'VACUUM_CLEANER', 'VEHICLE', 'WASHER', 'WATER_HEATER', 'WEARABLE'
]);

function parseJsonSafe(value, fallback) {
    return utils.parseJsonSafe(value, fallback);
}

/**
 * Alexa requires friendlyName to be "Up to 256 alphanumeric characters and
 * spaces. Don't include special characters or punctuation." A name that
 * violates this makes the endpoint invalid, and ONE bad endpoint causes Amazon
 * to reject the ENTIRE Discover.Response / AddOrUpdateReport (400) — so every
 * device silently disappears. HA names routinely contain apostrophes, hyphens,
 * accents, parentheses, emoji, etc., so we must coerce to the allowed charset.
 *
 * Strategy: replace any disallowed character with a space (preserves word
 * boundaries), collapse runs of whitespace, trim, cap length. If nothing usable
 * remains, fall back to a name derived from the entity_id.
 */
function sanitizeAlexaFriendlyName(rawName, entityId) {
    const cleaned = String(rawName || '')
        // Keep ASCII letters/digits/space; turn everything else (punctuation,
        // accents, emoji, symbols) into a space.
        .replace(/[^a-zA-Z0-9 ]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 128);
    if (cleaned) {
        return cleaned;
    }
    // Fallback: derive from entity_id (e.g. "light.kids_lamp" → "kids lamp").
    const fromId = String(entityId || '')
        .split('.')
        .slice(1)
        .join(' ')
        .replace(/[^a-zA-Z0-9 ]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 128);
    return fromId || 'Device';
}

// Derive the HA domain from an entity_id (e.g. "light.kitchen" → "light").
function mapDomainToEntityType(entityId) {
    if (typeof entityId === 'string' && entityId.includes('.')) {
        const domain = entityId.split('.')[0].toLowerCase();
        return domain || null;
    }
    return null;
}

/**
 * Normalize the device-pushed entity_type. Preserves the TRUE type (real
 * rawType, else entity_id domain) even when unmapped, so the Discovery gate —
 * not a silent coercion to 'switch' — decides exposure. Only a genuinely
 * typeless + domainless payload falls back to 'switch'.
 */
function normalizeAlexaEntityType(rawType, entityId) {
    const normalized = utils.sanitizeString(rawType, 40);
    if (normalized) {
        return normalized.toLowerCase();
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

function clampPercent(value) {
    return Math.max(0, Math.min(100, Math.round(Number(value) || 0)));
}

function clampRange(value, min, max) {
    const n = Number(value);
    if (!Number.isFinite(n)) return min;
    return Math.max(min, Math.min(max, n));
}

// ── capabilityResources / friendlyNames helpers ─────────────────────────
// Amazon supports two friendly-name kinds: free text and catalog asset IDs.
// We pair an asset with a text fallback where a documented asset exists.

// A friendlyName text resource. Amazon requires the text to be alphanumeric +
// spaces (same rule as endpoint friendlyName), so labels built from raw HA
// values (mode names, source names, options like "50%" or "Auto-Eco") must be
// coerced — otherwise the capability fails schema validation and 400s the batch.
function assetText(text) {
    const clean = String(text == null ? '' : text)
        .replace(/[^a-zA-Z0-9 ]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 128);
    return { '@type': 'text', value: { text: clean || 'Option', locale: 'en-US' } };
}

// Amazon's global catalog asset IDs (Alexa.Setting.* / Alexa.Value.* / Alexa.Unit.*).
// An assetId NOT in the catalog makes the capability invalid → endpoint rejected →
// whole Discovery batch 400s. Source: developer.amazon.com resources-and-assets.
const VALID_ASSET_IDS = new Set([
    'Alexa.Setting.2GGuestWiFi', 'Alexa.Setting.5GGuestWiFi', 'Alexa.Setting.Auto',
    'Alexa.Setting.Direction', 'Alexa.Setting.DryCycle', 'Alexa.Setting.FanSpeed',
    'Alexa.Setting.GuestWiFi', 'Alexa.Setting.Heat', 'Alexa.Setting.Mode', 'Alexa.Setting.Night',
    'Alexa.Setting.Opening', 'Alexa.Setting.Oscillate', 'Alexa.Setting.Preset',
    'Alexa.Setting.Quiet', 'Alexa.Setting.Temperature', 'Alexa.Setting.WashCycle',
    'Alexa.Setting.WaterTemperature',
    'Alexa.Value.Close', 'Alexa.Value.Delicate', 'Alexa.Value.High', 'Alexa.Value.Low',
    'Alexa.Value.Maximum', 'Alexa.Value.Medium', 'Alexa.Value.Minimum', 'Alexa.Value.Open',
    'Alexa.Value.QuickWash'
]);

// Reference an Amazon catalog asset. If the id isn't a known catalog asset, fall
// back to a plain text resource (always valid) so one bad assetId can never
// reject an endpoint. `textFallback` lets callers supply a readable label.
function assetId(id, textFallback) {
    if (VALID_ASSET_IDS.has(id)) {
        return { '@type': 'asset', value: { assetId: id } };
    }
    // Derive a label from the asset id (e.g. Alexa.Setting.FanSpeed → "Fan Speed").
    const label = textFallback || String(id).split('.').pop().replace(/([a-z])([A-Z])/g, '$1 $2');
    return assetText(label);
}

function friendlyNames(...names) {
    return { friendlyNames: names };
}

// Open/Close semantics for a RangeController whose 0..100 maps to closed..open.
// Lets "open/close the blinds" resolve to SetRangeValue 100/0 and "stop" if the
// device reports a partial position.
function openCloseRangeSemantics() {
    return {
        actionMappings: [
            { '@type': 'ActionsToDirective', actions: ['Alexa.Actions.Close'], directive: { name: 'SetRangeValue', payload: { rangeValue: 0 } } },
            { '@type': 'ActionsToDirective', actions: ['Alexa.Actions.Open'], directive: { name: 'SetRangeValue', payload: { rangeValue: 100 } } },
            { '@type': 'ActionsToDirective', actions: ['Alexa.Actions.Lower'], directive: { name: 'SetRangeValue', payload: { rangeValue: 0 } } },
            { '@type': 'ActionsToDirective', actions: ['Alexa.Actions.Raise'], directive: { name: 'SetRangeValue', payload: { rangeValue: 100 } } }
        ],
        stateMappings: [
            { '@type': 'StatesToValue', states: ['Alexa.States.Closed'], value: 0 },
            { '@type': 'StatesToRange', states: ['Alexa.States.Open'], range: { minimumValue: 1, maximumValue: 100 } }
        ]
    };
}

// ── Instanced-controller spec builders (reused across many entity types) ─

/**
 * RangeController — a 0..N numeric setting on an instance (fan speed, cover
 * position, valve position, humidifier target, vacuum suction, ...).
 * `readValue(statePayload)` returns the current numeric value (or null to omit).
 */
function rangeControllerSpec({ instance, names, min, max, precision, unitOfMeasure, presets, semantics, readValue }) {
    // Defensive range: Amazon's schema requires minimumValue < maximumValue and a
    // positive precision. Weird HA data (e.g. min_humidity == max_humidity, or
    // non-numeric) would otherwise emit an invalid range that fails schema
    // validation and 400s the WHOLE Discovery batch.
    let lo = Number(min);
    let hi = Number(max);
    if (!Number.isFinite(lo)) lo = 0;
    if (!Number.isFinite(hi)) hi = 100;
    if (hi <= lo) hi = lo + 100;
    let step = Number(precision);
    if (!Number.isFinite(step) || step <= 0) step = 1;
    const configuration = {
        supportedRange: { minimumValue: lo, maximumValue: hi, precision: step }
    };
    if (unitOfMeasure) configuration.unitOfMeasure = unitOfMeasure;
    if (Array.isArray(presets) && presets.length > 0) configuration.presets = presets;
    const discovery = { capabilityResources: friendlyNames(...names), configuration };
    if (semantics) discovery.semantics = semantics;
    return {
        iface: 'Alexa.RangeController',
        instance,
        version: '3',
        properties: ['rangeValue'],
        discovery,
        readState: (sp, online) => {
            const v = readValue(sp, online);
            return v === null || v === undefined ? [] : [{ name: 'rangeValue', value: v }];
        }
    };
}

/**
 * ModeController — an enumerated setting on an instance (fan preset, select
 * option, climate fan/preset/swing, vacuum mode, ...).
 * `modes` = [{ value, names: [assetText/assetId...] }]. `readMode(statePayload)`
 * returns the current mode value (or null/'' to omit).
 *
 * Returns null when fewer than 2 modes are supplied: Amazon's schema REQUIRES a
 * minimum of two mode objects, and a single-mode controller makes the whole
 * Discovery payload fail to parse ("Payload does not match required Schema").
 * Callers spread the result and filter falsy specs, so a 1-option HA entity
 * simply doesn't expose that controller instead of breaking the entire batch.
 */
function modeControllerSpec({ instance, names, modes, ordered, semantics, readMode }) {
    if (!Array.isArray(modes) || modes.length < 2) {
        return null;
    }
    const supportedModes = modes.map((m) => ({
        value: m.value,
        modeResources: friendlyNames(...m.names)
    }));
    const discovery = {
        capabilityResources: friendlyNames(...names),
        configuration: { ordered: Boolean(ordered), supportedModes }
    };
    if (semantics) discovery.semantics = semantics;
    return {
        iface: 'Alexa.ModeController',
        instance,
        version: '3',
        properties: ['mode'],
        discovery,
        readState: (sp) => {
            const v = readMode(sp);
            return v === null || v === undefined || v === '' ? [] : [{ name: 'mode', value: v }];
        }
    };
}

/**
 * ToggleController — an on/off sub-feature on an instance (fan oscillate, ...).
 * `readOn(statePayload)` returns a boolean.
 */
function toggleControllerSpec({ instance, names, semantics, readOn }) {
    const discovery = { capabilityResources: friendlyNames(...names) };
    if (semantics) discovery.semantics = semantics;
    return {
        iface: 'Alexa.ToggleController',
        instance,
        version: '3',
        properties: ['toggleState'],
        discovery,
        readState: (sp) => [{ name: 'toggleState', value: readOn(sp) ? 'ON' : 'OFF' }]
    };
}

// ── Shared capability-spec builders (reused across entity types) ────────

function baseSpec() {
    return { iface: 'Alexa', version: '3' };
}

function healthSpec() {
    return {
        iface: 'Alexa.EndpointHealth',
        version: '3.2',
        properties: ['connectivity'],
        readState: (_sp, online) => [{ name: 'connectivity', value: { value: online ? 'OK' : 'UNREACHABLE' } }]
    };
}

// PowerController from a boolean accessor (defaults to statePayload.on).
function powerSpec(getOn) {
    const accessor = typeof getOn === 'function' ? getOn : (sp) => Boolean(sp.on);
    return {
        iface: 'Alexa.PowerController',
        version: '3',
        properties: ['powerState'],
        readState: (sp) => [{ name: 'powerState', value: accessor(sp) ? 'ON' : 'OFF' }]
    };
}

function brightnessSpec() {
    return {
        iface: 'Alexa.BrightnessController',
        version: '3',
        properties: ['brightness'],
        readState: (sp) => {
            const raw = clampPercent(sp.brightness);
            // A light that's ON shouldn't report 0% (stale off-state brightness).
            return [{ name: 'brightness', value: sp.on && raw === 0 ? 100 : raw }];
        }
    };
}

function colorSpec() {
    return {
        iface: 'Alexa.ColorController',
        version: '3',
        properties: ['color'],
        readState: (sp) => {
            if (Array.isArray(sp.hs_color) && sp.hs_color.length >= 2) {
                const hue = Number(sp.hs_color[0]) || 0;
                const saturation = (Number(sp.hs_color[1]) || 0) / 100;
                const brightnessFraction = clampPercent(sp.brightness) / 100;
                return [
                    {
                        name: 'color',
                        value: {
                            hue: Math.max(0, Math.min(360, hue)),
                            saturation: Math.max(0, Math.min(1, saturation)),
                            brightness: Math.max(0, Math.min(1, brightnessFraction || 1))
                        }
                    }
                ];
            }
            return [];
        }
    };
}

function colorTemperatureSpec() {
    return {
        iface: 'Alexa.ColorTemperatureController',
        version: '3',
        properties: ['colorTemperatureInKelvin'],
        readState: (sp) =>
            sp.color_temp_kelvin
                ? [{ name: 'colorTemperatureInKelvin', value: Number(sp.color_temp_kelvin) || 3000 }]
                : []
    };
}

// SceneController is stateless: no reportable properties. `supportsDeactivation`
// is false for HA scenes/scripts/buttons (they fire-and-forget; there's no
// "undo"). The Discovery capability omits a `properties` block entirely.
function sceneControllerSpec(supportsDeactivation) {
    return {
        iface: 'Alexa.SceneController',
        version: '3',
        discovery: { supportsDeactivation: Boolean(supportsDeactivation) },
        readState: () => []
    };
}

function lockSpec() {
    return {
        iface: 'Alexa.LockController',
        version: '3',
        properties: ['lockState'],
        readState: (sp) => {
            // HA exposes locked/unlocked; jammed maps to Alexa JAMMED.
            let value = sp.isLocked ? 'LOCKED' : 'UNLOCKED';
            if (sp.jammed === true || sp.lock_state === 'jammed') {
                value = 'JAMMED';
            }
            return [{ name: 'lockState', value }];
        }
    };
}

// Read-only sensor interfaces (proactively reported, retrievable).
function temperatureSensorSpec() {
    return {
        iface: 'Alexa.TemperatureSensor',
        version: '3',
        properties: ['temperature'],
        readState: (sp) => {
            const scale = /F/i.test(sp.unit_of_measurement || '') ? 'FAHRENHEIT' : 'CELSIUS';
            const raw = sp.temperature != null ? sp.temperature : sp.value;
            return [{ name: 'temperature', value: { value: Number(raw) || 0, scale } }];
        }
    };
}

function humiditySensorSpec() {
    return {
        iface: 'Alexa.HumiditySensor',
        version: '3',
        properties: ['relativeHumidity'],
        readState: (sp) => {
            const raw = sp.value != null ? sp.value : sp.humidity;
            return [{ name: 'relativeHumidity', value: clampPercent(raw) }];
        }
    };
}

function contactSensorSpec() {
    return {
        iface: 'Alexa.ContactSensor',
        version: '3',
        properties: ['detectionState'],
        readState: (sp) => [{ name: 'detectionState', value: sp.is_on ? 'DETECTED' : 'NOT_DETECTED' }]
    };
}

function motionSensorSpec() {
    return {
        iface: 'Alexa.MotionSensor',
        version: '3',
        properties: ['detectionState'],
        readState: (sp) => [{ name: 'detectionState', value: sp.is_on ? 'DETECTED' : 'NOT_DETECTED' }]
    };
}

// A scale-tagged temperature value object for ThermostatController/TemperatureSensor.
function tempValue(raw, unit) {
    const scale = /F/i.test(unit || '') ? 'FAHRENHEIT' : 'CELSIUS';
    return { value: Number(raw) || 0, scale };
}

// HA→Alexa thermostat mode mapping.
const HA_TO_ALEXA_THERMOSTAT_MODE = {
    heat: 'HEAT',
    cool: 'COOL',
    heat_cool: 'AUTO',
    auto: 'AUTO',
    'fan_only': 'FAN',
    dry: 'DEHUMIDIFY',
    off: 'OFF'
};

function toAlexaThermostatMode(haMode) {
    if (!haMode) return 'OFF';
    return HA_TO_ALEXA_THERMOSTAT_MODE[String(haMode).toLowerCase()] || 'OFF';
}

/**
 * ThermostatController. `opts.modes` = list of HA hvac/operation modes to
 * advertise; omit/empty for a setpoint-only device (water_heater). `opts.dual`
 * enables lower/upper setpoints (climate heat_cool). State accessors pull from
 * the entity's statePayload.
 */
function thermostatSpec({ modes, single, readMode, readTarget, readLow, readHigh, unitKey }) {
    const properties = ['targetSetpoint'];
    if (!single) {
        properties.push('lowerSetpoint', 'upperSetpoint');
    }
    if (Array.isArray(modes) && modes.length > 0) {
        properties.push('thermostatMode');
    }
    const configuration = {};
    if (Array.isArray(modes) && modes.length > 0) {
        configuration.supportedModes = Array.from(new Set(modes.map(toAlexaThermostatMode)));
    }
    configuration.supportsScheduling = false;
    return {
        iface: 'Alexa.ThermostatController',
        version: '3',
        properties,
        discovery: { configuration },
        readState: (sp) => {
            const unit = sp[unitKey || 'temperature_unit'];
            const out = [];
            const target = readTarget(sp);
            if (target !== null && target !== undefined) {
                out.push({ name: 'targetSetpoint', value: tempValue(target, unit) });
            }
            if (!single) {
                const low = readLow ? readLow(sp) : null;
                const high = readHigh ? readHigh(sp) : null;
                if (low !== null && low !== undefined) out.push({ name: 'lowerSetpoint', value: tempValue(low, unit) });
                if (high !== null && high !== undefined) out.push({ name: 'upperSetpoint', value: tempValue(high, unit) });
            }
            if (Array.isArray(modes) && modes.length > 0 && readMode) {
                out.push({ name: 'thermostatMode', value: toAlexaThermostatMode(readMode(sp)) });
            }
            return out;
        }
    };
}

// ── The capability plan — single source of truth per endpoint ───────────

function buildCapabilityPlan(entityType, statePayload, options = {}) {
    const sp = statePayload || {};
    const specs = [baseSpec(), healthSpec()];

    if (!SUPPORTED_ENTITY_TYPES.has(entityType)) {
        // Unmapped type → base+health only → excluded by buildAlexaEndpoint.
        return specs;
    }

    if (isLight(entityType)) {
        specs.push(powerSpec());
        const { hasBrightness, hasColor, hasColorTemp } = lightColorSupport(sp);
        if (hasBrightness) specs.push(brightnessSpec());
        if (hasColor) specs.push(colorSpec());
        if (hasColorTemp) specs.push(colorTemperatureSpec());
    } else if (entityType === 'switch' || entityType === 'outlet' || entityType === 'input_boolean') {
        specs.push(powerSpec());
    } else if (entityType === 'automation' || entityType === 'group') {
        // On/off via PowerController. (automation.turn_on/off enables/disables
        // the automation; group is fanned out by the add-on via homeassistant.*)
        specs.push(powerSpec());
    } else if (
        entityType === 'scene' ||
        entityType === 'script' ||
        entityType === 'button' ||
        entityType === 'input_button'
    ) {
        // Stateless activation. HA scenes/scripts/buttons fire-and-forget.
        specs.push(sceneControllerSpec(false));
    } else if (entityType === 'lock') {
        specs.push(lockSpec());
    } else if (entityType === 'fan') {
        specs.push(...fanSpecs(sp));
    } else if (entityType === 'cover') {
        specs.push(...coverSpecs(sp));
    } else if (entityType === 'valve') {
        specs.push(...valveSpecs(sp));
    } else if (entityType === 'sensor') {
        // Only temperature/humidity are representable; other classes are Tier-D
        // (air quality etc.) → no spec → excluded at Discovery.
        if (sp.device_class === SENSOR_TEMPERATURE_CLASS) {
            specs.push(temperatureSensorSpec());
        } else if (sp.device_class === SENSOR_HUMIDITY_CLASS) {
            specs.push(humiditySensorSpec());
        }
    } else if (entityType === 'binary_sensor') {
        // door/window/opening → Contact; motion/occupancy → Motion. Others
        // (smoke/co/gas/moisture) are Tier-D → excluded.
        if (BINARY_CONTACT_CLASSES.has(sp.device_class)) {
            specs.push(contactSensorSpec());
        } else if (BINARY_MOTION_CLASSES.has(sp.device_class)) {
            specs.push(motionSensorSpec());
        }
    } else if (entityType === 'select' || entityType === 'input_select') {
        const options = Array.isArray(sp.options) ? sp.options : [];
        if (options.length > 0) {
            specs.push(
                modeControllerSpec({
                    instance: 'Select.Option',
                    names: [assetText('Option'), assetText('Mode')],
                    ordered: false,
                    modes: options.map((o) => ({ value: String(o), names: [assetText(String(o))] })),
                    readMode: (s) => (s.current_option == null ? null : String(s.current_option))
                })
            );
        }
        // No options → no spec → excluded at Discovery.
    } else if (entityType === 'humidifier') {
        specs.push(...humidifierSpecs(sp));
    } else if (entityType === 'water_heater') {
        specs.push(...waterHeaterSpecs(sp));
    } else if (entityType === 'climate') {
        specs.push(...climateSpecs(sp));
    } else if (entityType === 'vacuum') {
        specs.push(...vacuumSpecs(sp));
    } else if (entityType === 'lawn_mower') {
        specs.push(...lawnMowerSpecs(sp));
    } else if (entityType === 'media_player') {
        specs.push(...mediaPlayerSpecs(sp));
    } else if (entityType === 'alarm_control_panel') {
        specs.push(securityPanelSpec(sp, options.userHasSecurityPin));
    }

    // Drop any spec a builder declined to produce (e.g. a ModeController with
    // fewer than the schema-required 2 modes). Centralized here so no per-domain
    // helper can leak a null/invalid capability into Discovery.
    return specs.filter(Boolean);
}

// HA arm_state → Alexa armState.
const HA_TO_ALEXA_ARM_STATE = {
    armed_home: 'ARMED_STAY',
    armed_away: 'ARMED_AWAY',
    armed_night: 'ARMED_NIGHT',
    armed_custom_bypass: 'ARMED_STAY',
    armed_vacation: 'ARMED_AWAY'
};

function securityPanelSpec(sp, userHasSecurityPin) {
    const configuration = {
        supportedArmStates: [
            { value: 'ARMED_AWAY' },
            { value: 'ARMED_STAY' },
            { value: 'ARMED_NIGHT' },
            { value: 'DISARMED' }
        ]
    };
    // Disarm-only PIN: advertised only when the user configured one. Amazon
    // requires this field to be OMITTED when empty (an empty array fails schema
    // validation and 400s the whole Discovery batch).
    if (userHasSecurityPin) {
        configuration.supportedAuthorizationTypes = [{ type: 'FOUR_DIGIT_PIN' }];
    }
    return {
        iface: 'Alexa.SecurityPanelController',
        version: '3',
        properties: ['armState'],
        discovery: { configuration },
        readState: (s) => {
            const armState = HA_TO_ALEXA_ARM_STATE[s.arm_state] || 'DISARMED';
            return [{ name: 'armState', value: armState }];
        }
    };
}

// HA media_player supported_features bits.
const MP_PAUSE = 1;
const MP_VOLUME_SET = 4;
const MP_VOLUME_MUTE = 8;
const MP_PREVIOUS_TRACK = 16;
const MP_NEXT_TRACK = 32;
const MP_TURN_ON = 128;
const MP_TURN_OFF = 256;
const MP_PLAY = 16384;
const MP_STOP = 4096;
const MP_SELECT_SOURCE = 2048;
const MP_VOLUME_STEP = 1024;

function mediaPlayerSpecs(sp) {
    const sf = Number(sp.supported_features) || 0;
    const has = (bit) => (sf & bit) !== 0;
    const specs = [];

    // Power.
    if (has(MP_TURN_ON) || has(MP_TURN_OFF) || sf === 0) {
        specs.push(powerSpec((s) => Boolean(s.on)));
    }

    // PlaybackController — operation-only (no retrievable state).
    const ops = [];
    if (has(MP_PLAY) || has(MP_PAUSE)) ops.push('Play', 'Pause');
    if (has(MP_STOP)) ops.push('Stop');
    if (has(MP_NEXT_TRACK)) ops.push('Next');
    if (has(MP_PREVIOUS_TRACK)) ops.push('Previous');
    if (ops.length > 0) {
        specs.push({
            iface: 'Alexa.PlaybackController',
            version: '3',
            discovery: { supportedOperations: Array.from(new Set(ops)) },
            readState: () => []
        });
    }

    // Speaker — volume + mute.
    if (has(MP_VOLUME_SET) || has(MP_VOLUME_STEP) || sf === 0) {
        specs.push({
            iface: 'Alexa.Speaker',
            version: '3',
            properties: ['volume', 'muted'],
            readState: (s) => [
                { name: 'volume', value: clampPercent(s.volume) },
                { name: 'muted', value: Boolean(s.muted) }
            ]
        });
    }

    // InputController — from source_list. Input names must be alphanumeric +
    // spaces (Amazon schema); coerce raw HA source names and drop any that
    // collapse to empty or collide after sanitizing.
    const sources = Array.isArray(sp.source_list) ? sp.source_list : [];
    if (has(MP_SELECT_SOURCE) && sources.length > 0) {
        const seenInputs = new Set();
        const inputs = [];
        for (const s of sources) {
            const name = String(s == null ? '' : s)
                .replace(/[^a-zA-Z0-9 ]+/g, ' ')
                .replace(/\s+/g, ' ')
                .trim()
                .slice(0, 128);
            if (!name || seenInputs.has(name)) continue;
            seenInputs.add(name);
            inputs.push({ name });
        }
        if (inputs.length > 0) {
            specs.push({
                iface: 'Alexa.InputController',
                version: '3',
                properties: ['input'],
                discovery: { inputs },
                readState: (s) => (s.source ? [{ name: 'input', value: String(s.source) }] : [])
            });
        }
    }

    return specs;
}

const VACUUM_FAN_SPEED = 32;

function vacuumSpecs(sp) {
    const specs = [
        powerSpec((s) => Boolean(s.on)),
        modeControllerSpec({
            instance: 'Vacuum.Mode',
            names: [assetText('Mode'), assetText('Cleaning')],
            ordered: false,
            modes: [
                { value: 'Clean', names: [assetText('Clean'), assetText('Start')] },
                { value: 'Pause', names: [assetText('Pause')] },
                { value: 'Dock', names: [assetText('Dock'), assetText('Return'), assetText('Home')] }
            ],
            readMode: (s) => {
                if (s.isDocked) return 'Dock';
                if (s.isPaused) return 'Pause';
                if (s.isRunning) return 'Clean';
                return 'Pause';
            }
        })
    ];
    const sf = Number(sp.supported_features) || 0;
    const speeds = Array.isArray(sp.fan_speed_list) ? sp.fan_speed_list : [];
    if ((sf & VACUUM_FAN_SPEED) !== 0 && speeds.length > 0) {
        specs.push(
            modeControllerSpec({
                instance: 'Vacuum.Suction',
                names: [assetText('Suction'), assetText('Power')],
                ordered: true,
                modes: speeds.map((s) => ({ value: String(s), names: [assetText(String(s))] })),
                readMode: (s) => (s.fan_speed == null ? null : String(s.fan_speed))
            })
        );
    }
    return specs;
}

function lawnMowerSpecs(sp) {
    return [
        powerSpec((s) => Boolean(s.isRunning)),
        modeControllerSpec({
            instance: 'Mower.State',
            names: [assetText('Mode'), assetText('Mowing')],
            ordered: false,
            modes: [
                { value: 'Mow', names: [assetText('Mow'), assetText('Start')] },
                { value: 'Pause', names: [assetText('Pause')] },
                { value: 'Dock', names: [assetText('Dock'), assetText('Home')] }
            ],
            readMode: (s) => {
                if (s.isDocked) return 'Dock';
                if (s.isPaused) return 'Pause';
                if (s.isRunning) return 'Mow';
                return 'Pause';
            }
        })
    ];
}

// HA climate supported_features bits.
const CLIMATE_FAN_MODE = 8;
const CLIMATE_PRESET_MODE = 16;
const CLIMATE_SWING_MODE = 32;

function climateSpecs(sp) {
    const sf = Number(sp.supported_features) || 0;
    const has = (bit) => (sf & bit) !== 0;
    const hvacModes = Array.isArray(sp.hvac_modes) ? sp.hvac_modes : [];

    const specs = [
        thermostatSpec({
            single: false,
            modes: hvacModes.length > 0 ? hvacModes : ['off', 'heat', 'cool', 'auto'],
            unitKey: 'temperature_unit',
            readMode: (s) => s.mode,
            readTarget: (s) => (s.target_temperature == null ? null : s.target_temperature),
            readLow: (s) => (s.target_temp_low == null ? null : s.target_temp_low),
            readHigh: (s) => (s.target_temp_high == null ? null : s.target_temp_high)
        }),
        {
            iface: 'Alexa.TemperatureSensor',
            version: '3',
            properties: ['temperature'],
            readState: (s) =>
                s.ambient_temperature == null ? [] : [{ name: 'temperature', value: tempValue(s.ambient_temperature, s.temperature_unit) }]
        }
    ];

    // Fan / preset / swing as ModeControllers (one instance each).
    if (has(CLIMATE_FAN_MODE)) {
        const modes = Array.isArray(sp.fan_modes) ? sp.fan_modes : [];
        if (modes.length > 0) {
            specs.push(
                modeControllerSpec({
                    instance: 'Climate.FanMode',
                    names: [assetText('Fan Mode'), assetText('Fan Speed')],
                    ordered: false,
                    modes: modes.map((m) => ({ value: String(m), names: [assetText(String(m))] })),
                    readMode: (s) => (s.fan_mode == null ? null : String(s.fan_mode))
                })
            );
        }
    }
    if (has(CLIMATE_PRESET_MODE)) {
        const modes = Array.isArray(sp.preset_modes) ? sp.preset_modes : [];
        if (modes.length > 0) {
            specs.push(
                modeControllerSpec({
                    instance: 'Climate.PresetMode',
                    names: [assetText('Preset'), assetText('Mode')],
                    ordered: false,
                    modes: modes.map((m) => ({ value: String(m), names: [assetText(String(m))] })),
                    readMode: (s) => (s.preset_mode == null ? null : String(s.preset_mode))
                })
            );
        }
    }
    if (has(CLIMATE_SWING_MODE)) {
        const modes = Array.isArray(sp.swing_modes) ? sp.swing_modes : [];
        if (modes.length > 0) {
            specs.push(
                modeControllerSpec({
                    instance: 'Climate.SwingMode',
                    names: [assetText('Swing'), assetText('Swing Mode')],
                    ordered: false,
                    modes: modes.map((m) => ({ value: String(m), names: [assetText(String(m))] })),
                    readMode: (s) => (s.swing_mode == null ? null : String(s.swing_mode))
                })
            );
        }
    }
    return specs;
}

function humidifierSpecs(sp) {
    const specs = [powerSpec()];
    const min = Number.isFinite(Number(sp.min_humidity)) ? Number(sp.min_humidity) : 0;
    const max = Number.isFinite(Number(sp.max_humidity)) ? Number(sp.max_humidity) : 100;
    specs.push(
        rangeControllerSpec({
            instance: 'Humidifier.Humidity',
            // Alexa.Setting.Humidity is NOT in the global catalog — use plain text.
            names: [assetText('Humidity'), assetText('Moisture')],
            min,
            max,
            precision: 1,
            unitOfMeasure: 'Alexa.Unit.Percent',
            readValue: (s) => (s.target_humidity == null ? null : clampRange(s.target_humidity, 0, 100))
        })
    );
    const modes = Array.isArray(sp.available_modes) ? sp.available_modes : [];
    if (modes.length > 0) {
        specs.push(
            modeControllerSpec({
                instance: 'Humidifier.Mode',
                names: [assetText('Mode')],
                ordered: false,
                modes: modes.map((m) => ({ value: String(m), names: [assetText(String(m))] })),
                readMode: (s) => (s.mode == null ? null : String(s.mode))
            })
        );
    }
    return specs;
}

function waterHeaterSpecs(sp) {
    return [
        powerSpec(),
        thermostatSpec({
            single: true,
            modes: [],
            unitKey: 'temperature_unit',
            readTarget: (s) => (s.target_temperature == null ? null : s.target_temperature)
        }),
        {
            iface: 'Alexa.TemperatureSensor',
            version: '3',
            properties: ['temperature'],
            readState: (s) =>
                s.current_temperature == null ? [] : [{ name: 'temperature', value: tempValue(s.current_temperature, s.temperature_unit) }]
        }
    ];
}

// HA cover/valve supported_features bits.
const COVER_SET_POSITION = 4;
const COVER_SET_TILT_POSITION = 128;
const VALVE_SET_POSITION = 4;

// Discrete Open/Closed ModeController shared by garage covers, non-positional
// covers, and non-positional valves. The instance name varies by domain.
function openCloseModeSpec(instance, readOpen) {
    return modeControllerSpec({
        instance,
        names: [assetText('Position')],
        ordered: false,
        modes: [
            { value: 'Open', names: [assetId('Alexa.Value.Open'), assetText('Open')] },
            { value: 'Closed', names: [assetId('Alexa.Value.Close'), assetText('Closed')] }
        ],
        semantics: {
            actionMappings: [
                { '@type': 'ActionsToDirective', actions: ['Alexa.Actions.Close', 'Alexa.Actions.Lower'], directive: { name: 'SetMode', payload: { mode: 'Closed' } } },
                { '@type': 'ActionsToDirective', actions: ['Alexa.Actions.Open', 'Alexa.Actions.Raise'], directive: { name: 'SetMode', payload: { mode: 'Open' } } }
            ],
            stateMappings: [
                { '@type': 'StatesToValue', states: ['Alexa.States.Closed'], value: 'Closed' },
                { '@type': 'StatesToValue', states: ['Alexa.States.Open'], value: 'Open' }
            ]
        },
        readMode: (sp) => (readOpen(sp) ? 'Open' : 'Closed')
    });
}

function coverSpecs(sp) {
    const sf = Number(sp.supported_features) || 0;
    const has = (bit) => (sf & bit) !== 0;
    const dc = sp.device_class || null;
    const specs = [];

    // Garage doors are discrete Open/Closed (Amazon recommends ModeController +
    // semantics for GARAGE_DOOR, not a position range).
    if (dc === 'garage' || dc === 'gate') {
        specs.push(openCloseModeSpec('Cover.Position', (s) => Number(s.openPercent) > 0));
        return specs;
    }

    if (has(COVER_SET_POSITION)) {
        specs.push(
            rangeControllerSpec({
                instance: 'Cover.Position',
                names: [assetId('Alexa.Setting.Opening'), assetText('Position')],
                min: 0,
                max: 100,
                precision: 1,
                unitOfMeasure: 'Alexa.Unit.Percent',
                semantics: openCloseRangeSemantics(),
                readValue: (s) => clampPercent(s.openPercent)
            })
        );
    } else {
        // Open/close only — discrete ModeController.
        specs.push(openCloseModeSpec('Cover.Position', (s) => Number(s.openPercent) > 0));
    }

    if (has(COVER_SET_TILT_POSITION)) {
        specs.push(
            rangeControllerSpec({
                instance: 'Cover.Tilt',
                names: [assetText('Tilt'), assetId('Alexa.Setting.Direction')],
                min: 0,
                max: 100,
                precision: 1,
                unitOfMeasure: 'Alexa.Unit.Percent',
                readValue: (s) => (s.tilt_position === null || s.tilt_position === undefined ? null : clampPercent(s.tilt_position))
            })
        );
    }
    return specs;
}

function valveSpecs(sp) {
    const sf = Number(sp.supported_features) || 0;
    const has = (bit) => (sf & bit) !== 0;
    if (has(VALVE_SET_POSITION)) {
        return [
            rangeControllerSpec({
                instance: 'Valve.Position',
                names: [assetId('Alexa.Setting.Opening'), assetText('Position')],
                min: 0,
                max: 100,
                precision: 1,
                unitOfMeasure: 'Alexa.Unit.Percent',
                semantics: openCloseRangeSemantics(),
                readValue: (s) => clampPercent(s.openPercent)
            })
        ];
    }
    return [openCloseModeSpec('Valve.Position', (s) => Number(s.openPercent) > 0)];
}

// HA fan supported_features bits.
const FAN_SET_SPEED = 1;
const FAN_OSCILLATE = 2;
const FAN_DIRECTION = 4;
const FAN_PRESET_MODE = 8;

function fanSpecs(sp) {
    const specs = [powerSpec()];
    const sf = Number(sp.supported_features) || 0;
    const has = (bit) => (sf & bit) !== 0;

    // Speed as a percentage RangeController. Always offered (degrades to a
    // simple slider for fans that only support on/off, matching Google).
    const step = Number(sp.percentage_step) > 0 ? Math.round(Number(sp.percentage_step)) : 1;
    specs.push(
        rangeControllerSpec({
            instance: 'Fan.Speed',
            names: [assetId('Alexa.Setting.FanSpeed'), assetText('Speed')],
            min: 0,
            max: 100,
            precision: step,
            unitOfMeasure: 'Alexa.Unit.Percent',
            readValue: (s) => clampPercent(s.percentage)
        })
    );

    // Oscillation toggle.
    if (has(FAN_OSCILLATE)) {
        specs.push(
            toggleControllerSpec({
                instance: 'Fan.Oscillate',
                names: [assetId('Alexa.Setting.Oscillate'), assetText('Oscillate')],
                readOn: (s) => Boolean(s.oscillating)
            })
        );
    }

    // Preset modes (e.g. eco/sleep/turbo) as a ModeController.
    const presetModes = Array.isArray(sp.preset_modes) ? sp.preset_modes : [];
    if (has(FAN_PRESET_MODE) && presetModes.length > 0) {
        specs.push(
            modeControllerSpec({
                instance: 'Fan.PresetMode',
                names: [assetText('Preset'), assetText('Mode')],
                ordered: false,
                modes: presetModes.map((m) => ({ value: m, names: [assetText(m)] })),
                readMode: (s) => s.preset_mode || null
            })
        );
    }

    // Direction (forward/reverse) as a ModeController.
    if (has(FAN_DIRECTION)) {
        specs.push(
            modeControllerSpec({
                instance: 'Fan.Direction',
                names: [assetText('Direction')],
                ordered: false,
                modes: [
                    { value: 'forward', names: [assetText('Forward'), assetText('Normal')] },
                    { value: 'reverse', names: [assetText('Reverse'), assetText('Backward')] }
                ],
                readMode: (s) => s.direction || null
            })
        );
    }

    return specs;
}

// True when the plan carries a real capability beyond base Alexa + health.
function planHasControllableCapability(plan) {
    return plan.some((s) => s.iface !== 'Alexa' && s.iface !== 'Alexa.EndpointHealth');
}

// ── Discovery: project a spec → an AlexaInterface capability object ──────

function specToDiscoveryCapability(spec) {
    const cap = { type: 'AlexaInterface', interface: spec.iface, version: spec.version || '3' };
    if (spec.instance) {
        cap.instance = spec.instance;
    }
    if (Array.isArray(spec.properties) && spec.properties.length > 0) {
        cap.properties = {
            supported: spec.properties.map((name) => ({ name })),
            proactivelyReported: spec.proactive !== false,
            retrievable: spec.retrievable !== false
        };
    }
    if (spec.discovery && typeof spec.discovery === 'object') {
        Object.assign(cap, spec.discovery);
    }
    return cap;
}

function buildAlexaEndpoint(endpoint, options = {}) {
    const entityType = endpoint.entity_type;
    const statePayload = parseJsonSafe(endpoint.state_json, {}) || {};
    const plan = buildCapabilityPlan(entityType, statePayload, options);

    // Exclusion gate: no controllable/reportable capability → not exposed.
    if (!planHasControllableCapability(plan)) {
        return null;
    }

    const friendlyName = sanitizeAlexaFriendlyName(endpoint.display_name, endpoint.entity_id);
    const built = {
        endpointId: endpoint.entity_id,
        manufacturerName: utils.sanitizeString(statePayload._manufacturer, 120) || 'Apex Oasis',
        description: utils.sanitizeString(`${endpoint.display_name} (Apex Oasis Cloud Connect)`, 128) || 'Apex Oasis Cloud Connect',
        friendlyName,
        displayCategories: resolveDisplayCategories(entityType, statePayload),
        cookie: {},
        capabilities: plan.map(specToDiscoveryCapability)
    };

    // Final safety net: validate against Amazon's schema. A single invalid
    // endpoint makes Amazon reject the ENTIRE Discovery/AddOrUpdate batch
    // (0 devices), so we DROP a bad endpoint rather than poison the batch.
    const errors = validateAlexaEndpoint(built);
    if (errors.length > 0) {
        console.warn('ALEXA ENDPOINT DROPPED (schema-invalid):', endpoint.entity_id, '→', errors.join('; '));
        return null;
    }
    return built;
}

/**
 * Validate a built endpoint against the Alexa Discovery schema rules that, if
 * violated, cause Amazon to reject the whole batch. Returns an array of human
 * error strings (empty = valid). This is the defensive backstop — the per-field
 * builders already try to produce valid output, but this guarantees nothing
 * malformed ever reaches Amazon.
 */
function validateAlexaEndpoint(ep) {
    const errs = [];
    const NAME_RE = /^[a-zA-Z0-9 ]+$/;
    if (!ep.endpointId || String(ep.endpointId).length > 256) errs.push('bad endpointId');
    if (!ep.friendlyName || !NAME_RE.test(ep.friendlyName) || ep.friendlyName.length > 256) {
        errs.push(`friendlyName ${JSON.stringify(ep.friendlyName)}`);
    }
    if (!Array.isArray(ep.displayCategories) || ep.displayCategories.length === 0) {
        errs.push('no displayCategories');
    } else {
        for (const c of ep.displayCategories) if (!VALID_DISPLAY_CATEGORIES.has(c)) errs.push(`category ${c}`);
    }
    const caps = ep.capabilities || [];
    if (caps.length === 0 || caps.length > 100) errs.push(`capability count ${caps.length}`);
    const seen = new Set();
    let hasBase = false;
    for (const c of caps) {
        if (c.interface === 'Alexa') hasBase = true;
        if (c.type !== 'AlexaInterface') errs.push(`${c.interface}: type`);
        if (!c.interface || !c.version) errs.push(`${c.interface || '?'}: interface/version`);
        const key = `${c.interface}|${c.instance || ''}`;
        if (seen.has(key)) errs.push(`duplicate ${key}`);
        seen.add(key);
        const instanced = c.interface === 'Alexa.RangeController' || c.interface === 'Alexa.ModeController' || c.interface === 'Alexa.ToggleController';
        if (instanced) {
            if (!c.instance) errs.push(`${c.interface}: missing instance`);
            const fr = c.capabilityResources && c.capabilityResources.friendlyNames;
            if (!Array.isArray(fr) || fr.length === 0) errs.push(`${c.instance}: no capabilityResources`);
            for (const f of fr || []) {
                if (f['@type'] === 'asset') {
                    if (!VALID_ASSET_IDS.has(f.value && f.value.assetId)) errs.push(`${c.instance}: assetId ${f.value && f.value.assetId}`);
                } else if (f['@type'] === 'text') {
                    if (!f.value || !f.value.text || !NAME_RE.test(f.value.text) || !f.value.locale) errs.push(`${c.instance}: text resource ${JSON.stringify(f.value && f.value.text)}`);
                } else {
                    errs.push(`${c.instance}: friendlyName @type`);
                }
            }
        }
        if (c.interface === 'Alexa.ModeController') {
            const sm = c.configuration && c.configuration.supportedModes;
            if (!Array.isArray(sm) || sm.length < 2) errs.push(`${c.instance}: <2 modes`);
            for (const m of sm || []) {
                if (!m.value) errs.push(`${c.instance}: mode value`);
                const mfr = m.modeResources && m.modeResources.friendlyNames;
                if (!Array.isArray(mfr) || mfr.length === 0) errs.push(`${c.instance}: mode ${m.value} resources`);
            }
        }
        if (c.interface === 'Alexa.RangeController') {
            const r = c.configuration && c.configuration.supportedRange;
            if (!r || typeof r.minimumValue !== 'number' || typeof r.maximumValue !== 'number' || r.minimumValue >= r.maximumValue || typeof r.precision !== 'number' || r.precision <= 0) {
                errs.push(`${c.instance}: supportedRange`);
            }
        }
    }
    if (!hasBase) errs.push('missing base Alexa interface');
    return errs;
}

// Choose displayCategories, honouring device_class refinements where relevant.
// All return paths funnel through sanitizeDisplayCategories so an invalid value
// can never reach Alexa (which would reject the whole Discovery batch).
function resolveDisplayCategories(entityType, statePayload) {
    return sanitizeDisplayCategories(resolveDisplayCategoriesRaw(entityType, statePayload));
}

// Coerce any category not in Amazon's enum to OTHER; guarantee a non-empty array.
function sanitizeDisplayCategories(categories) {
    const cleaned = (Array.isArray(categories) ? categories : [])
        .map((c) => (VALID_DISPLAY_CATEGORIES.has(c) ? c : 'OTHER'));
    return cleaned.length > 0 ? cleaned : ['OTHER'];
}

function resolveDisplayCategoriesRaw(entityType, statePayload) {
    const dc = statePayload?.device_class || null;
    if (entityType === 'cover' && dc && COVER_DISPLAY_CATEGORY[dc]) {
        return [COVER_DISPLAY_CATEGORY[dc]];
    }
    if (entityType === 'sensor') {
        // Alexa has no HUMIDITY_SENSOR displayCategory (only the HumiditySensor
        // interface). Use TEMPERATURE_SENSOR as the closest valid category for
        // both — the interface, not the category, drives the humidity reading.
        return ['TEMPERATURE_SENSOR'];
    }
    if (entityType === 'binary_sensor') {
        return [BINARY_MOTION_CLASSES.has(dc) ? 'MOTION_SENSOR' : 'CONTACT_SENSOR'];
    }
    if (entityType === 'media_player' && dc && MEDIA_PLAYER_DISPLAY_CATEGORY[dc]) {
        return [MEDIA_PLAYER_DISPLAY_CATEGORY[dc]];
    }
    return [DISPLAY_CATEGORY[entityType] || 'OTHER'];
}

// ── ReportState / ChangeReport: project the plan → AlexaProp tuples ──────

/**
 * Returns an array of structured property tuples:
 *   { namespace, instance?, name, value }
 * `value` is already in final Alexa wire shape (e.g. connectivity is
 * pre-wrapped as { value: 'OK' }). The event-gateway/fulfillment layer only
 * stamps timeOfSample/uncertaintyInMilliseconds on top (see buildProperties).
 */
function parseAlexaEndpointState(endpoint) {
    const statePayload = parseJsonSafe(endpoint.state_json, {}) || {};
    const online = endpoint.online !== 0;
    const plan = buildCapabilityPlan(endpoint.entity_type, statePayload);

    const props = [];
    for (const spec of plan) {
        if (typeof spec.readState !== 'function') {
            continue;
        }
        const entries = spec.readState(statePayload, online) || [];
        for (const entry of entries) {
            props.push({
                namespace: spec.iface,
                ...(spec.instance ? { instance: spec.instance } : {}),
                name: entry.name,
                value: entry.value
            });
        }
    }
    return props;
}

module.exports = {
    SUPPORTED_ENTITY_TYPES,
    DISPLAY_CATEGORY,
    VALID_DISPLAY_CATEGORIES,
    VALID_ASSET_IDS,
    validateAlexaEndpoint,
    normalizeAlexaEntityType,
    mapDomainToEntityType,
    buildCapabilityPlan,
    specToDiscoveryCapability,
    buildAlexaEndpoint,
    parseAlexaEndpointState
};
