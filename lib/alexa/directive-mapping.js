// Alexa Smart Home API ↔ internal entity-type translation layer.
//
// Mirrors lib/google-home/entity-mapping.js. Reuses the SAME internal entity
// types (light, switch, fan, cover, lock, climate, media_player, scene,
// vacuum, humidifier, alarm_control_panel, water_heater, camera, valve,
// lawn_mower, select, input_select, script, automation, button, input_button)
// and the SAME state_json shape stored in google_home_entities.
//
// Key APIs:
//   buildAlexaEndpoint(entity, userPin)   - Alexa.Discovery endpoint JSON
//   buildAlexaProperties(entitySnap)      - context/change property list
//   mapDirectiveToInternalAction(dir)     - directive → {action, payload, successProps}
//
// The set of internal action strings MUST match those written by the Google
// fulfillment route (set_on, set_brightness, set_lock, etc.) so the queued
// commands remain compatible with the existing apex-cloud-link add-on.

const utils = require('../utils');

// ── Category mapping ─────────────────────────────────────────────────────
// Alexa has a fixed list of "display categories" used by the Alexa app.
const ENTITY_TYPE_TO_CATEGORY = {
    light: 'LIGHT',
    switch: 'SWITCH',
    fan: 'FAN',
    cover: 'EXTERIOR_BLIND',
    lock: 'SMARTLOCK',
    climate: 'THERMOSTAT',
    water_heater: 'WATER_HEATER',
    media_player: 'TV',
    scene: 'SCENE_TRIGGER',
    script: 'ACTIVITY_TRIGGER',
    automation: 'ACTIVITY_TRIGGER',
    button: 'ACTIVITY_TRIGGER',
    input_button: 'ACTIVITY_TRIGGER',
    vacuum: 'VACUUM_CLEANER',
    lawn_mower: 'OTHER',
    humidifier: 'AIR_FRESHENER',
    alarm_control_panel: 'SECURITY_PANEL',
    camera: 'CAMERA',
    valve: 'OTHER',
    select: 'OTHER',
    input_select: 'OTHER'
};

function capabilityObject(namespace, properties = [], extra = {}) {
    // Alexa.EndpointHealth is at version 3.2; other standard interfaces are version 3.
    // Using the wrong version causes AddOrUpdateReport schema rejection.
    const version = namespace === 'Alexa.EndpointHealth' ? '3.2' : '3';
    const base = {
        type: 'AlexaInterface',
        interface: namespace,
        version
    };
    if (properties.length > 0) {
        base.properties = {
            supported: properties.map((name) => ({ name })),
            proactivelyReported: true,
            retrievable: true
        };
    }
    return { ...base, ...extra };
}

function friendlyNamesText(...labels) {
    return {
        friendlyNames: labels
            .map((label) => sanitizeAlexaName(label))
            .filter(Boolean)
            .map((label) => ({
                '@type': 'text',
                value: { text: label, locale: 'en-US' }
            }))
    };
}

// Alexa endpointId must match /^[a-zA-Z0-9_\-=#;:?@&]{1,256}$/.
// Our entity_ids are Home-Assistant style like "light.bedroom" — the dot is
// not allowed and causes AddOrUpdateReport to be rejected with
// "Payload does not match required Schema". Encode `.` as `__` (two
// underscores) so the transform is deterministic and reversible; underscores
// in source ids are preserved as-is (single `_` stays single `_`).
function encodeAlexaEndpointId(entityId) {
    const raw = (entityId === undefined || entityId === null) ? '' : String(entityId);
    return raw.replace(/\./g, '__').slice(0, 256);
}

function decodeAlexaEndpointId(endpointId) {
    const raw = (endpointId === undefined || endpointId === null) ? '' : String(endpointId);
    return raw.replace(/__/g, '.');
}

// Alexa requires friendlyName / friendlyNames text to match [A-Za-z0-9& ]+
// (spaces, letters, digits, and & only). Anything else causes the whole
// discovery payload to be rejected with "Payload does not match required Schema".
function sanitizeAlexaName(value) {
    const raw = (value === undefined || value === null) ? '' : String(value);
    // Replace disallowed chars with space, collapse whitespace, trim
    const cleaned = raw
        .replace(/[^A-Za-z0-9& ]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
    return cleaned.slice(0, 128);
}

function percentRangeConfig() {
    return {
        supportedRange: { minimumValue: 0, maximumValue: 100, precision: 1 },
        unitOfMeasure: 'Alexa.Unit.Percent'
    };
}

// ── Capability resolver ──────────────────────────────────────────────────
function resolveAlexaCapabilities(entityType, statePayload) {
    const caps = [capabilityObject('Alexa')];
    const colorModes = Array.isArray(statePayload.supported_color_modes) ? statePayload.supported_color_modes : [];
    const sf = Number(statePayload.supported_features) || 0;

    switch (entityType) {
        case 'light': {
            caps.push(capabilityObject('Alexa.PowerController', ['powerState']));
            const hasBrightness = colorModes.length > 0 && !colorModes.every((m) => m === 'onoff');
            if (hasBrightness) {
                caps.push(capabilityObject('Alexa.BrightnessController', ['brightness']));
            }
            if (colorModes.includes('hs') || colorModes.includes('rgb') || colorModes.includes('xy')) {
                caps.push(capabilityObject('Alexa.ColorController', ['color']));
            }
            if (colorModes.includes('color_temp')) {
                caps.push(capabilityObject('Alexa.ColorTemperatureController', ['colorTemperatureInKelvin']));
            }
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
        case 'switch':
        case 'automation':
        case 'script': {
            caps.push(capabilityObject('Alexa.PowerController', ['powerState']));
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
        case 'fan': {
            caps.push(capabilityObject('Alexa.PowerController', ['powerState']));
            const hasSetSpeed = (sf & 1) !== 0;
            if (hasSetSpeed) {
                caps.push(
                    capabilityObject('Alexa.PercentageController', ['percentage'], {
                        instance: 'Fan.Speed',
                        capabilityResources: friendlyNamesText('Speed', 'Fan Speed')
                    })
                );
            }
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
        case 'cover': {
            caps.push(
                capabilityObject('Alexa.RangeController', ['rangeValue'], {
                    instance: 'Cover.Position',
                    capabilityResources: friendlyNamesText('Position', 'Opening'),
                    configuration: percentRangeConfig()
                })
            );
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
        case 'valve': {
            caps.push(
                capabilityObject('Alexa.RangeController', ['rangeValue'], {
                    instance: 'Valve.Position',
                    capabilityResources: friendlyNamesText('Position', 'Opening'),
                    configuration: percentRangeConfig()
                })
            );
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
        case 'lock': {
            caps.push(capabilityObject('Alexa.LockController', ['lockState']));
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
        case 'climate': {
            caps.push(
                capabilityObject(
                    'Alexa.ThermostatController',
                    ['targetSetpoint', 'lowerSetpoint', 'upperSetpoint', 'thermostatMode'],
                    {
                        configuration: {
                            supportedModes: ['AUTO', 'COOL', 'HEAT', 'ECO', 'OFF'],
                            supportsScheduling: false
                        }
                    }
                )
            );
            caps.push(capabilityObject('Alexa.TemperatureSensor', ['temperature']));
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
        case 'water_heater': {
            caps.push(
                capabilityObject('Alexa.ThermostatController', ['targetSetpoint'], {
                    configuration: {
                        supportedModes: ['HEAT', 'OFF'],
                        supportsScheduling: false
                    }
                })
            );
            caps.push(capabilityObject('Alexa.TemperatureSensor', ['temperature']));
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
        case 'media_player': {
            caps.push(capabilityObject('Alexa.PowerController', ['powerState']));
            caps.push(capabilityObject('Alexa.Speaker', ['volume', 'muted']));
            caps.push(
                capabilityObject('Alexa.PlaybackController', [], {
                    supportedOperations: ['Play', 'Pause', 'Stop', 'Next', 'Previous']
                })
            );
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
        case 'scene': {
            caps.push(
                capabilityObject('Alexa.SceneController', [], {
                    supportsDeactivation: false
                })
            );
            return caps;
        }
        case 'button':
        case 'input_button': {
            caps.push(
                capabilityObject('Alexa.SceneController', [], {
                    supportsDeactivation: false
                })
            );
            return caps;
        }
        case 'vacuum': {
            caps.push(capabilityObject('Alexa.PowerController', ['powerState']));
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
        case 'lawn_mower': {
            caps.push(capabilityObject('Alexa.PowerController', ['powerState']));
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
        case 'humidifier': {
            caps.push(capabilityObject('Alexa.PowerController', ['powerState']));
            caps.push(
                capabilityObject('Alexa.RangeController', ['rangeValue'], {
                    instance: 'Humidifier.Humidity',
                    capabilityResources: friendlyNamesText('Humidity', 'Level'),
                    configuration: percentRangeConfig()
                })
            );
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
        case 'alarm_control_panel': {
            caps.push(
                capabilityObject('Alexa.SecurityPanelController', ['armState'], {
                    configuration: {
                        supportedArmStates: [
                            { value: 'DISARMED' },
                            { value: 'ARMED_STAY' },
                            { value: 'ARMED_AWAY' },
                            { value: 'ARMED_NIGHT' }
                        ]
                    }
                })
            );
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
        case 'camera': {
            caps.push(
                capabilityObject('Alexa.CameraStreamController', [], {
                    cameraStreamConfigurations: [
                        {
                            protocols: ['HLS'],
                            resolutions: [{ width: 1280, height: 720 }],
                            authorizationTypes: ['NONE'],
                            videoCodecs: ['H264'],
                            audioCodecs: ['AAC']
                        }
                    ]
                })
            );
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
        case 'select':
        case 'input_select': {
            const rawOptions = Array.isArray(statePayload.options)
                ? statePayload.options.filter((o) => typeof o === 'string' && o.length > 0)
                : [];
            const seenSanitized = new Set();
            const supportedModes = [];
            for (const opt of rawOptions) {
                const friendly = sanitizeAlexaName(opt);
                if (!friendly || seenSanitized.has(friendly)) continue;
                seenSanitized.add(friendly);
                // Alexa mode value pattern: [A-Za-z0-9_\-.]
                const value = String(opt).replace(/[^A-Za-z0-9_\-.]/g, '_').slice(0, 128) || `opt_${supportedModes.length}`;
                supportedModes.push({
                    value,
                    modeResources: {
                        friendlyNames: [
                            { '@type': 'text', value: { text: friendly, locale: 'en-US' } }
                        ]
                    }
                });
            }
            if (supportedModes.length > 0) {
                caps.push(
                    capabilityObject('Alexa.ModeController', ['mode'], {
                        instance: 'Select.Option',
                        capabilityResources: friendlyNamesText('Option', 'Mode'),
                        configuration: {
                            ordered: false,
                            supportedModes
                        }
                    })
                );
            }
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
        default: {
            caps.push(capabilityObject('Alexa.EndpointHealth', ['connectivity']));
            return caps;
        }
    }
}

// ── Alexa endpoint discovery object ──────────────────────────────────────
function buildAlexaEndpoint(entity, _userPin) {
    if (!entity) return null;
    const entityType = entity.entity_type || 'switch';
    const statePayload = utils.parseJsonSafe(entity.state_json, {}) || {};
    const category = ENTITY_TYPE_TO_CATEGORY[entityType] || 'OTHER';

    const safe = (v, fallback) => {
        const s = (v === undefined || v === null) ? '' : String(v).trim();
        return s.length > 0 ? s.slice(0, 256) : fallback;
    };
    const manufacturer = sanitizeAlexaName(safe(statePayload._manufacturer, 'Apex Infosys')) || 'Apex Infosys';
    const model = safe(statePayload._model, entityType);
    const softwareVersion = safe(statePayload._sw_version, '1.0.0');
    // friendlyName must match [A-Za-z0-9& ]+ per Alexa schema
    const rawDisplay = entity.display_name || entity.entity_id;
    const friendlyName = sanitizeAlexaName(rawDisplay) || sanitizeAlexaName(entity.entity_id) || 'Device';
    // description is free-form but capped at 128 chars
    const description = `${friendlyName} (${entityType})`.slice(0, 128);

    return {
        endpointId: encodeAlexaEndpointId(entity.entity_id),
        manufacturerName: manufacturer,
        description,
        friendlyName,
        displayCategories: [category],
        additionalAttributes: {
            manufacturer,
            model,
            softwareVersion,
            customIdentifier: String(entity.id || entity.entity_id).slice(0, 256)
        },
        capabilities: resolveAlexaCapabilities(entityType, statePayload),
        connections: [],
        cookie: {
            entity_type: entityType,
            device_id: String(entity.device_id || '')
        }
    };
}

// ── Property builder ─────────────────────────────────────────────────────
//
// Generates the "properties" array for StateReport responses and ChangeReport
// events from a snapshot `{ entity_type, online, state }` (state already
// parsed from state_json).
function makeProp(namespace, name, value, instance = undefined) {
    const prop = {
        namespace,
        name,
        value,
        timeOfSample: new Date().toISOString(),
        uncertaintyInMilliseconds: 500
    };
    if (instance) prop.instance = instance;
    return prop;
}

function buildAlexaProperties(snap) {
    const { entity_type: entityType, online, state } = snap || {};
    const s = state || {};
    const props = [];
    const isOn = Boolean(s.on);

    switch (entityType) {
        case 'light':
            props.push(makeProp('Alexa.PowerController', 'powerState', isOn ? 'ON' : 'OFF'));
            if (s.brightness !== undefined && s.brightness !== null) {
                props.push(
                    makeProp('Alexa.BrightnessController', 'brightness', Math.max(0, Math.min(100, Number(s.brightness))))
                );
            }
            if (s.hs_color && Array.isArray(s.hs_color)) {
                const hue = Number(s.hs_color[0]) || 0;
                const saturation = (Number(s.hs_color[1]) || 0) / 100;
                const brightnessVal = (Number(s.brightness) || 0) / 100;
                props.push(makeProp('Alexa.ColorController', 'color', {
                    hue,
                    saturation,
                    brightness: brightnessVal
                }));
            }
            if (s.color_temp_kelvin) {
                props.push(
                    makeProp('Alexa.ColorTemperatureController', 'colorTemperatureInKelvin', Number(s.color_temp_kelvin))
                );
            }
            break;
        case 'switch':
        case 'automation':
        case 'script':
            props.push(makeProp('Alexa.PowerController', 'powerState', isOn ? 'ON' : 'OFF'));
            break;
        case 'fan':
            props.push(makeProp('Alexa.PowerController', 'powerState', isOn ? 'ON' : 'OFF'));
            if (s.percentage !== undefined) {
                props.push(
                    makeProp(
                        'Alexa.PercentageController',
                        'percentage',
                        Math.max(0, Math.min(100, Number(s.percentage))),
                        'Fan.Speed'
                    )
                );
            }
            break;
        case 'cover':
            props.push(
                makeProp(
                    'Alexa.RangeController',
                    'rangeValue',
                    Math.max(0, Math.min(100, Number(s.current_position ?? s.openPercent ?? 0))),
                    'Cover.Position'
                )
            );
            break;
        case 'valve':
            props.push(
                makeProp(
                    'Alexa.RangeController',
                    'rangeValue',
                    Math.max(0, Math.min(100, Number(s.current_position ?? s.openPercent ?? 0))),
                    'Valve.Position'
                )
            );
            break;
        case 'lock':
            props.push(makeProp('Alexa.LockController', 'lockState', s.locked ? 'LOCKED' : 'UNLOCKED'));
            break;
        case 'climate': {
            const mode = String(s.mode || s.hvac_mode || 'off').toUpperCase();
            const alexaMode = mode === 'HEAT_COOL' || mode === 'AUTO' ? 'AUTO' : mode === 'OFF' ? 'OFF' : mode;
            props.push(makeProp('Alexa.ThermostatController', 'thermostatMode', alexaMode));
            if (s.target_temp !== undefined) {
                props.push(
                    makeProp('Alexa.ThermostatController', 'targetSetpoint', {
                        value: Number(s.target_temp),
                        scale: 'CELSIUS'
                    })
                );
            }
            if (s.target_temp_low !== undefined) {
                props.push(
                    makeProp('Alexa.ThermostatController', 'lowerSetpoint', {
                        value: Number(s.target_temp_low),
                        scale: 'CELSIUS'
                    })
                );
            }
            if (s.target_temp_high !== undefined) {
                props.push(
                    makeProp('Alexa.ThermostatController', 'upperSetpoint', {
                        value: Number(s.target_temp_high),
                        scale: 'CELSIUS'
                    })
                );
            }
            if (s.current_temperature !== undefined) {
                props.push(
                    makeProp('Alexa.TemperatureSensor', 'temperature', {
                        value: Number(s.current_temperature),
                        scale: 'CELSIUS'
                    })
                );
            }
            break;
        }
        case 'water_heater':
            if (s.target_temp !== undefined) {
                props.push(
                    makeProp('Alexa.ThermostatController', 'targetSetpoint', {
                        value: Number(s.target_temp),
                        scale: 'CELSIUS'
                    })
                );
            }
            if (s.current_temperature !== undefined) {
                props.push(
                    makeProp('Alexa.TemperatureSensor', 'temperature', {
                        value: Number(s.current_temperature),
                        scale: 'CELSIUS'
                    })
                );
            }
            break;
        case 'media_player': {
            props.push(makeProp('Alexa.PowerController', 'powerState', isOn ? 'ON' : 'OFF'));
            if (s.volume !== undefined) {
                props.push(makeProp('Alexa.Speaker', 'volume', Math.max(0, Math.min(100, Number(s.volume)))));
            }
            if (s.muted !== undefined) {
                props.push(makeProp('Alexa.Speaker', 'muted', Boolean(s.muted)));
            }
            break;
        }
        case 'vacuum':
        case 'lawn_mower':
            props.push(makeProp('Alexa.PowerController', 'powerState', isOn ? 'ON' : 'OFF'));
            break;
        case 'humidifier':
            props.push(makeProp('Alexa.PowerController', 'powerState', isOn ? 'ON' : 'OFF'));
            if (s.humidity !== undefined) {
                props.push(
                    makeProp(
                        'Alexa.RangeController',
                        'rangeValue',
                        Math.max(0, Math.min(100, Number(s.humidity))),
                        'Humidifier.Humidity'
                    )
                );
            }
            break;
        case 'alarm_control_panel': {
            const armed = String(s.state || '').toLowerCase();
            let armState = 'DISARMED';
            if (armed.includes('home') || armed.includes('stay')) armState = 'ARMED_STAY';
            else if (armed.includes('away')) armState = 'ARMED_AWAY';
            else if (armed.includes('night')) armState = 'ARMED_NIGHT';
            props.push(makeProp('Alexa.SecurityPanelController', 'armState', armState));
            break;
        }
        case 'select':
        case 'input_select':
            if (s.option !== undefined) {
                props.push(makeProp('Alexa.ModeController', 'mode', String(s.option), 'Select.Option'));
            }
            break;
        default:
            break;
    }

    // Universal health
    const connectivity = online === 1 || online === true ? 'OK' : 'UNREACHABLE';
    props.push(makeProp('Alexa.EndpointHealth', 'connectivity', { value: connectivity }));

    return props;
}

// ── Directive → internal action mapping ──────────────────────────────────
//
// The internal action strings MUST match those in the Google fulfillment
// handler so apex-cloud-link can execute them unchanged.
function mapDirectiveToInternalAction(directive, entity) {
    const header = directive?.header || {};
    const namespace = header.namespace || '';
    const name = header.name || '';
    const payload = directive?.payload || {};
    const entityType = entity?.entity_type || 'switch';
    const statePayload = utils.parseJsonSafe(entity?.state_json, {}) || {};

    // ── Power ──
    if (namespace === 'Alexa.PowerController') {
        if (name === 'TurnOn' || name === 'TurnOff') {
            const on = name === 'TurnOn';
            const result = {
                action: 'set_on',
                payload: { on },
                responseProps: [makeProp('Alexa.PowerController', 'powerState', on ? 'ON' : 'OFF')]
            };
            if (entityType === 'light' && on) {
                const colorModes = Array.isArray(statePayload.supported_color_modes)
                    ? statePayload.supported_color_modes
                    : [];
                const hasBrightness = colorModes.length > 0 && !colorModes.every((m) => m === 'onoff');
                if (hasBrightness) {
                    const stored = Number(statePayload.brightness) || 0;
                    result.responseProps.push(
                        makeProp('Alexa.BrightnessController', 'brightness', stored > 0 ? stored : 100)
                    );
                }
            }
            return result;
        }
    }

    // ── Brightness ──
    if (namespace === 'Alexa.BrightnessController') {
        if (name === 'SetBrightness') {
            const brightness = Math.max(0, Math.min(100, Number(payload.brightness ?? 0)));
            const colorModes = Array.isArray(statePayload.supported_color_modes)
                ? statePayload.supported_color_modes
                : [];
            const hasBrightness = colorModes.length > 0 && !colorModes.every((m) => m === 'onoff');
            if (hasBrightness) {
                return {
                    action: 'set_brightness',
                    payload: { brightness },
                    responseProps: [
                        makeProp('Alexa.PowerController', 'powerState', 'ON'),
                        makeProp('Alexa.BrightnessController', 'brightness', brightness)
                    ]
                };
            }
            return {
                action: 'set_on',
                payload: { on: brightness > 0 },
                responseProps: [makeProp('Alexa.PowerController', 'powerState', brightness > 0 ? 'ON' : 'OFF')]
            };
        }
        if (name === 'AdjustBrightness') {
            const current = Number(statePayload.brightness) || 0;
            const delta = Number(payload.brightnessDelta ?? 0);
            const next = Math.max(0, Math.min(100, current + delta));
            return {
                action: 'set_brightness',
                payload: { brightness: next },
                responseProps: [makeProp('Alexa.BrightnessController', 'brightness', next)]
            };
        }
    }

    // ── Color ──
    if (namespace === 'Alexa.ColorController' && name === 'SetColor') {
        const c = payload.color || {};
        return {
            action: 'set_color_hs',
            payload: {
                hue: Number(c.hue ?? 0),
                saturation: Math.round(Number(c.saturation ?? 0) * 100),
                brightness_255: Math.round(Number(c.brightness ?? 1) * 255)
            },
            responseProps: [makeProp('Alexa.ColorController', 'color', c)]
        };
    }

    // ── Color temperature ──
    if (namespace === 'Alexa.ColorTemperatureController') {
        if (name === 'SetColorTemperature') {
            const kelvin = Number(payload.colorTemperatureInKelvin ?? 3000);
            return {
                action: 'set_color_temp',
                payload: { color_temp_kelvin: kelvin },
                responseProps: [makeProp('Alexa.ColorTemperatureController', 'colorTemperatureInKelvin', kelvin)]
            };
        }
    }

    // ── Percentage (fan speed) ──
    if (namespace === 'Alexa.PercentageController') {
        if (name === 'SetPercentage') {
            const percentage = Math.max(0, Math.min(100, Number(payload.percentage ?? 0)));
            return {
                action: 'set_fan_speed_percent',
                payload: { percentage },
                responseProps: [
                    makeProp('Alexa.PercentageController', 'percentage', percentage, 'Fan.Speed')
                ]
            };
        }
        if (name === 'AdjustPercentage') {
            const current = Number(statePayload.percentage) || 0;
            const delta = Number(payload.percentageDelta ?? 0);
            const next = Math.max(0, Math.min(100, current + delta));
            return {
                action: 'set_fan_speed_percent',
                payload: { percentage: next },
                responseProps: [makeProp('Alexa.PercentageController', 'percentage', next, 'Fan.Speed')]
            };
        }
    }

    // ── Range controller (covers, valves, humidifier) ──
    if (namespace === 'Alexa.RangeController') {
        const instance = header.instance || '';
        if (name === 'SetRangeValue') {
            const rangeValue = Math.max(0, Math.min(100, Number(payload.rangeValue ?? 0)));
            if (instance === 'Cover.Position') {
                return {
                    action: 'set_open_percent',
                    payload: { openPercent: rangeValue },
                    responseProps: [makeProp('Alexa.RangeController', 'rangeValue', rangeValue, 'Cover.Position')]
                };
            }
            if (instance === 'Valve.Position') {
                const sf = Number(statePayload.supported_features) || 0;
                const hasSetPosition = (sf & 4) !== 0;
                if (hasSetPosition) {
                    return {
                        action: 'set_valve_position',
                        payload: { openPercent: rangeValue },
                        responseProps: [
                            makeProp('Alexa.RangeController', 'rangeValue', rangeValue, 'Valve.Position')
                        ]
                    };
                }
                return {
                    action: 'set_valve_open_close',
                    payload: { open: rangeValue > 0 },
                    responseProps: [
                        makeProp('Alexa.RangeController', 'rangeValue', rangeValue > 0 ? 100 : 0, 'Valve.Position')
                    ]
                };
            }
            if (instance === 'Humidifier.Humidity') {
                return {
                    action: 'set_humidity',
                    payload: { humidity: rangeValue },
                    responseProps: [
                        makeProp('Alexa.RangeController', 'rangeValue', rangeValue, 'Humidifier.Humidity')
                    ]
                };
            }
        }
    }

    // ── Lock ──
    if (namespace === 'Alexa.LockController') {
        if (name === 'Lock') {
            return {
                action: 'set_lock',
                payload: { lock: true },
                responseProps: [makeProp('Alexa.LockController', 'lockState', 'LOCKED')]
            };
        }
        if (name === 'Unlock') {
            return {
                action: 'set_lock',
                payload: { lock: false },
                responseProps: [makeProp('Alexa.LockController', 'lockState', 'UNLOCKED')]
            };
        }
    }

    // ── Thermostat ──
    if (namespace === 'Alexa.ThermostatController') {
        if (name === 'SetTargetTemperature') {
            const setp = payload.targetSetpoint?.value !== undefined ? Number(payload.targetSetpoint.value) : null;
            const lower = payload.lowerSetpoint?.value !== undefined ? Number(payload.lowerSetpoint.value) : null;
            const upper = payload.upperSetpoint?.value !== undefined ? Number(payload.upperSetpoint.value) : null;

            if (lower !== null && upper !== null) {
                return {
                    action: 'set_thermostat_setpoint_range',
                    payload: { heat_setpoint: lower, cool_setpoint: upper },
                    responseProps: [
                        makeProp('Alexa.ThermostatController', 'lowerSetpoint', { value: lower, scale: 'CELSIUS' }),
                        makeProp('Alexa.ThermostatController', 'upperSetpoint', { value: upper, scale: 'CELSIUS' })
                    ]
                };
            }
            if (setp !== null) {
                if (entityType === 'water_heater') {
                    return {
                        action: 'set_water_heater_temperature',
                        payload: { temperature: setp },
                        responseProps: [
                            makeProp('Alexa.ThermostatController', 'targetSetpoint', {
                                value: setp,
                                scale: 'CELSIUS'
                            })
                        ]
                    };
                }
                return {
                    action: 'set_thermostat_setpoint',
                    payload: { setpoint: setp },
                    responseProps: [
                        makeProp('Alexa.ThermostatController', 'targetSetpoint', {
                            value: setp,
                            scale: 'CELSIUS'
                        })
                    ]
                };
            }
        }
        if (name === 'SetThermostatMode') {
            const modeValue = String(payload.thermostatMode?.value || payload.thermostatMode || 'off').toLowerCase();
            const mapped =
                {
                    auto: 'heat_cool',
                    heat: 'heat',
                    cool: 'cool',
                    eco: 'eco',
                    off: 'off'
                }[modeValue] || 'off';
            return {
                action: 'set_thermostat_mode',
                payload: { mode: mapped },
                responseProps: [makeProp('Alexa.ThermostatController', 'thermostatMode', modeValue.toUpperCase())]
            };
        }
    }

    // ── Speaker ──
    if (namespace === 'Alexa.Speaker') {
        if (name === 'SetVolume') {
            const volume = Math.max(0, Math.min(100, Number(payload.volume ?? 0)));
            return {
                action: 'set_volume',
                payload: { volume },
                responseProps: [makeProp('Alexa.Speaker', 'volume', volume)]
            };
        }
        if (name === 'AdjustVolume') {
            const current = Number(statePayload.volume) || 0;
            const delta = Number(payload.volume ?? 0);
            const next = Math.max(0, Math.min(100, current + delta));
            return {
                action: 'set_volume',
                payload: { volume: next },
                responseProps: [makeProp('Alexa.Speaker', 'volume', next)]
            };
        }
        if (name === 'SetMute') {
            const muted = Boolean(payload.mute);
            return {
                action: 'set_mute',
                payload: { muted },
                responseProps: [makeProp('Alexa.Speaker', 'muted', muted)]
            };
        }
    }

    // ── Playback ──
    if (namespace === 'Alexa.PlaybackController') {
        const map = { Play: 'media_resume', Pause: 'media_pause', Stop: 'media_stop', Next: 'media_next', Previous: 'media_previous' };
        if (map[name]) {
            return { action: map[name], payload: {}, responseProps: [] };
        }
    }

    // ── Scene ──
    if (namespace === 'Alexa.SceneController') {
        if (name === 'Activate') {
            return {
                action: 'activate_scene',
                payload: { deactivate: false },
                responseProps: [],
                sceneActivation: true
            };
        }
        if (name === 'Deactivate') {
            return {
                action: 'activate_scene',
                payload: { deactivate: true },
                responseProps: [],
                sceneActivation: true,
                deactivation: true
            };
        }
    }

    // ── Security panel ──
    if (namespace === 'Alexa.SecurityPanelController') {
        if (name === 'Arm') {
            const armState = String(payload.armState || 'ARMED_AWAY');
            const level = armState.replace('ARMED_', '').toLowerCase();
            return {
                action: 'arm_disarm',
                payload: { arm: true, arm_level: level },
                responseProps: [makeProp('Alexa.SecurityPanelController', 'armState', armState)]
            };
        }
        if (name === 'Disarm') {
            return {
                action: 'arm_disarm',
                payload: { arm: false, arm_level: '' },
                responseProps: [makeProp('Alexa.SecurityPanelController', 'armState', 'DISARMED')]
            };
        }
    }

    // ── Mode controller (select) ──
    if (namespace === 'Alexa.ModeController') {
        if (name === 'SetMode') {
            return {
                action: 'set_select_option',
                payload: { option: String(payload.mode || '') },
                responseProps: [makeProp('Alexa.ModeController', 'mode', String(payload.mode || ''), 'Select.Option')]
            };
        }
    }

    // ── Camera stream ──
    if (namespace === 'Alexa.CameraStreamController') {
        if (name === 'InitializeCameraStreams') {
            return {
                action: 'get_camera_stream',
                payload: {},
                responseProps: [],
                cameraStream: true
            };
        }
    }

    return null;
}

module.exports = {
    ENTITY_TYPE_TO_CATEGORY,
    resolveAlexaCapabilities,
    buildAlexaEndpoint,
    buildAlexaProperties,
    mapDirectiveToInternalAction,
    makeProp,
    encodeAlexaEndpointId,
    decodeAlexaEndpointId
};
