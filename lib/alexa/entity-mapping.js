const utils = require('../utils');

const sanitizeString = utils.sanitizeString;
const sanitizeEntityId = utils.sanitizeEntityId;
const parseJsonSafe = utils.parseJsonSafe;

// ── Domain vocabulary (mirrors google-home/entity-mapping.js) ─────────────

const DOMAIN_TO_ENTITY_TYPE = {
    light: 'light',
    switch: 'switch',
    input_boolean: 'input_boolean',
    automation: 'automation',
    script: 'script',
    fan: 'fan',
    cover: 'cover',
    lock: 'lock',
    climate: 'climate',
    media_player: 'media_player',
    scene: 'scene',
    button: 'button',
    vacuum: 'vacuum',
    sensor: 'sensor'
};

const ENTITY_TYPE_TO_DISPLAY_CATEGORY = {
    switch: 'SWITCH',
    input_boolean: 'SWITCH',
    automation: 'SWITCH',
    script: 'SWITCH',
    light: 'LIGHT',
    fan: 'FAN',
    cover: 'INTERIOR_BLIND',
    lock: 'SMARTLOCK',
    climate: 'THERMOSTAT',
    media_player: 'TV',
    scene: 'SCENE_TRIGGER',
    button: 'SCENE_TRIGGER',
    vacuum: 'VACUUM_CLEANER',
    sensor: 'TEMPERATURE_SENSOR'
};

function normalizeAlexaEntityType(entityType) {
    const normalized = sanitizeString(entityType, 64);
    if (!normalized) {
        return 'switch';
    }
    return normalized.toLowerCase();
}

function mapAlexaDomainToEntityType(entityId, fallbackType = 'switch') {
    const normalizedEntityId = sanitizeEntityId(entityId) || '';
    const domain = normalizedEntityId.includes('.') ? normalizedEntityId.split('.')[0] : '';
    return DOMAIN_TO_ENTITY_TYPE[domain] || fallbackType;
}

function parseEntityContext(statePayload) {
    const sf = Number(statePayload?.supported_features) || 0;
    const dc = statePayload?.device_class || null;
    const colorModes = Array.isArray(statePayload?.supported_color_modes) ? statePayload.supported_color_modes : [];
    const hasFeature = (bit) => (sf & bit) !== 0;
    return { sf, dc, colorModes, hasFeature };
}

// ── Effective-online composite predicate ──────────────────────────────────

function withEffectiveAlexaOnline(entity) {
    if (!entity) {
        return entity;
    }

    const effectiveOnline = utils.isEntityEffectivelyOnline(entity);
    return {
        ...entity,
        online: effectiveOnline ? 1 : 0,
        effective_online: effectiveOnline ? 1 : 0,
        device_online: utils.isDeviceOnline(entity.last_seen_at) ? 1 : 0,
        entity_fresh: utils.isEntityFresh(entity.entity_last_seen_at || entity.updated_at) ? 1 : 0
    };
}

function isEntityAlexaReachable(entity) {
    return Boolean(withEffectiveAlexaOnline(entity).effective_online);
}

// ── Capability-interface helpers ──────────────────────────────────────────

function cap(iface, version, propName, options = {}) {
    const base = {
        type: 'AlexaInterface',
        interface: iface,
        version: version || '3'
    };
    if (propName) {
        base.properties = {
            supported: [{ name: propName }],
            proactivelyReported: options.proactivelyReported !== false,
            retrievable: options.retrievable !== false
        };
    }
    if (options.instance) {
        base.instance = options.instance;
    }
    if (options.capabilityResources) {
        base.capabilityResources = options.capabilityResources;
    }
    if (options.configuration) {
        base.configuration = options.configuration;
    }
    if (options.semantics) {
        base.semantics = options.semantics;
    }
    if (options.supportedOperations) {
        base.supportedOperations = options.supportedOperations;
    }
    return base;
}

function capAlexaBase() {
    return { type: 'AlexaInterface', interface: 'Alexa', version: '3' };
}

function capEndpointHealth() {
    return cap('Alexa.EndpointHealth', '3.2', 'connectivity');
}

function labelResource(label) {
    return {
        friendlyNames: [
            {
                '@type': 'text',
                value: { text: label, locale: 'en-US' }
            }
        ]
    };
}

// ── Per-domain capability builders ────────────────────────────────────────

function lightCapabilities(statePayload) {
    const { colorModes } = parseEntityContext(statePayload);
    const caps = [capAlexaBase(), cap('Alexa.PowerController', '3', 'powerState')];
    const hasBrightness = colorModes.length > 0 && !colorModes.every((m) => m === 'onoff');
    if (hasBrightness) {
        caps.push(cap('Alexa.BrightnessController', '3', 'brightness'));
    }
    const hasColor = colorModes.some((m) => ['hs', 'xy', 'rgb', 'rgbw', 'rgbww'].includes(m));
    const hasColorTemp = colorModes.includes('color_temp');
    if (hasColor) {
        caps.push(cap('Alexa.ColorController', '3', 'color'));
    }
    if (hasColorTemp) {
        caps.push(cap('Alexa.ColorTemperatureController', '3', 'colorTemperatureInKelvin'));
    }
    caps.push(capEndpointHealth());
    return caps;
}

function fanCapabilities(statePayload) {
    const { sf } = parseEntityContext(statePayload);
    const caps = [capAlexaBase(), cap('Alexa.PowerController', '3', 'powerState')];
    caps.push(
        cap('Alexa.RangeController', '3', 'rangeValue', {
            instance: 'Fan.Speed',
            capabilityResources: labelResource('Speed'),
            configuration: {
                supportedRange: { minimumValue: 0, maximumValue: 100, precision: 10 },
                unitOfMeasure: 'Alexa.Unit.Percent'
            }
        })
    );
    // sf is referenced to mirror google-home's feature-sniffing shape; preset
    // modes are translated through RangeController at directive time.
    void sf;
    caps.push(capEndpointHealth());
    return caps;
}

function coverCapabilities(statePayload) {
    const { hasFeature } = parseEntityContext(statePayload);
    const hasSetPosition = hasFeature(4);
    const caps = [capAlexaBase()];
    if (hasSetPosition) {
        caps.push(
            cap('Alexa.RangeController', '3', 'rangeValue', {
                instance: 'Cover.Position',
                capabilityResources: labelResource('Position'),
                configuration: {
                    supportedRange: { minimumValue: 0, maximumValue: 100, precision: 1 },
                    unitOfMeasure: 'Alexa.Unit.Percent'
                }
            })
        );
    } else {
        caps.push(
            cap('Alexa.ModeController', '3', 'mode', {
                instance: 'Cover.Position',
                capabilityResources: labelResource('Position'),
                configuration: {
                    ordered: false,
                    supportedModes: [
                        { value: 'Position.Open', modeResources: labelResource('Open') },
                        { value: 'Position.Closed', modeResources: labelResource('Closed') }
                    ]
                }
            })
        );
    }
    caps.push(capEndpointHealth());
    return caps;
}

function lockCapabilities() {
    return [capAlexaBase(), cap('Alexa.LockController', '3', 'lockState'), capEndpointHealth()];
}

function climateCapabilities(statePayload) {
    const rawModes = Array.isArray(statePayload?.hvac_modes) ? statePayload.hvac_modes : [];
    const supportedModes = rawModes
        .map((m) => translateHaHvacModeToAlexa(m))
        .filter(Boolean)
        .filter((v, i, a) => a.indexOf(v) === i);
    const thermostat = cap('Alexa.ThermostatController', '3.2', 'targetSetpoint', {
        configuration: {
            supportsScheduling: false,
            supportedModes: supportedModes.length > 0 ? supportedModes : ['OFF', 'HEAT', 'COOL', 'AUTO']
        }
    });
    thermostat.properties.supported = [
        { name: 'targetSetpoint' },
        { name: 'lowerSetpoint' },
        { name: 'upperSetpoint' },
        { name: 'thermostatMode' }
    ];
    return [
        capAlexaBase(),
        thermostat,
        cap('Alexa.TemperatureSensor', '3', 'temperature'),
        capEndpointHealth()
    ];
}

function mediaPlayerCapabilities(statePayload) {
    const { hasFeature } = parseEntityContext(statePayload);
    const caps = [capAlexaBase(), cap('Alexa.PowerController', '3', 'powerState')];
    caps.push(cap('Alexa.Speaker', '3', 'volume'));
    caps.push(cap('Alexa.Speaker', '3', 'muted'));
    const ops = [];
    if (hasFeature(16384)) ops.push('Play');
    if (hasFeature(1)) ops.push('Pause');
    if (hasFeature(4096)) ops.push('Stop');
    if (hasFeature(32)) ops.push('Next');
    if (hasFeature(16)) ops.push('Previous');
    caps.push({
        type: 'AlexaInterface',
        interface: 'Alexa.PlaybackController',
        version: '3',
        supportedOperations: ops.length > 0 ? ops : ['Play', 'Pause', 'Stop']
    });
    caps.push(capEndpointHealth());
    return caps;
}

function sceneCapabilities() {
    return [
        capAlexaBase(),
        {
            type: 'AlexaInterface',
            interface: 'Alexa.SceneController',
            version: '3',
            supportsDeactivation: false,
            proactivelyReported: false
        },
        capEndpointHealth()
    ];
}

function vacuumCapabilities() {
    return [
        capAlexaBase(),
        cap('Alexa.PowerController', '3', 'powerState'),
        cap('Alexa.ToggleController', '3', 'toggleState', {
            instance: 'Vacuum.Pause',
            capabilityResources: labelResource('Pause')
        }),
        capEndpointHealth()
    ];
}

function switchCapabilities() {
    return [capAlexaBase(), cap('Alexa.PowerController', '3', 'powerState'), capEndpointHealth()];
}

function temperatureSensorCapabilities() {
    return [capAlexaBase(), cap('Alexa.TemperatureSensor', '3', 'temperature'), capEndpointHealth()];
}

// ── Discovery endpoint JSON ───────────────────────────────────────────────

function buildAlexaDiscoveryEndpoint(entity) {
    const statePayload = parseJsonSafe(entity?.state_json, {}) || {};
    const entityType = normalizeAlexaEntityType(entity?.entity_type);
    const displayCategory = ENTITY_TYPE_TO_DISPLAY_CATEGORY[entityType] || 'OTHER';

    let capabilities;
    switch (entityType) {
        case 'light':
            capabilities = lightCapabilities(statePayload);
            break;
        case 'fan':
            capabilities = fanCapabilities(statePayload);
            break;
        case 'cover':
            capabilities = coverCapabilities(statePayload);
            break;
        case 'lock':
            capabilities = lockCapabilities();
            break;
        case 'climate':
            capabilities = climateCapabilities(statePayload);
            break;
        case 'media_player':
            capabilities = mediaPlayerCapabilities(statePayload);
            break;
        case 'scene':
        case 'button':
            capabilities = sceneCapabilities();
            break;
        case 'vacuum':
            capabilities = vacuumCapabilities();
            break;
        case 'sensor':
            capabilities = temperatureSensorCapabilities();
            break;
        case 'switch':
        case 'input_boolean':
        case 'automation':
        case 'script':
        default:
            capabilities = switchCapabilities();
            break;
    }

    const friendlyName = sanitizeString(entity?.display_name, 120) || entity?.entity_id || 'Device';
    const manufacturerName = sanitizeString(statePayload._manufacturer, 120) || 'Apex Infosys';
    const model = sanitizeString(statePayload._model, 120) || entityType || 'generic';
    const swVersion = sanitizeString(statePayload._sw_version, 60) || '';

    const endpoint = {
        endpointId: entity?.entity_id,
        manufacturerName,
        description: `${model} via Apex Cloud Link`,
        friendlyName,
        displayCategories: [displayCategory],
        cookie: {
            entity_id: String(entity?.entity_id || ''),
            device_id: String(entity?.device_id || '')
        },
        capabilities
    };

    const additional = {
        manufacturer: manufacturerName,
        model,
        serialNumber: String(entity?.entity_id || ''),
        firmwareVersion: swVersion || 'apex-cloud-link',
        softwareVersion: swVersion || 'apex-cloud-link',
        customIdentifier: String(entity?.entity_id || '')
    };
    endpoint.additionalAttributes = additional;

    return endpoint;
}

// ── State translators → context.properties[] for ReportState ──────────────

function nowIso() {
    return new Date().toISOString();
}

function property(iface, name, value, extra = {}) {
    return {
        namespace: iface,
        name,
        value,
        timeOfSample: nowIso(),
        uncertaintyInMilliseconds: 500,
        ...extra
    };
}

function instanceProperty(iface, instance, name, value) {
    return {
        namespace: iface,
        instance,
        name,
        value,
        timeOfSample: nowIso(),
        uncertaintyInMilliseconds: 500
    };
}

function endpointHealthProperty(reachable) {
    return property('Alexa.EndpointHealth', 'connectivity', {
        value: reachable ? 'OK' : 'UNREACHABLE'
    });
}

function translateHaHvacModeToAlexa(mode) {
    if (!mode) return null;
    const m = String(mode).toLowerCase();
    if (m === 'heat') return 'HEAT';
    if (m === 'cool') return 'COOL';
    if (m === 'heat_cool' || m === 'heatcool' || m === 'auto') return 'AUTO';
    if (m === 'off') return 'OFF';
    if (m === 'fan_only' || m === 'fan-only') return 'OFF';
    if (m === 'dry') return 'ECO';
    return 'OFF';
}

function translateAlexaThermostatModeToHa(mode) {
    if (!mode) return null;
    const m = String(mode).toUpperCase();
    if (m === 'HEAT') return 'heat';
    if (m === 'COOL') return 'cool';
    if (m === 'AUTO') return 'heat_cool';
    if (m === 'OFF') return 'off';
    if (m === 'ECO') return 'dry';
    return 'off';
}

function translateAlexaEntityState(entity) {
    const statePayload = parseJsonSafe(entity?.state_json, {}) || {};
    const { colorModes, hasFeature } = parseEntityContext(statePayload);
    const entityType = normalizeAlexaEntityType(entity?.entity_type);
    const reachable = isEntityAlexaReachable(entity);
    const props = [];

    switch (entityType) {
        case 'switch':
        case 'input_boolean':
        case 'automation':
        case 'script': {
            props.push(property('Alexa.PowerController', 'powerState', statePayload.on ? 'ON' : 'OFF'));
            break;
        }
        case 'light': {
            const on = Boolean(statePayload.on);
            props.push(property('Alexa.PowerController', 'powerState', on ? 'ON' : 'OFF'));
            const hasBrightness = colorModes.length > 0 && !colorModes.every((m) => m === 'onoff');
            if (hasBrightness) {
                const rawBrightness = Number.isFinite(Number(statePayload.brightness))
                    ? Math.max(0, Math.min(100, Math.round(Number(statePayload.brightness))))
                    : 0;
                const brightness = on && rawBrightness === 0 ? 100 : rawBrightness;
                props.push(property('Alexa.BrightnessController', 'brightness', brightness));
            }
            const hasColor = colorModes.some((m) => ['hs', 'xy', 'rgb', 'rgbw', 'rgbww'].includes(m));
            const hasColorTemp = colorModes.includes('color_temp');
            if (hasColor && Array.isArray(statePayload.hs_color) && statePayload.hs_color.length >= 2) {
                const h = Number(statePayload.hs_color[0]) || 0;
                const s = Number(statePayload.hs_color[1]) || 0;
                props.push(
                    property('Alexa.ColorController', 'color', {
                        hue: h,
                        saturation: Math.max(0, Math.min(1, s / 100)),
                        brightness: Math.max(0, Math.min(1, (Number(statePayload.brightness) || 100) / 100))
                    })
                );
            }
            if (hasColorTemp && statePayload.color_temp_kelvin) {
                props.push(
                    property(
                        'Alexa.ColorTemperatureController',
                        'colorTemperatureInKelvin',
                        Math.max(1000, Math.min(10000, Number(statePayload.color_temp_kelvin) || 3000))
                    )
                );
            }
            break;
        }
        case 'fan': {
            const on = Boolean(statePayload.on);
            props.push(property('Alexa.PowerController', 'powerState', on ? 'ON' : 'OFF'));
            const percentage = Number(statePayload.percentage);
            const pct = Number.isFinite(percentage) ? Math.max(0, Math.min(100, Math.round(percentage))) : on ? 50 : 0;
            props.push(instanceProperty('Alexa.RangeController', 'Fan.Speed', 'rangeValue', pct));
            break;
        }
        case 'cover': {
            const openPercent = Number(statePayload.openPercent ?? 0);
            const pct = Math.max(0, Math.min(100, Math.round(openPercent)));
            if (hasFeature(4)) {
                props.push(instanceProperty('Alexa.RangeController', 'Cover.Position', 'rangeValue', pct));
            } else {
                props.push(
                    instanceProperty(
                        'Alexa.ModeController',
                        'Cover.Position',
                        'mode',
                        pct > 0 ? 'Position.Open' : 'Position.Closed'
                    )
                );
            }
            break;
        }
        case 'lock': {
            const locked = Boolean(statePayload.isLocked);
            props.push(property('Alexa.LockController', 'lockState', locked ? 'LOCKED' : 'UNLOCKED'));
            break;
        }
        case 'climate': {
            const unit = statePayload.temperature_unit === 'F' ? 'FAHRENHEIT' : 'CELSIUS';
            const target =
                statePayload.target_temperature != null ? Number(statePayload.target_temperature) : null;
            const ambient =
                statePayload.ambient_temperature != null ? Number(statePayload.ambient_temperature) : null;
            const lo = statePayload.target_temp_low != null ? Number(statePayload.target_temp_low) : null;
            const hi = statePayload.target_temp_high != null ? Number(statePayload.target_temp_high) : null;
            const mode = translateHaHvacModeToAlexa(statePayload.mode);

            if (Number.isFinite(target)) {
                props.push(
                    property('Alexa.ThermostatController', 'targetSetpoint', { value: target, scale: unit })
                );
            }
            if (Number.isFinite(lo)) {
                props.push(property('Alexa.ThermostatController', 'lowerSetpoint', { value: lo, scale: unit }));
            }
            if (Number.isFinite(hi)) {
                props.push(property('Alexa.ThermostatController', 'upperSetpoint', { value: hi, scale: unit }));
            }
            if (mode) {
                props.push(property('Alexa.ThermostatController', 'thermostatMode', mode));
            }
            if (Number.isFinite(ambient)) {
                props.push(
                    property('Alexa.TemperatureSensor', 'temperature', { value: ambient, scale: unit })
                );
            }
            break;
        }
        case 'media_player': {
            props.push(property('Alexa.PowerController', 'powerState', statePayload.on ? 'ON' : 'OFF'));
            const volume = Number(statePayload.volume);
            props.push(
                property('Alexa.Speaker', 'volume', Number.isFinite(volume) ? Math.max(0, Math.min(100, Math.round(volume))) : 0)
            );
            props.push(property('Alexa.Speaker', 'muted', Boolean(statePayload.muted)));
            break;
        }
        case 'scene':
        case 'button': {
            // Scene endpoints have no queryable state; ReportState is a no-op.
            break;
        }
        case 'vacuum': {
            props.push(property('Alexa.PowerController', 'powerState', statePayload.on ? 'ON' : 'OFF'));
            props.push(
                instanceProperty(
                    'Alexa.ToggleController',
                    'Vacuum.Pause',
                    'toggleState',
                    statePayload.isPaused ? 'ON' : 'OFF'
                )
            );
            break;
        }
        case 'sensor': {
            const unit = /F/.test(statePayload.unit_of_measurement || '') ? 'FAHRENHEIT' : 'CELSIUS';
            const temp = Number(statePayload.temperature != null ? statePayload.temperature : statePayload.value);
            props.push(
                property('Alexa.TemperatureSensor', 'temperature', {
                    value: Number.isFinite(temp) ? temp : 0,
                    scale: unit
                })
            );
            break;
        }
        default:
            break;
    }

    props.push(endpointHealthProperty(reachable));
    return props;
}

// ── Directive → normalized action/payload stored in alexa_command_queue ───
//
// Returns { action, payload } or null if the directive cannot be translated.
// The addon side consumes { action, payload } and translates to HA services.

function translateAlexaDirective(directive, directivePayload) {
    const ns = directive?.header?.namespace;
    const name = directive?.header?.name;
    const payload = directivePayload || directive?.payload || {};

    if (!ns || !name) {
        return null;
    }

    if (ns === 'Alexa.PowerController') {
        return { action: 'power.set', payload: { value: name === 'TurnOn' ? 'on' : 'off' } };
    }

    if (ns === 'Alexa.BrightnessController') {
        if (name === 'SetBrightness') {
            return { action: 'brightness.set', payload: { value: Number(payload.brightness) || 0 } };
        }
        if (name === 'AdjustBrightness') {
            return { action: 'brightness.adjust', payload: { delta: Number(payload.brightnessDelta) || 0 } };
        }
    }

    if (ns === 'Alexa.ColorController' && name === 'SetColor') {
        return {
            action: 'color.set',
            payload: {
                hue: Number(payload.color?.hue) || 0,
                saturation: Number(payload.color?.saturation) || 0,
                brightness: Number(payload.color?.brightness) || 1
            }
        };
    }

    if (ns === 'Alexa.ColorTemperatureController') {
        if (name === 'SetColorTemperature') {
            return {
                action: 'color_temperature.set',
                payload: { kelvin: Number(payload.colorTemperatureInKelvin) || 3000 }
            };
        }
        if (name === 'DecreaseColorTemperature' || name === 'IncreaseColorTemperature') {
            return {
                action: 'color_temperature.adjust',
                payload: { direction: name === 'IncreaseColorTemperature' ? 'up' : 'down' }
            };
        }
    }

    if (ns === 'Alexa.RangeController') {
        const instance = directive?.header?.instance || directive?.instance;
        if (name === 'SetRangeValue') {
            return {
                action: 'range.set',
                payload: { instance, value: Number(payload.rangeValue) || 0 }
            };
        }
        if (name === 'AdjustRangeValue') {
            return {
                action: 'range.adjust',
                payload: { instance, delta: Number(payload.rangeValueDelta) || 0 }
            };
        }
    }

    if (ns === 'Alexa.ModeController') {
        const instance = directive?.header?.instance || directive?.instance;
        return { action: 'mode.set', payload: { instance, value: String(payload.mode || '') } };
    }

    if (ns === 'Alexa.ToggleController') {
        const instance = directive?.header?.instance || directive?.instance;
        return {
            action: 'toggle.set',
            payload: { instance, value: name === 'TurnOn' ? 'on' : 'off' }
        };
    }

    if (ns === 'Alexa.LockController') {
        return { action: 'lock.set', payload: { value: name === 'Lock' ? 'lock' : 'unlock' } };
    }

    if (ns === 'Alexa.ThermostatController') {
        if (name === 'SetTargetTemperature') {
            return {
                action: 'thermostat.setpoint',
                payload: {
                    target:
                        payload.targetSetpoint != null
                            ? { value: Number(payload.targetSetpoint.value), scale: payload.targetSetpoint.scale }
                            : null,
                    lower:
                        payload.lowerSetpoint != null
                            ? { value: Number(payload.lowerSetpoint.value), scale: payload.lowerSetpoint.scale }
                            : null,
                    upper:
                        payload.upperSetpoint != null
                            ? { value: Number(payload.upperSetpoint.value), scale: payload.upperSetpoint.scale }
                            : null
                }
            };
        }
        if (name === 'AdjustTargetTemperature') {
            return {
                action: 'thermostat.adjust',
                payload: {
                    delta: Number(payload.targetSetpointDelta?.value) || 0,
                    scale: payload.targetSetpointDelta?.scale || 'CELSIUS'
                }
            };
        }
        if (name === 'SetThermostatMode') {
            return {
                action: 'thermostat.mode',
                payload: { value: translateAlexaThermostatModeToHa(payload.thermostatMode?.value) }
            };
        }
    }

    if (ns === 'Alexa.Speaker') {
        if (name === 'SetVolume') {
            return { action: 'volume.set', payload: { value: Number(payload.volume) || 0 } };
        }
        if (name === 'AdjustVolume') {
            return { action: 'volume.adjust', payload: { delta: Number(payload.volume) || 0 } };
        }
        if (name === 'SetMute') {
            return { action: 'mute.set', payload: { value: Boolean(payload.mute) } };
        }
    }

    if (ns === 'Alexa.PlaybackController') {
        return { action: 'playback.' + String(name || '').toLowerCase(), payload: {} };
    }

    if (ns === 'Alexa.SceneController') {
        if (name === 'Activate') {
            return { action: 'scene.activate', payload: {} };
        }
        if (name === 'Deactivate') {
            return { action: 'scene.deactivate', payload: {} };
        }
    }

    return null;
}

// ── Capability listing helper used by Discovery-time gating ───────────────

function supportsAlexaDirectiveForEntityType(entityType, namespace) {
    const t = normalizeAlexaEntityType(entityType);
    const allowed = {
        switch: new Set(['Alexa.PowerController']),
        input_boolean: new Set(['Alexa.PowerController']),
        automation: new Set(['Alexa.PowerController']),
        script: new Set(['Alexa.PowerController', 'Alexa.SceneController']),
        light: new Set([
            'Alexa.PowerController',
            'Alexa.BrightnessController',
            'Alexa.ColorController',
            'Alexa.ColorTemperatureController'
        ]),
        fan: new Set(['Alexa.PowerController', 'Alexa.RangeController']),
        cover: new Set(['Alexa.RangeController', 'Alexa.ModeController']),
        lock: new Set(['Alexa.LockController']),
        climate: new Set(['Alexa.ThermostatController', 'Alexa.TemperatureSensor']),
        media_player: new Set(['Alexa.PowerController', 'Alexa.Speaker', 'Alexa.PlaybackController']),
        scene: new Set(['Alexa.SceneController']),
        button: new Set(['Alexa.SceneController']),
        vacuum: new Set(['Alexa.PowerController', 'Alexa.ToggleController']),
        sensor: new Set(['Alexa.TemperatureSensor'])
    };
    const set = allowed[t] || allowed.switch;
    return set.has(namespace);
}

module.exports = {
    DOMAIN_TO_ENTITY_TYPE,
    ENTITY_TYPE_TO_DISPLAY_CATEGORY,
    normalizeAlexaEntityType,
    mapAlexaDomainToEntityType,
    withEffectiveAlexaOnline,
    isEntityAlexaReachable,
    buildAlexaDiscoveryEndpoint,
    translateAlexaEntityState,
    translateAlexaDirective,
    translateHaHvacModeToAlexa,
    translateAlexaThermostatModeToHa,
    supportsAlexaDirectiveForEntityType
};
