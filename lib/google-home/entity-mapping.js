const utils = require('../utils');
const config = require('../config');

const sanitizeString = utils.sanitizeString;
const sanitizeEntityId = utils.sanitizeEntityId;
const parseJsonSafe = utils.parseJsonSafe;

/**
 * Injectable reference for hasGoogleHomegraphCredentials().
 * Must be set by the caller (e.g. server.js) before buildGoogleDeviceObject is used.
 */
let _hasGoogleHomegraphCredentials = () => false;

function setHasGoogleHomegraphCredentials(fn) {
    _hasGoogleHomegraphCredentials = fn;
}

// --- Shared Helpers ---

function parseEntityContext(statePayload) {
    const sf = Number(statePayload?.supported_features) || 0;
    const dc = statePayload?.device_class || null;
    const colorModes = Array.isArray(statePayload?.supported_color_modes) ? statePayload.supported_color_modes : [];
    const hasFeature = (bit) => (sf & bit) !== 0;
    return { sf, dc, colorModes, hasFeature };
}

function buildModesAttribute(name, synonyms, settings) {
    return {
        name,
        name_values: [{ name_synonym: synonyms, lang: 'en' }],
        settings: settings.map((s) => ({
            setting_name: s,
            setting_values: [{ setting_synonym: [s], lang: 'en' }]
        })),
        ordered: false
    };
}

// --- Lookup Tables & Registries ---

const DOMAIN_TO_ENTITY_TYPE = {
    light: 'light',
    switch: 'switch',
    input_boolean: 'switch',
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
    humidifier: 'humidifier',
    alarm_control_panel: 'alarm_control_panel',
    water_heater: 'water_heater',
    binary_sensor: 'binary_sensor',
    sensor: 'sensor',
    camera: 'camera',
    group: 'group',
    input_button: 'input_button',
    input_select: 'input_select',
    select: 'select',
    valve: 'valve',
    lawn_mower: 'lawn_mower',
    event: 'event'
};

const COVER_DEVICE_CLASS_MAP = {
    garage: 'action.devices.types.GARAGE',
    door: 'action.devices.types.DOOR',
    gate: 'action.devices.types.GATE',
    window: 'action.devices.types.WINDOW',
    curtain: 'action.devices.types.CURTAIN',
    awning: 'action.devices.types.AWNING',
    shutter: 'action.devices.types.SHUTTER'
};

const SENSOR_DEVICE_CLASS_REGISTRY = {
    pm25: { name: 'PM2.5', unit: 'MICROGRAMS_PER_CUBIC_METER', maxValue: 1000 },
    pm10: { name: 'PM10', unit: 'MICROGRAMS_PER_CUBIC_METER', maxValue: 1000 },
    carbon_dioxide: { name: 'CarbonDioxideLevel', unit: 'PARTS_PER_MILLION', maxValue: 5000 },
    co2: { name: 'CarbonDioxideLevel', unit: 'PARTS_PER_MILLION', maxValue: 5000 },
    carbon_monoxide: { name: 'CarbonMonoxideLevel', unit: 'PARTS_PER_MILLION', maxValue: 1000 },
    co: { name: 'CarbonMonoxideLevel', unit: 'PARTS_PER_MILLION', maxValue: 1000 },
    volatile_organic_compounds: { name: 'VolatileOrganicCompounds', unit: 'PARTS_PER_MILLION', maxValue: 5000 },
    voc: { name: 'VolatileOrganicCompounds', unit: 'PARTS_PER_MILLION', maxValue: 5000 },
    aqi: { name: 'AirQuality', unit: 'AQI', maxValue: 500 }
};
const SENSOR_DEFAULT_ENTRY = { name: 'AirQuality', unit: 'AQI', maxValue: 500 };

const BINARY_SENSOR_OPENCLOSE_SET = new Set(['door', 'window', 'garage_door', 'opening']);
const BINARY_SENSOR_OPENCLOSE_TYPES = {
    door: 'action.devices.types.DOOR',
    window: 'action.devices.types.WINDOW',
    garage_door: 'action.devices.types.GARAGE'
};
const BINARY_SENSOR_DESCRIPTIVE_REGISTRY = {
    smoke: { name: 'SmokeLevel', onState: 'smoke detected', offState: 'no smoke detected' },
    moisture: { name: 'WaterLeak', onState: 'leak', offState: 'no leak' },
    motion: { name: 'OccupancyDetecting', onState: 'occupied', offState: 'unoccupied' },
    occupancy: { name: 'OccupancyDetecting', onState: 'occupied', offState: 'unoccupied' },
    co: { name: 'CarbonMonoxideLevel', onState: 'carbon monoxide detected', offState: 'no carbon monoxide detected' },
    carbon_monoxide: {
        name: 'CarbonMonoxideLevel',
        onState: 'carbon monoxide detected',
        offState: 'no carbon monoxide detected'
    },
    gas: { name: 'SmokeLevel', onState: 'smoke detected', offState: 'no smoke detected' }
};

function normalizeGoogleEntityType(entityType) {
    const normalized = sanitizeString(entityType, 64);
    if (!normalized) {
        return 'switch';
    }

    return normalized.toLowerCase();
}

function mapGoogleDomainToEntityType(entityId, fallbackType = 'switch') {
    const normalizedEntityId = sanitizeEntityId(entityId) || '';
    const domain = normalizedEntityId.includes('.') ? normalizedEntityId.split('.')[0] : '';
    return DOMAIN_TO_ENTITY_TYPE[domain] || fallbackType;
}

function resolveGoogleTraitsFromCapabilities(entityType, statePayload) {
    const { sf, dc, colorModes, hasFeature } = parseEntityContext(statePayload);

    if (entityType === 'light') {
        const traits = ['action.devices.traits.OnOff'];
        const hasBrightness = colorModes.length > 0 && !colorModes.every((m) => m === 'onoff');
        if (hasBrightness) {
            traits.push('action.devices.traits.Brightness');
        }
        const hasColor = colorModes.some((m) => ['hs', 'xy', 'rgb', 'rgbw', 'rgbww'].includes(m));
        const hasColorTemp = colorModes.includes('color_temp');
        if (hasColor || hasColorTemp) {
            traits.push('action.devices.traits.ColorSetting');
        }
        const effectList = Array.isArray(statePayload?.effect_list) ? statePayload.effect_list : [];
        if (effectList.length > 0) {
            traits.push('action.devices.traits.Modes');
        }
        return { type: 'action.devices.types.LIGHT', traits };
    }

    if (entityType === 'fan') {
        const traits = ['action.devices.traits.OnOff'];
        const hasSetSpeed = hasFeature(1);
        const hasPresetMode = hasFeature(8);
        if (hasSetSpeed || hasPresetMode || sf === 0) {
            traits.push('action.devices.traits.FanSpeed');
        }
        const presetModes = Array.isArray(statePayload?.preset_modes) ? statePayload.preset_modes : [];
        if (hasPresetMode && presetModes.length > 0) {
            traits.push('action.devices.traits.Modes');
        }
        return { type: 'action.devices.types.FAN', traits };
    }

    if (entityType === 'cover') {
        const deviceType = COVER_DEVICE_CLASS_MAP[dc] || 'action.devices.types.BLINDS';

        const traits = ['action.devices.traits.OpenClose'];
        const hasTilt = hasFeature(128);
        if (hasTilt) {
            traits.push('action.devices.traits.Rotation');
        }
        return { type: deviceType, traits };
    }

    if (entityType === 'lock') {
        return {
            type: 'action.devices.types.LOCK',
            traits: ['action.devices.traits.LockUnlock']
        };
    }

    if (entityType === 'climate') {
        const traits = ['action.devices.traits.TemperatureSetting'];
        const hasFanMode = hasFeature(8);
        const hasPresetMode = hasFeature(16);
        const hasSwingMode = hasFeature(32);
        if (hasFanMode || hasPresetMode || hasSwingMode) {
            traits.push('action.devices.traits.Modes');
        }
        return {
            type: 'action.devices.types.THERMOSTAT',
            traits
        };
    }

    if (entityType === 'media_player') {
        let deviceType = 'action.devices.types.TV';
        if (dc === 'speaker') deviceType = 'action.devices.types.SPEAKER';
        else if (dc === 'receiver') deviceType = 'action.devices.types.AUDIO_VIDEO_RECEIVER';
        else if (dc === 'tv') deviceType = 'action.devices.types.TV';

        const traits = [];
        const hasTurnOn = hasFeature(128);
        const hasTurnOff = hasFeature(256);
        if (hasTurnOn || hasTurnOff || sf === 0) {
            traits.push('action.devices.traits.OnOff');
        }
        const hasVolumeSet = hasFeature(4);
        const hasVolumeStep = hasFeature(1024);
        if (hasVolumeSet || hasVolumeStep || sf === 0) {
            traits.push('action.devices.traits.Volume');
        }
        const _hasVolumeMute = hasFeature(8);
        const hasPause = hasFeature(1);
        const hasPlay = hasFeature(16384);
        const hasNextTrack = hasFeature(32);
        const hasPreviousTrack = hasFeature(16);
        const hasStop = hasFeature(4096);
        if (hasPause || hasPlay || hasNextTrack || hasPreviousTrack || hasStop) {
            traits.push('action.devices.traits.TransportControl');
            traits.push('action.devices.traits.MediaState');
        }
        const hasSelectSource = hasFeature(2048);
        const sourceList = Array.isArray(statePayload?.source_list) ? statePayload.source_list : [];
        if (hasSelectSource && sourceList.length > 0) {
            traits.push('action.devices.traits.InputSelector');
        }
        const hasSelectSoundMode = hasFeature(65536);
        const soundModeList = Array.isArray(statePayload?.sound_mode_list) ? statePayload.sound_mode_list : [];
        if (hasSelectSoundMode && soundModeList.length > 0) {
            traits.push('action.devices.traits.Modes');
        }
        if (traits.length === 0) {
            traits.push('action.devices.traits.OnOff');
        }
        return { type: deviceType, traits };
    }

    if (entityType === 'scene') {
        return {
            type: 'action.devices.types.SCENE',
            traits: ['action.devices.traits.Scene']
        };
    }

    if (entityType === 'button') {
        return {
            type: 'action.devices.types.SCENE',
            traits: ['action.devices.traits.Scene']
        };
    }

    if (entityType === 'vacuum') {
        const traits = [];
        const hasStart = hasFeature(8192);
        const hasTurnOn = hasFeature(1);
        const hasTurnOff = hasFeature(2);
        const _hasPauseV = hasFeature(4);
        const hasReturnHome = hasFeature(16);
        const hasFanSpeed = hasFeature(32);
        const hasBattery = hasFeature(64);
        const hasLocate = hasFeature(512);

        if (hasStart || sf === 0) {
            traits.push('action.devices.traits.StartStop');
        }
        if (hasTurnOn || hasTurnOff) {
            traits.push('action.devices.traits.OnOff');
        }
        if (hasReturnHome) {
            traits.push('action.devices.traits.Dock');
        }
        if (hasLocate) {
            traits.push('action.devices.traits.Locator');
        }
        if (hasFanSpeed) {
            traits.push('action.devices.traits.FanSpeed');
        }
        if (hasBattery) {
            traits.push('action.devices.traits.EnergyStorage');
        }
        if (traits.length === 0) {
            traits.push('action.devices.traits.StartStop');
            traits.push('action.devices.traits.OnOff');
        }
        return { type: 'action.devices.types.VACUUM', traits };
    }

    if (entityType === 'sensor' || entityType === 'sensor_temperature') {
        const sensorDc = dc || statePayload?.device_class || 'temperature';
        // Temperature and humidity use dedicated traits; other sensors use SensorState
        if (sensorDc === 'temperature') {
            return {
                type: 'action.devices.types.SENSOR',
                traits: ['action.devices.traits.TemperatureSetting']
            };
        } else if (sensorDc === 'humidity') {
            return {
                type: 'action.devices.types.SENSOR',
                traits: ['action.devices.traits.HumiditySetting']
            };
        }
        return {
            type: 'action.devices.types.SENSOR',
            traits: ['action.devices.traits.SensorState']
        };
    }

    if (entityType === 'binary_sensor') {
        if (BINARY_SENSOR_OPENCLOSE_SET.has(dc)) {
            return {
                type: BINARY_SENSOR_OPENCLOSE_TYPES[dc] || 'action.devices.types.SENSOR',
                traits: ['action.devices.traits.OpenClose']
            };
        }
        if (dc === 'smoke') {
            return {
                type: 'action.devices.types.SMOKE_DETECTOR',
                traits: ['action.devices.traits.SensorState']
            };
        }
        if (dc === 'co' || dc === 'carbon_monoxide') {
            return {
                type: 'action.devices.types.CARBON_MONOXIDE_DETECTOR',
                traits: ['action.devices.traits.SensorState']
            };
        }
        return {
            type: 'action.devices.types.SENSOR',
            traits: ['action.devices.traits.SensorState']
        };
    }

    if (entityType === 'humidifier') {
        const deviceType =
            dc === 'dehumidifier' ? 'action.devices.types.DEHUMIDIFIER' : 'action.devices.types.HUMIDIFIER';
        const traits = ['action.devices.traits.OnOff', 'action.devices.traits.HumiditySetting'];
        const availableModes = Array.isArray(statePayload?.available_modes) ? statePayload.available_modes : [];
        if (availableModes.length > 0) {
            traits.push('action.devices.traits.Modes');
        }
        return {
            type: deviceType,
            traits
        };
    }

    if (entityType === 'alarm_control_panel') {
        return {
            type: 'action.devices.types.SECURITYSYSTEM',
            traits: ['action.devices.traits.ArmDisarm', 'action.devices.traits.StatusReport']
        };
    }

    if (entityType === 'water_heater') {
        return {
            type: 'action.devices.types.WATERHEATER',
            traits: ['action.devices.traits.OnOff', 'action.devices.traits.TemperatureControl']
        };
    }

    if (entityType === 'automation') {
        return {
            type: 'action.devices.types.SWITCH',
            traits: ['action.devices.traits.OnOff']
        };
    }

    if (entityType === 'script') {
        return {
            type: 'action.devices.types.SCENE',
            traits: ['action.devices.traits.Scene']
        };
    }

    if (entityType === 'camera') {
        return {
            type: 'action.devices.types.CAMERA',
            traits: ['action.devices.traits.CameraStream']
        };
    }

    if (entityType === 'switch') {
        const deviceType = dc === 'outlet' ? 'action.devices.types.OUTLET' : 'action.devices.types.SWITCH';
        return { type: deviceType, traits: ['action.devices.traits.OnOff'] };
    }

    if (entityType === 'group') {
        return {
            type: 'action.devices.types.SWITCH',
            traits: ['action.devices.traits.OnOff']
        };
    }

    if (entityType === 'input_button') {
        return {
            type: 'action.devices.types.SCENE',
            traits: ['action.devices.traits.Scene']
        };
    }

    if (entityType === 'select' || entityType === 'input_select') {
        return {
            type: 'action.devices.types.SENSOR',
            traits: ['action.devices.traits.Modes']
        };
    }

    if (entityType === 'valve') {
        const _hasSetPosition = hasFeature(4);
        const traits = ['action.devices.traits.OpenClose'];
        return { type: 'action.devices.types.VALVE', traits };
    }

    if (entityType === 'lawn_mower') {
        const traits = ['action.devices.traits.StartStop'];
        return { type: 'action.devices.types.MOWER', traits };
    }

    if (entityType === 'event') {
        if (dc === 'doorbell') {
            return {
                type: 'action.devices.types.DOORBELL',
                traits: ['action.devices.traits.ObjectDetection']
            };
        }
        return {
            type: 'action.devices.types.SENSOR',
            traits: ['action.devices.traits.SensorState']
        };
    }

    return {
        type: 'action.devices.types.SWITCH',
        traits: ['action.devices.traits.OnOff']
    };
}

function normalizeGoogleThermostatMode(mode) {
    const sanitized = sanitizeString(mode, 32);
    if (!sanitized) return 'off';
    const normalized = sanitized.toLowerCase();

    if (normalized === 'heat_cool' || normalized === 'heatcool') return 'heatcool';
    if (normalized === 'fan_only' || normalized === 'fan-only') return 'fan-only';
    return normalized;
}

function getGoogleThermostatModesForEntity(entity) {
    const statePayload = parseJsonSafe(entity?.state_json, {}) || {};
    const rawModes = Array.isArray(statePayload.hvac_modes) ? statePayload.hvac_modes : [];
    const normalizedModes = Array.from(
        new Set(rawModes.map((mode) => normalizeGoogleThermostatMode(mode)).filter(Boolean))
    );

    if (normalizedModes.length > 0) {
        return normalizedModes.join(',');
    }

    return 'off,heat,cool,heatcool';
}

function supportsGoogleCommandForEntityType(entityType, commandName, statePayload) {
    const { sf, hasFeature, colorModes } = parseEntityContext(statePayload);
    const sp = statePayload || {};

    const allowed = {
        light: () => {
            const cmds = new Set([
                'action.devices.commands.OnOff',
                'action.devices.commands.BrightnessAbsolute' // Always allow — gracefully degrades to on/off for non-dimmable lights
            ]);
            const hasColor = colorModes.some((m) => ['hs', 'xy', 'rgb', 'rgbw', 'rgbww'].includes(m));
            const hasColorTemp = colorModes.includes('color_temp');
            if (hasColor || hasColorTemp) {
                cmds.add('action.devices.commands.ColorAbsolute');
            }
            const effectList = Array.isArray(sp.effect_list) ? sp.effect_list : [];
            if (effectList.length > 0) {
                cmds.add('action.devices.commands.SetModes');
            }
            return cmds;
        },
        switch: () => new Set(['action.devices.commands.OnOff']),
        fan: () => {
            const cmds = new Set(['action.devices.commands.OnOff']);
            const hasSetSpeed = hasFeature(1);
            const hasPresetMode = hasFeature(8);
            if (hasSetSpeed || hasPresetMode || sf === 0) {
                cmds.add('action.devices.commands.SetFanSpeed');
                if (hasSetSpeed) {
                    cmds.add('action.devices.commands.SetFanSpeedRelative');
                }
            }
            const presetModes = Array.isArray(sp.preset_modes) ? sp.preset_modes : [];
            if (hasPresetMode && presetModes.length > 0) {
                cmds.add('action.devices.commands.SetModes');
            }
            return cmds;
        },
        cover: () => {
            const cmds = new Set(['action.devices.commands.OpenClose']);
            if (hasFeature(128)) {
                cmds.add('action.devices.commands.RotateAbsolute');
            }
            if (hasFeature(4)) {
                cmds.add('action.devices.commands.OpenCloseRelative');
            }
            return cmds;
        },
        lock: () => new Set(['action.devices.commands.LockUnlock']),
        climate: () => {
            const cmds = new Set([
                'action.devices.commands.ThermostatSetMode',
                'action.devices.commands.ThermostatTemperatureSetpoint',
                'action.devices.commands.ThermostatTemperatureSetRange'
            ]);
            if (hasFeature(8) || hasFeature(16) || hasFeature(32)) {
                cmds.add('action.devices.commands.SetModes');
            }
            return cmds;
        },
        media_player: () => {
            const cmds = new Set();
            if (hasFeature(128) || hasFeature(256) || sf === 0) {
                cmds.add('action.devices.commands.OnOff');
            }
            if (hasFeature(4) || hasFeature(1024) || sf === 0) {
                cmds.add('action.devices.commands.setVolume');
                cmds.add('action.devices.commands.volumeRelative');
            }
            if (hasFeature(8) || sf === 0) {
                cmds.add('action.devices.commands.mute');
            }
            if (hasFeature(1) || hasFeature(16384) || hasFeature(32) || hasFeature(16) || hasFeature(4096)) {
                cmds.add('action.devices.commands.mediaControl');
            }
            if (hasFeature(2)) {
                cmds.add('action.devices.commands.mediaSeekToPosition');
                cmds.add('action.devices.commands.mediaSeekRelative');
            }
            if (hasFeature(524288)) {
                cmds.add('action.devices.commands.Shuffle');
            }
            if (hasFeature(262144)) {
                cmds.add('action.devices.commands.SetRepeat');
            }
            if (hasFeature(2048)) {
                cmds.add('action.devices.commands.SetInput');
            }
            const soundModeList = Array.isArray(sp.sound_mode_list) ? sp.sound_mode_list : [];
            if (hasFeature(65536) && soundModeList.length > 0) {
                cmds.add('action.devices.commands.SetModes');
            }
            return cmds;
        },
        scene: () => new Set(['action.devices.commands.ActivateScene']),
        button: () => new Set(['action.devices.commands.ActivateScene']),
        automation: () => new Set(['action.devices.commands.OnOff']),
        script: () => new Set(['action.devices.commands.ActivateScene']),
        vacuum: () => {
            const cmds = new Set();
            if (hasFeature(8192) || sf === 0) {
                cmds.add('action.devices.commands.StartStop');
                cmds.add('action.devices.commands.PauseUnpause');
            }
            if (hasFeature(1) || hasFeature(2)) {
                cmds.add('action.devices.commands.OnOff');
            }
            if (hasFeature(16)) {
                cmds.add('action.devices.commands.Dock');
            }
            if (hasFeature(512)) {
                cmds.add('action.devices.commands.Locate');
            }
            if (hasFeature(32)) {
                cmds.add('action.devices.commands.SetFanSpeed');
            }
            if (cmds.size === 0) {
                cmds.add('action.devices.commands.StartStop');
                cmds.add('action.devices.commands.PauseUnpause');
                cmds.add('action.devices.commands.OnOff');
            }
            return cmds;
        },
        sensor: () => new Set(),
        sensor_temperature: () => new Set(),
        binary_sensor: () => new Set(),
        humidifier: () =>
            new Set([
                'action.devices.commands.OnOff',
                'action.devices.commands.SetHumidity',
                'action.devices.commands.SetModes'
            ]),
        alarm_control_panel: () => new Set(['action.devices.commands.ArmDisarm']),
        water_heater: () => new Set(['action.devices.commands.OnOff', 'action.devices.commands.SetTemperature']),
        camera: () => new Set(['action.devices.commands.GetCameraStream']),
        group: () => new Set(['action.devices.commands.OnOff']),
        input_button: () => new Set(['action.devices.commands.ActivateScene']),
        select: () => new Set(['action.devices.commands.SetModes']),
        input_select: () => new Set(['action.devices.commands.SetModes']),
        valve: () => {
            const cmds = new Set(['action.devices.commands.OpenClose']);
            if (hasFeature(4)) {
                cmds.add('action.devices.commands.OpenCloseRelative');
            }
            return cmds;
        },
        lawn_mower: () => {
            const cmds = new Set(['action.devices.commands.StartStop', 'action.devices.commands.PauseUnpause']);
            return cmds;
        },
        event: () => new Set()
    };

    const resolver = allowed[normalizeGoogleEntityType(entityType)];
    const allowedCommands = resolver ? resolver() : allowed.switch();
    return allowedCommands.has(commandName);
}

function buildGoogleDeviceAttributes(entityType, statePayload, traits) {
    const { sf, dc, colorModes, hasFeature } = parseEntityContext(statePayload);
    const hasTrait = (traitName) => traits.includes(`action.devices.traits.${traitName}`);
    const attrs = {};

    if (entityType === 'light') {
        if (hasTrait('Brightness')) {
            attrs.commandOnlyBrightness = false;
        }
        if (hasTrait('ColorSetting')) {
            const hasColor = colorModes.some((m) => ['hs', 'xy', 'rgb', 'rgbw', 'rgbww'].includes(m));
            const hasColorTemp = colorModes.includes('color_temp');
            if (hasColor) {
                attrs.colorModel = 'hsv';
            }
            if (hasColorTemp) {
                const minK = Number(statePayload?.min_color_temp_kelvin) || 2000;
                const maxK = Number(statePayload?.max_color_temp_kelvin) || 6535;
                attrs.colorTemperatureRange = {
                    temperatureMinK: Math.max(1000, Math.min(12000, minK)),
                    temperatureMaxK: Math.max(1000, Math.min(12000, maxK))
                };
            }
            attrs.commandOnlyColorSetting = false;
        }
        if (hasTrait('Modes')) {
            const effectList = Array.isArray(statePayload?.effect_list) ? statePayload.effect_list : [];
            if (effectList.length > 0) {
                attrs.availableModes = [buildModesAttribute('effect', ['effect', 'light effect'], effectList)];
                attrs.commandOnlyModes = false;
                attrs.queryOnlyModes = false;
            }
        }
        return attrs;
    }

    if (entityType === 'fan') {
        if (hasTrait('FanSpeed')) {
            const hasSetSpeed = hasFeature(1);
            const _hasPresetMode = hasFeature(8);
            const percentageStep = Number(statePayload?.percentage_step) || 0;
            const presetModes = Array.isArray(statePayload?.preset_modes) ? statePayload.preset_modes : [];

            if (hasSetSpeed && percentageStep > 0) {
                const numSpeeds = Math.round(100 / percentageStep);
                const speeds = [];
                for (let i = 1; i <= numSpeeds; i++) {
                    const pct = Math.round(i * percentageStep);
                    let label = `Speed ${i}`;
                    let synonyms = [`${i}`, `speed ${i}`, `${pct} percent`];
                    if (i === 1) {
                        label = 'Low';
                        synonyms = ['low', '1', 'slow', `${pct} percent`];
                    } else if (i === numSpeeds) {
                        label = 'High';
                        synonyms = ['high', `${i}`, 'fast', 'max', `${pct} percent`];
                    } else if (i === Math.ceil(numSpeeds / 2)) {
                        label = 'Medium';
                        synonyms = ['medium', `${i}`, 'mid', `${pct} percent`];
                    }
                    speeds.push({
                        speed_name: String(i),
                        speed_values: [{ speed_synonym: [label, ...synonyms], lang: 'en' }]
                    });
                }
                attrs.availableFanSpeeds = { speeds, ordered: true };
                attrs.supportsFanSpeedPercent = true;
            } else if (presetModes.length > 0 && !hasSetSpeed) {
                const speeds = presetModes.map((mode) => ({
                    speed_name: mode,
                    speed_values: [{ speed_synonym: [mode], lang: 'en' }]
                }));
                attrs.availableFanSpeeds = { speeds, ordered: false };
                attrs.supportsFanSpeedPercent = false;
            } else {
                attrs.availableFanSpeeds = {
                    speeds: [
                        { speed_name: '1', speed_values: [{ speed_synonym: ['low', '1'], lang: 'en' }] },
                        { speed_name: '2', speed_values: [{ speed_synonym: ['medium', '2'], lang: 'en' }] },
                        { speed_name: '3', speed_values: [{ speed_synonym: ['high', '3'], lang: 'en' }] }
                    ],
                    ordered: true
                };
            }
            attrs.reversible = false;
            attrs.commandOnlyFanSpeed = false;
        }
        if (hasTrait('Modes')) {
            const presetModes = Array.isArray(statePayload?.preset_modes) ? statePayload.preset_modes : [];
            if (presetModes.length > 0) {
                attrs.availableModes = [buildModesAttribute('preset_mode', ['preset', 'preset mode'], presetModes)];
                attrs.commandOnlyModes = false;
                attrs.queryOnlyModes = false;
            }
        }
        return attrs;
    }

    if (entityType === 'cover') {
        const hasSetPosition = hasFeature(4);
        attrs.discreteOnlyOpenClose = !hasSetPosition;
        attrs.queryOnlyOpenClose = false;
        if (hasTrait('Rotation')) {
            attrs.supportsDegrees = false;
            attrs.supportsPercent = true;
        }
        return attrs;
    }

    if (entityType === 'climate') {
        attrs.availableThermostatModes = getGoogleThermostatModesForEntity({
            state_json: JSON.stringify(statePayload)
        });
        const unit = statePayload?.temperature_unit || 'C';
        attrs.thermostatTemperatureUnit = unit === 'F' ? 'F' : 'C';
        const minTemp = Number(statePayload?.min_temp);
        const maxTemp = Number(statePayload?.max_temp);
        if (Number.isFinite(minTemp) && Number.isFinite(maxTemp)) {
            attrs.thermostatTemperatureRange = {
                minThresholdCelsius: unit === 'F' ? Math.round(((minTemp - 32) * 5) / 9) : minTemp,
                maxThresholdCelsius: unit === 'F' ? Math.round(((maxTemp - 32) * 5) / 9) : maxTemp
            };
        }
        const hvacModes = Array.isArray(statePayload?.hvac_modes) ? statePayload.hvac_modes : [];
        if (hvacModes.some((m) => m === 'heat_cool' || m === 'auto')) {
            attrs.bufferRangeCelsius = 2;
        }
        if (hasTrait('Modes')) {
            const climateModes = [];
            const hasFanMode = hasFeature(8);
            const hasPresetMode = hasFeature(16);
            const hasSwingMode = hasFeature(32);
            if (hasFanMode) {
                const fanModes = Array.isArray(statePayload?.fan_modes) ? statePayload.fan_modes : [];
                if (fanModes.length > 0) {
                    climateModes.push(buildModesAttribute('fan_mode', ['fan mode', 'fan speed', 'fan'], fanModes));
                }
            }
            if (hasPresetMode) {
                const presetModes = Array.isArray(statePayload?.preset_modes) ? statePayload.preset_modes : [];
                if (presetModes.length > 0) {
                    climateModes.push(buildModesAttribute('preset_mode', ['preset', 'preset mode'], presetModes));
                }
            }
            if (hasSwingMode) {
                const swingModes = Array.isArray(statePayload?.swing_modes) ? statePayload.swing_modes : [];
                if (swingModes.length > 0) {
                    climateModes.push(buildModesAttribute('swing_mode', ['swing mode', 'swing', 'vane'], swingModes));
                }
            }
            if (climateModes.length > 0) {
                attrs.availableModes = climateModes;
                attrs.commandOnlyModes = false;
                attrs.queryOnlyModes = false;
            }
        }
        return attrs;
    }

    if (entityType === 'media_player') {
        if (hasTrait('Volume')) {
            attrs.volumeMaxLevel = 100;
            attrs.volumeCanMuteAndUnmute = hasFeature(8) || sf === 0;
            attrs.commandOnlyVolume = false;
        }
        if (hasTrait('TransportControl')) {
            const transportCommands = [];
            if (hasFeature(1)) transportCommands.push('PAUSE');
            if (hasFeature(16384) || hasFeature(1)) transportCommands.push('RESUME');
            if (hasFeature(4096)) transportCommands.push('STOP');
            if (hasFeature(32)) transportCommands.push('NEXT');
            if (hasFeature(16)) transportCommands.push('PREVIOUS');
            if (hasFeature(2)) transportCommands.push('SEEK_TO_POSITION'); // SEEK feature
            if (hasFeature(2)) transportCommands.push('SEEK_RELATIVE'); // SEEK feature
            if (hasFeature(524288)) transportCommands.push('SHUFFLE'); // SHUFFLE_SET feature
            if (hasFeature(262144)) transportCommands.push('SET_REPEAT'); // REPEAT_SET feature
            attrs.transportControlSupported = transportCommands.map((cmd) => ({ command: cmd }));
        }
        if (hasTrait('MediaState')) {
            attrs.supportActivityState = false;
            attrs.supportPlaybackState = true;
        }
        if (hasTrait('InputSelector')) {
            const sourceList = Array.isArray(statePayload?.source_list) ? statePayload.source_list : [];
            attrs.availableInputs = sourceList.map((src) => ({
                key: src.toLowerCase().replace(/[^a-z0-9_]/g, '_'),
                names: [{ name_synonym: [src], lang: 'en' }]
            }));
            attrs.commandOnlyInputSelector = false;
            attrs.orderedInputs = false;
        }
        if (hasTrait('Modes')) {
            const soundModeList = Array.isArray(statePayload?.sound_mode_list) ? statePayload.sound_mode_list : [];
            if (soundModeList.length > 0) {
                attrs.availableModes = [
                    buildModesAttribute('sound_mode', ['sound mode', 'sound', 'audio mode'], soundModeList)
                ];
                attrs.commandOnlyModes = false;
                attrs.queryOnlyModes = false;
            }
        }
        return attrs;
    }

    if (entityType === 'scene' || entityType === 'button' || entityType === 'script' || entityType === 'input_button') {
        // HA core returns empty attributes for scenes — Google defaults sceneReversible to false
        return attrs;
    }

    if (entityType === 'vacuum') {
        if (hasTrait('StartStop')) {
            attrs.pausable = hasFeature(4) || sf === 0;
        }
        if (hasTrait('FanSpeed')) {
            const fanSpeedList = Array.isArray(statePayload?.fan_speed_list) ? statePayload.fan_speed_list : [];
            if (fanSpeedList.length > 0) {
                attrs.availableFanSpeeds = {
                    speeds: fanSpeedList.map((spd) => ({
                        speed_name: spd,
                        speed_values: [{ speed_synonym: [spd], lang: 'en' }]
                    })),
                    ordered: true
                };
                attrs.reversible = false;
            }
        }
        if (hasTrait('EnergyStorage')) {
            attrs.queryOnlyEnergyStorage = true;
            attrs.isRechargeable = true;
        }
        return attrs;
    }

    if (entityType === 'sensor' || entityType === 'sensor_temperature') {
        const sensorDc = dc || statePayload?.device_class || 'temperature';

        if (sensorDc === 'temperature') {
            const unitRaw = statePayload?.unit_of_measurement || '°C';
            const isFahrenheit = /F/.test(unitRaw);
            attrs.queryOnlyTemperatureSetting = true;
            attrs.thermostatTemperatureUnit = isFahrenheit ? 'F' : 'C';
            return attrs;
        } else if (sensorDc === 'humidity') {
            attrs.queryOnlyHumiditySetting = true;
            return attrs;
        }

        // All other sensors use SensorState with valid Google sensor names
        const entry = SENSOR_DEVICE_CLASS_REGISTRY[sensorDc] || SENSOR_DEFAULT_ENTRY;
        attrs.sensorStatesSupported = [
            {
                name: entry.name,
                numericCapabilities: {
                    rawValueUnit: entry.unit,
                    rawValueRange: { minValue: 0, maxValue: entry.maxValue }
                }
            }
        ];

        return attrs;
    }

    if (entityType === 'binary_sensor') {
        if (BINARY_SENSOR_OPENCLOSE_SET.has(dc)) {
            attrs.queryOnlyOpenClose = true;
            attrs.discreteOnlyOpenClose = true;
        } else {
            const descEntry = BINARY_SENSOR_DESCRIPTIVE_REGISTRY[dc];
            if (descEntry) {
                attrs.sensorStatesSupported = [
                    {
                        name: descEntry.name,
                        descriptiveCapabilities: {
                            availableStates: [descEntry.onState, descEntry.offState]
                        }
                    }
                ];
            }
        }
        return attrs;
    }

    if (entityType === 'humidifier') {
        const minHumidity = Number(statePayload?.min_humidity) || 0;
        const maxHumidity = Number(statePayload?.max_humidity) || 100;
        attrs.humiditySetpointRange = {
            minPercent: Math.max(0, minHumidity),
            maxPercent: Math.min(100, maxHumidity)
        };
        attrs.commandOnlyHumiditySetting = false;
        attrs.queryOnlyHumiditySetting = false;
        if (hasTrait('Modes')) {
            const availableModes = Array.isArray(statePayload?.available_modes) ? statePayload.available_modes : [];
            if (availableModes.length > 0) {
                attrs.availableModes = [buildModesAttribute('mode', ['mode'], availableModes)];
                attrs.commandOnlyModes = false;
                attrs.queryOnlyModes = false;
            }
        }
        return attrs;
    }

    if (entityType === 'alarm_control_panel') {
        const levels = [];
        if (hasFeature(1))
            levels.push({
                level_name: 'L1',
                level_values: [{ level_synonym: ['home', 'arm home', 'stay'], lang: 'en' }]
            });
        if (hasFeature(2))
            levels.push({ level_name: 'L2', level_values: [{ level_synonym: ['away', 'arm away'], lang: 'en' }] });
        if (hasFeature(4))
            levels.push({ level_name: 'L3', level_values: [{ level_synonym: ['night', 'arm night'], lang: 'en' }] });
        if (hasFeature(16))
            levels.push({
                level_name: 'L4',
                level_values: [{ level_synonym: ['custom', 'custom bypass'], lang: 'en' }]
            });
        if (levels.length === 0) {
            levels.push({ level_name: 'L1', level_values: [{ level_synonym: ['home', 'arm home'], lang: 'en' }] });
            levels.push({ level_name: 'L2', level_values: [{ level_synonym: ['away', 'arm away'], lang: 'en' }] });
        }
        attrs.availableArmLevels = { levels, ordered: true };
        return attrs;
    }

    if (entityType === 'water_heater') {
        const unit = statePayload?.temperature_unit || 'C';
        attrs.temperatureUnitForUX = unit === 'F' ? 'F' : 'C';
        const minTemp = Number(statePayload?.min_temp);
        const maxTemp = Number(statePayload?.max_temp);
        if (Number.isFinite(minTemp) && Number.isFinite(maxTemp)) {
            const minC = unit === 'F' ? Math.round(((minTemp - 32) * 5) / 9) : minTemp;
            const maxC = unit === 'F' ? Math.round(((maxTemp - 32) * 5) / 9) : maxTemp;
            attrs.temperatureRange = {
                minThresholdCelsius: minC,
                maxThresholdCelsius: maxC
            };
        }
        attrs.commandOnlyTemperatureControl = false;
        attrs.queryOnlyTemperatureControl = false;
        return attrs;
    }

    if (entityType === 'select' || entityType === 'input_select') {
        const options = Array.isArray(statePayload?.options) ? statePayload.options : [];
        if (options.length > 0) {
            attrs.availableModes = [buildModesAttribute('option', ['option'], options)];
            attrs.queryOnlyModes = false;
            attrs.commandOnlyModes = false;
        }
        return attrs;
    }

    if (entityType === 'valve') {
        const hasSetPosition = hasFeature(4);
        attrs.discreteOnlyOpenClose = !hasSetPosition;
        attrs.queryOnlyOpenClose = false;
        return attrs;
    }

    if (entityType === 'lawn_mower') {
        const hasPause = hasFeature(2);
        attrs.pausable = hasPause;
        return attrs;
    }

    if (entityType === 'event') {
        if (dc === 'doorbell') {
            attrs.queryOnlyObjectDetection = true;
        }
        return attrs;
    }

    if (entityType === 'camera') {
        attrs.cameraStreamSupportedProtocols = ['hls'];
        attrs.cameraStreamNeedAuthToken = false;
        return attrs;
    }

    return attrs;
}

function buildGoogleDeviceObject(entity, userSecurityPin) {
    const statePayload = parseJsonSafe(entity?.state_json, {}) || {};
    const mapped = resolveGoogleTraitsFromCapabilities(entity.entity_type, statePayload);
    const roomHint = sanitizeString(entity.room_hint, 120);
    const attributes = buildGoogleDeviceAttributes(entity.entity_type, statePayload, mapped.traits);

    const deviceObj = {
        id: entity.entity_id,
        type: mapped.type,
        traits: mapped.traits,
        name: {
            name: entity.display_name || entity.entity_id
        },
        roomHint: roomHint || undefined,
        willReportState: config.GOOGLE_HOMEGRAPH_REPORT_STATE_ENABLED && _hasGoogleHomegraphCredentials(),
        customData: {
            entity_id: entity.entity_id,
            device_id: entity.device_id
        },
        deviceInfo: {
            manufacturer: statePayload._manufacturer || 'Apex Infosys',
            model: statePayload._model || entity.entity_type || 'generic',
            hwVersion: entity.addon_version || 'apex-cloud-link',
            ...(statePayload._sw_version ? { swVersion: statePayload._sw_version } : {})
        },
        attributes
    };

    // Add PIN challenge for security-sensitive devices
    if (userSecurityPin && (entity.entity_type === 'alarm_control_panel' || entity.entity_type === 'lock')) {
        deviceObj.attributes = {
            ...deviceObj.attributes,
            pinNeeded: true
        };
    }

    return deviceObj;
}

function parseGoogleEntityState(entity) {
    const statePayload = parseJsonSafe(entity.state_json, {}) || {};
    const { sf, dc, colorModes, hasFeature } = parseEntityContext(statePayload);

    if (entity.entity_type === 'fan') {
        const fanOn = Boolean(statePayload.on);
        const state = {
            online: entity.online !== 0,
            on: fanOn
        };
        const hasSetSpeed = hasFeature(1);
        const percentageStep = Number(statePayload.percentage_step) || 0;
        if (hasSetSpeed && percentageStep > 0) {
            const percentage = Number(statePayload.percentage) || 0;
            const speedIndex = Math.max(1, Math.round(percentage / percentageStep));
            state.currentFanSpeedSetting = String(speedIndex);
            state.currentFanSpeedPercent = Math.max(0, Math.min(100, Math.round(percentage)));
        } else if (hasFeature(8) && statePayload.preset_mode) {
            state.currentFanSpeedSetting = statePayload.preset_mode;
        } else {
            const speed = Number(statePayload.speed ?? 0);
            state.currentFanSpeedSetting = String(Math.max(1, Math.min(3, Math.round(speed || 1))));
        }
        const presetModes = Array.isArray(statePayload.preset_modes) ? statePayload.preset_modes : [];
        if (hasFeature(8) && presetModes.length > 0 && statePayload.preset_mode) {
            state.currentModeSettings = { preset_mode: statePayload.preset_mode };
        }
        return state;
    }

    if (entity.entity_type === 'cover') {
        const openPercent = Number(statePayload.openPercent ?? 0);
        const state = {
            online: entity.online !== 0,
            openPercent: Math.max(0, Math.min(100, Math.round(openPercent)))
        };
        if (hasFeature(128) && statePayload.tilt_position != null) {
            state.rotationPercent = Math.max(0, Math.min(100, Math.round(Number(statePayload.tilt_position) || 0)));
        }
        return state;
    }

    if (entity.entity_type === 'lock') {
        return {
            online: entity.online !== 0,
            isLocked: Boolean(statePayload.isLocked)
        };
    }

    if (entity.entity_type === 'climate') {
        const ambient = statePayload.ambient_temperature != null ? Number(statePayload.ambient_temperature) : null;
        const target = statePayload.target_temperature != null ? Number(statePayload.target_temperature) : null;
        const targetLow = statePayload.target_temp_low != null ? Number(statePayload.target_temp_low) : null;
        const targetHigh = statePayload.target_temp_high != null ? Number(statePayload.target_temp_high) : null;
        const mode = normalizeGoogleThermostatMode(statePayload.mode);

        const state = {
            online: entity.online !== 0,
            thermostatMode: mode,
            thermostatTemperatureAmbient: Number.isFinite(ambient) ? ambient : 0,
            thermostatTemperatureSetpoint: Number.isFinite(target) ? target : Number.isFinite(ambient) ? ambient : 22
        };

        if (mode === 'heatcool' && Number.isFinite(targetLow) && Number.isFinite(targetHigh)) {
            state.thermostatTemperatureSetpointLow = targetLow;
            state.thermostatTemperatureSetpointHigh = targetHigh;
        }

        if (statePayload.current_humidity != null) {
            const humidity = Number(statePayload.current_humidity);
            if (Number.isFinite(humidity)) {
                state.thermostatHumidityAmbient = humidity;
            }
        }

        const modeSettings = {};
        if (statePayload.fan_mode) {
            modeSettings.fan_mode = statePayload.fan_mode;
        }
        if (statePayload.preset_mode) {
            modeSettings.preset_mode = statePayload.preset_mode;
        }
        if (statePayload.swing_mode) {
            modeSettings.swing_mode = statePayload.swing_mode;
        }
        if (Object.keys(modeSettings).length > 0) {
            state.currentModeSettings = modeSettings;
        }

        return state;
    }

    if (entity.entity_type === 'media_player') {
        const state = {
            online: entity.online !== 0,
            on: Boolean(statePayload.on)
        };
        if (hasFeature(4) || hasFeature(1024) || sf === 0) {
            const volume = Number(statePayload.volume ?? 0);
            state.currentVolume = Math.max(0, Math.min(100, Math.round(volume)));
            state.isMuted = Boolean(statePayload.muted);
        }
        if (hasFeature(1) || hasFeature(16384) || hasFeature(32) || hasFeature(16) || hasFeature(4096)) {
            if (statePayload.is_playing) {
                state.playbackState = 'PLAYING';
            } else if (statePayload.is_paused) {
                state.playbackState = 'PAUSED';
            } else {
                state.playbackState = 'STOPPED';
            }
        }
        if (hasFeature(2048) && statePayload.source) {
            state.currentInput = statePayload.source.toLowerCase().replace(/[^a-z0-9_]/g, '_');
        }
        if (hasFeature(65536) && statePayload.sound_mode) {
            state.currentModeSettings = { sound_mode: statePayload.sound_mode };
        }
        return state;
    }

    if (
        entity.entity_type === 'scene' ||
        entity.entity_type === 'button' ||
        entity.entity_type === 'script' ||
        entity.entity_type === 'input_button'
    ) {
        return {
            online: entity.online !== 0
        };
    }

    if (entity.entity_type === 'vacuum') {
        const state = {
            online: entity.online !== 0,
            isRunning: Boolean(statePayload.isRunning),
            isPaused: Boolean(statePayload.isPaused)
        };
        if (hasFeature(1) || hasFeature(2) || sf === 0) {
            state.on = Boolean(statePayload.on);
        }
        if (hasFeature(16)) {
            state.isDocked = Boolean(statePayload.isDocked);
        }
        if (hasFeature(32) && statePayload.fan_speed) {
            state.currentFanSpeedSetting = statePayload.fan_speed;
        }
        if (hasFeature(64) && statePayload.battery_level != null) {
            const battery = Number(statePayload.battery_level);
            state.descriptiveCapacityRemaining = 'FULL';
            if (Number.isFinite(battery)) {
                state.capacityRemaining = [{ rawValue: battery, unit: 'PERCENTAGE' }];
                if (battery <= 10) state.descriptiveCapacityRemaining = 'CRITICALLY_LOW';
                else if (battery <= 25) state.descriptiveCapacityRemaining = 'LOW';
                else if (battery <= 75) state.descriptiveCapacityRemaining = 'MEDIUM';
                else state.descriptiveCapacityRemaining = 'FULL';
            }
            state.isCharging = Boolean(statePayload.isDocked);
        }
        return state;
    }

    if (entity.entity_type === 'light') {
        const state = {
            online: entity.online !== 0,
            on: Boolean(statePayload.on)
        };
        const hasBrightness = colorModes.length > 0 && !colorModes.every((m) => m === 'onoff');
        if (hasBrightness) {
            const rawBrightness = Number.isFinite(Number(statePayload.brightness))
                ? Math.max(0, Math.min(100, Math.round(Number(statePayload.brightness))))
                : 0;
            // A light that is ON cannot have 0% brightness — use 100 as fallback
            // This prevents stale brightness=0 (from off state) from being reported
            // when the light was just turned on but addon hasn't synced yet
            state.brightness = state.on && rawBrightness === 0 ? 100 : rawBrightness;
        }
        const hasColor = colorModes.some((m) => ['hs', 'xy', 'rgb', 'rgbw', 'rgbww'].includes(m));
        const hasColorTemp = colorModes.includes('color_temp');
        if (hasColor || hasColorTemp) {
            const colorMode = statePayload.color_mode || '';
            if (colorMode === 'color_temp' && statePayload.color_temp_kelvin) {
                state.color = { temperatureK: Number(statePayload.color_temp_kelvin) || 3000 };
            } else if (hasColor && Array.isArray(statePayload.hs_color) && statePayload.hs_color.length >= 2) {
                const h = Number(statePayload.hs_color[0]) || 0;
                const s = Number(statePayload.hs_color[1]) || 0;
                state.color = {
                    spectrumHsv: {
                        hue: h,
                        saturation: s / 100,
                        value: (state.brightness || 100) / 100
                    }
                };
            } else if (hasColorTemp && statePayload.color_temp_kelvin) {
                state.color = { temperatureK: Number(statePayload.color_temp_kelvin) || 3000 };
            }
        }
        if (statePayload.effect) {
            state.currentModeSettings = { effect: statePayload.effect };
        }
        return state;
    }

    if (entity.entity_type === 'sensor' || entity.entity_type === 'sensor_temperature') {
        const sensorDc = dc || statePayload.device_class || 'temperature';
        const state = { online: entity.online !== 0 };

        if (sensorDc === 'temperature') {
            // TemperatureSetting trait — use thermostatTemperatureAmbient
            const temperature = Number(
                statePayload.temperature != null ? statePayload.temperature : statePayload.value
            );
            state.thermostatMode = 'off';
            state.thermostatTemperatureAmbient = Number.isFinite(temperature) ? temperature : 0;
            state.thermostatTemperatureSetpoint = state.thermostatTemperatureAmbient;
            return state;
        } else if (sensorDc === 'humidity') {
            // HumiditySetting trait — use humidityAmbientPercent
            const humidity = Number(statePayload.value);
            state.humidityAmbientPercent = Number.isFinite(humidity)
                ? Math.max(0, Math.min(100, Math.round(humidity)))
                : 0;
            return state;
        }

        // All other sensors use SensorState trait with currentSensorStateData
        const entry = SENSOR_DEVICE_CLASS_REGISTRY[sensorDc] || SENSOR_DEFAULT_ENTRY;
        const val = Number(statePayload.value);
        state.currentSensorStateData = [{ name: entry.name, rawValue: Number.isFinite(val) ? val : 0 }];

        return state;
    }

    if (entity.entity_type === 'binary_sensor') {
        const state = { online: entity.online !== 0 };
        const isOn = Boolean(statePayload.is_on);

        if (BINARY_SENSOR_OPENCLOSE_SET.has(dc)) {
            state.openPercent = isOn ? 100 : 0;
        } else {
            const descEntry = BINARY_SENSOR_DESCRIPTIVE_REGISTRY[dc];
            if (descEntry) {
                state.currentSensorStateData = [
                    {
                        name: descEntry.name,
                        currentSensorState: isOn ? descEntry.onState : descEntry.offState
                    }
                ];
            }
        }
        return state;
    }

    if (entity.entity_type === 'humidifier') {
        const state = {
            online: entity.online !== 0,
            on: Boolean(statePayload.on)
        };
        if (statePayload.target_humidity != null) {
            state.humiditySetpointPercent = Math.max(
                0,
                Math.min(100, Math.round(Number(statePayload.target_humidity) || 0))
            );
        }
        if (statePayload.current_humidity != null) {
            state.humidityAmbientPercent = Math.max(
                0,
                Math.min(100, Math.round(Number(statePayload.current_humidity) || 0))
            );
        }
        if (statePayload.mode) {
            state.currentModeSettings = { mode: statePayload.mode };
        }
        return state;
    }

    if (entity.entity_type === 'alarm_control_panel') {
        const armState = statePayload.arm_state || 'disarmed';
        const state = {
            online: entity.online !== 0,
            isArmed: armState !== 'disarmed' && armState !== 'pending'
        };
        if (state.isArmed) {
            if (armState === 'armed_home') state.currentArmLevel = 'L1';
            else if (armState === 'armed_away') state.currentArmLevel = 'L2';
            else if (armState === 'armed_night') state.currentArmLevel = 'L3';
            else if (armState === 'armed_custom_bypass') state.currentArmLevel = 'L4';
            else state.currentArmLevel = 'L1';
        }
        if (armState === 'triggered') {
            state.currentStatusReport = [
                {
                    blocking: true,
                    deviceTarget: entity.entity_id,
                    priority: 0,
                    statusCode: 'securityAlert'
                }
            ];
        }
        return state;
    }

    if (entity.entity_type === 'water_heater') {
        const ambient = statePayload.current_temperature != null ? Number(statePayload.current_temperature) : null;
        const target = statePayload.target_temperature != null ? Number(statePayload.target_temperature) : null;
        const state = {
            online: entity.online !== 0,
            on: Boolean(statePayload.on),
            temperatureSetpointCelsius: Number.isFinite(target) ? target : Number.isFinite(ambient) ? ambient : 50
        };
        if (Number.isFinite(ambient)) {
            state.temperatureAmbientCelsius = ambient;
        }
        return state;
    }

    if (entity.entity_type === 'group') {
        return {
            online: entity.online !== 0,
            on: Boolean(statePayload.on)
        };
    }

    if (entity.entity_type === 'select' || entity.entity_type === 'input_select') {
        const state = {
            online: entity.online !== 0
        };
        if (statePayload.current_option) {
            state.currentModeSettings = { option: statePayload.current_option };
        }
        return state;
    }

    if (entity.entity_type === 'valve') {
        const openPercent = Number(statePayload.openPercent ?? 0);
        return {
            online: entity.online !== 0,
            openPercent: Math.max(0, Math.min(100, Math.round(openPercent)))
        };
    }

    if (entity.entity_type === 'lawn_mower') {
        return {
            online: entity.online !== 0,
            isRunning: Boolean(statePayload.isRunning),
            isPaused: Boolean(statePayload.isPaused)
        };
    }

    if (entity.entity_type === 'event') {
        return {
            online: entity.online !== 0
        };
    }

    if (entity.entity_type === 'automation') {
        return {
            online: entity.online !== 0,
            on: Boolean(statePayload.on)
        };
    }

    if (entity.entity_type === 'camera') {
        return {
            online: entity.online !== 0
        };
    }

    return {
        online: entity.online !== 0,
        on: Boolean(statePayload.on)
    };
}

function withEffectiveGoogleOnline(entity) {
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

module.exports = {
    normalizeGoogleEntityType,
    mapGoogleDomainToEntityType,
    resolveGoogleTraitsFromCapabilities,
    normalizeGoogleThermostatMode,
    getGoogleThermostatModesForEntity,
    supportsGoogleCommandForEntityType,
    buildGoogleDeviceAttributes,
    buildGoogleDeviceObject,
    parseGoogleEntityState,
    setHasGoogleHomegraphCredentials,
    withEffectiveGoogleOnline
};
