const utils = require('../utils');

/**
 * Alexa directive translation — pure functions mapping an inbound Smart Home
 * directive (namespace, name, header.instance, payload) to an internal command
 * { action, payload, optimisticState } that the add-on's execute_alexa_command
 * knows how to apply.
 *
 * Kept separate from the route handler so it is unit-testable in isolation and
 * so the per-domain branches (which grow with every phase) live in one place.
 *
 * Returns { action: null } when a directive is not understood; the caller then
 * emits an INVALID_DIRECTIVE error.
 */

const clampPercent = (v) => Math.max(0, Math.min(100, Math.round(Number(v) || 0)));

// RangeController: SetRangeValue (absolute) / AdjustRangeValue (delta).
function translateRangeController(name, instance, payload, row) {
    const state = utils.parseJsonSafe(row?.state_json, {}) || {};
    if (instance === 'Fan.Speed') {
        let percentage;
        if (name === 'AdjustRangeValue') {
            percentage = clampPercent((Number(state.percentage) || 0) + (Number(payload.rangeValueDelta) || 0));
        } else {
            percentage = clampPercent(payload.rangeValue);
        }
        return {
            action: 'set_fan_speed_percent',
            payload: { percentage },
            optimisticState: { on: percentage > 0, percentage }
        };
    }
    if (instance === 'Cover.Position') {
        const openPercent = rangeFromDirective(name, payload, state.openPercent);
        return { action: 'set_open_percent', payload: { openPercent }, optimisticState: { openPercent } };
    }
    if (instance === 'Cover.Tilt') {
        const tilt = rangeFromDirective(name, payload, state.tilt_position);
        return { action: 'set_tilt', payload: { tilt }, optimisticState: { tilt_position: tilt } };
    }
    if (instance === 'Valve.Position') {
        const openPercent = rangeFromDirective(name, payload, state.openPercent);
        return { action: 'set_valve_position', payload: { openPercent }, optimisticState: { openPercent } };
    }
    if (instance === 'Humidifier.Humidity') {
        const humidity = rangeFromDirective(name, payload, state.target_humidity);
        return { action: 'set_humidity', payload: { humidity }, optimisticState: { target_humidity: humidity } };
    }
    return { action: null };
}

// Resolve a 0..100 range value from an absolute Set or relative Adjust directive.
function rangeFromDirective(name, payload, currentRaw) {
    if (name === 'AdjustRangeValue') {
        return clampPercent((Number(currentRaw) || 0) + (Number(payload.rangeValueDelta) || 0));
    }
    return clampPercent(payload.rangeValue);
}

// ModeController: SetMode / AdjustMode.
function translateModeController(name, instance, payload) {
    const mode = typeof payload.mode === 'string' ? payload.mode : '';
    if (instance === 'Fan.PresetMode') {
        if (!mode) return { action: null };
        return { action: 'set_fan_preset', payload: { preset_mode: mode }, optimisticState: { on: true, preset_mode: mode } };
    }
    if (instance === 'Fan.Direction') {
        if (!mode) return { action: null };
        return { action: 'set_fan_direction', payload: { direction: mode }, optimisticState: { direction: mode } };
    }
    if (instance === 'Cover.Position') {
        const open = mode === 'Open';
        return { action: 'set_open_close', payload: { open }, optimisticState: { openPercent: open ? 100 : 0 } };
    }
    if (instance === 'Valve.Position') {
        const open = mode === 'Open';
        return { action: 'set_valve_open_close', payload: { open }, optimisticState: { openPercent: open ? 100 : 0 } };
    }
    if (instance === 'Select.Option') {
        if (!mode) return { action: null };
        return { action: 'set_select_option', payload: { option: mode }, optimisticState: { current_option: mode } };
    }
    if (instance === 'Humidifier.Mode') {
        if (!mode) return { action: null };
        return { action: 'set_humidifier_mode', payload: { mode }, optimisticState: { mode } };
    }
    if (instance === 'Climate.FanMode') {
        if (!mode) return { action: null };
        return { action: 'set_climate_fan_mode', payload: { fan_mode: mode }, optimisticState: { fan_mode: mode } };
    }
    if (instance === 'Climate.PresetMode') {
        if (!mode) return { action: null };
        return { action: 'set_climate_preset_mode', payload: { preset_mode: mode }, optimisticState: { preset_mode: mode } };
    }
    if (instance === 'Climate.SwingMode') {
        if (!mode) return { action: null };
        return { action: 'set_climate_swing_mode', payload: { swing_mode: mode }, optimisticState: { swing_mode: mode } };
    }
    if (instance === 'Vacuum.Mode') {
        if (mode === 'Clean') return { action: 'set_start_stop', payload: { start: true }, optimisticState: { on: true, isRunning: true, isPaused: false, isDocked: false } };
        if (mode === 'Pause') return { action: 'set_pause', payload: { pause: true }, optimisticState: { isPaused: true, isRunning: false } };
        if (mode === 'Dock') return { action: 'dock', payload: {}, optimisticState: { isDocked: true, isRunning: false, on: false } };
        return { action: null };
    }
    if (instance === 'Vacuum.Suction') {
        if (!mode) return { action: null };
        return { action: 'set_vacuum_fan_speed', payload: { fan_speed: mode }, optimisticState: { fan_speed: mode } };
    }
    if (instance === 'Mower.State') {
        if (mode === 'Mow') return { action: 'lawn_mower_start', payload: {}, optimisticState: { isRunning: true, isPaused: false, isDocked: false } };
        if (mode === 'Pause') return { action: 'lawn_mower_pause', payload: {}, optimisticState: { isPaused: true, isRunning: false } };
        if (mode === 'Dock') return { action: 'lawn_mower_dock', payload: {}, optimisticState: { isDocked: true, isRunning: false } };
        return { action: null };
    }
    return { action: null };
}

// ToggleController: TurnOn / TurnOff on an instance.
function translateToggleController(name, instance) {
    const on = name === 'TurnOn';
    if (instance === 'Fan.Oscillate') {
        return { action: 'set_fan_oscillate', payload: { on }, optimisticState: { oscillating: on } };
    }
    return { action: null };
}

/**
 * Top-level dispatcher. `directive` carries header.instance for instanced
 * controllers; `row` is the stored endpoint (for relative adjustments that need
 * the current state).
 */
function translateControlDirective(namespace, name, directive, row) {
    const payload = directive?.payload || {};
    const instance = directive?.header?.instance;

    if (namespace === 'Alexa.PowerController') {
        const on = name === 'TurnOn';
        return { action: on ? 'turn_on' : 'turn_off', payload: { on }, optimisticState: { on } };
    }
    if (namespace === 'Alexa.LockController') {
        const lock = name === 'Lock';
        return { action: 'set_lock', payload: { lock }, optimisticState: { isLocked: lock } };
    }
    if (namespace === 'Alexa.BrightnessController') {
        if (name === 'SetBrightness') {
            const brightness = clampPercent(payload.brightness);
            return { action: 'set_brightness', payload: { brightness }, optimisticState: { on: brightness > 0, brightness } };
        }
        if (name === 'AdjustBrightness') {
            const current = Number(utils.parseJsonSafe(row?.state_json, {})?.brightness) || 0;
            const brightness = clampPercent(current + (Number(payload.brightnessDelta) || 0));
            return { action: 'set_brightness', payload: { brightness }, optimisticState: { on: brightness > 0, brightness } };
        }
    }
    if (namespace === 'Alexa.ColorController' && name === 'SetColor') {
        const color = payload.color || {};
        const hue = Number(color.hue) || 0;
        const saturation = Number(color.saturation) || 0;
        return {
            action: 'set_color',
            payload: { hs_color: [hue, Math.round(saturation * 100)] },
            optimisticState: { on: true, hs_color: [hue, Math.round(saturation * 100)] }
        };
    }
    if (namespace === 'Alexa.ColorTemperatureController' && name === 'SetColorTemperature') {
        const kelvin = Number(payload.colorTemperatureInKelvin) || 3000;
        return {
            action: 'set_color_temp',
            payload: { color_temp_kelvin: kelvin },
            optimisticState: { on: true, color_temp_kelvin: kelvin }
        };
    }
    if (namespace === 'Alexa.RangeController') {
        return translateRangeController(name, instance, payload, row);
    }
    if (namespace === 'Alexa.ModeController') {
        return translateModeController(name, instance, payload);
    }
    if (namespace === 'Alexa.ToggleController') {
        return translateToggleController(name, instance);
    }
    if (namespace === 'Alexa.ThermostatController') {
        return translateThermostatController(name, payload, row);
    }
    if (namespace === 'Alexa.PlaybackController') {
        return translatePlaybackController(name);
    }
    if (namespace === 'Alexa.Speaker') {
        return translateSpeaker(name, payload, row);
    }
    if (namespace === 'Alexa.InputController') {
        return translateInputController(payload);
    }
    return { action: null };
}

// PlaybackController: Play/Pause/Stop/Next/Previous (no instance, no payload).
function translatePlaybackController(name) {
    switch (name) {
        case 'Play':
            return { action: 'media_resume', payload: {}, optimisticState: { is_playing: true, is_paused: false, on: true } };
        case 'Pause':
            return { action: 'media_pause', payload: {}, optimisticState: { is_playing: false, is_paused: true } };
        case 'Stop':
            return { action: 'media_stop', payload: {}, optimisticState: { is_playing: false, is_paused: false } };
        case 'Next':
            return { action: 'media_next', payload: {}, optimisticState: {} };
        case 'Previous':
            return { action: 'media_previous', payload: {}, optimisticState: {} };
        default:
            return { action: null };
    }
}

// Speaker: SetVolume / AdjustVolume / SetMute.
function translateSpeaker(name, payload, row) {
    const state = utils.parseJsonSafe(row?.state_json, {}) || {};
    if (name === 'SetVolume') {
        const volume = clampPercent(payload.volume);
        return { action: 'set_volume', payload: { volume }, optimisticState: { volume } };
    }
    if (name === 'AdjustVolume') {
        const volume = clampPercent((Number(state.volume) || 0) + (Number(payload.volume) || 0));
        return { action: 'set_volume', payload: { volume }, optimisticState: { volume } };
    }
    if (name === 'SetMute') {
        const muted = Boolean(payload.mute);
        return { action: 'set_mute', payload: { muted }, optimisticState: { muted } };
    }
    return { action: null };
}

// InputController: SelectInput.
function translateInputController(payload) {
    const source = typeof payload.input === 'string' ? payload.input : '';
    if (!source) return { action: null };
    return { action: 'set_input', payload: { source }, optimisticState: { source } };
}

// Map an Alexa thermostatMode enum back to an HA hvac mode.
const ALEXA_TO_HA_THERMOSTAT_MODE = {
    HEAT: 'heat',
    COOL: 'cool',
    AUTO: 'heat_cool',
    ECO: 'auto',
    FAN: 'fan_only',
    DEHUMIDIFY: 'dry',
    OFF: 'off'
};

// ThermostatController: SetTargetTemperature / AdjustTargetTemperature /
// SetThermostatMode. water_heater entities route to a dedicated action; climate
// entities use the thermostat setpoint/range/mode actions.
function translateThermostatController(name, payload, row) {
    const entityId = row?.entity_id || '';
    const isWaterHeater = entityId.startsWith('water_heater.');
    const state = utils.parseJsonSafe(row?.state_json, {}) || {};

    if (name === 'SetThermostatMode') {
        const mode = ALEXA_TO_HA_THERMOSTAT_MODE[payload?.thermostatMode?.value] || 'off';
        return { action: 'set_thermostat_mode', payload: { mode }, optimisticState: { mode } };
    }

    if (name === 'SetTargetTemperature' || name === 'AdjustTargetTemperature') {
        // Dual setpoint (range) for climate auto/heat_cool.
        const lower = payload?.lowerSetpoint?.value;
        const upper = payload?.upperSetpoint?.value;
        if (!isWaterHeater && lower != null && upper != null) {
            return {
                action: 'set_thermostat_setpoint_range',
                payload: { target_temp_low: Number(lower), target_temp_high: Number(upper) },
                optimisticState: { target_temp_low: Number(lower), target_temp_high: Number(upper) }
            };
        }
        let temperature;
        if (name === 'AdjustTargetTemperature') {
            const current = Number(isWaterHeater ? state.target_temperature : state.target_temperature) || 0;
            temperature = current + (Number(payload?.targetSetpointDelta?.value) || 0);
        } else {
            temperature = Number(payload?.targetSetpoint?.value) || 0;
        }
        if (isWaterHeater) {
            return { action: 'set_water_heater_temperature', payload: { temperature }, optimisticState: { target_temperature: temperature } };
        }
        return { action: 'set_thermostat_setpoint', payload: { temperature }, optimisticState: { target_temperature: temperature } };
    }
    return { action: null };
}

// The set of namespaces handled by the generic stateful control path (i.e. all
// control directives EXCEPT SceneController, which uses a bespoke envelope).
const CONTROL_NAMESPACES = [
    'Alexa.PowerController',
    'Alexa.BrightnessController',
    'Alexa.ColorController',
    'Alexa.ColorTemperatureController',
    'Alexa.LockController',
    'Alexa.RangeController',
    'Alexa.ModeController',
    'Alexa.ToggleController',
    'Alexa.ThermostatController',
    'Alexa.PlaybackController',
    'Alexa.Speaker',
    'Alexa.InputController'
];

module.exports = {
    translateControlDirective,
    CONTROL_NAMESPACES
};
