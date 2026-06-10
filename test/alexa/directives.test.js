const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { translateControlDirective, CONTROL_NAMESPACES } = require('../../lib/alexa/directives');

// Build a directive envelope. `instance` lands in header (instanced controllers).
function directive(namespace, name, { payload = {}, instance } = {}) {
    const header = { namespace, name };
    if (instance) header.instance = instance;
    return { header, payload };
}

const row = (state) => ({ state_json: JSON.stringify(state || {}) });

describe('translateControlDirective — basic controllers', () => {
    it('PowerController TurnOn/TurnOff', () => {
        assert.deepEqual(translateControlDirective('Alexa.PowerController', 'TurnOn', directive('Alexa.PowerController', 'TurnOn'), row()), {
            action: 'turn_on',
            payload: { on: true },
            optimisticState: { on: true }
        });
        assert.equal(translateControlDirective('Alexa.PowerController', 'TurnOff', directive('Alexa.PowerController', 'TurnOff'), row()).action, 'turn_off');
    });

    it('LockController Lock/Unlock', () => {
        assert.deepEqual(translateControlDirective('Alexa.LockController', 'Lock', directive('Alexa.LockController', 'Lock'), row()), {
            action: 'set_lock',
            payload: { lock: true },
            optimisticState: { isLocked: true }
        });
        assert.equal(translateControlDirective('Alexa.LockController', 'Unlock', directive('Alexa.LockController', 'Unlock'), row()).payload.lock, false);
    });

    it('BrightnessController SetBrightness + AdjustBrightness uses current state', () => {
        const set = translateControlDirective('Alexa.BrightnessController', 'SetBrightness', directive('Alexa.BrightnessController', 'SetBrightness', { payload: { brightness: 40 } }), row());
        assert.equal(set.payload.brightness, 40);
        const adj = translateControlDirective('Alexa.BrightnessController', 'AdjustBrightness', directive('Alexa.BrightnessController', 'AdjustBrightness', { payload: { brightnessDelta: -15 } }), row({ brightness: 50 }));
        assert.equal(adj.payload.brightness, 35);
    });

    it('Color + ColorTemperature', () => {
        const color = translateControlDirective('Alexa.ColorController', 'SetColor', directive('Alexa.ColorController', 'SetColor', { payload: { color: { hue: 120, saturation: 0.5, brightness: 1 } } }), row());
        assert.deepEqual(color.payload.hs_color, [120, 50]);
        const temp = translateControlDirective('Alexa.ColorTemperatureController', 'SetColorTemperature', directive('Alexa.ColorTemperatureController', 'SetColorTemperature', { payload: { colorTemperatureInKelvin: 4200 } }), row());
        assert.equal(temp.payload.color_temp_kelvin, 4200);
    });
});

describe('translateControlDirective — instanced fan controllers (Phase 4)', () => {
    it('RangeController Fan.Speed SetRangeValue (absolute)', () => {
        const r = translateControlDirective('Alexa.RangeController', 'SetRangeValue', directive('Alexa.RangeController', 'SetRangeValue', { instance: 'Fan.Speed', payload: { rangeValue: 75 } }), row({ percentage: 20 }));
        assert.deepEqual(r, { action: 'set_fan_speed_percent', payload: { percentage: 75 }, optimisticState: { on: true, percentage: 75 } });
    });

    it('RangeController Fan.Speed AdjustRangeValue (delta against current state)', () => {
        const r = translateControlDirective('Alexa.RangeController', 'AdjustRangeValue', directive('Alexa.RangeController', 'AdjustRangeValue', { instance: 'Fan.Speed', payload: { rangeValueDelta: -30 } }), row({ percentage: 50 }));
        assert.equal(r.payload.percentage, 20);
    });

    it('ToggleController Fan.Oscillate TurnOn/TurnOff', () => {
        assert.deepEqual(translateControlDirective('Alexa.ToggleController', 'TurnOn', directive('Alexa.ToggleController', 'TurnOn', { instance: 'Fan.Oscillate' }), row()), {
            action: 'set_fan_oscillate',
            payload: { on: true },
            optimisticState: { oscillating: true }
        });
        assert.equal(translateControlDirective('Alexa.ToggleController', 'TurnOff', directive('Alexa.ToggleController', 'TurnOff', { instance: 'Fan.Oscillate' }), row()).payload.on, false);
    });

    it('ModeController Fan.PresetMode + Fan.Direction route by instance', () => {
        const preset = translateControlDirective('Alexa.ModeController', 'SetMode', directive('Alexa.ModeController', 'SetMode', { instance: 'Fan.PresetMode', payload: { mode: 'eco' } }), row());
        assert.deepEqual(preset, { action: 'set_fan_preset', payload: { preset_mode: 'eco' }, optimisticState: { on: true, preset_mode: 'eco' } });
        const dir = translateControlDirective('Alexa.ModeController', 'SetMode', directive('Alexa.ModeController', 'SetMode', { instance: 'Fan.Direction', payload: { mode: 'reverse' } }), row());
        assert.equal(dir.action, 'set_fan_direction');
        assert.equal(dir.payload.direction, 'reverse');
    });

    it('returns action:null for an unknown instance', () => {
        assert.equal(translateControlDirective('Alexa.RangeController', 'SetRangeValue', directive('Alexa.RangeController', 'SetRangeValue', { instance: 'Bogus.Thing', payload: { rangeValue: 1 } }), row()).action, null);
    });
});

describe('translateControlDirective — cover/valve (Phase 5)', () => {
    it('Cover.Position SetRangeValue → set_open_percent', () => {
        const r = translateControlDirective('Alexa.RangeController', 'SetRangeValue', directive('Alexa.RangeController', 'SetRangeValue', { instance: 'Cover.Position', payload: { rangeValue: 30 } }), row({ openPercent: 90 }));
        assert.deepEqual(r, { action: 'set_open_percent', payload: { openPercent: 30 }, optimisticState: { openPercent: 30 } });
    });

    it('Cover.Position AdjustRangeValue uses current openPercent', () => {
        const r = translateControlDirective('Alexa.RangeController', 'AdjustRangeValue', directive('Alexa.RangeController', 'AdjustRangeValue', { instance: 'Cover.Position', payload: { rangeValueDelta: -25 } }), row({ openPercent: 80 }));
        assert.equal(r.payload.openPercent, 55);
    });

    it('Cover.Tilt SetRangeValue → set_tilt', () => {
        const r = translateControlDirective('Alexa.RangeController', 'SetRangeValue', directive('Alexa.RangeController', 'SetRangeValue', { instance: 'Cover.Tilt', payload: { rangeValue: 45 } }), row({ tilt_position: 0 }));
        assert.equal(r.action, 'set_tilt');
        assert.equal(r.payload.tilt, 45);
    });

    it('Cover.Position ModeController Open/Closed → set_open_close', () => {
        const open = translateControlDirective('Alexa.ModeController', 'SetMode', directive('Alexa.ModeController', 'SetMode', { instance: 'Cover.Position', payload: { mode: 'Open' } }), row());
        assert.deepEqual(open, { action: 'set_open_close', payload: { open: true }, optimisticState: { openPercent: 100 } });
        const closed = translateControlDirective('Alexa.ModeController', 'SetMode', directive('Alexa.ModeController', 'SetMode', { instance: 'Cover.Position', payload: { mode: 'Closed' } }), row());
        assert.equal(closed.payload.open, false);
    });

    it('Valve.Position range → set_valve_position, mode → set_valve_open_close', () => {
        const range = translateControlDirective('Alexa.RangeController', 'SetRangeValue', directive('Alexa.RangeController', 'SetRangeValue', { instance: 'Valve.Position', payload: { rangeValue: 60 } }), row({ openPercent: 0 }));
        assert.equal(range.action, 'set_valve_position');
        assert.equal(range.payload.openPercent, 60);
        const mode = translateControlDirective('Alexa.ModeController', 'SetMode', directive('Alexa.ModeController', 'SetMode', { instance: 'Valve.Position', payload: { mode: 'Open' } }), row());
        assert.equal(mode.action, 'set_valve_open_close');
        assert.equal(mode.payload.open, true);
    });
});

describe('translateControlDirective — select (Phase 7)', () => {
    it('Select.Option SetMode → set_select_option', () => {
        const r = translateControlDirective('Alexa.ModeController', 'SetMode', directive('Alexa.ModeController', 'SetMode', { instance: 'Select.Option', payload: { mode: 'comfort' } }), row());
        assert.deepEqual(r, { action: 'set_select_option', payload: { option: 'comfort' }, optimisticState: { current_option: 'comfort' } });
    });

    it('empty mode → action:null', () => {
        assert.equal(translateControlDirective('Alexa.ModeController', 'SetMode', directive('Alexa.ModeController', 'SetMode', { instance: 'Select.Option', payload: { mode: '' } }), row()).action, null);
    });
});

describe('translateControlDirective — humidifier/water_heater (Phase 8)', () => {
    it('Humidifier.Humidity range → set_humidity', () => {
        const r = translateControlDirective('Alexa.RangeController', 'SetRangeValue', directive('Alexa.RangeController', 'SetRangeValue', { instance: 'Humidifier.Humidity', payload: { rangeValue: 55 } }), row({ target_humidity: 40 }));
        assert.deepEqual(r, { action: 'set_humidity', payload: { humidity: 55 }, optimisticState: { target_humidity: 55 } });
    });

    it('Humidifier.Mode → set_humidifier_mode', () => {
        const r = translateControlDirective('Alexa.ModeController', 'SetMode', directive('Alexa.ModeController', 'SetMode', { instance: 'Humidifier.Mode', payload: { mode: 'baby' } }), row());
        assert.equal(r.action, 'set_humidifier_mode');
        assert.equal(r.payload.mode, 'baby');
    });

    it('water_heater ThermostatController SetTargetTemperature → set_water_heater_temperature', () => {
        const d = { header: { namespace: 'Alexa.ThermostatController', name: 'SetTargetTemperature' }, payload: { targetSetpoint: { value: 60, scale: 'CELSIUS' } } };
        const r = translateControlDirective('Alexa.ThermostatController', 'SetTargetTemperature', d, { entity_id: 'water_heater.tank', state_json: '{}' });
        assert.equal(r.action, 'set_water_heater_temperature');
        assert.equal(r.payload.temperature, 60);
    });
});

describe('translateControlDirective — climate (Phase 9)', () => {
    const climateRow = { entity_id: 'climate.hall', state_json: JSON.stringify({ target_temperature: 21 }) };

    it('SetTargetTemperature (single) → set_thermostat_setpoint', () => {
        const d = { header: { namespace: 'Alexa.ThermostatController', name: 'SetTargetTemperature' }, payload: { targetSetpoint: { value: 23 } } };
        const r = translateControlDirective('Alexa.ThermostatController', 'SetTargetTemperature', d, climateRow);
        assert.equal(r.action, 'set_thermostat_setpoint');
        assert.equal(r.payload.temperature, 23);
    });

    it('SetTargetTemperature (dual) → set_thermostat_setpoint_range', () => {
        const d = { header: { namespace: 'Alexa.ThermostatController', name: 'SetTargetTemperature' }, payload: { lowerSetpoint: { value: 18 }, upperSetpoint: { value: 25 } } };
        const r = translateControlDirective('Alexa.ThermostatController', 'SetTargetTemperature', d, climateRow);
        assert.equal(r.action, 'set_thermostat_setpoint_range');
        assert.deepEqual(r.payload, { target_temp_low: 18, target_temp_high: 25 });
    });

    it('SetThermostatMode AUTO → heat_cool', () => {
        const d = { header: { namespace: 'Alexa.ThermostatController', name: 'SetThermostatMode' }, payload: { thermostatMode: { value: 'AUTO' } } };
        const r = translateControlDirective('Alexa.ThermostatController', 'SetThermostatMode', d, climateRow);
        assert.equal(r.action, 'set_thermostat_mode');
        assert.equal(r.payload.mode, 'heat_cool');
    });

    it('fan/preset/swing ModeControllers route by instance', () => {
        const mk = (instance, mode) => translateControlDirective('Alexa.ModeController', 'SetMode', directive('Alexa.ModeController', 'SetMode', { instance, payload: { mode } }), climateRow);
        assert.equal(mk('Climate.FanMode', 'low').action, 'set_climate_fan_mode');
        assert.equal(mk('Climate.PresetMode', 'away').action, 'set_climate_preset_mode');
        assert.equal(mk('Climate.SwingMode', 'vertical').action, 'set_climate_swing_mode');
    });
});

describe('translateControlDirective — vacuum/lawn_mower (Phase 10)', () => {
    const mk = (instance, mode) => translateControlDirective('Alexa.ModeController', 'SetMode', directive('Alexa.ModeController', 'SetMode', { instance, payload: { mode } }), row());

    it('Vacuum.Mode Clean/Pause/Dock map to start/pause/dock', () => {
        assert.equal(mk('Vacuum.Mode', 'Clean').action, 'set_start_stop');
        assert.equal(mk('Vacuum.Mode', 'Clean').payload.start, true);
        assert.equal(mk('Vacuum.Mode', 'Pause').action, 'set_pause');
        assert.equal(mk('Vacuum.Mode', 'Dock').action, 'dock');
    });

    it('Vacuum.Suction → set_vacuum_fan_speed', () => {
        assert.equal(mk('Vacuum.Suction', 'high').action, 'set_vacuum_fan_speed');
        assert.equal(mk('Vacuum.Suction', 'high').payload.fan_speed, 'high');
    });

    it('Mower.State Mow/Pause/Dock map to lawn_mower_*', () => {
        assert.equal(mk('Mower.State', 'Mow').action, 'lawn_mower_start');
        assert.equal(mk('Mower.State', 'Pause').action, 'lawn_mower_pause');
        assert.equal(mk('Mower.State', 'Dock').action, 'lawn_mower_dock');
    });
});

describe('translateControlDirective — media_player (Phase 11)', () => {
    it('PlaybackController Play/Pause/Stop/Next/Previous', () => {
        const mk = (name) => translateControlDirective('Alexa.PlaybackController', name, directive('Alexa.PlaybackController', name), row());
        assert.equal(mk('Play').action, 'media_resume');
        assert.equal(mk('Pause').action, 'media_pause');
        assert.equal(mk('Stop').action, 'media_stop');
        assert.equal(mk('Next').action, 'media_next');
        assert.equal(mk('Previous').action, 'media_previous');
    });

    it('Speaker SetVolume / AdjustVolume / SetMute', () => {
        const set = translateControlDirective('Alexa.Speaker', 'SetVolume', directive('Alexa.Speaker', 'SetVolume', { payload: { volume: 40 } }), row());
        assert.deepEqual(set, { action: 'set_volume', payload: { volume: 40 }, optimisticState: { volume: 40 } });
        const adj = translateControlDirective('Alexa.Speaker', 'AdjustVolume', directive('Alexa.Speaker', 'AdjustVolume', { payload: { volume: -10 } }), row({ volume: 50 }));
        assert.equal(adj.payload.volume, 40);
        const mute = translateControlDirective('Alexa.Speaker', 'SetMute', directive('Alexa.Speaker', 'SetMute', { payload: { mute: true } }), row());
        assert.equal(mute.action, 'set_mute');
        assert.equal(mute.payload.muted, true);
    });

    it('InputController SelectInput → set_input', () => {
        const r = translateControlDirective('Alexa.InputController', 'SelectInput', directive('Alexa.InputController', 'SelectInput', { payload: { input: 'HDMI2' } }), row());
        assert.deepEqual(r, { action: 'set_input', payload: { source: 'HDMI2' }, optimisticState: { source: 'HDMI2' } });
    });
});

describe('CONTROL_NAMESPACES', () => {
    it('includes the instanced controllers but not SceneController', () => {
        assert.ok(CONTROL_NAMESPACES.includes('Alexa.RangeController'));
        assert.ok(CONTROL_NAMESPACES.includes('Alexa.ModeController'));
        assert.ok(CONTROL_NAMESPACES.includes('Alexa.ToggleController'));
        assert.ok(!CONTROL_NAMESPACES.includes('Alexa.SceneController'));
    });
});
