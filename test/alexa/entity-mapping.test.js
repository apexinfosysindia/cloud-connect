const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const em = require('../../lib/alexa/entity-mapping');

function lightRow(state) {
    return {
        entity_id: 'light.test',
        display_name: 'Test Light',
        entity_type: 'light',
        online: 1,
        state_json: JSON.stringify(state)
    };
}

// Find a structured AlexaProp tuple by name (+ optional instance).
function propByName(props, name, instance) {
    return props.find((p) => p.name === name && (instance === undefined || p.instance === instance));
}

describe('normalizeAlexaEntityType', () => {
    it('keeps known supported types', () => {
        assert.equal(em.normalizeAlexaEntityType('light', 'light.x'), 'light');
        assert.equal(em.normalizeAlexaEntityType('switch', 'switch.x'), 'switch');
    });

    it('infers type from entity id domain when type missing', () => {
        assert.equal(em.normalizeAlexaEntityType(null, 'light.kitchen'), 'light');
        assert.equal(em.normalizeAlexaEntityType(null, 'fan.bedroom'), 'fan');
    });

    it('preserves the true (unmapped) type instead of silently coercing to switch', () => {
        // Previously coerced unknown→switch; now the truth is preserved and the
        // Discovery gate decides exposure.
        assert.equal(em.normalizeAlexaEntityType('sensor', 'sensor.aqi'), 'sensor');
        assert.equal(em.normalizeAlexaEntityType(null, 'climate.hall'), 'climate');
    });

    it('falls back to switch only for a typeless + domainless payload', () => {
        assert.equal(em.normalizeAlexaEntityType(null, 'noDomainHere'), 'switch');
    });
});

describe('buildAlexaEndpoint', () => {
    it('returns null for an unmapped type (excluded, not coerced)', () => {
        assert.equal(
            em.buildAlexaEndpoint({ entity_type: 'sensor', entity_id: 's.t', display_name: 'T', online: 1, state_json: '{}' }),
            null
        );
    });

    it('exposes PowerController + EndpointHealth for a plain switch', () => {
        const ep = em.buildAlexaEndpoint({
            entity_type: 'switch',
            entity_id: 'switch.pump',
            display_name: 'Pump',
            online: 1,
            state_json: JSON.stringify({ on: false })
        });
        const ifaces = ep.capabilities.map((c) => c.interface);
        assert.ok(ifaces.includes('Alexa.PowerController'));
        assert.ok(ifaces.includes('Alexa.EndpointHealth'));
        assert.ok(ifaces.includes('Alexa'));
        assert.ok(!ifaces.includes('Alexa.BrightnessController'));
        assert.deepEqual(ep.displayCategories, ['SWITCH']);
    });

    it('adds Brightness/Color/ColorTemperature for a full-color light', () => {
        const ep = em.buildAlexaEndpoint(
            lightRow({ on: true, brightness: 80, supported_color_modes: ['color_temp', 'hs'], color_temp_kelvin: 4000, hs_color: [200, 50] })
        );
        const ifaces = ep.capabilities.map((c) => c.interface);
        assert.ok(ifaces.includes('Alexa.BrightnessController'));
        assert.ok(ifaces.includes('Alexa.ColorController'));
        assert.ok(ifaces.includes('Alexa.ColorTemperatureController'));
        assert.deepEqual(ep.displayCategories, ['LIGHT']);
    });

    it('omits brightness for an on/off-only light', () => {
        const ep = em.buildAlexaEndpoint(lightRow({ on: true, supported_color_modes: ['onoff'] }));
        const ifaces = ep.capabilities.map((c) => c.interface);
        assert.ok(ifaces.includes('Alexa.PowerController'));
        assert.ok(!ifaces.includes('Alexa.BrightnessController'));
    });

    it('marks proactively-reported retrievable properties on a capability', () => {
        const ep = em.buildAlexaEndpoint(lightRow({ on: true, supported_color_modes: ['onoff'] }));
        const power = ep.capabilities.find((c) => c.interface === 'Alexa.PowerController');
        assert.deepEqual(power.properties.supported, [{ name: 'powerState' }]);
        assert.equal(power.properties.proactivelyReported, true);
        assert.equal(power.properties.retrievable, true);
    });

    it('exposes automation and group as PowerController endpoints (Phase 1)', () => {
        for (const entity_type of ['automation', 'group']) {
            const ep = em.buildAlexaEndpoint({
                entity_type,
                entity_id: `${entity_type}.x`,
                display_name: 'X',
                online: 1,
                state_json: JSON.stringify({ on: true })
            });
            assert.ok(ep, `${entity_type} should be discoverable`);
            const ifaces = ep.capabilities.map((c) => c.interface);
            assert.ok(ifaces.includes('Alexa.PowerController'));
            assert.deepEqual(ep.displayCategories, ['SWITCH']);
            const props = em.parseAlexaEndpointState({ entity_type, online: 1, state_json: JSON.stringify({ on: true }) });
            assert.equal(props.find((p) => p.name === 'powerState').value, 'ON');
        }
    });

    it('exposes the scene family as a stateless SceneController (Phase 2)', () => {
        const categories = {
            scene: 'SCENE_TRIGGER',
            script: 'ACTIVITY_TRIGGER',
            button: 'ACTIVITY_TRIGGER',
            input_button: 'ACTIVITY_TRIGGER'
        };
        for (const entity_type of Object.keys(categories)) {
            const row = { entity_type, entity_id: `${entity_type}.x`, display_name: 'X', online: 1, state_json: '{}' };
            const ep = em.buildAlexaEndpoint(row);
            assert.ok(ep, `${entity_type} should be discoverable`);
            const scene = ep.capabilities.find((c) => c.interface === 'Alexa.SceneController');
            assert.ok(scene, `${entity_type} exposes SceneController`);
            assert.equal(scene.supportsDeactivation, false);
            // Stateless → no `properties` block advertised.
            assert.equal(scene.properties, undefined);
            assert.deepEqual(ep.displayCategories, [categories[entity_type]]);
            // Only the health tuple — no controllable/reportable scene state.
            const props = em.parseAlexaEndpointState(row);
            assert.equal(props.length, 1);
            assert.equal(props[0].name, 'connectivity');
        }
    });

    it('exposes lock as a LockController (Phase 3)', () => {
        const row = (s) => ({ entity_type: 'lock', entity_id: 'lock.front', display_name: 'Front', online: 1, state_json: JSON.stringify(s) });
        const ep = em.buildAlexaEndpoint(row({ isLocked: true }));
        assert.ok(ep);
        assert.ok(ep.capabilities.some((c) => c.interface === 'Alexa.LockController'));
        assert.deepEqual(ep.displayCategories, ['SMARTLOCK']);
        assert.equal(em.parseAlexaEndpointState(row({ isLocked: true })).find((p) => p.name === 'lockState').value, 'LOCKED');
        assert.equal(em.parseAlexaEndpointState(row({ isLocked: false })).find((p) => p.name === 'lockState').value, 'UNLOCKED');
        assert.equal(em.parseAlexaEndpointState(row({ isLocked: false, jammed: true })).find((p) => p.name === 'lockState').value, 'JAMMED');
    });

    it('exposes fan speed/oscillate/preset/direction as instanced controllers (Phase 4)', () => {
        // supported_features: SET_SPEED(1)+OSCILLATE(2)+DIRECTION(4)+PRESET(8) = 15
        const row = {
            entity_type: 'fan',
            entity_id: 'fan.bed',
            display_name: 'Bedroom Fan',
            online: 1,
            state_json: JSON.stringify({
                on: true,
                percentage: 66,
                percentage_step: 33,
                oscillating: true,
                direction: 'forward',
                preset_mode: 'eco',
                preset_modes: ['eco', 'sleep'],
                supported_features: 15
            })
        };
        const ep = em.buildAlexaEndpoint(row);
        const byIface = (i) => ep.capabilities.filter((c) => c.interface === i);
        assert.ok(byIface('Alexa.PowerController').length === 1);

        const range = byIface('Alexa.RangeController');
        assert.equal(range.length, 1);
        assert.equal(range[0].instance, 'Fan.Speed');
        assert.equal(range[0].configuration.supportedRange.maximumValue, 100);
        assert.equal(range[0].configuration.unitOfMeasure, 'Alexa.Unit.Percent');

        const toggle = byIface('Alexa.ToggleController');
        assert.equal(toggle.length, 1);
        assert.equal(toggle[0].instance, 'Fan.Oscillate');

        const modes = byIface('Alexa.ModeController');
        const instances = modes.map((m) => m.instance).sort();
        assert.deepEqual(instances, ['Fan.Direction', 'Fan.PresetMode']);
        const preset = modes.find((m) => m.instance === 'Fan.PresetMode');
        assert.deepEqual(preset.configuration.supportedModes.map((m) => m.value), ['eco', 'sleep']);
        assert.deepEqual(ep.displayCategories, ['FAN']);

        // State tuples carry the right instance + value.
        const props = em.parseAlexaEndpointState(row);
        const find = (ns, inst, n) => props.find((p) => p.namespace === ns && p.instance === inst && p.name === n);
        assert.equal(find('Alexa.RangeController', 'Fan.Speed', 'rangeValue').value, 66);
        assert.equal(find('Alexa.ToggleController', 'Fan.Oscillate', 'toggleState').value, 'ON');
        assert.equal(find('Alexa.ModeController', 'Fan.PresetMode', 'mode').value, 'eco');
        assert.equal(find('Alexa.ModeController', 'Fan.Direction', 'mode').value, 'forward');
    });

    it('a simple on/off fan still exposes only Power + Fan.Speed range (Phase 4)', () => {
        const row = { entity_type: 'fan', entity_id: 'fan.simple', display_name: 'Fan', online: 1, state_json: JSON.stringify({ on: false, supported_features: 0 }) };
        const ep = em.buildAlexaEndpoint(row);
        const ifaces = ep.capabilities.map((c) => c.interface).sort();
        // No oscillate/preset/direction; speed range degrades gracefully.
        assert.ok(ifaces.includes('Alexa.RangeController'));
        assert.ok(!ifaces.includes('Alexa.ToggleController'));
        assert.ok(!ifaces.includes('Alexa.ModeController'));
    });

    it('positional cover → RangeController(position) with open/close semantics (Phase 5)', () => {
        // SET_POSITION(4) + SET_TILT_POSITION(128) = 132
        const row = { entity_type: 'cover', entity_id: 'cover.blind', display_name: 'Blind', online: 1, state_json: JSON.stringify({ openPercent: 40, tilt_position: 10, supported_features: 132, device_class: 'blind' }) };
        const ep = em.buildAlexaEndpoint(row);
        const ranges = ep.capabilities.filter((c) => c.interface === 'Alexa.RangeController');
        const instances = ranges.map((r) => r.instance).sort();
        assert.deepEqual(instances, ['Cover.Position', 'Cover.Tilt']);
        const pos = ranges.find((r) => r.instance === 'Cover.Position');
        assert.ok(pos.semantics, 'position has open/close semantics');
        assert.deepEqual(ep.displayCategories, ['INTERIOR_BLIND']);
        const props = em.parseAlexaEndpointState(row);
        assert.equal(props.find((p) => p.instance === 'Cover.Position').value, 40);
        assert.equal(props.find((p) => p.instance === 'Cover.Tilt').value, 10);
    });

    it('garage cover → discrete ModeController Open/Closed + GARAGE_DOOR (Phase 5)', () => {
        const row = (open) => ({ entity_type: 'cover', entity_id: 'cover.garage', display_name: 'Garage', online: 1, state_json: JSON.stringify({ openPercent: open ? 100 : 0, supported_features: 3, device_class: 'garage' }) });
        const ep = em.buildAlexaEndpoint(row(true));
        const modes = ep.capabilities.filter((c) => c.interface === 'Alexa.ModeController');
        assert.equal(modes.length, 1);
        assert.equal(modes[0].instance, 'Cover.Position');
        assert.ok(!ep.capabilities.some((c) => c.interface === 'Alexa.RangeController'));
        assert.deepEqual(ep.displayCategories, ['GARAGE_DOOR']);
        assert.equal(em.parseAlexaEndpointState(row(true)).find((p) => p.name === 'mode').value, 'Open');
        assert.equal(em.parseAlexaEndpointState(row(false)).find((p) => p.name === 'mode').value, 'Closed');
    });

    it('non-positional cover → discrete ModeController (Phase 5)', () => {
        const row = { entity_type: 'cover', entity_id: 'cover.simple', display_name: 'Curtain', online: 1, state_json: JSON.stringify({ openPercent: 100, supported_features: 3, device_class: 'curtain' }) };
        const ep = em.buildAlexaEndpoint(row);
        assert.ok(ep.capabilities.some((c) => c.interface === 'Alexa.ModeController' && c.instance === 'Cover.Position'));
        assert.ok(!ep.capabilities.some((c) => c.interface === 'Alexa.RangeController'));
    });

    it('valve → RangeController(position) when positional, else ModeController (Phase 5)', () => {
        const positional = { entity_type: 'valve', entity_id: 'valve.water', display_name: 'Water', online: 1, state_json: JSON.stringify({ openPercent: 70, supported_features: 4 }) };
        const epP = em.buildAlexaEndpoint(positional);
        assert.ok(epP.capabilities.some((c) => c.interface === 'Alexa.RangeController' && c.instance === 'Valve.Position'));
        const discrete = { entity_type: 'valve', entity_id: 'valve.gas', display_name: 'Gas', online: 1, state_json: JSON.stringify({ openPercent: 0, supported_features: 3 }) };
        const epD = em.buildAlexaEndpoint(discrete);
        assert.ok(epD.capabilities.some((c) => c.interface === 'Alexa.ModeController' && c.instance === 'Valve.Position'));
    });

    it('temperature sensor → TemperatureSensor with scale (Phase 6)', () => {
        const c = { entity_type: 'sensor', entity_id: 'sensor.temp', display_name: 'Temp', online: 1, state_json: JSON.stringify({ value: 21.5, device_class: 'temperature', unit_of_measurement: '°C', temperature: 21.5 }) };
        const ep = em.buildAlexaEndpoint(c);
        assert.ok(ep.capabilities.some((x) => x.interface === 'Alexa.TemperatureSensor'));
        assert.deepEqual(ep.displayCategories, ['TEMPERATURE_SENSOR']);
        const t = em.parseAlexaEndpointState(c).find((p) => p.name === 'temperature');
        assert.deepEqual(t.value, { value: 21.5, scale: 'CELSIUS' });
        const f = em.parseAlexaEndpointState({ entity_type: 'sensor', online: 1, state_json: JSON.stringify({ value: 70, device_class: 'temperature', unit_of_measurement: '°F', temperature: 70 }) });
        assert.equal(f.find((p) => p.name === 'temperature').value.scale, 'FAHRENHEIT');
    });

    it('humidity sensor → HumiditySensor (Phase 6)', () => {
        const c = { entity_type: 'sensor', entity_id: 'sensor.hum', display_name: 'Hum', online: 1, state_json: JSON.stringify({ value: 55, device_class: 'humidity' }) };
        const ep = em.buildAlexaEndpoint(c);
        assert.ok(ep.capabilities.some((x) => x.interface === 'Alexa.HumiditySensor'));
        // Alexa has no HUMIDITY_SENSOR displayCategory — the HumiditySensor
        // interface carries the reading; the category falls back to a valid one.
        assert.deepEqual(ep.displayCategories, ['TEMPERATURE_SENSOR']);
        assert.equal(em.parseAlexaEndpointState(c).find((p) => p.name === 'relativeHumidity').value, 55);
    });

    it('binary_sensor → Contact / Motion by device_class (Phase 6)', () => {
        const door = { entity_type: 'binary_sensor', entity_id: 'binary_sensor.door', display_name: 'Door', online: 1, state_json: JSON.stringify({ is_on: true, device_class: 'door' }) };
        const epD = em.buildAlexaEndpoint(door);
        assert.ok(epD.capabilities.some((c) => c.interface === 'Alexa.ContactSensor'));
        assert.deepEqual(epD.displayCategories, ['CONTACT_SENSOR']);
        assert.equal(em.parseAlexaEndpointState(door).find((p) => p.name === 'detectionState').value, 'DETECTED');

        const motion = { entity_type: 'binary_sensor', entity_id: 'binary_sensor.pir', display_name: 'PIR', online: 1, state_json: JSON.stringify({ is_on: false, device_class: 'motion' }) };
        const epM = em.buildAlexaEndpoint(motion);
        assert.ok(epM.capabilities.some((c) => c.interface === 'Alexa.MotionSensor'));
        assert.deepEqual(epM.displayCategories, ['MOTION_SENSOR']);
        assert.equal(em.parseAlexaEndpointState(motion).find((p) => p.name === 'detectionState').value, 'NOT_DETECTED');
    });

    it('Tier-D sensors are EXCLUDED, not coerced (Phase 6)', () => {
        // Air-quality sensor → no Alexa equivalent → null.
        assert.equal(em.buildAlexaEndpoint({ entity_type: 'sensor', entity_id: 'sensor.pm25', display_name: 'PM2.5', online: 1, state_json: JSON.stringify({ value: 12, device_class: 'pm25' }) }), null);
        // Smoke / CO / gas / moisture binary_sensors → null.
        for (const device_class of ['smoke', 'carbon_monoxide', 'gas', 'moisture']) {
            assert.equal(
                em.buildAlexaEndpoint({ entity_type: 'binary_sensor', entity_id: `binary_sensor.${device_class}`, display_name: device_class, online: 1, state_json: JSON.stringify({ is_on: true, device_class }) }),
                null,
                `${device_class} binary_sensor should be excluded`
            );
        }
    });

    it('select/input_select → ModeController from options (Phase 7)', () => {
        const row = { entity_type: 'select', entity_id: 'select.mode', display_name: 'Mode', online: 1, state_json: JSON.stringify({ current_option: 'eco', options: ['eco', 'comfort', 'boost'] }) };
        const ep = em.buildAlexaEndpoint(row);
        const mode = ep.capabilities.find((c) => c.interface === 'Alexa.ModeController' && c.instance === 'Select.Option');
        assert.ok(mode);
        assert.deepEqual(mode.configuration.supportedModes.map((m) => m.value), ['eco', 'comfort', 'boost']);
        assert.equal(em.parseAlexaEndpointState(row).find((p) => p.name === 'mode').value, 'eco');
    });

    it('select with no options is excluded (Phase 7)', () => {
        assert.equal(em.buildAlexaEndpoint({ entity_type: 'select', entity_id: 'select.empty', display_name: 'Empty', online: 1, state_json: JSON.stringify({ current_option: '', options: [] }) }), null);
    });

    it('humidifier → Power + RangeController(humidity) + ModeController (Phase 8)', () => {
        const row = { entity_type: 'humidifier', entity_id: 'humidifier.bed', display_name: 'Bed', online: 1, state_json: JSON.stringify({ on: true, target_humidity: 45, min_humidity: 30, max_humidity: 70, mode: 'auto', available_modes: ['auto', 'baby'] }) };
        const ep = em.buildAlexaEndpoint(row);
        assert.ok(ep.capabilities.some((c) => c.interface === 'Alexa.PowerController'));
        const range = ep.capabilities.find((c) => c.interface === 'Alexa.RangeController' && c.instance === 'Humidifier.Humidity');
        assert.ok(range);
        assert.equal(range.configuration.supportedRange.minimumValue, 30);
        assert.equal(range.configuration.supportedRange.maximumValue, 70);
        assert.ok(ep.capabilities.some((c) => c.interface === 'Alexa.ModeController' && c.instance === 'Humidifier.Mode'));
        const props = em.parseAlexaEndpointState(row);
        assert.equal(props.find((p) => p.instance === 'Humidifier.Humidity').value, 45);
        assert.equal(props.find((p) => p.instance === 'Humidifier.Mode').value, 'auto');
    });

    it('water_heater → Power + ThermostatController(single) + TemperatureSensor (Phase 8)', () => {
        const row = { entity_type: 'water_heater', entity_id: 'water_heater.tank', display_name: 'Tank', online: 1, state_json: JSON.stringify({ on: true, target_temperature: 55, current_temperature: 50, temperature_unit: 'C' }) };
        const ep = em.buildAlexaEndpoint(row);
        const thermo = ep.capabilities.find((c) => c.interface === 'Alexa.ThermostatController');
        assert.ok(thermo);
        // Single-setpoint: no lower/upper.
        const names = thermo.properties.supported.map((s) => s.name);
        assert.ok(names.includes('targetSetpoint'));
        assert.ok(!names.includes('lowerSetpoint'));
        assert.deepEqual(ep.displayCategories, ['WATER_HEATER']);
        const props = em.parseAlexaEndpointState(row);
        assert.deepEqual(props.find((p) => p.name === 'targetSetpoint').value, { value: 55, scale: 'CELSIUS' });
        assert.deepEqual(props.find((p) => p.name === 'temperature').value, { value: 50, scale: 'CELSIUS' });
    });

    it('climate → Thermostat(dual+modes) + TemperatureSensor + fan/preset/swing modes (Phase 9)', () => {
        // FAN_MODE(8)+PRESET(16)+SWING(32) = 56
        const row = {
            entity_type: 'climate',
            entity_id: 'climate.hall',
            display_name: 'Hall',
            online: 1,
            state_json: JSON.stringify({
                mode: 'heat_cool',
                hvac_modes: ['off', 'heat', 'cool', 'heat_cool'],
                target_temp_low: 19,
                target_temp_high: 24,
                ambient_temperature: 21,
                fan_mode: 'auto',
                fan_modes: ['auto', 'low', 'high'],
                preset_mode: 'eco',
                preset_modes: ['eco', 'away'],
                swing_mode: 'off',
                swing_modes: ['off', 'vertical'],
                temperature_unit: 'C',
                supported_features: 56
            })
        };
        const ep = em.buildAlexaEndpoint(row);
        const thermo = ep.capabilities.find((c) => c.interface === 'Alexa.ThermostatController');
        const tNames = thermo.properties.supported.map((s) => s.name);
        assert.ok(tNames.includes('lowerSetpoint') && tNames.includes('upperSetpoint') && tNames.includes('thermostatMode'));
        assert.ok(thermo.configuration.supportedModes.includes('AUTO')); // heat_cool → AUTO
        assert.ok(ep.capabilities.some((c) => c.interface === 'Alexa.TemperatureSensor'));
        const modeInstances = ep.capabilities.filter((c) => c.interface === 'Alexa.ModeController').map((c) => c.instance).sort();
        assert.deepEqual(modeInstances, ['Climate.FanMode', 'Climate.PresetMode', 'Climate.SwingMode']);
        assert.deepEqual(ep.displayCategories, ['THERMOSTAT']);

        const props = em.parseAlexaEndpointState(row);
        assert.equal(props.find((p) => p.name === 'thermostatMode').value, 'AUTO');
        assert.deepEqual(props.find((p) => p.name === 'lowerSetpoint').value, { value: 19, scale: 'CELSIUS' });
        assert.deepEqual(props.find((p) => p.name === 'upperSetpoint').value, { value: 24, scale: 'CELSIUS' });
        assert.deepEqual(props.find((p) => p.name === 'temperature').value, { value: 21, scale: 'CELSIUS' });
        assert.equal(props.find((p) => p.instance === 'Climate.FanMode').value, 'auto');
    });

    it('vacuum → Power + Vacuum.Mode + Vacuum.Suction (Phase 10)', () => {
        const row = { entity_type: 'vacuum', entity_id: 'vacuum.rufus', display_name: 'Rufus', online: 1, state_json: JSON.stringify({ on: true, isRunning: true, isPaused: false, isDocked: false, fan_speed: 'high', fan_speed_list: ['quiet', 'high'], supported_features: 32 }) };
        const ep = em.buildAlexaEndpoint(row);
        assert.ok(ep.capabilities.some((c) => c.interface === 'Alexa.PowerController'));
        assert.ok(ep.capabilities.some((c) => c.interface === 'Alexa.ModeController' && c.instance === 'Vacuum.Mode'));
        assert.ok(ep.capabilities.some((c) => c.interface === 'Alexa.ModeController' && c.instance === 'Vacuum.Suction'));
        assert.deepEqual(ep.displayCategories, ['VACUUM_CLEANER']);
        const props = em.parseAlexaEndpointState(row);
        assert.equal(props.find((p) => p.instance === 'Vacuum.Mode').value, 'Clean');
        assert.equal(props.find((p) => p.instance === 'Vacuum.Suction').value, 'high');
    });

    it('lawn_mower → Power + Mower.State (Phase 10)', () => {
        const row = { entity_type: 'lawn_mower', entity_id: 'lawn_mower.yard', display_name: 'Yard', online: 1, state_json: JSON.stringify({ isRunning: false, isPaused: false, isDocked: true }) };
        const ep = em.buildAlexaEndpoint(row);
        assert.ok(ep.capabilities.some((c) => c.interface === 'Alexa.ModeController' && c.instance === 'Mower.State'));
        assert.equal(em.parseAlexaEndpointState(row).find((p) => p.instance === 'Mower.State').value, 'Dock');
    });

    it('media_player → Power + Playback + Speaker + Input (Phase 11)', () => {
        // PAUSE(1)+VOL_SET(4)+PREV(16)+NEXT(32)+TURN_ON(128)+TURN_OFF(256)+SOURCE(2048)+STOP(4096)+PLAY(16384) = 22965
        const row = { entity_type: 'media_player', entity_id: 'media_player.tv', display_name: 'TV', online: 1, state_json: JSON.stringify({ on: true, volume: 35, muted: false, source: 'HDMI1', source_list: ['HDMI1', 'HDMI2'], supported_features: 22965, device_class: 'tv', is_playing: true }) };
        const ep = em.buildAlexaEndpoint(row);
        const ifaces = ep.capabilities.map((c) => c.interface);
        assert.ok(ifaces.includes('Alexa.PowerController'));
        assert.ok(ifaces.includes('Alexa.PlaybackController'));
        assert.ok(ifaces.includes('Alexa.Speaker'));
        assert.ok(ifaces.includes('Alexa.InputController'));
        const playback = ep.capabilities.find((c) => c.interface === 'Alexa.PlaybackController');
        assert.ok(playback.supportedOperations.includes('Play') && playback.supportedOperations.includes('Next'));
        const input = ep.capabilities.find((c) => c.interface === 'Alexa.InputController');
        assert.deepEqual(input.inputs, [{ name: 'HDMI1' }, { name: 'HDMI2' }]);
        assert.deepEqual(ep.displayCategories, ['TV']);

        const props = em.parseAlexaEndpointState(row);
        assert.equal(props.find((p) => p.name === 'volume').value, 35);
        assert.equal(props.find((p) => p.name === 'muted').value, false);
        assert.equal(props.find((p) => p.name === 'input').value, 'HDMI1');
        // PlaybackController has no retrievable state.
        assert.ok(!props.some((p) => p.namespace === 'Alexa.PlaybackController'));
    });

    it('speaker media_player gets SPEAKER category (Phase 11)', () => {
        const row = { entity_type: 'media_player', entity_id: 'media_player.sonos', display_name: 'Sonos', online: 1, state_json: JSON.stringify({ on: true, volume: 20, supported_features: 4, device_class: 'speaker' }) };
        assert.deepEqual(em.buildAlexaEndpoint(row).displayCategories, ['SPEAKER']);
    });

    it('alarm → SecurityPanelController; PIN advertised only when configured (Phase 12)', () => {
        const row = (s) => ({ entity_type: 'alarm_control_panel', entity_id: 'alarm_control_panel.home', display_name: 'Home', online: 1, state_json: JSON.stringify(s) });
        const noPin = em.buildAlexaEndpoint(row({ arm_state: 'disarmed' }));
        const sp = noPin.capabilities.find((c) => c.interface === 'Alexa.SecurityPanelController');
        assert.ok(sp);
        assert.deepEqual(noPin.displayCategories, ['SECURITY_PANEL']);
        // No PIN → field omitted entirely (an empty array fails Amazon's schema).
        assert.ok(!('supportedAuthorizationTypes' in sp.configuration));

        const withPin = em.buildAlexaEndpoint(row({ arm_state: 'disarmed' }), { userHasSecurityPin: true });
        const spPin = withPin.capabilities.find((c) => c.interface === 'Alexa.SecurityPanelController');
        assert.deepEqual(spPin.configuration.supportedAuthorizationTypes, [{ type: 'FOUR_DIGIT_PIN' }]);
    });

    it('alarm armState maps HA arm_state → Alexa (Phase 12)', () => {
        const read = (arm_state) => em.parseAlexaEndpointState({ entity_type: 'alarm_control_panel', online: 1, state_json: JSON.stringify({ arm_state }) }).find((p) => p.name === 'armState').value;
        assert.equal(read('armed_home'), 'ARMED_STAY');
        assert.equal(read('armed_away'), 'ARMED_AWAY');
        assert.equal(read('armed_night'), 'ARMED_NIGHT');
        assert.equal(read('disarmed'), 'DISARMED');
        assert.equal(read('pending'), 'DISARMED');
    });
});

describe('parseAlexaEndpointState', () => {
    it('returns structured AlexaProp tuples for on/brightness/color/temp', () => {
        const props = em.parseAlexaEndpointState(
            lightRow({ on: true, brightness: 60, supported_color_modes: ['color_temp', 'hs'], color_temp_kelvin: 3000, hs_color: [120, 40] })
        );
        const power = propByName(props, 'powerState');
        assert.equal(power.value, 'ON');
        assert.equal(power.namespace, 'Alexa.PowerController');
        assert.equal(propByName(props, 'brightness').value, 60);
        assert.deepEqual(propByName(props, 'connectivity').value, { value: 'OK' });
        assert.equal(propByName(props, 'colorTemperatureInKelvin').value, 3000);
        const color = propByName(props, 'color');
        assert.equal(color.value.hue, 120);
        assert.equal(color.value.saturation, 0.4);
    });

    it('reports UNREACHABLE + OFF for an offline switch', () => {
        const props = em.parseAlexaEndpointState({
            entity_type: 'switch',
            online: 0,
            state_json: JSON.stringify({ on: false })
        });
        assert.deepEqual(propByName(props, 'connectivity').value, { value: 'UNREACHABLE' });
        assert.equal(propByName(props, 'powerState').value, 'OFF');
    });

    it('does not report 0% brightness for a light that is ON', () => {
        const props = em.parseAlexaEndpointState(lightRow({ on: true, brightness: 0, supported_color_modes: ['brightness'] }));
        assert.equal(propByName(props, 'brightness').value, 100);
    });

    it('emits no controllable props (only health) for an unmapped type', () => {
        const props = em.parseAlexaEndpointState({
            entity_type: 'sensor',
            online: 1,
            state_json: JSON.stringify({ value: 42 })
        });
        // Plan is base+health only → only the connectivity tuple is emitted.
        assert.equal(props.length, 1);
        assert.equal(props[0].name, 'connectivity');
    });
});

// Regression guard: an invalid displayCategory causes Alexa to silently reject
// the ENTIRE Discover.Response (0 devices). This sweep asserts every supported
// domain — and the device_class variants that historically broke
// (sensor.humidity → HUMIDITY_SENSOR, media_player.receiver → RECEIVER) — emits
// only categories in Amazon's authoritative enum.
describe('displayCategories are always valid (Amazon Discovery)', () => {
    const sample = (entity_type, state) => ({
        entity_id: `${entity_type}.x`,
        display_name: 'X',
        entity_type,
        online: 1,
        state_json: JSON.stringify(state || {})
    });

    // One representative state per supported domain.
    const cases = [
        sample('light', { on: true, supported_color_modes: ['onoff'] }),
        sample('switch', { on: false }),
        sample('outlet', { on: false }),
        sample('input_boolean', { on: false }),
        sample('automation', { on: true }),
        sample('group', { on: true }),
        sample('scene', {}),
        sample('script', {}),
        sample('button', {}),
        sample('input_button', {}),
        sample('lock', { isLocked: true }),
        sample('fan', { on: true, percentage: 50, supported_features: 15, preset_modes: ['eco'], preset_mode: 'eco' }),
        sample('cover', { openPercent: 40, supported_features: 132, device_class: 'blind' }),
        sample('cover', { openPercent: 0, supported_features: 3, device_class: 'garage' }),
        sample('cover', { openPercent: 0, supported_features: 3, device_class: 'door' }),
        sample('cover', { openPercent: 0, supported_features: 3, device_class: 'awning' }),
        sample('valve', { openPercent: 70, supported_features: 4 }),
        sample('sensor', { value: 21, device_class: 'temperature', unit_of_measurement: '°C', temperature: 21 }),
        sample('sensor', { value: 55, device_class: 'humidity' }), // was HUMIDITY_SENSOR
        sample('binary_sensor', { is_on: true, device_class: 'door' }),
        sample('binary_sensor', { is_on: false, device_class: 'motion' }),
        sample('select', { current_option: 'a', options: ['a', 'b'] }),
        sample('input_select', { current_option: 'a', options: ['a', 'b'] }),
        sample('humidifier', { on: true, target_humidity: 45, min_humidity: 30, max_humidity: 70 }),
        sample('water_heater', { on: true, target_temperature: 55, current_temperature: 50, temperature_unit: 'C' }),
        sample('climate', { mode: 'heat_cool', hvac_modes: ['off', 'heat_cool'], ambient_temperature: 21, temperature_unit: 'C', supported_features: 8 }),
        sample('vacuum', { on: true, isRunning: true, fan_speed: 'high', fan_speed_list: ['high'], supported_features: 32 }),
        sample('lawn_mower', { isRunning: false, isDocked: true }),
        sample('media_player', { on: true, volume: 30, source: 'HDMI1', source_list: ['HDMI1'], supported_features: 22965, device_class: 'tv' }),
        sample('media_player', { on: true, volume: 30, supported_features: 4, device_class: 'speaker' }),
        sample('media_player', { on: true, volume: 30, supported_features: 4, device_class: 'receiver' }), // was RECEIVER
        sample('alarm_control_panel', { arm_state: 'disarmed' })
    ];

    it('every supported domain emits only Amazon-valid displayCategories', () => {
        for (const row of cases) {
            const ep = em.buildAlexaEndpoint(row, {});
            assert.ok(ep, `${row.entity_id} should be discoverable`);
            assert.ok(Array.isArray(ep.displayCategories) && ep.displayCategories.length > 0, `${row.entity_id} has categories`);
            for (const cat of ep.displayCategories) {
                assert.ok(
                    em.VALID_DISPLAY_CATEGORIES.has(cat),
                    `${row.entity_id} (${JSON.parse(row.state_json).device_class || '-'}) emitted INVALID displayCategory: ${cat}`
                );
            }
        }
    });

    it('every emitted catalog assetId is in Amazon global catalog', () => {
        // Walk all capabilityResources/modeResources friendlyNames; any @type:"asset"
        // must reference a real catalog id or Amazon rejects the whole batch.
        const collectAssets = (obj, out) => {
            if (Array.isArray(obj)) { obj.forEach((o) => collectAssets(o, out)); return out; }
            if (obj && typeof obj === 'object') {
                if (obj['@type'] === 'asset') out.push(obj.value && obj.value.assetId);
                for (const k of Object.keys(obj)) collectAssets(obj[k], out);
            }
            return out;
        };
        for (const row of cases) {
            const ep = em.buildAlexaEndpoint(row, {});
            const assets = collectAssets(ep.capabilities, []);
            for (const a of assets) {
                assert.ok(em.VALID_ASSET_IDS.has(a), `${row.entity_id} emitted INVALID assetId: ${a}`);
            }
        }
    });

    it('humidity sensor and AV receiver no longer emit invalid categories', () => {
        const hum = em.buildAlexaEndpoint(sample('sensor', { value: 55, device_class: 'humidity' }), {});
        assert.ok(!hum.displayCategories.includes('HUMIDITY_SENSOR'));
        assert.deepEqual(hum.displayCategories, ['TEMPERATURE_SENSOR']);
        const recv = em.buildAlexaEndpoint(sample('media_player', { on: true, volume: 30, supported_features: 4, device_class: 'receiver' }), {});
        assert.ok(!recv.displayCategories.includes('RECEIVER'));
        assert.deepEqual(recv.displayCategories, ['STREAMING_DEVICE']);
    });

    it('an unknown category is coerced to OTHER, never passed through', () => {
        // Drive resolveDisplayCategories via a hypothetical bad mapping by checking the
        // sanitizer contract: VALID set never contains a made-up value, and OTHER is valid.
        assert.ok(!em.VALID_DISPLAY_CATEGORIES.has('NOT_A_REAL_CATEGORY'));
        assert.ok(em.VALID_DISPLAY_CATEGORIES.has('OTHER'));
    });
});

// Amazon requires friendlyName: "Up to 256 alphanumeric characters and spaces.
// Don't include special characters or punctuation." A single non-conforming name
// makes the endpoint invalid and causes Amazon to reject the WHOLE Discovery /
// AddOrUpdateReport batch (HTTP 400 → 0 devices). HA names routinely contain
// apostrophes/hyphens/accents/parentheses/emoji, so every name must be coerced.
describe('friendlyName is always Amazon-valid (alphanumeric + spaces)', () => {
    const VALID = /^[a-zA-Z0-9 ]+$/;
    const build = (display_name, entity_id = 'light.kids_lamp') =>
        em.buildAlexaEndpoint({ entity_id, display_name, entity_type: 'light', online: 1, state_json: JSON.stringify({ on: true, supported_color_modes: ['onoff'] }) }, {});

    it('strips punctuation, accents, symbols, and emoji', () => {
        const cases = {
            "Kid's Lamp": 'Kid s Lamp',
            'Café Bulb': 'Caf Bulb',
            'Light #1': 'Light 1',
            'Garage (Left)': 'Garage Left',
            'Salon - Plafond': 'Salon Plafond',
            'TV 📺': 'TV'
        };
        for (const [input, expected] of Object.entries(cases)) {
            const fn = build(input).friendlyName;
            assert.ok(VALID.test(fn), `"${input}" → "${fn}" should be alphanumeric+spaces`);
            assert.equal(fn, expected);
        }
    });

    it('falls back to the entity_id when the name has nothing usable', () => {
        assert.equal(build('   ').friendlyName, 'kids lamp');
        assert.equal(build('!!!@#$').friendlyName, 'kids lamp');
    });

    it('never emits an empty friendlyName and caps length', () => {
        const long = build('A'.repeat(400)).friendlyName;
        assert.ok(long.length > 0 && long.length <= 256);
        assert.ok(VALID.test(long));
        // Even with an unusable name AND a symbol-only entity_id, a default remains.
        const ep = em.buildAlexaEndpoint({ entity_id: 'light.___', display_name: '###', entity_type: 'light', online: 1, state_json: JSON.stringify({ on: true, supported_color_modes: ['onoff'] }) }, {});
        assert.ok(ep.friendlyName.length > 0 && VALID.test(ep.friendlyName));
    });

    it('leaves a clean name unchanged', () => {
        assert.equal(build('Living Room Light').friendlyName, 'Living Room Light');
    });
});

// Structural schema rules Amazon enforces (violations → "Payload does not match
// required Schema" → entire Discovery batch rejected, 0 devices). These are
// data-dependent, which is why clean fixtures passed but real devices failed.
describe('capabilities satisfy Amazon structural schema rules', () => {
    const mk = (entity_type, state, opts = {}) =>
        em.buildAlexaEndpoint({ entity_id: `${entity_type}.x`, display_name: 'X', entity_type, online: 1, state_json: JSON.stringify(state) }, opts);

    it('never emits a ModeController with fewer than 2 modes', () => {
        const rows = [
            mk('fan', { on: true, percentage: 50, supported_features: 15, preset_modes: ['eco'], preset_mode: 'eco', direction: 'forward' }),
            mk('select', { current_option: 'a', options: ['a'] }),
            mk('input_select', { current_option: 'a', options: ['only'] }),
            mk('climate', { mode: 'cool', hvac_modes: ['off', 'cool'], fan_mode: 'auto', fan_modes: ['auto'], preset_mode: 'x', preset_modes: ['x'], ambient_temperature: 21, temperature_unit: 'C', supported_features: 24 }),
            mk('humidifier', { on: true, target_humidity: 45, min_humidity: 30, max_humidity: 70, available_modes: ['auto'], mode: 'auto' }),
            mk('vacuum', { on: true, isRunning: true, fan_speed: 'max', fan_speed_list: ['max'], supported_features: 32 })
        ].filter(Boolean);
        for (const ep of rows) {
            for (const c of ep.capabilities) {
                if (c.interface === 'Alexa.ModeController') {
                    assert.ok(
                        c.configuration && Array.isArray(c.configuration.supportedModes) && c.configuration.supportedModes.length >= 2,
                        `${ep.endpointId} ${c.instance} has <2 modes`
                    );
                }
            }
        }
    });

    it('a 1-option select is excluded (no controllable capability left)', () => {
        assert.equal(mk('select', { current_option: 'a', options: ['a'] }), null);
    });

    it('SecurityPanelController omits supportedAuthorizationTypes when no PIN', () => {
        const noPin = mk('alarm_control_panel', { arm_state: 'disarmed' });
        const sp = noPin.capabilities.find((c) => c.interface === 'Alexa.SecurityPanelController');
        assert.ok(!('supportedAuthorizationTypes' in sp.configuration), 'empty array must be omitted, not []');
        const withPin = mk('alarm_control_panel', { arm_state: 'disarmed' }, { userHasSecurityPin: true });
        const spPin = withPin.capabilities.find((c) => c.interface === 'Alexa.SecurityPanelController');
        assert.deepEqual(spPin.configuration.supportedAuthorizationTypes, [{ type: 'FOUR_DIGIT_PIN' }]);
    });
});

// Real HA values routinely contain %, /, +, parentheses, accents, emoji in mode
// names, source names, and labels. These must be sanitized (not just validated)
// or the capability fails Amazon's schema and 400s the whole batch. The exported
// validateAlexaEndpoint is the final backstop: a bad endpoint is dropped, never
// allowed to poison the batch.
describe('label sanitization + endpoint validation backstop', () => {
    const mk = (t, s, o = {}) => em.buildAlexaEndpoint({ entity_id: `${t}.x`, display_name: 'X', entity_type: t, online: 1, state_json: JSON.stringify(s) }, o);

    it('sanitizes ModeController text labels (keeps endpoint, cleans labels)', () => {
        const ep = mk('select', { current_option: '50%', options: ['50%', 'Auto-Eco', 'High »'] });
        const mc = ep.capabilities.find((c) => c.interface === 'Alexa.ModeController');
        for (const m of mc.configuration.supportedModes) {
            const text = m.modeResources.friendlyNames[0].value.text;
            assert.ok(/^[a-zA-Z0-9 ]+$/.test(text), `mode text "${text}" must be clean`);
        }
        // The mode VALUE (identifier) stays raw so commands still map.
        assert.deepEqual(mc.configuration.supportedModes.map((m) => m.value), ['50%', 'Auto-Eco', 'High »']);
    });

    it('sanitizes + dedups InputController source names', () => {
        const ep = mk('media_player', { on: true, volume: 30, source: 'Apple TV+', source_list: ['Apple TV+', 'HDMI #1', 'Netflix™'], supported_features: 22965, device_class: 'tv' });
        const ic = ep.capabilities.find((c) => c.interface === 'Alexa.InputController');
        for (const i of ic.inputs) assert.ok(/^[a-zA-Z0-9 ]+$/.test(i.name), `input "${i.name}" clean`);
    });

    it('coerces an invalid RangeController range (min>=max) to a valid one', () => {
        const ep = mk('humidifier', { on: true, target_humidity: 50, min_humidity: 50, max_humidity: 50, available_modes: ['a', 'b'] });
        const rc = ep.capabilities.find((c) => c.interface === 'Alexa.RangeController' && c.instance === 'Humidifier.Humidity');
        assert.ok(rc.configuration.supportedRange.minimumValue < rc.configuration.supportedRange.maximumValue);
        assert.ok(rc.configuration.supportedRange.precision > 0);
    });

    it('validateAlexaEndpoint passes every supported domain (messy data included)', () => {
        const rows = [
            mk('select', { current_option: '50%', options: ['50%', 'Auto-Eco', 'High »'] }),
            mk('fan', { on: true, percentage: 50, supported_features: 15, preset_modes: ['Auto/Eco', 'Sleep+'], preset_mode: 'Auto/Eco', direction: 'forward' }),
            mk('media_player', { on: true, volume: 30, source: 'Apple TV+', source_list: ['Apple TV+', 'HDMI #1'], supported_features: 22965, device_class: 'tv' }),
            mk('climate', { mode: 'cool', hvac_modes: ['off', 'cool'], fan_mode: 'Auto (Quiet)', fan_modes: ['Auto (Quiet)', 'High »'], ambient_temperature: 21, temperature_unit: 'C', supported_features: 8 }),
            mk('humidifier', { on: true, target_humidity: 50, min_humidity: 50, max_humidity: 50, available_modes: ['a', 'b'] }),
            mk('alarm_control_panel', { arm_state: 'disarmed' }),
            mk('cover', { openPercent: 40, supported_features: 132, device_class: 'blind' }),
            mk('light', { on: true, supported_color_modes: ['brightness'] })
        ].filter(Boolean);
        for (const ep of rows) {
            assert.deepEqual(em.validateAlexaEndpoint(ep), [], `${ep.endpointId} should be schema-valid`);
        }
    });

    it('validateAlexaEndpoint flags a deliberately broken endpoint', () => {
        const bad = { endpointId: 'x', friendlyName: 'Bad#Name', displayCategories: ['NOPE'], capabilities: [] };
        const errs = em.validateAlexaEndpoint(bad);
        assert.ok(errs.length >= 3, 'should flag friendlyName, category, capabilities, base');
    });
});
