const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const em = require('../../lib/google-home/entity-mapping');

// --- normalizeGoogleEntityType ---
describe('normalizeGoogleEntityType', () => {
    it('lowercases and sanitizes', () => {
        assert.equal(em.normalizeGoogleEntityType('LIGHT'), 'light');
        assert.equal(em.normalizeGoogleEntityType('Climate'), 'climate');
    });

    it('returns switch for empty/null', () => {
        assert.equal(em.normalizeGoogleEntityType(''), 'switch');
        assert.equal(em.normalizeGoogleEntityType(null), 'switch');
    });
});

// --- mapGoogleDomainToEntityType ---
describe('mapGoogleDomainToEntityType', () => {
    const expectedMappings = {
        'light.living_room': 'light',
        'switch.outlet': 'switch',
        'input_boolean.flag': 'switch',
        'fan.bedroom': 'fan',
        'cover.garage': 'cover',
        'lock.front_door': 'lock',
        'climate.thermostat': 'climate',
        'media_player.tv': 'media_player',
        'scene.goodnight': 'scene',
        'button.restart': 'button',
        'vacuum.roomba': 'vacuum',
        'sensor.temp': 'sensor',
        'binary_sensor.door': 'binary_sensor',
        'humidifier.bedroom': 'humidifier',
        'alarm_control_panel.home': 'alarm_control_panel',
        'water_heater.tank': 'water_heater',
        'automation.lights': 'automation',
        'script.startup': 'script',
        'camera.front': 'camera',
        'group.all_lights': 'group',
        'input_button.test': 'input_button',
        'input_select.mode': 'input_select',
        'select.speed': 'select',
        'valve.water': 'valve',
        'lawn_mower.mow': 'lawn_mower',
        'event.doorbell': 'event'
    };

    for (const [entityId, expectedType] of Object.entries(expectedMappings)) {
        it(`maps ${entityId} to ${expectedType}`, () => {
            assert.equal(em.mapGoogleDomainToEntityType(entityId), expectedType);
        });
    }

    it('returns fallback for unknown domain', () => {
        assert.equal(em.mapGoogleDomainToEntityType('unknown.entity'), 'switch');
        assert.equal(em.mapGoogleDomainToEntityType('unknown.entity', 'sensor'), 'sensor');
    });

    it('returns fallback for empty/null', () => {
        assert.equal(em.mapGoogleDomainToEntityType(''), 'switch');
        assert.equal(em.mapGoogleDomainToEntityType(null), 'switch');
    });
});

// --- normalizeGoogleThermostatMode ---
describe('normalizeGoogleThermostatMode', () => {
    it('normalizes heat_cool', () => {
        assert.equal(em.normalizeGoogleThermostatMode('heat_cool'), 'heatcool');
        assert.equal(em.normalizeGoogleThermostatMode('heatcool'), 'heatcool');
    });

    it('normalizes fan_only', () => {
        assert.equal(em.normalizeGoogleThermostatMode('fan_only'), 'fan-only');
        assert.equal(em.normalizeGoogleThermostatMode('fan-only'), 'fan-only');
    });

    it('passes through standard modes', () => {
        assert.equal(em.normalizeGoogleThermostatMode('heat'), 'heat');
        assert.equal(em.normalizeGoogleThermostatMode('cool'), 'cool');
        assert.equal(em.normalizeGoogleThermostatMode('off'), 'off');
    });

    it('returns off for empty/null', () => {
        assert.equal(em.normalizeGoogleThermostatMode(''), 'off');
        assert.equal(em.normalizeGoogleThermostatMode(null), 'off');
    });
});

// --- resolveGoogleTraitsFromCapabilities ---
describe('resolveGoogleTraitsFromCapabilities', () => {
    it('light — basic OnOff', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('light', {});
        assert.equal(result.type, 'action.devices.types.LIGHT');
        assert.ok(result.traits.includes('action.devices.traits.OnOff'));
    });

    it('light — with brightness', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('light', {
            supported_color_modes: ['brightness']
        });
        assert.ok(result.traits.includes('action.devices.traits.Brightness'));
    });

    it('light — with color', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('light', {
            supported_color_modes: ['hs', 'color_temp']
        });
        assert.ok(result.traits.includes('action.devices.traits.ColorSetting'));
    });

    it('light — with effects adds Modes', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('light', {
            effect_list: ['rainbow', 'fire']
        });
        assert.ok(result.traits.includes('action.devices.traits.Modes'));
    });

    it('fan — basic with FanSpeed', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('fan', { supported_features: 1 });
        assert.equal(result.type, 'action.devices.types.FAN');
        assert.ok(result.traits.includes('action.devices.traits.FanSpeed'));
    });

    it('cover — maps device_class to correct Google type', () => {
        assert.equal(
            em.resolveGoogleTraitsFromCapabilities('cover', { device_class: 'garage' }).type,
            'action.devices.types.GARAGE'
        );
        assert.equal(
            em.resolveGoogleTraitsFromCapabilities('cover', { device_class: 'door' }).type,
            'action.devices.types.DOOR'
        );
        assert.equal(
            em.resolveGoogleTraitsFromCapabilities('cover', { device_class: 'window' }).type,
            'action.devices.types.WINDOW'
        );
        assert.equal(
            em.resolveGoogleTraitsFromCapabilities('cover', { device_class: 'curtain' }).type,
            'action.devices.types.CURTAIN'
        );
        assert.equal(em.resolveGoogleTraitsFromCapabilities('cover', {}).type, 'action.devices.types.BLINDS');
    });

    it('cover — with tilt adds Rotation', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('cover', { supported_features: 128 });
        assert.ok(result.traits.includes('action.devices.traits.Rotation'));
    });

    it('lock — LockUnlock', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('lock', {});
        assert.equal(result.type, 'action.devices.types.LOCK');
        assert.deepEqual(result.traits, ['action.devices.traits.LockUnlock']);
    });

    it('climate — TemperatureSetting', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('climate', {});
        assert.equal(result.type, 'action.devices.types.THERMOSTAT');
        assert.ok(result.traits.includes('action.devices.traits.TemperatureSetting'));
    });

    it('climate — with modes', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('climate', { supported_features: 8 | 16 });
        assert.ok(result.traits.includes('action.devices.traits.Modes'));
    });

    it('media_player — device_class speaker', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('media_player', { device_class: 'speaker' });
        assert.equal(result.type, 'action.devices.types.SPEAKER');
    });

    it('media_player — default is TV', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('media_player', {});
        assert.equal(result.type, 'action.devices.types.TV');
    });

    it('scene — Scene trait', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('scene', {});
        assert.equal(result.type, 'action.devices.types.SCENE');
        assert.deepEqual(result.traits, ['action.devices.traits.Scene']);
    });

    it('button — Scene trait', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('button', {});
        assert.deepEqual(result.traits, ['action.devices.traits.Scene']);
    });

    it('vacuum — StartStop and OnOff', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('vacuum', { supported_features: 8192 | 1 | 2 });
        assert.ok(result.traits.includes('action.devices.traits.StartStop'));
        assert.ok(result.traits.includes('action.devices.traits.OnOff'));
    });

    it('sensor — temperature uses TemperatureSetting', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('sensor', { device_class: 'temperature' });
        assert.ok(result.traits.includes('action.devices.traits.TemperatureSetting'));
    });

    it('sensor — humidity uses HumiditySetting', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('sensor', { device_class: 'humidity' });
        assert.ok(result.traits.includes('action.devices.traits.HumiditySetting'));
    });

    it('sensor — pm25 uses SensorState', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('sensor', { device_class: 'pm25' });
        assert.ok(result.traits.includes('action.devices.traits.SensorState'));
    });

    it('binary_sensor — door uses OpenClose', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('binary_sensor', { device_class: 'door' });
        assert.equal(result.type, 'action.devices.types.DOOR');
        assert.ok(result.traits.includes('action.devices.traits.OpenClose'));
    });

    it('binary_sensor — smoke uses SensorState with SMOKE_DETECTOR type', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('binary_sensor', { device_class: 'smoke' });
        assert.equal(result.type, 'action.devices.types.SMOKE_DETECTOR');
    });

    it('binary_sensor — co uses CARBON_MONOXIDE_DETECTOR', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('binary_sensor', { device_class: 'co' });
        assert.equal(result.type, 'action.devices.types.CARBON_MONOXIDE_DETECTOR');
    });

    it('humidifier — OnOff + HumiditySetting', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('humidifier', {});
        assert.ok(result.traits.includes('action.devices.traits.OnOff'));
        assert.ok(result.traits.includes('action.devices.traits.HumiditySetting'));
    });

    it('alarm_control_panel — ArmDisarm + StatusReport', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('alarm_control_panel', {});
        assert.ok(result.traits.includes('action.devices.traits.ArmDisarm'));
        assert.ok(result.traits.includes('action.devices.traits.StatusReport'));
    });

    it('water_heater — OnOff + TemperatureControl', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('water_heater', {});
        assert.ok(result.traits.includes('action.devices.traits.OnOff'));
        assert.ok(result.traits.includes('action.devices.traits.TemperatureControl'));
    });

    it('switch — outlet device_class', () => {
        assert.equal(
            em.resolveGoogleTraitsFromCapabilities('switch', { device_class: 'outlet' }).type,
            'action.devices.types.OUTLET'
        );
        assert.equal(em.resolveGoogleTraitsFromCapabilities('switch', {}).type, 'action.devices.types.SWITCH');
    });

    it('select/input_select — Modes trait', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('select', {});
        assert.ok(result.traits.includes('action.devices.traits.Modes'));
    });

    it('valve — OpenClose', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('valve', {});
        assert.equal(result.type, 'action.devices.types.VALVE');
        assert.ok(result.traits.includes('action.devices.traits.OpenClose'));
    });

    it('lawn_mower — StartStop', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('lawn_mower', {});
        assert.equal(result.type, 'action.devices.types.MOWER');
    });

    it('event doorbell — ObjectDetection', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('event', { device_class: 'doorbell' });
        assert.equal(result.type, 'action.devices.types.DOORBELL');
    });

    it('event non-doorbell — SensorState', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('event', {});
        assert.equal(result.type, 'action.devices.types.SENSOR');
    });

    it('unknown entity type — fallback to SWITCH + OnOff', () => {
        const result = em.resolveGoogleTraitsFromCapabilities('unknown_type', {});
        assert.equal(result.type, 'action.devices.types.SWITCH');
        assert.ok(result.traits.includes('action.devices.traits.OnOff'));
    });
});

// --- supportsGoogleCommandForEntityType ---
describe('supportsGoogleCommandForEntityType', () => {
    it('light supports OnOff', () => {
        assert.ok(em.supportsGoogleCommandForEntityType('light', 'action.devices.commands.OnOff', {}));
    });

    it('light supports BrightnessAbsolute', () => {
        assert.ok(em.supportsGoogleCommandForEntityType('light', 'action.devices.commands.BrightnessAbsolute', {}));
    });

    it('light supports ColorAbsolute when color modes present', () => {
        assert.ok(
            em.supportsGoogleCommandForEntityType('light', 'action.devices.commands.ColorAbsolute', {
                supported_color_modes: ['hs']
            })
        );
    });

    it('light does not support ColorAbsolute without color modes', () => {
        assert.ok(!em.supportsGoogleCommandForEntityType('light', 'action.devices.commands.ColorAbsolute', {}));
    });

    it('switch supports only OnOff', () => {
        assert.ok(em.supportsGoogleCommandForEntityType('switch', 'action.devices.commands.OnOff', {}));
        assert.ok(!em.supportsGoogleCommandForEntityType('switch', 'action.devices.commands.BrightnessAbsolute', {}));
    });

    it('lock supports LockUnlock', () => {
        assert.ok(em.supportsGoogleCommandForEntityType('lock', 'action.devices.commands.LockUnlock', {}));
    });

    it('scene supports ActivateScene', () => {
        assert.ok(em.supportsGoogleCommandForEntityType('scene', 'action.devices.commands.ActivateScene', {}));
    });

    it('sensor supports nothing (read-only)', () => {
        assert.ok(!em.supportsGoogleCommandForEntityType('sensor', 'action.devices.commands.OnOff', {}));
    });

    it('binary_sensor supports nothing (read-only)', () => {
        assert.ok(!em.supportsGoogleCommandForEntityType('binary_sensor', 'action.devices.commands.OnOff', {}));
    });

    it('climate supports thermostat commands', () => {
        assert.ok(em.supportsGoogleCommandForEntityType('climate', 'action.devices.commands.ThermostatSetMode', {}));
        assert.ok(
            em.supportsGoogleCommandForEntityType(
                'climate',
                'action.devices.commands.ThermostatTemperatureSetpoint',
                {}
            )
        );
    });
});

// --- buildGoogleDeviceAttributes ---
describe('buildGoogleDeviceAttributes', () => {
    it('light with Brightness trait', () => {
        const attrs = em.buildGoogleDeviceAttributes('light', {}, [
            'action.devices.traits.OnOff',
            'action.devices.traits.Brightness'
        ]);
        assert.equal(attrs.commandOnlyBrightness, false);
    });

    it('light with Modes trait and effects', () => {
        const attrs = em.buildGoogleDeviceAttributes('light', { effect_list: ['rainbow'] }, [
            'action.devices.traits.OnOff',
            'action.devices.traits.Modes'
        ]);
        assert.ok(attrs.availableModes);
        assert.equal(attrs.availableModes[0].name, 'effect');
        assert.equal(attrs.commandOnlyModes, false);
    });

    it('cover with set position', () => {
        const attrs = em.buildGoogleDeviceAttributes('cover', { supported_features: 4 }, [
            'action.devices.traits.OpenClose'
        ]);
        assert.equal(attrs.discreteOnlyOpenClose, false);
    });

    it('cover without set position', () => {
        const attrs = em.buildGoogleDeviceAttributes('cover', {}, ['action.devices.traits.OpenClose']);
        assert.equal(attrs.discreteOnlyOpenClose, true);
    });

    it('climate includes thermostat modes', () => {
        const attrs = em.buildGoogleDeviceAttributes('climate', { hvac_modes: ['heat', 'cool'] }, [
            'action.devices.traits.TemperatureSetting'
        ]);
        assert.ok(attrs.availableThermostatModes);
        assert.ok(attrs.thermostatTemperatureUnit);
    });

    it('sensor — temperature has unit', () => {
        const attrs = em.buildGoogleDeviceAttributes(
            'sensor',
            { device_class: 'temperature', unit_of_measurement: '°F' },
            ['action.devices.traits.TemperatureSetting']
        );
        assert.equal(attrs.thermostatTemperatureUnit, 'F');
        assert.equal(attrs.queryOnlyTemperatureSetting, true);
    });

    it('sensor — pm25 uses SENSOR_DEVICE_CLASS_REGISTRY', () => {
        const attrs = em.buildGoogleDeviceAttributes('sensor', { device_class: 'pm25' }, [
            'action.devices.traits.SensorState'
        ]);
        assert.ok(attrs.sensorStatesSupported);
        assert.equal(attrs.sensorStatesSupported[0].name, 'PM2.5');
        assert.equal(attrs.sensorStatesSupported[0].numericCapabilities.rawValueUnit, 'MICROGRAMS_PER_CUBIC_METER');
    });

    it('sensor — co2 uses registry', () => {
        const attrs = em.buildGoogleDeviceAttributes('sensor', { device_class: 'co2' }, [
            'action.devices.traits.SensorState'
        ]);
        assert.equal(attrs.sensorStatesSupported[0].name, 'CarbonDioxideLevel');
    });

    it('sensor — unknown dc defaults to AirQuality', () => {
        const attrs = em.buildGoogleDeviceAttributes('sensor', { device_class: 'pressure' }, [
            'action.devices.traits.SensorState'
        ]);
        assert.equal(attrs.sensorStatesSupported[0].name, 'AirQuality');
    });

    it('binary_sensor — door uses OpenClose attrs', () => {
        const attrs = em.buildGoogleDeviceAttributes('binary_sensor', { device_class: 'door' }, [
            'action.devices.traits.OpenClose'
        ]);
        assert.equal(attrs.queryOnlyOpenClose, true);
        assert.equal(attrs.discreteOnlyOpenClose, true);
    });

    it('binary_sensor — smoke uses descriptive SensorState', () => {
        const attrs = em.buildGoogleDeviceAttributes('binary_sensor', { device_class: 'smoke' }, [
            'action.devices.traits.SensorState'
        ]);
        assert.equal(attrs.sensorStatesSupported[0].name, 'SmokeLevel');
    });

    it('binary_sensor — motion uses OccupancyDetecting', () => {
        const attrs = em.buildGoogleDeviceAttributes('binary_sensor', { device_class: 'motion' }, [
            'action.devices.traits.SensorState'
        ]);
        assert.equal(attrs.sensorStatesSupported[0].name, 'OccupancyDetecting');
    });

    it('select with options builds Modes', () => {
        const attrs = em.buildGoogleDeviceAttributes('select', { options: ['low', 'high'] }, [
            'action.devices.traits.Modes'
        ]);
        assert.ok(attrs.availableModes);
        assert.equal(attrs.availableModes[0].name, 'option');
        assert.equal(attrs.availableModes[0].settings.length, 2);
    });

    it('scene returns empty attributes', () => {
        const attrs = em.buildGoogleDeviceAttributes('scene', {}, ['action.devices.traits.Scene']);
        assert.deepEqual(attrs, {});
    });

    it('camera has protocol', () => {
        const attrs = em.buildGoogleDeviceAttributes('camera', {}, ['action.devices.traits.CameraStream']);
        assert.deepEqual(attrs.cameraStreamSupportedProtocols, ['hls']);
    });
});

// --- parseGoogleEntityState ---
describe('parseGoogleEntityState', () => {
    function makeEntity(type, statePayload, overrides = {}) {
        return {
            entity_type: type,
            entity_id: `${type}.test`,
            state_json: JSON.stringify(statePayload),
            online: 1,
            ...overrides
        };
    }

    it('light — on with brightness', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('light', {
                on: true,
                brightness: 75,
                supported_color_modes: ['brightness']
            })
        );
        assert.equal(state.online, true);
        assert.equal(state.on, true);
        assert.equal(state.brightness, 75);
    });

    it('light — on with brightness 0 gets fallback to 100', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('light', {
                on: true,
                brightness: 0,
                supported_color_modes: ['brightness']
            })
        );
        assert.equal(state.brightness, 100);
    });

    it('light — off with brightness 0 stays 0', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('light', {
                on: false,
                brightness: 0,
                supported_color_modes: ['brightness']
            })
        );
        assert.equal(state.brightness, 0);
    });

    it('fan — with speed', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('fan', {
                on: true,
                supported_features: 1,
                percentage_step: 33,
                percentage: 66
            })
        );
        assert.equal(state.on, true);
        assert.ok(state.currentFanSpeedSetting);
    });

    it('cover — open percent', () => {
        const state = em.parseGoogleEntityState(makeEntity('cover', { openPercent: 50 }));
        assert.equal(state.openPercent, 50);
    });

    it('lock — isLocked', () => {
        const state = em.parseGoogleEntityState(makeEntity('lock', { isLocked: true }));
        assert.equal(state.isLocked, true);
    });

    it('climate — thermostat state', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('climate', {
                mode: 'heat',
                ambient_temperature: 22,
                target_temperature: 24
            })
        );
        assert.equal(state.thermostatMode, 'heat');
        assert.equal(state.thermostatTemperatureAmbient, 22);
        assert.equal(state.thermostatTemperatureSetpoint, 24);
    });

    it('climate — heatcool with range', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('climate', {
                mode: 'heat_cool',
                ambient_temperature: 22,
                target_temp_low: 20,
                target_temp_high: 25,
                target_temperature: 22
            })
        );
        assert.equal(state.thermostatMode, 'heatcool');
        assert.equal(state.thermostatTemperatureSetpointLow, 20);
        assert.equal(state.thermostatTemperatureSetpointHigh, 25);
    });

    it('media_player — volume and playback', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('media_player', {
                on: true,
                volume: 50,
                muted: false,
                is_playing: true,
                supported_features: 4 | 1 | 16384
            })
        );
        assert.equal(state.currentVolume, 50);
        assert.equal(state.playbackState, 'PLAYING');
    });

    it('scene — online only', () => {
        const state = em.parseGoogleEntityState(makeEntity('scene', {}));
        assert.equal(state.online, true);
        assert.equal(state.on, undefined);
    });

    it('vacuum — running state', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('vacuum', {
                isRunning: true,
                isPaused: false
            })
        );
        assert.equal(state.isRunning, true);
        assert.equal(state.isPaused, false);
    });

    it('sensor — temperature', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('sensor', {
                device_class: 'temperature',
                temperature: 25
            })
        );
        assert.equal(state.thermostatMode, 'off');
        assert.equal(state.thermostatTemperatureAmbient, 25);
    });

    it('sensor — humidity', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('sensor', {
                device_class: 'humidity',
                value: 65
            })
        );
        assert.equal(state.humidityAmbientPercent, 65);
    });

    it('sensor — pm25 uses registry', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('sensor', {
                device_class: 'pm25',
                value: 42
            })
        );
        assert.equal(state.currentSensorStateData[0].name, 'PM2.5');
        assert.equal(state.currentSensorStateData[0].rawValue, 42);
    });

    it('sensor — co2 uses registry', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('sensor', {
                device_class: 'co2',
                value: 800
            })
        );
        assert.equal(state.currentSensorStateData[0].name, 'CarbonDioxideLevel');
    });

    it('sensor — unknown dc defaults to AirQuality', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('sensor', {
                device_class: 'pressure',
                value: 1013
            })
        );
        assert.equal(state.currentSensorStateData[0].name, 'AirQuality');
    });

    it('binary_sensor — door open', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('binary_sensor', {
                device_class: 'door',
                is_on: true
            })
        );
        assert.equal(state.openPercent, 100);
    });

    it('binary_sensor — door closed', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('binary_sensor', {
                device_class: 'door',
                is_on: false
            })
        );
        assert.equal(state.openPercent, 0);
    });

    it('binary_sensor — smoke detected', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('binary_sensor', {
                device_class: 'smoke',
                is_on: true
            })
        );
        assert.equal(state.currentSensorStateData[0].name, 'SmokeLevel');
        assert.equal(state.currentSensorStateData[0].currentSensorState, 'smoke detected');
    });

    it('binary_sensor — motion occupied', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('binary_sensor', {
                device_class: 'motion',
                is_on: true
            })
        );
        assert.equal(state.currentSensorStateData[0].name, 'OccupancyDetecting');
        assert.equal(state.currentSensorStateData[0].currentSensorState, 'occupied');
    });

    it('humidifier — with target humidity', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('humidifier', {
                on: true,
                target_humidity: 55,
                current_humidity: 40
            })
        );
        assert.equal(state.on, true);
        assert.equal(state.humiditySetpointPercent, 55);
        assert.equal(state.humidityAmbientPercent, 40);
    });

    it('alarm — armed_away', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('alarm_control_panel', {
                arm_state: 'armed_away'
            })
        );
        assert.equal(state.isArmed, true);
        assert.equal(state.currentArmLevel, 'L2');
    });

    it('alarm — disarmed', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('alarm_control_panel', {
                arm_state: 'disarmed'
            })
        );
        assert.equal(state.isArmed, false);
    });

    it('alarm — triggered has status report', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('alarm_control_panel', {
                arm_state: 'triggered'
            })
        );
        assert.ok(state.currentStatusReport);
        assert.equal(state.currentStatusReport[0].statusCode, 'securityAlert');
    });

    it('water_heater — temperature', () => {
        const state = em.parseGoogleEntityState(
            makeEntity('water_heater', {
                on: true,
                current_temperature: 45,
                target_temperature: 55
            })
        );
        assert.equal(state.on, true);
        assert.equal(state.temperatureSetpointCelsius, 55);
        assert.equal(state.temperatureAmbientCelsius, 45);
    });

    it('group — on/off', () => {
        const state = em.parseGoogleEntityState(makeEntity('group', { on: true }));
        assert.equal(state.on, true);
    });

    it('select — current option', () => {
        const state = em.parseGoogleEntityState(makeEntity('select', { current_option: 'fast' }));
        assert.deepEqual(state.currentModeSettings, { option: 'fast' });
    });

    it('valve — open percent', () => {
        const state = em.parseGoogleEntityState(makeEntity('valve', { openPercent: 75 }));
        assert.equal(state.openPercent, 75);
    });

    it('lawn_mower — running', () => {
        const state = em.parseGoogleEntityState(makeEntity('lawn_mower', { isRunning: true, isPaused: false }));
        assert.equal(state.isRunning, true);
    });

    it('unknown type — fallback on/off', () => {
        const state = em.parseGoogleEntityState(makeEntity('unknown', { on: true }));
        assert.equal(state.on, true);
    });

    it('offline device', () => {
        const state = em.parseGoogleEntityState(makeEntity('light', { on: true }, { online: 0 }));
        assert.equal(state.online, false);
    });
});

// --- getGoogleThermostatModesForEntity ---
describe('getGoogleThermostatModesForEntity', () => {
    it('returns normalized modes from entity', () => {
        const result = em.getGoogleThermostatModesForEntity({
            state_json: JSON.stringify({ hvac_modes: ['heat', 'cool', 'heat_cool'] })
        });
        assert.ok(result.includes('heat'));
        assert.ok(result.includes('cool'));
        assert.ok(result.includes('heatcool'));
    });

    it('returns default modes when none provided', () => {
        const result = em.getGoogleThermostatModesForEntity({ state_json: '{}' });
        assert.equal(result, 'off,heat,cool,heatcool');
    });
});
