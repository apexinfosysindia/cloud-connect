const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const em = require('../../lib/alexa/entity-mapping');

function makeEntity(type, statePayload, overrides = {}) {
    return {
        entity_type: type,
        entity_id: `${type}.test`,
        display_name: `Test ${type}`,
        device_id: 1,
        state_json: JSON.stringify(statePayload || {}),
        online: 1,
        last_seen_at: new Date().toISOString(),
        entity_last_seen_at: new Date().toISOString(),
        ...overrides
    };
}

function findCap(caps, iface, instance = null) {
    return caps.find((c) => c.interface === iface && (!instance || c.instance === instance));
}

function findProp(props, namespace, name, instance = null) {
    return props.find(
        (p) => p.namespace === namespace && p.name === name && (!instance || p.instance === instance)
    );
}

// --- normalizeAlexaEntityType ---
describe('normalizeAlexaEntityType', () => {
    it('maps unknown/empty to switch', () => {
        assert.equal(em.normalizeAlexaEntityType(''), 'switch');
        assert.equal(em.normalizeAlexaEntityType(null), 'switch');
        assert.equal(em.normalizeAlexaEntityType(undefined), 'switch');
    });

    it('lowercases input', () => {
        assert.equal(em.normalizeAlexaEntityType('LIGHT'), 'light');
        assert.equal(em.normalizeAlexaEntityType('Climate'), 'climate');
    });

    it('preserves known types', () => {
        for (const t of ['light', 'switch', 'fan', 'cover', 'lock', 'climate', 'media_player', 'scene', 'vacuum', 'sensor']) {
            assert.equal(em.normalizeAlexaEntityType(t), t);
        }
    });
});

// --- mapAlexaDomainToEntityType ---
describe('mapAlexaDomainToEntityType', () => {
    it('maps known domains', () => {
        assert.equal(em.mapAlexaDomainToEntityType('light.kitchen'), 'light');
        assert.equal(em.mapAlexaDomainToEntityType('switch.plug'), 'switch');
        assert.equal(em.mapAlexaDomainToEntityType('input_boolean.flag'), 'input_boolean');
        assert.equal(em.mapAlexaDomainToEntityType('automation.test'), 'automation');
        assert.equal(em.mapAlexaDomainToEntityType('script.test'), 'script');
        assert.equal(em.mapAlexaDomainToEntityType('button.restart'), 'button');
    });

    it('falls back for unknown domain', () => {
        assert.equal(em.mapAlexaDomainToEntityType('unknown.foo'), 'switch');
        assert.equal(em.mapAlexaDomainToEntityType('unknown.foo', 'sensor'), 'sensor');
    });
});

// --- buildAlexaDiscoveryEndpoint — base shape ---
describe('buildAlexaDiscoveryEndpoint base shape', () => {
    it('includes Alexa base + EndpointHealth on every endpoint', () => {
        const types = ['switch', 'light', 'fan', 'cover', 'lock', 'climate', 'media_player', 'scene', 'vacuum', 'sensor'];
        for (const t of types) {
            const ep = em.buildAlexaDiscoveryEndpoint(makeEntity(t, {}));
            assert.ok(findCap(ep.capabilities, 'Alexa'), `${t} missing Alexa base`);
            assert.ok(findCap(ep.capabilities, 'Alexa.EndpointHealth'), `${t} missing EndpointHealth`);
        }
    });

    it('has endpointId, friendlyName, displayCategories, cookie', () => {
        const ep = em.buildAlexaDiscoveryEndpoint(makeEntity('switch', {}));
        assert.equal(ep.endpointId, 'switch.test');
        assert.ok(ep.friendlyName);
        assert.ok(Array.isArray(ep.displayCategories));
        assert.ok(ep.cookie);
    });
});

// --- switch / input_boolean / automation / script ---
for (const entityType of ['switch', 'input_boolean', 'automation', 'script']) {
    describe(`${entityType} domain`, () => {
        it('DISCOVERY: PowerController + EndpointHealth', () => {
            const ep = em.buildAlexaDiscoveryEndpoint(makeEntity(entityType, {}));
            assert.ok(findCap(ep.capabilities, 'Alexa.PowerController'));
            assert.ok(findCap(ep.capabilities, 'Alexa.EndpointHealth'));
        });

        it('STATE on', () => {
            const props = em.translateAlexaEntityState(makeEntity(entityType, { on: true }));
            const p = findProp(props, 'Alexa.PowerController', 'powerState');
            assert.equal(p.value, 'ON');
        });

        it('STATE off', () => {
            const props = em.translateAlexaEntityState(makeEntity(entityType, { on: false }));
            const p = findProp(props, 'Alexa.PowerController', 'powerState');
            assert.equal(p.value, 'OFF');
        });

        it('DIRECTIVE TurnOn/TurnOff', () => {
            const on = em.translateAlexaDirective(
                { header: { namespace: 'Alexa.PowerController', name: 'TurnOn' }, payload: {} },
                {}
            );
            const off = em.translateAlexaDirective(
                { header: { namespace: 'Alexa.PowerController', name: 'TurnOff' }, payload: {} },
                {}
            );
            assert.deepEqual(on, { action: 'power.set', payload: { value: 'on' } });
            assert.deepEqual(off, { action: 'power.set', payload: { value: 'off' } });
        });
    });
}

// --- light ---
describe('light', () => {
    it('DISCOVERY: PowerController only (onoff mode)', () => {
        const ep = em.buildAlexaDiscoveryEndpoint(makeEntity('light', { supported_color_modes: ['onoff'] }));
        assert.ok(findCap(ep.capabilities, 'Alexa.PowerController'));
        assert.equal(findCap(ep.capabilities, 'Alexa.BrightnessController'), undefined);
    });

    it('DISCOVERY: + BrightnessController with brightness mode', () => {
        const ep = em.buildAlexaDiscoveryEndpoint(makeEntity('light', { supported_color_modes: ['brightness'] }));
        assert.ok(findCap(ep.capabilities, 'Alexa.BrightnessController'));
    });

    it('DISCOVERY: + ColorController when hs/rgb mode', () => {
        const ep = em.buildAlexaDiscoveryEndpoint(makeEntity('light', { supported_color_modes: ['hs'] }));
        assert.ok(findCap(ep.capabilities, 'Alexa.ColorController'));
    });

    it('DISCOVERY: + ColorTemperatureController when color_temp mode', () => {
        const ep = em.buildAlexaDiscoveryEndpoint(makeEntity('light', { supported_color_modes: ['color_temp'] }));
        assert.ok(findCap(ep.capabilities, 'Alexa.ColorTemperatureController'));
    });

    it('STATE: brightness translates 0..100', () => {
        const props = em.translateAlexaEntityState(
            makeEntity('light', { on: true, brightness: 50, supported_color_modes: ['brightness'] })
        );
        const p = findProp(props, 'Alexa.BrightnessController', 'brightness');
        assert.equal(p.value, 50);
    });

    it('STATE: on with brightness 0 falls back to 100', () => {
        const props = em.translateAlexaEntityState(
            makeEntity('light', { on: true, brightness: 0, supported_color_modes: ['brightness'] })
        );
        const p = findProp(props, 'Alexa.BrightnessController', 'brightness');
        assert.equal(p.value, 100);
    });

    it('DIRECTIVE: SetBrightness', () => {
        const r = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.BrightnessController', name: 'SetBrightness' } },
            { brightness: 75 }
        );
        assert.deepEqual(r, { action: 'brightness.set', payload: { value: 75 } });
    });

    it('DIRECTIVE: AdjustBrightness', () => {
        const r = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.BrightnessController', name: 'AdjustBrightness' } },
            { brightnessDelta: 10 }
        );
        assert.deepEqual(r, { action: 'brightness.adjust', payload: { delta: 10 } });
    });

    it('DIRECTIVE: SetColor', () => {
        const r = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.ColorController', name: 'SetColor' } },
            { color: { hue: 120, saturation: 0.5, brightness: 0.8 } }
        );
        assert.equal(r.action, 'color.set');
        assert.equal(r.payload.hue, 120);
        assert.equal(r.payload.saturation, 0.5);
    });

    it('DIRECTIVE: SetColorTemperature', () => {
        const r = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.ColorTemperatureController', name: 'SetColorTemperature' } },
            { colorTemperatureInKelvin: 4000 }
        );
        assert.deepEqual(r, { action: 'color_temperature.set', payload: { kelvin: 4000 } });
    });
});

// --- fan ---
describe('fan', () => {
    it('DISCOVERY: PowerController + RangeController(Fan.Speed)', () => {
        const ep = em.buildAlexaDiscoveryEndpoint(makeEntity('fan', {}));
        assert.ok(findCap(ep.capabilities, 'Alexa.PowerController'));
        const range = findCap(ep.capabilities, 'Alexa.RangeController', 'Fan.Speed');
        assert.ok(range);
        assert.equal(range.configuration.supportedRange.minimumValue, 0);
        assert.equal(range.configuration.supportedRange.maximumValue, 100);
    });

    it('STATE: on=true, percentage=60', () => {
        const props = em.translateAlexaEntityState(makeEntity('fan', { on: true, percentage: 60 }));
        const p = findProp(props, 'Alexa.RangeController', 'rangeValue', 'Fan.Speed');
        assert.equal(p.value, 60);
    });

    it('DIRECTIVE: SetRangeValue', () => {
        const r = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.RangeController', name: 'SetRangeValue', instance: 'Fan.Speed' } },
            { rangeValue: 80 }
        );
        assert.deepEqual(r, { action: 'range.set', payload: { instance: 'Fan.Speed', value: 80 } });
    });

    it('DIRECTIVE: AdjustRangeValue', () => {
        const r = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.RangeController', name: 'AdjustRangeValue', instance: 'Fan.Speed' } },
            { rangeValueDelta: -20 }
        );
        assert.equal(r.action, 'range.adjust');
        assert.equal(r.payload.delta, -20);
    });
});

// --- cover ---
describe('cover', () => {
    it('DISCOVERY: RangeController(Cover.Position) when SUPPORT_SET_POSITION=4', () => {
        const ep = em.buildAlexaDiscoveryEndpoint(makeEntity('cover', { supported_features: 4 }));
        assert.ok(findCap(ep.capabilities, 'Alexa.RangeController', 'Cover.Position'));
        assert.equal(findCap(ep.capabilities, 'Alexa.ModeController'), undefined);
    });

    it('DISCOVERY: ModeController when SUPPORT_SET_POSITION absent', () => {
        const ep = em.buildAlexaDiscoveryEndpoint(makeEntity('cover', {}));
        assert.ok(findCap(ep.capabilities, 'Alexa.ModeController', 'Cover.Position'));
        assert.equal(findCap(ep.capabilities, 'Alexa.RangeController'), undefined);
    });

    it('STATE: with SET_POSITION — rangeValue', () => {
        const props = em.translateAlexaEntityState(
            makeEntity('cover', { supported_features: 4, openPercent: 50 })
        );
        const p = findProp(props, 'Alexa.RangeController', 'rangeValue', 'Cover.Position');
        assert.equal(p.value, 50);
    });

    it('STATE: without SET_POSITION — mode Open/Closed', () => {
        const open = em.translateAlexaEntityState(makeEntity('cover', { openPercent: 100 }));
        const closed = em.translateAlexaEntityState(makeEntity('cover', { openPercent: 0 }));
        assert.equal(findProp(open, 'Alexa.ModeController', 'mode', 'Cover.Position').value, 'Position.Open');
        assert.equal(findProp(closed, 'Alexa.ModeController', 'mode', 'Cover.Position').value, 'Position.Closed');
    });

    it('DIRECTIVE: SetMode', () => {
        const r = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.ModeController', name: 'SetMode', instance: 'Cover.Position' } },
            { mode: 'Position.Open' }
        );
        assert.deepEqual(r, { action: 'mode.set', payload: { instance: 'Cover.Position', value: 'Position.Open' } });
    });

    it('DIRECTIVE: SetRangeValue for cover', () => {
        const r = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.RangeController', name: 'SetRangeValue', instance: 'Cover.Position' } },
            { rangeValue: 35 }
        );
        assert.deepEqual(r, { action: 'range.set', payload: { instance: 'Cover.Position', value: 35 } });
    });
});

// --- lock ---
describe('lock', () => {
    it('DISCOVERY: LockController', () => {
        const ep = em.buildAlexaDiscoveryEndpoint(makeEntity('lock', {}));
        assert.ok(findCap(ep.capabilities, 'Alexa.LockController'));
    });

    it('STATE: LOCKED/UNLOCKED', () => {
        const locked = em.translateAlexaEntityState(makeEntity('lock', { isLocked: true }));
        const unlocked = em.translateAlexaEntityState(makeEntity('lock', { isLocked: false }));
        assert.equal(findProp(locked, 'Alexa.LockController', 'lockState').value, 'LOCKED');
        assert.equal(findProp(unlocked, 'Alexa.LockController', 'lockState').value, 'UNLOCKED');
    });

    it('DIRECTIVE: Lock/Unlock', () => {
        const l = em.translateAlexaDirective({ header: { namespace: 'Alexa.LockController', name: 'Lock' } }, {});
        const u = em.translateAlexaDirective({ header: { namespace: 'Alexa.LockController', name: 'Unlock' } }, {});
        assert.deepEqual(l, { action: 'lock.set', payload: { value: 'lock' } });
        assert.deepEqual(u, { action: 'lock.set', payload: { value: 'unlock' } });
    });
});

// --- climate ---
describe('climate', () => {
    it('DISCOVERY: ThermostatController + TemperatureSensor', () => {
        const ep = em.buildAlexaDiscoveryEndpoint(makeEntity('climate', { hvac_modes: ['heat', 'cool', 'off'] }));
        assert.ok(findCap(ep.capabilities, 'Alexa.ThermostatController'));
        assert.ok(findCap(ep.capabilities, 'Alexa.TemperatureSensor'));
    });

    it('HVAC mode translation cool/heat/auto/off', () => {
        assert.equal(em.translateHaHvacModeToAlexa('heat'), 'HEAT');
        assert.equal(em.translateHaHvacModeToAlexa('cool'), 'COOL');
        assert.equal(em.translateHaHvacModeToAlexa('heat_cool'), 'AUTO');
        assert.equal(em.translateHaHvacModeToAlexa('auto'), 'AUTO');
        assert.equal(em.translateHaHvacModeToAlexa('off'), 'OFF');
    });

    it('STATE: setpoint + mode + ambient', () => {
        const props = em.translateAlexaEntityState(
            makeEntity('climate', {
                mode: 'heat',
                target_temperature: 22,
                ambient_temperature: 20,
                temperature_unit: 'C'
            })
        );
        const sp = findProp(props, 'Alexa.ThermostatController', 'targetSetpoint');
        assert.equal(sp.value.value, 22);
        assert.equal(sp.value.scale, 'CELSIUS');
        const mode = findProp(props, 'Alexa.ThermostatController', 'thermostatMode');
        assert.equal(mode.value, 'HEAT');
        const temp = findProp(props, 'Alexa.TemperatureSensor', 'temperature');
        assert.equal(temp.value.value, 20);
    });

    it('DIRECTIVE: SetTargetTemperature', () => {
        const r = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.ThermostatController', name: 'SetTargetTemperature' } },
            { targetSetpoint: { value: 23, scale: 'CELSIUS' } }
        );
        assert.equal(r.action, 'thermostat.setpoint');
        assert.equal(r.payload.target.value, 23);
    });

    it('DIRECTIVE: SetThermostatMode', () => {
        const r = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.ThermostatController', name: 'SetThermostatMode' } },
            { thermostatMode: { value: 'HEAT' } }
        );
        assert.deepEqual(r, { action: 'thermostat.mode', payload: { value: 'heat' } });
    });
});

// --- media_player ---
describe('media_player', () => {
    it('DISCOVERY: PowerController + Speaker + PlaybackController', () => {
        const ep = em.buildAlexaDiscoveryEndpoint(makeEntity('media_player', { supported_features: 16384 | 1 }));
        assert.ok(findCap(ep.capabilities, 'Alexa.PowerController'));
        assert.ok(findCap(ep.capabilities, 'Alexa.Speaker'));
        assert.ok(findCap(ep.capabilities, 'Alexa.PlaybackController'));
    });

    it('STATE: volume + muted', () => {
        const props = em.translateAlexaEntityState(
            makeEntity('media_player', { on: true, volume: 40, muted: true })
        );
        assert.equal(findProp(props, 'Alexa.Speaker', 'volume').value, 40);
        assert.equal(findProp(props, 'Alexa.Speaker', 'muted').value, true);
    });

    it('DIRECTIVE: SetVolume + AdjustVolume + SetMute', () => {
        const sv = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.Speaker', name: 'SetVolume' } },
            { volume: 55 }
        );
        const av = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.Speaker', name: 'AdjustVolume' } },
            { volume: -10 }
        );
        const sm = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.Speaker', name: 'SetMute' } },
            { mute: true }
        );
        assert.deepEqual(sv, { action: 'volume.set', payload: { value: 55 } });
        assert.deepEqual(av, { action: 'volume.adjust', payload: { delta: -10 } });
        assert.deepEqual(sm, { action: 'mute.set', payload: { value: true } });
    });

    it('DIRECTIVE: Playback Play/Pause/Stop', () => {
        const play = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.PlaybackController', name: 'Play' } },
            {}
        );
        assert.deepEqual(play, { action: 'playback.play', payload: {} });
        const pause = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.PlaybackController', name: 'Pause' } },
            {}
        );
        assert.deepEqual(pause, { action: 'playback.pause', payload: {} });
    });
});

// --- scene / button ---
describe('scene and button', () => {
    it('DISCOVERY: SceneController, supportsDeactivation false', () => {
        for (const t of ['scene', 'button']) {
            const ep = em.buildAlexaDiscoveryEndpoint(makeEntity(t, {}));
            const sc = findCap(ep.capabilities, 'Alexa.SceneController');
            assert.ok(sc);
            assert.equal(sc.supportsDeactivation, false);
        }
    });

    it('STATE: scene/button have no controller properties other than EndpointHealth', () => {
        const props = em.translateAlexaEntityState(makeEntity('scene', {}));
        const nonHealth = props.filter((p) => p.namespace !== 'Alexa.EndpointHealth');
        assert.equal(nonHealth.length, 0);
    });

    it('DIRECTIVE: Activate', () => {
        const r = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.SceneController', name: 'Activate' } },
            {}
        );
        assert.deepEqual(r, { action: 'scene.activate', payload: {} });
    });

    it('DIRECTIVE: Deactivate is translated (downstream addon-action-map drops it)', () => {
        const r = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.SceneController', name: 'Deactivate' } },
            {}
        );
        assert.deepEqual(r, { action: 'scene.deactivate', payload: {} });
    });
});

// --- vacuum ---
describe('vacuum', () => {
    it('DISCOVERY: PowerController + ToggleController(Vacuum.Pause)', () => {
        const ep = em.buildAlexaDiscoveryEndpoint(makeEntity('vacuum', {}));
        assert.ok(findCap(ep.capabilities, 'Alexa.PowerController'));
        assert.ok(findCap(ep.capabilities, 'Alexa.ToggleController', 'Vacuum.Pause'));
    });

    it('STATE: powerState + toggleState (pause)', () => {
        const props = em.translateAlexaEntityState(makeEntity('vacuum', { on: true, isPaused: true }));
        assert.equal(findProp(props, 'Alexa.PowerController', 'powerState').value, 'ON');
        const toggle = findProp(props, 'Alexa.ToggleController', 'toggleState', 'Vacuum.Pause');
        assert.equal(toggle.value, 'ON');
    });

    it('DIRECTIVE: ToggleController TurnOn', () => {
        const r = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.ToggleController', name: 'TurnOn', instance: 'Vacuum.Pause' } },
            {}
        );
        assert.deepEqual(r, { action: 'toggle.set', payload: { instance: 'Vacuum.Pause', value: 'on' } });
    });
});

// --- sensor (temperature) ---
describe('sensor (temperature)', () => {
    it('DISCOVERY: TemperatureSensor', () => {
        const ep = em.buildAlexaDiscoveryEndpoint(makeEntity('sensor', {}));
        assert.ok(findCap(ep.capabilities, 'Alexa.TemperatureSensor'));
    });

    it('STATE: temperature with celsius', () => {
        const props = em.translateAlexaEntityState(
            makeEntity('sensor', { temperature: 21.5, unit_of_measurement: '°C' })
        );
        const p = findProp(props, 'Alexa.TemperatureSensor', 'temperature');
        assert.equal(p.value.value, 21.5);
        assert.equal(p.value.scale, 'CELSIUS');
    });

    it('STATE: fahrenheit via unit_of_measurement', () => {
        const props = em.translateAlexaEntityState(
            makeEntity('sensor', { temperature: 70, unit_of_measurement: '°F' })
        );
        assert.equal(findProp(props, 'Alexa.TemperatureSensor', 'temperature').value.scale, 'FAHRENHEIT');
    });
});

// --- EndpointHealth connectivity ---
describe('EndpointHealth connectivity', () => {
    const now = new Date().toISOString();
    const old = new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString();

    function connectivity(entity) {
        const props = em.translateAlexaEntityState(entity);
        return findProp(props, 'Alexa.EndpointHealth', 'connectivity').value.value;
    }

    it('OK when device_online + entity_fresh + entity available', () => {
        const v = connectivity({
            entity_type: 'switch',
            entity_id: 'switch.x',
            state_json: '{"on":true}',
            online: 1,
            last_seen_at: now,
            entity_last_seen_at: now
        });
        assert.equal(v, 'OK');
    });

    it('UNREACHABLE when device offline (stale last_seen_at)', () => {
        const v = connectivity({
            entity_type: 'switch',
            entity_id: 'switch.x',
            state_json: '{"on":true}',
            online: 1,
            last_seen_at: old,
            entity_last_seen_at: now
        });
        assert.equal(v, 'UNREACHABLE');
    });

    it('UNREACHABLE when entity stale (entity_last_seen_at old)', () => {
        const v = connectivity({
            entity_type: 'switch',
            entity_id: 'switch.x',
            state_json: '{"on":true}',
            online: 1,
            last_seen_at: now,
            entity_last_seen_at: old,
            updated_at: old
        });
        assert.equal(v, 'UNREACHABLE');
    });

    it('UNREACHABLE when entity unavailable (online=0)', () => {
        const v = connectivity({
            entity_type: 'switch',
            entity_id: 'switch.x',
            state_json: '{"on":true}',
            online: 0,
            last_seen_at: now,
            entity_last_seen_at: now
        });
        assert.equal(v, 'UNREACHABLE');
    });
});

// --- translateAlexaDirective fallbacks ---
describe('translateAlexaDirective unknown', () => {
    it('returns null for unknown namespace', () => {
        const r = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.Unknown', name: 'DoThing' } },
            {}
        );
        assert.equal(r, null);
    });

    it('returns null for missing header', () => {
        assert.equal(em.translateAlexaDirective({}, {}), null);
        assert.equal(em.translateAlexaDirective(null, {}), null);
    });

    it('returns object for known directive', () => {
        const r = em.translateAlexaDirective(
            { header: { namespace: 'Alexa.PowerController', name: 'TurnOn' } },
            {}
        );
        assert.ok(r && typeof r === 'object');
        assert.ok('action' in r && 'payload' in r);
    });
});

// --- supportsAlexaDirectiveForEntityType ---
describe('supportsAlexaDirectiveForEntityType', () => {
    it('light supports Brightness + Color', () => {
        assert.ok(em.supportsAlexaDirectiveForEntityType('light', 'Alexa.BrightnessController'));
        assert.ok(em.supportsAlexaDirectiveForEntityType('light', 'Alexa.ColorController'));
    });

    it('lock supports only LockController', () => {
        assert.ok(em.supportsAlexaDirectiveForEntityType('lock', 'Alexa.LockController'));
        assert.ok(!em.supportsAlexaDirectiveForEntityType('lock', 'Alexa.PowerController'));
    });

    it('sensor supports TemperatureSensor', () => {
        assert.ok(em.supportsAlexaDirectiveForEntityType('sensor', 'Alexa.TemperatureSensor'));
    });
});
