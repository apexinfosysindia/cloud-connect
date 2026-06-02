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

describe('normalizeAlexaEntityType', () => {
    it('keeps known supported types', () => {
        assert.equal(em.normalizeAlexaEntityType('light', 'light.x'), 'light');
        assert.equal(em.normalizeAlexaEntityType('switch', 'switch.x'), 'switch');
    });

    it('infers type from entity id domain when type missing', () => {
        assert.equal(em.normalizeAlexaEntityType(null, 'light.kitchen'), 'light');
        assert.equal(em.normalizeAlexaEntityType(null, 'fan.bedroom'), 'fan');
    });

    it('falls back to switch for unknown controllable types', () => {
        assert.equal(em.normalizeAlexaEntityType('weird', 'x.y'), 'switch');
    });
});

describe('buildAlexaEndpoint', () => {
    it('returns null for unsupported types', () => {
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
});

describe('parseAlexaEndpointState', () => {
    it('maps on/brightness/color/temp into Alexa properties', () => {
        const props = em.parseAlexaEndpointState(
            lightRow({ on: true, brightness: 60, supported_color_modes: ['color_temp', 'hs'], color_temp_kelvin: 3000, hs_color: [120, 40] })
        );
        assert.equal(props.powerState, 'ON');
        assert.equal(props.brightness, 60);
        assert.equal(props.connectivity, 'OK');
        assert.equal(props.colorTemperatureInKelvin, 3000);
        assert.equal(props.color.hue, 120);
        assert.equal(props.color.saturation, 0.4);
    });

    it('reports UNREACHABLE + OFF for an offline switch', () => {
        const props = em.parseAlexaEndpointState({
            entity_type: 'switch',
            online: 0,
            state_json: JSON.stringify({ on: false })
        });
        assert.equal(props.connectivity, 'UNREACHABLE');
        assert.equal(props.powerState, 'OFF');
    });

    it('does not report 0% brightness for a light that is ON', () => {
        const props = em.parseAlexaEndpointState(lightRow({ on: true, brightness: 0, supported_color_modes: ['brightness'] }));
        assert.equal(props.brightness, 100);
    });
});
