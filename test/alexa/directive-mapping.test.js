const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const mapping = require('../../lib/alexa/directive-mapping');

function entity(overrides = {}) {
    return {
        id: 1,
        entity_id: 'light.bedroom',
        device_id: 'dev1',
        display_name: 'Bedroom',
        entity_type: 'light',
        online: 1,
        state_json: JSON.stringify({
            on: true,
            brightness: 50,
            supported_color_modes: ['brightness', 'color_temp']
        }),
        ...overrides
    };
}

describe('buildAlexaEndpoint', () => {
    it('produces a well-formed endpoint for a light', () => {
        const ep = mapping.buildAlexaEndpoint(entity(), null);
        assert.equal(ep.endpointId, 'light.bedroom');
        assert.deepEqual(ep.displayCategories, ['LIGHT']);
        assert.ok(Array.isArray(ep.capabilities));
        const interfaces = ep.capabilities.map((c) => c.interface);
        assert.ok(interfaces.includes('Alexa.PowerController'));
        assert.ok(interfaces.includes('Alexa.BrightnessController'));
    });

    it('returns null for null entity', () => {
        assert.equal(mapping.buildAlexaEndpoint(null, null), null);
    });

    it('maps lock to SMARTLOCK category', () => {
        const ep = mapping.buildAlexaEndpoint(
            entity({ entity_type: 'lock', state_json: '{"locked":true}' }),
            null
        );
        assert.deepEqual(ep.displayCategories, ['SMARTLOCK']);
    });

    it('maps scene to SCENE_TRIGGER', () => {
        const ep = mapping.buildAlexaEndpoint(
            entity({ entity_type: 'scene', state_json: '{}' }),
            null
        );
        assert.deepEqual(ep.displayCategories, ['SCENE_TRIGGER']);
    });
});

describe('mapDirectiveToInternalAction', () => {
    it('TurnOn → set_on', () => {
        const r = mapping.mapDirectiveToInternalAction(
            { header: { namespace: 'Alexa.PowerController', name: 'TurnOn' }, payload: {} },
            entity()
        );
        assert.equal(r.action, 'set_on');
        assert.deepEqual(r.payload, { on: true });
        assert.ok(Array.isArray(r.responseProps));
    });

    it('TurnOff → set_on with on:false', () => {
        const r = mapping.mapDirectiveToInternalAction(
            { header: { namespace: 'Alexa.PowerController', name: 'TurnOff' }, payload: {} },
            entity()
        );
        assert.equal(r.action, 'set_on');
        assert.deepEqual(r.payload, { on: false });
    });

    it('SetBrightness → set_brightness', () => {
        const r = mapping.mapDirectiveToInternalAction(
            {
                header: { namespace: 'Alexa.BrightnessController', name: 'SetBrightness' },
                payload: { brightness: 75 }
            },
            entity()
        );
        assert.equal(r.action, 'set_brightness');
        assert.equal(r.payload.brightness, 75);
    });

    it('Lock → set_lock with true', () => {
        const r = mapping.mapDirectiveToInternalAction(
            { header: { namespace: 'Alexa.LockController', name: 'Lock' }, payload: {} },
            entity({ entity_type: 'lock', state_json: '{"locked":false}' })
        );
        assert.equal(r.action, 'set_lock');
        assert.equal(r.payload.lock, true);
    });

    it('scene Activate → activate_scene + sceneActivation flag', () => {
        const r = mapping.mapDirectiveToInternalAction(
            { header: { namespace: 'Alexa.SceneController', name: 'Activate' }, payload: {} },
            entity({ entity_type: 'scene', state_json: '{}' })
        );
        assert.equal(r.action, 'activate_scene');
        assert.equal(r.sceneActivation, true);
    });

    it('SecurityPanel Arm → arm_disarm', () => {
        const r = mapping.mapDirectiveToInternalAction(
            {
                header: { namespace: 'Alexa.SecurityPanelController', name: 'Arm' },
                payload: { armState: 'ARMED_AWAY' }
            },
            entity({ entity_type: 'alarm_control_panel', state_json: '{}' })
        );
        assert.equal(r.action, 'arm_disarm');
        assert.equal(r.payload.arm, true);
        assert.equal(r.payload.arm_level, 'away');
    });

    it('camera stream directive sets cameraStream flag', () => {
        const r = mapping.mapDirectiveToInternalAction(
            {
                header: {
                    namespace: 'Alexa.CameraStreamController',
                    name: 'InitializeCameraStreams'
                },
                payload: {}
            },
            entity({ entity_type: 'camera', state_json: '{}' })
        );
        assert.equal(r.action, 'get_camera_stream');
        assert.equal(r.cameraStream, true);
    });

    it('unknown directive returns null', () => {
        const r = mapping.mapDirectiveToInternalAction(
            { header: { namespace: 'Alexa.Unknown', name: 'Foo' }, payload: {} },
            entity()
        );
        assert.equal(r, null);
    });
});

describe('buildAlexaProperties', () => {
    it('emits EndpointHealth + PowerController for a light', () => {
        const props = mapping.buildAlexaProperties({
            entity_type: 'light',
            online: true,
            state: { on: true, brightness: 60 }
        });
        const names = props.map((p) => `${p.namespace}.${p.name}`);
        assert.ok(names.includes('Alexa.EndpointHealth.connectivity'));
        assert.ok(names.includes('Alexa.PowerController.powerState'));
    });

    it('emits offline connectivity when online=false', () => {
        const props = mapping.buildAlexaProperties({
            entity_type: 'switch',
            online: false,
            state: {}
        });
        const health = props.find((p) => p.name === 'connectivity');
        assert.equal(health.value.value, 'UNREACHABLE');
    });
});
