const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { translateAlexaActionToAddonAction } = require('../../lib/alexa/addon-action-map');

const lightEntity = { entity_type: 'light' };
const fanEntity = { entity_type: 'fan' };
const coverEntity = { entity_type: 'cover' };
const vacuumEntity = { entity_type: 'vacuum' };

describe('translateAlexaActionToAddonAction — base cases', () => {
    it('power.set on → set_on {on:true}', () => {
        const r = translateAlexaActionToAddonAction('power.set', { value: 'on' }, lightEntity);
        assert.deepEqual(r, { addonAction: 'set_on', addonPayload: { on: true } });
    });

    it('power.set off → set_on {on:false}', () => {
        const r = translateAlexaActionToAddonAction('power.set', { value: 'off' }, lightEntity);
        assert.deepEqual(r, { addonAction: 'set_on', addonPayload: { on: false } });
    });

    it('brightness.set → set_brightness clamped', () => {
        const r = translateAlexaActionToAddonAction('brightness.set', { value: 70 }, lightEntity);
        assert.deepEqual(r, { addonAction: 'set_brightness', addonPayload: { brightness: 70 } });
    });

    it('color.set → set_color_hs', () => {
        const r = translateAlexaActionToAddonAction(
            'color.set',
            { hue: 120, saturation: 0.5, brightness: 0.5 },
            lightEntity
        );
        assert.equal(r.addonAction, 'set_color_hs');
        assert.equal(r.addonPayload.hue, 120);
        assert.equal(r.addonPayload.saturation, 50);
        assert.ok(r.addonPayload.brightness_255 > 0 && r.addonPayload.brightness_255 <= 255);
    });

    it('color_temperature.set → set_color_temp', () => {
        const r = translateAlexaActionToAddonAction('color_temperature.set', { kelvin: 4000 }, lightEntity);
        assert.deepEqual(r, { addonAction: 'set_color_temp', addonPayload: { color_temp_kelvin: 4000 } });
    });

    it('thermostat.mode → set_thermostat_mode', () => {
        const r = translateAlexaActionToAddonAction('thermostat.mode', { value: 'heat' }, {});
        assert.deepEqual(r, { addonAction: 'set_thermostat_mode', addonPayload: { mode: 'heat' } });
    });

    it('thermostat.setpoint target → set_thermostat_setpoint', () => {
        const r = translateAlexaActionToAddonAction(
            'thermostat.setpoint',
            { target: { value: 22, scale: 'CELSIUS' } },
            {}
        );
        assert.deepEqual(r, { addonAction: 'set_thermostat_setpoint', addonPayload: { setpoint: 22 } });
    });

    it('thermostat.setpoint lower+upper → set_thermostat_setpoint_range', () => {
        const r = translateAlexaActionToAddonAction(
            'thermostat.setpoint',
            { lower: { value: 18 }, upper: { value: 24 } },
            {}
        );
        assert.deepEqual(r, {
            addonAction: 'set_thermostat_setpoint_range',
            addonPayload: { low: 18, high: 24 }
        });
    });

    it('lock.set lock/unlock → set_lock', () => {
        assert.deepEqual(translateAlexaActionToAddonAction('lock.set', { value: 'lock' }, {}), {
            addonAction: 'set_lock',
            addonPayload: { lock: true }
        });
        assert.deepEqual(translateAlexaActionToAddonAction('lock.set', { value: 'unlock' }, {}), {
            addonAction: 'set_lock',
            addonPayload: { lock: false }
        });
    });

    it('scene.activate → activate_scene', () => {
        assert.deepEqual(translateAlexaActionToAddonAction('scene.activate', {}, {}), {
            addonAction: 'activate_scene',
            addonPayload: {}
        });
    });

    it('range.set with Fan.Speed → set_fan_speed_percent', () => {
        const r = translateAlexaActionToAddonAction(
            'range.set',
            { instance: 'Fan.Speed', value: 80 },
            fanEntity
        );
        assert.deepEqual(r, { addonAction: 'set_fan_speed_percent', addonPayload: { percentage: 80 } });
    });

    it('range.set with Cover.Position → set_open_percent', () => {
        const r = translateAlexaActionToAddonAction(
            'range.set',
            { instance: 'Cover.Position', value: 40 },
            coverEntity
        );
        assert.deepEqual(r, { addonAction: 'set_open_percent', addonPayload: { openPercent: 40 } });
    });

    it('mode.set Cover.Position Position.Open → set_open_close', () => {
        const r = translateAlexaActionToAddonAction(
            'mode.set',
            { instance: 'Cover.Position', value: 'Position.Open' },
            coverEntity
        );
        assert.deepEqual(r, { addonAction: 'set_open_close', addonPayload: { open: true } });
    });

    it('mode.set Cover.Position Position.Closed → set_open_close open:false', () => {
        const r = translateAlexaActionToAddonAction(
            'mode.set',
            { instance: 'Cover.Position', value: 'Position.Closed' },
            coverEntity
        );
        assert.deepEqual(r, { addonAction: 'set_open_close', addonPayload: { open: false } });
    });

    it('toggle.set Vacuum.Pause on → set_pause', () => {
        const r = translateAlexaActionToAddonAction(
            'toggle.set',
            { instance: 'Vacuum.Pause', value: 'on' },
            vacuumEntity
        );
        assert.deepEqual(r, { addonAction: 'set_pause', addonPayload: { pause: true } });
    });

    it('volume.set → set_volume', () => {
        assert.deepEqual(translateAlexaActionToAddonAction('volume.set', { value: 55 }, {}), {
            addonAction: 'set_volume',
            addonPayload: { volume: 55 }
        });
    });

    it('mute.set → set_mute', () => {
        assert.deepEqual(translateAlexaActionToAddonAction('mute.set', { value: true }, {}), {
            addonAction: 'set_mute',
            addonPayload: { muted: true }
        });
    });

    it('playback.* → media_*', () => {
        const cases = [
            ['playback.play', 'media_resume'],
            ['playback.pause', 'media_pause'],
            ['playback.stop', 'media_stop'],
            ['playback.next', 'media_next'],
            ['playback.previous', 'media_previous']
        ];
        for (const [a, expected] of cases) {
            assert.equal(translateAlexaActionToAddonAction(a, {}, {}).addonAction, expected);
        }
    });
});

describe('translateAlexaActionToAddonAction — unmapped and adjust semantics', () => {
    it('unknown alexa actions → null', () => {
        assert.equal(translateAlexaActionToAddonAction('nonexistent.action', {}, {}), null);
        assert.equal(translateAlexaActionToAddonAction(null, {}, {}), null);
        assert.equal(translateAlexaActionToAddonAction('', {}, {}), null);
    });

    it('brightness.adjust is intentionally NOT null (forwarded as absolute set_brightness) — documented quirk', () => {
        const r = translateAlexaActionToAddonAction('brightness.adjust', { delta: 10 }, lightEntity);
        assert.equal(r.addonAction, 'set_brightness');
    });

    it('color_temperature.adjust → null (unsupported)', () => {
        assert.equal(translateAlexaActionToAddonAction('color_temperature.adjust', { direction: 'up' }, lightEntity), null);
    });

    it('thermostat.adjust → null', () => {
        assert.equal(translateAlexaActionToAddonAction('thermostat.adjust', { delta: 1 }, {}), null);
    });

    it('range.adjust → null', () => {
        assert.equal(translateAlexaActionToAddonAction('range.adjust', { instance: 'Fan.Speed', delta: 10 }, fanEntity), null);
    });

    it('scene.deactivate → null', () => {
        assert.equal(translateAlexaActionToAddonAction('scene.deactivate', {}, {}), null);
    });

    it('volume.adjust → null', () => {
        assert.equal(translateAlexaActionToAddonAction('volume.adjust', { delta: 5 }, {}), null);
    });
});

describe('translateAlexaActionToAddonAction — cover range vs mode disambiguation', () => {
    it('range.set with Cover.Position routes to set_open_percent (not mode)', () => {
        const r = translateAlexaActionToAddonAction(
            'range.set',
            { instance: 'Cover.Position', value: 25 },
            coverEntity
        );
        assert.equal(r.addonAction, 'set_open_percent');
    });

    it('mode.set with Cover.Position routes to set_open_close (not range)', () => {
        const r = translateAlexaActionToAddonAction(
            'mode.set',
            { instance: 'Cover.Position', value: 'Position.Open' },
            coverEntity
        );
        assert.equal(r.addonAction, 'set_open_close');
    });

    it('unknown range instance with no entity type → null', () => {
        assert.equal(translateAlexaActionToAddonAction('range.set', { instance: 'Unknown.X', value: 1 }, {}), null);
    });
});
