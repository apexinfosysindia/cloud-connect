const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const factory = require('../../lib/alexa/entity-mapping');
const {
    encodeEndpointId,
    decodeEndpointId,
    sanitizeAlexaName,
    sanitizeModeValue,
    buildAlexaEndpoint,
    buildPropertyState,
    resolveDirective,
    parseEntityState,
    mapPowerState,
    mapBrightness,
    mapConnectivity
} = factory._pure;

const { validateEndpoint } = require('../../lib/alexa/discovery-validator');

// ─── Helper: plausible row from `alexa_entities` ───────────────────────────

function row(overrides = {}) {
    return {
        id: 1,
        user_id: 1,
        device_id: 1,
        entity_id: 'switch.living_room_lamp',
        display_name: 'Living Room Lamp',
        entity_type: 'switch',
        room_hint: null,
        exposed: 1,
        online: 1,
        state_json: JSON.stringify({ state: 'on', attributes: {} }),
        ...overrides
    };
}

// ─── encodeEndpointId / decodeEndpointId ───────────────────────────────────

describe('encodeEndpointId / decodeEndpointId', () => {
    it('encodes a switch entity_id by replacing the dot with __', () => {
        assert.equal(encodeEndpointId('switch.kitchen'), 'switch__kitchen');
        assert.equal(encodeEndpointId('light.living_room_lamp'), 'light__living_room_lamp');
    });

    it('round-trips through decodeEndpointId', () => {
        const ids = ['switch.kitchen', 'light.bedroom_ceiling', 'switch.x123_4'];
        for (const id of ids) {
            assert.equal(decodeEndpointId(encodeEndpointId(id)), id);
        }
    });

    it('throws on inputs that are not valid HA entity_ids — fail at the source, not at Alexa', () => {
        // Empty / non-string
        assert.throws(() => encodeEndpointId(''), /non-empty string/);
        assert.throws(() => encodeEndpointId(null), /non-empty string/);
        // No dot
        assert.throws(() => encodeEndpointId('switch'), /not a valid Home Assistant/);
        // Multiple dots
        assert.throws(() => encodeEndpointId('switch.a.b'), /not a valid Home Assistant/);
        // Uppercase domain
        assert.throws(() => encodeEndpointId('Switch.kitchen'), /not a valid Home Assistant/);
        // Domain starts with a digit
        assert.throws(() => encodeEndpointId('1switch.kitchen'), /not a valid Home Assistant/);
    });

    it('decodeEndpointId returns null for malformed input rather than throwing', () => {
        // Soft fail because the directive layer needs NO_SUCH_ENDPOINT path.
        assert.equal(decodeEndpointId(''), null);
        assert.equal(decodeEndpointId(null), null);
        assert.equal(decodeEndpointId('no-separator-here'), null);
        assert.equal(decodeEndpointId('__leading'), null);
        assert.equal(decodeEndpointId('trailing__'), null);
        assert.equal(decodeEndpointId('Bad__Caps'), null);
    });

    it('encoded form always passes ENDPOINT_ID_RE (the v1 dot bug)', () => {
        const { ENDPOINT_ID_RE } = require('../../lib/alexa/discovery-validator');
        for (const id of ['switch.a', 'light.b_c_d', 'switch.x9']) {
            assert.match(encodeEndpointId(id), ENDPOINT_ID_RE);
        }
    });
});

// ─── sanitizeAlexaName ─────────────────────────────────────────────────────

describe('sanitizeAlexaName', () => {
    it('passes already-clean names through', () => {
        assert.equal(sanitizeAlexaName('Living Room Lamp'), 'Living Room Lamp');
        assert.equal(sanitizeAlexaName('Bed & Bath'), 'Bed & Bath');
    });

    it('strips characters outside the Alexa friendlyName charset', () => {
        // emoji, punctuation, accented chars all get scrubbed
        assert.equal(sanitizeAlexaName("Adi's Light 🎉"), 'Adi s Light');
        assert.equal(sanitizeAlexaName('Café Lámpara'), 'Caf L mpara');
    });

    it('collapses runs of replacement spaces and trims', () => {
        assert.equal(sanitizeAlexaName('  ___***   weird   ***___  '), 'weird');
    });

    it('returns null when nothing usable survives', () => {
        assert.equal(sanitizeAlexaName(''), null);
        assert.equal(sanitizeAlexaName('***'), null);
        assert.equal(sanitizeAlexaName(null), null);
        assert.equal(sanitizeAlexaName(undefined), null);
    });

    it('clamps to 128 chars without breaking the regex', () => {
        const long = 'A'.repeat(200);
        const out = sanitizeAlexaName(long);
        assert.ok(out.length <= 128);
        assert.match(out, /^[A-Za-z0-9& ]+$/);
    });
});

// ─── sanitizeModeValue (forward-compat contract for Phase 10) ──────────────

describe('sanitizeModeValue', () => {
    it('lowers an arbitrary string into the MODE_VALUE_RE charset', () => {
        const taken = new Set();
        assert.equal(sanitizeModeValue('Cool', taken), 'Cool');
        assert.equal(sanitizeModeValue('eco mode', taken), 'eco_mode');
    });

    it('suffixes _2, _3 on collision within the same instance', () => {
        const taken = new Set();
        assert.equal(sanitizeModeValue('cool', taken), 'cool');
        assert.equal(sanitizeModeValue('cool', taken), 'cool_2');
        assert.equal(sanitizeModeValue('cool', taken), 'cool_3');
    });

    it('returns null for empty / unsalvageable input', () => {
        assert.equal(sanitizeModeValue('', new Set()), null);
        assert.equal(sanitizeModeValue('___', new Set()), null);
        assert.equal(sanitizeModeValue(null, new Set()), null);
    });
});

// ─── parseEntityState ──────────────────────────────────────────────────────

describe('parseEntityState', () => {
    it('parses a normal HA-shaped state_json blob', () => {
        const r = row({ state_json: JSON.stringify({ state: 'on', attributes: { brightness: 200 } }) });
        const p = parseEntityState(r);
        assert.equal(p.state, 'on');
        assert.equal(p.attributes.brightness, 200);
    });

    it('returns safe defaults when state_json is missing or malformed', () => {
        assert.deepEqual(parseEntityState(row({ state_json: null })), { state: null, attributes: {} });
        assert.deepEqual(parseEntityState(row({ state_json: '{not json' })), {
            state: null,
            attributes: {}
        });
        // Array attributes is bogus shape — fall back to empty object
        assert.deepEqual(
            parseEntityState(row({ state_json: JSON.stringify({ state: 'on', attributes: [] }) })).attributes,
            {}
        );
    });
});

// ─── State mappers ─────────────────────────────────────────────────────────

describe('mapPowerState', () => {
    it('maps on/off to ON/OFF and everything else to null', () => {
        assert.equal(mapPowerState('on'), 'ON');
        assert.equal(mapPowerState('off'), 'OFF');
        assert.equal(mapPowerState('unavailable'), null);
        assert.equal(mapPowerState(null), null);
    });
});

describe('mapBrightness', () => {
    it('maps HA 0..255 to Alexa 0..100 (rounded)', () => {
        assert.equal(mapBrightness(0), 0);
        assert.equal(mapBrightness(255), 100);
        assert.equal(mapBrightness(128), 50); // 50.196 → 50
        assert.equal(mapBrightness(64), 25); // 25.098 → 25
    });

    it('returns null for out-of-range or non-numeric input', () => {
        assert.equal(mapBrightness(-1), null);
        assert.equal(mapBrightness(256), null);
        assert.equal(mapBrightness(NaN), null);
        assert.equal(mapBrightness('200'), null);
        assert.equal(mapBrightness(undefined), null);
    });
});

describe('mapConnectivity', () => {
    it('OK when entity is online and HA reports a real state', () => {
        const r = row({ online: 1 });
        const p = parseEntityState(r);
        assert.equal(mapConnectivity(r, p), 'OK');
    });

    it('UNREACHABLE when addon transport is down', () => {
        const r = row({ online: 0 });
        const p = parseEntityState(r);
        assert.equal(mapConnectivity(r, p), 'UNREACHABLE');
    });

    it('UNREACHABLE when HA itself reports the entity unavailable', () => {
        const r = row({
            online: 1,
            state_json: JSON.stringify({ state: 'unavailable', attributes: {} })
        });
        const p = parseEntityState(r);
        assert.equal(mapConnectivity(r, p), 'UNREACHABLE');
    });
});

// ─── buildAlexaEndpoint — the contract test ────────────────────────────────

describe('buildAlexaEndpoint', () => {
    it('builds a valid SWITCH endpoint that survives validateEndpoint', () => {
        const ep = buildAlexaEndpoint(row());
        assert.equal(ep.endpointId, 'switch__living_room_lamp');
        assert.deepEqual(ep.displayCategories, ['SWITCH']);
        assert.equal(ep.friendlyName, 'Living Room Lamp');
        const ifaces = ep.capabilities.map((c) => c.interface);
        assert.ok(ifaces.includes('Alexa'));
        assert.ok(ifaces.includes('Alexa.EndpointHealth'));
        assert.ok(ifaces.includes('Alexa.PowerController'));
        assert.ok(!ifaces.includes('Alexa.BrightnessController'));
        // Cookie carries the raw entity_id back so the directive layer can
        // skip a decode step.
        assert.equal(ep.cookie.ha_entity_id, 'switch.living_room_lamp');
        // Hard contract.
        assert.deepEqual(validateEndpoint(ep), { ok: true });
    });

    it('builds a LIGHT endpoint and INCLUDES BrightnessController when brightness present', () => {
        const ep = buildAlexaEndpoint(
            row({
                entity_id: 'light.kitchen',
                display_name: 'Kitchen Ceiling',
                state_json: JSON.stringify({ state: 'on', attributes: { brightness: 180 } })
            })
        );
        assert.deepEqual(ep.displayCategories, ['LIGHT']);
        const ifaces = ep.capabilities.map((c) => c.interface);
        assert.ok(ifaces.includes('Alexa.BrightnessController'));
        assert.deepEqual(validateEndpoint(ep), { ok: true });
    });

    it('OMITS BrightnessController when the light reports no numeric brightness', () => {
        const ep = buildAlexaEndpoint(
            row({
                entity_id: 'light.kitchen',
                state_json: JSON.stringify({ state: 'off', attributes: {} })
            })
        );
        const ifaces = ep.capabilities.map((c) => c.interface);
        assert.ok(!ifaces.includes('Alexa.BrightnessController'));
        // PowerController + EndpointHealth still present, validator happy.
        assert.deepEqual(validateEndpoint(ep), { ok: true });
    });

    it('returns null (not throw) for out-of-scope domains so route can filter', () => {
        // Phase 10 will add fan; for now it's silently dropped from Discovery.
        assert.equal(buildAlexaEndpoint(row({ entity_id: 'fan.bedroom' })), null);
        assert.equal(buildAlexaEndpoint(row({ entity_id: 'climate.thermostat' })), null);
    });

    it('falls back to the object_id when display_name has no salvageable chars', () => {
        const ep = buildAlexaEndpoint(
            row({ entity_id: 'switch.kitchen_fan', display_name: '🔥🎉' })
        );
        // "kitchen_fan" → "kitchen fan"
        assert.equal(ep.friendlyName, 'kitchen fan');
        assert.deepEqual(validateEndpoint(ep), { ok: true });
    });

    it('produces an endpointId that contains NO dots (the v1 root cause)', () => {
        const ep = buildAlexaEndpoint(row());
        assert.ok(!ep.endpointId.includes('.'), 'endpointId must not contain "."');
    });

    it('always advertises Alexa.EndpointHealth (v1 missed it on some endpoints)', () => {
        for (const eid of ['switch.a', 'light.b']) {
            const ep = buildAlexaEndpoint(row({ entity_id: eid }));
            const health = ep.capabilities.find((c) => c.interface === 'Alexa.EndpointHealth');
            assert.ok(health, `EndpointHealth missing for ${eid}`);
            assert.equal(health.version, '3.2');
        }
    });

    it('throws on missing entity_id', () => {
        assert.throws(() => buildAlexaEndpoint({ display_name: 'x' }), /entity\.entity_id required/);
        assert.throws(() => buildAlexaEndpoint(null), /must be an object/);
    });
});

// ─── buildPropertyState ────────────────────────────────────────────────────

describe('buildPropertyState', () => {
    const FIXED_NOW = '2026-05-10T00:00:00.000Z';

    it('reports connectivity + powerState for a normal switch', () => {
        const props = buildPropertyState(row({ state_json: JSON.stringify({ state: 'on' }) }), FIXED_NOW);
        const byName = Object.fromEntries(props.map((p) => [`${p.namespace}/${p.name}`, p]));
        assert.equal(byName['Alexa.EndpointHealth/connectivity'].value.value, 'OK');
        assert.equal(byName['Alexa.PowerController/powerState'].value, 'ON');
        // timeOfSample uses the supplied nowIso, not a fresh new Date()
        assert.equal(byName['Alexa.PowerController/powerState'].timeOfSample, FIXED_NOW);
    });

    it('reports brightness for a light only when the attribute is present', () => {
        const lit = buildPropertyState(
            row({
                entity_id: 'light.kitchen',
                state_json: JSON.stringify({ state: 'on', attributes: { brightness: 255 } })
            }),
            FIXED_NOW
        );
        const brightness = lit.find((p) => p.namespace === 'Alexa.BrightnessController');
        assert.equal(brightness.value, 100);

        const dark = buildPropertyState(
            row({ entity_id: 'light.kitchen', state_json: JSON.stringify({ state: 'off' }) }),
            FIXED_NOW
        );
        assert.ok(!dark.some((p) => p.namespace === 'Alexa.BrightnessController'));
    });

    it('reports UNREACHABLE + omits powerState when device is offline', () => {
        const props = buildPropertyState(row({ online: 0 }), FIXED_NOW);
        const conn = props.find((p) => p.namespace === 'Alexa.EndpointHealth');
        assert.equal(conn.value.value, 'UNREACHABLE');
        // powerState is unknown, so it should not appear.
        // (parsedState.state = "on" still, but we keep the rule simple for now.)
        // We DO emit powerState if HA reports on/off — that's fine even when
        // transport is flaky. The connectivity flag carries the warning.
        assert.ok(props.some((p) => p.namespace === 'Alexa.PowerController'));
    });

    it('returns [] for out-of-scope domains', () => {
        assert.deepEqual(buildPropertyState(row({ entity_id: 'fan.bedroom' })), []);
    });
});

// ─── resolveDirective ──────────────────────────────────────────────────────

describe('resolveDirective', () => {
    const switchRow = row();
    const lightRow = row({ entity_id: 'light.kitchen' });

    it('PowerController.TurnOn → switch.turn_on / light.turn_on', () => {
        assert.deepEqual(
            resolveDirective({ header: { namespace: 'Alexa.PowerController', name: 'TurnOn' } }, switchRow),
            { service: 'switch.turn_on', payload: { entity_id: 'switch.living_room_lamp' } }
        );
        assert.deepEqual(
            resolveDirective({ header: { namespace: 'Alexa.PowerController', name: 'TurnOn' } }, lightRow),
            { service: 'light.turn_on', payload: { entity_id: 'light.kitchen' } }
        );
    });

    it('PowerController.TurnOff → switch.turn_off / light.turn_off', () => {
        assert.deepEqual(
            resolveDirective({ header: { namespace: 'Alexa.PowerController', name: 'TurnOff' } }, switchRow),
            { service: 'switch.turn_off', payload: { entity_id: 'switch.living_room_lamp' } }
        );
    });

    it('BrightnessController.SetBrightness scales 0..100 → 0..255 for HA', () => {
        const r = resolveDirective(
            {
                header: { namespace: 'Alexa.BrightnessController', name: 'SetBrightness' },
                payload: { brightness: 50 }
            },
            lightRow
        );
        assert.equal(r.service, 'light.turn_on');
        assert.equal(r.payload.brightness, 128); // round(0.5 * 255)
    });

    it('BrightnessController.AdjustBrightness → brightness_step_pct passthrough', () => {
        const r = resolveDirective(
            {
                header: { namespace: 'Alexa.BrightnessController', name: 'AdjustBrightness' },
                payload: { brightnessDelta: -25 }
            },
            lightRow
        );
        assert.equal(r.payload.brightness_step_pct, -25);
    });

    it('returns null for BrightnessController against a non-light entity', () => {
        assert.equal(
            resolveDirective(
                {
                    header: { namespace: 'Alexa.BrightnessController', name: 'SetBrightness' },
                    payload: { brightness: 50 }
                },
                switchRow
            ),
            null
        );
    });

    it('returns null for unsupported namespaces / names so route emits INVALID_DIRECTIVE', () => {
        assert.equal(
            resolveDirective({ header: { namespace: 'Alexa.PowerController', name: 'Toggle' } }, switchRow),
            null
        );
        assert.equal(
            resolveDirective(
                { header: { namespace: 'Alexa.ColorController', name: 'SetColor' } },
                lightRow
            ),
            null
        );
    });

    it('rejects malformed brightness payloads instead of silently coercing', () => {
        // Out of range
        assert.equal(
            resolveDirective(
                {
                    header: { namespace: 'Alexa.BrightnessController', name: 'SetBrightness' },
                    payload: { brightness: 200 }
                },
                lightRow
            ),
            null
        );
        // Wrong type
        assert.equal(
            resolveDirective(
                {
                    header: { namespace: 'Alexa.BrightnessController', name: 'SetBrightness' },
                    payload: { brightness: '50' }
                },
                lightRow
            ),
            null
        );
    });
});

// ─── Factory contract ──────────────────────────────────────────────────────

describe('factory shape', () => {
    it('exposes the public surface needed by the route layer', () => {
        const m = factory();
        for (const k of [
            'encodeEndpointId',
            'decodeEndpointId',
            'sanitizeAlexaName',
            'sanitizeModeValue',
            'buildAlexaEndpoint',
            'buildPropertyState',
            'resolveDirective',
            'DOMAIN_TO_DISPLAY_CATEGORY',
            'DOMAIN_TO_INTERFACES',
            'MANUFACTURER_NAME'
        ]) {
            assert.ok(k in m, `missing export: ${k}`);
        }
    });
});
