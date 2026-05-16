const test = require('node:test');
const assert = require('node:assert/strict');
const v = require('../../lib/alexa/discovery-validator');

// A minimum-valid endpoint we can perturb in each test. Built to mirror the
// shape lib/alexa/entity-mapping.js will eventually emit for `switch.foo`.
function goodEndpoint(overrides = {}) {
    const base = {
        endpointId: 'switch__kitchen_light',
        manufacturerName: 'Apex Infosys',
        friendlyName: 'Kitchen Light',
        description: 'Cloud Connect switch',
        displayCategories: ['SWITCH'],
        capabilities: [
            { type: 'AlexaInterface', interface: 'Alexa', version: '3' },
            { type: 'AlexaInterface', interface: 'Alexa.PowerController', version: '3' },
            { type: 'AlexaInterface', interface: 'Alexa.EndpointHealth', version: '3.2' }
        ]
    };
    return { ...base, ...overrides };
}

function goodPayload(endpoints) {
    return {
        event: {
            header: {
                namespace: 'Alexa.Discovery',
                name: 'Discover.Response',
                payloadVersion: '3',
                messageId: 'test-message'
            },
            payload: { endpoints }
        }
    };
}

// ─────────── happy path ───────────

test('valid endpoint passes', () => {
    const r = v.validateEndpoint(goodEndpoint());
    assert.equal(r.ok, true, JSON.stringify(r.errors));
});

test('valid full Discovery payload passes', () => {
    const r = v.validateDiscoveryPayload(goodPayload([goodEndpoint()]));
    assert.equal(r.ok, true, JSON.stringify(r.errors));
});

// ─────────── endpointId rules (v1 commits 5508690 / 8005202) ───────────

test('endpointId containing a dot is rejected with hint about encodeEndpointId', () => {
    const r = v.validateEndpoint(goodEndpoint({ endpointId: 'switch.kitchen_light' }));
    assert.equal(r.ok, false);
    assert.match(r.errors[0].message, /encodeEndpointId/);
});

test('endpointId allows the encoded "__" form', () => {
    const r = v.validateEndpoint(goodEndpoint({ endpointId: 'light__hallway' }));
    assert.equal(r.ok, true);
});

// ─────────── friendlyName / manufacturerName regex (v1 commits 218e0d4 / d31e90e) ───────────

test('friendlyName with disallowed characters is rejected', () => {
    const r = v.validateEndpoint(goodEndpoint({ friendlyName: 'Kitchen / Light!' }));
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.path === 'friendlyName'));
});

test('manufacturerName with disallowed characters is rejected', () => {
    const r = v.validateEndpoint(goodEndpoint({ manufacturerName: 'Apex, Infosys.' }));
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.path === 'manufacturerName'));
});

test('friendlyName over 128 chars is rejected', () => {
    const r = v.validateEndpoint(goodEndpoint({ friendlyName: 'A'.repeat(129) }));
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /exceeds 128/.test(e.message)));
});

// ─────────── EndpointHealth interface version (v1 commit 2138b2e) ───────────

test('EndpointHealth at version "3" instead of "3.2" is rejected', () => {
    const ep = goodEndpoint();
    ep.capabilities = ep.capabilities.map((c) =>
        c.interface === 'Alexa.EndpointHealth' ? { ...c, version: '3' } : c
    );
    const r = v.validateEndpoint(ep);
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /Alexa.EndpointHealth requires version "3.2"/.test(e.message)));
});

test('endpoint missing EndpointHealth entirely is rejected', () => {
    const ep = goodEndpoint();
    ep.capabilities = ep.capabilities.filter((c) => c.interface !== 'Alexa.EndpointHealth');
    const r = v.validateEndpoint(ep);
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /EndpointHealth/.test(e.message)));
});

// ─────────── ModeController unique-value rule (v1 commit 72217c8) ───────────

test('ModeController with duplicate mode values is rejected', () => {
    const ep = goodEndpoint();
    ep.capabilities.push({
        type: 'AlexaInterface',
        interface: 'Alexa.ModeController',
        version: '3',
        configuration: {
            supportedModes: [
                { value: 'position.open' },
                { value: 'position.closed' },
                { value: 'position.open' } // duplicate
            ]
        }
    });
    const r = v.validateEndpoint(ep);
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /duplicate mode value "position\.open"/.test(e.message)));
});

test('ModeController with all unique mode values passes', () => {
    const ep = goodEndpoint();
    ep.capabilities.push({
        type: 'AlexaInterface',
        interface: 'Alexa.ModeController',
        version: '3',
        configuration: {
            supportedModes: [{ value: 'position.open' }, { value: 'position.closed' }]
        }
    });
    const r = v.validateEndpoint(ep);
    assert.equal(r.ok, true, JSON.stringify(r.errors));
});

// ─────────── displayCategories ───────────

test('empty displayCategories array is rejected', () => {
    const r = v.validateEndpoint(goodEndpoint({ displayCategories: [] }));
    assert.equal(r.ok, false);
});

// ─────────── Discovery envelope ───────────

test('Discovery envelope missing payloadVersion is rejected', () => {
    const payload = goodPayload([goodEndpoint()]);
    delete payload.event.header.payloadVersion;
    const r = v.validateDiscoveryPayload(payload);
    assert.equal(r.ok, false);
});

test('Discovery envelope with non-array endpoints is rejected', () => {
    const payload = goodPayload([goodEndpoint()]);
    payload.event.payload.endpoints = 'not-an-array';
    const r = v.validateDiscoveryPayload(payload);
    assert.equal(r.ok, false);
});

test('Discovery payload reports errors for every bad endpoint, not just the first', () => {
    const r = v.validateDiscoveryPayload(
        goodPayload([
            goodEndpoint({ endpointId: 'has.dot' }),
            goodEndpoint({ friendlyName: '!!!' })
        ])
    );
    assert.equal(r.ok, false);
    // We expect errors covering both endpoint indices.
    const indices = new Set(
        r.errors
            .map((e) => e.path.match(/endpoints\[(\d+)\]/))
            .filter(Boolean)
            .map((m) => m[1])
    );
    assert.deepEqual([...indices].sort(), ['0', '1']);
});
