const { describe, it, before, after, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const sqlite3 = require('sqlite3').verbose();

const createDbHelpers = require('../../lib/db-helpers');
const createAlexaCore = require('../../lib/alexa/core');
const createEntityMapping = require('../../lib/alexa/entity-mapping');
const utils = require('../../lib/utils');
const config = require('../../lib/config');
const smarthomeFactory = require('../../routes/alexa-smarthome');

// ─── Schema ────────────────────────────────────────────────────────────────

const SCHEMA = `
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'active',
        alexa_enabled INTEGER NOT NULL DEFAULT 1,
        alexa_linked  INTEGER NOT NULL DEFAULT 0,
        alexa_security_pin TEXT
    );
    CREATE TABLE devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL
    );
    CREATE TABLE alexa_auth_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        code_hash TEXT NOT NULL UNIQUE,
        redirect_uri TEXT NOT NULL,
        scopes TEXT,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        consumed_at DATETIME
    );
    CREATE TABLE alexa_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE,
        access_token_hash TEXT NOT NULL UNIQUE,
        refresh_token_hash TEXT NOT NULL UNIQUE,
        expires_at DATETIME NOT NULL,
        lwa_access_token_encrypted TEXT,
        lwa_refresh_token_encrypted TEXT,
        lwa_expires_at DATETIME,
        lwa_scopes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE alexa_entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        device_id INTEGER NOT NULL,
        entity_id TEXT NOT NULL,
        display_name TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        room_hint TEXT,
        exposed INTEGER NOT NULL DEFAULT 1,
        online INTEGER NOT NULL DEFAULT 1,
        state_json TEXT,
        UNIQUE(user_id, entity_id)
    );
    CREATE TABLE alexa_command_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        device_id INTEGER NOT NULL,
        entity_id TEXT NOT NULL,
        action TEXT NOT NULL,
        payload_json TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        result_json TEXT,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
`;

// noop crypto stub — we don't exercise real AES here.
const noopLwaCrypto = {
    encryptLwaToken: (x) => (x === null || x === undefined ? null : `enc::${x}`),
    decryptLwaToken: (x) => (x ? String(x).replace(/^enc::/, '') : null),
    hasEncryptionKey: () => true
};

// ─── Test scaffolding ──────────────────────────────────────────────────────

async function makeAppWithStub({ lwaExchange = null } = {}) {
    const db = new sqlite3.Database(':memory:');
    const helpers = createDbHelpers(db);
    await new Promise((res, rej) => {
        db.exec(SCHEMA, (e) => (e ? rej(e) : res()));
    });

    const alexaCore = createAlexaCore({
        dbGet: helpers.dbGet,
        dbRun: helpers.dbRun,
        dbAll: helpers.dbAll,
        lwaCrypto: noopLwaCrypto
    });
    const entityMapping = createEntityMapping();

    const router = smarthomeFactory({
        dbGet: helpers.dbGet,
        dbRun: helpers.dbRun,
        dbAll: helpers.dbAll,
        config: { ...config, ALEXA_CONTROL_RESPONSE_TIMEOUT_MS: 800 },
        utils,
        alexaCore,
        entityMapping,
        lwaExchange
    });

    const app = express();
    app.use(express.json());
    app.use(router);
    return { app, db, helpers, alexaCore, entityMapping };
}

function listen(app) {
    return new Promise((resolve) => {
        const server = app.listen(0, '127.0.0.1', () =>
            resolve({ server, base: `http://127.0.0.1:${server.address().port}` })
        );
    });
}

async function makeUserWithToken(helpers, alexaCore, { email = 'u@x', enabled = 1, status = 'active' } = {}) {
    await helpers.dbRun(
        `INSERT INTO users (email, status, alexa_enabled) VALUES (?, ?, ?)`,
        [email, status, enabled]
    );
    const u = await helpers.dbGet(`SELECT id FROM users WHERE email = ?`, [email]);
    const tokens = await alexaCore.issueAlexaTokensForUser(u.id);
    return { userId: u.id, ...tokens };
}

async function postDirective(base, directive, bearer) {
    return await fetch(`${base}/api/alexa/smarthome`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            ...(bearer ? { Authorization: `Bearer ${bearer}` } : {})
        },
        body: JSON.stringify({ directive })
    });
}

function discoveryDirective(token) {
    return {
        header: {
            namespace: 'Alexa.Discovery',
            name: 'Discover',
            messageId: 'm-1',
            payloadVersion: '3'
        },
        payload: { scope: { type: 'BearerToken', token } }
    };
}

function controlDirective(namespace, name, endpointId, token, payload = {}) {
    return {
        header: { namespace, name, messageId: 'm-c', correlationToken: 'c-1', payloadVersion: '3' },
        endpoint: { scope: { type: 'BearerToken', token }, endpointId, cookie: {} },
        payload
    };
}

function reportStateDirective(endpointId, token) {
    return {
        header: { namespace: 'Alexa', name: 'ReportState', messageId: 'm-r', correlationToken: 'c-r', payloadVersion: '3' },
        endpoint: { scope: { type: 'BearerToken', token }, endpointId, cookie: {} },
        payload: {}
    };
}

function acceptGrantDirective(token, code = 'lwa-code-XYZ') {
    return {
        header: {
            namespace: 'Alexa.Authorization',
            name: 'AcceptGrant',
            messageId: 'm-a',
            payloadVersion: '3'
        },
        payload: {
            grant: { type: 'OAuth2.AuthorizationCode', code },
            grantee: { type: 'BearerToken', token }
        }
    };
}

// ─── Bearer / unauth paths ─────────────────────────────────────────────────

describe('POST /api/alexa/smarthome — bearer resolution', () => {
    let server, base, db, helpers, alexaCore;
    beforeEach(async () => {
        const ctx = await makeAppWithStub();
        ({ db, helpers, alexaCore } = ctx);
        ({ server, base } = await listen(ctx.app));
    });
    afterEach(() => {
        server.close();
        db.close();
    });

    it('returns ErrorResponse INVALID_AUTHORIZATION_CREDENTIAL for an unknown bearer', async () => {
        const res = await postDirective(base, discoveryDirective('unknown-token'));
        assert.equal(res.status, 200);
        const body = await res.json();
        assert.equal(body.event.header.name, 'ErrorResponse');
        assert.equal(body.event.payload.type, 'INVALID_AUTHORIZATION_CREDENTIAL');
    });

    it('returns ErrorResponse when account is disabled', async () => {
        const u = await makeUserWithToken(helpers, alexaCore, { enabled: 0 });
        const res = await postDirective(base, discoveryDirective(u.accessToken));
        const body = await res.json();
        assert.equal(body.event.payload.type, 'INVALID_AUTHORIZATION_CREDENTIAL');
        assert.match(body.event.payload.message, /disabled/);
    });

    it('returns ErrorResponse when account is suspended', async () => {
        const u = await makeUserWithToken(helpers, alexaCore, { status: 'suspended' });
        const res = await postDirective(base, discoveryDirective(u.accessToken));
        const body = await res.json();
        assert.equal(body.event.payload.type, 'INVALID_AUTHORIZATION_CREDENTIAL');
        assert.match(body.event.payload.message, /inactive/);
    });

    it('returns ErrorResponse when the request body has no directive envelope', async () => {
        const res = await fetch(`${base}/api/alexa/smarthome`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const body = await res.json();
        assert.equal(body.event.payload.type, 'INVALID_DIRECTIVE');
    });
});

// ─── Discovery ─────────────────────────────────────────────────────────────

describe('Alexa.Discovery / Discover', () => {
    let server, base, db, helpers, alexaCore;
    beforeEach(async () => {
        const ctx = await makeAppWithStub();
        ({ db, helpers, alexaCore } = ctx);
        ({ server, base } = await listen(ctx.app));
    });
    afterEach(() => {
        server.close();
        db.close();
    });

    async function seedEntities(userId) {
        await helpers.dbRun(`INSERT INTO devices (id, user_id) VALUES (1, ?)`, [userId]);
        await helpers.dbRun(
            `INSERT INTO alexa_entities
                (user_id, device_id, entity_id, display_name, entity_type, exposed, online, state_json)
             VALUES (?, 1, 'switch.living_room_lamp', 'Living Room Lamp', 'switch', 1, 1, ?)`,
            [userId, JSON.stringify({ state: 'on', attributes: {} })]
        );
        await helpers.dbRun(
            `INSERT INTO alexa_entities
                (user_id, device_id, entity_id, display_name, entity_type, exposed, online, state_json)
             VALUES (?, 1, 'light.kitchen', 'Kitchen Ceiling', 'light', 1, 1, ?)`,
            [userId, JSON.stringify({ state: 'on', attributes: { brightness: 200 } })]
        );
        // exposed=0 must NOT appear
        await helpers.dbRun(
            `INSERT INTO alexa_entities
                (user_id, device_id, entity_id, display_name, entity_type, exposed, online, state_json)
             VALUES (?, 1, 'switch.hidden', 'Hidden', 'switch', 0, 1, ?)`,
            [userId, JSON.stringify({ state: 'off' })]
        );
        // out-of-scope domain — silently dropped this phase
        await helpers.dbRun(
            `INSERT INTO alexa_entities
                (user_id, device_id, entity_id, display_name, entity_type, exposed, online, state_json)
             VALUES (?, 1, 'fan.bedroom', 'Bedroom Fan', 'fan', 1, 1, ?)`,
            [userId, JSON.stringify({ state: 'off' })]
        );
    }

    it('returns Discover.Response with only exposed, in-scope entities', async () => {
        const u = await makeUserWithToken(helpers, alexaCore);
        await seedEntities(u.userId);

        const res = await postDirective(base, discoveryDirective(u.accessToken));
        const body = await res.json();
        assert.equal(body.event.header.namespace, 'Alexa.Discovery');
        assert.equal(body.event.header.name, 'Discover.Response');
        const ids = body.event.payload.endpoints.map((e) => e.endpointId).sort();
        assert.deepEqual(ids, ['light__kitchen', 'switch__living_room_lamp']);
    });

    it('every emitted endpoint passes validateDiscoveryPayload', async () => {
        const u = await makeUserWithToken(helpers, alexaCore);
        await seedEntities(u.userId);
        const res = await postDirective(base, discoveryDirective(u.accessToken));
        const body = await res.json();
        const { validateDiscoveryPayload } = require('../../lib/alexa/discovery-validator');
        const v = validateDiscoveryPayload(body);
        assert.deepEqual(v, { ok: true });
    });

    it('returns Discover.Response with empty endpoints when user has no entities', async () => {
        const u = await makeUserWithToken(helpers, alexaCore);
        const res = await postDirective(base, discoveryDirective(u.accessToken));
        const body = await res.json();
        assert.deepEqual(body.event.payload.endpoints, []);
    });
});

// ─── AcceptGrant — the v1 weak point ───────────────────────────────────────

describe('Alexa.Authorization / AcceptGrant', () => {
    let server, base, db, helpers, alexaCore;
    let exchangeImpl; // mutable per test

    beforeEach(async () => {
        // Default: a successful LWA exchange returning a complete pair.
        exchangeImpl = async () => ({
            access_token: 'lwa-access-XYZ',
            refresh_token: 'lwa-refresh-XYZ',
            expires_in: 3600,
            scope: 'alexa::async_event:write'
        });
        const ctx = await makeAppWithStub({ lwaExchange: (...a) => exchangeImpl(...a) });
        ({ db, helpers, alexaCore } = ctx);
        ({ server, base } = await listen(ctx.app));
    });
    afterEach(() => {
        server.close();
        db.close();
    });

    it('happy path: exchanges code, persists encrypted tokens, flips alexa_linked=1', async () => {
        const u = await makeUserWithToken(helpers, alexaCore);
        const res = await postDirective(base, acceptGrantDirective(u.accessToken));
        const body = await res.json();

        assert.equal(body.event.header.namespace, 'Alexa.Authorization');
        assert.equal(body.event.header.name, 'AcceptGrant.Response');

        const row = await helpers.dbGet(
            `SELECT alexa_linked FROM users WHERE id = ?`,
            [u.userId]
        );
        assert.equal(row.alexa_linked, 1);
        const tok = await helpers.dbGet(`SELECT * FROM alexa_tokens WHERE user_id = ?`, [u.userId]);
        assert.match(tok.lwa_refresh_token_encrypted, /^enc::lwa-refresh-XYZ$/);
    });

    it('CRITICAL v1 REGRESSION: LWA exchange failure returns ErrorResponse, NOT AcceptGrant.Response', async () => {
        exchangeImpl = async () => {
            throw new Error('simulated 502 from LWA');
        };
        const u = await makeUserWithToken(helpers, alexaCore);
        const res = await postDirective(base, acceptGrantDirective(u.accessToken));
        const body = await res.json();
        // The exact bug: v1 returned AcceptGrant.Response here, telling
        // Alexa "you're linked" when in fact we had no LWA refresh token.
        assert.equal(body.event.header.name, 'ErrorResponse');
        assert.equal(body.event.payload.type, 'ACCEPT_GRANT_FAILED');
        // And — critically — alexa_linked must STILL be 0.
        const row = await helpers.dbGet(`SELECT alexa_linked FROM users WHERE id = ?`, [u.userId]);
        assert.equal(row.alexa_linked, 0, 'alexa_linked must NOT be set on partial state');
    });

    it('CRITICAL v1 REGRESSION: LWA returns access token but no refresh token → ErrorResponse', async () => {
        exchangeImpl = async () => ({
            access_token: 'lwa-only-access',
            // refresh_token: missing — exact v1 silent-acceptance scenario
            expires_in: 3600
        });
        const u = await makeUserWithToken(helpers, alexaCore);
        const res = await postDirective(base, acceptGrantDirective(u.accessToken));
        const body = await res.json();
        assert.equal(body.event.header.name, 'ErrorResponse');
        assert.equal(body.event.payload.type, 'ACCEPT_GRANT_FAILED');
        const row = await helpers.dbGet(`SELECT alexa_linked FROM users WHERE id = ?`, [u.userId]);
        assert.equal(row.alexa_linked, 0);
    });

    it('rejects AcceptGrant when grant.code is missing', async () => {
        const u = await makeUserWithToken(helpers, alexaCore);
        const directive = acceptGrantDirective(u.accessToken);
        delete directive.payload.grant.code;
        const res = await postDirective(base, directive);
        const body = await res.json();
        assert.equal(body.event.header.name, 'ErrorResponse');
        assert.equal(body.event.payload.type, 'INVALID_AUTHORIZATION_CREDENTIAL');
    });
});

// ─── ReportState ───────────────────────────────────────────────────────────

describe('Alexa / ReportState', () => {
    let server, base, db, helpers, alexaCore;
    beforeEach(async () => {
        const ctx = await makeAppWithStub();
        ({ db, helpers, alexaCore } = ctx);
        ({ server, base } = await listen(ctx.app));
    });
    afterEach(() => {
        server.close();
        db.close();
    });

    it('returns StateReport with current properties from the DB', async () => {
        const u = await makeUserWithToken(helpers, alexaCore);
        await helpers.dbRun(`INSERT INTO devices (id, user_id) VALUES (1, ?)`, [u.userId]);
        await helpers.dbRun(
            `INSERT INTO alexa_entities (user_id, device_id, entity_id, display_name, entity_type, exposed, online, state_json)
             VALUES (?, 1, 'light.kitchen', 'Kitchen Ceiling', 'light', 1, 1, ?)`,
            [u.userId, JSON.stringify({ state: 'on', attributes: { brightness: 255 } })]
        );

        const res = await postDirective(base, reportStateDirective('light__kitchen', u.accessToken));
        const body = await res.json();
        assert.equal(body.event.header.name, 'StateReport');
        assert.equal(body.event.endpoint.endpointId, 'light__kitchen');
        const props = Object.fromEntries(body.context.properties.map((p) => [`${p.namespace}/${p.name}`, p]));
        assert.equal(props['Alexa.PowerController/powerState'].value, 'ON');
        assert.equal(props['Alexa.BrightnessController/brightness'].value, 100);
        assert.equal(props['Alexa.EndpointHealth/connectivity'].value.value, 'OK');
    });

    it('NO_SUCH_ENDPOINT for unknown endpointId', async () => {
        const u = await makeUserWithToken(helpers, alexaCore);
        const res = await postDirective(base, reportStateDirective('light__nonexistent', u.accessToken));
        const body = await res.json();
        assert.equal(body.event.header.name, 'ErrorResponse');
        assert.equal(body.event.payload.type, 'NO_SUCH_ENDPOINT');
    });
});

// ─── Control directives ────────────────────────────────────────────────────

describe('Alexa.PowerController / BrightnessController control flow', () => {
    let server, base, db, helpers, alexaCore;
    beforeEach(async () => {
        const ctx = await makeAppWithStub();
        ({ db, helpers, alexaCore } = ctx);
        ({ server, base } = await listen(ctx.app));
    });
    afterEach(() => {
        server.close();
        db.close();
    });

    async function seedSwitch(userId) {
        await helpers.dbRun(`INSERT INTO devices (id, user_id) VALUES (1, ?)`, [userId]);
        await helpers.dbRun(
            `INSERT INTO alexa_entities (user_id, device_id, entity_id, display_name, entity_type, exposed, online, state_json)
             VALUES (?, 1, 'switch.living_room_lamp', 'Living Room Lamp', 'switch', 1, 1, ?)`,
            [userId, JSON.stringify({ state: 'off' })]
        );
    }

    // Background "addon" that completes any pending command after a short
    // delay — simulates the polling addon flipping rows to status='completed'.
    function startFakeAddon(helpers, { delayMs = 100, fail = false } = {}) {
        const t = setInterval(async () => {
            try {
                const rows = await helpers.dbAll(
                    `SELECT id FROM alexa_command_queue WHERE status = 'pending' LIMIT 5`
                );
                for (const r of rows) {
                    await new Promise((res) => {
                        setTimeout(res, delayMs);
                    });
                    await helpers.dbRun(
                        `UPDATE alexa_command_queue SET status = ?, result_json = ?, updated_at = ? WHERE id = ?`,
                        [
                            fail ? 'failed' : 'completed',
                            fail ? 'simulated_failure' : 'ok',
                            new Date().toISOString(),
                            r.id
                        ]
                    );
                }
            } catch (_e) {
                /* swallow — test teardown closes db */
            }
        }, 25);
        return () => clearInterval(t);
    }

    it('TurnOn: enqueues command, waits for addon, returns Alexa.Response with optimistic powerState=ON', async () => {
        const u = await makeUserWithToken(helpers, alexaCore);
        await seedSwitch(u.userId);
        const stop = startFakeAddon(helpers);
        try {
            const res = await postDirective(
                base,
                controlDirective(
                    'Alexa.PowerController',
                    'TurnOn',
                    'switch__living_room_lamp',
                    u.accessToken
                )
            );
            const body = await res.json();
            assert.equal(body.event.header.namespace, 'Alexa');
            assert.equal(body.event.header.name, 'Response');
            assert.equal(body.event.endpoint.endpointId, 'switch__living_room_lamp');
            const props = Object.fromEntries(
                body.context.properties.map((p) => [`${p.namespace}/${p.name}`, p])
            );
            assert.equal(props['Alexa.PowerController/powerState'].value, 'ON');
        } finally {
            stop();
        }

        // Verify the command row was actually completed
        const row = await helpers.dbGet(
            `SELECT status FROM alexa_command_queue WHERE entity_id = 'switch.living_room_lamp'`
        );
        assert.equal(row.status, 'completed');
    });

    it('addon never responds: marks command expired, returns ENDPOINT_UNREACHABLE', async () => {
        const u = await makeUserWithToken(helpers, alexaCore);
        await seedSwitch(u.userId);
        // No fake addon — command will sit in 'pending' until our 800ms budget elapses.
        const res = await postDirective(
            base,
            controlDirective(
                'Alexa.PowerController',
                'TurnOff',
                'switch__living_room_lamp',
                u.accessToken
            )
        );
        const body = await res.json();
        assert.equal(body.event.header.name, 'ErrorResponse');
        assert.equal(body.event.payload.type, 'ENDPOINT_UNREACHABLE');
        // Command row must be 'expired' now so the addon doesn't fire it late.
        const row = await helpers.dbGet(
            `SELECT status FROM alexa_command_queue WHERE entity_id = 'switch.living_room_lamp'`
        );
        assert.equal(row.status, 'expired');
    });

    it('addon reports failure: returns INTERNAL_ERROR with the failure detail', async () => {
        const u = await makeUserWithToken(helpers, alexaCore);
        await seedSwitch(u.userId);
        const stop = startFakeAddon(helpers, { fail: true });
        try {
            const res = await postDirective(
                base,
                controlDirective('Alexa.PowerController', 'TurnOn', 'switch__living_room_lamp', u.accessToken)
            );
            const body = await res.json();
            assert.equal(body.event.header.name, 'ErrorResponse');
            assert.equal(body.event.payload.type, 'INTERNAL_ERROR');
            assert.match(body.event.payload.message, /simulated_failure/);
        } finally {
            stop();
        }
    });

    it('NO_SUCH_ENDPOINT for unknown endpointId', async () => {
        const u = await makeUserWithToken(helpers, alexaCore);
        const res = await postDirective(
            base,
            controlDirective('Alexa.PowerController', 'TurnOn', 'switch__unknown', u.accessToken)
        );
        const body = await res.json();
        assert.equal(body.event.payload.type, 'NO_SUCH_ENDPOINT');
    });

    it('INVALID_DIRECTIVE for unsupported namespace/name combination', async () => {
        const u = await makeUserWithToken(helpers, alexaCore);
        await seedSwitch(u.userId);
        const res = await postDirective(
            base,
            controlDirective('Alexa.PowerController', 'Toggle', 'switch__living_room_lamp', u.accessToken)
        );
        const body = await res.json();
        assert.equal(body.event.payload.type, 'INVALID_DIRECTIVE');
    });

    it('SetBrightness on a light enqueues the right HA payload', async () => {
        const u = await makeUserWithToken(helpers, alexaCore);
        await helpers.dbRun(`INSERT INTO devices (id, user_id) VALUES (1, ?)`, [u.userId]);
        await helpers.dbRun(
            `INSERT INTO alexa_entities (user_id, device_id, entity_id, display_name, entity_type, exposed, online, state_json)
             VALUES (?, 1, 'light.kitchen', 'Kitchen', 'light', 1, 1, ?)`,
            [u.userId, JSON.stringify({ state: 'on', attributes: { brightness: 100 } })]
        );
        const stop = startFakeAddon(helpers);
        try {
            const res = await postDirective(
                base,
                controlDirective(
                    'Alexa.BrightnessController',
                    'SetBrightness',
                    'light__kitchen',
                    u.accessToken,
                    { brightness: 75 }
                )
            );
            const body = await res.json();
            assert.equal(body.event.header.name, 'Response');
            const row = await helpers.dbGet(
                `SELECT action, payload_json FROM alexa_command_queue WHERE entity_id = 'light.kitchen'`
            );
            assert.equal(row.action, 'light.turn_on');
            const payload = JSON.parse(row.payload_json);
            assert.equal(payload.brightness, Math.round((75 / 100) * 255));
        } finally {
            stop();
        }
    });
});

// ─── Unsupported directive namespace ───────────────────────────────────────

describe('unsupported directive', () => {
    let server, base, db;
    before(async () => {
        const ctx = await makeAppWithStub();
        db = ctx.db;
        const u = await makeUserWithToken(ctx.helpers, ctx.alexaCore);
        ({ server, base } = await listen(ctx.app));
        // Stash bearer for the test to use
        global.__bearer = u.accessToken;
    });
    after(() => {
        server.close();
        db.close();
        delete global.__bearer;
    });

    it('returns INVALID_DIRECTIVE for an unknown namespace', async () => {
        const res = await postDirective(
            base,
            {
                header: { namespace: 'Alexa.WeatherController', name: 'GetForecast', messageId: 'm' },
                payload: { scope: { type: 'BearerToken', token: global.__bearer } }
            }
        );
        const body = await res.json();
        assert.equal(body.event.header.name, 'ErrorResponse');
        assert.equal(body.event.payload.type, 'INVALID_DIRECTIVE');
    });
});

// ─── Pure-helper tests (no HTTP) ───────────────────────────────────────────

describe('helper exports', () => {
    const { extractBearer, errorResponse } = require('../../routes/alexa-smarthome')._test;

    it('extractBearer pulls from endpoint.scope, payload.scope, payload.grantee in that order', () => {
        assert.equal(extractBearer({ endpoint: { scope: { token: 'a' } } }), 'a');
        assert.equal(extractBearer({ payload: { scope: { token: 'b' } } }), 'b');
        assert.equal(extractBearer({ payload: { grantee: { token: 'c' } } }), 'c');
        assert.equal(extractBearer({}), null);
        assert.equal(extractBearer(null), null);
    });

    it('errorResponse echoes the endpoint when present', () => {
        const out = errorResponse(
            {
                header: { correlationToken: 'c-1' },
                endpoint: { endpointId: 'switch__x' }
            },
            'NO_SUCH_ENDPOINT',
            'gone'
        );
        assert.equal(out.event.header.name, 'ErrorResponse');
        assert.equal(out.event.header.namespace, 'Alexa');
        assert.equal(out.event.header.correlationToken, 'c-1');
        assert.equal(out.event.endpoint.endpointId, 'switch__x');
        assert.equal(out.event.payload.type, 'NO_SUCH_ENDPOINT');
    });

    it('errorResponse omits endpoint for envelope-less directives', () => {
        const out = errorResponse({ header: {} }, 'INVALID_DIRECTIVE', 'no envelope');
        assert.equal('endpoint' in out.event, false);
    });
});
