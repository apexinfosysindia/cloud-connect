/**
 * End-to-end integration test for the Alexa Smart Home control loop.
 *
 * What this exercises that the per-route unit tests cannot:
 *
 *   The smart-home route inserts a row into alexa_command_queue and then
 *   busy-polls that same row waiting for the addon to flip it. The addon
 *   route polls /commands/poll, takes the row (status='dispatched'), runs
 *   the action, and POSTs /commands/:id/result.
 *
 *   The unit tests stub the other half each. This file mounts BOTH routes
 *   against one in-memory SQLite and drives the actual handoff. Specifically
 *   we verify three things the unit tests do not see:
 *
 *     1. Happy path: the directive returns Alexa.Response within the
 *        timeout, with the optimistic property reflecting the directive.
 *
 *     2. Addon-late path: the smart-home route MUST give up at the
 *        ALEXA_CONTROL_RESPONSE_TIMEOUT_MS boundary, mark the row 'expired',
 *        and return ENDPOINT_UNREACHABLE. A late /commands/:id/result POST
 *        from the addon must be accepted as a no-op (prior_status 'expired')
 *        rather than throwing or re-firing the command.
 *
 *     3. Addon-failure path: the addon claims the command and reports
 *        success=false. The smart-home route must return Alexa.ErrorResponse
 *        with INTERNAL_ERROR rather than spinning to timeout.
 *
 * The v1 post-mortem flagged the addon-late case specifically: a directive
 * arriving during a brief addon disconnect would have its row sit in
 * 'pending' until timeout, but the addon would later claim and execute it
 * after we'd already returned an error to Alexa, leaving the device in an
 * inconsistent state. The accept-as-no-op contract is what prevents that.
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const sqlite3 = require('sqlite3').verbose();

const createDbHelpers = require('../../lib/db-helpers');
const createAlexaCore = require('../../lib/alexa/core');
const createEntityMapping = require('../../lib/alexa/entity-mapping');
const utils = require('../../lib/utils');
const config = require('../../lib/config');
const smarthomeFactory = require('../../routes/alexa-smarthome');
const deviceApiFactory = require('../../routes/alexa-device-api');

// Unioned schema: superset of what each route touches, taken verbatim from
// the per-route test schemas so this file doesn't drift from them.
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
        state_hash TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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
    CREATE TABLE alexa_sync_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        device_id INTEGER NOT NULL,
        snapshot_entity_ids_json TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, device_id)
    );
`;

const noopLwaCrypto = {
    encryptLwaToken: (x) => (x === null || x === undefined ? null : `enc::${x}`),
    decryptLwaToken: (x) => (x ? String(x).replace(/^enc::/, '') : null),
    hasEncryptionKey: () => true
};

// Same shape as device-api.test.js: addon authenticates with x-device-token.
function fakeDeviceAuth({ userId = 1, deviceId = 1 } = {}) {
    return {
        requireDeviceAuth(req, res, next) {
            const token = req.get('x-device-token') || '';
            if (token !== 'good-token') {
                return res.status(401).json({ error: 'unauthorized' });
            }
            req.device = { id: deviceId, user_id: userId };
            return next();
        }
    };
}

// Build an app with BOTH routes mounted on the same SQLite instance.
// `controlTimeoutMs` is exposed so individual tests can pick a value that
// matches the timing assertion they care about.
async function makeApp({ controlTimeoutMs = 1500 } = {}) {
    const db = new sqlite3.Database(':memory:');
    const helpers = createDbHelpers(db);
    await new Promise((res, rej) => {
        db.exec(SCHEMA, (e) => (e ? rej(e) : res()));
    });
    await helpers.dbRun(`INSERT INTO devices (id, user_id) VALUES (1, 1)`);

    const alexaCore = createAlexaCore({
        dbGet: helpers.dbGet,
        dbRun: helpers.dbRun,
        dbAll: helpers.dbAll,
        lwaCrypto: noopLwaCrypto
    });
    const entityMapping = createEntityMapping();

    const smarthome = smarthomeFactory({
        dbGet: helpers.dbGet,
        dbRun: helpers.dbRun,
        dbAll: helpers.dbAll,
        config: { ...config, ALEXA_CONTROL_RESPONSE_TIMEOUT_MS: controlTimeoutMs },
        utils,
        alexaCore,
        entityMapping
    });
    const deviceApi = deviceApiFactory({
        dbGet: helpers.dbGet,
        dbRun: helpers.dbRun,
        dbAll: helpers.dbAll,
        auth: fakeDeviceAuth(),
        utils,
        alexaCore: {}
    });

    const app = express();
    app.use(express.json());
    app.use(smarthome);
    app.use(deviceApi);
    return { app, db, helpers, alexaCore, entityMapping };
}

function listen(app) {
    return new Promise((resolve) => {
        const server = app.listen(0, '127.0.0.1', () =>
            resolve({ server, base: `http://127.0.0.1:${server.address().port}` })
        );
    });
}

// ─── Test fixture: a linked user with one switch entity ────────────────────

async function seedLinkedUserWithSwitch(helpers, alexaCore) {
    await helpers.dbRun(`INSERT INTO users (email, alexa_enabled) VALUES ('e2e@x', 1)`);
    const u = await helpers.dbGet(`SELECT id FROM users WHERE email = 'e2e@x'`);
    const tokens = await alexaCore.issueAlexaTokensForUser(u.id);
    await helpers.dbRun(
        `INSERT INTO alexa_entities
            (user_id, device_id, entity_id, display_name, entity_type, exposed, online, state_json)
         VALUES (?, 1, 'switch.kitchen', 'Kitchen', 'switch', 1, 1, ?)`,
        [u.id, JSON.stringify({ state: 'off', attributes: {} })]
    );
    return { userId: u.id, accessToken: tokens.accessToken };
}

function turnOnDirective(token) {
    return {
        header: {
            namespace: 'Alexa.PowerController',
            name: 'TurnOn',
            messageId: 'msg-e2e-1',
            correlationToken: 'ct-1',
            payloadVersion: '3'
        },
        endpoint: {
            scope: { type: 'BearerToken', token },
            endpointId: 'switch__kitchen'
        },
        payload: {}
    };
}

async function postDirective(base, directive) {
    return await fetch(`${base}/api/alexa/smarthome`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ directive })
    });
}

async function pollCommands(base) {
    const r = await fetch(`${base}/api/internal/devices/alexa/commands/poll`, {
        headers: { 'x-device-token': 'good-token' }
    });
    return await r.json();
}

async function postResult(base, id, body) {
    return await fetch(`${base}/api/internal/devices/alexa/commands/${id}/result`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-device-token': 'good-token'
        },
        body: JSON.stringify(body)
    });
}

// ─── Tests ─────────────────────────────────────────────────────────────────

describe('alexa end-to-end: directive → queue → addon → result', () => {
    let server, base, db, helpers, alexaCore;

    afterEach(() => {
        if (server) server.close();
        if (db) db.close();
    });

    it('happy path: addon answers within timeout, Alexa.Response returned', async () => {
        const ctx = await makeApp({ controlTimeoutMs: 1500 });
        ({ db, helpers, alexaCore } = ctx);
        ({ server, base } = await listen(ctx.app));

        const { accessToken } = await seedLinkedUserWithSwitch(helpers, alexaCore);

        // Drive the directive and the addon concurrently. The smart-home
        // route's busy-poll cadence is 100 ms; we let it run two cycles
        // before the addon answers, which is well inside the 1500 ms
        // budget but proves the loop actually rendezvous'd via SQLite
        // rather than racing past it.
        //
        // The addon coroutine always acks before returning, even if it
        // collects information for later assertions. A throw inside the
        // coroutine would unblock the Promise.all but leave the smart-home
        // request still busy-polling at afterEach time, producing a
        // SQLITE_MISUSE noise trail. So: ack first, assert after.
        let observedPending = null;
        const [resp] = await Promise.all([
            postDirective(base, turnOnDirective(accessToken)),
            (async () => {
                await new Promise((r) => setTimeout(r, 250));
                const { pending } = await pollCommands(base);
                observedPending = pending;
                if (pending.length > 0) {
                    await postResult(base, pending[0].id, { success: true });
                }
            })()
        ]);

        // Now safe to assert on what the addon coroutine saw — the
        // directive request has fully resolved.
        assert.ok(observedPending, 'addon coroutine ran');
        assert.equal(observedPending.length, 1, 'addon should see exactly one pending command');
        assert.equal(observedPending[0].action, 'switch.turn_on');

        assert.equal(resp.status, 200);
        const body = await resp.json();
        assert.equal(body.event.header.namespace, 'Alexa');
        assert.equal(body.event.header.name, 'Response');
        assert.equal(body.event.endpoint.endpointId, 'switch__kitchen');
        // Optimistic property: powerState should reflect the directive.
        const power = body.context.properties.find((p) => p.namespace === 'Alexa.PowerController');
        assert.ok(power, 'PowerController property should be present');
        assert.equal(power.value, 'ON');

        // And the queue row must be marked completed (not still 'dispatched').
        const queueRow = await helpers.dbGet(`SELECT status FROM alexa_command_queue ORDER BY id DESC LIMIT 1`);
        assert.equal(queueRow.status, 'completed');
    });

    it('addon-late path: timeout returns ENDPOINT_UNREACHABLE; late result is no-op', async () => {
        // Tight timeout so we don't burn 8 seconds in the test.
        const ctx = await makeApp({ controlTimeoutMs: 500 });
        ({ db, helpers, alexaCore } = ctx);
        ({ server, base } = await listen(ctx.app));

        const { accessToken } = await seedLinkedUserWithSwitch(helpers, alexaCore);

        // Send the directive but DO NOT run the addon side until after the
        // route has timed out.
        const resp = await postDirective(base, turnOnDirective(accessToken));
        assert.equal(resp.status, 200);
        const body = await resp.json();
        assert.equal(body.event.header.namespace, 'Alexa');
        assert.equal(body.event.header.name, 'ErrorResponse');
        assert.equal(body.event.payload.type, 'ENDPOINT_UNREACHABLE');

        // Row must be 'expired' now — the smart-home route flips it on
        // timeout precisely so the addon doesn't fire it late.
        let queueRow = await helpers.dbGet(`SELECT id, status FROM alexa_command_queue ORDER BY id DESC LIMIT 1`);
        assert.equal(queueRow.status, 'expired');

        // The addon shows up late and tries to claim the command. /poll
        // already filters on status='pending', so 'expired' rows are NOT
        // handed to it — verify that contract.
        const { pending } = await pollCommands(base);
        assert.equal(pending.length, 0, 'expired commands must not be returned by /poll');

        // If the addon did execute the command anyway (race against /poll
        // or stale cache), it might still try to POST a result. The contract
        // is: accept it as a no-op rather than 500'ing.
        const lateResultRes = await postResult(base, queueRow.id, { success: true });
        assert.equal(lateResultRes.status, 200);
        const lateBody = await lateResultRes.json();
        assert.equal(lateBody.no_op, true);
        assert.equal(lateBody.prior_status, 'expired');

        // And critically: the row stays expired. We do NOT promote a late
        // ack to 'completed' — that would re-write history and confuse any
        // future audit query.
        queueRow = await helpers.dbGet(`SELECT status FROM alexa_command_queue ORDER BY id DESC LIMIT 1`);
        assert.equal(queueRow.status, 'expired');
    });

    it('addon-failure path: success=false yields ErrorResponse INTERNAL_ERROR', async () => {
        const ctx = await makeApp({ controlTimeoutMs: 1500 });
        ({ db, helpers, alexaCore } = ctx);
        ({ server, base } = await listen(ctx.app));

        const { accessToken } = await seedLinkedUserWithSwitch(helpers, alexaCore);

        const [resp] = await Promise.all([
            postDirective(base, turnOnDirective(accessToken)),
            (async () => {
                await new Promise((r) => setTimeout(r, 200));
                const { pending } = await pollCommands(base);
                await postResult(base, pending[0].id, {
                    success: false,
                    error: 'service_call_failed: zigbee.send timed out'
                });
            })()
        ]);

        assert.equal(resp.status, 200);
        const body = await resp.json();
        assert.equal(body.event.header.name, 'ErrorResponse');
        // The smart-home route translates a 'failed' row into INTERNAL_ERROR
        // (not ENDPOINT_UNREACHABLE — that one is reserved for the timeout
        // path, where we never heard back at all).
        assert.equal(body.event.payload.type, 'INTERNAL_ERROR');

        const queueRow = await helpers.dbGet(`SELECT status, result_json FROM alexa_command_queue ORDER BY id DESC LIMIT 1`);
        assert.equal(queueRow.status, 'failed');
        assert.match(queueRow.result_json, /zigbee\.send/);
    });

    it('two concurrent directives for distinct entities do not block each other', async () => {
        // Regression guard: the busy-poll inside handleControl runs in its
        // own request handler, so two simultaneous directives should each
        // get their own queue row and resolve independently. If we ever
        // accidentally introduced a single-flight gate on the queue, this
        // test would surface it as a doubled latency.
        const ctx = await makeApp({ controlTimeoutMs: 1500 });
        ({ db, helpers, alexaCore } = ctx);
        ({ server, base } = await listen(ctx.app));

        const { accessToken } = await seedLinkedUserWithSwitch(helpers, alexaCore);
        // Add a second exposed entity so we have two endpoints to drive.
        await helpers.dbRun(
            `INSERT INTO alexa_entities
                (user_id, device_id, entity_id, display_name, entity_type, exposed, online, state_json)
             VALUES (1, 1, 'switch.bedroom', 'Bedroom', 'switch', 1, 1, ?)`,
            [JSON.stringify({ state: 'off', attributes: {} })]
        );

        const directiveA = turnOnDirective(accessToken);
        const directiveB = {
            ...directiveA,
            header: { ...directiveA.header, messageId: 'msg-e2e-2', correlationToken: 'ct-2' },
            endpoint: { ...directiveA.endpoint, endpointId: 'switch__bedroom' }
        };

        const t0 = Date.now();
        const [respA, respB] = await Promise.all([
            postDirective(base, directiveA),
            postDirective(base, directiveB),
            (async () => {
                // Single addon-side worker that drains whatever's pending.
                // We poll once to grab both, then ack them.
                await new Promise((r) => setTimeout(r, 250));
                const { pending } = await pollCommands(base);
                assert.equal(pending.length, 2, 'both directives should be queued');
                for (const cmd of pending) {
                    await postResult(base, cmd.id, { success: true });
                }
            })()
        ]);
        const elapsed = Date.now() - t0;

        assert.equal((await respA.json()).event.header.name, 'Response');
        assert.equal((await respB.json()).event.header.name, 'Response');
        // Both should resolve in well under one timeout window — we'd expect
        // ~300 ms in practice. If they were serialized through a shared
        // latch they'd take >= 2× the addon's polling delay, which is a
        // signal worth catching even if we keep the bound generous.
        assert.ok(elapsed < 1200, `concurrent directives took ${elapsed}ms`);
    });
});
