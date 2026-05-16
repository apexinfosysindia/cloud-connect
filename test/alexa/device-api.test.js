const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const sqlite3 = require('sqlite3').verbose();

const createDbHelpers = require('../../lib/db-helpers');
const utils = require('../../lib/utils');
const deviceApiFactory = require('../../routes/alexa-device-api');
const { hashEntityState, asValidEntityId } = require('../../routes/alexa-device-api')._test;

// ─── Schema (only the bits this route touches) ─────────────────────────────

const SCHEMA = `
    CREATE TABLE devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL
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

// Stub the device-auth middleware. Real auth.requireDeviceAuth has its own
// tests; here we just need it to attach req.device.
function fakeAuth({ userId = 1, deviceId = 1 } = {}) {
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

async function makeApp() {
    const db = new sqlite3.Database(':memory:');
    const helpers = createDbHelpers(db);
    await new Promise((res, rej) => {
        db.exec(SCHEMA, (e) => (e ? rej(e) : res()));
    });
    await helpers.dbRun(`INSERT INTO devices (id, user_id) VALUES (1, 1)`);

    const router = deviceApiFactory({
        dbGet: helpers.dbGet,
        dbRun: helpers.dbRun,
        dbAll: helpers.dbAll,
        auth: fakeAuth(),
        utils,
        alexaCore: {} // unused by this route
    });
    const app = express();
    app.use(express.json());
    app.use(router);
    return { app, db, helpers };
}

function listen(app) {
    return new Promise((resolve) => {
        const server = app.listen(0, '127.0.0.1', () =>
            resolve({ server, base: `http://127.0.0.1:${server.address().port}` })
        );
    });
}

const AUTH_HEADERS = { 'x-device-token': 'good-token', 'Content-Type': 'application/json' };

// ─── Pure helpers ─────────────────────────────────────────────────────────

describe('helpers', () => {
    it('hashEntityState is stable for identical input and differs for changed input', () => {
        const a = JSON.stringify({ state: 'on' });
        const b = JSON.stringify({ state: 'off' });
        assert.equal(hashEntityState(a), hashEntityState(a));
        assert.notEqual(hashEntityState(a), hashEntityState(b));
        assert.equal(hashEntityState('').length, 64); // sha256 hex
    });

    it('asValidEntityId mirrors entity-mapping.encodeEndpointId input contract', () => {
        assert.equal(asValidEntityId('switch.kitchen'), true);
        assert.equal(asValidEntityId('light.bedroom_lamp_2'), true);
        assert.equal(asValidEntityId('Switch.kitchen'), false);
        assert.equal(asValidEntityId('switch'), false);
        assert.equal(asValidEntityId('switch.a.b'), false);
        assert.equal(asValidEntityId(''), false);
        assert.equal(asValidEntityId(null), false);
    });
});

// ─── Auth ─────────────────────────────────────────────────────────────────

describe('device-auth gating', () => {
    let server, base, db;
    beforeEach(async () => {
        const ctx = await makeApp();
        ({ db } = ctx);
        ({ server, base } = await listen(ctx.app));
    });
    afterEach(() => {
        server.close();
        db.close();
    });

    it('401 without device token on every endpoint', async () => {
        const r1 = await fetch(`${base}/api/internal/devices/alexa/entities/sync`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ entities: [] })
        });
        assert.equal(r1.status, 401);
        const r2 = await fetch(`${base}/api/internal/devices/alexa/commands/poll`);
        assert.equal(r2.status, 401);
        const r3 = await fetch(`${base}/api/internal/devices/alexa/commands/1/result`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: '{}'
        });
        assert.equal(r3.status, 401);
    });
});

// ─── Sync ─────────────────────────────────────────────────────────────────

describe('POST /entities/sync', () => {
    let server, base, db, helpers;
    beforeEach(async () => {
        const ctx = await makeApp();
        ({ db, helpers } = ctx);
        ({ server, base } = await listen(ctx.app));
    });
    afterEach(() => {
        server.close();
        db.close();
    });

    async function sync(entities) {
        const res = await fetch(`${base}/api/internal/devices/alexa/entities/sync`, {
            method: 'POST',
            headers: AUTH_HEADERS,
            body: JSON.stringify({ entities })
        });
        return { status: res.status, body: await res.json() };
    }

    it('first sync inserts every valid entity and reports added count', async () => {
        const out = await sync([
            { entity_id: 'switch.kitchen', display_name: 'Kitchen', entity_type: 'switch', state: { state: 'off' } },
            { entity_id: 'light.bedroom', display_name: 'Bedroom', entity_type: 'light', state: { state: 'on', attributes: { brightness: 200 } } }
        ]);
        assert.equal(out.status, 200);
        assert.equal(out.body.added, 2);
        assert.equal(out.body.updated, 0);
        assert.equal(out.body.removed, 0);
        const rows = await helpers.dbAll(`SELECT entity_id, exposed FROM alexa_entities ORDER BY entity_id`);
        assert.equal(rows.length, 2);
        assert.ok(rows.every((r) => r.exposed === 1));
    });

    it('second sync with same payload reports zero adds/updates', async () => {
        const ents = [
            { entity_id: 'switch.kitchen', display_name: 'Kitchen', entity_type: 'switch', state: { state: 'on' } }
        ];
        await sync(ents);
        const out2 = await sync(ents);
        assert.equal(out2.body.added, 0);
        assert.equal(out2.body.updated, 0);
        assert.equal(out2.body.removed, 0);
    });

    it('detects state changes via state_hash', async () => {
        await sync([
            { entity_id: 'switch.kitchen', display_name: 'Kitchen', entity_type: 'switch', state: { state: 'on' } }
        ]);
        const out2 = await sync([
            { entity_id: 'switch.kitchen', display_name: 'Kitchen', entity_type: 'switch', state: { state: 'off' } }
        ]);
        assert.equal(out2.body.updated, 1);
        const row = await helpers.dbGet(`SELECT state_json FROM alexa_entities WHERE entity_id = 'switch.kitchen'`);
        assert.equal(JSON.parse(row.state_json).state, 'off');
    });

    it('removed entities are marked exposed=0, NOT deleted (in-flight commands need them)', async () => {
        await sync([
            { entity_id: 'switch.kitchen', display_name: 'Kitchen', entity_type: 'switch', state: { state: 'on' } },
            { entity_id: 'switch.living_room', display_name: 'Living', entity_type: 'switch', state: { state: 'off' } }
        ]);
        const out2 = await sync([
            { entity_id: 'switch.kitchen', display_name: 'Kitchen', entity_type: 'switch', state: { state: 'on' } }
        ]);
        assert.equal(out2.body.removed, 1);
        const row = await helpers.dbGet(`SELECT exposed FROM alexa_entities WHERE entity_id = 'switch.living_room'`);
        assert.equal(row.exposed, 0); // hidden, not gone
    });

    it('re-exposes a previously-removed entity if the addon re-sends it', async () => {
        await sync([
            { entity_id: 'switch.kitchen', display_name: 'Kitchen', entity_type: 'switch', state: { state: 'on' } }
        ]);
        await sync([]); // removes it (exposed=0)
        const out3 = await sync([
            { entity_id: 'switch.kitchen', display_name: 'Kitchen', entity_type: 'switch', state: { state: 'off' } }
        ]);
        assert.equal(out3.body.updated, 1);
        const row = await helpers.dbGet(`SELECT exposed FROM alexa_entities WHERE entity_id = 'switch.kitchen'`);
        assert.equal(row.exposed, 1);
    });

    it('skips invalid entities with reasons rather than 400-ing the whole batch', async () => {
        const out = await sync([
            { entity_id: 'Bad.Caps', display_name: 'X', entity_type: 'switch' }, // invalid id
            { entity_id: 'switch.no_name', display_name: '', entity_type: 'switch' }, // missing name
            { entity_id: 'switch.no_type', display_name: 'OK', entity_type: '' }, // missing type
            { entity_id: 'switch.good', display_name: 'Good', entity_type: 'switch', state: { state: 'on' } }
        ]);
        assert.equal(out.body.added, 1);
        assert.equal(out.body.skipped.length, 3);
        const reasons = out.body.skipped.map((s) => s.reason).sort();
        assert.deepEqual(reasons, ['invalid_entity_id', 'missing_display_name', 'missing_entity_type']);
    });

    it('400 when `entities` is not an array', async () => {
        const res = await fetch(`${base}/api/internal/devices/alexa/entities/sync`, {
            method: 'POST',
            headers: AUTH_HEADERS,
            body: JSON.stringify({})
        });
        assert.equal(res.status, 400);
    });
});

// ─── Poll ─────────────────────────────────────────────────────────────────

describe('GET /commands/poll', () => {
    let server, base, db, helpers;
    beforeEach(async () => {
        const ctx = await makeApp();
        ({ db, helpers } = ctx);
        ({ server, base } = await listen(ctx.app));
    });
    afterEach(() => {
        server.close();
        db.close();
    });

    async function enqueue({ status = 'pending', expiresAt = new Date(Date.now() + 60_000).toISOString(), payload = {} } = {}) {
        const r = await helpers.dbRun(
            `INSERT INTO alexa_command_queue (user_id, device_id, entity_id, action, payload_json, status, expires_at)
             VALUES (1, 1, 'switch.kitchen', 'switch.turn_on', ?, ?, ?)`,
            [JSON.stringify(payload), status, expiresAt]
        );
        return r.lastID;
    }

    it('returns pending commands and atomically flips them to dispatched', async () => {
        const id = await enqueue({ payload: { entity_id: 'switch.kitchen' } });
        const res = await fetch(`${base}/api/internal/devices/alexa/commands/poll`, { headers: AUTH_HEADERS });
        const body = await res.json();
        assert.equal(body.pending.length, 1);
        assert.equal(body.pending[0].id, id);
        assert.equal(body.pending[0].action, 'switch.turn_on');
        assert.deepEqual(body.pending[0].payload, { entity_id: 'switch.kitchen' });

        const row = await helpers.dbGet(`SELECT status FROM alexa_command_queue WHERE id = ?`, [id]);
        assert.equal(row.status, 'dispatched');

        // A second poll must NOT return the same row.
        const res2 = await fetch(`${base}/api/internal/devices/alexa/commands/poll`, { headers: AUTH_HEADERS });
        const body2 = await res2.json();
        assert.equal(body2.pending.length, 0);
    });

    it('expires commands past their TTL before dispatching', async () => {
        const id = await enqueue({ expiresAt: new Date(Date.now() - 1000).toISOString() });
        const res = await fetch(`${base}/api/internal/devices/alexa/commands/poll`, { headers: AUTH_HEADERS });
        const body = await res.json();
        assert.equal(body.pending.length, 0);
        const row = await helpers.dbGet(`SELECT status FROM alexa_command_queue WHERE id = ?`, [id]);
        assert.equal(row.status, 'expired');
    });

    it('respects the limit query parameter (clamped 1..50)', async () => {
        for (let i = 0; i < 5; i++) await enqueue();
        const res = await fetch(`${base}/api/internal/devices/alexa/commands/poll?limit=2`, { headers: AUTH_HEADERS });
        const body = await res.json();
        assert.equal(body.pending.length, 2);
    });

    it('does not surface commands for other devices', async () => {
        // Insert a row scoped to a different device_id
        await helpers.dbRun(
            `INSERT INTO alexa_command_queue (user_id, device_id, entity_id, action, payload_json, status, expires_at)
             VALUES (1, 2, 'switch.other', 'switch.turn_on', '{}', 'pending', ?)`,
            [new Date(Date.now() + 60_000).toISOString()]
        );
        const res = await fetch(`${base}/api/internal/devices/alexa/commands/poll`, { headers: AUTH_HEADERS });
        const body = await res.json();
        assert.equal(body.pending.length, 0);
    });
});

// ─── Result ack ───────────────────────────────────────────────────────────

describe('POST /commands/:id/result', () => {
    let server, base, db, helpers;
    beforeEach(async () => {
        const ctx = await makeApp();
        ({ db, helpers } = ctx);
        ({ server, base } = await listen(ctx.app));
    });
    afterEach(() => {
        server.close();
        db.close();
    });

    async function enqueue(status = 'dispatched') {
        const r = await helpers.dbRun(
            `INSERT INTO alexa_command_queue (user_id, device_id, entity_id, action, payload_json, status, expires_at)
             VALUES (1, 1, 'switch.x', 'switch.turn_on', '{}', ?, ?)`,
            [status, new Date(Date.now() + 60_000).toISOString()]
        );
        return r.lastID;
    }

    async function postResult(id, body) {
        return await fetch(`${base}/api/internal/devices/alexa/commands/${id}/result`, {
            method: 'POST',
            headers: AUTH_HEADERS,
            body: JSON.stringify(body)
        });
    }

    it('success flips dispatched → completed with result_json="ok"', async () => {
        const id = await enqueue();
        const res = await postResult(id, { success: true });
        assert.equal(res.status, 200);
        const row = await helpers.dbGet(`SELECT status, result_json FROM alexa_command_queue WHERE id = ?`, [id]);
        assert.equal(row.status, 'completed');
        assert.equal(row.result_json, 'ok');
    });

    it('failure flips dispatched → failed with the error message', async () => {
        const id = await enqueue();
        const res = await postResult(id, { success: false, error: 'service unavailable' });
        assert.equal(res.status, 200);
        const row = await helpers.dbGet(`SELECT status, result_json FROM alexa_command_queue WHERE id = ?`, [id]);
        assert.equal(row.status, 'failed');
        assert.equal(row.result_json, 'service unavailable');
    });

    it('quietly no-ops late acks for already-expired commands', async () => {
        const id = await enqueue('expired');
        const res = await postResult(id, { success: true });
        assert.equal(res.status, 200);
        const body = await res.json();
        assert.equal(body.no_op, true);
        assert.equal(body.prior_status, 'expired');
        // Status MUST NOT be silently overwritten — that would unblock a
        // smart-home loop that already returned ENDPOINT_UNREACHABLE.
        const row = await helpers.dbGet(`SELECT status FROM alexa_command_queue WHERE id = ?`, [id]);
        assert.equal(row.status, 'expired');
    });

    it('404 for unknown command id', async () => {
        const res = await postResult(99999, { success: true });
        assert.equal(res.status, 404);
    });

    it('404 for a command belonging to a different device (cross-device tenancy guard)', async () => {
        const r = await helpers.dbRun(
            `INSERT INTO alexa_command_queue (user_id, device_id, entity_id, action, payload_json, status, expires_at)
             VALUES (1, 2, 'switch.x', 'switch.turn_on', '{}', 'dispatched', ?)`,
            [new Date(Date.now() + 60_000).toISOString()]
        );
        const res = await postResult(r.lastID, { success: true });
        assert.equal(res.status, 404);
    });

    it('400 for malformed command id in the URL', async () => {
        const res = await fetch(`${base}/api/internal/devices/alexa/commands/abc/result`, {
            method: 'POST',
            headers: AUTH_HEADERS,
            body: '{"success":true}'
        });
        assert.equal(res.status, 400);
    });
});
