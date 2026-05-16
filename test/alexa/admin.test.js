/**
 * routes/alexa-admin.js — admin-facing Alexa endpoints.
 *
 * Auth is stubbed: requireAdmin just attaches `req.admin = { email }`.
 * lib/auth has its own tests for the real bcrypt + HMAC machinery.
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const sqlite3 = require('sqlite3').verbose();

const createDbHelpers = require('../../lib/db-helpers');
const utils = require('../../lib/utils');
const adminFactory = require('../../routes/alexa-admin');

const SCHEMA = `
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        subdomain TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        alexa_enabled INTEGER NOT NULL DEFAULT 0,
        alexa_linked  INTEGER NOT NULL DEFAULT 0,
        alexa_security_pin TEXT
    );
    CREATE TABLE alexa_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE,
        lwa_refresh_token_encrypted TEXT,
        lwa_expires_at DATETIME
    );
    CREATE TABLE alexa_entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        device_id INTEGER NOT NULL,
        entity_id TEXT NOT NULL,
        display_name TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        exposed INTEGER NOT NULL DEFAULT 1,
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
`;

function fakeAuth() {
    return {
        requireAdmin(req, res, next) {
            const tok = req.get('x-admin') || '';
            if (tok !== 'ok') return res.status(401).json({ error: 'unauth' });
            req.admin = { email: 'ops@example.com' };
            return next();
        }
    };
}

function fakeAlexaCore(helpers) {
    return {
        async unlinkAlexaForUser(userId) {
            await helpers.dbRun(`DELETE FROM alexa_tokens WHERE user_id = ?`, [userId]);
            await helpers.dbRun(`UPDATE users SET alexa_linked = 0 WHERE id = ?`, [userId]);
        },
        // Used by the replay endpoint to compute fresh expires_at.
        getAlexaCommandTtlSeconds: () => 45
    };
}

async function makeApp({ eventGateway = null } = {}) {
    const db = new sqlite3.Database(':memory:');
    const helpers = createDbHelpers(db);
    await new Promise((res, rej) => {
        db.exec(SCHEMA, (e) => (e ? rej(e) : res()));
    });
    const router = adminFactory({
        dbGet: helpers.dbGet,
        dbRun: helpers.dbRun,
        dbAll: helpers.dbAll,
        utils,
        auth: fakeAuth(),
        alexaCore: fakeAlexaCore(helpers),
        eventGateway
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

const ADMIN_HEADERS = { 'x-admin': 'ok', 'Content-Type': 'application/json' };

// ── /admin/alexa/users ────────────────────────────────────────────────────

describe('GET /api/admin/alexa/users', () => {
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

    it('401 without admin header', async () => {
        const res = await fetch(`${base}/api/admin/alexa/users`);
        assert.equal(res.status, 401);
    });

    it('lists only users with alexa_enabled OR alexa_linked', async () => {
        await helpers.dbRun(`INSERT INTO users (email, alexa_enabled, alexa_linked) VALUES
            ('linked@x', 1, 1),
            ('enabled-only@x', 1, 0),
            ('linked-only@x', 0, 1),
            ('off@x', 0, 0)`);
        const res = await fetch(`${base}/api/admin/alexa/users`, { headers: ADMIN_HEADERS });
        const body = await res.json();
        const emails = body.users.map((u) => u.email).sort();
        assert.deepEqual(emails, ['enabled-only@x', 'linked-only@x', 'linked@x']);
    });

    it('aggregates entity counts and last_synced_at per user', async () => {
        await helpers.dbRun(`INSERT INTO users (id, email, alexa_enabled, alexa_linked) VALUES (1, 'a@x', 1, 1)`);
        await helpers.dbRun(`INSERT INTO alexa_tokens (user_id, lwa_expires_at) VALUES (1, '2099-01-01')`);
        await helpers.dbRun(
            `INSERT INTO alexa_entities (user_id, device_id, entity_id, display_name, entity_type, exposed, updated_at)
             VALUES (1, 1, 'switch.a', 'A', 'switch', 1, '2026-04-01T00:00:00Z'),
                    (1, 1, 'switch.b', 'B', 'switch', 0, '2026-04-02T00:00:00Z')`
        );
        const res = await fetch(`${base}/api/admin/alexa/users`, { headers: ADMIN_HEADERS });
        const [u] = (await res.json()).users;
        assert.equal(u.total_entities, 2);
        assert.equal(u.exposed_entities, 1);
        assert.equal(u.last_synced_at, '2026-04-02T00:00:00Z');
        assert.equal(u.lwa_expires_at, '2099-01-01');
    });

    it('reports security_pin_set as a boolean', async () => {
        await helpers.dbRun(
            `INSERT INTO users (email, alexa_enabled, alexa_linked, alexa_security_pin) VALUES
             ('pin@x', 1, 1, '1234'), ('nopin@x', 1, 1, NULL)`
        );
        const res = await fetch(`${base}/api/admin/alexa/users`, { headers: ADMIN_HEADERS });
        const map = Object.fromEntries((await res.json()).users.map((u) => [u.email, u.alexa_security_pin_set]));
        assert.equal(map['pin@x'], true);
        assert.equal(map['nopin@x'], false);
    });
});

// ── /admin/alexa/users/:id/force-unlink ───────────────────────────────────

describe('POST /api/admin/alexa/users/:id/force-unlink', () => {
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

    it('401 without admin header', async () => {
        const res = await fetch(`${base}/api/admin/alexa/users/1/force-unlink`, { method: 'POST' });
        assert.equal(res.status, 401);
    });

    it('400 for non-numeric id', async () => {
        const res = await fetch(`${base}/api/admin/alexa/users/abc/force-unlink`, {
            method: 'POST',
            headers: ADMIN_HEADERS
        });
        assert.equal(res.status, 400);
    });

    it('404 for unknown user', async () => {
        const res = await fetch(`${base}/api/admin/alexa/users/99999/force-unlink`, {
            method: 'POST',
            headers: ADMIN_HEADERS
        });
        assert.equal(res.status, 404);
    });

    it('unlinks: drops tokens row, alexa_linked→0, leaves alexa_enabled', async () => {
        await helpers.dbRun(
            `INSERT INTO users (id, email, alexa_enabled, alexa_linked) VALUES (1, 'x@x', 1, 1)`
        );
        await helpers.dbRun(`INSERT INTO alexa_tokens (user_id, lwa_expires_at) VALUES (1, '2099-01-01')`);
        const res = await fetch(`${base}/api/admin/alexa/users/1/force-unlink`, {
            method: 'POST',
            headers: ADMIN_HEADERS
        });
        assert.equal(res.status, 200);
        const u = await helpers.dbGet(`SELECT * FROM users WHERE id = 1`);
        assert.equal(u.alexa_linked, 0);
        assert.equal(u.alexa_enabled, 1);
        const tok = await helpers.dbGet(`SELECT * FROM alexa_tokens WHERE user_id = 1`);
        assert.equal(tok, undefined);
    });

    it('idempotent — second call still 200', async () => {
        await helpers.dbRun(`INSERT INTO users (id, email) VALUES (1, 'x@x')`);
        await fetch(`${base}/api/admin/alexa/users/1/force-unlink`, {
            method: 'POST',
            headers: ADMIN_HEADERS
        });
        const res = await fetch(`${base}/api/admin/alexa/users/1/force-unlink`, {
            method: 'POST',
            headers: ADMIN_HEADERS
        });
        assert.equal(res.status, 200);
    });
});

// ── /admin/alexa/health ───────────────────────────────────────────────────

describe('GET /api/admin/alexa/health', () => {
    let server, base, db;

    afterEach(() => {
        server.close();
        db.close();
    });

    it('401 without admin header', async () => {
        const ctx = await makeApp({ eventGateway: { getHealthSnapshot: () => ({}) } });
        ({ db } = ctx);
        ({ server, base } = await listen(ctx.app));
        const res = await fetch(`${base}/api/admin/alexa/health`);
        assert.equal(res.status, 401);
    });

    it('returns available=false when eventGateway is not wired', async () => {
        const ctx = await makeApp({ eventGateway: null });
        ({ db } = ctx);
        ({ server, base } = await listen(ctx.app));
        const res = await fetch(`${base}/api/admin/alexa/health`, { headers: ADMIN_HEADERS });
        assert.equal(res.status, 200);
        const body = await res.json();
        assert.equal(body.available, false);
        assert.equal(body.reason, 'event_gateway_not_wired');
    });

    it('returns the snapshot with counters, queue depth, startedAt', async () => {
        const fakeGw = {
            getHealthSnapshot: () => ({
                startedAt: '2026-05-10T00:00:00.000Z',
                queueDepth: 3,
                counters: {
                    ok: { count: 42, firstAt: '2026-05-10T00:00:01.000Z', lastAt: '2026-05-10T00:01:00.000Z' },
                    gateway_error: { count: 1, firstAt: '2026-05-10T00:00:30.000Z', lastAt: '2026-05-10T00:00:30.000Z' }
                }
            })
        };
        const ctx = await makeApp({ eventGateway: fakeGw });
        ({ db } = ctx);
        ({ server, base } = await listen(ctx.app));
        const res = await fetch(`${base}/api/admin/alexa/health`, { headers: ADMIN_HEADERS });
        const body = await res.json();
        assert.equal(body.available, true);
        assert.equal(body.queueDepth, 3);
        assert.equal(body.counters.ok.count, 42);
        assert.equal(body.counters.gateway_error.count, 1);
        assert.equal(body.startedAt, '2026-05-10T00:00:00.000Z');
    });
});

// ── /admin/alexa/users/:id/preview-change-report ──────────────────────────

describe('GET /api/admin/alexa/users/:id/preview-change-report', () => {
    let server, base, db, helpers;

    afterEach(() => {
        server.close();
        db.close();
    });

    function fakePreviewGateway(overrides = {}) {
        return {
            async previewChangeReportForUserEntity(userId, entityId) {
                if (overrides.reason) return { ok: false, reason: overrides.reason };
                return {
                    ok: true,
                    event: {
                        header: { namespace: 'Alexa', name: 'ChangeReport', payloadVersion: '3' },
                        endpoint: {
                            scope: { type: 'BearerToken', token: '<dry-run-placeholder>' },
                            endpointId: entityId.replace('.', '__'),
                            cookie: { ha_entity_id: entityId }
                        },
                        payload: { change: { cause: { type: 'PHYSICAL_INTERACTION' }, properties: [] } }
                    },
                    context: { properties: [] }
                };
            }
        };
    }

    it('401 without admin header', async () => {
        const ctx = await makeApp({ eventGateway: fakePreviewGateway() });
        ({ db } = ctx);
        ({ server, base } = await listen(ctx.app));
        const res = await fetch(
            `${base}/api/admin/alexa/users/1/preview-change-report?entity_id=light.kitchen`
        );
        assert.equal(res.status, 401);
    });

    it('503 when eventGateway is not wired', async () => {
        const ctx = await makeApp({ eventGateway: null });
        ({ db } = ctx);
        ({ server, base } = await listen(ctx.app));
        const res = await fetch(
            `${base}/api/admin/alexa/users/1/preview-change-report?entity_id=light.kitchen`,
            { headers: ADMIN_HEADERS }
        );
        assert.equal(res.status, 503);
    });

    it('400 when entity_id query param is missing', async () => {
        const ctx = await makeApp({ eventGateway: fakePreviewGateway() });
        ({ db, helpers } = ctx);
        await helpers.dbRun(`INSERT INTO users (id, email) VALUES (1, 'x@x')`);
        ({ server, base } = await listen(ctx.app));
        const res = await fetch(`${base}/api/admin/alexa/users/1/preview-change-report`, {
            headers: ADMIN_HEADERS
        });
        assert.equal(res.status, 400);
        const body = await res.json();
        assert.equal(body.error, 'missing_entity_id');
    });

    it('404 when user_id does not resolve', async () => {
        const ctx = await makeApp({ eventGateway: fakePreviewGateway() });
        ({ db } = ctx);
        ({ server, base } = await listen(ctx.app));
        const res = await fetch(
            `${base}/api/admin/alexa/users/9999/preview-change-report?entity_id=light.kitchen`,
            { headers: ADMIN_HEADERS }
        );
        assert.equal(res.status, 404);
        const body = await res.json();
        assert.equal(body.error, 'user_not_found');
    });

    it('404 entity_not_found when gateway reports no entity row', async () => {
        const ctx = await makeApp({ eventGateway: fakePreviewGateway({ reason: 'entity_not_found' }) });
        ({ db, helpers } = ctx);
        await helpers.dbRun(`INSERT INTO users (id, email) VALUES (1, 'x@x')`);
        ({ server, base } = await listen(ctx.app));
        const res = await fetch(
            `${base}/api/admin/alexa/users/1/preview-change-report?entity_id=light.unknown`,
            { headers: ADMIN_HEADERS }
        );
        assert.equal(res.status, 404);
    });

    it('422 no_reportable_properties for out-of-scope domain', async () => {
        const ctx = await makeApp({ eventGateway: fakePreviewGateway({ reason: 'no_properties' }) });
        ({ db, helpers } = ctx);
        await helpers.dbRun(`INSERT INTO users (id, email) VALUES (1, 'x@x')`);
        ({ server, base } = await listen(ctx.app));
        const res = await fetch(
            `${base}/api/admin/alexa/users/1/preview-change-report?entity_id=fan.bedroom`,
            { headers: ADMIN_HEADERS }
        );
        assert.equal(res.status, 422);
    });

    it('200 returns the rendered envelope with placeholder bearer (no leak)', async () => {
        const ctx = await makeApp({ eventGateway: fakePreviewGateway() });
        ({ db, helpers } = ctx);
        await helpers.dbRun(`INSERT INTO users (id, email) VALUES (1, 'x@x')`);
        ({ server, base } = await listen(ctx.app));
        const res = await fetch(
            `${base}/api/admin/alexa/users/1/preview-change-report?entity_id=light.kitchen`,
            { headers: ADMIN_HEADERS }
        );
        assert.equal(res.status, 200);
        const body = await res.json();
        assert.equal(body.user_id, 1);
        assert.equal(body.entity_id, 'light.kitchen');
        assert.equal(body.event.header.name, 'ChangeReport');
        assert.equal(body.event.endpoint.scope.token, '<dry-run-placeholder>');
        assert.equal(body.event.endpoint.endpointId, 'light__kitchen');
    });
});

// ── /admin/alexa/users/:id/commands/:cmd_id/replay ────────────────────────

describe('POST /api/admin/alexa/users/:id/commands/:cmd_id/replay', () => {
    let server, base, db, helpers;

    beforeEach(async () => {
        const ctx = await makeApp();
        ({ db, helpers } = ctx);
        ({ server, base } = await listen(ctx.app));
        await helpers.dbRun(`INSERT INTO users (id, email) VALUES (1, 'a@x'), (2, 'b@x')`);
    });
    afterEach(() => {
        server.close();
        db.close();
    });

    async function insertCommand(overrides = {}) {
        const row = {
            user_id: 1,
            device_id: 1,
            entity_id: 'switch.kitchen',
            action: 'switch.turn_on',
            payload_json: JSON.stringify({ entity_id: 'switch.kitchen' }),
            status: 'failed',
            result_json: 'service_call_failed: timeout',
            expires_at: '2020-01-01T00:00:00Z',
            ...overrides
        };
        const ins = await helpers.dbRun(
            `INSERT INTO alexa_command_queue
                (user_id, device_id, entity_id, action, payload_json, status, result_json, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                row.user_id,
                row.device_id,
                row.entity_id,
                row.action,
                row.payload_json,
                row.status,
                row.result_json,
                row.expires_at
            ]
        );
        return ins.lastID;
    }

    it('401 without admin header', async () => {
        const cmdId = await insertCommand();
        const res = await fetch(`${base}/api/admin/alexa/users/1/commands/${cmdId}/replay`, {
            method: 'POST'
        });
        assert.equal(res.status, 401);
    });

    it('400 invalid_user_id for non-numeric :id', async () => {
        const res = await fetch(`${base}/api/admin/alexa/users/abc/commands/1/replay`, {
            method: 'POST',
            headers: ADMIN_HEADERS
        });
        assert.equal(res.status, 400);
        assert.equal((await res.json()).error, 'invalid_user_id');
    });

    it('400 invalid_command_id for non-numeric :cmd_id', async () => {
        const res = await fetch(`${base}/api/admin/alexa/users/1/commands/abc/replay`, {
            method: 'POST',
            headers: ADMIN_HEADERS
        });
        assert.equal(res.status, 400);
        assert.equal((await res.json()).error, 'invalid_command_id');
    });

    it('404 user_not_found', async () => {
        const res = await fetch(`${base}/api/admin/alexa/users/9999/commands/1/replay`, {
            method: 'POST',
            headers: ADMIN_HEADERS
        });
        assert.equal(res.status, 404);
        assert.equal((await res.json()).error, 'user_not_found');
    });

    it('404 command_not_found when ID does not exist', async () => {
        const res = await fetch(`${base}/api/admin/alexa/users/1/commands/9999/replay`, {
            method: 'POST',
            headers: ADMIN_HEADERS
        });
        assert.equal(res.status, 404);
        assert.equal((await res.json()).error, 'command_not_found');
    });

    it('404 command_not_found on cross-user replay (id mismatch is not a leak)', async () => {
        // Command belongs to user 1; replay attempt is against user 2.
        const cmdId = await insertCommand({ user_id: 1 });
        const res = await fetch(`${base}/api/admin/alexa/users/2/commands/${cmdId}/replay`, {
            method: 'POST',
            headers: ADMIN_HEADERS
        });
        // Same 404 as "doesn't exist" so an operator can't enumerate
        // queue rows by user via timing or response shape.
        assert.equal(res.status, 404);
        assert.equal((await res.json()).error, 'command_not_found');
    });

    for (const status of ['pending', 'dispatched']) {
        it(`409 command_in_flight when source status is ${status}`, async () => {
            const cmdId = await insertCommand({ status });
            const res = await fetch(`${base}/api/admin/alexa/users/1/commands/${cmdId}/replay`, {
                method: 'POST',
                headers: ADMIN_HEADERS
            });
            assert.equal(res.status, 409);
            const body = await res.json();
            assert.equal(body.error, 'command_in_flight');
            assert.equal(body.current_status, status);
        });
    }

    for (const status of ['failed', 'expired', 'completed']) {
        it(`200 inserts a new pending row from a ${status} source`, async () => {
            const cmdId = await insertCommand({ status });
            const beforeCount = (await helpers.dbAll(`SELECT id FROM alexa_command_queue`)).length;
            const res = await fetch(`${base}/api/admin/alexa/users/1/commands/${cmdId}/replay`, {
                method: 'POST',
                headers: ADMIN_HEADERS
            });
            assert.equal(res.status, 200);
            const body = await res.json();
            assert.equal(body.ok, true);
            assert.equal(body.source_command_id, cmdId);
            assert.equal(body.source_status, status);
            assert.equal(body.entity_id, 'switch.kitchen');
            assert.equal(body.action, 'switch.turn_on');
            assert.ok(body.new_command_id > cmdId);

            // Source row must be UNCHANGED.
            const source = await helpers.dbGet(
                `SELECT status, result_json FROM alexa_command_queue WHERE id = ?`,
                [cmdId]
            );
            assert.equal(source.status, status);

            // New row exists with status='pending' and a fresh future expires_at.
            const newRow = await helpers.dbGet(
                `SELECT user_id, device_id, entity_id, action, payload_json, status, expires_at
                 FROM alexa_command_queue WHERE id = ?`,
                [body.new_command_id]
            );
            assert.equal(newRow.status, 'pending');
            assert.equal(newRow.user_id, 1);
            assert.equal(newRow.entity_id, 'switch.kitchen');
            assert.equal(newRow.action, 'switch.turn_on');
            assert.equal(newRow.payload_json, JSON.stringify({ entity_id: 'switch.kitchen' }));
            assert.ok(new Date(newRow.expires_at).getTime() > Date.now());

            // Total count went up by exactly one (no double-insert).
            const afterCount = (await helpers.dbAll(`SELECT id FROM alexa_command_queue`)).length;
            assert.equal(afterCount, beforeCount + 1);
        });
    }

    it('replays use the alexaCore TTL setting', async () => {
        const cmdId = await insertCommand({ status: 'failed' });
        const t0 = Date.now();
        const res = await fetch(`${base}/api/admin/alexa/users/1/commands/${cmdId}/replay`, {
            method: 'POST',
            headers: ADMIN_HEADERS
        });
        const body = await res.json();
        const expiresMs = new Date(body.expires_at).getTime();
        // fakeAlexaCore returns 45s. Allow generous timing slack for CI.
        assert.ok(expiresMs - t0 >= 40_000 && expiresMs - t0 <= 50_000,
            `expected ~45s TTL, got ${expiresMs - t0}ms`);
    });

    it('two rapid replays of the same source row produce two new rows (operator double-click)', async () => {
        const cmdId = await insertCommand({ status: 'failed' });
        const [r1, r2] = await Promise.all([
            fetch(`${base}/api/admin/alexa/users/1/commands/${cmdId}/replay`, {
                method: 'POST',
                headers: ADMIN_HEADERS
            }),
            fetch(`${base}/api/admin/alexa/users/1/commands/${cmdId}/replay`, {
                method: 'POST',
                headers: ADMIN_HEADERS
            })
        ]);
        assert.equal(r1.status, 200);
        assert.equal(r2.status, 200);
        const b1 = await r1.json();
        const b2 = await r2.json();
        assert.notEqual(b1.new_command_id, b2.new_command_id);
        // Three rows total now: original + two replays.
        const all = await helpers.dbAll(`SELECT id, status FROM alexa_command_queue ORDER BY id`);
        assert.equal(all.length, 3);
        assert.equal(all[0].status, 'failed');
        assert.equal(all[1].status, 'pending');
        assert.equal(all[2].status, 'pending');
    });
});
