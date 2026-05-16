/**
 * routes/alexa-portal.js — portal-facing Alexa endpoints.
 *
 * Auth is stubbed: the portal session middleware is replaced with a fake
 * that just attaches `req.portalUser` from a fixed lookup. lib/auth has its
 * own tests for the real session machinery.
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const sqlite3 = require('sqlite3').verbose();

const createDbHelpers = require('../../lib/db-helpers');
const utils = require('../../lib/utils');
const portalFactory = require('../../routes/alexa-portal');

const SCHEMA = `
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'active',
        alexa_enabled INTEGER NOT NULL DEFAULT 0,
        alexa_linked  INTEGER NOT NULL DEFAULT 0,
        alexa_security_pin TEXT
    );
    CREATE TABLE alexa_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE,
        access_token_hash TEXT,
        refresh_token_hash TEXT,
        expires_at DATETIME,
        lwa_access_token_encrypted TEXT,
        lwa_refresh_token_encrypted TEXT,
        lwa_expires_at DATETIME,
        lwa_scopes TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE alexa_entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        device_id INTEGER NOT NULL,
        entity_id TEXT NOT NULL,
        display_name TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        exposed INTEGER NOT NULL DEFAULT 1,
        online INTEGER NOT NULL DEFAULT 1,
        state_json TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, entity_id)
    );
`;

function fakeAuth(getUser) {
    return {
        requirePortalUser(req, _res, next) {
            req.portalUser = getUser();
            next();
        },
        createPortalSessionToken(_email) {
            return 'fake-token';
        },
        setPortalSessionCookie(_res, _token) {
            /* noop in tests */
        },
        serializeUserWithPortalSession(user, token) {
            return {
                id: user.id,
                email: user.email,
                portal_session_token: token,
                alexa_enabled: Boolean(user.alexa_enabled),
                alexa_linked: Boolean(user.alexa_linked)
            };
        }
    };
}

function fakeAlexaCore(helpers) {
    return {
        async unlinkAlexaForUser(userId) {
            await helpers.dbRun(`DELETE FROM alexa_tokens WHERE user_id = ?`, [userId]);
            await helpers.dbRun(`UPDATE users SET alexa_linked = 0 WHERE id = ?`, [userId]);
        }
    };
}

async function makeApp() {
    const db = new sqlite3.Database(':memory:');
    const helpers = createDbHelpers(db);
    await new Promise((res, rej) => {
        db.exec(SCHEMA, (e) => (e ? rej(e) : res()));
    });
    await helpers.dbRun(
        `INSERT INTO users (id, email, alexa_enabled, alexa_linked) VALUES (1, 'a@b.c', 1, 1)`
    );

    let currentUser = null;
    async function refreshUser() {
        currentUser = await helpers.dbGet(`SELECT * FROM users WHERE id = 1`);
        return currentUser;
    }
    await refreshUser();

    const router = portalFactory({
        dbGet: helpers.dbGet,
        dbRun: helpers.dbRun,
        utils,
        auth: fakeAuth(() => currentUser),
        alexaCore: fakeAlexaCore(helpers)
    });
    const app = express();
    app.use(express.json());
    app.use(router);
    return { app, db, helpers, refreshUser };
}

function listen(app) {
    return new Promise((resolve) => {
        const server = app.listen(0, '127.0.0.1', () =>
            resolve({ server, base: `http://127.0.0.1:${server.address().port}` })
        );
    });
}

const JSON_HEADERS = { 'Content-Type': 'application/json' };

// ── /enable ───────────────────────────────────────────────────────────────

describe('POST /api/account/alexa/enable', () => {
    let server, base, db, helpers, refreshUser;
    beforeEach(async () => {
        const ctx = await makeApp();
        ({ db, helpers, refreshUser } = ctx);
        ({ server, base } = await listen(ctx.app));
    });
    afterEach(() => {
        server.close();
        db.close();
    });

    it('disabling unlinks tokens — leaving them around would silently re-arm on re-enable', async () => {
        await helpers.dbRun(
            `INSERT INTO alexa_tokens (user_id, lwa_refresh_token_encrypted, lwa_expires_at)
             VALUES (1, 'enc', '2030-01-01')`
        );
        const res = await fetch(`${base}/api/account/alexa/enable`, {
            method: 'POST',
            headers: JSON_HEADERS,
            body: JSON.stringify({ enabled: false })
        });
        assert.equal(res.status, 200);
        const tokenRow = await helpers.dbGet(`SELECT * FROM alexa_tokens WHERE user_id = 1`);
        assert.equal(tokenRow, undefined);
        const u = await refreshUser();
        assert.equal(u.alexa_enabled, 0);
        assert.equal(u.alexa_linked, 0);
    });

    it('enabling sets alexa_enabled=1 without touching tokens', async () => {
        await helpers.dbRun(`UPDATE users SET alexa_enabled = 0 WHERE id = 1`);
        await refreshUser();
        const res = await fetch(`${base}/api/account/alexa/enable`, {
            method: 'POST',
            headers: JSON_HEADERS,
            body: JSON.stringify({ enabled: true })
        });
        assert.equal(res.status, 200);
        const u = await refreshUser();
        assert.equal(u.alexa_enabled, 1);
    });
});

// ── /status ───────────────────────────────────────────────────────────────

describe('GET /api/account/alexa/status', () => {
    let server, base, db, helpers, refreshUser;
    beforeEach(async () => {
        const ctx = await makeApp();
        ({ db, helpers, refreshUser } = ctx);
        ({ server, base } = await listen(ctx.app));
    });
    afterEach(() => {
        server.close();
        db.close();
    });

    it('summarises link state, PIN, entity counts, and last sync', async () => {
        await helpers.dbRun(`UPDATE users SET alexa_security_pin = '1234' WHERE id = 1`);
        await helpers.dbRun(
            `INSERT INTO alexa_entities (user_id, device_id, entity_id, display_name, entity_type, exposed, updated_at)
             VALUES (1, 1, 'switch.kitchen', 'Kitchen', 'switch', 1, '2026-05-01T10:00:00Z'),
                    (1, 1, 'switch.bedroom', 'Bedroom', 'switch', 0, '2026-05-02T10:00:00Z')`
        );
        await refreshUser();
        const res = await fetch(`${base}/api/account/alexa/status`);
        const body = await res.json();
        assert.equal(body.enabled, true);
        assert.equal(body.linked, true);
        assert.equal(body.security_pin_set, true);
        assert.equal(body.total_entity_count, 2);
        assert.equal(body.exposed_entity_count, 1);
        assert.equal(body.last_synced_at, '2026-05-02T10:00:00Z');
    });

    it('returns zero counts and null last_synced_at for never-synced user', async () => {
        const res = await fetch(`${base}/api/account/alexa/status`);
        const body = await res.json();
        assert.equal(body.total_entity_count, 0);
        assert.equal(body.exposed_entity_count, 0);
        assert.equal(body.last_synced_at, null);
        assert.equal(body.security_pin_set, false);
    });
});

// ── /unlink ───────────────────────────────────────────────────────────────

describe('POST /api/account/alexa/unlink', () => {
    let server, base, db, helpers, refreshUser;
    beforeEach(async () => {
        const ctx = await makeApp();
        ({ db, helpers, refreshUser } = ctx);
        ({ server, base } = await listen(ctx.app));
    });
    afterEach(() => {
        server.close();
        db.close();
    });

    it('clears alexa_tokens row and flips alexa_linked → 0 but leaves alexa_enabled alone', async () => {
        await helpers.dbRun(
            `INSERT INTO alexa_tokens (user_id, lwa_refresh_token_encrypted, lwa_expires_at)
             VALUES (1, 'enc', '2030-01-01')`
        );
        const res = await fetch(`${base}/api/account/alexa/unlink`, { method: 'POST' });
        assert.equal(res.status, 200);
        const tokenRow = await helpers.dbGet(`SELECT * FROM alexa_tokens WHERE user_id = 1`);
        assert.equal(tokenRow, undefined);
        const u = await refreshUser();
        assert.equal(u.alexa_linked, 0);
        // The user's PREFERENCE to use Alexa is preserved — they probably
        // want to re-link, not turn off the integration entirely.
        assert.equal(u.alexa_enabled, 1);
    });

    it('idempotent — second unlink call still 200s', async () => {
        await fetch(`${base}/api/account/alexa/unlink`, { method: 'POST' });
        const res = await fetch(`${base}/api/account/alexa/unlink`, { method: 'POST' });
        assert.equal(res.status, 200);
    });
});

// ── /security-pin ─────────────────────────────────────────────────────────

describe('PIN endpoints', () => {
    let server, base, db, helpers, refreshUser;
    beforeEach(async () => {
        const ctx = await makeApp();
        ({ db, helpers, refreshUser } = ctx);
        ({ server, base } = await listen(ctx.app));
    });
    afterEach(() => {
        server.close();
        db.close();
    });

    it('GET reflects DB state', async () => {
        let res = await fetch(`${base}/api/account/alexa/security-pin`);
        assert.deepEqual(await res.json(), { has_pin: false });
        await helpers.dbRun(`UPDATE users SET alexa_security_pin = '4321' WHERE id = 1`);
        await refreshUser();
        res = await fetch(`${base}/api/account/alexa/security-pin`);
        assert.deepEqual(await res.json(), { has_pin: true });
    });

    it('POST with empty pin clears it', async () => {
        await helpers.dbRun(`UPDATE users SET alexa_security_pin = '4321' WHERE id = 1`);
        const res = await fetch(`${base}/api/account/alexa/security-pin`, {
            method: 'POST',
            headers: JSON_HEADERS,
            body: JSON.stringify({ pin: '' })
        });
        const body = await res.json();
        assert.equal(body.has_pin, false);
        const u = await refreshUser();
        assert.equal(u.alexa_security_pin, null);
    });

    it('POST rejects non-digit / wrong-length pins', async () => {
        for (const pin of ['abcd', '12', '123456789']) {
            const res = await fetch(`${base}/api/account/alexa/security-pin`, {
                method: 'POST',
                headers: JSON_HEADERS,
                body: JSON.stringify({ pin })
            });
            assert.equal(res.status, 400, `pin "${pin}" should be rejected`);
        }
    });

    it('POST stores valid pin', async () => {
        const res = await fetch(`${base}/api/account/alexa/security-pin`, {
            method: 'POST',
            headers: JSON_HEADERS,
            body: JSON.stringify({ pin: '4567' })
        });
        const body = await res.json();
        assert.equal(body.has_pin, true);
        const u = await refreshUser();
        assert.equal(u.alexa_security_pin, '4567');
    });
});
