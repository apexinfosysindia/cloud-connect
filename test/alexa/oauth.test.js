const { describe, it, before, after, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const cookieParser = require('cookie-parser');
const sqlite3 = require('sqlite3').verbose();

const createDbHelpers = require('../../lib/db-helpers');
const createAlexaCore = require('../../lib/alexa/core');
const alexaOauthFactory = require('../../routes/alexa-oauth');

// ─── Test scaffolding ──────────────────────────────────────────────────────

const SCHEMA = `
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'active',
        alexa_enabled INTEGER NOT NULL DEFAULT 0,
        alexa_linked  INTEGER NOT NULL DEFAULT 0,
        alexa_security_pin TEXT
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
`;

const FAKE_CLIENT_ID = 'amzn-test-client';
const FAKE_CLIENT_SECRET = 'amzn-test-secret';

// Minimal `auth` stub — we don't want this test depending on lib/auth's
// real session-signing (that has its own tests). The OAuth route uses
// only three auth helpers, all mocked here.
function makeFakeAuth(validSessions = new Map()) {
    return {
        verifyPortalSessionToken(token) {
            return validSessions.get(token) || null;
        },
        portalTokenEpochMatches(_session, _user) {
            // Real auth checks user.session_epoch — we'll always say yes
            // unless a specific test wants to simulate the rotated case.
            return true;
        },
        setPortalSessionCookie(_res, _token) {
            /* not exercised by these routes */
        }
    };
}

// Real factories from the codebase, wired against in-memory state.
function makeApp({ validSessions = new Map(), epochMismatch = false } = {}) {
    const db = new sqlite3.Database(':memory:');
    const helpers = createDbHelpers(db);
    const fakeAuth = makeFakeAuth(validSessions);
    if (epochMismatch) {
        fakeAuth.portalTokenEpochMatches = () => false;
    }

    const utils = require('../../lib/utils');
    const config = require('../../lib/config');

    const alexaCore = createAlexaCore({
        dbGet: helpers.dbGet,
        dbRun: helpers.dbRun,
        dbAll: helpers.dbAll,
        // Tests don't exercise LWA encryption — pass a noop.
        lwaCrypto: { encryptLwaToken: (x) => x, decryptLwaToken: (x) => x, hasEncryptionKey: () => true }
    });

    const router = alexaOauthFactory({
        dbGet: helpers.dbGet,
        dbRun: helpers.dbRun,
        config,
        utils,
        auth: fakeAuth,
        alexaCore
    });

    const app = express();
    app.use(cookieParser());
    app.use(express.urlencoded({ extended: false }));
    app.use(express.json());
    app.use(router);

    return { app, db, helpers, alexaCore };
}

// Boot a real http server on an ephemeral port for one test.
function listen(app) {
    return new Promise((resolve) => {
        const server = app.listen(0, '127.0.0.1', () =>
            resolve({ server, base: `http://127.0.0.1:${server.address().port}` })
        );
    });
}

async function execSchema(db) {
    await new Promise((res, rej) => {
        db.exec(SCHEMA, (e) => (e ? rej(e) : res()));
    });
}

// Manual redirect handling so tests can assert on Location headers.
const NO_REDIRECT = { redirect: 'manual' };

// ─── Setup the env for the entire test file ───────────────────────────────

const ENV_BACKUP = {};
before(() => {
    for (const k of ['ALEXA_OAUTH_CLIENT_ID', 'ALEXA_OAUTH_CLIENT_SECRET']) {
        ENV_BACKUP[k] = process.env[k];
    }
    process.env.ALEXA_OAUTH_CLIENT_ID = FAKE_CLIENT_ID;
    process.env.ALEXA_OAUTH_CLIENT_SECRET = FAKE_CLIENT_SECRET;
});
after(() => {
    for (const [k, v] of Object.entries(ENV_BACKUP)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
    }
});

// ─── helpers/isTrustedAlexaRedirectUri unit tests ─────────────────────────

describe('isTrustedAlexaRedirectUri', () => {
    const { isTrustedAlexaRedirectUri } = alexaOauthFactory._test;
    const allowed = ['pitangui.amazon.com', 'layla.amazon.com', 'alexa.amazon.co.jp'];

    it('accepts the three Amazon regional hosts over https', () => {
        for (const h of allowed) {
            assert.equal(
                isTrustedAlexaRedirectUri(`https://${h}/api/skill/link/X`, allowed),
                true
            );
        }
    });

    it('rejects http (Amazon never uses plain http for skill linking)', () => {
        assert.equal(
            isTrustedAlexaRedirectUri('http://pitangui.amazon.com/api/skill/link/X', allowed),
            false
        );
    });

    it('rejects unknown hosts even if path looks legit', () => {
        assert.equal(
            isTrustedAlexaRedirectUri('https://evil.example/api/skill/link/X', allowed),
            false
        );
    });

    it('rejects malformed URLs without throwing', () => {
        assert.equal(isTrustedAlexaRedirectUri('not-a-url', allowed), false);
        assert.equal(isTrustedAlexaRedirectUri(null, allowed), false);
        assert.equal(isTrustedAlexaRedirectUri('', allowed), false);
    });
});

// ─── GET /api/alexa/oauth ──────────────────────────────────────────────────

describe('GET /api/alexa/oauth', () => {
    let server;
    let base;
    let db;
    let helpers;
    const sessionMap = new Map();

    beforeEach(async () => {
        const app = makeApp({ validSessions: sessionMap });
        await execSchema(app.db);
        ({ server, base } = await listen(app.app));
        db = app.db;
        helpers = app.helpers;
        sessionMap.clear();
    });

    afterEach(() => {
        server.close();
        db.close();
    });

    it('returns 503 when ALEXA_OAUTH_CLIENT_ID env is missing', async () => {
        const saved = process.env.ALEXA_OAUTH_CLIENT_ID;
        delete process.env.ALEXA_OAUTH_CLIENT_ID;
        try {
            const res = await fetch(
                `${base}/api/alexa/oauth?client_id=${FAKE_CLIENT_ID}` +
                    `&redirect_uri=${encodeURIComponent('https://pitangui.amazon.com/api/skill/link/X')}` +
                    `&state=abc`,
                NO_REDIRECT
            );
            assert.equal(res.status, 503);
        } finally {
            process.env.ALEXA_OAUTH_CLIENT_ID = saved;
        }
    });

    it('returns 400 when client_id is missing', async () => {
        const res = await fetch(`${base}/api/alexa/oauth`, NO_REDIRECT);
        assert.equal(res.status, 400);
    });

    it('returns 401 when client_id does not match the configured one', async () => {
        const res = await fetch(
            `${base}/api/alexa/oauth?client_id=wrong` +
                `&redirect_uri=${encodeURIComponent('https://pitangui.amazon.com/api/skill/link/X')}` +
                `&state=abc`,
            NO_REDIRECT
        );
        assert.equal(res.status, 401);
    });

    it('returns 400 when redirect_uri host is not in the allow-list', async () => {
        const res = await fetch(
            `${base}/api/alexa/oauth?client_id=${FAKE_CLIENT_ID}` +
                `&redirect_uri=${encodeURIComponent('https://evil.example/cb')}` +
                `&state=abc`,
            NO_REDIRECT
        );
        assert.equal(res.status, 400);
    });

    it('redirects to /login.html when no portal session is present', async () => {
        const res = await fetch(
            `${base}/api/alexa/oauth?client_id=${FAKE_CLIENT_ID}` +
                `&redirect_uri=${encodeURIComponent('https://pitangui.amazon.com/api/skill/link/X')}` +
                `&state=abc`,
            NO_REDIRECT
        );
        assert.equal(res.status, 302);
        const loc = res.headers.get('location');
        assert.match(loc, /^\/login\.html\?alexa_oauth=1/);
        assert.match(loc, /client_id=amzn-test-client/);
        assert.match(loc, /state=abc/);
    });

    it('redirects to /login.html when portal session cookie is invalid', async () => {
        const res = await fetch(
            `${base}/api/alexa/oauth?client_id=${FAKE_CLIENT_ID}` +
                `&redirect_uri=${encodeURIComponent('https://pitangui.amazon.com/api/skill/link/X')}` +
                `&state=abc`,
            { ...NO_REDIRECT, headers: { Cookie: 'apx_portal_session=garbage' } }
        );
        assert.equal(res.status, 302);
        assert.match(res.headers.get('location'), /^\/login\.html/);
    });

    it('happy path: valid session → 302 to redirect_uri WITH code param, NO consent screen', async () => {
        await helpers.dbRun(
            `INSERT INTO users (email, status) VALUES ('u@x', 'active')`
        );
        sessionMap.set('valid-tok', { email: 'u@x' });

        const res = await fetch(
            `${base}/api/alexa/oauth?client_id=${FAKE_CLIENT_ID}` +
                `&redirect_uri=${encodeURIComponent('https://pitangui.amazon.com/api/skill/link/X')}` +
                `&state=abc`,
            { ...NO_REDIRECT, headers: { Cookie: 'apx_portal_session=valid-tok' } }
        );

        assert.equal(res.status, 302);
        const loc = res.headers.get('location');
        const u = new URL(loc);
        // Must redirect back to Amazon, NOT to /login.html (no consent step).
        assert.equal(u.host, 'pitangui.amazon.com');
        assert.match(u.searchParams.get('code'), /^aac_[0-9a-f]{48}$/);
        assert.equal(u.searchParams.get('state'), 'abc');
        // CRITICAL: ensure we didn't accidentally add a consent param ourselves.
        assert.equal(u.searchParams.get('approved'), null);

        // alexa_enabled flipped on from 0
        const userRow = await helpers.dbGet(`SELECT alexa_enabled FROM users WHERE email = 'u@x'`);
        assert.equal(userRow.alexa_enabled, 1);
    });

    it('accepts portal session via query parameter (post-login bounce)', async () => {
        await helpers.dbRun(`INSERT INTO users (email, status) VALUES ('q@x', 'active')`);
        sessionMap.set('query-tok', { email: 'q@x' });

        const res = await fetch(
            `${base}/api/alexa/oauth?client_id=${FAKE_CLIENT_ID}` +
                `&redirect_uri=${encodeURIComponent('https://pitangui.amazon.com/api/skill/link/X')}` +
                `&state=abc&portal_session_token=query-tok`,
            NO_REDIRECT
        );
        assert.equal(res.status, 302);
        assert.match(res.headers.get('location'), /^https:\/\/pitangui\.amazon\.com.*code=aac_/);
    });

    it('subscription not active → redirects to Amazon with error=access_denied', async () => {
        await helpers.dbRun(
            `INSERT INTO users (email, status) VALUES ('p@x', 'payment_pending')`
        );
        sessionMap.set('pending-tok', { email: 'p@x' });

        const res = await fetch(
            `${base}/api/alexa/oauth?client_id=${FAKE_CLIENT_ID}` +
                `&redirect_uri=${encodeURIComponent('https://pitangui.amazon.com/api/skill/link/X')}` +
                `&state=abc`,
            { ...NO_REDIRECT, headers: { Cookie: 'apx_portal_session=pending-tok' } }
        );
        assert.equal(res.status, 302);
        const u = new URL(res.headers.get('location'));
        assert.equal(u.host, 'pitangui.amazon.com');
        assert.equal(u.searchParams.get('error'), 'access_denied');
    });

    it('explicit ?deny=1 → redirects to Amazon with error=access_denied', async () => {
        const res = await fetch(
            `${base}/api/alexa/oauth?client_id=${FAKE_CLIENT_ID}` +
                `&redirect_uri=${encodeURIComponent('https://pitangui.amazon.com/api/skill/link/X')}` +
                `&state=abc&deny=1`,
            NO_REDIRECT
        );
        assert.equal(res.status, 302);
        const u = new URL(res.headers.get('location'));
        assert.equal(u.searchParams.get('error'), 'access_denied');
    });
});

// ─── POST /api/alexa/token ─────────────────────────────────────────────────

describe('POST /api/alexa/token', () => {
    let server;
    let base;
    let db;
    let helpers;
    let alexaCore;
    const sessionMap = new Map();

    beforeEach(async () => {
        const app = makeApp({ validSessions: sessionMap });
        await execSchema(app.db);
        ({ server, base } = await listen(app.app));
        db = app.db;
        helpers = app.helpers;
        alexaCore = app.alexaCore;
        sessionMap.clear();
    });

    afterEach(() => {
        server.close();
        db.close();
    });

    async function makeUser(email = 't@x', status = 'active') {
        await helpers.dbRun(
            `INSERT INTO users (email, status, alexa_enabled) VALUES (?, ?, 1)`,
            [email, status]
        );
        return helpers.dbGet(`SELECT id FROM users WHERE email = ?`, [email]);
    }

    function form(obj) {
        return new URLSearchParams(obj).toString();
    }

    async function postForm(body) {
        return await fetch(`${base}/api/alexa/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: form(body)
        });
    }

    it('returns 401 invalid_client when client credentials are wrong', async () => {
        const res = await postForm({
            grant_type: 'authorization_code',
            client_id: 'wrong',
            client_secret: 'also-wrong',
            code: 'irrelevant',
            redirect_uri: 'https://pitangui.amazon.com/api/skill/link/X'
        });
        assert.equal(res.status, 401);
        const body = await res.json();
        assert.equal(body.error, 'invalid_client');
    });

    it('returns 400 unsupported_grant_type for unknown grants', async () => {
        const res = await postForm({
            grant_type: 'password', // RFC-defined but not allowed here
            client_id: FAKE_CLIENT_ID,
            client_secret: FAKE_CLIENT_SECRET
        });
        assert.equal(res.status, 400);
        assert.equal((await res.json()).error, 'unsupported_grant_type');
    });

    it('authorization_code grant: exchanges valid code for access+refresh', async () => {
        const u = await makeUser();
        const { code } = await alexaCore.issueAlexaAuthCode({
            userId: u.id,
            redirectUri: 'https://pitangui.amazon.com/api/skill/link/X'
        });

        const res = await postForm({
            grant_type: 'authorization_code',
            client_id: FAKE_CLIENT_ID,
            client_secret: FAKE_CLIENT_SECRET,
            code,
            redirect_uri: 'https://pitangui.amazon.com/api/skill/link/X'
        });

        assert.equal(res.status, 200);
        const body = await res.json();
        assert.match(body.access_token, /^aat_[0-9a-f]{48}$/);
        assert.match(body.refresh_token, /^art_[0-9a-f]{48}$/);
        assert.equal(body.token_type, 'bearer');
        assert.ok(Number.isInteger(body.expires_in) && body.expires_in > 0);
    });

    it('authorization_code grant: rejects when redirect_uri differs from authorize-time value', async () => {
        const u = await makeUser();
        const { code } = await alexaCore.issueAlexaAuthCode({
            userId: u.id,
            redirectUri: 'https://pitangui.amazon.com/api/skill/link/X'
        });

        const res = await postForm({
            grant_type: 'authorization_code',
            client_id: FAKE_CLIENT_ID,
            client_secret: FAKE_CLIENT_SECRET,
            code,
            redirect_uri: 'https://layla.amazon.com/api/skill/link/X' // different
        });
        assert.equal(res.status, 400);
        assert.equal((await res.json()).error, 'invalid_grant');
    });

    it('authorization_code grant: cannot reuse a code (consumed_at gates retry)', async () => {
        const u = await makeUser();
        const { code } = await alexaCore.issueAlexaAuthCode({
            userId: u.id,
            redirectUri: 'https://pitangui.amazon.com/api/skill/link/X'
        });

        const ok = await postForm({
            grant_type: 'authorization_code',
            client_id: FAKE_CLIENT_ID,
            client_secret: FAKE_CLIENT_SECRET,
            code,
            redirect_uri: 'https://pitangui.amazon.com/api/skill/link/X'
        });
        assert.equal(ok.status, 200);

        const replay = await postForm({
            grant_type: 'authorization_code',
            client_id: FAKE_CLIENT_ID,
            client_secret: FAKE_CLIENT_SECRET,
            code,
            redirect_uri: 'https://pitangui.amazon.com/api/skill/link/X'
        });
        assert.equal(replay.status, 400);
        assert.equal((await replay.json()).error, 'invalid_grant');
    });

    it('authorization_code grant: 403 access_denied when user is suspended', async () => {
        const u = await makeUser('s@x', 'suspended');
        const { code } = await alexaCore.issueAlexaAuthCode({
            userId: u.id,
            redirectUri: 'https://pitangui.amazon.com/api/skill/link/X'
        });

        const res = await postForm({
            grant_type: 'authorization_code',
            client_id: FAKE_CLIENT_ID,
            client_secret: FAKE_CLIENT_SECRET,
            code,
            redirect_uri: 'https://pitangui.amazon.com/api/skill/link/X'
        });
        assert.equal(res.status, 403);
    });

    it('refresh_token grant: rotates access token, returns same refresh token', async () => {
        const u = await makeUser();
        const initial = await alexaCore.issueAlexaTokensForUser(u.id);

        const res = await postForm({
            grant_type: 'refresh_token',
            client_id: FAKE_CLIENT_ID,
            client_secret: FAKE_CLIENT_SECRET,
            refresh_token: initial.refreshToken
        });
        assert.equal(res.status, 200);
        const body = await res.json();
        assert.equal(body.refresh_token, initial.refreshToken);
        assert.notEqual(body.access_token, initial.accessToken);
    });

    it('refresh_token grant: 400 invalid_grant for unknown refresh token', async () => {
        const res = await postForm({
            grant_type: 'refresh_token',
            client_id: FAKE_CLIENT_ID,
            client_secret: FAKE_CLIENT_SECRET,
            refresh_token: 'art_unknown_token_value_for_test_does_not_exist'
        });
        assert.equal(res.status, 400);
        assert.equal((await res.json()).error, 'invalid_grant');
    });

    it('refresh_token grant: 403 access_denied if account became disabled after issue', async () => {
        const u = await makeUser();
        const initial = await alexaCore.issueAlexaTokensForUser(u.id);
        // Simulate the user being suspended after linking.
        await helpers.dbRun(`UPDATE users SET status = 'suspended' WHERE id = ?`, [u.id]);

        const res = await postForm({
            grant_type: 'refresh_token',
            client_id: FAKE_CLIENT_ID,
            client_secret: FAKE_CLIENT_SECRET,
            refresh_token: initial.refreshToken
        });
        assert.equal(res.status, 403);
    });
});
