const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('node:crypto');
const createDbHelpers = require('../../lib/db-helpers');
const createAlexaCore = require('../../lib/alexa/core');
const utils = require('../../lib/utils');

// In-memory schema mirrors what migration 003 left in prod (only the parts
// core.js actually touches — auth codes, tokens, and a stub users table).
const SCHEMA = `
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
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

// Fake LWA crypto so tests don't need ALEXA_LWA_TOKEN_ENC_KEY in env.
// We tag the ciphertext so we can assert "yes, this went through encryption"
// without needing real AES round-tripping (which crypto.test.js covers).
const fakeLwaCrypto = {
    encryptLwaToken(pt) {
        if (pt === null || pt === undefined) return null;
        return 'enc::' + Buffer.from(String(pt)).toString('base64');
    },
    decryptLwaToken(ct) {
        if (!ct) return null;
        if (!String(ct).startsWith('enc::')) return null;
        return Buffer.from(String(ct).slice(5), 'base64').toString('utf8');
    },
    hasEncryptionKey: () => true
};

describe('lib/alexa/core', () => {
    let db;
    let helpers;
    let core;

    before(async () => {
        db = new sqlite3.Database(':memory:');
        helpers = createDbHelpers(db);
        // dbRun is single-statement; use db.exec for the multi-table DDL.
        await new Promise((resolve, reject) => {
            db.exec(SCHEMA, (err) => (err ? reject(err) : resolve()));
        });
    });

    after(() => db.close());

    beforeEach(async () => {
        await helpers.dbRun(`DELETE FROM alexa_tokens`);
        await helpers.dbRun(`DELETE FROM alexa_auth_codes`);
        await helpers.dbRun(`DELETE FROM users`);
        core = createAlexaCore({
            dbGet: helpers.dbGet,
            dbRun: helpers.dbRun,
            dbAll: helpers.dbAll,
            lwaCrypto: fakeLwaCrypto
        });
    });

    async function makeUser(email = 't@example.com') {
        const r = await helpers.dbRun(`INSERT INTO users (email) VALUES (?)`, [email]);
        return r.lastID;
    }

    // ── token generation prefixes (small but matters for log greppability) ──

    it('generates auth code, access, and refresh tokens with stable prefixes', () => {
        assert.match(core.generateAlexaOAuthCode(), /^aac_[0-9a-f]{48}$/);
        assert.match(core.generateAlexaAccessToken(), /^aat_[0-9a-f]{48}$/);
        assert.match(core.generateAlexaRefreshToken(), /^art_[0-9a-f]{48}$/);
    });

    // ── auth-code happy path ────────────────────────────────────────────────

    it('issueAlexaAuthCode then findUserByAlexaAuthCode returns the user', async () => {
        const userId = await makeUser();
        const { code } = await core.issueAlexaAuthCode({
            userId,
            redirectUri: 'https://pitangui.amazon.com/api/skill/link/X'
        });
        const found = await core.findUserByAlexaAuthCode(
            code,
            'https://pitangui.amazon.com/api/skill/link/X'
        );
        assert.equal(found.id, userId);
        assert.equal(found.oauth_redirect_uri, 'https://pitangui.amazon.com/api/skill/link/X');
    });

    it('findUserByAlexaAuthCode returns nothing when redirect_uri does not match', async () => {
        const userId = await makeUser();
        const { code } = await core.issueAlexaAuthCode({
            userId,
            redirectUri: 'https://pitangui.amazon.com/api/skill/link/X'
        });
        const found = await core.findUserByAlexaAuthCode(code, 'https://evil.example/x');
        assert.equal(found, undefined);
    });

    it('consumeAlexaAuthCode prevents reuse', async () => {
        const userId = await makeUser();
        const { code } = await core.issueAlexaAuthCode({ userId, redirectUri: 'https://r' });
        const found = await core.findUserByAlexaAuthCode(code, 'https://r');
        await core.consumeAlexaAuthCode(found.oauth_code_id);
        const second = await core.findUserByAlexaAuthCode(code, 'https://r');
        assert.equal(second, undefined);
    });

    // ── access/refresh token issuance + lookup ──────────────────────────────

    it('issueAlexaTokensForUser stores hashes that lookup can find', async () => {
        const userId = await makeUser();
        const { accessToken, refreshToken } = await core.issueAlexaTokensForUser(userId);

        const u = await core.findUserByAlexaAccessToken(accessToken);
        assert.equal(u.id, userId);

        const r = await core.findAlexaRefreshTokenRow(refreshToken);
        assert.equal(r.user_id, userId);
    });

    it('access token is rejected once expires_at has passed', async () => {
        const userId = await makeUser();
        const { accessToken } = await core.issueAlexaTokensForUser(userId);
        // Fast-forward by overwriting expires_at to the past.
        await helpers.dbRun(
            `UPDATE alexa_tokens SET expires_at = ? WHERE user_id = ?`,
            [new Date(Date.now() - 1000).toISOString(), userId]
        );
        const u = await core.findUserByAlexaAccessToken(accessToken);
        assert.equal(u, undefined);
    });

    it('refresh-token grant: re-issue keeps the same refresh token, rotates access token', async () => {
        const userId = await makeUser();
        const first = await core.issueAlexaTokensForUser(userId);
        const second = await core.issueAlexaTokensForUser(userId, first.refreshToken);

        assert.equal(second.refreshToken, first.refreshToken);
        assert.notEqual(second.accessToken, first.accessToken);

        // Old access token is no longer valid; new one is.
        assert.equal(await core.findUserByAlexaAccessToken(first.accessToken), undefined);
        const u = await core.findUserByAlexaAccessToken(second.accessToken);
        assert.equal(u.id, userId);
    });

    // ── AcceptGrant — the v1 weak point ─────────────────────────────────────

    describe('storeAcceptGrantTokens', () => {
        it('encrypts and stores LWA tokens and flips users.alexa_linked to 1', async () => {
            const userId = await makeUser();
            await core.issueAlexaTokensForUser(userId); // alexa_tokens row must exist first

            await core.storeAcceptGrantTokens(userId, {
                accessToken: 'lwa-access-XYZ',
                refreshToken: 'lwa-refresh-XYZ',
                expiresIn: 3600,
                scopes: 'alexa::async_event:write'
            });

            const tokRow = await helpers.dbGet(
                `SELECT * FROM alexa_tokens WHERE user_id = ?`,
                [userId]
            );
            assert.match(tokRow.lwa_access_token_encrypted, /^enc::/);
            assert.match(tokRow.lwa_refresh_token_encrypted, /^enc::/);
            // Plaintexts should NEVER appear in the row, even by accident.
            assert.ok(!String(tokRow.lwa_access_token_encrypted).includes('lwa-access-XYZ'));
            assert.ok(!String(tokRow.lwa_refresh_token_encrypted).includes('lwa-refresh-XYZ'));
            assert.equal(tokRow.lwa_scopes, 'alexa::async_event:write');

            const userRow = await helpers.dbGet(
                `SELECT alexa_linked FROM users WHERE id = ?`,
                [userId]
            );
            assert.equal(userRow.alexa_linked, 1);
        });

        it('REFUSES to persist a half-linked state when refreshToken is missing (v1 failure mode)', async () => {
            const userId = await makeUser();
            await core.issueAlexaTokensForUser(userId);

            await assert.rejects(
                core.storeAcceptGrantTokens(userId, {
                    accessToken: 'lwa-access-only',
                    refreshToken: '', // ← the actual v1 bug: silent acceptance
                    expiresIn: 3600
                }),
                /half-linked Alexa account/
            );

            const userRow = await helpers.dbGet(
                `SELECT alexa_linked FROM users WHERE id = ?`,
                [userId]
            );
            assert.equal(userRow.alexa_linked, 0, 'must NOT mark linked');
        });

        it('throws (and leaves alexa_linked = 0) when no alexa_tokens row exists yet', async () => {
            const userId = await makeUser();
            // Note: no issueAlexaTokensForUser first — simulates AcceptGrant
            // arriving before /api/alexa/token completed.
            await assert.rejects(
                core.storeAcceptGrantTokens(userId, {
                    refreshToken: 'lwa-refresh',
                    expiresIn: 3600
                }),
                /no alexa_tokens row exists/
            );
            const userRow = await helpers.dbGet(
                `SELECT alexa_linked FROM users WHERE id = ?`,
                [userId]
            );
            assert.equal(userRow.alexa_linked, 0);
        });

        it('rejects invalid userId without touching the database', async () => {
            await assert.rejects(
                core.storeAcceptGrantTokens(0, { refreshToken: 'x' }),
                /invalid userId/
            );
            await assert.rejects(
                core.storeAcceptGrantTokens(null, { refreshToken: 'x' }),
                /invalid userId/
            );
        });
    });

    // ── Decrypt + unlink ────────────────────────────────────────────────────

    it('getDecryptedLwaTokensForUser returns plaintexts after AcceptGrant', async () => {
        const userId = await makeUser();
        await core.issueAlexaTokensForUser(userId);
        await core.storeAcceptGrantTokens(userId, {
            accessToken: 'access-PT',
            refreshToken: 'refresh-PT',
            expiresIn: 3600
        });
        const got = await core.getDecryptedLwaTokensForUser(userId);
        assert.equal(got.accessToken, 'access-PT');
        assert.equal(got.refreshToken, 'refresh-PT');
    });

    it('getDecryptedLwaTokensForUser returns null before AcceptGrant', async () => {
        const userId = await makeUser();
        await core.issueAlexaTokensForUser(userId);
        const got = await core.getDecryptedLwaTokensForUser(userId);
        assert.equal(got, null);
    });

    it('unlinkAlexaForUser clears tokens row and resets alexa_linked', async () => {
        const userId = await makeUser();
        await core.issueAlexaTokensForUser(userId);
        await core.storeAcceptGrantTokens(userId, { refreshToken: 'r', expiresIn: 60 });
        await core.unlinkAlexaForUser(userId);
        const tokRow = await helpers.dbGet(`SELECT * FROM alexa_tokens WHERE user_id = ?`, [userId]);
        assert.equal(tokRow, undefined);
        const userRow = await helpers.dbGet(`SELECT alexa_linked FROM users WHERE id = ?`, [userId]);
        assert.equal(userRow.alexa_linked, 0);
    });

    // ── TTL clamps ──────────────────────────────────────────────────────────

    it('TTL helpers stay within the documented bounds even on weird config', () => {
        // We can't easily mutate the frozen config from a test, but we can
        // assert the clamps' upper/lower edges by reading the public values.
        assert.ok(core.getAlexaAuthCodeTtlSeconds() >= 120);
        assert.ok(core.getAlexaAuthCodeTtlSeconds() <= 1800);
        assert.ok(core.getAlexaAccessTokenTtlSeconds() >= 300);
        assert.ok(core.getAlexaAccessTokenTtlSeconds() <= 7200);
        assert.ok(core.getAlexaCommandTtlSeconds() >= 10);
        assert.ok(core.getAlexaCommandTtlSeconds() <= 180);
    });

    // ── Hashing sanity ──────────────────────────────────────────────────────

    it('access tokens are stored hashed, not plaintext (defense vs DB dump)', async () => {
        const userId = await makeUser();
        const { accessToken } = await core.issueAlexaTokensForUser(userId);
        const row = await helpers.dbGet(`SELECT * FROM alexa_tokens WHERE user_id = ?`, [userId]);
        assert.notEqual(row.access_token_hash, accessToken);
        assert.equal(row.access_token_hash, utils.hashSecret(accessToken));
        // sha256 hex digest is 64 chars; sanity-check that's what we stored.
        assert.equal(row.access_token_hash.length, 64);
    });

    it('different users get different access tokens (no caching bug)', async () => {
        const u1 = await makeUser('a@x');
        const u2 = await makeUser('b@x');
        const t1 = await core.issueAlexaTokensForUser(u1);
        const t2 = await core.issueAlexaTokensForUser(u2);
        assert.notEqual(t1.accessToken, t2.accessToken);
        assert.notEqual(t1.refreshToken, t2.refreshToken);
    });

    // ── Defensive returns ───────────────────────────────────────────────────

    it('lookup helpers return null/undefined for empty inputs without querying DB', async () => {
        assert.equal(await core.findUserByAlexaAccessToken(''), null);
        assert.equal(await core.findUserByAlexaAccessToken(null), null);
        assert.equal(await core.findAlexaRefreshTokenRow(''), null);
        assert.equal(await core.findUserByAlexaAuthCode('', 'https://r'), null);
    });

    // Suppress lint for unused crypto import — kept so a future test that
    // needs raw randomness has it ready without re-adding the require.
    void crypto;
});
