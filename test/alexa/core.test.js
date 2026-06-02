const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

process.env.ALEXA_LWA_TOKEN_ENC_KEY = crypto.randomBytes(32).toString('hex');

const utils = require('../../lib/utils');
const config = require('../../lib/config');

function makeDb() {
    const db = new sqlite3.Database(':memory:');
    const dbRun = (sql, p = []) => new Promise((res, rej) => db.run(sql, p, function (e) { e ? rej(e) : res(this); }));
    const dbGet = (sql, p = []) => new Promise((res, rej) => db.get(sql, p, (e, r) => (e ? rej(e) : res(r))));
    const dbAll = (sql, p = []) => new Promise((res, rej) => db.all(sql, p, (e, r) => (e ? rej(e) : res(r))));
    return { db, dbRun, dbGet, dbAll };
}

describe('alexa core', () => {
    let core;
    let helpers;

    before(async () => {
        helpers = makeDb();
        await new Promise((res, rej) =>
            helpers.db.serialize(() =>
                require('../../lib/migrator')({ db: helpers.db, migrationsDir: path.join(__dirname, '../../migrations') })
                    .runPending()
                    .then(res, rej)
            )
        );
        const alexaCrypto = require('../../lib/alexa/crypto')({ config });
        core = require('../../lib/alexa/core')({ ...helpers, alexaCrypto });
        await helpers.dbRun(
            "INSERT INTO users (email,password,status,alexa_enabled,alexa_linked) VALUES (?,?,?,1,1)",
            ['u@x.com', 'pw', 'active']
        );
        await helpers.dbRun("INSERT INTO devices (user_id,device_uid,device_token_hash) VALUES (1,?,?)", ['d1', 'h1']);
    });

    it('TTLs are within bounds', () => {
        assert.ok(core.getAlexaAuthCodeTtlSeconds() >= 120);
        assert.ok(core.getAlexaAccessTokenTtlSeconds() >= 300);
        assert.ok(core.getAlexaCommandTtlSeconds() >= 10);
    });

    it('issues a bearer token and resolves the user from it', async () => {
        const tok = await core.issueAlexaTokensForUser(1);
        assert.ok(tok.access_token.startsWith('aat_'));
        assert.equal(tok.token_type, 'Bearer');
        const user = await core.findUserByAlexaAccessToken(tok.access_token);
        assert.equal(user.id, 1);
    });

    it('rejects an unknown bearer token', async () => {
        assert.ok(!(await core.findUserByAlexaAccessToken('aat_bogus')));
    });

    it('stores LWA tokens as ciphertext and decrypts them back', async () => {
        await core.storeAlexaLwaTokens(1, { accessToken: 'Atza|acc', refreshToken: 'Atzr|ref', region: 'NA', expiresInSeconds: 3600 });
        const raw = await helpers.dbGet('SELECT access_token_encrypted FROM alexa_lwa_tokens WHERE user_id = 1');
        assert.ok(raw.access_token_encrypted.startsWith('v1:'));
        assert.ok(!/Atza/.test(raw.access_token_encrypted));
        const decoded = await core.getAlexaLwaTokenRow(1);
        assert.equal(decoded.access_token, 'Atza|acc');
        assert.equal(decoded.refresh_token, 'Atzr|ref');
    });

    it('upserts an endpoint and lists it', async () => {
        const { endpoint, syncChanged } = await core.upsertAlexaEndpointFromDevice(1, 1, {
            entity_id: 'light.k',
            display_name: 'Kitchen',
            entity_type: 'light',
            state: { on: true, brightness: 50, supported_color_modes: ['brightness'] }
        });
        assert.equal(endpoint.entity_id, 'light.k');
        assert.equal(syncChanged, true);
        const list = await core.getAlexaEndpointsForUser(1);
        assert.equal(list.length, 1);
    });

    it('queues a command and supersedes a prior pending one', async () => {
        const first = await core.queueAlexaCommandForEndpoint(1, 1, 'light.k', 'set_brightness', { brightness: 10 });
        const second = await core.queueAlexaCommandForEndpoint(1, 1, 'light.k', 'set_brightness', { brightness: 90 });
        assert.equal(second.status, 'pending');
        const firstAfter = await helpers.dbGet('SELECT status FROM alexa_command_queue WHERE id = ?', [first.id]);
        assert.equal(firstAfter.status, 'expired');
    });

    it('cleanup removes tokens and unlinks the user', async () => {
        await core.cleanupAlexaAuthDataForUser(1);
        const u = await helpers.dbGet('SELECT alexa_linked, alexa_enabled FROM users WHERE id = 1');
        assert.equal(u.alexa_linked, 0);
        const lwa = await helpers.dbGet('SELECT COUNT(*) AS c FROM alexa_lwa_tokens WHERE user_id = 1');
        assert.equal(lwa.c, 0);
    });
});

describe('alexa crypto', () => {
    it('rejects a tampered ciphertext (GCM auth tag)', () => {
        const alexaCrypto = require('../../lib/alexa/crypto')({ config });
        const ct = alexaCrypto.encryptToken('secret');
        assert.throws(() => alexaCrypto.decryptToken(ct.slice(0, -4) + 'AAAA'));
    });

    it('passes through null', () => {
        const alexaCrypto = require('../../lib/alexa/crypto')({ config });
        assert.equal(alexaCrypto.encryptToken(null), null);
        assert.equal(alexaCrypto.decryptToken(null), null);
    });
});
