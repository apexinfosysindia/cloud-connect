const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

process.env.ALEXA_LWA_TOKEN_ENC_KEY = crypto.randomBytes(32).toString('hex');

const config = require('../../lib/config');

function makeDb() {
    const db = new sqlite3.Database(':memory:');
    const dbRun = (sql, p = []) => new Promise((res, rej) => db.run(sql, p, function (e) { e ? rej(e) : res(this); }));
    const dbGet = (sql, p = []) => new Promise((res, rej) => db.get(sql, p, (e, r) => (e ? rej(e) : res(r))));
    const dbAll = (sql, p = []) => new Promise((res, rej) => db.all(sql, p, (e, r) => (e ? rej(e) : res(r))));
    return { db, dbRun, dbGet, dbAll };
}

describe('alexa event-gateway report collection', () => {
    let core;
    let eventGateway;
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
        eventGateway = require('../../lib/alexa/event-gateway')({ ...helpers, core });
        await helpers.dbRun(
            "INSERT INTO users (email,password,status,alexa_enabled,alexa_linked) VALUES (?,?,?,1,1)",
            ['u@x.com', 'pw', 'active']
        );
        await helpers.dbRun("INSERT INTO devices (user_id,device_uid,device_token_hash) VALUES (1,?,?)", ['d1', 'h1']);
        await core.upsertAlexaEndpointFromDevice(1, 1, {
            entity_id: 'light.k',
            display_name: 'K',
            entity_type: 'light',
            state: { on: true, brightness: 60, supported_color_modes: ['color_temp'], color_temp_kelvin: 3000 }
        });
    });

    it('force-collects the endpoint', async () => {
        const { reports } = await eventGateway.collectAlexaChangeReportsForUser(1, { force: true });
        assert.equal(reports.length, 1);
        assert.equal(reports[0].entityId, 'light.k');
        const power = reports[0].props.find((p) => p.name === 'powerState');
        assert.equal(power.value, 'ON');
    });

    it('skips endpoints whose hash is unchanged', async () => {
        const { hashes } = await eventGateway.collectAlexaChangeReportsForUser(1, { force: true });
        await eventGateway.markAlexaReportedStateHashes(1, hashes);
        const { reports } = await eventGateway.collectAlexaChangeReportsForUser(1, { force: false });
        assert.equal(reports.length, 0);
    });

    it('re-detects after a state change', async () => {
        await core.upsertAlexaEndpointFromDevice(1, 1, {
            entity_id: 'light.k',
            display_name: 'K',
            entity_type: 'light',
            state: { on: false, supported_color_modes: ['color_temp'] }
        });
        const { reports } = await eventGateway.collectAlexaChangeReportsForUser(1, { force: false });
        assert.equal(reports.length, 1);
        const power = reports[0].props.find((p) => p.name === 'powerState');
        assert.equal(power.value, 'OFF');
    });

    it('suppresses an endpoint with an in-flight command', async () => {
        // Reset reported hash so it would otherwise be collected.
        await eventGateway.markAlexaReportedStateHashes(1, { 'light.k': 'stale' });
        await core.queueAlexaCommandForEndpoint(1, 1, 'light.k', 'turn_on', { on: true });
        const { reports } = await eventGateway.collectAlexaChangeReportsForUser(1, { force: true });
        assert.equal(reports.length, 0);
    });

    it('buildProperties stamps structured AlexaProp tuples (with instance)', () => {
        const props = eventGateway.buildProperties([
            { namespace: 'Alexa.PowerController', name: 'powerState', value: 'ON' },
            { namespace: 'Alexa.RangeController', instance: 'Fan.Speed', name: 'rangeValue', value: 50 },
            { namespace: 'Alexa.EndpointHealth', name: 'connectivity', value: { value: 'OK' } }
        ]);
        const power = props.find((p) => p.name === 'powerState');
        assert.equal(power.namespace, 'Alexa.PowerController');
        assert.equal(power.value, 'ON');
        assert.ok(power.timeOfSample);
        const speed = props.find((p) => p.name === 'rangeValue');
        assert.equal(speed.instance, 'Fan.Speed');
        assert.equal(speed.value, 50);
        const health = props.find((p) => p.name === 'connectivity');
        assert.deepEqual(health.value, { value: 'OK' });
    });

    it('buildProperties still accepts a legacy flat object (back-compat)', () => {
        const props = eventGateway.buildProperties({ powerState: 'ON', connectivity: 'OK' });
        const power = props.find((p) => p.name === 'powerState');
        assert.equal(power.namespace, 'Alexa.PowerController');
        assert.equal(power.value, 'ON');
        const health = props.find((p) => p.name === 'connectivity');
        assert.deepEqual(health.value, { value: 'OK' });
    });
});

describe('sendDoorbellPressEvent', () => {
    let core;
    let eventGateway;
    let helpers;
    const captured = [];

    before(async () => {
        helpers = makeDb();
        await new Promise((res, rej) =>
            helpers.db.serialize(() =>
                require('../../lib/migrator')({ db: helpers.db, migrationsDir: path.join(__dirname, '../../migrations') })
                    .runPending()
                    .then(res, rej)
            )
        );
        // Credentials must be present for hasAlexaCredentials().
        process.env.ALEXA_LWA_CLIENT_ID = 'cid';
        process.env.ALEXA_LWA_CLIENT_SECRET = 'secret';
        process.env.ALEXA_REPORT_STATE_ENABLED = '1';
        delete require.cache[require.resolve('../../lib/config')];
        const freshConfig = require('../../lib/config');
        const alexaCrypto = require('../../lib/alexa/crypto')({ config: freshConfig });
        core = require('../../lib/alexa/core')({ ...helpers, alexaCrypto });
        eventGateway = require('../../lib/alexa/event-gateway')({ ...helpers, core });
        await helpers.dbRun(
            "INSERT INTO users (email,password,status,alexa_enabled,alexa_linked) VALUES (?,?,?,1,1)",
            ['d@x.com', 'pw', 'active']
        );
        await core.storeAlexaLwaTokens(1, { accessToken: 'lwa-acc', refreshToken: 'lwa-ref', region: 'NA', expiresInSeconds: 3600 });

        // Stub fetch: token refresh returns an access token; event POST returns 202
        // and captures the envelope.
        global.fetch = async (url, opts) => {
            if (String(url).includes('/auth/') || String(url).includes('token')) {
                return { ok: true, status: 200, json: async () => ({ access_token: 'acc-tok', expires_in: 3600 }) };
            }
            captured.push({ url, body: JSON.parse(opts.body) });
            return { ok: true, status: 202, text: async () => '', json: async () => ({}) };
        };
    });

    it('posts a DoorbellPress envelope with PHYSICAL_INTERACTION cause', async () => {
        const res = await eventGateway.sendDoorbellPressEvent(1, 'event.front_doorbell');
        assert.equal(res.ok, true);
        assert.equal(res.statusCode, 202);
        const ev = captured[captured.length - 1].body.event;
        assert.equal(ev.header.namespace, 'Alexa.DoorbellEventSource');
        assert.equal(ev.header.name, 'DoorbellPress');
        assert.equal(ev.endpoint.endpointId, 'event.front_doorbell');
        assert.equal(ev.endpoint.scope.type, 'BearerToken');
        assert.equal(ev.payload.cause.type, 'PHYSICAL_INTERACTION');
        assert.ok(ev.payload.timestamp);
    });

    it('skips (does not throw) for an unlinked user', async () => {
        await helpers.dbRun('UPDATE users SET alexa_linked = 0 WHERE id = 1');
        const res = await eventGateway.sendDoorbellPressEvent(1, 'event.front_doorbell');
        assert.equal(res.skipped, true);
        assert.equal(res.reason, 'not_linked');
        await helpers.dbRun('UPDATE users SET alexa_linked = 1 WHERE id = 1');
    });
});
