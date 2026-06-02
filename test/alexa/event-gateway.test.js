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
        assert.equal(reports[0].props.powerState, 'ON');
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
        assert.equal(reports[0].props.powerState, 'OFF');
    });

    it('suppresses an endpoint with an in-flight command', async () => {
        // Reset reported hash so it would otherwise be collected.
        await eventGateway.markAlexaReportedStateHashes(1, { 'light.k': 'stale' });
        await core.queueAlexaCommandForEndpoint(1, 1, 'light.k', 'turn_on', { on: true });
        const { reports } = await eventGateway.collectAlexaChangeReportsForUser(1, { force: true });
        assert.equal(reports.length, 0);
    });

    it('buildProperties wraps values in the Alexa context envelope', () => {
        const props = eventGateway.buildProperties({ powerState: 'ON', connectivity: 'OK' });
        const power = props.find((p) => p.name === 'powerState');
        assert.equal(power.namespace, 'Alexa.PowerController');
        assert.equal(power.value, 'ON');
        assert.ok(power.timeOfSample);
        const health = props.find((p) => p.name === 'connectivity');
        assert.deepEqual(health.value, { value: 'OK' });
    });
});
