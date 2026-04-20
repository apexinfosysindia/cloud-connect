const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

process.env.PORTAL_SESSION_SECRET =
    process.env.PORTAL_SESSION_SECRET || 'x'.repeat(48);

const utils = require('../../lib/utils');
const alexaState = require('../../lib/alexa/state');
const directiveMapping = require('../../lib/alexa/directive-mapping');

function makeEventsWithMocks({ dbGet = async () => null, dbRun = async () => ({}), dbAll = async () => [] } = {}) {
    return require('../../lib/alexa/events')({
        dbGet,
        dbRun,
        dbAll,
        config: require('../../lib/config'),
        utils,
        state: alexaState,
        directiveMapping
    });
}

describe('alexa/events debounce clamps', () => {
    const events = makeEventsWithMocks();
    it('change-report debounce is positive', () => {
        const ms = events.getAlexaChangeReportDebounceMs();
        assert.ok(ms >= 250 && ms <= 10000);
    });
    it('discovery debounce is positive', () => {
        const ms = events.getAlexaDiscoveryDebounceMs();
        assert.ok(ms >= 500 && ms <= 30000);
    });
});

describe('alexa/events hash determinism', () => {
    const events = makeEventsWithMocks();
    it('same state → same hash', () => {
        const a = events.computeAlexaStateHash({ on: true, brightness: 50 });
        const b = events.computeAlexaStateHash({ on: true, brightness: 50 });
        assert.equal(a, b);
    });
    it('different state → different hash', () => {
        const a = events.computeAlexaStateHash({ on: true });
        const b = events.computeAlexaStateHash({ on: false });
        assert.notEqual(a, b);
    });
});

describe('alexa/events hasAlexaLwaCredentials', () => {
    const events = makeEventsWithMocks();
    it('returns a boolean', () => {
        assert.equal(typeof events.hasAlexaLwaCredentials(), 'boolean');
    });
});

describe('alexa/events scheduleAlexaChangeReportForUser no-op safety', () => {
    it('does not throw for an invalid userId', () => {
        const events = makeEventsWithMocks();
        assert.doesNotThrow(() => events.scheduleAlexaChangeReportForUser(null));
        assert.doesNotThrow(() => events.scheduleAlexaChangeReportForUser(0));
    });
});

describe('utils.encryptAtRest / decryptAtRest round-trip', () => {
    it('encrypted value decrypts back to plaintext', () => {
        const pt = 'atza|SECRET-REFRESH-TOKEN-123';
        const ct = utils.encryptAtRest(pt);
        assert.ok(ct.startsWith('enc_v1:'));
        assert.equal(utils.decryptAtRest(ct), pt);
    });
    it('null / empty returns null', () => {
        assert.equal(utils.encryptAtRest(''), null);
        assert.equal(utils.encryptAtRest(null), null);
    });
    it('legacy plaintext is returned unchanged by decrypt', () => {
        assert.equal(utils.decryptAtRest('plain-value'), 'plain-value');
    });
    it('tampered ciphertext returns null', () => {
        const ct = utils.encryptAtRest('hello');
        const tampered = ct.slice(0, -4) + 'XXXX';
        assert.equal(utils.decryptAtRest(tampered), null);
    });
});
