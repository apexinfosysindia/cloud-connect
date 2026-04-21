const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const eventGatewayMock = {
    computeAlexaStateHash: () => 'hash',
    markAlexaEntitiesStaleByFreshness: async () => {},
    queueAlexaChangeReport: () => {},
    queueAlexaAddOrUpdateReport: () => {}
};

const core = require('../../lib/alexa/core')({
    dbGet: async () => null,
    dbRun: async () => ({}),
    dbAll: async () => [],
    eventGateway: eventGatewayMock
});

describe('getAlexaAuthCodeTtlSeconds', () => {
    it('returns a number within bounds', () => {
        const ttl = core.getAlexaAuthCodeTtlSeconds();
        assert.equal(typeof ttl, 'number');
        assert.ok(ttl >= 120 && ttl <= 1800);
    });
});

describe('getAlexaAccessTokenTtlSeconds', () => {
    it('returns a number within bounds', () => {
        const ttl = core.getAlexaAccessTokenTtlSeconds();
        assert.equal(typeof ttl, 'number');
        assert.ok(ttl >= 300 && ttl <= 7200);
    });
});

describe('getAlexaCommandTtlSeconds', () => {
    it('returns a number within bounds', () => {
        const ttl = core.getAlexaCommandTtlSeconds();
        assert.equal(typeof ttl, 'number');
        assert.ok(ttl >= 10 && ttl <= 180);
    });
});

describe('token generators', () => {
    it('generateAlexaOAuthCode starts with aac_', () => {
        const code = core.generateAlexaOAuthCode();
        assert.ok(code.startsWith('aac_'));
        assert.ok(code.length >= 40);
    });

    it('generateAlexaAccessToken starts with aat_', () => {
        const token = core.generateAlexaAccessToken();
        assert.ok(token.startsWith('aat_'));
        assert.ok(token.length >= 40);
    });

    it('generateAlexaRefreshToken starts with art_', () => {
        const token = core.generateAlexaRefreshToken();
        assert.ok(token.startsWith('art_'));
        assert.ok(token.length >= 40);
    });

    it('generates unique tokens across N=100', () => {
        const set = new Set();
        for (let i = 0; i < 100; i++) {
            set.add(core.generateAlexaOAuthCode());
            set.add(core.generateAlexaAccessToken());
            set.add(core.generateAlexaRefreshToken());
        }
        assert.equal(set.size, 300);
    });
});

describe('findUserByAlexaAccessToken', () => {
    it('returns null for falsy input without touching dbGet', async () => {
        let dbGetCalled = false;
        const c = require('../../lib/alexa/core')({
            dbGet: async () => {
                dbGetCalled = true;
                return { id: 1 };
            },
            dbRun: async () => ({}),
            dbAll: async () => [],
            eventGateway: eventGatewayMock
        });

        assert.equal(await c.findUserByAlexaAccessToken(null), null);
        assert.equal(await c.findUserByAlexaAccessToken(''), null);
        assert.equal(await c.findUserByAlexaAccessToken(undefined), null);
        assert.equal(dbGetCalled, false);
    });
});

describe('queueAlexaCommandForEntity', () => {
    it('rejects empty entity_id with null', async () => {
        const result = await core.queueAlexaCommandForEntity(1, 1, '', 'set_on', {});
        assert.equal(result, null);
    });

    it('rejects falsy entity_id with null', async () => {
        assert.equal(await core.queueAlexaCommandForEntity(1, 1, null, 'set_on', {}), null);
        assert.equal(await core.queueAlexaCommandForEntity(1, 1, undefined, 'set_on', {}), null);
    });
});

describe('cleanupAlexaAuthDataForUser', () => {
    it('does not throw when user has no rows', async () => {
        await assert.doesNotReject(core.cleanupAlexaAuthDataForUser(9999));
    });
});
