const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const homegraphMock = {
    hasGoogleHomegraphCredentials: () => false,
    sendGoogleRequestSync: async () => {},
    sendGoogleReportState: async () => {},
    scheduleGoogleRequestSyncForUser: () => {},
    scheduleGoogleReportStateForUser: () => {},
    collectGoogleReportableStateChangesForUser: async () => ({ changes: [], hashes: [] }),
    markGoogleReportedStateHashes: async () => {},
    markGoogleEntitiesStaleByFreshness: async () => {}
};

const core = require('../../lib/google-home/core')({
    dbGet: async () => null,
    dbRun: async () => ({}),
    dbAll: async () => [],
    homegraph: homegraphMock
});

describe('getGoogleAuthCodeTtlSeconds', () => {
    it('returns a number within bounds', () => {
        const ttl = core.getGoogleAuthCodeTtlSeconds();
        assert.ok(typeof ttl === 'number');
        assert.ok(ttl >= 60 && ttl <= 3600);
    });
});

describe('getGoogleAccessTokenTtlSeconds', () => {
    it('returns a number within bounds', () => {
        const ttl = core.getGoogleAccessTokenTtlSeconds();
        assert.ok(typeof ttl === 'number');
        assert.ok(ttl >= 300 && ttl <= 86400);
    });
});

describe('getGoogleCommandTtlSeconds', () => {
    it('returns a number within bounds', () => {
        const ttl = core.getGoogleCommandTtlSeconds();
        assert.ok(typeof ttl === 'number');
        assert.ok(ttl >= 5 && ttl <= 120);
    });
});

describe('token generators', () => {
    it('generateGoogleOAuthCode starts with prefix', () => {
        const code = core.generateGoogleOAuthCode();
        assert.ok(code.startsWith('gac_'));
    });

    it('generateGoogleAccessToken starts with prefix', () => {
        const token = core.generateGoogleAccessToken();
        assert.ok(token.startsWith('gat_'));
    });

    it('generateGoogleRefreshToken starts with prefix', () => {
        const token = core.generateGoogleRefreshToken();
        assert.ok(token.startsWith('grt_'));
    });

    it('each call generates unique tokens', () => {
        const a = core.generateGoogleOAuthCode();
        const b = core.generateGoogleOAuthCode();
        assert.notEqual(a, b);
    });
});

describe('withEffectiveGoogleOnline', () => {
    it('enriches entity with online flag', () => {
        const entity = {
            entity_id: 'light.test',
            entity_type: 'light',
            online: 0,
            last_seen_at: '2020-01-01T00:00:00Z',
            entity_last_seen_at: null,
            updated_at: null
        };
        const result = core.withEffectiveGoogleOnline(entity);
        assert.ok('online' in result);
        assert.equal(typeof result.online, 'number');
    });

    it('marks recently seen devices as online', () => {
        const entity = {
            entity_id: 'light.test',
            entity_type: 'light',
            online: 1,
            last_seen_at: new Date().toISOString(),
            entity_last_seen_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        };
        const result = core.withEffectiveGoogleOnline(entity);
        assert.equal(result.online, 1);
    });
});
