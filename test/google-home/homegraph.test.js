const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const config = require('../../lib/config');
const utils = require('../../lib/utils');
const state = require('../../lib/google-home/state');
const entityMapping = require('../../lib/google-home/entity-mapping');

const homegraph = require('../../lib/google-home/homegraph')({
    dbGet: async () => null,
    dbRun: async () => ({}),
    dbAll: async () => [],
    config,
    utils,
    state,
    entityMapping
});

// --- normalizeJsonForHash ---
describe('normalizeJsonForHash', () => {
    it('sorts object keys alphabetically', () => {
        const result = homegraph.normalizeJsonForHash({ b: 2, a: 1 });
        const keys = Object.keys(result);
        assert.deepEqual(keys, ['a', 'b']);
    });

    it('recursively sorts nested objects', () => {
        const result = homegraph.normalizeJsonForHash({ z: { b: 2, a: 1 }, a: 1 });
        const outerKeys = Object.keys(result);
        const innerKeys = Object.keys(result.z);
        assert.deepEqual(outerKeys, ['a', 'z']);
        assert.deepEqual(innerKeys, ['a', 'b']);
    });

    it('handles arrays by recursing into elements', () => {
        const result = homegraph.normalizeJsonForHash([{ b: 1, a: 2 }]);
        assert.deepEqual(Object.keys(result[0]), ['a', 'b']);
    });

    it('returns null/undefined as-is', () => {
        assert.equal(homegraph.normalizeJsonForHash(null), null);
        assert.equal(homegraph.normalizeJsonForHash(undefined), undefined);
    });

    it('returns primitives as-is', () => {
        assert.equal(homegraph.normalizeJsonForHash(42), 42);
        assert.equal(homegraph.normalizeJsonForHash('hello'), 'hello');
        assert.equal(homegraph.normalizeJsonForHash(true), true);
    });
});

// --- computeGoogleStateHash ---
describe('computeGoogleStateHash', () => {
    it('produces a consistent SHA-1 hex string', () => {
        const hash1 = homegraph.computeGoogleStateHash({ on: true, brightness: 50 });
        const hash2 = homegraph.computeGoogleStateHash({ on: true, brightness: 50 });
        assert.equal(hash1, hash2);
        assert.equal(hash1.length, 40); // SHA-1 = 40 hex chars
    });

    it('same data in different key order produces same hash', () => {
        const hash1 = homegraph.computeGoogleStateHash({ a: 1, b: 2 });
        const hash2 = homegraph.computeGoogleStateHash({ b: 2, a: 1 });
        assert.equal(hash1, hash2);
    });

    it('different data produces different hash', () => {
        const hash1 = homegraph.computeGoogleStateHash({ on: true });
        const hash2 = homegraph.computeGoogleStateHash({ on: false });
        assert.notEqual(hash1, hash2);
    });

    it('handles null/empty', () => {
        const hash = homegraph.computeGoogleStateHash(null);
        assert.equal(typeof hash, 'string');
        assert.equal(hash.length, 40);
    });
});

// --- base64UrlEncodeJson ---
describe('base64UrlEncodeJson', () => {
    it('encodes JSON object to base64url', () => {
        const result = homegraph.base64UrlEncodeJson({ key: 'value' });
        const decoded = JSON.parse(Buffer.from(result, 'base64url').toString());
        assert.deepEqual(decoded, { key: 'value' });
    });

    it('does not contain + / = chars (base64url)', () => {
        const result = homegraph.base64UrlEncodeJson({ data: 'test string with special chars???' });
        assert.ok(!result.includes('+'));
        assert.ok(!result.includes('/'));
    });
});

// --- homegraph metrics ---
describe('homegraph metrics', () => {
    it('markHomegraphMetricSuccess increments sent', () => {
        const before = state.homegraphMetrics.request_sync.sent;
        homegraph.markHomegraphMetricSuccess('request_sync', 'user1', 200);
        assert.equal(state.homegraphMetrics.request_sync.sent, before + 1);
        assert.equal(state.homegraphMetrics.request_sync.last_status, 200);
        assert.equal(state.homegraphMetrics.request_sync.last_user_id, 'user1');
    });

    it('markHomegraphMetricFailure increments failed', () => {
        const before = state.homegraphMetrics.request_sync.failed;
        homegraph.markHomegraphMetricFailure('request_sync', 'user2', 500, 'timeout');
        assert.equal(state.homegraphMetrics.request_sync.failed, before + 1);
        assert.equal(state.homegraphMetrics.request_sync.last_failure_reason, 'timeout');
    });

    it('markHomegraphMetricSkipped increments skipped', () => {
        const before = state.homegraphMetrics.report_state.skipped;
        homegraph.markHomegraphMetricSkipped('report_state', 'user3', 'no_credentials');
        assert.equal(state.homegraphMetrics.report_state.skipped, before + 1);
    });

    it('ignores invalid metric type', () => {
        // Should not throw
        homegraph.markHomegraphMetricSuccess('nonexistent', 'user');
        homegraph.markHomegraphMetricFailure('nonexistent', 'user');
        homegraph.markHomegraphMetricSkipped('nonexistent', 'user');
    });
});

// --- debounce config ---
describe('debounce config', () => {
    it('getGoogleHomegraphRequestSyncDebounceMs returns a clamped value', () => {
        const ms = homegraph.getGoogleHomegraphRequestSyncDebounceMs();
        assert.ok(ms >= 250 && ms <= 30000);
    });

    it('getGoogleHomegraphReportStateDebounceMs returns a clamped value', () => {
        const ms = homegraph.getGoogleHomegraphReportStateDebounceMs();
        assert.ok(ms >= 250 && ms <= 10000);
    });

    it('getGoogleHomegraphDebounceMs clamps correctly', () => {
        assert.equal(homegraph.getGoogleHomegraphDebounceMs(100, 500, 200, 1000), 200); // below min
        assert.equal(homegraph.getGoogleHomegraphDebounceMs(2000, 500, 200, 1000), 1000); // above max
        assert.equal(homegraph.getGoogleHomegraphDebounceMs(600, 500, 200, 1000), 600); // in range
        assert.equal(homegraph.getGoogleHomegraphDebounceMs(NaN, 500, 200, 1000), 500); // fallback
    });
});

// --- credential helpers ---
describe('credential helpers', () => {
    it('hasGoogleHomegraphCredentials returns false without env vars', () => {
        assert.equal(homegraph.hasGoogleHomegraphCredentials(), false);
    });

    it('getGoogleHomegraphJwtLifetimeSeconds returns 3600', () => {
        assert.equal(homegraph.getGoogleHomegraphJwtLifetimeSeconds(), 3600);
    });

    it('getGoogleHomegraphTokenUri returns default', () => {
        assert.equal(homegraph.getGoogleHomegraphTokenUri(), config.GOOGLE_HOMEGRAPH_DEFAULT_TOKEN_URI);
    });

    it('getGoogleHomegraphApiBaseUrl returns default', () => {
        assert.equal(homegraph.getGoogleHomegraphApiBaseUrl(), config.GOOGLE_HOMEGRAPH_API_BASE_URL);
    });
});
