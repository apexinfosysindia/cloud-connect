const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const config = require('../../lib/config');
const utils = require('../../lib/utils');
const alexaState = require('../../lib/alexa/state');
const entityMapping = require('../../lib/alexa/entity-mapping');

// Factory helper that accepts per-test dbGet/dbRun/dbAll mocks.
function makeGateway(overrides = {}) {
    return require('../../lib/alexa/event-gateway')({
        dbGet: overrides.dbGet || (async () => null),
        dbRun: overrides.dbRun || (async () => ({})),
        dbAll: overrides.dbAll || (async () => []),
        config,
        utils,
        state: alexaState,
        entityMapping
    });
}

const gateway = makeGateway();

// --- computeAlexaStateHash ---
describe('computeAlexaStateHash', () => {
    it('returns string stable across calls with same input', () => {
        const hash1 = gateway.computeAlexaStateHash([{ namespace: 'Alexa.PowerController', name: 'powerState', value: 'ON' }]);
        const hash2 = gateway.computeAlexaStateHash([{ namespace: 'Alexa.PowerController', name: 'powerState', value: 'ON' }]);
        assert.equal(hash1, hash2);
        assert.equal(typeof hash1, 'string');
        assert.equal(hash1.length, 40);
    });

    it('changes when relevant fields change', () => {
        const a = gateway.computeAlexaStateHash([{ namespace: 'Alexa.PowerController', name: 'powerState', value: 'ON' }]);
        const b = gateway.computeAlexaStateHash([{ namespace: 'Alexa.PowerController', name: 'powerState', value: 'OFF' }]);
        assert.notEqual(a, b);
    });

    it('is stable when only timeOfSample/uncertainty differ', () => {
        const a = gateway.computeAlexaStateHash([
            { namespace: 'Alexa.PowerController', name: 'powerState', value: 'ON', timeOfSample: '2025-01-01T00:00:00Z', uncertaintyInMilliseconds: 500 }
        ]);
        const b = gateway.computeAlexaStateHash([
            { namespace: 'Alexa.PowerController', name: 'powerState', value: 'ON', timeOfSample: '2026-12-31T23:59:59Z', uncertaintyInMilliseconds: 9000 }
        ]);
        assert.equal(a, b);
    });

    it('handles null/empty', () => {
        assert.equal(typeof gateway.computeAlexaStateHash(null), 'string');
        assert.equal(typeof gateway.computeAlexaStateHash({}), 'string');
    });
});

// --- debounce config ---
describe('debounce config', () => {
    it('getAlexaChangeReportDebounceMs in bounds', () => {
        const ms = gateway.getAlexaChangeReportDebounceMs();
        assert.ok(ms >= 250 && ms <= 10000);
    });

    it('getAlexaAddOrUpdateReportDebounceMs in bounds', () => {
        const ms = gateway.getAlexaAddOrUpdateReportDebounceMs();
        assert.ok(ms >= 250 && ms <= 30000);
    });
});

// --- credential helpers / skip behavior ---
describe('credential helpers', () => {
    it('hasLwaClientCredentials returns false without env vars', () => {
        // Config has no LWA defaults; env unset in test.
        const prevId = process.env.LWA_CLIENT_ID;
        const prevSecret = process.env.LWA_CLIENT_SECRET;
        delete process.env.LWA_CLIENT_ID;
        delete process.env.LWA_CLIENT_SECRET;
        try {
            assert.equal(gateway.hasLwaClientCredentials(), false);
        } finally {
            if (prevId !== undefined) process.env.LWA_CLIENT_ID = prevId;
            if (prevSecret !== undefined) process.env.LWA_CLIENT_SECRET = prevSecret;
        }
    });

    it('postToAlexaEventGateway skips when LWA credentials missing, increments skipped', async () => {
        const prevId = process.env.LWA_CLIENT_ID;
        const prevSecret = process.env.LWA_CLIENT_SECRET;
        delete process.env.LWA_CLIENT_ID;
        delete process.env.LWA_CLIENT_SECRET;
        try {
            const result = await gateway.postToAlexaEventGateway(1, { event: {} });
            assert.equal(result.ok, false);
            assert.equal(result.skipped, true);
            assert.equal(result.reason, 'missing_lwa_credentials');
        } finally {
            if (prevId !== undefined) process.env.LWA_CLIENT_ID = prevId;
            if (prevSecret !== undefined) process.env.LWA_CLIENT_SECRET = prevSecret;
        }
    });
});

// --- URL helpers ---
describe('URL helpers', () => {
    it('getAlexaEventGatewayUrl returns default', () => {
        const url = gateway.getAlexaEventGatewayUrl();
        assert.ok(url.includes('amazonalexa.com') || url.length > 0);
    });

    it('getLwaTokenUrl returns default', () => {
        const url = gateway.getLwaTokenUrl();
        assert.ok(url.includes('amazon.com') || url.length > 0);
    });
});

// --- debounce coalescing ---
describe('queueAlexaChangeReport debounce', () => {
    it('coalesces rapid successive calls for the same (user, entity) into one timer', () => {
        // Force credentials present by providing mock env and encryption key.
        const prevId = process.env.LWA_CLIENT_ID;
        const prevSec = process.env.LWA_CLIENT_SECRET;
        const prevKey = process.env.ALEXA_LWA_TOKEN_ENC_KEY;
        process.env.LWA_CLIENT_ID = 'amzn1.application-oa2-client.test';
        process.env.LWA_CLIENT_SECRET = 'secret-secret-secret';
        process.env.ALEXA_LWA_TOKEN_ENC_KEY = require('crypto').randomBytes(32).toString('hex');

        try {
            // Clear queue for isolation
            for (const [key, entry] of alexaState.alexaChangeReportQueue.entries()) {
                if (entry?.timer) clearTimeout(entry.timer);
                alexaState.alexaChangeReportQueue.delete(key);
            }

            const g = makeGateway();
            g.queueAlexaChangeReport(42, 'light.test');
            g.queueAlexaChangeReport(42, 'light.test');
            g.queueAlexaChangeReport(42, 'light.test');

            // Only one entry per (user,entity)
            assert.equal(alexaState.alexaChangeReportQueue.size, 1);
            const entry = alexaState.alexaChangeReportQueue.get('42:light.test');
            assert.ok(entry);
            assert.ok(entry.timer);

            // Cleanup
            clearTimeout(entry.timer);
            alexaState.alexaChangeReportQueue.delete('42:light.test');
        } finally {
            if (prevId === undefined) delete process.env.LWA_CLIENT_ID;
            else process.env.LWA_CLIENT_ID = prevId;
            if (prevSec === undefined) delete process.env.LWA_CLIENT_SECRET;
            else process.env.LWA_CLIENT_SECRET = prevSec;
            if (prevKey === undefined) delete process.env.ALEXA_LWA_TOKEN_ENC_KEY;
            else process.env.ALEXA_LWA_TOKEN_ENC_KEY = prevKey;
        }
    });

    it('different (user, entity) tuples get independent debounce keys', () => {
        const prevId = process.env.LWA_CLIENT_ID;
        const prevSec = process.env.LWA_CLIENT_SECRET;
        const prevKey = process.env.ALEXA_LWA_TOKEN_ENC_KEY;
        process.env.LWA_CLIENT_ID = 'amzn1.application-oa2-client.test';
        process.env.LWA_CLIENT_SECRET = 'secret-secret-secret';
        process.env.ALEXA_LWA_TOKEN_ENC_KEY = require('crypto').randomBytes(32).toString('hex');

        try {
            for (const [key, entry] of alexaState.alexaChangeReportQueue.entries()) {
                if (entry?.timer) clearTimeout(entry.timer);
                alexaState.alexaChangeReportQueue.delete(key);
            }

            const g = makeGateway();
            g.queueAlexaChangeReport(1, 'switch.a');
            g.queueAlexaChangeReport(1, 'switch.b');
            g.queueAlexaChangeReport(2, 'switch.a');

            assert.equal(alexaState.alexaChangeReportQueue.size, 3);
            for (const [, entry] of alexaState.alexaChangeReportQueue.entries()) {
                if (entry?.timer) clearTimeout(entry.timer);
            }
            alexaState.alexaChangeReportQueue.clear();
        } finally {
            if (prevId === undefined) delete process.env.LWA_CLIENT_ID;
            else process.env.LWA_CLIENT_ID = prevId;
            if (prevSec === undefined) delete process.env.LWA_CLIENT_SECRET;
            else process.env.LWA_CLIENT_SECRET = prevSec;
            if (prevKey === undefined) delete process.env.ALEXA_LWA_TOKEN_ENC_KEY;
            else process.env.ALEXA_LWA_TOKEN_ENC_KEY = prevKey;
        }
    });
});

// --- metric markers ---
describe('event gateway metrics', () => {
    it('markMetricSuccess increments sent', () => {
        const before = alexaState.eventGatewayMetrics.change_report.sent;
        gateway.markMetricSuccess('change_report', 'user1', 202);
        assert.equal(alexaState.eventGatewayMetrics.change_report.sent, before + 1);
        assert.equal(alexaState.eventGatewayMetrics.change_report.last_status, 202);
    });

    it('markMetricFailure increments failed', () => {
        const before = alexaState.eventGatewayMetrics.change_report.failed;
        gateway.markMetricFailure('change_report', 'user2', 500, 'internal_error');
        assert.equal(alexaState.eventGatewayMetrics.change_report.failed, before + 1);
        assert.equal(alexaState.eventGatewayMetrics.change_report.last_failure_reason, 'internal_error');
    });

    it('markMetricSkipped increments skipped', () => {
        const before = alexaState.eventGatewayMetrics.add_or_update_report.skipped;
        gateway.markMetricSkipped('add_or_update_report', 'user3', 'no_endpoints');
        assert.equal(alexaState.eventGatewayMetrics.add_or_update_report.skipped, before + 1);
    });

    it('ignores invalid metric type', () => {
        gateway.markMetricSuccess('nonexistent', 'u');
        gateway.markMetricFailure('nonexistent', 'u');
        gateway.markMetricSkipped('nonexistent', 'u');
    });
});

// --- postToAlexaEventGateway with fetch mock ---
describe('postToAlexaEventGateway with mocked fetch', () => {
    function withEnvAndFetch(fn) {
        return async () => {
            const prevFetch = global.fetch;
            const prevId = process.env.LWA_CLIENT_ID;
            const prevSec = process.env.LWA_CLIENT_SECRET;
            const prevKey = process.env.ALEXA_LWA_TOKEN_ENC_KEY;
            process.env.LWA_CLIENT_ID = 'amzn1.application-oa2-client.test';
            process.env.LWA_CLIENT_SECRET = 'secret-secret-secret';
            process.env.ALEXA_LWA_TOKEN_ENC_KEY = require('crypto').randomBytes(32).toString('hex');
            try {
                await fn();
            } finally {
                global.fetch = prevFetch;
                if (prevId === undefined) delete process.env.LWA_CLIENT_ID;
                else process.env.LWA_CLIENT_ID = prevId;
                if (prevSec === undefined) delete process.env.LWA_CLIENT_SECRET;
                else process.env.LWA_CLIENT_SECRET = prevSec;
                if (prevKey === undefined) delete process.env.ALEXA_LWA_TOKEN_ENC_KEY;
                else process.env.ALEXA_LWA_TOKEN_ENC_KEY = prevKey;
            }
        };
    }

    it('returns ok on 202', withEnvAndFetch(async () => {
        // Build encrypted refresh token.
        const alexaCrypto = require('../../lib/alexa/crypto');
        const encRefresh = alexaCrypto.encryptLwaToken('refresh-me');

        const calls = [];
        global.fetch = async (url, init) => {
            calls.push({ url, init });
            if (url.includes('o2/token')) {
                return {
                    ok: true,
                    status: 200,
                    text: async () => JSON.stringify({ access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 3600 })
                };
            }
            return { ok: true, status: 202, text: async () => '' };
        };

        const g = makeGateway({
            dbGet: async () => ({
                user_id: 99,
                lwa_refresh_token_encrypted: encRefresh,
                lwa_access_token_encrypted: null,
                lwa_expires_at: new Date(0).toISOString(),
                lwa_scopes: null
            }),
            dbRun: async () => ({})
        });

        const result = await g.postToAlexaEventGateway(99, { event: { header: {} } });
        assert.equal(result.ok, true);
        assert.equal(result.statusCode, 202);
        assert.ok(calls.length >= 2);
    }));

    it('returns not-ok on 4xx and surfaces status', withEnvAndFetch(async () => {
        const alexaCrypto = require('../../lib/alexa/crypto');
        const encRefresh = alexaCrypto.encryptLwaToken('refresh-me');

        global.fetch = async (url) => {
            if (url.includes('o2/token')) {
                return {
                    ok: true,
                    status: 200,
                    text: async () => JSON.stringify({ access_token: 'a', refresh_token: 'r', expires_in: 3600 })
                };
            }
            return {
                ok: false,
                status: 400,
                text: async () => JSON.stringify({ payload: { message: 'invalid_endpoint' } })
            };
        };

        const g = makeGateway({
            dbGet: async () => ({
                user_id: 99,
                lwa_refresh_token_encrypted: encRefresh,
                lwa_access_token_encrypted: null,
                lwa_expires_at: new Date(0).toISOString()
            }),
            dbRun: async () => ({})
        });

        const result = await g.postToAlexaEventGateway(99, { event: { header: {} } });
        assert.equal(result.ok, false);
        assert.equal(result.statusCode, 400);
        assert.ok(result.error);
    }));

    it('500 failure populates error', withEnvAndFetch(async () => {
        const alexaCrypto = require('../../lib/alexa/crypto');
        const encRefresh = alexaCrypto.encryptLwaToken('r');

        global.fetch = async (url) => {
            if (url.includes('o2/token')) {
                return {
                    ok: true,
                    status: 200,
                    text: async () => JSON.stringify({ access_token: 'a', refresh_token: 'r', expires_in: 3600 })
                };
            }
            return { ok: false, status: 500, text: async () => 'oops' };
        };

        const g = makeGateway({
            dbGet: async () => ({
                user_id: 1,
                lwa_refresh_token_encrypted: encRefresh,
                lwa_access_token_encrypted: null,
                lwa_expires_at: new Date(0).toISOString()
            }),
            dbRun: async () => ({})
        });

        const result = await g.postToAlexaEventGateway(1, {});
        assert.equal(result.ok, false);
        assert.equal(result.statusCode, 500);
    }));
});

// --- LWA refresh ---
describe('fetchValidLwaAccessTokenForUser', () => {
    function withEnvAndFetch(fn) {
        return async () => {
            const prevFetch = global.fetch;
            const prevId = process.env.LWA_CLIENT_ID;
            const prevSec = process.env.LWA_CLIENT_SECRET;
            const prevKey = process.env.ALEXA_LWA_TOKEN_ENC_KEY;
            process.env.LWA_CLIENT_ID = 'amzn1.application-oa2-client.test';
            process.env.LWA_CLIENT_SECRET = 'secret-secret-secret';
            process.env.ALEXA_LWA_TOKEN_ENC_KEY = require('crypto').randomBytes(32).toString('hex');
            try {
                await fn();
            } finally {
                global.fetch = prevFetch;
                if (prevId === undefined) delete process.env.LWA_CLIENT_ID;
                else process.env.LWA_CLIENT_ID = prevId;
                if (prevSec === undefined) delete process.env.LWA_CLIENT_SECRET;
                else process.env.LWA_CLIENT_SECRET = prevSec;
                if (prevKey === undefined) delete process.env.ALEXA_LWA_TOKEN_ENC_KEY;
                else process.env.ALEXA_LWA_TOKEN_ENC_KEY = prevKey;
            }
        };
    }

    it('calls token URL and updates encrypted columns when expired', withEnvAndFetch(async () => {
        const alexaCrypto = require('../../lib/alexa/crypto');
        const encRefresh = alexaCrypto.encryptLwaToken('refresh-me');

        let tokenCalled = false;
        let persistCalled = false;
        global.fetch = async (url) => {
            if (url.includes('o2/token')) {
                tokenCalled = true;
                return {
                    ok: true,
                    status: 200,
                    text: async () =>
                        JSON.stringify({ access_token: 'new-at', refresh_token: 'new-rt', expires_in: 3600 })
                };
            }
            throw new Error('unexpected URL ' + url);
        };

        const g = makeGateway({
            dbGet: async () => ({
                user_id: 7,
                lwa_refresh_token_encrypted: encRefresh,
                lwa_access_token_encrypted: null,
                lwa_expires_at: new Date(Date.now() - 1000).toISOString()
            }),
            dbRun: async (sql) => {
                if (/UPDATE alexa_tokens/i.test(sql)) persistCalled = true;
                return {};
            }
        });

        const result = await g.fetchValidLwaAccessTokenForUser(7);
        assert.equal(result.ok, true);
        assert.equal(result.accessToken, 'new-at');
        assert.equal(tokenCalled, true);
        assert.equal(persistCalled, true);
    }));

    it('uses cached access token when still valid', withEnvAndFetch(async () => {
        const alexaCrypto = require('../../lib/alexa/crypto');
        const encRefresh = alexaCrypto.encryptLwaToken('refresh-me');
        const encAccess = alexaCrypto.encryptLwaToken('cached-at');

        let tokenCalled = false;
        global.fetch = async (url) => {
            if (url.includes('o2/token')) {
                tokenCalled = true;
                return { ok: true, status: 200, text: async () => '{}' };
            }
            throw new Error('unexpected');
        };

        const g = makeGateway({
            dbGet: async () => ({
                user_id: 8,
                lwa_refresh_token_encrypted: encRefresh,
                lwa_access_token_encrypted: encAccess,
                lwa_expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString()
            })
        });

        const result = await g.fetchValidLwaAccessTokenForUser(8);
        assert.equal(result.ok, true);
        assert.equal(result.accessToken, 'cached-at');
        assert.equal(tokenCalled, false);
    }));

    it('skips when no LWA tokens persisted for user', withEnvAndFetch(async () => {
        const g = makeGateway({ dbGet: async () => null });
        const result = await g.fetchValidLwaAccessTokenForUser(10);
        assert.equal(result.ok, false);
        assert.equal(result.skipped, true);
    }));
});
