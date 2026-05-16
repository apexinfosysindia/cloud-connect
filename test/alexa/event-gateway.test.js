/**
 * lib/alexa/event-gateway.js — proactive ChangeReport delivery.
 *
 * The unit tests inject:
 *   - fetchImpl   : a stub matching the bits of fetch we use
 *   - now         : a deterministic clock
 *   - lwaCrypto   : pass-through (no real encryption)
 *   - alexaCore   : a tiny stub returning a chosen token row
 *   - entityMapping: the real factory (we want its actual output shape)
 *
 * That gives us deterministic coverage of every reason code in the
 * sendChangeReport contract without bringing up sqlite or the network.
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const sqlite3 = require('sqlite3').verbose();
const createDbHelpers = require('../../lib/db-helpers');
const entityMappingFactory = require('../../lib/alexa/entity-mapping');
const eventGatewayFactory = require('../../lib/alexa/event-gateway');
const { buildChangeReportEvent } = require('../../lib/alexa/event-gateway')._pure;

const entityMapping = entityMappingFactory();

function row(overrides = {}) {
    return {
        id: 1,
        user_id: 1,
        device_id: 1,
        entity_id: 'switch.kitchen',
        display_name: 'Kitchen',
        entity_type: 'switch',
        exposed: 1,
        online: 1,
        state_json: JSON.stringify({ state: 'on', attributes: {} }),
        ...overrides
    };
}

// Minimal fetch double — supports `.ok`, `.status`, `.json()`, `.text()`.
function fakeResponse({ ok = true, status = 200, json = null, text = '' } = {}) {
    return {
        ok,
        status,
        json: async () => json,
        text: async () => text
    };
}

function fakeFetch(handlers) {
    // handlers: { [url]: (init) => Response | Promise<Response> }
    const calls = [];
    async function impl(url, init) {
        calls.push({ url, init });
        const handler = handlers[url];
        if (!handler) throw new Error(`fakeFetch: no handler for ${url}`);
        return await handler(init);
    }
    impl.calls = calls;
    return impl;
}

// ─── buildChangeReportEvent (pure) ─────────────────────────────────────────

describe('buildChangeReportEvent', () => {
    it('builds an envelope with bearer token, encoded endpointId, and split change/context', () => {
        const ev = buildChangeReportEvent({
            entity: row({ entity_id: 'light.kitchen', state_json: JSON.stringify({ state: 'on', attributes: { brightness: 255 } }) }),
            entityMapping,
            accessToken: 'tok-123'
        });
        assert.equal(ev.event.header.namespace, 'Alexa');
        assert.equal(ev.event.header.name, 'ChangeReport');
        assert.equal(ev.event.header.payloadVersion, '3');
        assert.equal(ev.event.endpoint.endpointId, 'light__kitchen');
        assert.equal(ev.event.endpoint.scope.type, 'BearerToken');
        assert.equal(ev.event.endpoint.scope.token, 'tok-123');
        assert.equal(ev.event.endpoint.cookie.ha_entity_id, 'light.kitchen');
        // The trigger property goes in change.properties, NOT context.
        const changed = ev.event.payload.change.properties[0];
        assert.notEqual(changed.namespace, 'Alexa.EndpointHealth', 'trigger should be the real state change, not connectivity');
        // Context carries everything else (e.g. EndpointHealth).
        const ctxNs = ev.context.properties.map((p) => p.namespace);
        assert.ok(ctxNs.includes('Alexa.EndpointHealth'), 'context must carry connectivity');
    });

    it('returns null for out-of-scope domain (no reportable properties)', () => {
        const ev = buildChangeReportEvent({
            entity: row({ entity_id: 'fan.bedroom' }),
            entityMapping,
            accessToken: 'tok-123'
        });
        assert.equal(ev, null);
    });
});

// ─── getValidAccessTokenForUser ────────────────────────────────────────────

describe('getValidAccessTokenForUser', () => {
    let db, helpers, prevClientId, prevClientSecret;
    beforeEach(async () => {
        db = new sqlite3.Database(':memory:');
        helpers = createDbHelpers(db);
        await new Promise((r) => {
            db.exec(
                `CREATE TABLE alexa_tokens (
                    user_id INTEGER PRIMARY KEY,
                    lwa_access_token_encrypted TEXT,
                    lwa_refresh_token_encrypted TEXT,
                    lwa_expires_at DATETIME,
                    updated_at DATETIME
                );`,
                () => r()
            );
        });
        prevClientId = process.env.ALEXA_LWA_CLIENT_ID;
        prevClientSecret = process.env.ALEXA_LWA_CLIENT_SECRET;
        process.env.ALEXA_LWA_CLIENT_ID = 'cid';
        process.env.ALEXA_LWA_CLIENT_SECRET = 'csec';
    });
    afterEach(() => {
        db.close();
        process.env.ALEXA_LWA_CLIENT_ID = prevClientId;
        process.env.ALEXA_LWA_CLIENT_SECRET = prevClientSecret;
    });

    function makeGw({ tokensRow, fetchHandlers, currentMs = 1_000_000 }) {
        const lwaCrypto = { encryptLwaToken: (x) => x, decryptLwaToken: (x) => x };
        const alexaCore = {
            async getDecryptedLwaTokensForUser(_uid) {
                if (!tokensRow) return null;
                return {
                    accessToken: tokensRow.lwa_access_token_encrypted,
                    refreshToken: tokensRow.lwa_refresh_token_encrypted,
                    expiresAt: tokensRow.lwa_expires_at,
                    scopes: null
                };
            }
        };
        return eventGatewayFactory({
            dbGet: helpers.dbGet,
            dbRun: helpers.dbRun,
            alexaCore,
            lwaCrypto,
            entityMapping,
            config: { ALEXA_EVENT_GATEWAY_AUTO_START: false },
            fetchImpl: fakeFetch(fetchHandlers || {}),
            now: () => currentMs
        });
    }

    it('returns the in-cache access token when not yet expired', async () => {
        const future = new Date(2_000_000_000_000).toISOString();
        const gw = makeGw({
            tokensRow: { lwa_access_token_encrypted: 'live-tok', lwa_refresh_token_encrypted: 'r', lwa_expires_at: future },
            currentMs: 1_000_000
        });
        const tok = await gw.getValidAccessTokenForUser(1);
        assert.equal(tok, 'live-tok');
    });

    it('refreshes against LWA when expired and persists the new pair', async () => {
        await helpers.dbRun(
            `INSERT INTO alexa_tokens (user_id, lwa_access_token_encrypted, lwa_refresh_token_encrypted, lwa_expires_at)
             VALUES (1, 'old', 'r-old', '2020-01-01T00:00:00Z')`
        );
        const handlers = {
            'https://api.amazon.com/auth/o2/token': () =>
                fakeResponse({ ok: true, status: 200, json: { access_token: 'NEW-AT', refresh_token: 'NEW-RT', expires_in: 3600 } })
        };
        const gw = makeGw({
            tokensRow: { lwa_access_token_encrypted: 'old', lwa_refresh_token_encrypted: 'r-old', lwa_expires_at: '2020-01-01T00:00:00Z' },
            fetchHandlers: handlers,
            currentMs: 1_700_000_000_000
        });
        const tok = await gw.getValidAccessTokenForUser(1);
        assert.equal(tok, 'NEW-AT');
        const persisted = await helpers.dbGet(`SELECT * FROM alexa_tokens WHERE user_id = 1`);
        assert.equal(persisted.lwa_access_token_encrypted, 'NEW-AT');
        assert.equal(persisted.lwa_refresh_token_encrypted, 'NEW-RT');
        // expiry must be ~now + 3600s
        const expMs = new Date(persisted.lwa_expires_at).getTime();
        assert.ok(expMs > 1_700_000_000_000 && expMs <= 1_700_000_000_000 + 3601_000);
    });

    it('throws if user has no LWA tokens (unlinked)', async () => {
        const gw = makeGw({ tokensRow: null });
        await assert.rejects(() => gw.getValidAccessTokenForUser(1), /unlinked/);
    });

    it('throws if LWA refresh returns non-2xx — never silently keeps using the old token', async () => {
        const handlers = {
            'https://api.amazon.com/auth/o2/token': () => fakeResponse({ ok: false, status: 400, text: 'invalid_grant' })
        };
        const gw = makeGw({
            tokensRow: { lwa_access_token_encrypted: 'old', lwa_refresh_token_encrypted: 'r-old', lwa_expires_at: '2020-01-01T00:00:00Z' },
            fetchHandlers: handlers,
            currentMs: 1_700_000_000_000
        });
        await assert.rejects(() => gw.getValidAccessTokenForUser(1), /HTTP 400/);
    });

    it('throws when LWA refresh returns 200 but no access_token (defensive)', async () => {
        const handlers = {
            'https://api.amazon.com/auth/o2/token': () => fakeResponse({ ok: true, status: 200, json: { /* no access_token */ } })
        };
        const gw = makeGw({
            tokensRow: { lwa_access_token_encrypted: 'old', lwa_refresh_token_encrypted: 'r-old', lwa_expires_at: '2020-01-01T00:00:00Z' },
            fetchHandlers: handlers,
            currentMs: 1_700_000_000_000
        });
        await assert.rejects(() => gw.getValidAccessTokenForUser(1), /no access_token/);
    });
});

// ─── sendChangeReportForEntity (end-to-end, never throws) ──────────────────

describe('sendChangeReportForEntity', () => {
    function makeGw({ accessToken = 'tok', getThrows = null, fetchHandlers = {} } = {}) {
        const alexaCore = {
            async getDecryptedLwaTokensForUser(_uid) {
                if (getThrows === 'unlinked') return null;
                if (getThrows === 'refresh') {
                    return { accessToken: null, refreshToken: 'r', expiresAt: '2020-01-01T00:00:00Z', scopes: null };
                }
                return {
                    accessToken,
                    refreshToken: 'r',
                    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
                    scopes: null
                };
            }
        };
        return eventGatewayFactory({
            dbGet: async () => null,
            dbRun: async () => ({}),
            alexaCore,
            lwaCrypto: { encryptLwaToken: (x) => x, decryptLwaToken: (x) => x },
            entityMapping,
            config: { ALEXA_EVENT_GATEWAY_AUTO_START: false },
            fetchImpl: fakeFetch(fetchHandlers)
        });
    }

    it('returns ok=true on a 202 from the gateway', async () => {
        const handlers = {
            'https://api.amazonalexa.com/v3/events': () => fakeResponse({ ok: true, status: 202 })
        };
        const gw = makeGw({ fetchHandlers: handlers });
        const out = await gw.sendChangeReportForEntity(row());
        assert.deepEqual(out, { ok: true, statusCode: 202 });
    });

    it('returns ok=false reason=unlinked when user has no tokens', async () => {
        const gw = makeGw({ getThrows: 'unlinked' });
        const out = await gw.sendChangeReportForEntity(row());
        assert.equal(out.ok, false);
        assert.equal(out.reason, 'unlinked');
    });

    it('returns ok=false reason=lwa_refresh_failed when refresh blows up', async () => {
        const prev = process.env.ALEXA_LWA_CLIENT_ID;
        process.env.ALEXA_LWA_CLIENT_ID = '';
        const gw = makeGw({ getThrows: 'refresh' });
        const out = await gw.sendChangeReportForEntity(row());
        assert.equal(out.ok, false);
        assert.equal(out.reason, 'lwa_refresh_failed');
        process.env.ALEXA_LWA_CLIENT_ID = prev;
    });

    it('returns ok=false reason=no_properties for out-of-scope entity', async () => {
        const gw = makeGw();
        const out = await gw.sendChangeReportForEntity(row({ entity_id: 'fan.bedroom' }));
        assert.equal(out.reason, 'no_properties');
    });

    it('returns gateway_error with status code when Alexa rejects', async () => {
        const handlers = {
            'https://api.amazonalexa.com/v3/events': () => fakeResponse({ ok: false, status: 401, text: 'TOKEN_INVALID' })
        };
        const gw = makeGw({ fetchHandlers: handlers });
        const out = await gw.sendChangeReportForEntity(row());
        assert.equal(out.ok, false);
        assert.equal(out.reason, 'gateway_error');
        assert.equal(out.statusCode, 401);
    });

    it('returns network_error when fetch throws', async () => {
        const fetchImpl = async () => {
            throw new Error('ECONNRESET');
        };
        const alexaCore = {
            async getDecryptedLwaTokensForUser() {
                return {
                    accessToken: 'tok',
                    refreshToken: 'r',
                    expiresAt: new Date(Date.now() + 3_600_000).toISOString()
                };
            }
        };
        const gw = eventGatewayFactory({
            dbGet: async () => null,
            dbRun: async () => ({}),
            alexaCore,
            lwaCrypto: { encryptLwaToken: (x) => x, decryptLwaToken: (x) => x },
            entityMapping,
            config: { ALEXA_EVENT_GATEWAY_AUTO_START: false },
            fetchImpl
        });
        const out = await gw.sendChangeReportForEntity(row());
        assert.equal(out.reason, 'network_error');
    });
});

// ─── Debounced scheduler ──────────────────────────────────────────────────

describe('scheduleChangeReportForEntity / flushScheduledChangeReports', () => {
    function makeGw({ now }) {
        const alexaCore = {
            async getDecryptedLwaTokensForUser() {
                return {
                    accessToken: 'tok',
                    refreshToken: 'r',
                    expiresAt: new Date(now() + 3_600_000).toISOString()
                };
            }
        };
        const handlers = {
            'https://api.amazonalexa.com/v3/events': () => fakeResponse({ ok: true, status: 202 })
        };
        const fetchImpl = fakeFetch(handlers);
        const gw = eventGatewayFactory({
            dbGet: async () => null,
            dbRun: async () => ({}),
            alexaCore,
            lwaCrypto: { encryptLwaToken: (x) => x, decryptLwaToken: (x) => x },
            entityMapping,
            config: { ALEXA_EVENT_GATEWAY_AUTO_START: false },
            fetchImpl,
            now,
            debounceMs: 1500
        });
        return { gw, fetchImpl };
    }

    it('coalesces repeated schedules for the same (user, entity) into one POST', async () => {
        let t = 1_000_000;
        const { gw, fetchImpl } = makeGw({ now: () => t });
        const e = row();
        gw.scheduleChangeReportForEntity(e);
        gw.scheduleChangeReportForEntity(e);
        gw.scheduleChangeReportForEntity(e);
        assert.equal(gw._queueSize(), 1);
        // Advance past debounce
        t += 2000;
        await gw.flushScheduledChangeReports();
        assert.equal(fetchImpl.calls.length, 1, 'should POST exactly once for three coalesced schedules');
        assert.equal(gw._queueSize(), 0);
    });

    it('does not flush entries that are not yet due', async () => {
        const t = 1_000_000;
        const { gw, fetchImpl } = makeGw({ now: () => t });
        gw.scheduleChangeReportForEntity(row());
        // Don't advance time
        await gw.flushScheduledChangeReports();
        assert.equal(fetchImpl.calls.length, 0);
        assert.equal(gw._queueSize(), 1);
    });

    it('keeps separate entries per (user, entity) pair', async () => {
        let t = 1_000_000;
        const { gw, fetchImpl } = makeGw({ now: () => t });
        gw.scheduleChangeReportForEntity(row({ user_id: 1, entity_id: 'switch.a' }));
        gw.scheduleChangeReportForEntity(row({ user_id: 1, entity_id: 'switch.b' }));
        gw.scheduleChangeReportForEntity(row({ user_id: 2, entity_id: 'switch.a' }));
        assert.equal(gw._queueSize(), 3);
        t += 2000;
        await gw.flushScheduledChangeReports();
        assert.equal(fetchImpl.calls.length, 3);
    });

    it('one user failure does not abort the loop for other users', async () => {
        let t = 1_000_000;
        // First call returns 500, second returns 202.
        const responses = [
            fakeResponse({ ok: false, status: 500, text: 'boom' }),
            fakeResponse({ ok: true, status: 202 })
        ];
        const fetchImpl = async () => responses.shift();
        fetchImpl.calls = []; // shape parity with fakeFetch; not used here
        const alexaCore = {
            async getDecryptedLwaTokensForUser() {
                return {
                    accessToken: 'tok',
                    refreshToken: 'r',
                    expiresAt: new Date(t + 3_600_000).toISOString()
                };
            }
        };
        const gw = eventGatewayFactory({
            dbGet: async () => null,
            dbRun: async () => ({}),
            alexaCore,
            lwaCrypto: { encryptLwaToken: (x) => x, decryptLwaToken: (x) => x },
            entityMapping,
            config: { ALEXA_EVENT_GATEWAY_AUTO_START: false },
            fetchImpl,
            now: () => t,
            debounceMs: 1500
        });
        const origWarn = console.warn;
        console.warn = () => {}; // keep test output clean
        gw.scheduleChangeReportForEntity(row({ user_id: 1 }));
        gw.scheduleChangeReportForEntity(row({ user_id: 2 }));
        t += 2000;
        await gw.flushScheduledChangeReports();
        console.warn = origWarn;
        // Both processed and queue drained, regardless of one having failed.
        assert.equal(gw._queueSize(), 0);
        assert.equal(responses.length, 0, 'both fetches consumed');
    });
});

// ─── getHealthSnapshot ─────────────────────────────────────────────────────
//
// Counters drive the admin /api/admin/alexa/health endpoint. We verify them
// at the gateway layer so the wire-level test can stay focused on the JSON
// shape, not on coverage of every reason code.

describe('getHealthSnapshot', () => {
    function makeGw({ accessToken = 'tok', fetchHandlers = {}, getThrows = null } = {}) {
        const alexaCore = {
            async getDecryptedLwaTokensForUser() {
                if (getThrows === 'unlinked') return null;
                return {
                    accessToken,
                    refreshToken: 'r',
                    expiresAt: new Date(Date.now() + 3_600_000).toISOString()
                };
            }
        };
        return eventGatewayFactory({
            dbGet: async () => null,
            dbRun: async () => ({}),
            alexaCore,
            lwaCrypto: { encryptLwaToken: (x) => x, decryptLwaToken: (x) => x },
            entityMapping,
            config: { ALEXA_EVENT_GATEWAY_AUTO_START: false },
            fetchImpl: fakeFetch(fetchHandlers)
        });
    }

    it('returns startedAt + zero counters before any dispatch', () => {
        const gw = makeGw();
        const snap = gw.getHealthSnapshot();
        assert.ok(snap.startedAt, 'startedAt must be set');
        assert.equal(snap.queueDepth, 0);
        assert.deepEqual(snap.counters, {});
    });

    it('increments ok counter on successful dispatch', async () => {
        const handlers = {
            'https://api.amazonalexa.com/v3/events': () => fakeResponse({ ok: true, status: 202 })
        };
        const gw = makeGw({ fetchHandlers: handlers });
        await gw.sendChangeReportForEntity(row());
        await gw.sendChangeReportForEntity(row());
        const snap = gw.getHealthSnapshot();
        assert.equal(snap.counters.ok.count, 2);
        assert.ok(snap.counters.ok.firstAt);
        assert.ok(snap.counters.ok.lastAt);
    });

    it('increments distinct counters for distinct reasons', async () => {
        const handlers = {
            'https://api.amazonalexa.com/v3/events': () => fakeResponse({ ok: false, status: 401, text: 'TOKEN' })
        };
        const gw = makeGw({ fetchHandlers: handlers });
        await gw.sendChangeReportForEntity(row()); // gateway_error
        await gw.sendChangeReportForEntity(row({ entity_id: 'fan.bedroom' })); // no_properties
        const unlinkedGw = makeGw({ getThrows: 'unlinked' });
        await unlinkedGw.sendChangeReportForEntity(row());

        const snap = gw.getHealthSnapshot();
        assert.equal(snap.counters.gateway_error.count, 1);
        assert.equal(snap.counters.no_properties.count, 1);
        assert.equal(snap.counters.ok, undefined);

        const unlinkedSnap = unlinkedGw.getHealthSnapshot();
        assert.equal(unlinkedSnap.counters.unlinked.count, 1);
    });

    it('queueDepth reflects pending scheduled entries', () => {
        const gw = makeGw();
        gw.scheduleChangeReportForEntity(row({ entity_id: 'switch.a' }));
        gw.scheduleChangeReportForEntity(row({ entity_id: 'switch.b' }));
        assert.equal(gw.getHealthSnapshot().queueDepth, 2);
    });
});

// ─── previewChangeReportForEntity (dry-run) ────────────────────────────────
//
// Sister of buildChangeReportEvent + sendChangeReportForEntity. Used by the
// admin diagnostic endpoint during Phase 9 bring-up. Critical invariants:
//
//   - never makes a network call
//   - never mints a real LWA access token (otherwise an operator running
//     this in a loop would invalidate the user's live refresh tokens
//     through the rotation path)
//   - never increments the health counters (it is not a dispatch)

describe('previewChangeReportForEntity / previewChangeReportForUserEntity', () => {
    function makeGw({ entityRow = null } = {}) {
        let lwaCalls = 0;
        const alexaCore = {
            async getDecryptedLwaTokensForUser() {
                lwaCalls += 1;
                return null;
            }
        };
        let fetchCalls = 0;
        const fetchImpl = async () => {
            fetchCalls += 1;
            throw new Error('fetch must not be called from preview path');
        };
        const gw = eventGatewayFactory({
            dbGet: async () => entityRow,
            dbRun: async () => ({}),
            alexaCore,
            lwaCrypto: { encryptLwaToken: (x) => x, decryptLwaToken: (x) => x },
            entityMapping,
            config: { ALEXA_EVENT_GATEWAY_AUTO_START: false },
            fetchImpl
        });
        return { gw, getCounts: () => ({ lwaCalls, fetchCalls }) };
    }

    it('returns the same envelope shape as the real dispatch path', () => {
        const { gw } = makeGw();
        const out = gw.previewChangeReportForEntity(row({ entity_id: 'light.kitchen' }));
        assert.equal(out.ok, true);
        assert.equal(out.event.header.name, 'ChangeReport');
        assert.equal(out.event.endpoint.endpointId, 'light__kitchen');
        assert.equal(out.event.endpoint.cookie.ha_entity_id, 'light.kitchen');
        // Context still carries the non-trigger properties (e.g. EndpointHealth).
        assert.ok(Array.isArray(out.context.properties));
    });

    it('uses a placeholder bearer, not a real access token', () => {
        const { gw, getCounts } = makeGw();
        const out = gw.previewChangeReportForEntity(row());
        assert.equal(out.event.endpoint.scope.type, 'BearerToken');
        assert.equal(out.event.endpoint.scope.token, '<dry-run-placeholder>');
        // And critically: LWA was never asked for tokens, fetch never called.
        assert.equal(getCounts().lwaCalls, 0);
        assert.equal(getCounts().fetchCalls, 0);
    });

    it('reason=no_properties for out-of-scope domain (matches real path)', () => {
        const { gw } = makeGw();
        const out = gw.previewChangeReportForEntity(row({ entity_id: 'fan.bedroom' }));
        assert.equal(out.ok, false);
        assert.equal(out.reason, 'no_properties');
    });

    it('reason=no_entity when entity is null/undefined', () => {
        const { gw } = makeGw();
        assert.equal(gw.previewChangeReportForEntity(null).reason, 'no_entity');
        assert.equal(gw.previewChangeReportForEntity(undefined).reason, 'no_entity');
    });

    it('does NOT increment health counters (preview is not a dispatch)', () => {
        const { gw } = makeGw();
        gw.previewChangeReportForEntity(row());
        gw.previewChangeReportForEntity(row({ entity_id: 'fan.bedroom' }));
        const snap = gw.getHealthSnapshot();
        assert.deepEqual(snap.counters, {});
    });

    it('previewForUserEntity returns entity_not_found when row is missing', async () => {
        const { gw } = makeGw({ entityRow: null });
        const out = await gw.previewChangeReportForUserEntity(1, 'light.kitchen');
        assert.equal(out.ok, false);
        assert.equal(out.reason, 'entity_not_found');
    });

    it('previewForUserEntity loads via dbGet and returns the envelope', async () => {
        const entityRow = row({ entity_id: 'light.bedroom' });
        const { gw } = makeGw({ entityRow });
        const out = await gw.previewChangeReportForUserEntity(1, 'light.bedroom');
        assert.equal(out.ok, true);
        assert.equal(out.event.endpoint.endpointId, 'light__bedroom');
    });
});
