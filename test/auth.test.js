const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const config = require('../lib/config');
const utils = require('../lib/utils');

// Set required env vars for auth testing
const TEST_PORTAL_SECRET = 'a'.repeat(64);
const TEST_ADMIN_SECRET = 'b'.repeat(64);
const savedPortalSecret = process.env.PORTAL_SESSION_SECRET;
const savedAdminSecret = process.env.ADMIN_SESSION_SECRET;
const savedAdminEmail = process.env.ADMIN_EMAIL;
const savedAdminPasswordHash = process.env.ADMIN_PASSWORD_HASH;

before(() => {
    process.env.PORTAL_SESSION_SECRET = TEST_PORTAL_SECRET;
    process.env.ADMIN_SESSION_SECRET = TEST_ADMIN_SECRET;
    process.env.ADMIN_EMAIL = 'admin@test.com';
    process.env.ADMIN_PASSWORD_HASH = '$2a$10$fakehashfortest';
});

const auth = require('../lib/auth')({ dbGet: async () => null, config, utils });

describe('getPortalSecret', () => {
    it('returns the configured secret', () => {
        assert.equal(auth.getPortalSecret(), TEST_PORTAL_SECRET);
    });

    it('throws when secret is too short', () => {
        const saved = process.env.PORTAL_SESSION_SECRET;
        process.env.PORTAL_SESSION_SECRET = 'short';
        assert.throws(() => auth.getPortalSecret(), /at least 32 characters/);
        process.env.PORTAL_SESSION_SECRET = saved;
    });
});

describe('getAdminSecret', () => {
    it('returns the configured secret', () => {
        assert.equal(auth.getAdminSecret(), TEST_ADMIN_SECRET);
    });
});

describe('portal session token round-trip', () => {
    it('creates and verifies a token', () => {
        const token = auth.createPortalSessionToken('user@example.com');
        assert.ok(typeof token === 'string');
        assert.ok(utils.hasExactlyOneDot(token));

        const decoded = auth.verifyPortalSessionToken(token);
        assert.ok(decoded);
        assert.equal(decoded.email, 'user@example.com');
        assert.ok(decoded.exp > Date.now());
    });

    it('rejects a tampered token', () => {
        const token = auth.createPortalSessionToken('user@example.com');
        const [payload] = token.split('.');
        const tampered = `${payload}.invalidsignature`;
        assert.equal(auth.verifyPortalSessionToken(tampered), null);
    });

    it('rejects null/empty', () => {
        assert.equal(auth.verifyPortalSessionToken(null), null);
        assert.equal(auth.verifyPortalSessionToken(''), null);
    });

    it('rejects token without dot', () => {
        assert.equal(auth.verifyPortalSessionToken('nodottoken'), null);
    });
});

describe('pickValidPortalToken', () => {
    const cookieUser = 'cookie-account@example.com';
    const explicitUser = 'dashboard-account@example.com';

    it('prefers the explicit token when BOTH are valid but name different accounts', () => {
        // The hijack case. A previous login for cookieUser is still in the jar while
        // the page is acting as explicitUser. The cookie must not win, or the request
        // (account linking, entity reads, account mutations) lands on the wrong user.
        const cookie = auth.createPortalSessionToken(cookieUser);
        const explicit = auth.createPortalSessionToken(explicitUser);

        const picked = auth.pickValidPortalToken(cookie, explicit);
        assert.equal(picked.token, explicit);
        assert.equal(picked.session.email, explicitUser);
    });

    it('falls back to a valid cookie when no explicit token is supplied', () => {
        const cookie = auth.createPortalSessionToken(cookieUser);
        for (const explicit of ['', null, undefined, '   ']) {
            const picked = auth.pickValidPortalToken(cookie, explicit);
            assert.equal(picked.token, cookie);
            assert.equal(picked.session.email, cookieUser);
        }
    });

    it('uses a valid explicit token even when the cookie is garbage', () => {
        // The linking-loop case: a stale cookie must not shadow a good token.
        const explicit = auth.createPortalSessionToken(explicitUser);
        const picked = auth.pickValidPortalToken('stale.garbage', explicit);
        assert.equal(picked.token, explicit);
        assert.equal(picked.session.email, explicitUser);
    });

    it('uses a valid cookie when the explicit token is garbage', () => {
        // Both candidates are verified, so an unusable explicit token cannot lock
        // out a working browser session.
        const cookie = auth.createPortalSessionToken(cookieUser);
        const picked = auth.pickValidPortalToken(cookie, 'bad.token');
        assert.equal(picked.token, cookie);
        assert.equal(picked.session.email, cookieUser);
    });

    it('reports no session but keeps a non-empty token when neither verifies', () => {
        // Callers distinguish "no token supplied" (400) from "token rejected" (401).
        // Returning '' here would turn every rejection into the wrong error.
        const picked = auth.pickValidPortalToken('bad.cookie', 'bad.explicit');
        assert.equal(picked.session, null);
        assert.equal(picked.token, 'bad.explicit');

        const cookieOnly = auth.pickValidPortalToken('bad.cookie', '');
        assert.equal(cookieOnly.session, null);
        assert.equal(cookieOnly.token, 'bad.cookie');
    });

    it('returns an empty token only when nothing at all was supplied', () => {
        for (const [cookie, explicit] of [
            ['', ''],
            [null, undefined],
            ['  ', '\t']
        ]) {
            const picked = auth.pickValidPortalToken(cookie, explicit);
            assert.equal(picked.token, '');
            assert.equal(picked.session, null);
        }
    });

    it('ignores non-string inputs instead of throwing', () => {
        const picked = auth.pickValidPortalToken({ token: 'x' }, 42);
        assert.equal(picked.token, '');
        assert.equal(picked.session, null);
    });
});

describe('requirePortalUser token precedence', () => {
    const cookieUser = { id: 1, email: 'cookie-account@example.com', session_epoch: 0 };
    const explicitUser = { id: 19, email: 'dashboard-account@example.com', session_epoch: 0 };

    // A fresh auth instance whose dbGet resolves the two seeded users, so we can
    // assert WHICH account the middleware attaches to the request.
    const usersByEmail = new Map([
        [cookieUser.email, cookieUser],
        [explicitUser.email, explicitUser]
    ]);
    const scopedAuth = require('../lib/auth')({
        dbGet: async (_sql, [email]) => usersByEmail.get(email) || null,
        config,
        utils
    });

    function req({ cookie, body, query, bearer }) {
        return {
            get: (name) => (name.toLowerCase() === 'authorization' && bearer ? `Bearer ${bearer}` : ''),
            cookies: cookie ? { [config.PORTAL_SESSION_COOKIE_NAME]: cookie } : {},
            body: body || {},
            query: query || {}
        };
    }

    function res() {
        return {
            statusCode: 0,
            payload: null,
            status(code) {
                this.statusCode = code;
                return this;
            },
            json(payload) {
                this.payload = payload;
                return this;
            }
        };
    }

    it('resolves to the body token, not a still-valid cookie for another account', async () => {
        const request = req({
            cookie: scopedAuth.createPortalSessionToken(cookieUser.email),
            body: { portal_session_token: scopedAuth.createPortalSessionToken(explicitUser.email) }
        });
        let nextCalled = false;
        await scopedAuth.requirePortalUser(request, res(), () => {
            nextCalled = true;
        });

        assert.ok(nextCalled);
        assert.equal(request.portalUser.id, explicitUser.id);
        assert.equal(request.portalSession.email, explicitUser.email);
    });

    it('resolves to the query token over a cookie for another account', async () => {
        const request = req({
            cookie: scopedAuth.createPortalSessionToken(cookieUser.email),
            query: { portal_session_token: scopedAuth.createPortalSessionToken(explicitUser.email) }
        });
        await scopedAuth.requirePortalUser(request, res(), () => {});
        assert.equal(request.portalUser.id, explicitUser.id);
    });

    it('resolves to the bearer token over a cookie for another account', async () => {
        const request = req({
            cookie: scopedAuth.createPortalSessionToken(cookieUser.email),
            bearer: scopedAuth.createPortalSessionToken(explicitUser.email)
        });
        await scopedAuth.requirePortalUser(request, res(), () => {});
        assert.equal(request.portalUser.id, explicitUser.id);
    });

    it('still accepts a cookie-only session', async () => {
        const request = req({ cookie: scopedAuth.createPortalSessionToken(cookieUser.email) });
        await scopedAuth.requirePortalUser(request, res(), () => {});
        assert.equal(request.portalUser.id, cookieUser.id);
    });

    it('falls back to the cookie when the explicit token is garbage', async () => {
        const request = req({
            cookie: scopedAuth.createPortalSessionToken(cookieUser.email),
            body: { portal_session_token: 'bad.token' }
        });
        await scopedAuth.requirePortalUser(request, res(), () => {});
        assert.equal(request.portalUser.id, cookieUser.id);
    });

    it('rejects an unverifiable token as invalid, not as missing', async () => {
        const response = res();
        let nextCalled = false;
        await scopedAuth.requirePortalUser(req({ cookie: 'bad.cookie' }), response, () => {
            nextCalled = true;
        });
        assert.equal(nextCalled, false);
        assert.equal(response.statusCode, 401);
        assert.match(response.payload.error, /Invalid portal session/);
    });

    it('reports a missing token when nothing is supplied', async () => {
        const response = res();
        await scopedAuth.requirePortalUser(req({}), response, () => {});
        assert.equal(response.statusCode, 401);
        assert.match(response.payload.error, /required/);
    });
});

describe('admin token round-trip', () => {
    it('creates and verifies an admin token', () => {
        const token = auth.createAdminToken('admin@test.com');
        const decoded = auth.verifyAdminToken(token);
        assert.ok(decoded);
        assert.equal(decoded.email, 'admin@test.com');
    });

    it('rejects tampered admin token', () => {
        const token = auth.createAdminToken('admin@test.com');
        const [payload] = token.split('.');
        assert.equal(auth.verifyAdminToken(`${payload}.badsig`), null);
    });
});

describe('signPortalValue', () => {
    it('returns consistent HMAC-SHA256 hex', () => {
        const sig1 = auth.signPortalValue('test');
        const sig2 = auth.signPortalValue('test');
        assert.equal(sig1, sig2);
        assert.equal(sig1.length, 64);
    });

    it('different values produce different signatures', () => {
        assert.notEqual(auth.signPortalValue('a'), auth.signPortalValue('b'));
    });
});

describe('serializeUser', () => {
    const activeUser = {
        id: 1,
        email: 'user@test.com',
        subdomain: 'mycloud',
        access_token: 'token123',
        status: 'active',
        google_home_enabled: 1,
        google_home_linked: 0,
        trial_ends_at: null,
        trial_approved_at: null,
        activated_at: '2024-01-01'
    };

    it('includes access_token for active users', () => {
        const result = auth.serializeUser(activeUser);
        assert.equal(result.access_token, 'token123');
        assert.equal(result.status, 'active');
        assert.equal(result.payment_pending, false);
        assert.ok(result.domain.includes('mycloud'));
    });

    it('excludes access_token for payment_pending users', () => {
        const result = auth.serializeUser({ ...activeUser, status: 'payment_pending' });
        assert.equal(result.access_token, null);
        assert.equal(result.payment_pending, true);
    });

    it('domain is null when subdomain is empty', () => {
        const result = auth.serializeUser({ ...activeUser, subdomain: '' });
        assert.equal(result.domain, null);
    });

    it('google_home fields are boolean', () => {
        const result = auth.serializeUser(activeUser);
        assert.equal(result.google_home_enabled, true);
        assert.equal(result.google_home_linked, false);
    });
});

describe('serializeAdminUser', () => {
    it('includes razorpay fields', () => {
        const user = {
            id: 1,
            email: 'u@t.com',
            subdomain: 'sub',
            status: 'active',
            access_token: 'tok',
            razorpay_customer_id: 'cust_1',
            razorpay_subscription_id: 'sub_1',
            razorpay_payment_id: 'pay_1',
            razorpay_subscription_status: 'active',
            trial_ends_at: null,
            trial_approved_at: null,
            activated_at: null,
            created_at: '2024-01-01'
        };
        const result = auth.serializeAdminUser(user);
        assert.equal(result.razorpay_customer_id, 'cust_1');
        assert.ok(result.domain);
    });
});

describe('ensureBillingConfigured', () => {
    it('throws when razorpay env vars not set', () => {
        const saved = {
            key: process.env.RAZORPAY_KEY_ID,
            secret: process.env.RAZORPAY_KEY_SECRET,
            plan: process.env.RAZORPAY_PLAN_ID
        };
        delete process.env.RAZORPAY_KEY_ID;
        delete process.env.RAZORPAY_KEY_SECRET;
        delete process.env.RAZORPAY_PLAN_ID;

        assert.throws(() => auth.ensureBillingConfigured(), /not configured/);

        if (saved.key) process.env.RAZORPAY_KEY_ID = saved.key;
        if (saved.secret) process.env.RAZORPAY_KEY_SECRET = saved.secret;
        if (saved.plan) process.env.RAZORPAY_PLAN_ID = saved.plan;
    });
});

describe('ensureAdminConfigured', () => {
    it('does not throw when env vars are set', () => {
        assert.doesNotThrow(() => auth.ensureAdminConfigured());
    });

    it('throws when admin env vars not set', () => {
        const savedEmail = process.env.ADMIN_EMAIL;
        delete process.env.ADMIN_EMAIL;
        assert.throws(() => auth.ensureAdminConfigured(), /not configured/);
        process.env.ADMIN_EMAIL = savedEmail;
    });
});

describe('requireGoogleHomegraphAdmin middleware', () => {
    function mockReq(authHeader) {
        return { get: (name) => (name === 'authorization' ? authHeader : '') };
    }
    function mockRes() {
        const r = { statusCode: null, body: null };
        r.status = (code) => {
            r.statusCode = code;
            return r;
        };
        r.json = (body) => {
            r.body = body;
            return r;
        };
        return r;
    }

    it('returns 503 when admin token not configured', () => {
        const saved = process.env.GOOGLE_HOMEGRAPH_ADMIN_TOKEN;
        delete process.env.GOOGLE_HOMEGRAPH_ADMIN_TOKEN;
        const res = mockRes();
        auth.requireGoogleHomegraphAdmin(mockReq(''), res, () => {});
        assert.equal(res.statusCode, 503);
        if (saved) process.env.GOOGLE_HOMEGRAPH_ADMIN_TOKEN = saved;
    });

    it('returns 401 for invalid token', () => {
        process.env.GOOGLE_HOMEGRAPH_ADMIN_TOKEN = 'secret123';
        const res = mockRes();
        auth.requireGoogleHomegraphAdmin(mockReq('Bearer wrongtoken'), res, () => {});
        assert.equal(res.statusCode, 401);
        delete process.env.GOOGLE_HOMEGRAPH_ADMIN_TOKEN;
    });

    it('calls next for valid token', () => {
        process.env.GOOGLE_HOMEGRAPH_ADMIN_TOKEN = 'secret123';
        const res = mockRes();
        let nextCalled = false;
        auth.requireGoogleHomegraphAdmin(mockReq('Bearer secret123'), res, () => {
            nextCalled = true;
        });
        assert.ok(nextCalled);
        delete process.env.GOOGLE_HOMEGRAPH_ADMIN_TOKEN;
    });
});

// Restore env
after(() => {
    if (savedPortalSecret) process.env.PORTAL_SESSION_SECRET = savedPortalSecret;
    if (savedAdminSecret) process.env.ADMIN_SESSION_SECRET = savedAdminSecret;
    if (savedAdminEmail) process.env.ADMIN_EMAIL = savedAdminEmail;
    if (savedAdminPasswordHash) process.env.ADMIN_PASSWORD_HASH = savedAdminPasswordHash;
});
