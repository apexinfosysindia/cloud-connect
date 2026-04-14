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
