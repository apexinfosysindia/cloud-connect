const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const savedKeySecret = process.env.RAZORPAY_KEY_SECRET;
const savedWebhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
const savedKeyId = process.env.RAZORPAY_KEY_ID;
const savedPlanId = process.env.RAZORPAY_PLAN_ID;

before(() => {
    process.env.RAZORPAY_KEY_ID = 'rzp_test_key';
    process.env.RAZORPAY_KEY_SECRET = 'rzp_test_secret_123456789012345';
    process.env.RAZORPAY_PLAN_ID = 'plan_test_123';
    process.env.RAZORPAY_WEBHOOK_SECRET = 'webhook_secret_123456789012345';
});

const billing = require('../lib/billing')({
    dbGet: async () => null,
    dbRun: async () => ({}),
    dbAll: async () => [],
    config: {
        RAZORPAY_PLAN_ID_MONTHLY: 'plan_monthly_test',
        RAZORPAY_PLAN_ID_ANNUAL: 'plan_annual_test'
    },
    createUniqueAccessToken: async () => 'apx_test_token'
});

describe('verifyPaymentSignature', () => {
    it('verifies a correct signature', () => {
        const paymentId = 'pay_123';
        const subscriptionId = 'sub_456';
        const expectedSig = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(`${paymentId}|${subscriptionId}`)
            .digest('hex');

        assert.ok(billing.verifyPaymentSignature(paymentId, subscriptionId, expectedSig));
    });

    it('rejects an incorrect signature', () => {
        assert.ok(!billing.verifyPaymentSignature('pay_123', 'sub_456', 'invalidsignature'));
    });

    it('rejects null signature', () => {
        assert.ok(!billing.verifyPaymentSignature('pay_123', 'sub_456', null));
    });

    it('rejects empty signature', () => {
        assert.ok(!billing.verifyPaymentSignature('pay_123', 'sub_456', ''));
    });
});

describe('verifyWebhookSignature', () => {
    it('verifies a correct webhook signature', () => {
        const rawBody = '{"event":"payment.captured"}';
        const expectedSig = crypto
            .createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET)
            .update(rawBody)
            .digest('hex');

        assert.ok(billing.verifyWebhookSignature(rawBody, expectedSig));
    });

    it('rejects an incorrect webhook signature', () => {
        assert.ok(!billing.verifyWebhookSignature('body', 'badsignature'));
    });

    it('throws when webhook secret not configured', () => {
        const saved = process.env.RAZORPAY_WEBHOOK_SECRET;
        delete process.env.RAZORPAY_WEBHOOK_SECRET;
        assert.throws(() => billing.verifyWebhookSignature('body', 'sig'), /not configured/);
        process.env.RAZORPAY_WEBHOOK_SECRET = saved;
    });
});

describe('ensureBillingConfigured', () => {
    it('does not throw when configured', () => {
        assert.doesNotThrow(() => billing.ensureBillingConfigured());
    });

    it('throws when key is missing', () => {
        const saved = process.env.RAZORPAY_KEY_ID;
        delete process.env.RAZORPAY_KEY_ID;
        assert.throws(() => billing.ensureBillingConfigured(), /not configured/);
        process.env.RAZORPAY_KEY_ID = saved;
    });
});

describe('getBillingErrorMessage', () => {
    it('extracts error.error.description', () => {
        assert.equal(billing.getBillingErrorMessage({ error: { description: 'bad' } }, 'fallback'), 'bad');
    });

    it('falls back to message', () => {
        assert.equal(billing.getBillingErrorMessage({ message: 'msg' }, 'fallback'), 'msg');
    });

    it('uses fallback when nothing available', () => {
        assert.equal(billing.getBillingErrorMessage({}, 'fallback'), 'fallback');
        assert.equal(billing.getBillingErrorMessage(null, 'fallback'), 'fallback');
    });
});

describe('extractWebhookSubscriptionInfo', () => {
    it('extracts subscription and payment info', () => {
        const payload = {
            payload: {
                subscription: { entity: { id: 'sub_1', status: 'active' } },
                payment: { entity: { id: 'pay_1', amount: 5000 } }
            }
        };
        const result = billing.extractWebhookSubscriptionInfo(payload);
        assert.equal(result.subscriptionId, 'sub_1');
        assert.equal(result.subscriptionStatus, 'active');
        assert.equal(result.paymentId, 'pay_1');
    });

    it('handles empty payload gracefully', () => {
        const result = billing.extractWebhookSubscriptionInfo({});
        assert.equal(result.subscriptionId, null);
    });
});

describe('buildCheckoutPayload', () => {
    it('builds correct checkout structure with default description', () => {
        const user = { email: 'u@t.com', subdomain: 'mycloud' };
        const payload = billing.buildCheckoutPayload(user, 'sub_123');
        assert.equal(payload.subscription_id, 'sub_123');
        assert.equal(payload.prefill.email, 'u@t.com');
        assert.equal(payload.name, 'ApexOS Cloud');
        assert.equal(payload.description, 'ApexOS Cloud remote access subscription');
    });

    it('uses planConfig description when provided', () => {
        const user = { email: 'u@t.com', subdomain: 'mycloud' };
        const planConfig = { description: 'ApexOS Cloud monthly remote access subscription' };
        const payload = billing.buildCheckoutPayload(user, 'sub_123', planConfig);
        assert.equal(payload.description, 'ApexOS Cloud monthly remote access subscription');
    });
});

describe('PLAN_TYPES', () => {
    it('exports monthly and annual plan configs', () => {
        assert.ok(billing.PLAN_TYPES.monthly);
        assert.ok(billing.PLAN_TYPES.annual);
    });

    it('monthly plan has no trial', () => {
        assert.equal(billing.PLAN_TYPES.monthly.hasTrial, false);
        assert.equal(billing.PLAN_TYPES.monthly.totalCount, 120);
    });

    it('annual plan has trial', () => {
        assert.equal(billing.PLAN_TYPES.annual.hasTrial, true);
        assert.equal(billing.PLAN_TYPES.annual.totalCount, 10);
        assert.equal(billing.PLAN_TYPES.annual.trialSeconds, 365 * 24 * 60 * 60);
    });

    it('getPlanId returns configured plan IDs', () => {
        assert.equal(billing.PLAN_TYPES.monthly.getPlanId(), 'plan_monthly_test');
        assert.equal(billing.PLAN_TYPES.annual.getPlanId(), 'plan_annual_test');
    });
});

after(() => {
    if (savedKeySecret) process.env.RAZORPAY_KEY_SECRET = savedKeySecret;
    else delete process.env.RAZORPAY_KEY_SECRET;
    if (savedWebhookSecret) process.env.RAZORPAY_WEBHOOK_SECRET = savedWebhookSecret;
    else delete process.env.RAZORPAY_WEBHOOK_SECRET;
    if (savedKeyId) process.env.RAZORPAY_KEY_ID = savedKeyId;
    else delete process.env.RAZORPAY_KEY_ID;
    if (savedPlanId) process.env.RAZORPAY_PLAN_ID = savedPlanId;
    else delete process.env.RAZORPAY_PLAN_ID;
});
