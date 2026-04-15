const Razorpay = require('razorpay');
const crypto = require('crypto');

let razorpayClient = null;

module.exports = function ({ dbGet, dbRun, dbAll, config, createUniqueAccessToken }) {
    const PLAN_TYPES = {
        monthly: {
            label: 'Monthly',
            description: 'ApexOS Cloud monthly remote access subscription',
            getPlanId: () => config.RAZORPAY_PLAN_ID_MONTHLY,
            totalCount: 120, // 10 years of monthly cycles
            hasTrial: false
        },
        annual: {
            label: 'Annual',
            description: 'ApexOS Cloud annual remote access subscription',
            getPlanId: () => config.RAZORPAY_PLAN_ID_ANNUAL,
            totalCount: 10, // 10 years of annual cycles
            hasTrial: true,
            trialSeconds: 365 * 24 * 60 * 60 // 1 year
        }
    };

    function ensureBillingConfigured() {
        if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
            throw new Error('Billing is not configured. Please set Razorpay keys.');
        }
    }

    function getRazorpayClient() {
        ensureBillingConfigured();

        if (!razorpayClient) {
            razorpayClient = new Razorpay({
                key_id: process.env.RAZORPAY_KEY_ID,
                key_secret: process.env.RAZORPAY_KEY_SECRET
            });
        }

        return razorpayClient;
    }

    function getBillingErrorMessage(error, fallbackMessage) {
        return (
            error?.error?.description ||
            error?.description ||
            error?.message ||
            error?.response?.data?.error?.description ||
            fallbackMessage
        );
    }

    async function getOrCreateCustomer(user) {
        const razorpay = getRazorpayClient();

        // Reuse the customer ID already stored in our database
        if (user.razorpay_customer_id) {
            try {
                return await razorpay.customers.fetch(user.razorpay_customer_id);
            } catch (_ignored) {
                // Customer may have been deleted on Razorpay side; fall through to create
            }
        }

        // Always create a new customer — Razorpay's list endpoint does NOT
        // support email filtering, so .all({ email }) returns ALL customers
        // and previously returned the wrong one.
        return razorpay.customers.create({
            name: user.subdomain || user.email,
            email: user.email,
            notes: { subdomain: user.subdomain || '' }
        });
    }

    function buildCheckoutPayload(user, subscriptionId, planConfig) {
        return {
            key: process.env.RAZORPAY_KEY_ID,
            subscription_id: subscriptionId,
            name: 'Apex Infosys India',
            description: planConfig?.description ?? 'ApexOS Cloud remote access subscription',
            prefill: {
                email: user.email
            },
            notes: {
                subdomain: user.subdomain || ''
            }
        };
    }

    async function prepareCheckoutForUser(user, planType = 'annual') {
        if (
            user.status === 'active' ||
            ['active', 'authenticated', 'charged'].includes((user.razorpay_subscription_status || '').toLowerCase())
        ) {
            const error = new Error('Your account is already active. Additional payment is not required.');
            error.statusCode = 409;
            throw error;
        }

        if (user.status !== 'payment_pending') {
            const error = new Error('This account does not require a payment checkout.');
            error.statusCode = 400;
            throw error;
        }

        if (!user.subdomain) {
            const error = new Error('Set your cloud address before creating a payment checkout.');
            error.statusCode = 400;
            throw error;
        }

        const planConfig = PLAN_TYPES[planType];
        if (!planConfig) {
            const error = new Error(`Invalid plan type: ${planType}. Must be "monthly" or "annual".`);
            error.statusCode = 400;
            throw error;
        }

        const planId = planConfig.getPlanId();
        if (!planId) {
            const error = new Error(`The ${planConfig.label} plan is not configured.`);
            error.statusCode = 500;
            throw error;
        }

        const razorpay = getRazorpayClient();

        const customer = await getOrCreateCustomer(user);
        // Always create a fresh checkout subscription for payment-pending users.
        // This avoids reusing stale live-mode IDs after switching to test mode,
        // or vice versa, which Razorpay reports as "The id provided does not exist".
        const subscriptionParams = {
            plan_id: planId,
            customer_id: customer.id,
            total_count: planConfig.totalCount,
            customer_notify: 1,
            notes: {
                email: user.email,
                subdomain: user.subdomain,
                plan_type: planType
            }
        };

        // Annual plan: start_at defers the first charge by 1 year (free trial).
        // Razorpay authenticates the payment method immediately (card/UPI mandate)
        // but does not charge until start_at.  The subscription.authenticated
        // webhook fires on auth success and grants trial access.
        //
        // Monthly plan: no start_at — subscription starts immediately and the
        // first charge is the plan amount.  The subscription.authenticated
        // webhook fires on payment success and activates the user.
        if (planConfig.hasTrial) {
            subscriptionParams.start_at = Math.floor(Date.now() / 1000) + planConfig.trialSeconds;
        }

        const subscription = await razorpay.subscriptions.create(subscriptionParams);

        const subscriptionId = subscription.id;
        const subscriptionStatus = subscription.status || 'created';

        await dbRun(
            `
            UPDATE users
            SET razorpay_customer_id = ?,
                razorpay_subscription_id = ?,
                razorpay_subscription_status = ?
            WHERE id = ?
        `,
            [customer.id, subscriptionId, subscriptionStatus, user.id]
        );

        const updatedUser = await dbGet(`SELECT * FROM users WHERE id = ?`, [user.id]);
        return {
            user: updatedUser,
            checkout: buildCheckoutPayload(updatedUser, subscriptionId, planConfig)
        };
    }

    function verifyPaymentSignature(paymentId, subscriptionId, signature) {
        const expectedSignature = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(`${paymentId}|${subscriptionId}`)
            .digest('hex');

        const expectedBuffer = Buffer.from(expectedSignature, 'hex');
        const signatureBuffer = Buffer.from(signature || '', 'hex');

        if (expectedBuffer.length !== signatureBuffer.length) {
            return false;
        }

        return crypto.timingSafeEqual(expectedBuffer, signatureBuffer);
    }

    function verifyWebhookSignature(rawBody, signature) {
        if (!process.env.RAZORPAY_WEBHOOK_SECRET) {
            throw new Error('Razorpay webhook secret is not configured.');
        }

        const expectedSignature = crypto
            .createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET)
            .update(rawBody)
            .digest('hex');

        const expectedBuffer = Buffer.from(expectedSignature, 'hex');
        const signatureBuffer = Buffer.from(signature || '', 'hex');

        if (expectedBuffer.length !== signatureBuffer.length) {
            return false;
        }

        return crypto.timingSafeEqual(expectedBuffer, signatureBuffer);
    }

    function extractWebhookSubscriptionInfo(payload) {
        const subscription = payload?.payload?.subscription?.entity || payload?.payload?.subscription || null;
        const payment = payload?.payload?.payment?.entity || payload?.payload?.payment || null;
        const invoice = payload?.payload?.invoice?.entity || payload?.payload?.invoice || null;

        return {
            subscriptionId: subscription?.id || payment?.subscription_id || null,
            subscriptionStatus: subscription?.status || null,
            paymentId: payment?.id || invoice?.payment_id || null
        };
    }

    async function activateUserAccount(subscriptionId, paymentId, subscriptionStatus = 'active') {
        const user = await dbGet(`SELECT * FROM users WHERE razorpay_subscription_id = ?`, [subscriptionId]);
        if (!user) {
            return null;
        }

        // Determine whether this is a trial (annual w/ future start_at) or
        // an immediate activation (monthly).  We inspect the subscription's
        // notes.plan_type that we stored at creation time AND whether start_at
        // is still in the future.  Once the billing cycle starts (start_at has
        // passed), even annual subscriptions should fully activate.
        let isTrial = false;
        try {
            const razorpay = getRazorpayClient();
            const sub = await razorpay.subscriptions.fetch(subscriptionId);
            const nowEpoch = Math.floor(Date.now() / 1000);
            const startInFuture = sub.start_at != null && sub.start_at > nowEpoch + 60;

            const notePlanType = sub.notes?.plan_type;
            if (notePlanType === 'annual' && startInFuture) {
                // Annual plan, billing hasn't started yet → trial
                isTrial = true;
            } else if (notePlanType === 'monthly') {
                isTrial = false;
            } else if (!notePlanType && startInFuture) {
                // Legacy subscriptions without plan_type note
                isTrial = true;
            }
            // For annual where start_at has passed → isTrial stays false → active
        } catch (_fetchError) {
            // If we cannot reach Razorpay, fall back to safe default (active)
            isTrial = false;
        }

        const activatedAt = user.activated_at || new Date().toISOString();
        const accessToken = user.access_token || (await createUniqueAccessToken());

        if (isTrial) {
            // Annual plan with deferred start: grant trial access until billing begins
            const trialEndsAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
            await dbRun(
                `
                UPDATE users
                SET status = 'trial',
                    access_token = ?,
                    razorpay_payment_id = COALESCE(?, razorpay_payment_id),
                    razorpay_subscription_status = ?,
                    activated_at = ?,
                    trial_approved_at = ?,
                    trial_ends_at = ?
                WHERE id = ?
            `,
                [accessToken, paymentId || null, subscriptionStatus, activatedAt, activatedAt, trialEndsAt, user.id]
            );
        } else {
            // Monthly plan (or already-started annual): immediate full activation
            await dbRun(
                `
                UPDATE users
                SET status = 'active',
                    access_token = ?,
                    razorpay_payment_id = COALESCE(?, razorpay_payment_id),
                    razorpay_subscription_status = ?,
                    activated_at = ?,
                    trial_ends_at = NULL
                WHERE id = ?
            `,
                [accessToken, paymentId || null, subscriptionStatus, activatedAt, user.id]
            );
        }

        return dbGet(`SELECT * FROM users WHERE id = ?`, [user.id]);
    }

    async function updateUserStatus(userId, status, options = {}) {
        const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [userId]);
        if (!user) {
            return null;
        }

        const now = new Date();
        const nowIso = now.toISOString();
        let trialEndsAt = user.trial_ends_at;
        let trialApprovedAt = user.trial_approved_at;
        let activatedAt = user.activated_at;
        let accessToken = user.access_token;

        if (status === 'trial') {
            const trialDays = Number.isFinite(options.trialDays) ? options.trialDays : 365;
            trialApprovedAt = nowIso;
            trialEndsAt = new Date(now.getTime() + trialDays * 24 * 60 * 60 * 1000).toISOString();
            activatedAt = activatedAt || nowIso;
            accessToken = accessToken || (await createUniqueAccessToken());
        } else if (status === 'active') {
            trialEndsAt = null;
            activatedAt = activatedAt || nowIso;
            accessToken = accessToken || (await createUniqueAccessToken());
        } else if (status === 'payment_pending') {
            trialEndsAt = null;
            trialApprovedAt = null;
            activatedAt = null;
        } else if (status === 'expired' || status === 'suspended') {
            trialEndsAt = null;
        }

        await dbRun(
            `
            UPDATE users
            SET status = ?,
                access_token = ?,
                trial_ends_at = ?,
                trial_approved_at = ?,
                activated_at = ?
            WHERE id = ?
        `,
            [status, accessToken, trialEndsAt, trialApprovedAt, activatedAt, userId]
        );

        return dbGet(`SELECT * FROM users WHERE id = ?`, [userId]);
    }

    /**
     * Transitions overdue accounts to payment_pending so they must pay
     * via Razorpay to continue.
     *
     * Catches two categories:
     *  1. Trial users whose trial_ends_at has passed.
     *  2. Suspended / expired users (from Razorpay webhook or admin action)
     *     — immediately moved to payment_pending so they can self-service
     *     pay to reactivate.
     *
     * Admin-activated users (status = 'active' via the Activate button)
     * are treated as confirmed offline payments and never auto-expire.
     *
     * Returns the number of accounts transitioned.
     */
    async function expireOverdueAccounts() {
        const nowIso = new Date().toISOString();

        // Expired trials
        const expiredTrials = await dbAll(
            `SELECT id, email FROM users
             WHERE status = 'trial'
               AND trial_ends_at IS NOT NULL
               AND trial_ends_at < ?`,
            [nowIso]
        );

        // Suspended / expired users → let them re-subscribe
        const blockedUsers = await dbAll(
            `SELECT id, email FROM users WHERE status IN ('suspended', 'expired')`
        );

        const overdueUsers = [...expiredTrials, ...blockedUsers];

        for (const user of overdueUsers) {
            await dbRun(
                `UPDATE users
                 SET status = 'payment_pending',
                     trial_ends_at = NULL,
                     trial_approved_at = NULL,
                     activated_at = NULL,
                     razorpay_customer_id = NULL,
                     razorpay_subscription_id = NULL,
                     razorpay_subscription_status = NULL
                 WHERE id = ?`,
                [user.id]
            );
            console.log(`Account expired → payment_pending: ${user.email} (id=${user.id})`);
        }

        return overdueUsers.length;
    }

    return {
        PLAN_TYPES,
        ensureBillingConfigured,
        getRazorpayClient,
        getBillingErrorMessage,
        getOrCreateCustomer,
        buildCheckoutPayload,
        prepareCheckoutForUser,
        verifyPaymentSignature,
        verifyWebhookSignature,
        extractWebhookSubscriptionInfo,
        activateUserAccount,
        updateUserStatus,
        expireOverdueAccounts
    };
};
