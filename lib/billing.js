const Razorpay = require('razorpay');
const crypto = require('crypto');

let razorpayClient = null;

module.exports = function ({ dbGet, dbRun, dbAll, dbTransaction, config, createUniqueAccessToken }) {
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

    /**
     * Normalize an email for trial-history lookup.
     *
     * Treat cosmetic variants of the same mailbox as the same identity so a
     * user cannot claim multiple free trials by adding dots or +tags:
     *   - lowercase + trim
     *   - strip "+tag" from the local part
     *   - for Gmail / Googlemail: also strip dots and canonicalize to gmail.com
     *
     * This is layered with payment-instrument fingerprinting below — together
     * they catch the common abuse paths. Neither is foolproof alone.
     */
    function normalizeEmailForTrialHistory(email) {
        if (!email || typeof email !== 'string') return '';
        const trimmed = email.trim().toLowerCase();
        const atIdx = trimmed.lastIndexOf('@');
        if (atIdx < 1 || atIdx === trimmed.length - 1) return trimmed;
        let local = trimmed.slice(0, atIdx);
        let domain = trimmed.slice(atIdx + 1);

        const plusIdx = local.indexOf('+');
        if (plusIdx >= 0) local = local.slice(0, plusIdx);

        if (domain === 'gmail.com' || domain === 'googlemail.com') {
            domain = 'gmail.com';
            local = local.replace(/\./g, '');
        }

        if (!local) return trimmed;
        return `${local}@${domain}`;
    }

    /**
     * Returns true if this identity has already consumed a free trial at any
     * point — either on the current user row (trial_consumed_at) or on a
     * previously-deleted/recycled row for the same normalized email
     * (trial_history).
     */
    async function hasConsumedTrial(user) {
        if (!user) return false;
        if (user.trial_consumed_at) return true;

        const normalized = normalizeEmailForTrialHistory(user.email);
        if (!normalized) return false;

        const row = await dbGet(
            `SELECT 1 AS found FROM trial_history WHERE email_normalized = ? LIMIT 1`,
            [normalized]
        );
        return Boolean(row);
    }

    /**
     * Record that this user has consumed a free trial. Idempotent — safe to
     * call multiple times. Writes both to the user row (trial_consumed_at)
     * AND to the persistent trial_history table (keyed on normalized email)
     * so the record survives account deletion.
     *
     * If `tx` is passed, uses that transaction context (the caller is
     * responsible for BEGIN/COMMIT). Otherwise, wraps the writes in a
     * fresh transaction so the user-row update and the trial_history
     * insert either both succeed or both fail.
     */
    async function recordTrialConsumedWithin(tx, user, source, options = {}) {
        if (!user || !user.email) return;
        const nowIso = new Date().toISOString();
        const fingerprint = options.paymentFingerprint || null;

        if (!user.trial_consumed_at) {
            await tx.dbRun(
                `UPDATE users SET trial_consumed_at = ? WHERE id = ? AND trial_consumed_at IS NULL`,
                [nowIso, user.id]
            );
        }

        if (fingerprint && !user.payment_fingerprint) {
            await tx.dbRun(
                `UPDATE users SET payment_fingerprint = ? WHERE id = ? AND payment_fingerprint IS NULL`,
                [fingerprint, user.id]
            );
        }

        const normalized = normalizeEmailForTrialHistory(user.email);
        if (!normalized) return;

        const existing = await tx.dbGet(
            `SELECT 1 AS found FROM trial_history WHERE email_normalized = ? AND user_id_at_time = ? LIMIT 1`,
            [normalized, user.id]
        );
        if (existing) return;

        await tx.dbRun(
            `INSERT INTO trial_history (email_normalized, email_original, source, user_id_at_time, payment_fingerprint, consumed_at)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [normalized, user.email, source || 'subscription', user.id, fingerprint, nowIso]
        );
    }

    async function recordTrialConsumed(user, source, options = {}) {
        await dbTransaction((tx) => recordTrialConsumedWithin(tx, user, source, options));
    }

    /**
     * Derive a stable, privacy-preserving fingerprint from a Razorpay payment
     * object. The fingerprint is designed to match when the SAME payment
     * instrument is used across different accounts (same card, same UPI VPA)
     * so we can detect re-trial abuse by identity-swapping users.
     *
     * We deliberately do NOT store raw card numbers or VPAs — only a hash of
     * the identifying attributes. Returns null if the payment method cannot
     * be fingerprinted (e.g. netbanking, wallet) or required fields are
     * missing. Callers must tolerate a null result.
     *
     * Schema is prefixed so different instrument types don't collide:
     *   - "fpc:…"  card
     *   - "fpu:…"  UPI
     */
    function derivePaymentFingerprint(payment) {
        if (!payment || typeof payment !== 'object') return null;
        const method = String(payment.method || '').toLowerCase();

        if (method === 'card' && payment.card && typeof payment.card === 'object') {
            const card = payment.card;
            const last4 = String(card.last4 || '').trim();
            if (!last4) return null;
            const parts = [
                'card',
                last4,
                String(card.network || '').toLowerCase().trim(),
                String(card.issuer || '').toLowerCase().trim(),
                String(card.type || '').toLowerCase().trim()
            ];
            const digest = crypto.createHash('sha256').update(parts.join('|')).digest('hex');
            return `fpc:${digest.slice(0, 40)}`;
        }

        if (method === 'upi') {
            const vpa = String(payment.vpa || '').toLowerCase().trim();
            if (!vpa) return null;
            const digest = crypto.createHash('sha256').update(vpa).digest('hex');
            return `fpu:${digest.slice(0, 40)}`;
        }

        // netbanking / wallet / emandate — no reliable cross-account fingerprint.
        return null;
    }

    /**
     * Fetch a payment from Razorpay and return its derived fingerprint.
     * Returns null on any error (missing payment id, API failure, unsupported
     * method). Callers should never let a fingerprint lookup failure block
     * activation — the email guard remains in place.
     */
    async function fetchPaymentFingerprint(paymentId) {
        if (!paymentId) return null;
        try {
            const razorpay = getRazorpayClient();
            const payment = await razorpay.payments.fetch(paymentId);
            return derivePaymentFingerprint(payment);
        } catch (fetchError) {
            console.warn(
                `fetchPaymentFingerprint: unable to fetch payment ${paymentId}:`,
                getBillingErrorMessage(fetchError, fetchError.message)
            );
            return null;
        }
    }

    /**
     * Look up any prior trial_history row that used the same payment
     * instrument as the given fingerprint, excluding the supplied user id
     * (so a user's own prior attempt with the same card doesn't self-match
     * incorrectly — though in that case email-based history would already
     * block them).
     *
     * Returns the row or null.
     */
    async function findPriorTrialByFingerprint(fingerprint, excludeUserId) {
        if (!fingerprint) return null;
        return dbGet(
            `SELECT * FROM trial_history
             WHERE payment_fingerprint = ?
               AND (user_id_at_time IS NULL OR user_id_at_time != ?)
             ORDER BY consumed_at ASC
             LIMIT 1`,
            [fingerprint, excludeUserId || 0]
        );
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

        // Create-or-return: fail_existing=0 tells Razorpay to return the
        // existing customer with the same email/contact instead of throwing
        // "Customer already exists for the merchant". Razorpay's REST API
        // expects the string "0", not an integer.
        //
        // Belt-and-braces: if the param is ignored (older SDK, API quirk)
        // and Razorpay still throws, we catch it and fall back to listing
        // customers and matching by email to recover the id.
        try {
            return await razorpay.customers.create({
                name: user.subdomain || user.email,
                email: user.email,
                fail_existing: '0',
                notes: { subdomain: user.subdomain || '' }
            });
        } catch (createError) {
            const description = getBillingErrorMessage(createError, '') || '';
            const alreadyExists = /already exists/i.test(description);
            if (!alreadyExists) throw createError;

            // Razorpay doesn't expose email filtering on the list endpoint.
            // Scan the most recent customers (count=100 is Razorpay's max)
            // and match locally.
            const list = await razorpay.customers.all({ count: 100 });
            const items = Array.isArray(list?.items) ? list.items : [];
            const match = items.find(
                (c) => String(c.email || '').toLowerCase() === String(user.email || '').toLowerCase()
            );
            if (match) return match;

            const wrapped = new Error(
                'Razorpay reports this email already has a customer record, but we could not retrieve it. Contact support.'
            );
            wrapped.statusCode = 502;
            throw wrapped;
        }
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
        //
        // Trial-abuse guard: only grant the 1-year deferral if this identity
        // has never consumed a free trial before. This blocks:
        //   (a) a user whose annual auto-renewal failed from getting another
        //       free year by re-checking out (status would flip to
        //       payment_pending after expireOverdueAccounts).
        //   (b) a user who deleted their account and re-signed up with the
        //       same email (or gmail +tag/dot variant) — trial_history
        //       preserves the record across deletion.
        let trialGrantedOnThisCheckout = false;
        if (planConfig.hasTrial) {
            const alreadyConsumed = await hasConsumedTrial(user);
            if (!alreadyConsumed) {
                subscriptionParams.start_at = Math.floor(Date.now() / 1000) + planConfig.trialSeconds;
                trialGrantedOnThisCheckout = true;
            }
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
            checkout: buildCheckoutPayload(updatedUser, subscriptionId, planConfig),
            trialGranted: trialGrantedOnThisCheckout
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
        let currentPeriodEndIso = null;
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

            // Capture the end of the current paid cycle so the dashboard can
            // show "Renews on <date>" / "Access ends on <date>" for paid users.
            // Razorpay returns current_end as epoch seconds. For pre-cycle
            // subscriptions (trial annual), current_end is null until the
            // first cycle starts; we leave the column NULL in that case and
            // let the trial_ends_at field carry the same date for display.
            if (sub.current_end != null) {
                currentPeriodEndIso = new Date(sub.current_end * 1000).toISOString();
            }
        } catch (_fetchError) {
            // If we cannot reach Razorpay, fall back to safe default (active)
            isTrial = false;
        }

        const activatedAt = user.activated_at || new Date().toISOString();
        const accessToken = user.access_token || (await createUniqueAccessToken());

        // Resolve the payment-instrument fingerprint up front. Used for both
        // trial abuse detection (below) and for persisting on the user row
        // so a future signup using the same instrument can be spotted.
        const paymentFingerprint = await fetchPaymentFingerprint(paymentId);

        if (isTrial) {
            // Fingerprint-based trial abuse guard.
            //
            // If this payment instrument (same card or same UPI VPA) has
            // already been recorded against a PRIOR trial on a different
            // account, the trial is NOT granted. We cancel the deferred
            // Razorpay subscription, mark trial as consumed on this user, and
            // push them back to payment_pending so they can start a fresh
            // checkout — which, thanks to trial_consumed_at now being set,
            // will bill immediately (no start_at deferral).
            //
            // This catches the case where a user creates a brand-new email,
            // signs up, and tries to pay with the same card they already used
            // to claim a trial on another (deleted or active) account.
            if (paymentFingerprint) {
                const priorTrial = await findPriorTrialByFingerprint(paymentFingerprint, user.id);
                if (priorTrial) {
                    console.log(
                        `Trial blocked by payment fingerprint match for user ${user.email} ` +
                        `(prior trial user_id=${priorTrial.user_id_at_time}, source=${priorTrial.source})`
                    );

                    // Cancel the deferred Razorpay subscription best-effort.
                    try {
                        const razorpay = getRazorpayClient();
                        await razorpay.subscriptions.cancel(subscriptionId, {
                            cancel_at_cycle_end: false
                        });
                    } catch (cancelError) {
                        console.error(
                            `Failed to cancel blocked trial subscription ${subscriptionId}:`,
                            getBillingErrorMessage(cancelError, cancelError.message)
                        );
                    }

                    // Record the blocked attempt in trial_history so future
                    // attempts from the same email ALSO get caught by the
                    // email guard (belt + suspenders).
                    await recordTrialConsumed(user, 'blocked_fingerprint', {
                        paymentFingerprint
                    });

                    // Reset user to payment_pending. trial_consumed_at is now
                    // set, so the next prepareCheckoutForUser call will
                    // create an immediate-billing subscription.
                    await dbRun(
                        `UPDATE users
                         SET status = 'payment_pending',
                             razorpay_subscription_id = NULL,
                             razorpay_subscription_status = NULL,
                             razorpay_payment_id = COALESCE(?, razorpay_payment_id),
                             trial_ends_at = NULL,
                             trial_approved_at = NULL,
                             activated_at = NULL
                         WHERE id = ?`,
                        [paymentId || null, user.id]
                    );

                    return dbGet(`SELECT * FROM users WHERE id = ?`, [user.id]);
                }
            }

            // No fingerprint conflict — grant trial access until billing begins.
            const trialEndsAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
            await dbTransaction(async (tx) => {
                await tx.dbRun(
                    `
                UPDATE users
                SET status = 'trial',
                    access_token = ?,
                    razorpay_payment_id = COALESCE(?, razorpay_payment_id),
                    razorpay_subscription_status = ?,
                    activated_at = ?,
                    trial_approved_at = ?,
                    trial_ends_at = ?,
                    current_period_end = COALESCE(?, current_period_end)
                WHERE id = ?
            `,
                    [
                        accessToken,
                        paymentId || null,
                        subscriptionStatus,
                        activatedAt,
                        activatedAt,
                        trialEndsAt,
                        currentPeriodEndIso,
                        user.id
                    ]
                );

                // Persist trial consumption (email + fingerprint) so a future
                // payment_pending re-checkout or delete-and-resignup cannot
                // claim another free year — even with a fresh email, as long
                // as the same payment instrument is used.
                await recordTrialConsumedWithin(tx, user, 'subscription', { paymentFingerprint });
            });
        } else {
            // Monthly plan (or already-started annual): immediate full activation
            await dbTransaction(async (tx) => {
                await tx.dbRun(
                    `
                UPDATE users
                SET status = 'active',
                    access_token = ?,
                    razorpay_payment_id = COALESCE(?, razorpay_payment_id),
                    razorpay_subscription_status = ?,
                    activated_at = ?,
                    trial_ends_at = NULL,
                    current_period_end = COALESCE(?, current_period_end)
                WHERE id = ?
            `,
                    [accessToken, paymentId || null, subscriptionStatus, activatedAt, currentPeriodEndIso, user.id]
                );

                // Even for non-trial activations, record the payment fingerprint
                // on the user row so the first time a monthly-plan user's card
                // is seen, it's tied to their identity. If they later switch to
                // annual on a new account, the fingerprint lookup would catch
                // them (monthly users are already flagged as trial_consumed_at
                // by the aggressive backfill, so their own re-trial is blocked
                // by email anyway — the fingerprint protects against new accounts
                // using that same card).
                if (paymentFingerprint && !user.payment_fingerprint) {
                    await tx.dbRun(
                        `UPDATE users SET payment_fingerprint = ? WHERE id = ? AND payment_fingerprint IS NULL`,
                        [paymentFingerprint, user.id]
                    );
                }

                // Mark trial as consumed even for paid (monthly / immediate-annual)
                // activations. This blocks the "subscribe → cancel/expire →
                // resubscribe expecting a fresh trial" path: the resubscribe
                // flow checks trial_history by email and will (correctly) treat
                // them as ineligible for a free year. Without this row, a paid
                // user whose sub later expires could claim a fresh trial via
                // the now-visible billing card.
                await recordTrialConsumedWithin(tx, user, 'subscription', { paymentFingerprint });
            });
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

        await dbTransaction(async (tx) => {
            await tx.dbRun(
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

            // Record admin-granted trials in the persistent history table so a
            // future delete-and-resignup cannot claim another free trial.
            if (status === 'trial') {
                await recordTrialConsumedWithin(tx, user, 'admin');
            }
        });

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

    /**
     * Cancels a user's Razorpay subscription without deleting the account.
     *
     * Default policy: cancel at cycle end — user keeps the service they
     * already paid for; no new charges after the current period.
     *
     * Does NOT change the user's status (access stays 'active'/'trial'
     * until the subscription.completed webhook fires at period end and
     * expireOverdueAccounts / webhook handler drops them to 'expired').
     *
     * Idempotent: returns { cancelled: false, reason } if the user has no
     * active subscription ID to cancel. Any Razorpay API error surfaces
     * a readable billing error message.
     */
    async function cancelSubscription(userId, options = {}) {
        const atCycleEnd = options.atCycleEnd !== false; // default true
        const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [userId]);
        if (!user) {
            return { cancelled: false, reason: 'user_not_found' };
        }
        if (!user.razorpay_subscription_id) {
            return { cancelled: false, reason: 'no_subscription', user };
        }

        const razorpay = getRazorpayClient();
        const TERMINAL_RZP = ['cancelled', 'completed', 'expired', 'halted'];

        // Pre-flight: inspect Razorpay's view of the subscription. This decides
        // three things:
        //   a) Is the sub already terminal on Razorpay? → skip API call,
        //      just reconcile our DB (idempotent recovery from prior partial
        //      failures, double-clicks, admin-then-user cancel sequences).
        //   b) Is the sub in a pre-cycle state (authenticated, paid_count=0,
        //      future start_at)? → must use parameterless cancel; Razorpay
        //      rejects the cancel_at_cycle_end parameter in either form.
        //   c) Otherwise → normal cancel with cancel_at_cycle_end honored.
        let preCycleSoftCancel = false;
        let alreadyTerminalOnRzp = false;
        let fetchedSub = null;
        try {
            fetchedSub = await razorpay.subscriptions.fetch(user.razorpay_subscription_id);
            const subStatus = String(fetchedSub.status || '').toLowerCase();
            if (TERMINAL_RZP.includes(subStatus)) {
                alreadyTerminalOnRzp = true;
            } else {
                const nowEpoch = Math.floor(Date.now() / 1000);
                const startInFuture = fetchedSub.start_at != null && fetchedSub.start_at > nowEpoch;
                const preCycleStatus = ['created', 'authenticated', 'pending'].includes(subStatus);
                const noPaidInvoice = !fetchedSub.paid_count || fetchedSub.paid_count === 0;
                if (preCycleStatus && noPaidInvoice && (startInFuture || !fetchedSub.current_start)) {
                    preCycleSoftCancel = true;
                }
            }
        } catch (fetchErr) {
            console.error(
                `Razorpay fetch before cancel failed for ${user.email}: ${
                    getBillingErrorMessage(fetchErr, fetchErr.message)
                }`
            );
        }

        // Race guard: write the trial-abort DB state BEFORE calling Razorpay.
        // Razorpay fires the subscription.cancelled webhook within milliseconds
        // of the cancel call returning. Without pre-writing, the webhook handler
        // can read user.status='trial' and flip the user to 'expired' before our
        // post-cancel UPDATE lands. With pre-writing, the webhook sees
        // 'payment_pending' and preserves it (see routes/billing.js webhook).
        // We snapshot the original state so we can roll back if Razorpay fails.
        const trialAbort = user.status === 'trial';
        const rollbackSnapshot = {
            status: user.status,
            trial_ends_at: user.trial_ends_at,
            trial_approved_at: user.trial_approved_at,
            razorpay_subscription_status: user.razorpay_subscription_status
        };
        let trialHistoryWritten = false;
        if (trialAbort) {
            try {
                await recordTrialConsumed(user, 'trial_cancel');
                trialHistoryWritten = true;
            } catch (historyErr) {
                console.error(
                    `Failed to write trial_history on trial cancel for ${user.email}:`,
                    historyErr.message
                );
            }
            try {
                await dbRun(
                    `UPDATE users
                     SET status = 'payment_pending',
                         trial_ends_at = NULL,
                         trial_approved_at = NULL
                     WHERE id = ?`,
                    [userId]
                );
            } catch (preWriteErr) {
                console.error(
                    `Failed to pre-write payment_pending for ${user.email}:`,
                    preWriteErr.message
                );
            }
        }

        let cancelledSub;
        let effectiveAtCycleEnd = atCycleEnd;
        try {
            if (alreadyTerminalOnRzp) {
                // Sub is already cancelled/completed on Razorpay's side. No API
                // call needed; just synthesize a response so we can reconcile
                // our DB. Common when admin cancelled first, user double-clicked,
                // or a previous attempt succeeded on Razorpay but failed mid-DB.
                cancelledSub = fetchedSub;
                effectiveAtCycleEnd = false;
                console.log(
                    `Reconciling already-cancelled subscription for ${user.email} sub=${user.razorpay_subscription_id} (Razorpay status=${fetchedSub.status})`
                );
            } else if (preCycleSoftCancel) {
                cancelledSub = await razorpay.subscriptions.cancel(
                    user.razorpay_subscription_id
                );
                effectiveAtCycleEnd = false;
                console.log(
                    `Cancelled pre-cycle subscription for ${user.email} sub=${user.razorpay_subscription_id} (was status=${fetchedSub && fetchedSub.status}, paid_count=${fetchedSub && fetchedSub.paid_count}); Razorpay status now=${cancelledSub.status}`
                );
            } else {
                try {
                    cancelledSub = await razorpay.subscriptions.cancel(
                        user.razorpay_subscription_id,
                        { cancel_at_cycle_end: atCycleEnd }
                    );
                } catch (err) {
                    const rawMsg = getBillingErrorMessage(err, '') || '';
                    console.error(
                        `Razorpay cancel failed for ${user.email} sub=${user.razorpay_subscription_id} atCycleEnd=${atCycleEnd}: "${rawMsg}". Trying opposite mode.`
                    );
                    try {
                        cancelledSub = await razorpay.subscriptions.cancel(
                            user.razorpay_subscription_id,
                            { cancel_at_cycle_end: !atCycleEnd }
                        );
                        effectiveAtCycleEnd = !atCycleEnd;
                        console.log(
                            `Razorpay cancel succeeded for ${user.email} on retry with atCycleEnd=${!atCycleEnd}.`
                        );
                    } catch (retryErr) {
                        const retryMsg = getBillingErrorMessage(retryErr, '') || '';
                        console.error(
                            `Razorpay opposite-mode cancel also failed for ${user.email}: "${retryMsg}". Trying parameterless cancel.`
                        );
                        cancelledSub = await razorpay.subscriptions.cancel(
                            user.razorpay_subscription_id
                        );
                        effectiveAtCycleEnd = false;
                        console.log(
                            `Razorpay parameterless cancel succeeded for ${user.email}.`
                        );
                    }
                }
            }
        } catch (cancelErr) {
            // All Razorpay attempts failed AND it wasn't already terminal.
            // Roll back the pre-write so the user keeps trial access and we
            // remove the bogus trial_history entry. They get an error toast.
            const message = getBillingErrorMessage(cancelErr, 'Unable to cancel subscription');
            console.error(
                `All Razorpay cancel attempts failed for ${user.email}: "${message}". Rolling back DB pre-write.`
            );
            if (trialAbort) {
                try {
                    await dbRun(
                        `UPDATE users
                         SET status = ?,
                             trial_ends_at = ?,
                             trial_approved_at = ?,
                             razorpay_subscription_status = ?
                         WHERE id = ?`,
                        [
                            rollbackSnapshot.status,
                            rollbackSnapshot.trial_ends_at,
                            rollbackSnapshot.trial_approved_at,
                            rollbackSnapshot.razorpay_subscription_status,
                            userId
                        ]
                    );
                } catch (rollbackErr) {
                    console.error(
                        `Rollback of trial pre-write failed for ${user.email}:`,
                        rollbackErr.message
                    );
                }
                if (trialHistoryWritten) {
                    try {
                        await dbRun(
                            `DELETE FROM trial_history
                             WHERE id = (
                                 SELECT id FROM trial_history
                                 WHERE email_normalized = ? AND source = 'trial_cancel'
                                 ORDER BY id DESC LIMIT 1
                             )`,
                            [String(user.email || '').trim().toLowerCase()]
                        );
                    } catch (historyRollbackErr) {
                        console.error(
                            `Failed to roll back trial_history for ${user.email}:`,
                            historyRollbackErr.message
                        );
                    }
                }
            }
            const wrapped = new Error(message);
            wrapped.cause = cancelErr;
            throw wrapped;
        }

        // Reflect Razorpay's returned status so the dashboard surfaces
        // 'cancelled' immediately, even before the webhook arrives.
        const statusFromRzp = cancelledSub && cancelledSub.status ? cancelledSub.status : 'cancelled';

        try {
            await dbRun(
                `UPDATE users SET razorpay_subscription_status = ? WHERE id = ?`,
                [statusFromRzp, userId]
            );
        } catch (dbErr) {
            console.error(
                `Subscription cancelled on Razorpay for ${user.email} but DB status update failed:`,
                dbErr.message
            );
        }

        console.log(
            `Subscription cancelled: user=${user.email} sub=${user.razorpay_subscription_id} at_cycle_end=${effectiveAtCycleEnd} status=${statusFromRzp} trial_abort=${trialAbort} already_terminal=${alreadyTerminalOnRzp}`
        );
        return {
            cancelled: true,
            atCycleEnd: effectiveAtCycleEnd,
            subscription: cancelledSub,
            user,
            trialAbort,
            alreadyTerminal: alreadyTerminalOnRzp
        };
    }

    /**
     * Permanently deletes a user account.
     *
     * 1. Cancels any active Razorpay subscription (best-effort).
     * 2. Deletes the user row — ON DELETE CASCADE removes devices,
     *    device_logs, tokens, Google Home entities, etc.
     *
     * Returns the deleted user row (snapshot before deletion) or null
     * if the user was not found.
     */
    async function deleteUserAccount(userId) {
        const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [userId]);
        if (!user) {
            return null;
        }

        // Preserve trial-consumption record BEFORE deleting the user row.
        // If the user ever held trial state (trial_consumed_at, trial_approved_at,
        // or current trial_ends_at), persist a trial_history entry keyed on the
        // normalized email so the same identity cannot delete-and-resignup
        // for another free year.
        const hadTrial =
            Boolean(user.trial_consumed_at) ||
            Boolean(user.trial_approved_at) ||
            Boolean(user.trial_ends_at);
        if (hadTrial) {
            try {
                await recordTrialConsumed(user, 'deleted');
            } catch (historyError) {
                console.error(
                    `Failed to write trial_history before deleting user ${user.email}:`,
                    historyError.message
                );
            }
        }

        // Cancel Razorpay subscription (best-effort — don't block deletion)
        if (user.razorpay_subscription_id) {
            try {
                const razorpay = getRazorpayClient();
                await razorpay.subscriptions.cancel(user.razorpay_subscription_id, { cancel_at_cycle_end: false });
            } catch (cancelError) {
                console.error(
                    `Failed to cancel Razorpay subscription ${user.razorpay_subscription_id} for user ${user.email}:`,
                    getBillingErrorMessage(cancelError, cancelError.message)
                );
            }
        }

        await dbRun(`DELETE FROM users WHERE id = ?`, [userId]);
        console.log(`Account deleted: ${user.email} (id=${userId})`);
        return user;
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
        expireOverdueAccounts,
        cancelSubscription,
        deleteUserAccount,
        normalizeEmailForTrialHistory,
        hasConsumedTrial,
        recordTrialConsumed,
        derivePaymentFingerprint,
        fetchPaymentFingerprint,
        findPriorTrialByFingerprint
    };
};
