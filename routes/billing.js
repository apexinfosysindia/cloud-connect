const express = require('express');

module.exports = function ({ dbGet, dbRun, config, auth, billing }) {
    const router = express.Router();

    // Returns whether the authenticated user is still eligible for the
    // 1-year free trial on the annual plan. The UI uses this to hide the
    // "1 Year Free Trial" badge and adjust copy for users who have already
    // consumed a trial (e.g. an auto-renewal failed and they're back on
    // payment_pending, or they deleted and re-signed up with the same email).
    router.post('/api/billing/trial-eligibility', async (req, res) => {
        const { portal_session_token } = req.body || {};
        const cookieToken = req.cookies?.[config.PORTAL_SESSION_COOKIE_NAME] || '';
        const sessionToken = cookieToken || portal_session_token;

        if (!sessionToken) {
            return res.status(400).json({ error: 'Portal session token is required' });
        }

        try {
            const session = auth.verifyPortalSessionToken(sessionToken);
            if (!session) {
                return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
            }

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
            if (!user) {
                return res.status(404).json({ error: 'Account not found' });
            }

            if (!auth.portalTokenEpochMatches(session, user)) {
                return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
            }

            const consumed = await billing.hasConsumedTrial(user);
            return res.status(200).json({
                trial_available: !consumed,
                trial_consumed_at: user.trial_consumed_at || null
            });
        } catch (error) {
            console.error('TRIAL ELIGIBILITY ERROR:', error);
            return res.status(500).json({ error: 'Unable to check trial eligibility' });
        }
    });

    router.post('/api/billing/create-checkout', async (req, res) => {
        const { access_token, portal_session_token, plan } = req.body;
        const cookieToken = req.cookies?.[config.PORTAL_SESSION_COOKIE_NAME] || '';
        const sessionToken = cookieToken || portal_session_token;
        const planType = plan === 'monthly' ? 'monthly' : 'annual';

        if (!access_token && !sessionToken) {
            return res.status(400).json({ error: 'Portal session token is required' });
        }

        try {
            let user = null;
            if (access_token) {
                user = await dbGet(`SELECT * FROM users WHERE access_token = ?`, [access_token]);
            }

            if (!user && sessionToken) {
                const session = auth.verifyPortalSessionToken(sessionToken);
                if (!session) {
                    return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
                }
                user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
                if (user && !auth.portalTokenEpochMatches(session, user)) {
                    return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
                }
            }

            if (!user) {
                return res.status(404).json({ error: 'Account not found' });
            }

            if (!user.subdomain) {
                return res.status(400).json({ error: 'Set your cloud address before creating a payment checkout.' });
            }

            if (!user.email_verified) {
                return res.status(403).json({ error: 'Please verify your email address before proceeding to payment.' });
            }

            if (
                user.status === 'active' ||
                ['active', 'authenticated', 'charged'].includes((user.razorpay_subscription_status || '').toLowerCase())
            ) {
                return res
                    .status(409)
                    .json({ error: 'Your account is already active. Additional payment is not required.' });
            }

            if (user.status !== 'payment_pending') {
                return res.status(400).json({ error: 'This account does not require a payment checkout.' });
            }

            const checkoutState = await billing.prepareCheckoutForUser(user, planType);
            res.status(200).json({
                message: 'Checkout ready',
                data: auth.serializeUserWithPortalSession(checkoutState.user, sessionToken),
                checkout: checkoutState.checkout,
                plan: planType,
                trial_granted: Boolean(checkoutState.trialGranted)
            });
        } catch (error) {
            console.error('CHECKOUT CREATION ERROR:', error);
            const message = billing.getBillingErrorMessage(
                error,
                'Unable to create Razorpay checkout right now.'
            );
            if (error.statusCode) {
                return res.status(error.statusCode).json({ error: message });
            }
            res.status(502).json({ error: message });
        }
    });

    router.post('/api/billing/verify', async (req, res) => {
        const { razorpay_payment_id, razorpay_subscription_id, razorpay_signature, portal_session_token } = req.body;
        const cookieToken = req.cookies?.[config.PORTAL_SESSION_COOKIE_NAME] || '';
        const sessionToken = cookieToken || portal_session_token;

        if (!razorpay_payment_id || !razorpay_subscription_id || !razorpay_signature) {
            return res.status(400).json({ error: 'Missing Razorpay verification fields' });
        }

        try {
            auth.ensureBillingConfigured();

            if (!billing.verifyPaymentSignature(razorpay_payment_id, razorpay_subscription_id, razorpay_signature)) {
                return res.status(400).json({ error: 'Invalid Razorpay signature' });
            }

            const updatedUser = await billing.activateUserAccount(
                razorpay_subscription_id,
                razorpay_payment_id,
                'active'
            );

            if (!updatedUser) {
                return res.status(404).json({ error: 'No account found for this subscription' });
            }

            // Include portal session token so the client preserves its session
            const session = sessionToken ? auth.verifyPortalSessionToken(sessionToken) : null;
            const sessionValid = session && auth.portalTokenEpochMatches(session, updatedUser);
            const responseData = sessionValid
                ? auth.serializeUserWithPortalSession(updatedUser, sessionToken)
                : auth.serializeUser(updatedUser);

            res.status(200).json({
                message: 'Payment verified successfully',
                data: responseData
            });
        } catch (error) {
            console.error('PAYMENT VERIFICATION ERROR:', error);
            res.status(500).json({ error: billing.getBillingErrorMessage(error, 'Unable to verify payment') });
        }
    });

    router.post('/api/razorpay/webhook', async (req, res) => {
        const signature = req.get('x-razorpay-signature');

        try {
            if (!signature || !billing.verifyWebhookSignature(req.rawBody || '', signature)) {
                return res.status(400).json({ error: 'Invalid webhook signature' });
            }

            const eventName = req.body.event;
            const info = billing.extractWebhookSubscriptionInfo(req.body);

            if (!info.subscriptionId) {
                return res.status(200).json({ message: 'Webhook ignored' });
            }

            const user = await dbGet(`SELECT * FROM users WHERE razorpay_subscription_id = ?`, [info.subscriptionId]);
            if (!user) {
                return res.status(200).json({ message: 'No matching user for webhook event' });
            }

            // Guard against webhook reordering: Razorpay delivers events
            // asynchronously and out-of-order, so a late authenticated/activated
            // event can land AFTER we've already cancelled locally. If the
            // local record is already in a terminal subscription state
            // (cancelled/completed/expired/halted), ignore late activation
            // events — they would otherwise resurrect a cancelled user to
            // 'active' for a few minutes until the cancel event catches up.
            const terminalRzpStatuses = ['cancelled', 'completed', 'expired', 'halted'];
            const localRzpStatus = String(user.razorpay_subscription_status || '').toLowerCase();
            const alreadyTerminal = terminalRzpStatuses.includes(localRzpStatus);

            if (
                [
                    'subscription.authenticated',
                    'subscription.activated',
                    'subscription.charged',
                    'payment.captured',
                    'invoice.paid'
                ].includes(eventName)
            ) {
                if (alreadyTerminal) {
                    console.log(
                        `Ignoring late ${eventName} for ${user.email} — subscription already ${localRzpStatus} locally.`
                    );
                    return res.status(200).json({ message: 'Webhook ignored (already terminal)' });
                }
                await billing.activateUserAccount(
                    info.subscriptionId,
                    info.paymentId,
                    info.subscriptionStatus || 'active'
                );
            } else if (['subscription.halted', 'subscription.paused'].includes(eventName)) {
                await billing.updateUserStatus(user.id, 'suspended');
                await dbRun(`UPDATE users SET razorpay_subscription_status = ? WHERE id = ?`, [
                    info.subscriptionStatus || eventName,
                    user.id
                ]);
            } else if (['subscription.cancelled', 'subscription.completed', 'invoice.expired'].includes(eventName)) {
                // If we already soft-cancelled a trial locally (status=payment_pending,
                // trial_history written), don't downgrade to 'expired' — the user
                // never held a paid period, they returned to the pre-trial state.
                // Only paid users who cancel should land in 'expired'.
                if (user.status === 'payment_pending') {
                    console.log(
                        `Preserving payment_pending for ${user.email} — trial-cancel already handled locally, not overwriting with expired.`
                    );
                    await dbRun(`UPDATE users SET razorpay_subscription_status = ? WHERE id = ?`, [
                        info.subscriptionStatus || eventName,
                        user.id
                    ]);
                } else {
                    await billing.updateUserStatus(user.id, 'expired');
                    await dbRun(`UPDATE users SET razorpay_subscription_status = ? WHERE id = ?`, [
                        info.subscriptionStatus || eventName,
                        user.id
                    ]);
                }
            } else if (info.subscriptionStatus) {
                await dbRun(`UPDATE users SET razorpay_subscription_status = ? WHERE id = ?`, [
                    info.subscriptionStatus,
                    user.id
                ]);
            }

            res.status(200).json({ received: true });
        } catch (error) {
            console.error('RAZORPAY WEBHOOK ERROR:', error);
            res.status(500).json({ error: billing.getBillingErrorMessage(error, 'Webhook processing failed') });
        }
    });

    return router;
};
