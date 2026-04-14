const express = require('express');

module.exports = function ({ dbGet, dbRun, config, auth, billing }) {
    const router = express.Router();

    router.post('/api/billing/create-checkout', async (req, res) => {
        const { access_token, portal_session_token } = req.body;
        const cookieToken = req.cookies?.[config.PORTAL_SESSION_COOKIE_NAME] || '';
        const sessionToken = cookieToken || portal_session_token;

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
            }

            if (!user) {
                return res.status(404).json({ error: 'Account not found' });
            }

            if (!user.subdomain) {
                return res.status(400).json({ error: 'Set your cloud address before creating a payment checkout.' });
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

            const checkoutState = await billing.prepareCheckoutForUser(user);
            res.status(200).json({
                message: 'Checkout ready',
                data: auth.serializeUser(checkoutState.user),
                checkout: checkoutState.checkout
            });
        } catch (error) {
            console.error('CHECKOUT CREATION ERROR:', error);
            if (error.statusCode) {
                return res.status(error.statusCode).json({ error: error.message });
            }
            res.status(502).json({
                error: billing.getBillingErrorMessage(error, 'Unable to create Razorpay checkout right now.')
            });
        }
    });

    router.post('/api/billing/verify', async (req, res) => {
        const { razorpay_payment_id, razorpay_subscription_id, razorpay_signature } = req.body;

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

            res.status(200).json({
                message: 'Payment verified successfully',
                data: auth.serializeUser(updatedUser)
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

            if (
                [
                    'subscription.authenticated',
                    'subscription.activated',
                    'subscription.charged',
                    'payment.captured',
                    'invoice.paid'
                ].includes(eventName)
            ) {
                await billing.activateUserAccount(
                    info.subscriptionId,
                    info.paymentId,
                    info.subscriptionStatus || 'active'
                );
            } else if (['subscription.cancelled', 'subscription.halted', 'subscription.paused'].includes(eventName)) {
                await billing.updateUserStatus(user.id, 'suspended');
                await dbRun(`UPDATE users SET razorpay_subscription_status = ? WHERE id = ?`, [
                    info.subscriptionStatus || eventName,
                    user.id
                ]);
            } else if (['subscription.completed', 'invoice.expired'].includes(eventName)) {
                await billing.updateUserStatus(user.id, 'expired');
                await dbRun(`UPDATE users SET razorpay_subscription_status = ? WHERE id = ?`, [
                    info.subscriptionStatus || eventName,
                    user.id
                ]);
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
