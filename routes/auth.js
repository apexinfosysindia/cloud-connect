const express = require('express');
const bcrypt = require('bcryptjs');

module.exports = function ({ dbGet, dbRun, config, utils, auth, billing }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.post('/api/auth/signup', async (req, res) => {
        const { email, password, subdomain } = req.body;
        const normalizedSubdomain =
            String(subdomain || '')
                .trim()
                .toLowerCase() || null;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const normalizedEmail = String(email).trim().toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail) || normalizedEmail.length > 254) {
            return res.status(400).json({ error: 'Please enter a valid email address.' });
        }

        if (typeof password !== 'string' || password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
        }

        if (password.length > 128) {
            return res.status(400).json({ error: 'Password must not exceed 128 characters.' });
        }

        if (normalizedSubdomain && !/^[a-z0-9-]{3,20}$/.test(normalizedSubdomain)) {
            return res.status(400).json({ error: 'Subdomain must be 3-20 lowercase letters, numbers, or hyphens.' });
        }

        try {
            const existingUser = normalizedSubdomain
                ? await dbGet(`SELECT * FROM users WHERE email = ? OR subdomain = ?`, [
                      normalizedEmail,
                      normalizedSubdomain
                  ])
                : await dbGet(`SELECT * FROM users WHERE email = ?`, [normalizedEmail]);

            if (existingUser) {
                const message =
                    existingUser.email === normalizedEmail
                        ? existingUser.status === 'payment_pending'
                            ? 'Account already exists. Log in to continue setup.'
                            : 'Email already exists'
                        : 'Cloud address is already in use';
                return res.status(409).json({ error: message });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            const insertResult = await dbRun(
                `
                    INSERT INTO users (email, password, subdomain, status)
                    VALUES (?, ?, ?, 'payment_pending')
                `,
                [normalizedEmail, hashedPassword, normalizedSubdomain]
            );

            let user = await dbGet(`SELECT * FROM users WHERE id = ?`, [insertResult.lastID]);
            let checkout = null;
            let message = user.subdomain
                ? 'Account created. Complete payment to activate remote access.'
                : 'Account created. Set your desired cloud address to continue activation.';

            if (user.subdomain) {
                try {
                    const checkoutState = await billing.prepareCheckoutForUser(user);
                    user = checkoutState.user;
                    checkout = checkoutState.checkout;
                } catch (billingError) {
                    console.error('RAZORPAY CHECKOUT SETUP ERROR:', billingError);
                    message = billing.getBillingErrorMessage(
                        billingError,
                        'Account created, but billing setup is temporarily unavailable. Log in later to complete payment.'
                    );
                }
            }

            const portalSessionToken = auth.createPortalSessionToken(user.email);
            auth.setPortalSessionCookie(res, portalSessionToken);

            res.setHeader('Cache-Control', 'no-store');
            res.status(201).json({
                message,
                data: auth.serializeUserWithPortalSession(user, portalSessionToken),
                checkout
            });
        } catch (error) {
            console.error('SIGNUP ERROR:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    });

    router.post(
        '/api/auth/login',
        asyncHandler(async (req, res) => {
            const { email, password } = req.body;

            if (!email || !password) {
                return res.status(400).json({ error: 'Email and password are required' });
            }

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [email]);
            if (!user) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            const portalSessionToken = auth.createPortalSessionToken(user.email);
            auth.setPortalSessionCookie(res, portalSessionToken);

            res.setHeader('Cache-Control', 'no-store');
            res.status(200).json({
                message: 'Login successful',
                data: auth.serializeUserWithPortalSession(user, portalSessionToken)
            });
        })
    );

    router.post(
        '/api/account/subdomain',
        asyncHandler(async (req, res) => {
            const { portal_session_token, subdomain } = req.body;
            const cookieToken = req.cookies?.[config.PORTAL_SESSION_COOKIE_NAME] || '';
            const sessionToken = cookieToken || portal_session_token;

            if (!sessionToken) {
                return res.status(400).json({ error: 'Portal session token is required' });
            }

            const normalizedSubdomain = String(subdomain || '')
                .trim()
                .toLowerCase();
            if (!/^[a-z0-9-]{3,20}$/.test(normalizedSubdomain)) {
                return res
                    .status(400)
                    .json({ error: 'Subdomain must be 3-20 lowercase letters, numbers, or hyphens.' });
            }

            const session = auth.verifyPortalSessionToken(sessionToken);
            if (!session) {
                return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
            }

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
            if (!user) {
                return res.status(404).json({ error: 'Account not found' });
            }

            if (user.subdomain === normalizedSubdomain) {
                const portalSessionToken = auth.createPortalSessionToken(user.email);
                auth.setPortalSessionCookie(res, portalSessionToken);
                return res.status(200).json({
                    message: 'Cloud address saved',
                    data: auth.serializeUserWithPortalSession(user, portalSessionToken)
                });
            }

            const existing = await dbGet(`SELECT id FROM users WHERE subdomain = ? AND id != ?`, [
                normalizedSubdomain,
                user.id
            ]);
            if (existing) {
                return res.status(409).json({ error: 'This cloud address is already in use.' });
            }

            await dbRun(`UPDATE users SET subdomain = ? WHERE id = ?`, [normalizedSubdomain, user.id]);
            const updatedUser = await dbGet(`SELECT * FROM users WHERE id = ?`, [user.id]);
            const portalSessionToken = auth.createPortalSessionToken(updatedUser.email);
            auth.setPortalSessionCookie(res, portalSessionToken);

            return res.status(200).json({
                message: 'Cloud address saved',
                data: auth.serializeUserWithPortalSession(updatedUser, portalSessionToken)
            });
        })
    );

    router.post(
        '/api/account/me',
        asyncHandler(async (req, res) => {
            const { portal_session_token } = req.body;
            const cookieToken = req.cookies?.[config.PORTAL_SESSION_COOKIE_NAME] || '';
            const sessionToken = cookieToken || portal_session_token;

            if (!sessionToken) {
                return res.status(400).json({ error: 'Portal session token is required' });
            }

            const session = auth.verifyPortalSessionToken(sessionToken);
            if (!session) {
                return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
            }

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
            if (!user) {
                return res.status(404).json({ error: 'Account not found' });
            }

            const portalSessionToken = auth.createPortalSessionToken(user.email);
            auth.setPortalSessionCookie(res, portalSessionToken);

            return res.status(200).json({
                data: auth.serializeUserWithPortalSession(user, portalSessionToken)
            });
        })
    );

    router.post('/api/account/logout', (_req, res) => {
        auth.clearPortalSessionCookie(res);
        return res.status(200).json({ message: 'Logged out' });
    });

    return router;
};
