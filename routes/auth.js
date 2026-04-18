const express = require('express');
const bcrypt = require('bcryptjs');

module.exports = function ({ dbGet, dbRun, config, utils, auth, email }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.post('/api/auth/signup', async (req, res) => {
        const { email: rawEmail, password, subdomain } = req.body;
        const normalizedSubdomain =
            String(subdomain || '')
                .trim()
                .toLowerCase() || null;

        if (!rawEmail || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const normalizedEmail = String(rawEmail).trim().toLowerCase();
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
                    INSERT INTO users (email, password, subdomain, status, email_verified)
                    VALUES (?, ?, ?, 'payment_pending', 0)
                `,
                [normalizedEmail, hashedPassword, normalizedSubdomain]
            );

            const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [insertResult.lastID]);

            // Send verification email (non-blocking - don't fail signup if email fails)
            let verificationSent = false;
            if (email.isEmailConfigured()) {
                try {
                    const token = await email.createEmailVerificationToken(user.id);
                    await email.sendVerificationEmail(normalizedEmail, token);
                    verificationSent = true;
                } catch (emailError) {
                    console.error('SIGNUP VERIFICATION EMAIL ERROR:', emailError);
                }
            }

            const portalSessionToken = auth.createPortalSessionToken(user.email);
            auth.setPortalSessionCookie(res, portalSessionToken);

            res.setHeader('Cache-Control', 'no-store');
            res.status(201).json({
                message: verificationSent
                    ? 'Account created. A verification email has been sent to your inbox.'
                    : 'Account created. Please verify your email to continue.',
                data: auth.serializeUserWithPortalSession(user, portalSessionToken)
            });
        } catch (error) {
            console.error('SIGNUP ERROR:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    });

    router.post(
        '/api/auth/login',
        asyncHandler(async (req, res) => {
            const { email: rawEmail, password } = req.body;

            if (!rawEmail || !password) {
                return res.status(400).json({ error: 'Email and password are required' });
            }

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [rawEmail]);
            if (!user) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            // Send verification email on login for unverified users
            let verificationSent = false;
            if (!user.email_verified && email.isEmailConfigured()) {
                try {
                    const token = await email.createEmailVerificationToken(user.id);
                    await email.sendVerificationEmail(user.email, token);
                    verificationSent = true;
                } catch (emailError) {
                    console.error('LOGIN VERIFICATION EMAIL ERROR:', emailError);
                }
            }

            const portalSessionToken = auth.createPortalSessionToken(user.email);
            auth.setPortalSessionCookie(res, portalSessionToken);

            res.setHeader('Cache-Control', 'no-store');
            res.status(200).json({
                message: !user.email_verified
                    ? (verificationSent
                        ? 'Login successful. A verification email has been sent to your inbox.'
                        : 'Login successful. Please verify your email to continue.')
                    : 'Login successful',
                data: auth.serializeUserWithPortalSession(user, portalSessionToken)
            });
        })
    );

    // Verify email from link
    router.post(
        '/api/auth/verify-email',
        asyncHandler(async (req, res) => {
            const { token } = req.body;

            if (!token || typeof token !== 'string') {
                return res.status(400).json({ error: 'Verification token is required.' });
            }

            const record = await email.verifyEmailToken(token);
            if (!record) {
                return res.status(400).json({ error: 'Invalid or expired verification link. Please request a new one.' });
            }

            await email.markEmailVerificationTokenUsed(record.id);
            await email.markUserEmailVerified(record.user_id);

            const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [record.user_id]);
            if (!user) {
                return res.status(404).json({ error: 'Account not found.' });
            }

            const portalSessionToken = auth.createPortalSessionToken(user.email);
            auth.setPortalSessionCookie(res, portalSessionToken);

            res.setHeader('Cache-Control', 'no-store');
            return res.status(200).json({
                message: 'Email verified successfully.',
                data: auth.serializeUserWithPortalSession(user, portalSessionToken)
            });
        })
    );

    // Resend verification email
    router.post(
        '/api/auth/resend-verification',
        asyncHandler(async (req, res) => {
            const { portal_session_token } = req.body;
            const cookieToken = req.cookies?.[config.PORTAL_SESSION_COOKIE_NAME] || '';
            const sessionToken = cookieToken || portal_session_token;

            if (!sessionToken) {
                return res.status(400).json({ error: 'Portal session token is required.' });
            }

            const session = auth.verifyPortalSessionToken(sessionToken);
            if (!session) {
                return res.status(401).json({ error: 'Invalid session. Please log in again.' });
            }

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
            if (!user) {
                return res.status(404).json({ error: 'Account not found.' });
            }

            if (user.email_verified) {
                return res.status(400).json({ error: 'Email is already verified.' });
            }

            if (!email.isEmailConfigured()) {
                return res.status(503).json({ error: 'Email service is not configured. Contact support.' });
            }

            try {
                const token = await email.createEmailVerificationToken(user.id);
                await email.sendVerificationEmail(user.email, token);
            } catch (emailError) {
                console.error('RESEND VERIFICATION EMAIL ERROR:', emailError);
                return res.status(500).json({ error: 'Unable to send verification email. Please try again later.' });
            }

            return res.status(200).json({
                message: 'Verification email sent. Check your inbox.'
            });
        })
    );

    // Forgot password - send reset email
    router.post(
        '/api/auth/forgot-password',
        asyncHandler(async (req, res) => {
            const { email: rawEmail } = req.body;

            if (!rawEmail) {
                return res.status(400).json({ error: 'Email address is required.' });
            }

            const normalizedEmail = String(rawEmail).trim().toLowerCase();
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail) || normalizedEmail.length > 254) {
                return res.status(400).json({ error: 'Please enter a valid email address.' });
            }

            if (!email.isEmailConfigured()) {
                return res.status(503).json({ error: 'Email service is not configured. Contact support.' });
            }

            // Always return success to prevent email enumeration
            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [normalizedEmail]);
            if (user) {
                try {
                    const token = await email.createPasswordResetToken(user.id);
                    await email.sendPasswordResetEmail(normalizedEmail, token);
                } catch (emailError) {
                    console.error('FORGOT PASSWORD EMAIL ERROR:', emailError);
                }
            }

            return res.status(200).json({
                message: 'If an account exists with that email, a password reset link has been sent.'
            });
        })
    );

    // Reset password with token
    router.post(
        '/api/auth/reset-password',
        asyncHandler(async (req, res) => {
            const { token, password } = req.body;

            if (!token || typeof token !== 'string') {
                return res.status(400).json({ error: 'Reset token is required.' });
            }

            if (!password || typeof password !== 'string' || password.length < 8) {
                return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
            }

            if (password.length > 128) {
                return res.status(400).json({ error: 'Password must not exceed 128 characters.' });
            }

            const record = await email.verifyPasswordResetToken(token);
            if (!record) {
                return res.status(400).json({ error: 'Invalid or expired reset link. Please request a new one.' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            await dbRun(`UPDATE users SET password = ? WHERE id = ?`, [hashedPassword, record.user_id]);
            await email.markPasswordResetTokenUsed(record.id);

            // Also verify the email if not already verified (they proved ownership)
            await email.markUserEmailVerified(record.user_id);

            return res.status(200).json({
                message: 'Password has been reset successfully. You can now sign in with your new password.'
            });
        })
    );

    // Validate a password reset token (so the frontend can show error before user fills the form)
    router.post(
        '/api/auth/validate-reset-token',
        asyncHandler(async (req, res) => {
            const { token } = req.body;

            if (!token || typeof token !== 'string') {
                return res.status(400).json({ error: 'Reset token is required.' });
            }

            const record = await email.verifyPasswordResetToken(token);
            if (!record) {
                return res.status(400).json({ error: 'Invalid or expired reset link. Please request a new one.' });
            }

            return res.status(200).json({
                valid: true,
                email: record.email
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

            // Require email verification before setting subdomain
            if (!user.email_verified) {
                return res.status(403).json({ error: 'Please verify your email address before setting a cloud address.' });
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

            // Only rotate the token when it's within 1 day of expiry to avoid
            // cookie churn from 5-second polling causing race conditions.
            let portalSessionToken = sessionToken;
            if (auth.portalTokenNeedsRotation(session)) {
                portalSessionToken = auth.createPortalSessionToken(user.email);
                auth.setPortalSessionCookie(res, portalSessionToken);
            }

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
