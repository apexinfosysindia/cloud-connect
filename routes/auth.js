const express = require('express');
const bcrypt = require('bcryptjs');

module.exports = function ({
    dbGet,
    dbRun,
    dbTransaction,
    config,
    utils,
    auth,
    webauthn,
    email,
    billing,
    device,
    eventGateway
}) {
    const router = express.Router();
    const { asyncHandler } = utils;

    // Canonical email form used for every users-table lookup. Signup stores
    // emails lowercased + trimmed, so any sign-in path that looks a user up by
    // a raw, as-typed address must normalize first — otherwise "User@x.com"
    // silently fails to match the stored "user@x.com". (This was a latent bug
    // in the legacy /login handler; normalizing here fixes it everywhere.)
    const normEmail = (e) =>
        String(e || '')
            .trim()
            .toLowerCase();

    // Enrich a user row with `has_oauth_identity` (true when the account has >=1
    // linked SSO identity) so the serializers can pass it to the dashboard,
    // which uses it to skip the passkey-enrolment nag for SSO users. One cheap
    // indexed EXISTS lookup; best-effort (a failure just leaves the flag false).
    async function attachOauthIdentityFlag(user) {
        if (!user || !user.id) {
            return user;
        }
        try {
            const row = await dbGet(`SELECT 1 AS linked FROM user_oauth_identities WHERE user_id = ? LIMIT 1`, [
                user.id
            ]);
            user.has_oauth_identity = Boolean(row);
        } catch (error) {
            console.error('OAUTH IDENTITY FLAG ERROR:', error.message);
        }
        return user;
    }

    // Shared "issue the session and respond 200" tail for every successful
    // customer sign-in (passwordless passkey, password-only, OTP fallback, and
    // the legacy combined login). Mints the portal session cookie + token and,
    // for an unverified account, best-effort re-sends the verification email and
    // reflects that in the success message — so the behavior the old /login
    // handler had on every path is preserved no matter which factor was used.
    async function finishLogin(res, user) {
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

        const portalSessionToken = auth.createPortalSessionToken(user.email, user.session_epoch);
        auth.setPortalSessionCookie(res, portalSessionToken);

        await attachOauthIdentityFlag(user);

        res.setHeader('Cache-Control', 'no-store');
        return res.status(200).json({
            message: !user.email_verified
                ? verificationSent
                    ? 'Login successful. A verification email has been sent to your inbox.'
                    : 'Login successful. Please verify your email to continue.'
                : 'Login successful',
            data: auth.serializeUserWithPortalSession(user, portalSessionToken)
        });
    }

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

            const portalSessionToken = auth.createPortalSessionToken(user.email, user.session_epoch);
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

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [normEmail(rawEmail)]);
            if (!user) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            // Legacy combined login (kept one release for back-compat with any
            // cached/native client still POSTing here). The identifier-first
            // flow has superseded it: lookup → passkey/begin+verify, or
            // password → otp. The 202 step-up below mirrors the old behavior so
            // those clients still work until this route is removed next cycle.
            if (user.passkey_2fa_enabled) {
                const principal = { kind: 'customer', subject: user.email, userId: user.id, displayName: user.email };
                const options = await webauthn.beginAuthentication(principal);
                if (options) {
                    res.setHeader('Cache-Control', 'no-store');
                    return res.status(202).json({ mfa_required: true, mfa_method: 'passkey', options });
                }
                // Flag set but no credentials survive (e.g. all removed out of
                // band): fail open to password-only rather than lock the user out.
            }

            return finishLogin(res, user);
        })
    );

    // ── Identifier-first passwordless login ─────────────────────────────────
    // Step 1: the email lookup. The client shows ONLY an email field first;
    // this tells it which factor to offer next. Account existence IS revealed
    // (has_passkey implies the account exists) — an accepted trade-off so the UI
    // can branch the way Google/Microsoft/GitHub sign-in does.
    router.post(
        '/api/auth/login/lookup',
        asyncHandler(async (req, res) => {
            const emailNorm = normEmail(req.body?.email);
            if (!emailNorm || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNorm)) {
                return res.status(400).json({ error: 'Please enter a valid email address.' });
            }

            const user = await dbGet(`SELECT id, passkey_2fa_enabled FROM users WHERE email = ?`, [emailNorm]);
            res.setHeader('Cache-Control', 'no-store');
            if (!user) {
                return res.status(200).json({ exists: false, has_passkey: false });
            }

            // passkey_2fa_enabled now means "has >=1 passkey". Double-check the
            // live credential count so a stale flag (creds removed out of band)
            // never advertises a passkey the user can't actually produce.
            const principal = { kind: 'customer', subject: emailNorm, userId: user.id };
            const hasPasskey = Boolean(user.passkey_2fa_enabled) && (await webauthn.countCredentials(principal)) > 0;
            return res.status(200).json({ exists: true, has_passkey: hasPasskey });
        })
    );

    // Step 2a (passkey path): issue a WebAuthn assertion challenge for the
    // email. No password required — the passkey IS the primary factor. The
    // client completes the assertion and POSTs to /login/passkey/verify below.
    router.post(
        '/api/auth/login/passkey/begin',
        asyncHandler(async (req, res) => {
            const emailNorm = normEmail(req.body?.email);
            if (!emailNorm) {
                return res.status(400).json({ error: 'Email is required' });
            }

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [emailNorm]);
            res.setHeader('Cache-Control', 'no-store');
            if (!user) {
                return res.status(404).json({ error: 'No passkey is available for this account.' });
            }

            const principal = { kind: 'customer', subject: user.email, userId: user.id, displayName: user.email };
            const options = await webauthn.beginAuthentication(principal);
            if (!options) {
                return res.status(404).json({ error: 'No passkey is available for this account.' });
            }
            return res.status(200).json({ options });
        })
    );

    // Step 2a (cont.): complete the passkey assertion and sign in. In the
    // passwordless model the valid, unconsumed 'authentication' challenge issued
    // by /login/passkey/begin is the ONLY factor — possession of the passkey IS
    // the proof of identity, so no prior password step is required or implied.
    // The challenge is single-use and bound to this email, which is what makes
    // that safe. (Also reached by the legacy /login 202 step-up during the
    // back-compat window.)
    router.post(
        '/api/auth/login/passkey/verify',
        asyncHandler(async (req, res) => {
            const emailNorm = normEmail(req.body?.email);
            const assertion = req.body?.assertion || req.body?.response;
            if (!emailNorm || !assertion) {
                return res.status(400).json({ error: 'Email and passkey assertion are required' });
            }

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [emailNorm]);
            if (!user || !user.passkey_2fa_enabled) {
                return res.status(401).json({ error: 'Passkey verification failed. Please sign in again.' });
            }

            const principal = { kind: 'customer', subject: user.email, userId: user.id, displayName: user.email };
            const result = await webauthn.finishAuthentication(principal, assertion);
            if (!result.verified) {
                console.error('[webauthn] customer login passkey verify failed:', result.error);
                return res.status(401).json({ error: 'Passkey verification failed. Please sign in again.' });
            }

            return finishLogin(res, user);
        })
    );

    // ── Usernameless passkey login (the "Sign in with a passkey" button) ────
    // No email typed: issue a challenge with no allowCredentials so the browser
    // offers every discoverable passkey for this site; the user is identified
    // from the credential they pick. The client must echo the challenge back on
    // verify so the server can find the matching single-use challenge.
    router.post(
        '/api/auth/login/passkey/discoverable/begin',
        asyncHandler(async (req, res) => {
            const options = await webauthn.beginDiscoverableAuthentication('customer');
            res.setHeader('Cache-Control', 'no-store');
            return res.status(200).json({ options });
        })
    );

    router.post(
        '/api/auth/login/passkey/discoverable/verify',
        asyncHandler(async (req, res) => {
            const assertion = req.body?.assertion || req.body?.response;
            const challenge = req.body?.challenge;
            if (!assertion || !challenge) {
                return res.status(400).json({ error: 'A passkey assertion is required' });
            }

            const result = await webauthn.finishDiscoverableAuthentication('customer', challenge, assertion);
            if (!result.verified) {
                console.error('[webauthn] discoverable passkey verify failed:', result.error);
                return res.status(401).json({ error: 'Passkey sign-in failed. Please try again.' });
            }

            const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [result.userId]);
            if (!user) {
                return res.status(404).json({ error: 'Account not found' });
            }

            return finishLogin(res, user);
        })
    );

    // Step 2b (password path): verify the password.
    //   • Account WITHOUT a passkey → password is its primary factor → sign in
    //     directly (matches today's behavior for password-only accounts).
    //   • Account WITH a passkey → the user is deliberately falling back (lost
    //     device). A correct password is necessary but NOT sufficient: email a
    //     6-digit code and return 202 WITHOUT a session. The user completes the
    //     code at /login/otp/verify. This is the emergency fallback that keeps a
    //     lost-passkey user from being locked out without weakening the passkey-
    //     primary posture to "password is just as good".
    router.post(
        '/api/auth/login/password',
        asyncHandler(async (req, res) => {
            const emailNorm = normEmail(req.body?.email);
            const password = req.body?.password;
            if (!emailNorm || !password) {
                return res.status(400).json({ error: 'Email and password are required' });
            }

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [emailNorm]);
            if (!user) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            const principal = { kind: 'customer', subject: user.email, userId: user.id };
            const hasPasskey = Boolean(user.passkey_2fa_enabled) && (await webauthn.countCredentials(principal)) > 0;

            if (hasPasskey) {
                if (!email.isEmailConfigured()) {
                    // No mail transport = no way to deliver the code. Rather than
                    // strand a passkey user mid-fallback, fail closed with a
                    // clear message (they can still use their passkey).
                    return res.status(503).json({
                        error: 'Email service is unavailable, so a sign-in code cannot be sent. Please use your passkey instead.'
                    });
                }
                try {
                    const code = await email.createLoginOtp(user.id);
                    await email.sendLoginOtpEmail(user.email, code);
                } catch (otpError) {
                    console.error('LOGIN OTP EMAIL ERROR:', otpError);
                    return res.status(500).json({ error: 'Unable to send your sign-in code. Please try again.' });
                }
                res.setHeader('Cache-Control', 'no-store');
                return res.status(202).json({
                    otp_required: true,
                    message: 'We emailed you a 6-digit sign-in code. Enter it to finish signing in.'
                });
            }

            return finishLogin(res, user);
        })
    );

    // Step 3 (OTP fallback): verify the emailed 6-digit code and sign in. Only
    // reached after /login/password returned 202 for a passkey-holding account.
    router.post(
        '/api/auth/login/otp/verify',
        asyncHandler(async (req, res) => {
            const emailNorm = normEmail(req.body?.email);
            const code = String(req.body?.code || '').trim();
            if (!emailNorm || !code) {
                return res.status(400).json({ error: 'Email and code are required' });
            }

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [emailNorm]);
            if (!user) {
                return res.status(401).json({ error: 'Invalid or expired code.' });
            }

            const result = await email.verifyLoginOtp(user.id, code);
            if (result.locked) {
                return res.status(429).json({
                    error: 'Too many incorrect codes. Please request a new sign-in code.'
                });
            }
            if (!result.ok) {
                return res.status(401).json({ error: 'Invalid or expired code.' });
            }

            await email.markLoginOtpUsed(result.id);
            return finishLogin(res, user);
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
                return res
                    .status(400)
                    .json({ error: 'Invalid or expired verification link. Please request a new one.' });
            }

            await email.markEmailVerificationTokenUsed(record.id);
            await email.markUserEmailVerified(record.user_id);

            const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [record.user_id]);
            if (!user) {
                return res.status(404).json({ error: 'Account not found.' });
            }

            const portalSessionToken = auth.createPortalSessionToken(user.email, user.session_epoch);
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

            if (!auth.portalTokenEpochMatches(session, user)) {
                return res.status(401).json({ error: 'Invalid session. Please log in again.' });
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

            // NOTE: a password reset deliberately does NOT touch the user's
            // passkeys anymore. Under the passwordless model the passkey is a
            // primary credential — wiping it on a password reset would let
            // anyone with inbox access silently strip a victim's strongest
            // factor. A lost-passkey user instead recovers via the password +
            // email-OTP fallback at sign-in; they keep any other passkeys.

            // Also verify the email if not already verified (they proved ownership)
            await email.markUserEmailVerified(record.user_id);

            // Security notification (best-effort; never blocks the response).
            email.sendPasswordChangedEmail(record.email).catch(() => {});

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

            if (!auth.portalTokenEpochMatches(session, user)) {
                return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
            }

            // Require email verification before setting subdomain
            if (!user.email_verified) {
                return res
                    .status(403)
                    .json({ error: 'Please verify your email address before setting a cloud address.' });
            }

            if (user.subdomain === normalizedSubdomain) {
                const portalSessionToken = auth.createPortalSessionToken(user.email, user.session_epoch);
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
            const portalSessionToken = auth.createPortalSessionToken(updatedUser.email, updatedUser.session_epoch);
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

            if (!auth.portalTokenEpochMatches(session, user)) {
                return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
            }

            // Only rotate the token when it's within 1 day of expiry to avoid
            // cookie churn from 5-second polling causing race conditions.
            let portalSessionToken = sessionToken;
            if (auth.portalTokenNeedsRotation(session)) {
                portalSessionToken = auth.createPortalSessionToken(user.email, user.session_epoch);
                auth.setPortalSessionCookie(res, portalSessionToken);
            }

            // Liveness probe: Amazon sends no directive when a customer disables
            // the skill in the Alexa app — the only signal is a 403 on a proactive
            // POST. Fire a throttled (≤1/min/user), fire-and-forget AddOrUpdateReport
            // so the dashboard learns about an app-side disable and flips
            // alexa_linked → 0 within a refresh cycle. Never blocks this response.
            if (user.alexa_linked && user.alexa_enabled && eventGateway?.probeAlexaLinkLivenessThrottled) {
                eventGateway.probeAlexaLinkLivenessThrottled(user.id);
            }

            await attachOauthIdentityFlag(user);

            return res.status(200).json({
                data: auth.serializeUserWithPortalSession(user, portalSessionToken)
            });
        })
    );

    router.post(
        '/api/account/logout-all-devices',
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

            if (!auth.portalTokenEpochMatches(session, user)) {
                return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
            }

            // Rotate access token so all devices using the old one lose access
            const newAccessToken = await device.createUniqueAccessToken();

            // Before we DELETE the device rows below, drop this user's Alexa endpoints
            // from Amazon. Those endpoint rows are FK'd to devices ON DELETE CASCADE, so
            // the DELETE wipes them locally with no DeleteReport — Amazon would keep the
            // tiles forever (we'd no longer have the entity_ids to delete them later).
            // Best-effort, awaited, while rows + LWA token still exist. Only meaningful
            // if the account is alexa-linked.
            if (user.alexa_linked && eventGateway?.deleteAllEndpointsForUserNow) {
                try {
                    await eventGateway.deleteAllEndpointsForUserNow(user.id, 'logout_all_devices');
                } catch (error) {
                    console.warn('ALEXA logout-all DeleteReport skipped:', error?.message);
                }
            }

            await dbTransaction(async ({ dbRun: txRun }) => {
                await txRun(`UPDATE users SET access_token = ? WHERE id = ?`, [newAccessToken, user.id]);

                // Remove device registrations — devices must re-register with the new token
                await txRun(`DELETE FROM devices WHERE user_id = ?`, [user.id]);

                // Revoke Google Home tokens so Google Assistant must re-link
                await txRun(`DELETE FROM google_home_tokens WHERE user_id = ?`, [user.id]);
                await txRun(`UPDATE users SET google_home_linked = 0 WHERE id = ?`, [user.id]);

                // Bump session epoch so all other portal sessions (other browsers) are invalidated.
                // We mint a fresh token for the current browser below that carries the new epoch.
                await txRun(`UPDATE users SET session_epoch = COALESCE(session_epoch, 0) + 1 WHERE id = ?`, [user.id]);
            });

            const updatedUser = await dbGet(`SELECT * FROM users WHERE id = ?`, [user.id]);
            const portalSessionToken = auth.createPortalSessionToken(updatedUser.email, updatedUser.session_epoch);
            auth.setPortalSessionCookie(res, portalSessionToken);

            // Security notification (best-effort; never blocks the response).
            email.sendSessionsRevokedEmail(user.email).catch(() => {});

            return res.status(200).json({
                message:
                    'All devices have been logged out. It can take up to an hour before all sessions are fully terminated.',
                data: auth.serializeUserWithPortalSession(updatedUser, portalSessionToken)
            });
        })
    );

    router.post(
        '/api/account/change-password',
        asyncHandler(async (req, res) => {
            const { portal_session_token, current_password, new_password } = req.body;
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

            if (!auth.portalTokenEpochMatches(session, user)) {
                return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
            }

            // Pure-SSO accounts have no real password (just the '!sso:' sentinel),
            // so this endpoint doubles as SET a password for them: skip the
            // current-password check and let them establish one. Accounts that
            // DO have a password must still prove it (unchanged) — otherwise a
            // hijacked session could silently rotate the password.
            const userHasPassword = auth.hasUsablePassword(user);
            if (userHasPassword) {
                if (!current_password || typeof current_password !== 'string') {
                    return res.status(400).json({ error: 'Current password is required.' });
                }

                const isMatch = await bcrypt.compare(current_password, user.password);
                if (!isMatch) {
                    return res.status(401).json({ error: 'Current password is incorrect.' });
                }
            }

            if (!new_password || typeof new_password !== 'string' || new_password.length < 8) {
                return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
            }

            if (new_password.length > 128) {
                return res.status(400).json({ error: 'New password must not exceed 128 characters.' });
            }

            const hashedPassword = await bcrypt.hash(new_password, 10);
            await dbRun(`UPDATE users SET password = ? WHERE id = ?`, [hashedPassword, user.id]);

            // Security notification (best-effort; never blocks the response).
            email.sendPasswordChangedEmail(user.email).catch(() => {});

            return res.status(200).json({
                message: userHasPassword ? 'Password changed successfully.' : 'Password set successfully.'
            });
        })
    );

    router.post(
        '/api/account/delete',
        asyncHandler(async (req, res) => {
            const { portal_session_token, password } = req.body;
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

            if (!auth.portalTokenEpochMatches(session, user)) {
                return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
            }

            if (!password || typeof password !== 'string') {
                return res.status(400).json({ error: 'Password is required to confirm account deletion.' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ error: 'Incorrect password. Account was not deleted.' });
            }

            const deletedEmail = user.email;
            const deleted = await billing.deleteUserAccount(user.id);
            if (!deleted) {
                return res.status(500).json({ error: 'Unable to delete account. Please try again.' });
            }

            // Security notification (best-effort) using the pre-captured address;
            // the user row is gone now.
            email.sendAccountDeletedEmail(deletedEmail).catch(() => {});

            auth.clearPortalSessionCookie(res);
            return res.status(200).json({ message: 'Your account has been permanently deleted.' });
        })
    );

    router.post(
        '/api/account/cancel-subscription',
        asyncHandler(async (req, res) => {
            const { portal_session_token, password } = req.body;
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
            if (!auth.portalTokenEpochMatches(session, user)) {
                return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
            }
            if (!password || typeof password !== 'string') {
                return res.status(400).json({ error: 'Password is required to cancel the subscription.' });
            }
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ error: 'Incorrect password. Subscription was not cancelled.' });
            }

            if (!user.razorpay_subscription_id) {
                return res.status(400).json({ error: 'No active subscription to cancel.' });
            }

            try {
                const result = await billing.cancelSubscription(user.id, { atCycleEnd: true });
                if (!result.cancelled) {
                    return res.status(400).json({ error: 'No active subscription to cancel.' });
                }
                let message;
                if (result.trialAbort) {
                    message =
                        'Subscription cancelled. Because this was a trial account, access has been disabled immediately and no charges will occur. You can start a new subscription any time from your dashboard.';
                } else if (result.atCycleEnd) {
                    message =
                        'Subscription cancelled. You will keep access until the end of your current billing period, after which no further charges will be made.';
                } else {
                    message =
                        'Subscription cancelled. No billing cycle had started yet, so the cancellation took effect immediately and you will not be charged.';
                }
                return res.status(200).json({ message });
            } catch (error) {
                return res.status(502).json({
                    error: error.message || 'Unable to cancel subscription. Please try again.'
                });
            }
        })
    );

    router.post('/api/account/logout', (_req, res) => {
        auth.clearPortalSessionCookie(res);
        return res.status(200).json({ message: 'Logged out' });
    });

    return router;
};
