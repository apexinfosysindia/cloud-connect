const crypto = require('crypto');
const bcrypt = require('bcryptjs');

module.exports = function ({ dbGet, config, utils, device, googleCore, alexaCore }) {
    function getPortalSecret() {
        const secret = utils.sanitizeString(process.env.PORTAL_SESSION_SECRET || '', 512);
        if (!secret || secret.length < 32) {
            throw new Error('PORTAL_SESSION_SECRET must be configured with at least 32 characters');
        }

        return secret;
    }

    function signPortalValue(value) {
        return crypto.createHmac('sha256', getPortalSecret()).update(value).digest('hex');
    }

    function createPortalSessionToken(email, sessionEpoch = 0) {
        const payload = Buffer.from(
            JSON.stringify({
                email,
                epoch: Number.isFinite(sessionEpoch) ? Number(sessionEpoch) : 0,
                exp: Date.now() + 7 * 24 * 60 * 60 * 1000
            })
        ).toString('base64url');
        return `${payload}.${signPortalValue(payload)}`;
    }

    function verifyPortalSessionToken(token) {
        if (!token || !utils.hasExactlyOneDot(token)) {
            return null;
        }

        const [payload, signature] = token.split('.');
        const expected = signPortalValue(payload);
        const expectedBuffer = Buffer.from(expected);
        const signatureBuffer = Buffer.from(signature || '');

        if (expectedBuffer.length !== signatureBuffer.length) {
            return null;
        }

        if (!crypto.timingSafeEqual(expectedBuffer, signatureBuffer)) {
            return null;
        }

        try {
            const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
            if (!decoded?.email || decoded.exp < Date.now()) {
                return null;
            }
            return decoded;
        } catch (_error) {
            return null;
        }
    }

    // Pick whichever token VERIFIES, preferring the EXPLICIT token (the one the
    // client put in the query/body) over the cookie. The explicit token is the
    // account the user is actively acting as on the dashboard, so it is the
    // authority for account-linking; the cookie is only a fallback for when no
    // explicit token is supplied.
    //
    // History: this originally did `cookie || query`, so a STALE/invalid cookie
    // shadowed a fresh valid query token → verification failed → bounce to /login
    // → infinite linking loop. The first fix flipped it to "cookie-if-valid-else
    // -query", which fixed the loop but introduced a worse bug: a VALID cookie for
    // a DIFFERENT account (e.g. a previous login still in the jar) hijacked the
    // link — it minted the OAuth code for the cookie's user instead of the user
    // shown on the dashboard ("linked but discovered nothing"). Preferring the
    // explicit token fixes BOTH: a bad cookie can't shadow it, and a valid cookie
    // for another account can't override the account the client explicitly asked
    // to act as. Returns { token, session } or { token: '', session: null }.
    function pickValidPortalToken(cookieToken, explicitToken) {
        const cookie = typeof cookieToken === 'string' ? cookieToken.trim() : '';
        const explicit = typeof explicitToken === 'string' ? explicitToken.trim() : '';
        const explicitSession = explicit ? verifyPortalSessionToken(explicit) : null;
        if (explicitSession) {
            return { token: explicit, session: explicitSession };
        }
        const cookieSession = cookie ? verifyPortalSessionToken(cookie) : null;
        if (cookieSession) {
            return { token: cookie, session: cookieSession };
        }
        return { token: '', session: null };
    }

    function portalTokenEpochMatches(session, user) {
        const tokenEpoch = Number(session?.epoch ?? 0) || 0;
        const userEpoch = Number(user?.session_epoch ?? 0) || 0;
        return tokenEpoch === userEpoch;
    }

    const TOKEN_ROTATION_THRESHOLD_MS = 24 * 60 * 60 * 1000; // 1 day

    function portalTokenNeedsRotation(session) {
        if (!session?.exp) return true;
        return (session.exp - Date.now()) < TOKEN_ROTATION_THRESHOLD_MS;
    }

    function setPortalSessionCookie(res, token) {
        if (!token) {
            return;
        }

        res.cookie(config.PORTAL_SESSION_COOKIE_NAME, token, {
            httpOnly: true,
            secure: config.PORTAL_SESSION_COOKIE_SECURE,
            sameSite: 'lax',
            domain: config.PORTAL_SESSION_COOKIE_DOMAIN,
            path: '/',
            maxAge: config.PORTAL_SESSION_COOKIE_MAX_AGE_MS
        });
    }

    function clearPortalSessionCookie(res) {
        res.clearCookie(config.PORTAL_SESSION_COOKIE_NAME, {
            domain: config.PORTAL_SESSION_COOKIE_DOMAIN,
            path: '/',
            sameSite: 'lax',
            secure: config.PORTAL_SESSION_COOKIE_SECURE,
            httpOnly: true
        });
    }

    function isTerminalSubscriptionStatus(status) {
        if (!status) return false;
        const s = String(status).toLowerCase();
        return ['cancelled', 'completed', 'expired', 'halted'].includes(s);
    }

    function serializeUser(user) {
        const accessEnabled = utils.isAccessEnabled(user.status);
        const hasSubdomain = Boolean(user.subdomain);
        return {
            id: user.id,
            email: user.email,
            subdomain: user.subdomain,
            access_token: accessEnabled ? user.access_token : null,
            status: user.status,
            email_verified: Boolean(user.email_verified),
            domain: hasSubdomain ? `${user.subdomain}.${config.CLOUD_BASE_DOMAIN}` : null,
            google_home_enabled: Boolean(user.google_home_enabled),
            google_home_linked: Boolean(user.google_home_linked),
            alexa_enabled: Boolean(user.alexa_enabled),
            alexa_linked: Boolean(user.alexa_linked),
            passkey_2fa_enabled: Boolean(user.passkey_2fa_enabled),
            trial_ends_at: user.trial_ends_at,
            trial_approved_at: user.trial_approved_at,
            activated_at: user.activated_at,
            current_period_end: user.current_period_end || null,
            admin_granted_access: Boolean(
                ['active', 'trial'].includes(user.status) && !user.razorpay_subscription_id
            ),
            has_active_subscription: Boolean(
                user.razorpay_subscription_id &&
                    !isTerminalSubscriptionStatus(user.razorpay_subscription_status)
            ),
            razorpay_subscription_status: user.razorpay_subscription_status || null,
            payment_pending: user.status === 'payment_pending'
        };
    }

    function serializeUserWithPortalSession(user, portalSessionToken) {
        const accessEnabled = utils.isAccessEnabled(user.status);
        const hasSubdomain = Boolean(user.subdomain);
        return {
            id: user.id,
            email: user.email,
            subdomain: user.subdomain,
            access_token: accessEnabled ? user.access_token : null,
            portal_session_token: portalSessionToken,
            status: user.status,
            email_verified: Boolean(user.email_verified),
            domain: hasSubdomain ? `${user.subdomain}.${config.CLOUD_BASE_DOMAIN}` : null,
            google_home_enabled: Boolean(user.google_home_enabled),
            google_home_linked: Boolean(user.google_home_linked),
            alexa_enabled: Boolean(user.alexa_enabled),
            alexa_linked: Boolean(user.alexa_linked),
            passkey_2fa_enabled: Boolean(user.passkey_2fa_enabled),
            trial_ends_at: user.trial_ends_at,
            trial_approved_at: user.trial_approved_at,
            activated_at: user.activated_at,
            current_period_end: user.current_period_end || null,
            admin_granted_access: Boolean(
                ['active', 'trial'].includes(user.status) && !user.razorpay_subscription_id
            ),
            has_active_subscription: Boolean(
                user.razorpay_subscription_id &&
                    !isTerminalSubscriptionStatus(user.razorpay_subscription_status)
            ),
            razorpay_subscription_status: user.razorpay_subscription_status || null,
            payment_pending: user.status === 'payment_pending'
        };
    }

    function serializeAdminUser(user) {
        const hasSubdomain = Boolean(user.subdomain);
        return {
            id: user.id,
            email: user.email,
            subdomain: user.subdomain,
            domain: hasSubdomain ? `${user.subdomain}.${config.CLOUD_BASE_DOMAIN}` : null,
            status: user.status,
            access_token: utils.isAccessEnabled(user.status) ? user.access_token : null,
            razorpay_customer_id: user.razorpay_customer_id,
            razorpay_subscription_id: user.razorpay_subscription_id,
            razorpay_payment_id: user.razorpay_payment_id,
            razorpay_subscription_status: user.razorpay_subscription_status,
            trial_ends_at: user.trial_ends_at,
            trial_approved_at: user.trial_approved_at,
            activated_at: user.activated_at,
            current_period_end: user.current_period_end || null,
            created_at: user.created_at
        };
    }

    function ensureBillingConfigured() {
        const hasKeys = process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET;
        const hasAnyPlan =
            process.env.RAZORPAY_PLAN_ID ||
            process.env.RAZORPAY_PLAN_ID_MONTHLY ||
            process.env.RAZORPAY_PLAN_ID_ANNUAL;
        if (!hasKeys || !hasAnyPlan) {
            throw new Error('Billing is not configured. Please set Razorpay keys and plan ID.');
        }
    }

    function ensureAdminConfigured() {
        if (!process.env.ADMIN_EMAIL || (!process.env.ADMIN_PASSWORD_HASH && !process.env.ADMIN_PASSWORD)) {
            throw new Error(
                'Admin credentials are not configured. Please set ADMIN_EMAIL and ADMIN_PASSWORD_HASH (bcrypt hash).'
            );
        }
    }

    // Verify a candidate admin password against the configured credential
    // (bcrypt hash preferred, constant-time plaintext fallback). Shared by the
    // admin login, the passkey-remove confirm, and the sudo re-auth flows.
    function verifyAdminPassword(password) {
        const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;
        if (adminPasswordHash) {
            return bcrypt.compare(password || '', adminPasswordHash);
        }
        if (process.env.ADMIN_PASSWORD) {
            const expected = Buffer.from(process.env.ADMIN_PASSWORD);
            const received = Buffer.from(password || '');
            return Promise.resolve(expected.length === received.length && crypto.timingSafeEqual(expected, received));
        }
        return Promise.resolve(false);
    }

    function getAdminSecret() {
        const secret = utils.sanitizeString(
            process.env.ADMIN_SESSION_SECRET || process.env.RAZORPAY_KEY_SECRET || '',
            512
        );
        if (!secret || secret.length < 32) {
            throw new Error(
                'ADMIN_SESSION_SECRET or RAZORPAY_KEY_SECRET must be configured with at least 32 characters'
            );
        }

        return secret;
    }

    function signAdminValue(value) {
        return crypto.createHmac('sha256', getAdminSecret()).update(value).digest('hex');
    }

    function createAdminToken(email) {
        const payload = Buffer.from(
            JSON.stringify({
                email,
                exp: Date.now() + 8 * 60 * 60 * 1000
            })
        ).toString('base64url');
        return `${payload}.${signAdminValue(payload)}`;
    }

    function verifyAdminToken(token) {
        if (!token || !utils.hasExactlyOneDot(token)) {
            return null;
        }

        const [payload, signature] = token.split('.');
        const expected = signAdminValue(payload);
        const expectedBuffer = Buffer.from(expected);
        const signatureBuffer = Buffer.from(signature || '');

        if (expectedBuffer.length !== signatureBuffer.length) {
            return null;
        }

        if (!crypto.timingSafeEqual(expectedBuffer, signatureBuffer)) {
            return null;
        }

        try {
            const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
            if (!decoded?.email || decoded.exp < Date.now()) {
                return null;
            }
            return decoded;
        } catch (_error) {
            return null;
        }
    }

    // ── Scoped admin "sudo" tokens ──────────────────────────────────────────
    // A short-lived, single-purpose grant minted after a fresh re-auth (admin
    // password + passkey assertion). Used to gate the fortress security page so
    // a stolen 8h session token alone cannot add/remove passkeys. `bind` ties
    // the grant to the exact session that minted it; `scope` keeps it strictly
    // separate from the 8h session token (each rejects the other).
    function createScopedAdminToken(email, { scope, ttlMs, bind } = {}) {
        const now = Date.now();
        const payload = Buffer.from(
            JSON.stringify({
                email,
                scope: scope || 'sudo',
                bind: bind || null,
                iat: now,
                exp: now + (Number.isFinite(ttlMs) ? ttlMs : 5 * 60 * 1000)
            })
        ).toString('base64url');
        return `${payload}.${signAdminValue(payload)}`;
    }

    function verifyScopedAdminToken(token, { scope } = {}) {
        const decoded = verifyAdminToken(token);
        if (!decoded) {
            return null;
        }
        // A non-scoped (8h session) token must NOT pass as a scoped grant.
        if (!decoded.scope || (scope && decoded.scope !== scope)) {
            return null;
        }
        return decoded;
    }

    // Compute the binding value for a given base (8h) bearer token.
    function computeSudoBind(baseBearerToken) {
        return signAdminValue(String(baseBearerToken || '')).slice(0, 32);
    }

    function requireAdmin(req, res, next) {
        try {
            ensureAdminConfigured();
        } catch (error) {
            return res.status(500).json({ error: error.message });
        }

        const authHeader = req.get('authorization') || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
        const session = verifyAdminToken(token);

        // A sudo-scoped grant is NOT a session — it must never satisfy requireAdmin.
        if (!session || session.scope || session.email !== process.env.ADMIN_EMAIL) {
            return res.status(401).json({ error: 'Admin authentication required' });
        }

        req.admin = session;
        next();
    }

    // Gate for sensitive admin mutations. MUST run after requireAdmin (so
    // req.admin + a valid base bearer exist). Requires a fresh sudo grant in
    // the X-Sudo-Token header, bound to the current 8h session token.
    function requireAdminSudo(req, res, next) {
        const authHeader = req.get('authorization') || '';
        const baseToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
        const sudoToken = req.get('x-sudo-token') || '';

        const grant = verifyScopedAdminToken(sudoToken, { scope: 'sudo' });
        if (!grant || grant.email !== process.env.ADMIN_EMAIL) {
            return res.status(401).json({ error: 'sudo_required' });
        }

        // The grant must have been minted by THIS session token, so a leaked
        // sudo grant can't be paired with a different hijacked session.
        if (!grant.bind || grant.bind !== computeSudoBind(baseToken)) {
            return res.status(401).json({ error: 'sudo_required' });
        }

        req.adminSudo = grant;
        next();
    }

    async function requireDeviceAuth(req, res, next) {
        try {
            const authHeader = req.get('authorization') || '';
            const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
            const deviceToken = req.get('x-device-token') || bearerToken || req.body?.device_token || '';

            if (!deviceToken) {
                return res.status(401).json({ error: 'Device token is required' });
            }

            const foundDevice = await device.findDeviceByToken(deviceToken);
            if (!foundDevice) {
                return res.status(401).json({ error: 'Invalid device token' });
            }

            req.deviceAuthToken = deviceToken;
            req.device = foundDevice;
            return next();
        } catch (error) {
            console.error('DEVICE AUTH ERROR:', error);
            return res.status(500).json({ error: 'Unable to authenticate device' });
        }
    }

    async function requirePortalUser(req, res, next) {
        try {
            const authHeader = req.get('authorization') || '';
            const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
            const cookieToken = req.cookies?.[config.PORTAL_SESSION_COOKIE_NAME] || '';
            // Prefer the EXPLICIT token the client supplied (body/query/bearer = the
            // account the dashboard is acting as) over the cookie, so a leftover
            // cookie for a DIFFERENT account can't make this resolve to the wrong
            // user (same class of bug as the account-linking hijack).
            const explicitToken =
                req.body?.portal_session_token || req.query?.portal_session_token || bearerToken || '';
            const portalToken = pickValidPortalToken(cookieToken, explicitToken).token;

            if (!portalToken) {
                return res.status(401).json({ error: 'Portal session token is required' });
            }

            const session = verifyPortalSessionToken(portalToken);
            if (!session) {
                return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
            }

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
            if (!user) {
                return res.status(404).json({ error: 'Account not found' });
            }

            if (!portalTokenEpochMatches(session, user)) {
                return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
            }

            req.portalSession = session;
            req.portalUser = user;
            return next();
        } catch (error) {
            console.error('PORTAL AUTH ERROR:', error);
            return res.status(500).json({ error: 'Unable to authenticate account session' });
        }
    }

    async function requireGoogleBearer(req, res, next) {
        try {
            const authHeader = req.get('authorization') || '';
            if (!authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'Missing bearer token' });
            }

            const token = authHeader.slice(7).trim();
            const user = await googleCore.findUserByGoogleAccessToken(token);
            if (!user) {
                return res.status(401).json({ error: 'Invalid or expired access token' });
            }

            if (!user.google_home_enabled) {
                return res.status(403).json({ error: 'Google Home integration is disabled for this account' });
            }

            if (!utils.isAccessEnabled(user.status)) {
                return res.status(403).json({ error: 'Account is not active for Google integration' });
            }

            req.googleUser = user;
            req.googleAccessToken = token;
            return next();
        } catch (error) {
            console.error('GOOGLE AUTH ERROR:', error);
            return res.status(500).json({ error: 'Unable to authenticate Google request' });
        }
    }

    async function requireAlexaBearer(req, res, next) {
        try {
            const authHeader = req.get('authorization') || '';
            if (!authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'Missing bearer token' });
            }

            const token = authHeader.slice(7).trim();
            const user = await alexaCore.findUserByAlexaAccessToken(token);
            if (!user) {
                return res.status(401).json({ error: 'Invalid or expired access token' });
            }

            if (!user.alexa_enabled) {
                return res.status(403).json({ error: 'Alexa integration is disabled for this account' });
            }

            if (!utils.isAccessEnabled(user.status)) {
                return res.status(403).json({ error: 'Account is not active for Alexa integration' });
            }

            req.alexaUser = user;
            req.alexaAccessToken = token;
            return next();
        } catch (error) {
            console.error('ALEXA AUTH ERROR:', error);
            return res.status(500).json({ error: 'Unable to authenticate Alexa request' });
        }
    }

    function requireGoogleHomegraphAdmin(req, res, next) {
        const authHeader = req.get('authorization') || '';
        const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
        const adminToken = utils.sanitizeString(process.env.GOOGLE_HOMEGRAPH_ADMIN_TOKEN || '', 512) || '';

        if (!adminToken) {
            return res.status(503).json({ error: 'google_homegraph_admin_token_not_configured' });
        }

        if (!bearerToken || bearerToken !== adminToken) {
            return res.status(401).json({ error: 'invalid_homegraph_admin_token' });
        }

        return next();
    }

    return {
        getPortalSecret,
        signPortalValue,
        createPortalSessionToken,
        verifyPortalSessionToken,
        pickValidPortalToken,
        portalTokenEpochMatches,
        portalTokenNeedsRotation,
        setPortalSessionCookie,
        clearPortalSessionCookie,
        serializeUser,
        serializeUserWithPortalSession,
        serializeAdminUser,
        ensureBillingConfigured,
        ensureAdminConfigured,
        verifyAdminPassword,
        getAdminSecret,
        signAdminValue,
        createAdminToken,
        verifyAdminToken,
        createScopedAdminToken,
        verifyScopedAdminToken,
        computeSudoBind,
        requireAdmin,
        requireAdminSudo,
        requireDeviceAuth,
        requirePortalUser,
        requireGoogleBearer,
        requireAlexaBearer,
        requireGoogleHomegraphAdmin
    };
};
