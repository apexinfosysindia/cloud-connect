const crypto = require('crypto');

module.exports = function ({ dbGet, config, utils, device, googleCore }) {
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
            trial_ends_at: user.trial_ends_at,
            trial_approved_at: user.trial_approved_at,
            activated_at: user.activated_at,
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
            trial_ends_at: user.trial_ends_at,
            trial_approved_at: user.trial_approved_at,
            activated_at: user.activated_at,
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
            created_at: user.created_at
        };
    }

    function ensureBillingConfigured() {
        if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET || !process.env.RAZORPAY_PLAN_ID) {
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

    function requireAdmin(req, res, next) {
        try {
            ensureAdminConfigured();
        } catch (error) {
            return res.status(500).json({ error: error.message });
        }

        const authHeader = req.get('authorization') || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
        const session = verifyAdminToken(token);

        if (!session || session.email !== process.env.ADMIN_EMAIL) {
            return res.status(401).json({ error: 'Admin authentication required' });
        }

        req.admin = session;
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
            const portalToken =
                cookieToken || req.body?.portal_session_token || req.query?.portal_session_token || bearerToken;

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
        portalTokenEpochMatches,
        portalTokenNeedsRotation,
        setPortalSessionCookie,
        clearPortalSessionCookie,
        serializeUser,
        serializeUserWithPortalSession,
        serializeAdminUser,
        ensureBillingConfigured,
        ensureAdminConfigured,
        getAdminSecret,
        signAdminValue,
        createAdminToken,
        verifyAdminToken,
        requireAdmin,
        requireDeviceAuth,
        requirePortalUser,
        requireGoogleBearer,
        requireGoogleHomegraphAdmin
    };
};
