require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const path = require('path');

const db = require('./db');

const app = express();
app.use(express.json({
    verify: (req, res, buf) => {
        if (buf && buf.length > 0) {
            req.rawBody = buf.toString();
        }
    }
}));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

let razorpayClient = null;

function generateToken() {
    return 'apx_' + crypto.randomBytes(16).toString('hex');
}

function dbGet(query, params = []) {
    return new Promise((resolve, reject) => {
        db.get(query, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function dbRun(query, params = []) {
    return new Promise((resolve, reject) => {
        db.run(query, params, function onRun(err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
}

function dbAll(query, params = []) {
    return new Promise((resolve, reject) => {
        db.all(query, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

async function createUniqueAccessToken() {
    while (true) {
        const candidate = generateToken();
        const existing = await dbGet(`SELECT id FROM users WHERE access_token = ?`, [candidate]);
        if (!existing) {
            return candidate;
        }
    }
}

function isAccessEnabled(status) {
    return status === 'active' || status === 'trial';
}

function getPortalSecret() {
    return process.env.PORTAL_SESSION_SECRET || process.env.ADMIN_SESSION_SECRET || process.env.RAZORPAY_KEY_SECRET || 'apex-portal-secret';
}

function signPortalValue(value) {
    return crypto.createHmac('sha256', getPortalSecret()).update(value).digest('hex');
}

function createPortalSessionToken(email) {
    const payload = Buffer.from(JSON.stringify({
        email,
        exp: Date.now() + (7 * 24 * 60 * 60 * 1000)
    })).toString('base64url');
    return `${payload}.${signPortalValue(payload)}`;
}

function verifyPortalSessionToken(token) {
    if (!token || !token.includes('.')) {
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
    } catch (error) {
        return null;
    }
}

function serializeUser(user) {
    const accessEnabled = isAccessEnabled(user.status);
    return {
        email: user.email,
        subdomain: user.subdomain,
        access_token: accessEnabled ? user.access_token : null,
        portal_session_token: createPortalSessionToken(user.email),
        status: user.status,
        domain: `${user.subdomain}.cloud.apexinfosys.in`,
        trial_ends_at: user.trial_ends_at,
        trial_approved_at: user.trial_approved_at,
        activated_at: user.activated_at,
        payment_pending: user.status === 'payment_pending'
    };
}

function serializeAdminUser(user) {
    return {
        id: user.id,
        email: user.email,
        subdomain: user.subdomain,
        domain: `${user.subdomain}.cloud.apexinfosys.in`,
        status: user.status,
        access_token: isAccessEnabled(user.status) ? user.access_token : null,
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
    return error?.error?.description ||
        error?.description ||
        error?.message ||
        error?.response?.data?.error?.description ||
        fallbackMessage;
}

function ensureAdminConfigured() {
    if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
        throw new Error('Admin credentials are not configured. Please set ADMIN_EMAIL and ADMIN_PASSWORD.');
    }
}

function getAdminSecret() {
    return process.env.ADMIN_SESSION_SECRET || process.env.RAZORPAY_KEY_SECRET || 'apex-admin-secret';
}

function signAdminValue(value) {
    return crypto.createHmac('sha256', getAdminSecret()).update(value).digest('hex');
}

function createAdminToken(email) {
    const payload = Buffer.from(JSON.stringify({
        email,
        exp: Date.now() + (8 * 60 * 60 * 1000)
    })).toString('base64url');
    return `${payload}.${signAdminValue(payload)}`;
}

function verifyAdminToken(token) {
    if (!token || !token.includes('.')) {
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
    } catch (error) {
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

async function getOrCreateCustomer(user) {
    const razorpay = getRazorpayClient();
    const customers = await razorpay.customers.all({ email: user.email });
    if (customers.items && customers.items.length > 0) {
        return customers.items[0];
    }

    return razorpay.customers.create({ email: user.email });
}

function buildCheckoutPayload(user, subscriptionId) {
    return {
        key: process.env.RAZORPAY_KEY_ID,
        subscription_id: subscriptionId,
        name: 'ApexOS Cloud',
        description: 'ApexOS Cloud annual remote access subscription',
        prefill: {
            email: user.email
        },
        notes: {
            subdomain: user.subdomain
        }
    };
}

async function prepareCheckoutForUser(user) {
    const razorpay = getRazorpayClient();

    const customer = await getOrCreateCustomer(user);
    // Always create a fresh checkout subscription for payment-pending users.
    // This avoids reusing stale live-mode IDs after switching to test mode,
    // or vice versa, which Razorpay reports as "The id provided does not exist".
    const subscription = await razorpay.subscriptions.create({
        plan_id: process.env.RAZORPAY_PLAN_ID,
        customer_id: customer.id,
        total_count: 100,
        customer_notify: 1,
        notes: {
            email: user.email,
            subdomain: user.subdomain
        }
    });

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
        checkout: buildCheckoutPayload(updatedUser, subscriptionId)
    };
}

function verifyPaymentSignature(paymentId, subscriptionId, signature) {
    const expectedSignature = crypto
        .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
        .update(`${paymentId}|${subscriptionId}`)
        .digest('hex');

    return expectedSignature === signature;
}

function verifyWebhookSignature(rawBody, signature) {
    if (!process.env.RAZORPAY_WEBHOOK_SECRET) {
        throw new Error('Razorpay webhook secret is not configured.');
    }

    const expectedSignature = crypto
        .createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET)
        .update(rawBody)
        .digest('hex');

    return expectedSignature === signature;
}

function extractWebhookSubscriptionInfo(payload) {
    const subscription = payload?.payload?.subscription?.entity || payload?.payload?.subscription || null;
    const payment = payload?.payload?.payment?.entity || payload?.payload?.payment || null;

    return {
        subscriptionId: subscription?.id || payment?.subscription_id || null,
        subscriptionStatus: subscription?.status || null,
        paymentId: payment?.id || null
    };
}

async function activateUserAccount(subscriptionId, paymentId, subscriptionStatus = 'active') {
    const user = await dbGet(`SELECT * FROM users WHERE razorpay_subscription_id = ?`, [subscriptionId]);
    if (!user) {
        return null;
    }

    const activatedAt = user.activated_at || new Date().toISOString();
    const accessToken = user.access_token || await createUniqueAccessToken();

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
        trialEndsAt = new Date(now.getTime() + (trialDays * 24 * 60 * 60 * 1000)).toISOString();
        activatedAt = activatedAt || nowIso;
        accessToken = accessToken || await createUniqueAccessToken();
    } else if (status === 'active') {
        trialEndsAt = null;
        activatedAt = activatedAt || nowIso;
        accessToken = accessToken || await createUniqueAccessToken();
    } else if (status === 'payment_pending') {
        trialEndsAt = null;
        trialApprovedAt = null;
        activatedAt = null;
        accessToken = null;
    } else if (status === 'expired' || status === 'suspended') {
        trialEndsAt = null;
        accessToken = null;
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

app.post('/api/auth/signup', async (req, res) => {
    const { email, password, subdomain } = req.body;

    if (!email || !password || !subdomain) {
        return res.status(400).json({ error: 'Email, password, and subdomain are required' });
    }

    if (!/^[a-z0-9\-]{3,20}$/.test(subdomain)) {
        return res.status(400).json({ error: 'Subdomain must be 3-20 lowercase letters, numbers, or hyphens.' });
    }

    try {
        const existingUser = await dbGet(`SELECT * FROM users WHERE email = ? OR subdomain = ?`, [email, subdomain]);
        if (existingUser) {
            const message = existingUser.status === 'payment_pending'
                ? 'Account already exists. Log in to complete payment.'
                : 'Email or subdomain already exists';
            return res.status(409).json({ error: message });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const insertResult = await dbRun(
            `
                INSERT INTO users (email, password, subdomain, status)
                VALUES (?, ?, ?, 'payment_pending')
            `,
            [email, hashedPassword, subdomain]
        );

        let user = await dbGet(`SELECT * FROM users WHERE id = ?`, [insertResult.lastID]);
        let checkout = null;
        let message = 'Account created. Complete payment to activate remote access.';

        try {
            const checkoutState = await prepareCheckoutForUser(user);
            user = checkoutState.user;
            checkout = checkoutState.checkout;
        } catch (billingError) {
            console.error('RAZORPAY CHECKOUT SETUP ERROR:', billingError);
            message = getBillingErrorMessage(
                billingError,
                'Account created, but billing setup is temporarily unavailable. Log in later to complete payment.'
            );
        }

        res.status(201).json({
            message,
            data: serializeUser(user),
            checkout
        });
    } catch (error) {
        console.error('SIGNUP ERROR:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [email]);
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        res.status(200).json({
            message: 'Login successful',
            data: serializeUser(user)
        });
    } catch (error) {
        console.error('LOGIN ERROR:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/billing/create-checkout', async (req, res) => {
    const { access_token, portal_session_token } = req.body;

    if (!access_token && !portal_session_token) {
        return res.status(400).json({ error: 'Portal session token is required' });
    }

    try {
        let user = null;
        if (access_token) {
            user = await dbGet(`SELECT * FROM users WHERE access_token = ?`, [access_token]);
        }

        if (!user && portal_session_token) {
            const session = verifyPortalSessionToken(portal_session_token);
            if (!session) {
                return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
            }
            user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
        }

        if (!user) {
            return res.status(404).json({ error: 'Account not found' });
        }

        if (user.status !== 'payment_pending') {
            return res.status(400).json({ error: 'This account does not require a payment checkout.' });
        }

        const checkoutState = await prepareCheckoutForUser(user);
        res.status(200).json({
            message: 'Checkout ready',
            data: serializeUser(checkoutState.user),
            checkout: checkoutState.checkout
        });
    } catch (error) {
        console.error('CHECKOUT CREATION ERROR:', error);
        res.status(502).json({
            error: getBillingErrorMessage(error, 'Unable to create Razorpay checkout right now.')
        });
    }
});

app.post('/api/billing/verify', async (req, res) => {
    const {
        razorpay_payment_id,
        razorpay_subscription_id,
        razorpay_signature
    } = req.body;

    if (!razorpay_payment_id || !razorpay_subscription_id || !razorpay_signature) {
        return res.status(400).json({ error: 'Missing Razorpay verification fields' });
    }

    try {
        ensureBillingConfigured();

        if (!verifyPaymentSignature(razorpay_payment_id, razorpay_subscription_id, razorpay_signature)) {
            return res.status(400).json({ error: 'Invalid Razorpay signature' });
        }

        const updatedUser = await activateUserAccount(
            razorpay_subscription_id,
            razorpay_payment_id,
            'active'
        );

        if (!updatedUser) {
            return res.status(404).json({ error: 'No account found for this subscription' });
        }

        res.status(200).json({
            message: 'Payment verified successfully',
            data: serializeUser(updatedUser)
        });
    } catch (error) {
        console.error('PAYMENT VERIFICATION ERROR:', error);
        res.status(500).json({ error: getBillingErrorMessage(error, 'Unable to verify payment') });
    }
});

app.post('/api/razorpay/webhook', async (req, res) => {
    const signature = req.get('x-razorpay-signature');

    try {
        if (!signature || !verifyWebhookSignature(req.rawBody || '', signature)) {
            return res.status(400).json({ error: 'Invalid webhook signature' });
        }

        const eventName = req.body.event;
        const info = extractWebhookSubscriptionInfo(req.body);

        if (!info.subscriptionId) {
            return res.status(200).json({ message: 'Webhook ignored' });
        }

        const user = await dbGet(`SELECT * FROM users WHERE razorpay_subscription_id = ?`, [info.subscriptionId]);
        if (!user) {
            return res.status(200).json({ message: 'No matching user for webhook event' });
        }

        if (['subscription.authenticated', 'subscription.activated', 'subscription.charged', 'payment.captured', 'invoice.paid'].includes(eventName)) {
            await activateUserAccount(info.subscriptionId, info.paymentId, info.subscriptionStatus || 'active');
        } else if (['subscription.cancelled', 'subscription.halted', 'subscription.paused'].includes(eventName)) {
            await updateUserStatus(user.id, 'suspended');
            await dbRun(`UPDATE users SET razorpay_subscription_status = ? WHERE id = ?`, [info.subscriptionStatus || eventName, user.id]);
        } else if (['subscription.completed', 'invoice.expired'].includes(eventName)) {
            await updateUserStatus(user.id, 'expired');
            await dbRun(`UPDATE users SET razorpay_subscription_status = ? WHERE id = ?`, [info.subscriptionStatus || eventName, user.id]);
        } else if (info.subscriptionStatus) {
            await dbRun(
                `UPDATE users SET razorpay_subscription_status = ? WHERE id = ?`,
                [info.subscriptionStatus, user.id]
            );
        }

        res.status(200).json({ received: true });
    } catch (error) {
        console.error('RAZORPAY WEBHOOK ERROR:', error);
        res.status(500).json({ error: getBillingErrorMessage(error, 'Webhook processing failed') });
    }
});

app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        ensureAdminConfigured();
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }

    if (email !== process.env.ADMIN_EMAIL || password !== process.env.ADMIN_PASSWORD) {
        return res.status(401).json({ error: 'Invalid admin credentials' });
    }

    res.status(200).json({
        message: 'Admin login successful',
        token: createAdminToken(email)
    });
});

app.get('/api/admin/me', requireAdmin, (req, res) => {
    res.status(200).json({
        email: req.admin.email
    });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const rows = await dbAll(`
            SELECT *
            FROM users
            ORDER BY
                CASE status
                    WHEN 'payment_pending' THEN 0
                    WHEN 'trial' THEN 1
                    WHEN 'active' THEN 2
                    WHEN 'suspended' THEN 3
                    WHEN 'expired' THEN 4
                    ELSE 5
                END,
                created_at DESC
        `);

        res.status(200).json({
            users: rows.map(serializeAdminUser)
        });
    } catch (error) {
        console.error('ADMIN USERS ERROR:', error);
        res.status(500).json({ error: 'Unable to load users' });
    }
});

app.post('/api/admin/users/:id/status', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { status, trial_days } = req.body;
    const allowedStatuses = ['payment_pending', 'active', 'trial', 'expired', 'suspended'];

    if (!allowedStatuses.includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    try {
        const updatedUser = await updateUserStatus(Number(id), status, {
            trialDays: Number(trial_days) || 365
        });

        if (!updatedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json({
            message: 'User status updated',
            user: serializeAdminUser(updatedUser)
        });
    } catch (error) {
        console.error('ADMIN STATUS UPDATE ERROR:', error);
        res.status(500).json({ error: 'Unable to update user status' });
    }
});

app.get('/api/internal/verify-domain', async (req, res) => {
    const { domain } = req.query;
    if (!domain) {
        return res.status(400).send('Domain missing');
    }

    const baseDomain = '.cloud.apexinfosys.in';
    if (!domain.endsWith(baseDomain)) {
        return res.status(403).send('Not our domain');
    }

    try {
        const subdomain = domain.replace(baseDomain, '');
        const row = await dbGet(`SELECT status FROM users WHERE subdomain = ?`, [subdomain]);

        if (!row) {
            return res.status(403).send('Domain not found');
        }

        if (isAccessEnabled(row.status)) {
            return res.status(200).send('OK');
        }

        return res.status(403).send('Subscription Expired/Suspended');
    } catch (error) {
        console.error('VERIFY DOMAIN ERROR:', error);
        return res.status(500).send('Internal error');
    }
});

app.post('/api/internal/verify-token', async (req, res) => {
    let body = req.body;
    if (body.content === undefined && Object.keys(body).length > 0) {
        try {
            if (typeof req.body === 'string') {
                body = JSON.parse(req.body);
            }
        } catch (error) {
            // Ignore parse fallback failures and use the original body.
        }
    }

    const op = body.op;
    const content = body.content || body;

    const reject = (reason) => res.status(200).json({ reject: true, reject_reason: reason });
    const accept = () => res.status(200).json({ reject: false, unchange: true });

    if (op !== 'Login') {
        return accept();
    }

    const token = content?.metas?.token ||
        content?.meta?.token ||
        content?.client_token ||
        content?.user ||
        content?.token ||
        content?.metadatas?.token ||
        (content?.custom_dict && content?.custom_dict.token) ||
        (content?.run_id && content.run_id);

    if (!token) {
        console.error('Token not found in payload:', JSON.stringify(content, null, 2));
        return reject('Missing Access Token. Received content keys: ' + Object.keys(content || {}).join(', '));
    }

    try {
        const row = await dbGet(`SELECT status FROM users WHERE access_token = ?`, [token]);
        if (!row) {
            return reject('Invalid Token');
        }

        if (isAccessEnabled(row.status)) {
            return accept();
        }

        return reject('Account not active');
    } catch (error) {
        console.error('VERIFY TOKEN ERROR:', error);
        return reject('Internal verification error');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Cloud Portal API is running on http://localhost:${PORT}`);
});
