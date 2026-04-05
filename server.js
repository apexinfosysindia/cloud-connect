const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const express = require('express');
const cors = require('cors');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const db = require('./db');

const CUSTOMER_PORTAL_HOST = process.env.CUSTOMER_PORTAL_HOST || 'oasis.apexinfosys.in';
const ADMIN_PORTAL_HOST = process.env.ADMIN_PORTAL_HOST || 'vista.apexinfosys.in';
const CLOUD_BASE_DOMAIN = process.env.CLOUD_BASE_DOMAIN || 'cloud.apexinfosys.in';
const DEVICE_TUNNEL_HOST = process.env.DEVICE_TUNNEL_HOST || CLOUD_BASE_DOMAIN;
const ADMIN_SSH_JUMP_HOST = 'cloud.apexinfosys.in';
const ADMIN_SSH_JUMP_USER = 'fleetadmin';
const ADMIN_SSH_JUMP_PORT = 22;
const ADMIN_SSH_TARGET_HOST = '127.0.0.1';
const DEVICE_HEARTBEAT_TIMEOUT_SECONDS = Number(process.env.DEVICE_HEARTBEAT_TIMEOUT_SECONDS || 45);
const DEVICE_HEARTBEAT_INTERVAL_SECONDS = Number(process.env.DEVICE_HEARTBEAT_INTERVAL_SECONDS || 20);
const ADMIN_CONNECT_TOKEN_TTL_MINUTES = Number(process.env.ADMIN_CONNECT_TOKEN_TTL_MINUTES || 10);
const DEVICE_TUNNEL_PORT_MIN = Number(process.env.DEVICE_TUNNEL_PORT_MIN || 22000);
const DEVICE_TUNNEL_PORT_MAX = Number(process.env.DEVICE_TUNNEL_PORT_MAX || 22999);
const DEVICE_TOKEN_PREFIX = 'dvc_';
const ADMIN_CONNECT_TOKEN_PREFIX = 'acn_';

const app = express();
app.use(express.json({
    verify: (req, res, buf) => {
        if (buf && buf.length > 0) {
            req.rawBody = buf.toString();
        }
    }
}));
app.use(cors());

app.get(['/login', '/login.html', '/signup', '/signup.html'], (req, res, next) => {
    const isSignupPath = req.path.startsWith('/signup');
    const targetPath = isSignupPath ? '/signup.html' : '/login.html';

    if (req.hostname === CUSTOMER_PORTAL_HOST) {
        if (req.path === '/login' || req.path === '/signup') {
            return res.redirect(targetPath);
        }
        return next();
    }

    if (req.hostname === ADMIN_PORTAL_HOST || req.hostname === CLOUD_BASE_DOMAIN) {
        return res.redirect(`https://${CUSTOMER_PORTAL_HOST}${targetPath}`);
    }

    return next();
});

app.get(['/admin', '/admin.html'], (req, res, next) => {
    if (req.hostname === ADMIN_PORTAL_HOST) {
        return res.redirect('/');
    }

    if (req.hostname === CUSTOMER_PORTAL_HOST || req.hostname === CLOUD_BASE_DOMAIN) {
        return res.redirect(`https://${ADMIN_PORTAL_HOST}/`);
    }

    return next();
});

app.get('/index.html', (req, res) => {
    if (req.hostname === ADMIN_PORTAL_HOST || req.hostname === CUSTOMER_PORTAL_HOST) {
        return res.redirect('/');
    }

    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/', (req, res) => {
    if (req.hostname === ADMIN_PORTAL_HOST) {
        return res.sendFile(path.join(__dirname, 'public', 'admin.html'));
    }

    if (req.hostname === CUSTOMER_PORTAL_HOST) {
        return res.sendFile(path.join(__dirname, 'public', 'login.html'));
    }

    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use(express.static(path.join(__dirname, 'public'), { index: false }));

let razorpayClient = null;

function generateToken() {
    return 'apx_' + crypto.randomBytes(16).toString('hex');
}

function hashSecret(value) {
    return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function generateDeviceAuthToken() {
    return DEVICE_TOKEN_PREFIX + crypto.randomBytes(24).toString('hex');
}

function generateAdminConnectToken() {
    return ADMIN_CONNECT_TOKEN_PREFIX + crypto.randomBytes(24).toString('hex');
}

function sanitizeString(value, maxLength = 120) {
    if (typeof value !== 'string') {
        return null;
    }

    const normalized = value.trim();
    if (!normalized) {
        return null;
    }

    return normalized.slice(0, maxLength);
}

function sanitizeDeviceUid(value) {
    const normalized = sanitizeString(value, 80);
    if (!normalized) {
        return null;
    }

    return /^[a-zA-Z0-9._-]+$/.test(normalized) ? normalized : null;
}

function sanitizeDeviceName(value) {
    const normalized = sanitizeString(value, 120);
    if (!normalized) {
        return null;
    }

    return normalized.replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim();
}

function sanitizeSshHost(value, maxLength = 255) {
    const normalized = sanitizeString(value, maxLength);
    if (!normalized) {
        return null;
    }

    return /^[a-zA-Z0-9._:-]+$/.test(normalized) ? normalized : null;
}

function sanitizeSshUser(value) {
    const normalized = sanitizeString(value, 48);
    if (!normalized) {
        return null;
    }

    return /^[a-z_][a-z0-9_-]*$/i.test(normalized) ? normalized : null;
}

function sanitizeEventType(value) {
    const normalized = sanitizeString(value, 64);
    if (!normalized) {
        return null;
    }

    return /^[a-z0-9._-]+$/i.test(normalized) ? normalized.toLowerCase() : null;
}

function sanitizePort(value) {
    if (value === null || value === undefined || value === '') {
        return null;
    }

    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
        return null;
    }

    return parsed;
}

function normalizeLocalIps(value) {
    const entries = [];

    if (Array.isArray(value)) {
        entries.push(...value);
    } else if (typeof value === 'string') {
        entries.push(...value.split(/[\s,]+/g));
    }

    const unique = [];
    for (const entry of entries) {
        const candidate = String(entry || '').trim();
        if (!candidate) {
            continue;
        }

        if (!/^[0-9a-fA-F:.]+$/.test(candidate)) {
            continue;
        }

        if (!unique.includes(candidate)) {
            unique.push(candidate);
        }
    }

    return unique.slice(0, 8).join(',') || null;
}

function parseJsonSafe(value, fallback = null) {
    if (!value) {
        return fallback;
    }

    if (typeof value === 'object') {
        return value;
    }

    try {
        return JSON.parse(value);
    } catch (error) {
        return fallback;
    }
}

function getHeartbeatWindowSeconds() {
    if (!Number.isFinite(DEVICE_HEARTBEAT_TIMEOUT_SECONDS)) {
        return 45;
    }

    return Math.max(20, Math.min(300, Math.round(DEVICE_HEARTBEAT_TIMEOUT_SECONDS)));
}

function isDeviceOnline(lastSeenAt) {
    if (!lastSeenAt) {
        return false;
    }

    const lastSeenEpoch = new Date(lastSeenAt).getTime();
    if (!Number.isFinite(lastSeenEpoch)) {
        return false;
    }

    return (Date.now() - lastSeenEpoch) <= (getHeartbeatWindowSeconds() * 1000);
}

function getHeartbeatIntervalSeconds() {
    if (!Number.isFinite(DEVICE_HEARTBEAT_INTERVAL_SECONDS)) {
        return 20;
    }

    return Math.max(10, Math.min(120, Math.round(DEVICE_HEARTBEAT_INTERVAL_SECONDS)));
}

function getAdminConnectTokenTtlMinutes() {
    if (!Number.isFinite(ADMIN_CONNECT_TOKEN_TTL_MINUTES)) {
        return 10;
    }

    return Math.max(3, Math.min(60, Math.round(ADMIN_CONNECT_TOKEN_TTL_MINUTES)));
}

function getDeviceTunnelPortRange() {
    let min = Number.isFinite(DEVICE_TUNNEL_PORT_MIN) ? Math.round(DEVICE_TUNNEL_PORT_MIN) : 22000;
    let max = Number.isFinite(DEVICE_TUNNEL_PORT_MAX) ? Math.round(DEVICE_TUNNEL_PORT_MAX) : 22999;

    min = Math.max(1025, Math.min(65000, min));
    max = Math.max(1025, Math.min(65535, max));

    if (max < min) {
        max = min;
    }

    if ((max - min) < 32) {
        max = Math.min(65535, min + 255);
    }

    return { min, max };
}

function isDeviceTunnelPortInRange(port) {
    if (!Number.isInteger(port)) {
        return false;
    }

    const { min, max } = getDeviceTunnelPortRange();
    return port >= min && port <= max;
}

function getAdminSshRoute() {
    const jumpHost = sanitizeSshHost(ADMIN_SSH_JUMP_HOST) || sanitizeSshHost(DEVICE_TUNNEL_HOST) || CLOUD_BASE_DOMAIN;
    const jumpUser = sanitizeSshUser(ADMIN_SSH_JUMP_USER) || 'root';
    const jumpPort = sanitizePort(ADMIN_SSH_JUMP_PORT) || 22;
    const targetHost = sanitizeSshHost(ADMIN_SSH_TARGET_HOST) || '127.0.0.1';

    return {
        method: 'proxyjump',
        jump_host: jumpHost,
        jump_user: jumpUser,
        jump_port: jumpPort,
        target_host: targetHost,
        target_user: 'root'
    };
}

async function allocateDeviceTunnelPort(excludedDeviceId = null) {
    const { min, max } = getDeviceTunnelPortRange();
    const rows = excludedDeviceId
        ? await dbAll(
            `
                SELECT tunnel_port
                FROM devices
                WHERE tunnel_port IS NOT NULL
                  AND tunnel_port BETWEEN ? AND ?
                  AND id != ?
                ORDER BY tunnel_port ASC
            `,
            [min, max, excludedDeviceId]
        )
        : await dbAll(
            `
                SELECT tunnel_port
                FROM devices
                WHERE tunnel_port IS NOT NULL
                  AND tunnel_port BETWEEN ? AND ?
                ORDER BY tunnel_port ASC
            `,
            [min, max]
        );

    const usedPorts = new Set(
        (rows || [])
            .map((row) => Number(row.tunnel_port))
            .filter((port) => Number.isInteger(port) && port >= min && port <= max)
    );

    for (let port = min; port <= max; port += 1) {
        if (!usedPorts.has(port)) {
            return port;
        }
    }

    return null;
}

function serializeDevice(row) {
    const ownerDomain = row.user_subdomain ? `${row.user_subdomain}.${CLOUD_BASE_DOMAIN}` : null;
    const online = isDeviceOnline(row.last_seen_at);
    const accountEnabled = isAccessEnabled(row.user_status);
    const connectReady = accountEnabled && isDeviceTunnelPortInRange(sanitizePort(row.tunnel_port));
    const sshRoute = getAdminSshRoute();

    return {
        id: row.id,
        owner: {
            user_id: row.user_id,
            email: row.user_email,
            status: row.user_status,
            domain: ownerDomain
        },
        device_uid: row.device_uid,
        device_name: row.device_name,
        admin_name_override: Boolean(row.admin_name_override),
        hostname: row.hostname,
        local_ips: row.local_ips ? row.local_ips.split(',').filter(Boolean) : [],
        ssh_port: row.ssh_port || 22,
        remote_user: row.remote_user || 'root',
        tunnel_host: row.tunnel_host,
        tunnel_port: row.tunnel_port,
        ssh_route: sshRoute,
        addon_version: row.addon_version,
        agent_state: row.agent_state,
        online,
        connect_ready: connectReady,
        account_enabled: accountEnabled,
        last_seen_at: row.last_seen_at,
        created_at: row.created_at,
        updated_at: row.updated_at
    };
}

async function insertDeviceLog(deviceId, level, eventType, message, payload = null) {
    const normalizedLevel = ['info', 'warn', 'error'].includes(level) ? level : 'info';
    const normalizedEventType = sanitizeEventType(eventType) || 'event';
    const normalizedMessage = sanitizeString(message, 400) || 'Device event';
    const payloadText = payload ? JSON.stringify(payload).slice(0, 2000) : null;

    await dbRun(
        `
            INSERT INTO device_logs (device_id, level, event_type, message, payload)
            VALUES (?, ?, ?, ?, ?)
        `,
        [deviceId, normalizedLevel, normalizedEventType, normalizedMessage, payloadText]
    );

    await dbRun(
        `
            DELETE FROM device_logs
            WHERE device_id = ?
              AND id NOT IN (
                SELECT id FROM device_logs WHERE device_id = ? ORDER BY id DESC LIMIT 250
              )
        `,
        [deviceId, deviceId]
    );
}

async function insertAdminAccessLog(deviceId, adminEmail, action, details = null) {
    await dbRun(
        `
            INSERT INTO admin_access_logs (device_id, admin_email, action, details)
            VALUES (?, ?, ?, ?)
        `,
        [deviceId || null, adminEmail, action, details ? JSON.stringify(details).slice(0, 2000) : null]
    );
}

async function findDeviceByToken(deviceToken) {
    if (!deviceToken) {
        return null;
    }

    const tokenHash = hashSecret(deviceToken);
    return dbGet(
        `
            SELECT
                d.*,
                u.id AS user_id,
                u.email AS user_email,
                u.status AS user_status,
                u.subdomain AS user_subdomain
            FROM devices d
            INNER JOIN users u ON u.id = d.user_id
            WHERE d.device_token_hash = ?
        `,
        [tokenHash]
    );
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
    const hasSubdomain = Boolean(user.subdomain);
    return {
        email: user.email,
        subdomain: user.subdomain,
        access_token: accessEnabled ? user.access_token : null,
        portal_session_token: createPortalSessionToken(user.email),
        status: user.status,
        domain: hasSubdomain ? `${user.subdomain}.${CLOUD_BASE_DOMAIN}` : null,
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
        domain: hasSubdomain ? `${user.subdomain}.${CLOUD_BASE_DOMAIN}` : null,
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

async function requireDeviceAuth(req, res, next) {
    try {
        const authHeader = req.get('authorization') || '';
        const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
        const deviceToken = req.get('x-device-token') || bearerToken || req.body?.device_token || '';

        if (!deviceToken) {
            return res.status(401).json({ error: 'Device token is required' });
        }

        const device = await findDeviceByToken(deviceToken);
        if (!device) {
            return res.status(401).json({ error: 'Invalid device token' });
        }

        req.deviceAuthToken = deviceToken;
        req.device = device;
        return next();
    } catch (error) {
        console.error('DEVICE AUTH ERROR:', error);
        return res.status(500).json({ error: 'Unable to authenticate device' });
    }
}

function buildAdminConnectCommand(device) {
    const tunnelPort = sanitizePort(device.tunnel_port);
    const sshRoute = getAdminSshRoute();

    if (!tunnelPort || !isDeviceTunnelPortInRange(tunnelPort)) {
        return null;
    }

    const jumpSpec = sshRoute.jump_port === 22
        ? `${sshRoute.jump_user}@${sshRoute.jump_host}`
        : `${sshRoute.jump_user}@${sshRoute.jump_host}:${sshRoute.jump_port}`;

    return `ssh -J ${jumpSpec} -p ${tunnelPort} ${sshRoute.target_user}@${sshRoute.target_host}`;
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
            subdomain: user.subdomain || ''
        }
    };
}

async function prepareCheckoutForUser(user) {
    if (user.status === 'active' || ['active', 'authenticated', 'charged'].includes((user.razorpay_subscription_status || '').toLowerCase())) {
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

function parsePositiveInt(value) {
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed <= 0) {
        return null;
    }

    return parsed;
}

async function getDeviceWithOwnerById(deviceId) {
    return dbGet(
        `
            SELECT
                d.*,
                u.id AS user_id,
                u.email AS user_email,
                u.status AS user_status,
                u.subdomain AS user_subdomain
            FROM devices d
            INNER JOIN users u ON u.id = d.user_id
            WHERE d.id = ?
        `,
        [deviceId]
    );
}

app.post('/api/internal/devices/register', async (req, res) => {
    const accessToken = sanitizeString(req.body?.access_token, 180);
    const deviceUid = sanitizeDeviceUid(req.body?.device_uid);

    if (!accessToken || !deviceUid) {
        return res.status(400).json({ error: 'access_token and device_uid are required' });
    }

    try {
        const user = await dbGet(`SELECT * FROM users WHERE access_token = ?`, [accessToken]);

        if (!user) {
            return res.status(404).json({ error: 'No account found for this access token' });
        }

        if (!isAccessEnabled(user.status)) {
            return res.status(403).json({ error: 'Account is not active for remote access' });
        }

        const nowIso = new Date().toISOString();
        const deviceToken = generateDeviceAuthToken();
        const deviceTokenHash = hashSecret(deviceToken);
        const incomingDeviceName = sanitizeDeviceName(req.body?.device_name);
        const hostname = sanitizeString(req.body?.hostname, 120);
        const localIps = normalizeLocalIps(req.body?.local_ips);
        const sshPort = sanitizePort(req.body?.ssh_port) || 22;
        const remoteUser = 'root';
        const addonVersion = sanitizeString(req.body?.addon_version, 64);
        const agentState = sanitizeString(req.body?.agent_state, 64);
        const defaultDeviceName = incomingDeviceName || hostname || deviceUid;

        const existing = await dbGet(
            `SELECT id, device_name, admin_name_override, tunnel_host, tunnel_port FROM devices WHERE user_id = ? AND device_uid = ?`,
            [user.id, deviceUid]
        );

        let deviceId;
        let assignedTunnelHost = null;
        let assignedTunnelPort = null;

        if (existing) {
            const preservedName = existing.admin_name_override
                ? sanitizeDeviceName(existing.device_name)
                : null;
            const nextDeviceName = preservedName || incomingDeviceName || sanitizeDeviceName(existing.device_name) || defaultDeviceName;
            assignedTunnelHost = sanitizeString(existing.tunnel_host, 255) || DEVICE_TUNNEL_HOST;
            assignedTunnelPort = sanitizePort(existing.tunnel_port);
            if (!assignedTunnelPort || !isDeviceTunnelPortInRange(assignedTunnelPort)) {
                assignedTunnelPort = await allocateDeviceTunnelPort(existing.id);
            }

            await dbRun(
                `
                    UPDATE devices
                    SET device_name = ?,
                        hostname = ?,
                        local_ips = ?,
                        ssh_port = ?,
                        remote_user = ?,
                        tunnel_host = ?,
                        tunnel_port = ?,
                        addon_version = ?,
                        agent_state = ?,
                        device_token_hash = ?,
                        last_seen_at = ?,
                        updated_at = ?
                    WHERE id = ?
                `,
                [
                    nextDeviceName,
                    hostname,
                    localIps,
                    sshPort,
                    remoteUser,
                    assignedTunnelHost,
                    assignedTunnelPort,
                    addonVersion,
                    agentState,
                    deviceTokenHash,
                    nowIso,
                    nowIso,
                    existing.id
                ]
            );
            deviceId = existing.id;
        } else {
            assignedTunnelHost = DEVICE_TUNNEL_HOST;
            assignedTunnelPort = await allocateDeviceTunnelPort();

            const insertResult = await dbRun(
                `
                    INSERT INTO devices (
                        user_id,
                        device_uid,
                        device_name,
                        hostname,
                        local_ips,
                        ssh_port,
                        remote_user,
                        tunnel_host,
                        tunnel_port,
                        addon_version,
                        agent_state,
                        device_token_hash,
                        last_seen_at,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `,
                [
                    user.id,
                    deviceUid,
                    defaultDeviceName,
                    hostname,
                    localIps,
                    sshPort,
                    remoteUser,
                    assignedTunnelHost,
                    assignedTunnelPort,
                    addonVersion,
                    agentState,
                    deviceTokenHash,
                    nowIso,
                    nowIso,
                    nowIso
                ]
            );
            deviceId = insertResult.lastID;
        }

        await insertDeviceLog(
            deviceId,
            'info',
            existing ? 'device.re_register' : 'device.register',
            existing ? 'Device registration refreshed' : 'Device registered',
            {
                device_uid: deviceUid,
                hostname,
                addon_version: addonVersion,
                tunnel_host: assignedTunnelHost,
                tunnel_port: assignedTunnelPort
            }
        );

        const deviceRow = await getDeviceWithOwnerById(deviceId);

        return res.status(existing ? 200 : 201).json({
            message: existing ? 'Device registration updated' : 'Device registered',
            device_token: deviceToken,
            heartbeat_interval_seconds: getHeartbeatIntervalSeconds(),
            data: serializeDevice(deviceRow)
        });
    } catch (error) {
        console.error('DEVICE REGISTER ERROR:', error);
        return res.status(500).json({ error: 'Unable to register device' });
    }
});

app.post('/api/internal/devices/heartbeat', requireDeviceAuth, async (req, res) => {
    try {
        const nowIso = new Date().toISOString();
        const body = req.body || {};
        const hasOwn = Object.prototype.hasOwnProperty;
        const current = req.device;
        const currentAdminOverride = Number(current.admin_name_override || 0) === 1;

        const incomingDeviceName = hasOwn.call(body, 'device_name')
            ? sanitizeDeviceName(body.device_name)
            : sanitizeDeviceName(current.device_name);
        const deviceName = currentAdminOverride
            ? sanitizeDeviceName(current.device_name)
            : incomingDeviceName;
        const hostname = hasOwn.call(body, 'hostname')
            ? sanitizeString(body.hostname, 120)
            : current.hostname;
        const localIps = hasOwn.call(body, 'local_ips')
            ? normalizeLocalIps(body.local_ips)
            : current.local_ips;

        const nextSshPort = hasOwn.call(body, 'ssh_port')
            ? (sanitizePort(body.ssh_port) || current.ssh_port || 22)
            : (current.ssh_port || 22);

        const nextRemoteUser = 'root';

        const tunnelHost = sanitizeString(current.tunnel_host, 255) || DEVICE_TUNNEL_HOST;
        let nextTunnelPort = sanitizePort(current.tunnel_port);
        if (!nextTunnelPort || !isDeviceTunnelPortInRange(nextTunnelPort)) {
            nextTunnelPort = await allocateDeviceTunnelPort(current.id);
        }

        const addonVersion = hasOwn.call(body, 'addon_version')
            ? sanitizeString(body.addon_version, 64)
            : current.addon_version;

        const agentState = hasOwn.call(body, 'agent_state')
            ? sanitizeString(body.agent_state, 64)
            : current.agent_state;

        await dbRun(
            `
                UPDATE devices
                SET device_name = ?,
                    hostname = ?,
                    local_ips = ?,
                    ssh_port = ?,
                    remote_user = ?,
                    tunnel_host = ?,
                    tunnel_port = ?,
                    addon_version = ?,
                    agent_state = ?,
                    last_seen_at = ?,
                    updated_at = ?
                WHERE id = ?
            `,
            [
                deviceName,
                hostname,
                localIps,
                nextSshPort,
                nextRemoteUser,
                tunnelHost,
                nextTunnelPort,
                addonVersion,
                agentState,
                nowIso,
                nowIso,
                current.id
            ]
        );

        if (agentState && agentState !== current.agent_state) {
            await insertDeviceLog(
                current.id,
                'info',
                'device.state',
                `Agent state changed to ${agentState}`,
                {
                    previous_state: current.agent_state,
                    current_state: agentState
                }
            );
        }

        const updated = await getDeviceWithOwnerById(current.id);

        return res.status(200).json({
            message: 'Heartbeat accepted',
            heartbeat_interval_seconds: getHeartbeatIntervalSeconds(),
            data: serializeDevice(updated)
        });
    } catch (error) {
        console.error('DEVICE HEARTBEAT ERROR:', error);
        return res.status(500).json({ error: 'Unable to process heartbeat' });
    }
});

app.post('/api/internal/devices/log', requireDeviceAuth, async (req, res) => {
    try {
        const level = sanitizeString(req.body?.level, 12)?.toLowerCase() || 'info';
        const eventType = sanitizeEventType(req.body?.event_type);
        const message = sanitizeString(req.body?.message, 400);
        const payload = req.body?.payload || null;

        if (!eventType || !message) {
            return res.status(400).json({ error: 'event_type and message are required' });
        }

        await insertDeviceLog(req.device.id, level, eventType, message, payload);

        const nowIso = new Date().toISOString();
        await dbRun(
            `
                UPDATE devices
                SET last_seen_at = ?,
                    updated_at = ?
                WHERE id = ?
            `,
            [nowIso, nowIso, req.device.id]
        );

        return res.status(200).json({ message: 'Log stored' });
    } catch (error) {
        console.error('DEVICE LOG ERROR:', error);
        return res.status(500).json({ error: 'Unable to store device log' });
    }
});

app.get('/api/admin/fleet', requireAdmin, async (req, res) => {
    try {
        await dbRun(`DELETE FROM admin_connect_sessions WHERE expires_at < ?`, [new Date().toISOString()]);

        const rows = await dbAll(
            `
                SELECT
                    d.*,
                    u.id AS user_id,
                    u.email AS user_email,
                    u.status AS user_status,
                    u.subdomain AS user_subdomain,
                    (
                        SELECT COUNT(*)
                        FROM device_logs dl
                        WHERE dl.device_id = d.id
                    ) AS log_count,
                    (
                        SELECT dl.level
                        FROM device_logs dl
                        WHERE dl.device_id = d.id
                        ORDER BY dl.id DESC
                        LIMIT 1
                    ) AS last_event_level,
                    (
                        SELECT dl.event_type
                        FROM device_logs dl
                        WHERE dl.device_id = d.id
                        ORDER BY dl.id DESC
                        LIMIT 1
                    ) AS last_event_type,
                    (
                        SELECT dl.message
                        FROM device_logs dl
                        WHERE dl.device_id = d.id
                        ORDER BY dl.id DESC
                        LIMIT 1
                    ) AS last_event_message,
                    (
                        SELECT dl.created_at
                        FROM device_logs dl
                        WHERE dl.device_id = d.id
                        ORDER BY dl.id DESC
                        LIMIT 1
                    ) AS last_event_at
                FROM devices d
                INNER JOIN users u ON u.id = d.user_id
                ORDER BY d.last_seen_at DESC, d.updated_at DESC, d.created_at DESC
            `
        );

        const devices = rows.map((row) => {
            const data = serializeDevice(row);
            return {
                ...data,
                log_count: Number(row.log_count || 0),
                last_event: row.last_event_at
                    ? {
                        level: row.last_event_level,
                        event_type: row.last_event_type,
                        message: row.last_event_message,
                        created_at: row.last_event_at
                    }
                    : null
            };
        });

        const stats = {
            total: devices.length,
            online: devices.filter((device) => device.online).length,
            offline: devices.filter((device) => !device.online).length,
            connect_ready: devices.filter((device) => device.connect_ready).length,
            blocked: devices.filter((device) => !device.account_enabled).length
        };

        return res.status(200).json({
            stats,
            heartbeat_window_seconds: getHeartbeatWindowSeconds(),
            devices
        });
    } catch (error) {
        console.error('ADMIN FLEET LIST ERROR:', error);
        return res.status(500).json({ error: 'Unable to load fleet devices' });
    }
});

app.get('/api/admin/fleet/:id/logs', requireAdmin, async (req, res) => {
    const deviceId = parsePositiveInt(req.params.id);
    const requestedLimit = Number(req.query.limit);
    const limit = Number.isFinite(requestedLimit)
        ? Math.max(10, Math.min(200, Math.round(requestedLimit)))
        : 60;

    if (!deviceId) {
        return res.status(400).json({ error: 'Invalid device id' });
    }

    try {
        const device = await getDeviceWithOwnerById(deviceId);
        if (!device) {
            return res.status(404).json({ error: 'Device not found' });
        }

        const deviceLogs = await dbAll(
            `
                SELECT id, level, event_type, message, payload, created_at
                FROM device_logs
                WHERE device_id = ?
                ORDER BY id DESC
                LIMIT ?
            `,
            [deviceId, limit]
        );

        const adminLogs = await dbAll(
            `
                SELECT id, admin_email, action, details, created_at
                FROM admin_access_logs
                WHERE device_id = ?
                ORDER BY id DESC
                LIMIT ?
            `,
            [deviceId, Math.max(10, Math.min(100, Math.round(limit / 2)))]
        );

        return res.status(200).json({
            device: serializeDevice(device),
            logs: deviceLogs.map((entry) => ({
                id: entry.id,
                level: entry.level,
                event_type: entry.event_type,
                message: entry.message,
                payload: parseJsonSafe(entry.payload, entry.payload),
                created_at: entry.created_at
            })),
            admin_actions: adminLogs.map((entry) => ({
                id: entry.id,
                admin_email: entry.admin_email,
                action: entry.action,
                details: parseJsonSafe(entry.details, entry.details),
                created_at: entry.created_at
            }))
        });
    } catch (error) {
        console.error('ADMIN FLEET LOGS ERROR:', error);
        return res.status(500).json({ error: 'Unable to load device logs' });
    }
});

app.post('/api/admin/fleet/:id/name', requireAdmin, async (req, res) => {
    const deviceId = parsePositiveInt(req.params.id);
    if (!deviceId) {
        return res.status(400).json({ error: 'Invalid device id' });
    }

    const rawName = sanitizeString(req.body?.device_name, 120);
    if (!rawName) {
        return res.status(400).json({ error: 'device_name is required' });
    }

    const deviceName = sanitizeDeviceName(rawName);
    if (!deviceName) {
        return res.status(400).json({ error: 'device_name is invalid' });
    }

    try {
        const device = await getDeviceWithOwnerById(deviceId);
        if (!device) {
            return res.status(404).json({ error: 'Device not found' });
        }

        const nowIso = new Date().toISOString();
        await dbRun(
            `
                UPDATE devices
                SET device_name = ?,
                    admin_name_override = 1,
                    updated_at = ?
                WHERE id = ?
            `,
            [deviceName, nowIso, deviceId]
        );

        await insertAdminAccessLog(deviceId, req.admin.email, 'device_rename', {
            previous_name: device.device_name || null,
            next_name: deviceName,
            device_uid: device.device_uid
        });

        await insertDeviceLog(
            deviceId,
            'info',
            'admin.rename',
            `Admin ${req.admin.email} renamed device to ${deviceName}`,
            {
                previous_name: device.device_name || null,
                next_name: deviceName
            }
        );

        const updated = await getDeviceWithOwnerById(deviceId);
        return res.status(200).json({
            message: 'Device name updated',
            device: serializeDevice(updated)
        });
    } catch (error) {
        console.error('ADMIN FLEET RENAME ERROR:', error);
        return res.status(500).json({ error: 'Unable to update device name' });
    }
});

app.post('/api/admin/fleet/:id/connect', requireAdmin, async (req, res) => {
    const deviceId = parsePositiveInt(req.params.id);

    if (!deviceId) {
        return res.status(400).json({ error: 'Invalid device id' });
    }

    try {
        const device = await getDeviceWithOwnerById(deviceId);
        if (!device) {
            return res.status(404).json({ error: 'Device not found' });
        }

        if (!isAccessEnabled(device.user_status)) {
            return res.status(403).json({ error: 'Owner account is not active for remote access' });
        }

        const command = buildAdminConnectCommand(device);

        if (!command) {
            return res.status(409).json({ error: 'Device tunnel is not ready. Wait for next heartbeat.' });
        }

        const reason = sanitizeString(req.body?.reason, 200);
        const connectToken = generateAdminConnectToken();
        const connectTokenHash = hashSecret(connectToken);
        const ttlMinutes = getAdminConnectTokenTtlMinutes();
        const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();
        await dbRun(`DELETE FROM admin_connect_sessions WHERE expires_at < ?`, [new Date().toISOString()]);
        await dbRun(
            `
                INSERT INTO admin_connect_sessions (
                    device_id,
                    admin_email,
                    token_hash,
                    expires_at,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
            `,
            [deviceId, req.admin.email, connectTokenHash, expiresAt, new Date().toISOString()]
        );

        await insertAdminAccessLog(deviceId, req.admin.email, 'connect_command_issued', {
            reason: reason || null,
            device_uid: device.device_uid,
            tunnel_host: device.tunnel_host,
            tunnel_port: device.tunnel_port,
            ssh_route: getAdminSshRoute(),
            remote_user: 'root',
            ttl_minutes: ttlMinutes
        });

        await insertDeviceLog(
            deviceId,
            'info',
            'admin.connect',
            `Admin ${req.admin.email} generated an SSH connect command`,
            {
                reason: reason || null,
                expires_at: expiresAt,
                ssh_route: getAdminSshRoute()
            }
        );

        return res.status(200).json({
            device: serializeDevice(device),
            connect: {
                token: connectToken,
                expires_at: expiresAt,
                command,
                note: 'Token is issued for admin session tracking and rotates on each connect request.'
            }
        });
    } catch (error) {
        console.error('ADMIN CONNECT ERROR:', error);
        return res.status(500).json({ error: 'Unable to create connect command right now' });
    }
});

app.post('/api/auth/signup', async (req, res) => {
    const { email, password, subdomain } = req.body;
    const normalizedSubdomain = String(subdomain || '').trim().toLowerCase() || null;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    if (normalizedSubdomain && !/^[a-z0-9\-]{3,20}$/.test(normalizedSubdomain)) {
        return res.status(400).json({ error: 'Subdomain must be 3-20 lowercase letters, numbers, or hyphens.' });
    }

    try {
        const existingUser = normalizedSubdomain
            ? await dbGet(`SELECT * FROM users WHERE email = ? OR subdomain = ?`, [email, normalizedSubdomain])
            : await dbGet(`SELECT * FROM users WHERE email = ?`, [email]);

        if (existingUser) {
            const message = existingUser.email === email
                ? (existingUser.status === 'payment_pending'
                    ? 'Account already exists. Log in to continue setup.'
                    : 'Email already exists')
                : 'Cloud address is already in use';
            return res.status(409).json({ error: message });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const insertResult = await dbRun(
            `
                INSERT INTO users (email, password, subdomain, status)
                VALUES (?, ?, ?, 'payment_pending')
            `,
            [email, hashedPassword, normalizedSubdomain]
        );

        let user = await dbGet(`SELECT * FROM users WHERE id = ?`, [insertResult.lastID]);
        let checkout = null;
        let message = user.subdomain
            ? 'Account created. Complete payment to activate remote access.'
            : 'Account created. Set your desired cloud address to continue activation.';

        if (user.subdomain) {
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

app.post('/api/account/subdomain', async (req, res) => {
    const { portal_session_token, subdomain } = req.body;

    if (!portal_session_token) {
        return res.status(400).json({ error: 'Portal session token is required' });
    }

    const normalizedSubdomain = String(subdomain || '').trim().toLowerCase();
    if (!/^[a-z0-9\-]{3,20}$/.test(normalizedSubdomain)) {
        return res.status(400).json({ error: 'Subdomain must be 3-20 lowercase letters, numbers, or hyphens.' });
    }

    try {
        const session = verifyPortalSessionToken(portal_session_token);
        if (!session) {
            return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
        }

        const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
        if (!user) {
            return res.status(404).json({ error: 'Account not found' });
        }

        if (user.subdomain === normalizedSubdomain) {
            return res.status(200).json({
                message: 'Cloud address saved',
                data: serializeUser(user)
            });
        }

        const existing = await dbGet(`SELECT id FROM users WHERE subdomain = ? AND id != ?`, [normalizedSubdomain, user.id]);
        if (existing) {
            return res.status(409).json({ error: 'This cloud address is already in use.' });
        }

        await dbRun(`UPDATE users SET subdomain = ? WHERE id = ?`, [normalizedSubdomain, user.id]);
        const updatedUser = await dbGet(`SELECT * FROM users WHERE id = ?`, [user.id]);

        return res.status(200).json({
            message: 'Cloud address saved',
            data: serializeUser(updatedUser)
        });
    } catch (error) {
        console.error('SUBDOMAIN UPDATE ERROR:', error);
        return res.status(500).json({ error: 'Unable to save cloud address right now.' });
    }
});

app.post('/api/account/me', async (req, res) => {
    const { portal_session_token } = req.body;

    if (!portal_session_token) {
        return res.status(400).json({ error: 'Portal session token is required' });
    }

    try {
        const session = verifyPortalSessionToken(portal_session_token);
        if (!session) {
            return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
        }

        const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
        if (!user) {
            return res.status(404).json({ error: 'Account not found' });
        }

        return res.status(200).json({
            data: serializeUser(user)
        });
    } catch (error) {
        console.error('ACCOUNT ME ERROR:', error);
        return res.status(500).json({ error: 'Unable to load account details right now.' });
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

        if (!user.subdomain) {
            return res.status(400).json({ error: 'Set your cloud address before creating a payment checkout.' });
        }

        if (user.status === 'active' || ['active', 'authenticated', 'charged'].includes((user.razorpay_subscription_status || '').toLowerCase())) {
            return res.status(409).json({ error: 'Your account is already active. Additional payment is not required.' });
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
        if (error.statusCode) {
            return res.status(error.statusCode).json({ error: error.message });
        }
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
        email,
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
    const allowedStatuses = ['active', 'trial', 'suspended'];

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

    const baseDomain = `.${CLOUD_BASE_DOMAIN}`;
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

    const opsRequiringTokenValidation = new Set(['Login', 'Ping', 'NewWorkConn', 'NewUserConn']);
    if (!opsRequiringTokenValidation.has(op)) {
        return accept();
    }

    const tokenCandidates = [
        content?.metas?.token,
        content?.user?.metas?.token,
        content?.meta?.token,
        content?.user?.meta?.token,
        content?.client_token,
        typeof content?.user === 'string' ? content.user : null,
        content?.token,
        content?.metadatas?.token,
        content?.custom_dict?.token,
        content?.run_id
    ];

    const token = tokenCandidates.find((candidate) => typeof candidate === 'string' && candidate.length > 0);

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
