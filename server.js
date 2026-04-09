const path = require('path');
const https = require('https');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
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
const GOOGLE_HOME_CLIENT_ID = process.env.GOOGLE_HOME_CLIENT_ID || '';
const GOOGLE_HOME_CLIENT_SECRET = process.env.GOOGLE_HOME_CLIENT_SECRET || '';
const GOOGLE_HOME_REDIRECT_URI_HOSTS = (process.env.GOOGLE_HOME_REDIRECT_URI_HOSTS || 'oauth-redirect.googleusercontent.com,oauth-redirect-sandbox.googleusercontent.com').split(',').map((item) => item.trim().toLowerCase()).filter(Boolean);
const GOOGLE_HOME_AUTH_CODE_TTL_SECONDS = Number(process.env.GOOGLE_HOME_AUTH_CODE_TTL_SECONDS || 600);
const GOOGLE_HOME_ACCESS_TOKEN_TTL_SECONDS = Number(process.env.GOOGLE_HOME_ACCESS_TOKEN_TTL_SECONDS || 3600);
const GOOGLE_HOME_COMMAND_TTL_SECONDS = Number(process.env.GOOGLE_HOME_COMMAND_TTL_SECONDS || 45);
const GOOGLE_HOMEGRAPH_SCOPE = 'https://www.googleapis.com/auth/homegraph';
const GOOGLE_HOMEGRAPH_DEFAULT_TOKEN_URI = 'https://oauth2.googleapis.com/token';
const GOOGLE_HOMEGRAPH_API_BASE_URL = 'https://homegraph.googleapis.com/v1';
const GOOGLE_HOMEGRAPH_REQUEST_SYNC_DEBOUNCE_MS = Number(process.env.GOOGLE_HOMEGRAPH_REQUEST_SYNC_DEBOUNCE_MS || 2500);
const GOOGLE_HOMEGRAPH_REPORT_STATE_DEBOUNCE_MS = Number(process.env.GOOGLE_HOMEGRAPH_REPORT_STATE_DEBOUNCE_MS || 1200);
const GOOGLE_HOMEGRAPH_REPORT_STATE_ENABLED = process.env.GOOGLE_HOMEGRAPH_REPORT_STATE_ENABLED === '0' ? false : true;
const GOOGLE_CAPABILITY_ENGINE_V2 = process.env.GOOGLE_CAPABILITY_ENGINE_V2 === '1';
const GOOGLE_ENTITY_FRESH_WINDOW_SECONDS = Number(process.env.GOOGLE_ENTITY_FRESH_WINDOW_SECONDS || 0);
const GOOGLE_ENTITY_AVAILABILITY_STRICT = process.env.GOOGLE_ENTITY_AVAILABILITY_STRICT === '1';
const GOOGLE_DEBUG_ENDPOINTS_ENABLED = process.env.GOOGLE_DEBUG_ENDPOINTS_ENABLED === '1';
const ALLOWED_CORS_ORIGINS = (process.env.ALLOWED_CORS_ORIGINS || '').split(',').map((item) => item.trim()).filter(Boolean);
const PORTAL_SESSION_COOKIE_NAME = 'apx_portal_session';
const PORTAL_SESSION_COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const PORTAL_SESSION_COOKIE_SECURE = process.env.PORTAL_COOKIE_SECURE === '0' ? false : true;
const PORTAL_SESSION_COOKIE_DOMAIN = process.env.PORTAL_COOKIE_DOMAIN || '.apexinfosys.in';
const DEVICE_HEARTBEAT_TIMEOUT_SECONDS = Number(process.env.DEVICE_HEARTBEAT_TIMEOUT_SECONDS || 45);
const DEVICE_HEARTBEAT_INTERVAL_SECONDS = Number(process.env.DEVICE_HEARTBEAT_INTERVAL_SECONDS || 20);
const ADMIN_CONNECT_TOKEN_TTL_MINUTES = Number(process.env.ADMIN_CONNECT_TOKEN_TTL_MINUTES || 10);
const DEVICE_TUNNEL_PORT_MIN = Number(process.env.DEVICE_TUNNEL_PORT_MIN || 22000);
const DEVICE_TUNNEL_PORT_MAX = Number(process.env.DEVICE_TUNNEL_PORT_MAX || 22999);
const DEVICE_TOKEN_PREFIX = 'dvc_';
const ADMIN_CONNECT_TOKEN_PREFIX = 'acn_';
const GOOGLE_BACKEND_RELEASE = 'google-backend-2026-04-09-r3';

let googleHomegraphAccessTokenCache = {
    token: null,
    expiresAt: 0
};

const googleHomegraphRequestSyncQueue = new Map();
const googleHomegraphReportStateQueue = new Map();
const googleEndpointStats = {
    oauth_hits: 0,
    token_hits: 0,
    fulfillment_hits: 0,
    fulfillment_pre_auth_hits: 0,
    fulfillment_auth_failures: 0,
    oauth_status_counts: {},
    token_status_counts: {},
    fulfillment_status_counts: {},
    last_oauth_at: null,
    last_token_at: null,
    last_fulfillment_at: null,
    last_fulfillment_pre_auth_at: null,
    last_fulfillment_auth_failure_at: null,
    last_oauth_status: null,
    last_token_status: null,
    last_fulfillment_status: null
};

function incrementStatusCounter(bucket, statusCode) {
    const key = String(Number(statusCode) || 0);
    bucket[key] = (bucket[key] || 0) + 1;
}

function trackGoogleEdgeRequest(req, res, next) {
    const pathName = req.path || '';
    const shouldTrack = pathName.startsWith('/api/google/home')
        || pathName.startsWith('/google/home')
        || pathName === '/oauth'
        || pathName === '/token'
        || pathName === '/fulfillment';

    if (!shouldTrack) {
        return next();
    }

    const startedAt = Date.now();
    res.on('finish', () => {
        const elapsedMs = Date.now() - startedAt;
        if (pathName.includes('/oauth') || pathName === '/oauth') {
            incrementStatusCounter(googleEndpointStats.oauth_status_counts, res.statusCode);
            googleEndpointStats.last_oauth_status = res.statusCode;
        }
        if (pathName.includes('/token') || pathName === '/token') {
            incrementStatusCounter(googleEndpointStats.token_status_counts, res.statusCode);
            googleEndpointStats.last_token_status = res.statusCode;
        }
        if (pathName.includes('/fulfillment') || pathName === '/fulfillment') {
            incrementStatusCounter(googleEndpointStats.fulfillment_status_counts, res.statusCode);
            googleEndpointStats.last_fulfillment_status = res.statusCode;
        }

        console.log('GOOGLE EDGE REQUEST:', {
            method: req.method,
            path: pathName,
            status: res.statusCode,
            elapsed_ms: elapsedMs,
            host: req.get('host') || null,
            user_agent: req.get('user-agent') || null,
            origin: req.get('origin') || null
        });
    });

    return next();
}

function trackGoogleFulfillmentPreAuth(req, _res, next) {
    googleEndpointStats.fulfillment_pre_auth_hits += 1;
    googleEndpointStats.last_fulfillment_pre_auth_at = new Date().toISOString();
    return next();
}
const homegraphMetrics = {
    request_sync: {
        sent: 0,
        failed: 0,
        skipped: 0,
        last_success_at: null,
        last_failure_at: null,
        last_failure_reason: null,
        last_status: null,
        last_user_id: null
    },
    report_state: {
        sent: 0,
        failed: 0,
        skipped: 0,
        last_success_at: null,
        last_failure_at: null,
        last_failure_reason: null,
        last_status: null,
        last_user_id: null
    }
};

let googleEntityLastSeenColumnSupported = true;
let googleSyncSnapshotsTableSupported = true;
let googleSyncSnapshotsUpsertSupported = true;
let googleStateHashColumnSupported = true;
let googleLastReportedColumnsSupported = true;

function sqliteMessage(error) {
    return String(error?.message || '').toLowerCase();
}

function isMissingGoogleEntityLastSeenColumnError(error) {
    return sqliteMessage(error).includes('no such column: entity_last_seen_at');
}

function isMissingGoogleSyncSnapshotsTableError(error) {
    return sqliteMessage(error).includes('no such table: google_home_sync_snapshots');
}

function isGoogleSyncSnapshotsUpsertUnsupportedError(error) {
    const message = sqliteMessage(error);
    return message.includes('near "on": syntax error') || message.includes('near "do": syntax error');
}

function isMissingGoogleStateHashColumnError(error) {
    return sqliteMessage(error).includes('no such column: state_hash');
}

function isMissingGoogleLastReportedColumnsError(error) {
    const message = sqliteMessage(error);
    return message.includes('no such column: last_reported_state_hash') || message.includes('no such column: last_reported_at');
}

function hasExactlyOneDot(value) {
    if (typeof value !== 'string') {
        return false;
    }

    const firstDot = value.indexOf('.');
    if (firstDot <= 0) {
        return false;
    }

    return value.indexOf('.', firstDot + 1) === -1;
}

function markHomegraphMetricSuccess(metricType, userId, statusCode = null) {
    const metric = homegraphMetrics[metricType];
    if (!metric) {
        return;
    }

    metric.sent += 1;
    metric.last_success_at = new Date().toISOString();
    metric.last_status = statusCode;
    metric.last_user_id = sanitizeString(userId, 120) || null;
}

function markHomegraphMetricFailure(metricType, userId, statusCode = null, reason = null) {
    const metric = homegraphMetrics[metricType];
    if (!metric) {
        return;
    }

    metric.failed += 1;
    metric.last_failure_at = new Date().toISOString();
    metric.last_status = statusCode;
    metric.last_failure_reason = sanitizeString(reason, 300) || 'unknown_error';
    metric.last_user_id = sanitizeString(userId, 120) || null;
}

function markHomegraphMetricSkipped(metricType, userId, reason = null) {
    const metric = homegraphMetrics[metricType];
    if (!metric) {
        return;
    }

    metric.skipped += 1;
    metric.last_status = null;
    metric.last_user_id = sanitizeString(userId, 120) || null;
    if (reason) {
        metric.last_failure_reason = sanitizeString(reason, 300) || metric.last_failure_reason;
    }
}

const app = express();
app.use(cookieParser());
app.use(express.json({
    limit: '5mb',
    verify: (req, res, buf) => {
        if (buf && buf.length > 0) {
            req.rawBody = buf.toString();
        }
    }
}));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(trackGoogleEdgeRequest);
app.use(cors({
    origin: (origin, callback) => {
        if (!origin) {
            callback(null, true);
            return;
        }

        if (ALLOWED_CORS_ORIGINS.length === 0) {
            callback(null, false);
            return;
        }

        callback(null, ALLOWED_CORS_ORIGINS.includes(origin));
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use((error, req, res, next) => {
    if (error?.type === 'entity.too.large') {
        return res.status(413).json({ error: 'payload_too_large' });
    }

    if (error instanceof SyntaxError && error?.status === 400 && 'body' in error) {
        return res.status(400).json({ error: 'invalid_json_payload' });
    }

    return next(error);
});

app.get(['/login', '/login.html', '/signup', '/signup.html'], (req, res, next) => {
    const isSignupPath = req.path.startsWith('/signup');
    const targetPath = isSignupPath ? '/signup.html' : '/login.html';
    const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';

    if (req.hostname === CUSTOMER_PORTAL_HOST) {
        if (req.path === '/login' || req.path === '/signup') {
            return res.redirect(`${targetPath}${query}`);
        }
        return next();
    }

    if (req.hostname === ADMIN_PORTAL_HOST || req.hostname === CLOUD_BASE_DOMAIN) {
        return res.redirect(`https://${CUSTOMER_PORTAL_HOST}${targetPath}${query}`);
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

function sanitizeEntityId(value) {
    const normalized = sanitizeString(value, 200);
    if (!normalized) {
        return null;
    }

    return /^[a-zA-Z0-9._:-]+$/.test(normalized) ? normalized : null;
}

function sanitizeActionName(value) {
    const normalized = sanitizeString(value, 120);
    if (!normalized) {
        return null;
    }

    return /^[a-zA-Z0-9_.:-]+$/.test(normalized) ? normalized : null;
}

function sanitizeGoogleRequestId(value) {
    const normalized = sanitizeString(value, 128);
    if (!normalized) {
        return null;
    }

    return /^[a-zA-Z0-9._:-]+$/.test(normalized) ? normalized : null;
}

function isTrustedGoogleRedirectUri(redirectUri) {
    const normalized = sanitizeString(redirectUri, 1000);
    if (!normalized) {
        return false;
    }

    let parsed;
    try {
        parsed = new URL(normalized);
    } catch (error) {
        return false;
    }

    if (parsed.protocol !== 'https:') {
        return false;
    }

    const host = (parsed.hostname || '').toLowerCase();
    return GOOGLE_HOME_REDIRECT_URI_HOSTS.includes(host);
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

function getEntityFreshWindowSeconds() {
    if (Number.isFinite(GOOGLE_ENTITY_FRESH_WINDOW_SECONDS) && GOOGLE_ENTITY_FRESH_WINDOW_SECONDS > 0) {
        return Math.max(10, Math.min(1800, Math.round(GOOGLE_ENTITY_FRESH_WINDOW_SECONDS)));
    }

    const base = getHeartbeatWindowSeconds();
    const computed = Math.max(30, Math.round(base * 2.5));
    return Math.min(900, computed);
}

function isEntityFresh(entityLastSeenAt) {
    if (!entityLastSeenAt) {
        return false;
    }

    const lastSeenEpoch = new Date(entityLastSeenAt).getTime();
    if (!Number.isFinite(lastSeenEpoch)) {
        return false;
    }

    return (Date.now() - lastSeenEpoch) <= (getEntityFreshWindowSeconds() * 1000);
}

function isEntityEffectivelyOnline(entityRow) {
    if (!entityRow) {
        return false;
    }

    const deviceOnline = isDeviceOnline(entityRow.last_seen_at);
    if (!deviceOnline) {
        return false;
    }

    const entityFresh = isEntityFresh(entityRow.entity_last_seen_at || entityRow.updated_at || entityRow.last_seen_at);
    if (!entityFresh) {
        return false;
    }

    if (!GOOGLE_ENTITY_AVAILABILITY_STRICT) {
        return true;
    }

    return Number(entityRow.online) !== 0;
}

async function refreshGoogleEntityFreshnessFromDeviceHeartbeat(userId = null, deviceId = null) {
    const params = [];
    let where = '';

    if (parsePositiveInt(userId)) {
        where += ' AND ge.user_id = ?';
        params.push(parsePositiveInt(userId));
    }

    if (parsePositiveInt(deviceId)) {
        where += ' AND ge.device_id = ?';
        params.push(parsePositiveInt(deviceId));
    }

    try {
        await dbRun(
            `
                UPDATE google_home_entities
                SET entity_last_seen_at = (
                    SELECT d.last_seen_at
                    FROM devices d
                    WHERE d.id = google_home_entities.device_id
                )
                WHERE (entity_last_seen_at IS NULL OR entity_last_seen_at = '')
                  ${where}
            `,
            params
        );
    } catch (error) {
        if (isMissingGoogleEntityLastSeenColumnError(error)) {
            googleEntityLastSeenColumnSupported = false;
            return;
        }
        throw error;
    }
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

function getGoogleAuthCodeTtlSeconds() {
    if (!Number.isFinite(GOOGLE_HOME_AUTH_CODE_TTL_SECONDS)) {
        return 600;
    }

    return Math.max(120, Math.min(1800, Math.round(GOOGLE_HOME_AUTH_CODE_TTL_SECONDS)));
}

function getGoogleAccessTokenTtlSeconds() {
    if (!Number.isFinite(GOOGLE_HOME_ACCESS_TOKEN_TTL_SECONDS)) {
        return 3600;
    }

    return Math.max(300, Math.min(7200, Math.round(GOOGLE_HOME_ACCESS_TOKEN_TTL_SECONDS)));
}

function getGoogleCommandTtlSeconds() {
    if (!Number.isFinite(GOOGLE_HOME_COMMAND_TTL_SECONDS)) {
        return 45;
    }

    return Math.max(10, Math.min(180, Math.round(GOOGLE_HOME_COMMAND_TTL_SECONDS)));
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

function generateGoogleOAuthCode() {
    return 'gac_' + crypto.randomBytes(24).toString('hex');
}

function generateGoogleAccessToken() {
    return 'gat_' + crypto.randomBytes(24).toString('hex');
}

function generateGoogleRefreshToken() {
    return 'grt_' + crypto.randomBytes(24).toString('hex');
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

async function findUserByGoogleAccessToken(accessToken) {
    if (!accessToken) {
        return null;
    }

    const tokenHash = hashSecret(accessToken);
    return dbGet(
        `
            SELECT u.*
            FROM users u
            INNER JOIN google_home_tokens ght ON ght.user_id = u.id
            WHERE ght.access_token_hash = ?
              AND ght.expires_at > ?
        `,
        [tokenHash, new Date().toISOString()]
    );
}

async function findGoogleRefreshTokenRow(refreshToken) {
    if (!refreshToken) {
        return null;
    }

    const tokenHash = hashSecret(refreshToken);
    return dbGet(
        `
            SELECT *
            FROM google_home_tokens
            WHERE refresh_token_hash = ?
            LIMIT 1
        `,
        [tokenHash]
    );
}

async function findUserByGoogleAuthCode(authCode, redirectUri) {
    if (!authCode) {
        return null;
    }

    const codeHash = hashSecret(authCode);
    return dbGet(
        `
            SELECT
                u.*,
                ghac.id AS oauth_code_id,
                ghac.redirect_uri AS oauth_redirect_uri
            FROM google_home_auth_codes ghac
            INNER JOIN users u ON u.id = ghac.user_id
            WHERE ghac.code_hash = ?
              AND ghac.expires_at > ?
              AND ghac.consumed_at IS NULL
              AND ghac.redirect_uri = ?
            LIMIT 1
        `,
        [codeHash, new Date().toISOString(), redirectUri]
    );
}

async function issueGoogleTokensForUser(userId, existingRefreshToken = null) {
    const accessToken = generateGoogleAccessToken();
    const refreshToken = existingRefreshToken || generateGoogleRefreshToken();
    const accessTokenHash = hashSecret(accessToken);
    const refreshTokenHash = hashSecret(refreshToken);
    const expiresAt = new Date(Date.now() + getGoogleAccessTokenTtlSeconds() * 1000).toISOString();
    const nowIso = new Date().toISOString();

    await dbRun(
        `
            INSERT INTO google_home_tokens (
                user_id,
                access_token_hash,
                refresh_token_hash,
                expires_at,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                access_token_hash = excluded.access_token_hash,
                refresh_token_hash = excluded.refresh_token_hash,
                expires_at = excluded.expires_at,
                updated_at = excluded.updated_at
        `,
        [userId, accessTokenHash, refreshTokenHash, expiresAt, nowIso, nowIso]
    );

    return {
        access_token: accessToken,
        refresh_token: refreshToken,
        expires_in: getGoogleAccessTokenTtlSeconds(),
        token_type: 'Bearer'
    };
}

function normalizeGoogleEntityType(entityType) {
    const normalized = sanitizeString(entityType, 64);
    if (!normalized) {
        return 'switch';
    }

    return normalized.toLowerCase();
}

function mapGoogleDomainToEntityType(entityId, fallbackType = 'switch') {
    const normalizedEntityId = sanitizeEntityId(entityId) || '';
    const domain = normalizedEntityId.includes('.') ? normalizedEntityId.split('.')[0] : '';

    if (domain === 'light') return 'light';
    if (domain === 'switch' || domain === 'input_boolean' || domain === 'automation' || domain === 'script') return 'switch';
    if (domain === 'fan') return 'fan';
    if (domain === 'cover') return 'cover';
    if (domain === 'lock') return 'lock';
    if (domain === 'climate') return 'climate';
    if (domain === 'media_player') return 'media_player';
    if (domain === 'scene') return 'scene';
    if (domain === 'button') return 'button';
    if (domain === 'vacuum') return 'vacuum';
    if (domain === 'sensor') return 'sensor_temperature';

    return fallbackType;
}

function mapGoogleEntityTypeToTraits(entityType) {
    if (entityType === 'fan') {
        return {
            type: 'action.devices.types.FAN',
            traits: [
                'action.devices.traits.OnOff',
                'action.devices.traits.FanSpeed'
            ]
        };
    }

    if (entityType === 'cover') {
        return {
            type: 'action.devices.types.BLINDS',
            traits: [
                'action.devices.traits.OpenClose'
            ]
        };
    }

    if (entityType === 'lock') {
        return {
            type: 'action.devices.types.LOCK',
            traits: [
                'action.devices.traits.LockUnlock'
            ]
        };
    }

    if (entityType === 'climate') {
        return {
            type: 'action.devices.types.THERMOSTAT',
            traits: [
                'action.devices.traits.TemperatureSetting'
            ]
        };
    }

    if (entityType === 'media_player') {
        return {
            type: 'action.devices.types.TV',
            traits: [
                'action.devices.traits.OnOff',
                'action.devices.traits.Volume'
            ]
        };
    }

    if (entityType === 'scene') {
        return {
            type: 'action.devices.types.SCENE',
            traits: [
                'action.devices.traits.Scene'
            ]
        };
    }

    if (entityType === 'button') {
        return {
            type: 'action.devices.types.SCENE',
            traits: [
                'action.devices.traits.Scene'
            ]
        };
    }

    if (entityType === 'vacuum') {
        return {
            type: 'action.devices.types.VACUUM',
            traits: [
                'action.devices.traits.StartStop',
                'action.devices.traits.OnOff'
            ]
        };
    }

    if (entityType === 'light') {
        return {
            type: 'action.devices.types.LIGHT',
            traits: [
                'action.devices.traits.OnOff',
                'action.devices.traits.Brightness'
            ]
        };
    }

    if (entityType === 'sensor_temperature') {
        return {
            type: 'action.devices.types.SENSOR',
            traits: [
                'action.devices.traits.SensorState'
            ]
        };
    }

    return {
        type: 'action.devices.types.SWITCH',
        traits: [
            'action.devices.traits.OnOff'
        ]
    };
}

function parseGoogleCapabilities(entity) {
    const parsed = parseJsonSafe(entity?.capabilities_json, null) || parseJsonSafe(entity?.state_json, {}) || {};
    if (!parsed || typeof parsed !== 'object') {
        return {};
    }

    return parsed;
}

function getGoogleDeviceAttributesFromCapabilities(entity, traits) {
    const capabilities = parseGoogleCapabilities(entity);
    const attrs = {};

    if (traits.includes('action.devices.traits.Brightness')) {
        attrs.commandOnlyBrightness = false;
    }

    if (traits.includes('action.devices.traits.FanSpeed')) {
        const percentageStep = Number(capabilities?.fan?.percentage_step);
        const max = Number(capabilities?.fan?.speed_max || 100);
        const min = Number(capabilities?.fan?.speed_min || 0);
        const supportsPercent = capabilities?.fan?.supports_percentage !== false;

        if (supportsPercent) {
            attrs.availableFanSpeeds = {
                speeds: [
                    {
                        speed_name: 'speed_percent',
                        speed_values: [
                            {
                                speed_synonym: ['percent', 'speed', 'fan speed'],
                                lang: 'en'
                            }
                        ]
                    }
                ],
                ordered: true
            };
            attrs.reversible = false;
            attrs.commandOnlyFanSpeed = false;
            attrs.fanSpeedPercentStep = Number.isFinite(percentageStep) && percentageStep > 0 ? percentageStep : 1;
            attrs.fanSpeedPercentMin = Number.isFinite(min) ? Math.max(0, min) : 0;
            attrs.fanSpeedPercentMax = Number.isFinite(max) ? Math.min(100, max) : 100;
        }
    }

    if (traits.includes('action.devices.traits.OpenClose')) {
        attrs.discreteOnlyOpenClose = false;
        attrs.queryOnlyOpenClose = false;
    }

    if (traits.includes('action.devices.traits.TemperatureSetting')) {
        attrs.availableThermostatModes = getGoogleThermostatModesForEntity(entity);
        attrs.thermostatTemperatureUnit = String(capabilities?.climate?.temperature_unit || 'C').toUpperCase() === 'F' ? 'F' : 'C';
    }

    if (traits.includes('action.devices.traits.Volume')) {
        attrs.volumeMaxLevel = 100;
        attrs.levelStepSize = 5;
        attrs.volumeCanMuteAndUnmute = capabilities?.media_player?.supports_mute !== false;
    }

    if (traits.includes('action.devices.traits.Scene')) {
        attrs.sceneReversible = false;
    }

    if (traits.includes('action.devices.traits.StartStop')) {
        attrs.pausable = capabilities?.vacuum?.supports_pause !== false;
    }

    if (traits.includes('action.devices.traits.TemperatureControl')) {
        attrs.temperatureUnitForUX = String(capabilities?.sensor?.temperature_unit || 'C').toUpperCase() === 'F' ? 'F' : 'C';
    }

    return attrs;
}

function getGoogleTraitsForEntity(entity) {
    const fallbackTraits = mapGoogleEntityTypeToTraits(entity.entity_type);
    if (!GOOGLE_CAPABILITY_ENGINE_V2) {
        return fallbackTraits;
    }

    const capabilities = parseGoogleCapabilities(entity);
    const entityType = normalizeGoogleEntityType(entity?.entity_type);
    const traits = [];

    const supports = {
        onOff: capabilities?.supports?.on_off !== false,
        brightness: capabilities?.light?.supports_brightness === true,
        fanSpeed: capabilities?.fan?.supports_speed === true,
        openClose: capabilities?.cover?.supports_position === true,
        lockUnlock: capabilities?.lock?.supports_lock_unlock !== false,
        tempSetting: capabilities?.climate?.supports_mode === true || capabilities?.climate?.supports_setpoint === true,
        tempControl: capabilities?.sensor?.supports_temperature === true,
        volume: capabilities?.media_player?.supports_volume === true,
        scene: capabilities?.scene?.supports_activate === true || capabilities?.button?.supports_press === true,
        startStop: capabilities?.vacuum?.supports_start_stop === true,
        pauseUnpause: capabilities?.vacuum?.supports_pause === true
    };

    if (entityType === 'light') {
        if (supports.onOff) traits.push('action.devices.traits.OnOff');
        if (supports.brightness) traits.push('action.devices.traits.Brightness');
    } else if (entityType === 'fan') {
        if (supports.onOff) traits.push('action.devices.traits.OnOff');
        if (supports.fanSpeed) traits.push('action.devices.traits.FanSpeed');
    } else if (entityType === 'cover') {
        if (supports.openClose) traits.push('action.devices.traits.OpenClose');
    } else if (entityType === 'lock') {
        if (supports.lockUnlock) traits.push('action.devices.traits.LockUnlock');
    } else if (entityType === 'climate') {
        if (supports.tempSetting) traits.push('action.devices.traits.TemperatureSetting');
    } else if (entityType === 'media_player') {
        if (supports.onOff) traits.push('action.devices.traits.OnOff');
        if (supports.volume) traits.push('action.devices.traits.Volume');
    } else if (entityType === 'scene' || entityType === 'button') {
        if (supports.scene) traits.push('action.devices.traits.Scene');
    } else if (entityType === 'vacuum') {
        if (supports.onOff) traits.push('action.devices.traits.OnOff');
        if (supports.startStop) traits.push('action.devices.traits.StartStop');
        if (supports.pauseUnpause) traits.push('action.devices.traits.PauseUnpause');
    } else if (entityType === 'sensor_temperature') {
        if (supports.tempControl) traits.push('action.devices.traits.TemperatureControl');
    } else if (entityType === 'switch') {
        if (supports.onOff) traits.push('action.devices.traits.OnOff');
    }

    if (traits.length === 0) {
        return fallbackTraits;
    }

    return Array.from(new Set(traits));
}

function normalizeGoogleThermostatMode(mode) {
    const normalized = sanitizeString(mode, 32).toLowerCase();
    if (!normalized) return 'off';

    if (normalized === 'heat_cool' || normalized === 'heatcool') return 'heatcool';
    if (normalized === 'fan_only' || normalized === 'fan-only') return 'fan-only';
    return normalized;
}

function getGoogleThermostatModesForEntity(entity) {
    const statePayload = parseJsonSafe(entity?.state_json, {}) || {};
    const rawModes = Array.isArray(statePayload.hvac_modes) ? statePayload.hvac_modes : [];
    const normalizedModes = Array.from(new Set(rawModes
        .map((mode) => normalizeGoogleThermostatMode(mode))
        .filter(Boolean)));

    if (normalizedModes.length > 0) {
        return normalizedModes.join(',');
    }

    return 'off,heat,cool,heatcool';
}

function supportsGoogleCommandForEntityType(entityType, commandName) {
    const allowed = {
        light: new Set([
            'action.devices.commands.OnOff',
            'action.devices.commands.BrightnessAbsolute'
        ]),
        switch: new Set([
            'action.devices.commands.OnOff'
        ]),
        fan: new Set([
            'action.devices.commands.OnOff',
            'action.devices.commands.SetFanSpeed'
        ]),
        cover: new Set([
            'action.devices.commands.OpenClose'
        ]),
        lock: new Set([
            'action.devices.commands.LockUnlock'
        ]),
        climate: new Set([
            'action.devices.commands.ThermostatSetMode',
            'action.devices.commands.ThermostatTemperatureSetpoint'
        ]),
        media_player: new Set([
            'action.devices.commands.OnOff',
            'action.devices.commands.setVolume',
            'action.devices.commands.mute'
        ]),
        scene: new Set([
            'action.devices.commands.activateScene'
        ]),
        button: new Set([
            'action.devices.commands.activateScene'
        ]),
        vacuum: new Set([
            'action.devices.commands.StartStop',
            'action.devices.commands.PauseUnpause',
            'action.devices.commands.OnOff'
        ]),
        sensor_temperature: new Set([])
    };

    const allowedCommands = allowed[normalizeGoogleEntityType(entityType)] || allowed.switch;
    return allowedCommands.has(commandName);
}

function supportsGoogleCommandForEntity(entity, commandName) {
    if (!GOOGLE_CAPABILITY_ENGINE_V2) {
        return supportsGoogleCommandForEntityType(entity?.entity_type, commandName);
    }

    const capabilities = parseGoogleCapabilities(entity);
    const traits = getGoogleTraitsForEntity(entity);
    const hasTrait = (traitName) => traits.includes(traitName);
    const supportsMute = capabilities?.media_player?.supports_mute !== false;

    const commandTraitRequirements = {
        'action.devices.commands.OnOff': 'action.devices.traits.OnOff',
        'action.devices.commands.BrightnessAbsolute': 'action.devices.traits.Brightness',
        'action.devices.commands.SetFanSpeed': 'action.devices.traits.FanSpeed',
        'action.devices.commands.OpenClose': 'action.devices.traits.OpenClose',
        'action.devices.commands.LockUnlock': 'action.devices.traits.LockUnlock',
        'action.devices.commands.ThermostatSetMode': 'action.devices.traits.TemperatureSetting',
        'action.devices.commands.ThermostatTemperatureSetpoint': 'action.devices.traits.TemperatureSetting',
        'action.devices.commands.setVolume': 'action.devices.traits.Volume',
        'action.devices.commands.mute': 'action.devices.traits.Volume',
        'action.devices.commands.activateScene': 'action.devices.traits.Scene',
        'action.devices.commands.StartStop': 'action.devices.traits.StartStop',
        'action.devices.commands.PauseUnpause': 'action.devices.traits.PauseUnpause'
    };

    const requiredTrait = commandTraitRequirements[commandName];
    if (!requiredTrait) {
        return false;
    }

    if (!hasTrait(requiredTrait)) {
        return false;
    }

    if (commandName === 'action.devices.commands.mute' && !supportsMute) {
        return false;
    }

    return true;
}

function buildGoogleDeviceObject(entity) {
    const mapped = {
        type: mapGoogleEntityTypeToDeviceType(entity.entity_type),
        traits: getGoogleTraitsForEntity(entity)
    };
    const roomHint = sanitizeString(entity.room_hint, 120);

    return {
        id: entity.entity_id,
        type: mapped.type,
        traits: mapped.traits,
        name: {
            name: entity.display_name || entity.entity_id
        },
        roomHint: roomHint || undefined,
        willReportState: GOOGLE_HOMEGRAPH_REPORT_STATE_ENABLED && hasGoogleHomegraphCredentials(),
        customData: {
            entity_id: entity.entity_id,
            device_id: entity.device_id
        },
        deviceInfo: {
            manufacturer: 'Apex Infosys',
            model: entity.entity_type || 'generic',
            hwVersion: entity.addon_version || 'apex-cloud-link'
        },
        attributes: {
            ...getGoogleDeviceAttributesFromCapabilities(entity, mapped.traits),
            ...(mapped.traits.includes('action.devices.traits.TemperatureControl')
                ? {
                    sensorStatesSupported: [
                        {
                            name: 'TemperatureAmbient',
                            numericCapabilities: {
                                rawValueUnit: 'CELSIUS',
                                rawValueRange: {
                                    minValue: -40,
                                    maxValue: 130
                                }
                            }
                        }
                    ]
                }
                : {})
        }
    };
}

function parseGoogleEntityState(entity) {
    const statePayload = parseJsonSafe(entity.state_json, {}) || {};

    if (entity.entity_type === 'fan') {
        const fanOn = Boolean(statePayload.on);
        const speed = Number(statePayload.speed_percent ?? statePayload.speed ?? 0);
        return {
            online: entity.online !== 0,
            on: fanOn,
            currentFanSpeedPercent: Math.max(0, Math.min(100, Math.round(speed || 0))),
            currentFanSpeedSetting: String(Math.max(0, Math.min(100, Math.round(speed || 0))))
        };
    }

    if (entity.entity_type === 'cover') {
        const openPercent = Number(statePayload.openPercent || 0);
        return {
            online: entity.online !== 0,
            openPercent: Math.max(0, Math.min(100, Math.round(openPercent)))
        };
    }

    if (entity.entity_type === 'lock') {
        return {
            online: entity.online !== 0,
            isLocked: Boolean(statePayload.isLocked)
        };
    }

    if (entity.entity_type === 'climate') {
        const ambient = Number(statePayload.ambient_temperature || 0);
        const target = Number(statePayload.target_temperature || ambient || 22);
        return {
            online: entity.online !== 0,
            thermostatMode: normalizeGoogleThermostatMode(statePayload.mode),
            thermostatTemperatureAmbient: Number.isFinite(ambient) ? ambient : 0,
            thermostatTemperatureSetpoint: Number.isFinite(target) ? target : 22
        };
    }

    if (entity.entity_type === 'media_player') {
        const volume = Number(statePayload.volume || 0);
        return {
            online: entity.online !== 0,
            on: Boolean(statePayload.on),
            currentVolume: Math.max(0, Math.min(100, Math.round(volume))),
            isMuted: Boolean(statePayload.muted)
        };
    }

    if (entity.entity_type === 'scene' || entity.entity_type === 'button') {
        return {
            online: entity.online !== 0
        };
    }

    if (entity.entity_type === 'vacuum') {
        return {
            online: entity.online !== 0,
            on: Boolean(statePayload.on),
            isRunning: Boolean(statePayload.isRunning),
            isPaused: Boolean(statePayload.isPaused)
        };
    }

    if (entity.entity_type === 'light') {
        return {
            online: entity.online !== 0,
            on: Boolean(statePayload.on),
            brightness: Number.isFinite(Number(statePayload.brightness))
                ? Math.max(0, Math.min(100, Math.round(Number(statePayload.brightness))))
                : 0
        };
    }

    if (entity.entity_type === 'sensor_temperature') {
        const temperature = Number(statePayload.temperature);
        return {
            online: entity.online !== 0,
            currentSensorStateData: [
                {
                    name: 'TemperatureAmbient',
                    currentSensorState: Number.isFinite(temperature) ? temperature : 0
                }
            ]
        };
    }

    return {
        online: entity.online !== 0,
        on: Boolean(statePayload.on)
    };
}

function withEffectiveGoogleOnline(entity) {
    if (!entity) {
        return entity;
    }

    const effectiveOnline = isEntityEffectivelyOnline(entity);
    return {
        ...entity,
        online: effectiveOnline ? 1 : 0,
        effective_online: effectiveOnline ? 1 : 0,
        device_online: isDeviceOnline(entity.last_seen_at) ? 1 : 0,
        entity_fresh: isEntityFresh(entity.entity_last_seen_at || entity.updated_at) ? 1 : 0
    };
}

async function getGoogleEntitiesForUser(userId, options = {}) {
    const includeDisabled = Boolean(options.includeDisabled);
    const rows = includeDisabled
        ? await dbAll(
            `
                SELECT
                    ge.*,
                    d.addon_version,
                    d.last_seen_at
                FROM google_home_entities ge
                INNER JOIN devices d ON d.id = ge.device_id
                WHERE ge.user_id = ?
                ORDER BY ge.updated_at DESC
            `,
            [userId]
        )
        : await dbAll(
            `
                SELECT
                    ge.*,
                    d.addon_version,
                    d.last_seen_at
                FROM google_home_entities ge
                INNER JOIN devices d ON d.id = ge.device_id
                WHERE ge.user_id = ?
                  AND ge.exposed = 1
                ORDER BY ge.updated_at DESC
            `,
            [userId]
        );

    return (rows || []).map((row) => {
        const normalizedRow = {
            ...row,
            entity_last_seen_at: googleEntityLastSeenColumnSupported
                ? row.entity_last_seen_at
                : row.updated_at
        };
        return withEffectiveGoogleOnline(normalizedRow);
    });
}

setInterval(() => {
    markGoogleEntitiesStaleByFreshness().catch((error) => {
        console.error('GOOGLE ENTITY STALE MARK ERROR:', error);
    });
}, 30000).unref?.();

async function upsertGoogleEntityFromDevice(userId, deviceId, payload) {
    const entityId = sanitizeEntityId(payload?.entity_id);
    if (!entityId) {
        return null;
    }

    const displayName = sanitizeString(payload?.display_name, 120) || entityId;
    const entityType = mapGoogleDomainToEntityType(entityId, normalizeGoogleEntityType(payload?.entity_type));
    const roomHint = sanitizeString(payload?.room_hint, 120);
    const online = payload?.online === false ? 0 : 1;
    const capabilitiesJson = JSON.stringify(payload?.capabilities || {}).slice(0, 5000);
    const stateJson = JSON.stringify(payload?.state || {}).slice(0, 2500);
    const entityState = parseGoogleEntityState({
        entity_type: entityType,
        online,
        state_json: stateJson
    });
    const stateHash = computeGoogleStateHash(entityState);
    const nowIso = new Date().toISOString();

    const existing = await dbGet(
        `
            SELECT id, exposed, device_id, display_name, entity_type, room_hint
            FROM google_home_entities
            WHERE user_id = ? AND entity_id = ?
            LIMIT 1
        `,
        [userId, entityId]
    );

    const syncChanged = !existing
        || Number(existing.device_id) !== Number(deviceId)
        || (existing.display_name || '') !== displayName
        || (existing.entity_type || '') !== entityType
        || (existing.room_hint || '') !== (roomHint || '');

    if (existing) {
        const updateWithLastSeenSql = `
            UPDATE google_home_entities
            SET device_id = ?,
                display_name = ?,
                entity_type = ?,
                room_hint = ?,
                online = ?,
                entity_last_seen_at = ?,
                capabilities_json = ?,
                state_json = ?,
                updated_at = ?
            WHERE id = ?
        `;

        const updateFallbackSql = `
            UPDATE google_home_entities
            SET device_id = ?,
                display_name = ?,
                entity_type = ?,
                room_hint = ?,
                online = ?,
                capabilities_json = ?,
                state_json = ?,
                updated_at = ?
            WHERE id = ?
        `;

        const updateWithLastSeenAndHashSql = `
            UPDATE google_home_entities
            SET device_id = ?,
                display_name = ?,
                entity_type = ?,
                room_hint = ?,
                online = ?,
                entity_last_seen_at = ?,
                capabilities_json = ?,
                state_json = ?,
                state_hash = ?,
                updated_at = ?
            WHERE id = ?
        `;

        const updateFallbackAndHashSql = `
            UPDATE google_home_entities
            SET device_id = ?,
                display_name = ?,
                entity_type = ?,
                room_hint = ?,
                online = ?,
                capabilities_json = ?,
                state_json = ?,
                state_hash = ?,
                updated_at = ?
            WHERE id = ?
        `;

        try {
            if (googleEntityLastSeenColumnSupported && googleStateHashColumnSupported) {
                await dbRun(updateWithLastSeenAndHashSql, [deviceId, displayName, entityType, roomHint, online, nowIso, capabilitiesJson, stateJson, stateHash, nowIso, existing.id]);
            } else if (googleEntityLastSeenColumnSupported && !googleStateHashColumnSupported) {
                await dbRun(updateWithLastSeenSql, [deviceId, displayName, entityType, roomHint, online, nowIso, capabilitiesJson, stateJson, nowIso, existing.id]);
            } else if (!googleEntityLastSeenColumnSupported && googleStateHashColumnSupported) {
                await dbRun(updateFallbackAndHashSql, [deviceId, displayName, entityType, roomHint, online, capabilitiesJson, stateJson, stateHash, nowIso, existing.id]);
            } else {
                await dbRun(updateFallbackSql, [deviceId, displayName, entityType, roomHint, online, capabilitiesJson, stateJson, nowIso, existing.id]);
            }
        } catch (error) {
            if (isMissingGoogleEntityLastSeenColumnError(error) || isMissingGoogleStateHashColumnError(error)) {
                googleEntityLastSeenColumnSupported = false;
                googleStateHashColumnSupported = false;
                await dbRun(updateFallbackSql, [deviceId, displayName, entityType, roomHint, online, capabilitiesJson, stateJson, nowIso, existing.id]);
            } else {
                throw error;
            }
        }
    } else {
        const insertWithLastSeenSql = `
            INSERT INTO google_home_entities (
                user_id,
                device_id,
                entity_id,
                display_name,
                entity_type,
                room_hint,
                exposed,
                online,
                entity_last_seen_at,
                capabilities_json,
                state_json,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
        `;

        const insertFallbackSql = `
            INSERT INTO google_home_entities (
                user_id,
                device_id,
                entity_id,
                display_name,
                entity_type,
                room_hint,
                exposed,
                online,
                capabilities_json,
                state_json,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
        `;

        const insertWithLastSeenAndHashSql = `
            INSERT INTO google_home_entities (
                user_id,
                device_id,
                entity_id,
                display_name,
                entity_type,
                room_hint,
                exposed,
                online,
                entity_last_seen_at,
                capabilities_json,
                state_json,
                state_hash,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
        `;

        const insertFallbackAndHashSql = `
            INSERT INTO google_home_entities (
                user_id,
                device_id,
                entity_id,
                display_name,
                entity_type,
                room_hint,
                exposed,
                online,
                capabilities_json,
                state_json,
                state_hash,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
        `;

        try {
            if (googleEntityLastSeenColumnSupported && googleStateHashColumnSupported) {
                await dbRun(insertWithLastSeenAndHashSql, [userId, deviceId, entityId, displayName, entityType, roomHint, online, nowIso, capabilitiesJson, stateJson, stateHash, nowIso, nowIso]);
            } else if (googleEntityLastSeenColumnSupported && !googleStateHashColumnSupported) {
                await dbRun(insertWithLastSeenSql, [userId, deviceId, entityId, displayName, entityType, roomHint, online, nowIso, capabilitiesJson, stateJson, nowIso, nowIso]);
            } else if (!googleEntityLastSeenColumnSupported && googleStateHashColumnSupported) {
                await dbRun(insertFallbackAndHashSql, [userId, deviceId, entityId, displayName, entityType, roomHint, online, capabilitiesJson, stateJson, stateHash, nowIso, nowIso]);
            } else {
                await dbRun(insertFallbackSql, [userId, deviceId, entityId, displayName, entityType, roomHint, online, capabilitiesJson, stateJson, nowIso, nowIso]);
            }
        } catch (error) {
            if (isMissingGoogleEntityLastSeenColumnError(error) || isMissingGoogleStateHashColumnError(error)) {
                googleEntityLastSeenColumnSupported = false;
                googleStateHashColumnSupported = false;
                await dbRun(insertFallbackSql, [userId, deviceId, entityId, displayName, entityType, roomHint, online, capabilitiesJson, stateJson, nowIso, nowIso]);
            } else {
                throw error;
            }
        }
    }

    const entity = await dbGet(
        `
            SELECT *
            FROM google_home_entities
            WHERE user_id = ? AND entity_id = ?
            LIMIT 1
        `,
        [userId, entityId]
    );

    return {
        entity,
        syncChanged
    };
}

async function saveGoogleDeviceSnapshotEntityIds(userId, deviceId, entityIds = []) {
    if (!googleSyncSnapshotsTableSupported) {
        return;
    }

    const normalizedUserId = parsePositiveInt(userId);
    const normalizedDeviceId = parsePositiveInt(deviceId);
    if (!normalizedUserId || !normalizedDeviceId) {
        return;
    }

    const normalizedEntityIds = Array.from(new Set((Array.isArray(entityIds) ? entityIds : [])
        .map((entityId) => sanitizeEntityId(entityId))
        .filter(Boolean)));

    const nowIso = new Date().toISOString();
    const payload = JSON.stringify(normalizedEntityIds).slice(0, 120000);

    try {
        if (googleSyncSnapshotsUpsertSupported) {
            await dbRun(
                `
                    INSERT INTO google_home_sync_snapshots (
                        user_id,
                        device_id,
                        snapshot_entity_ids_json,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id, device_id) DO UPDATE SET
                        snapshot_entity_ids_json = excluded.snapshot_entity_ids_json,
                        updated_at = excluded.updated_at
                `,
                [normalizedUserId, normalizedDeviceId, payload, nowIso]
            );
            return;
        }
    } catch (error) {
        if (isGoogleSyncSnapshotsUpsertUnsupportedError(error)) {
            googleSyncSnapshotsUpsertSupported = false;
        } else if (isMissingGoogleSyncSnapshotsTableError(error)) {
            googleSyncSnapshotsTableSupported = false;
            return;
        } else {
            throw error;
        }
    }

    if (!googleSyncSnapshotsTableSupported) {
        return;
    }

    const existing = await dbGet(
        `
            SELECT id
            FROM google_home_sync_snapshots
            WHERE user_id = ?
              AND device_id = ?
            LIMIT 1
        `,
        [normalizedUserId, normalizedDeviceId]
    );

    if (existing) {
        await dbRun(
            `
                UPDATE google_home_sync_snapshots
                SET snapshot_entity_ids_json = ?,
                    updated_at = ?
                WHERE id = ?
            `,
            [payload, nowIso, existing.id]
        );
    } else {
        await dbRun(
            `
                INSERT INTO google_home_sync_snapshots (
                    user_id,
                    device_id,
                    snapshot_entity_ids_json,
                    updated_at
                )
                VALUES (?, ?, ?, ?)
            `,
            [normalizedUserId, normalizedDeviceId, payload, nowIso]
        );
    }
}

async function getGoogleDeviceSnapshotEntityIds(userId, deviceId) {
    if (!googleSyncSnapshotsTableSupported) {
        return [];
    }

    const normalizedUserId = parsePositiveInt(userId);
    const normalizedDeviceId = parsePositiveInt(deviceId);
    if (!normalizedUserId || !normalizedDeviceId) {
        return [];
    }

    let row;
    try {
        row = await dbGet(
            `
                SELECT snapshot_entity_ids_json
                FROM google_home_sync_snapshots
                WHERE user_id = ?
                  AND device_id = ?
                LIMIT 1
            `,
            [normalizedUserId, normalizedDeviceId]
        );
    } catch (error) {
        if (isMissingGoogleSyncSnapshotsTableError(error)) {
            googleSyncSnapshotsTableSupported = false;
            return [];
        }
        throw error;
    }

    const parsed = parseJsonSafe(row?.snapshot_entity_ids_json, []);
    return Array.from(new Set((Array.isArray(parsed) ? parsed : [])
        .map((entityId) => sanitizeEntityId(entityId))
        .filter(Boolean)));
}

async function queueGoogleCommandForEntity(userId, deviceId, entityId, action, payload) {
    const nowIso = new Date().toISOString();
    const expiresAt = new Date(Date.now() + getGoogleCommandTtlSeconds() * 1000).toISOString();
    const normalizedAction = sanitizeActionName(action) || 'set';
    const normalizedEntityId = sanitizeEntityId(entityId);

    if (!normalizedEntityId) {
        return null;
    }

    const insertResult = await dbRun(
        `
            INSERT INTO google_home_command_queue (
                user_id,
                device_id,
                entity_id,
                action,
                payload_json,
                status,
                expires_at,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)
        `,
        [
            userId,
            deviceId,
            normalizedEntityId,
            normalizedAction,
            JSON.stringify(payload || {}).slice(0, 2000),
            expiresAt,
            nowIso,
            nowIso
        ]
    );

    return dbGet(
        `
            SELECT *
            FROM google_home_command_queue
            WHERE id = ?
            LIMIT 1
        `,
        [insertResult.lastID]
    );
}

async function cleanupGoogleAuthDataForUser(userId) {
    await dbRun(`DELETE FROM google_home_auth_codes WHERE user_id = ?`, [userId]);
    await dbRun(`DELETE FROM google_home_tokens WHERE user_id = ?`, [userId]);
    await dbRun(
        `
            UPDATE users
            SET google_home_linked = 0,
                google_home_enabled = 0
            WHERE id = ?
        `,
        [userId]
    );

    const normalizedUserId = Number(userId);
    const requestSyncEntry = googleHomegraphRequestSyncQueue.get(normalizedUserId);
    if (requestSyncEntry?.timer) {
        clearTimeout(requestSyncEntry.timer);
    }
    googleHomegraphRequestSyncQueue.delete(normalizedUserId);

    const reportStateEntry = googleHomegraphReportStateQueue.get(normalizedUserId);
    if (reportStateEntry?.timer) {
        clearTimeout(reportStateEntry.timer);
    }
    googleHomegraphReportStateQueue.delete(normalizedUserId);
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

let googleRuntimeSchemaReadyPromise = null;

function isIgnorableSqliteMigrationError(error) {
    const message = String(error?.message || '').toLowerCase();
    return message.includes('duplicate column name') || message.includes('already exists');
}

async function ensureGoogleRuntimeSchemaReady() {
    if (googleRuntimeSchemaReadyPromise) {
        return googleRuntimeSchemaReadyPromise;
    }

    googleRuntimeSchemaReadyPromise = (async () => {
        const statements = [
            'ALTER TABLE google_home_entities ADD COLUMN entity_last_seen_at DATETIME',
            'ALTER TABLE google_home_entities ADD COLUMN capabilities_json TEXT',
            'ALTER TABLE google_home_entities ADD COLUMN state_hash TEXT',
            'ALTER TABLE google_home_entities ADD COLUMN last_reported_state_hash TEXT',
            'ALTER TABLE google_home_entities ADD COLUMN last_reported_at DATETIME',
            `
                CREATE TABLE IF NOT EXISTS google_home_sync_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    device_id INTEGER NOT NULL,
                    snapshot_entity_ids_json TEXT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, device_id),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                )
            `,
            'CREATE INDEX IF NOT EXISTS idx_google_home_entities_user_last_seen ON google_home_entities(user_id, entity_last_seen_at)',
            'CREATE INDEX IF NOT EXISTS idx_google_home_sync_snapshots_user_device ON google_home_sync_snapshots(user_id, device_id)'
        ];

        for (const statement of statements) {
            try {
                await dbRun(statement);
            } catch (error) {
                if (isIgnorableSqliteMigrationError(error)) {
                    continue;
                }
                throw error;
            }
        }
    })().catch((error) => {
        googleRuntimeSchemaReadyPromise = null;
        throw error;
    });

    return googleRuntimeSchemaReadyPromise;
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
    const secret = sanitizeString(process.env.PORTAL_SESSION_SECRET || '', 512);
    if (!secret || secret.length < 32) {
        throw new Error('PORTAL_SESSION_SECRET must be configured with at least 32 characters');
    }

    return secret;
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
    if (!token || !hasExactlyOneDot(token)) {
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

function setPortalSessionCookie(res, token) {
    if (!token) {
        return;
    }

    res.cookie(PORTAL_SESSION_COOKIE_NAME, token, {
        httpOnly: true,
        secure: PORTAL_SESSION_COOKIE_SECURE,
        sameSite: 'lax',
        domain: PORTAL_SESSION_COOKIE_DOMAIN,
        path: '/',
        maxAge: PORTAL_SESSION_COOKIE_MAX_AGE_MS
    });
}

function clearPortalSessionCookie(res) {
    res.clearCookie(PORTAL_SESSION_COOKIE_NAME, {
        domain: PORTAL_SESSION_COOKIE_DOMAIN,
        path: '/',
        sameSite: 'lax',
        secure: PORTAL_SESSION_COOKIE_SECURE,
        httpOnly: true
    });
}

function serializeUser(user) {
    const accessEnabled = isAccessEnabled(user.status);
    const hasSubdomain = Boolean(user.subdomain);
    return {
        id: user.id,
        email: user.email,
        subdomain: user.subdomain,
        access_token: accessEnabled ? user.access_token : null,
        status: user.status,
        domain: hasSubdomain ? `${user.subdomain}.${CLOUD_BASE_DOMAIN}` : null,
        google_home_enabled: Boolean(user.google_home_enabled),
        google_home_linked: Boolean(user.google_home_linked),
        trial_ends_at: user.trial_ends_at,
        trial_approved_at: user.trial_approved_at,
        activated_at: user.activated_at,
        payment_pending: user.status === 'payment_pending'
    };
}

function serializeUserWithPortalSession(user, portalSessionToken) {
    const accessEnabled = isAccessEnabled(user.status);
    const hasSubdomain = Boolean(user.subdomain);
    return {
        id: user.id,
        email: user.email,
        subdomain: user.subdomain,
        access_token: accessEnabled ? user.access_token : null,
        portal_session_token: portalSessionToken,
        status: user.status,
        domain: hasSubdomain ? `${user.subdomain}.${CLOUD_BASE_DOMAIN}` : null,
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
    const secret = sanitizeString(process.env.ADMIN_SESSION_SECRET || process.env.RAZORPAY_KEY_SECRET || '', 512);
    if (!secret || secret.length < 32) {
        throw new Error('ADMIN_SESSION_SECRET or RAZORPAY_KEY_SECRET must be configured with at least 32 characters');
    }

    return secret;
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
    if (!token || !hasExactlyOneDot(token)) {
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

async function requirePortalUser(req, res, next) {
    try {
        const authHeader = req.get('authorization') || '';
        const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
        const cookieToken = req.cookies?.[PORTAL_SESSION_COOKIE_NAME] || '';
        const portalToken = cookieToken || req.body?.portal_session_token || req.query?.portal_session_token || bearerToken;

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
            googleEndpointStats.fulfillment_auth_failures += 1;
            googleEndpointStats.last_fulfillment_auth_failure_at = new Date().toISOString();
            return res.status(401).json({ error: 'Missing bearer token' });
        }

        const token = authHeader.slice(7).trim();
        const user = await findUserByGoogleAccessToken(token);
        if (!user) {
            googleEndpointStats.fulfillment_auth_failures += 1;
            googleEndpointStats.last_fulfillment_auth_failure_at = new Date().toISOString();
            return res.status(401).json({ error: 'Invalid or expired access token' });
        }

        if (!user.google_home_enabled) {
            googleEndpointStats.fulfillment_auth_failures += 1;
            googleEndpointStats.last_fulfillment_auth_failure_at = new Date().toISOString();
            return res.status(403).json({ error: 'Google Home integration is disabled for this account' });
        }

        if (!isAccessEnabled(user.status)) {
            googleEndpointStats.fulfillment_auth_failures += 1;
            googleEndpointStats.last_fulfillment_auth_failure_at = new Date().toISOString();
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

function buildAdminConnectCommand(device) {
    const tunnelPort = sanitizePort(device.tunnel_port);
    const sshRoute = getAdminSshRoute();

    if (!tunnelPort || !isDeviceTunnelPortInRange(tunnelPort)) {
        return null;
    }

    const jumpHostArg = sshRoute.jump_port === 22
        ? `${sshRoute.jump_user}@${sshRoute.jump_host}`
        : `${sshRoute.jump_user}@${sshRoute.jump_host} -p ${sshRoute.jump_port}`;

    return `ssh -o "ProxyCommand=ssh -i ~/.ssh/jump_key -W %h:%p ${jumpHostArg}" -i ~/.ssh/device_key -p ${tunnelPort} ${sshRoute.target_user}@${sshRoute.target_host}`;
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

function getGoogleHomegraphDebounceMs(value, fallback, min, max) {
    if (!Number.isFinite(value)) {
        return fallback;
    }

    return Math.max(min, Math.min(max, Math.round(value)));
}

function getGoogleHomegraphRequestSyncDebounceMs() {
    return getGoogleHomegraphDebounceMs(GOOGLE_HOMEGRAPH_REQUEST_SYNC_DEBOUNCE_MS, 2500, 250, 30000);
}

function getGoogleHomegraphReportStateDebounceMs() {
    return getGoogleHomegraphDebounceMs(GOOGLE_HOMEGRAPH_REPORT_STATE_DEBOUNCE_MS, 1200, 250, 10000);
}

function getGoogleServiceAccountClientEmail() {
    return sanitizeString(process.env.GOOGLE_SERVICE_ACCOUNT_CLIENT_EMAIL || process.env.GOOGLE_HOMEGRAPH_CLIENT_EMAIL || '', 320);
}

function getGoogleServiceAccountPrivateKey() {
    const direct = sanitizeString(process.env.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY || process.env.GOOGLE_HOMEGRAPH_PRIVATE_KEY || '', 8192);
    if (direct) {
        return direct.replace(/\\n/g, '\n');
    }

    const base64Value = sanitizeString(process.env.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY_B64 || process.env.GOOGLE_HOMEGRAPH_PRIVATE_KEY_B64 || '', 12000);
    if (!base64Value) {
        return null;
    }

    try {
        return Buffer.from(base64Value, 'base64').toString('utf8').replace(/\\n/g, '\n');
    } catch (error) {
        return null;
    }
}

function getGoogleHomegraphTokenUri() {
    const configured = sanitizeString(process.env.GOOGLE_HOMEGRAPH_TOKEN_URI || '', 800);
    return configured || GOOGLE_HOMEGRAPH_DEFAULT_TOKEN_URI;
}

function getGoogleHomegraphApiBaseUrl() {
    const configured = sanitizeString(process.env.GOOGLE_HOMEGRAPH_API_BASE_URL || '', 800);
    return configured || GOOGLE_HOMEGRAPH_API_BASE_URL;
}

function hasGoogleHomegraphCredentials() {
    return Boolean(getGoogleServiceAccountClientEmail() && getGoogleServiceAccountPrivateKey());
}

function getGoogleHomegraphJwtLifetimeSeconds() {
    return 3600;
}

function base64UrlEncodeJson(value) {
    return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function generateGoogleServiceJwtAssertion() {
    const clientEmail = getGoogleServiceAccountClientEmail();
    const privateKey = getGoogleServiceAccountPrivateKey();
    if (!clientEmail || !privateKey) {
        return null;
    }

    const tokenUri = getGoogleHomegraphTokenUri();
    const now = Math.floor(Date.now() / 1000);
    const iat = now - 5;
    const exp = iat + getGoogleHomegraphJwtLifetimeSeconds();

    const header = {
        alg: 'RS256',
        typ: 'JWT'
    };

    const payload = {
        iss: clientEmail,
        scope: GOOGLE_HOMEGRAPH_SCOPE,
        aud: tokenUri,
        iat,
        exp
    };

    const encodedHeader = base64UrlEncodeJson(header);
    const encodedPayload = base64UrlEncodeJson(payload);
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(signingInput);
    signer.end();
    const signature = signer.sign(privateKey, 'base64url');
    return `${signingInput}.${signature}`;
}

function normalizeJsonForHash(value) {
    if (value === null || value === undefined) {
        return value;
    }

    if (Array.isArray(value)) {
        return value.map((item) => normalizeJsonForHash(item));
    }

    if (typeof value === 'object') {
        const sorted = {};
        const keys = Object.keys(value).sort();
        for (const key of keys) {
            sorted[key] = normalizeJsonForHash(value[key]);
        }
        return sorted;
    }

    return value;
}

function computeGoogleStateHash(value) {
    const normalized = normalizeJsonForHash(value || {});
    return crypto.createHash('sha1').update(JSON.stringify(normalized)).digest('hex');
}

async function fetchGoogleAccessTokenForHomegraph() {
    const now = Date.now();
    if (googleHomegraphAccessTokenCache.token && googleHomegraphAccessTokenCache.expiresAt > (now + 60 * 1000)) {
        return googleHomegraphAccessTokenCache.token;
    }

    const assertion = generateGoogleServiceJwtAssertion();
    if (!assertion) {
        return null;
    }

    const tokenUri = new URL(getGoogleHomegraphTokenUri());
    const postBody = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion
    }).toString();

    const tokenPayload = await new Promise((resolve, reject) => {
        const request = https.request(
            {
                protocol: tokenUri.protocol,
                hostname: tokenUri.hostname,
                port: tokenUri.port || (tokenUri.protocol === 'https:' ? 443 : 80),
                path: `${tokenUri.pathname}${tokenUri.search || ''}`,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': Buffer.byteLength(postBody),
                    'Accept': 'application/json'
                },
                timeout: 10000
            },
            (response) => {
                const chunks = [];
                response.on('data', (chunk) => chunks.push(chunk));
                response.on('end', () => {
                    const raw = Buffer.concat(chunks).toString('utf8');
                    const parsed = parseJsonSafe(raw, null);
                    const isSuccess = response.statusCode >= 200 && response.statusCode < 300;
                    if (!isSuccess) {
                        const errorText = parsed?.error_description || parsed?.error || `status_${response.statusCode || 0}`;
                        reject(new Error(`HOMEGRAPH TOKEN ERROR: ${errorText}`));
                        return;
                    }

                    resolve(parsed || {});
                });
            }
        );

        request.on('error', reject);
        request.on('timeout', () => request.destroy(new Error('HOMEGRAPH TOKEN REQUEST TIMEOUT')));
        request.write(postBody);
        request.end();
    });

    const accessToken = sanitizeString(tokenPayload?.access_token, 4000);
    if (!accessToken) {
        return null;
    }

    const expiresIn = Number(tokenPayload?.expires_in);
    const ttlMs = Number.isFinite(expiresIn) ? Math.max(60, Math.min(3600, Math.round(expiresIn))) * 1000 : 3300 * 1000;
    googleHomegraphAccessTokenCache = {
        token: accessToken,
        expiresAt: Date.now() + ttlMs
    };

    return accessToken;
}

async function postToGoogleHomegraph(pathname, payload) {
    if (!hasGoogleHomegraphCredentials()) {
        return { ok: false, skipped: true, reason: 'missing_credentials' };
    }

    const accessToken = await fetchGoogleAccessTokenForHomegraph();
    if (!accessToken) {
        return { ok: false, skipped: true, reason: 'missing_access_token' };
    }

    const baseUrl = new URL(getGoogleHomegraphApiBaseUrl());
    const endpoint = new URL(pathname, `${baseUrl.origin}/`);
    endpoint.search = baseUrl.search;
    const bodyText = JSON.stringify(payload || {});

    return new Promise((resolve, reject) => {
        const request = https.request(
            {
                protocol: endpoint.protocol,
                hostname: endpoint.hostname,
                port: endpoint.port || (endpoint.protocol === 'https:' ? 443 : 80),
                path: `${endpoint.pathname}${endpoint.search || ''}`,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(bodyText),
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/json'
                },
                timeout: 10000
            },
            (response) => {
                const chunks = [];
                response.on('data', (chunk) => chunks.push(chunk));
                response.on('end', () => {
                    const raw = Buffer.concat(chunks).toString('utf8');
                    const parsed = parseJsonSafe(raw, null);
                    const isSuccess = response.statusCode >= 200 && response.statusCode < 300;

                    if (!isSuccess && response.statusCode === 401) {
                        googleHomegraphAccessTokenCache = { token: null, expiresAt: 0 };
                    }

                    if (!isSuccess) {
                        const apiError = parsed?.error?.message || parsed?.error_description || parsed?.error || `status_${response.statusCode || 0}`;
                        resolve({ ok: false, statusCode: response.statusCode, error: apiError });
                        return;
                    }

                    resolve({ ok: true, statusCode: response.statusCode, payload: parsed || {} });
                });
            }
        );

        request.on('error', reject);
        request.on('timeout', () => request.destroy(new Error('HOMEGRAPH API REQUEST TIMEOUT')));
        request.write(bodyText);
        request.end();
    });
}

async function sendGoogleRequestSync(agentUserId) {
    const normalized = sanitizeString(agentUserId, 120);
    if (!normalized) {
        return { ok: false, skipped: true, reason: 'invalid_agent_user_id' };
    }

    return postToGoogleHomegraph('/v1/devices:requestSync', {
        agentUserId: normalized,
        async: true
    });
}

async function sendGoogleReportState(agentUserId, statesByEntityId, requestId = null) {
    const normalized = sanitizeString(agentUserId, 120);
    if (!normalized) {
        return { ok: false, skipped: true, reason: 'invalid_agent_user_id' };
    }

    const payload = {
        requestId: sanitizeGoogleRequestId(requestId) || `rs_${Date.now()}_${Math.floor(Math.random() * 10000)}`,
        agentUserId: normalized,
        payload: {
            devices: {
                states: statesByEntityId || {}
            }
        }
    };

    return postToGoogleHomegraph('/v1/devices:reportStateAndNotification', payload);
}

function scheduleGoogleRequestSyncForUser(userId, reason = 'change') {
    const normalizedUserId = parsePositiveInt(userId);
    if (!normalizedUserId || !hasGoogleHomegraphCredentials()) {
        return;
    }

    const existing = googleHomegraphRequestSyncQueue.get(normalizedUserId);
    const now = Date.now();
    if (existing?.timer) {
        clearTimeout(existing.timer);
    }

    const scheduledAt = now;
    const timer = setTimeout(async () => {
        googleHomegraphRequestSyncQueue.delete(normalizedUserId);

        try {
            const user = await dbGet(`SELECT id, google_home_enabled, google_home_linked FROM users WHERE id = ?`, [normalizedUserId]);
            if (!user || !user.google_home_enabled || !user.google_home_linked) {
                return;
            }

            const response = await sendGoogleRequestSync(String(normalizedUserId));
            if (!response?.ok && !response?.skipped) {
                markHomegraphMetricFailure('request_sync', String(normalizedUserId), response.statusCode || null, response.error || null);
                console.warn('GOOGLE REQUEST SYNC FAILED:', {
                    user_id: normalizedUserId,
                    reason,
                    error: response.error || null,
                    status: response.statusCode || null
                });
                return;
            }

            if (response?.skipped) {
                markHomegraphMetricSkipped('request_sync', String(normalizedUserId), response.reason || null);
                return;
            }

            markHomegraphMetricSuccess('request_sync', String(normalizedUserId), response?.statusCode || null);

            console.log('GOOGLE REQUEST SYNC SENT:', {
                user_id: normalizedUserId,
                reason,
                queued_for_ms: Date.now() - scheduledAt
            });
        } catch (error) {
            markHomegraphMetricFailure('request_sync', String(normalizedUserId), null, error?.message || null);
            console.error('GOOGLE REQUEST SYNC ERROR:', error);
        }
    }, getGoogleHomegraphRequestSyncDebounceMs());

    if (typeof timer.unref === 'function') {
        timer.unref();
    }

    googleHomegraphRequestSyncQueue.set(normalizedUserId, {
        reason,
        timer,
        queuedAt: scheduledAt
    });
}

async function collectGoogleReportableStateChangesForUser(userId, options = {}) {
    const normalizedUserId = parsePositiveInt(userId);
    if (!normalizedUserId) {
        return {
            states: {},
            hashes: {}
        };
    }

    const force = Boolean(options.force);
    let rows;
    try {
        rows = await dbAll(
            `
                SELECT
                    entity_id,
                    entity_type,
                    online,
                    state_json,
                    last_reported_state_hash,
                    exposed
                FROM google_home_entities
                WHERE user_id = ?
            `,
            [normalizedUserId]
        );
    } catch (error) {
        if (isMissingGoogleLastReportedColumnsError(error)) {
            googleLastReportedColumnsSupported = false;
            rows = await dbAll(
                `
                    SELECT
                        entity_id,
                        entity_type,
                        online,
                        state_json,
                        NULL AS last_reported_state_hash,
                        exposed
                    FROM google_home_entities
                    WHERE user_id = ?
                `,
                [normalizedUserId]
            );
        } else {
            throw error;
        }
    }

    const states = {};
    const hashes = {};
    for (const row of rows || []) {
        const entityId = sanitizeEntityId(row.entity_id);
        if (!entityId) {
            continue;
        }

        const parsedState = {
            ...parseGoogleEntityState(withEffectiveGoogleOnline(row))
        };
        const stateHash = computeGoogleStateHash(parsedState);
        const lastReportedHash = row.last_reported_state_hash || null;

        if (row.exposed === 1 && (force || stateHash !== lastReportedHash)) {
            states[entityId] = parsedState;
            hashes[entityId] = stateHash;
        }
    }

    return { states, hashes };
}

async function markGoogleReportedStateHashes(userId, stateHashesByEntityId) {
    const normalizedUserId = parsePositiveInt(userId);
    if (!normalizedUserId || !stateHashesByEntityId || typeof stateHashesByEntityId !== 'object' || !googleLastReportedColumnsSupported) {
        return;
    }

    const nowIso = new Date().toISOString();
    const entries = Object.entries(stateHashesByEntityId)
        .map(([entityId, hash]) => [sanitizeEntityId(entityId), sanitizeString(hash, 80)])
        .filter(([entityId, hash]) => Boolean(entityId && hash));

    if (entries.length === 0) {
        return;
    }

    const byEntityId = new Map(entries);
    const entityIds = Array.from(byEntityId.keys());
    const placeholders = entityIds.map(() => '?').join(',');
    const caseClauses = entityIds.map(() => 'WHEN ? THEN ?').join(' ');
    const args = [];
    for (const entityId of entityIds) {
        args.push(entityId, byEntityId.get(entityId));
    }

    try {
        await dbRun(
            `
                UPDATE google_home_entities
                SET last_reported_state_hash = CASE entity_id ${caseClauses} ELSE last_reported_state_hash END,
                    last_reported_at = ?
                WHERE user_id = ?
                  AND entity_id IN (${placeholders})
            `,
            [...args, nowIso, normalizedUserId, ...entityIds]
        );
    } catch (error) {
        if (isMissingGoogleLastReportedColumnsError(error)) {
            googleLastReportedColumnsSupported = false;
            return;
        }
        throw error;
    }
}

async function markGoogleEntitiesStaleByFreshness() {
    const freshnessThresholdIso = new Date(Date.now() - (getEntityFreshWindowSeconds() * 1000)).toISOString();
    const nowIso = new Date().toISOString();

    const staleClause = googleEntityLastSeenColumnSupported
        ? '(entity_last_seen_at IS NULL OR entity_last_seen_at < ?)'
        : 'updated_at < ?';

    try {
        await dbRun(
            `
                UPDATE google_home_entities
                SET online = 0,
                    updated_at = ?
                WHERE online = 1
                  AND ${staleClause}
            `,
            [nowIso, freshnessThresholdIso]
        );
    } catch (error) {
        if (isMissingGoogleEntityLastSeenColumnError(error)) {
            googleEntityLastSeenColumnSupported = false;
            await dbRun(
                `
                    UPDATE google_home_entities
                    SET online = 0,
                        updated_at = ?
                    WHERE online = 1
                      AND updated_at < ?
                `,
                [nowIso, freshnessThresholdIso]
            );
            return;
        }

        throw error;
    }
}

function scheduleGoogleReportStateForUser(userId, options = {}) {
    if (!GOOGLE_HOMEGRAPH_REPORT_STATE_ENABLED || !hasGoogleHomegraphCredentials()) {
        return;
    }

    const normalizedUserId = parsePositiveInt(userId);
    if (!normalizedUserId) {
        return;
    }

    const force = Boolean(options.force);
    const existing = googleHomegraphReportStateQueue.get(normalizedUserId);

    if (existing?.timer) {
        clearTimeout(existing.timer);
    }

    const timer = setTimeout(async () => {
        googleHomegraphReportStateQueue.delete(normalizedUserId);

        try {
            const user = await dbGet(`SELECT id, google_home_enabled, google_home_linked FROM users WHERE id = ?`, [normalizedUserId]);
            if (!user || !user.google_home_enabled || !user.google_home_linked) {
                return;
            }

            await markGoogleEntitiesStaleByFreshness();

            const reportable = await collectGoogleReportableStateChangesForUser(normalizedUserId, { force });
            const entityIds = Object.keys(reportable.states);
            if (entityIds.length === 0) {
                return;
            }

            const response = await sendGoogleReportState(String(normalizedUserId), reportable.states);
            if (!response?.ok && !response?.skipped) {
                markHomegraphMetricFailure('report_state', String(normalizedUserId), response.statusCode || null, response.error || null);
                console.warn('GOOGLE REPORT STATE FAILED:', {
                    user_id: normalizedUserId,
                    entities: entityIds.length,
                    error: response.error || null,
                    status: response.statusCode || null
                });
                return;
            }

            if (!response?.ok) {
                markHomegraphMetricSkipped('report_state', String(normalizedUserId), response?.reason || null);
                return;
            }

            await markGoogleReportedStateHashes(normalizedUserId, reportable.hashes);
            markHomegraphMetricSuccess('report_state', String(normalizedUserId), response?.statusCode || null);
            console.log('GOOGLE REPORT STATE SENT:', {
                user_id: normalizedUserId,
                entities: entityIds.length,
                force
            });
        } catch (error) {
            markHomegraphMetricFailure('report_state', String(normalizedUserId), null, error?.message || null);
            console.error('GOOGLE REPORT STATE ERROR:', error);
        }
    }, force ? 200 : getGoogleHomegraphReportStateDebounceMs());

    if (typeof timer.unref === 'function') {
        timer.unref();
    }

    googleHomegraphReportStateQueue.set(normalizedUserId, {
        timer,
        force,
        queuedAt: Date.now()
    });
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

        const portalSessionToken = createPortalSessionToken(user.email);
        setPortalSessionCookie(res, portalSessionToken);

        res.setHeader('Cache-Control', 'no-store');
        res.status(201).json({
            message,
            data: serializeUserWithPortalSession(user, portalSessionToken),
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

        const portalSessionToken = createPortalSessionToken(user.email);
        setPortalSessionCookie(res, portalSessionToken);

        res.setHeader('Cache-Control', 'no-store');
        res.status(200).json({
            message: 'Login successful',
            data: serializeUserWithPortalSession(user, portalSessionToken)
        });
    } catch (error) {
        console.error('LOGIN ERROR:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/account/subdomain', async (req, res) => {
    const { portal_session_token, subdomain } = req.body;
    const cookieToken = req.cookies?.[PORTAL_SESSION_COOKIE_NAME] || '';
    const sessionToken = cookieToken || portal_session_token;

    if (!sessionToken) {
        return res.status(400).json({ error: 'Portal session token is required' });
    }

    const normalizedSubdomain = String(subdomain || '').trim().toLowerCase();
    if (!/^[a-z0-9\-]{3,20}$/.test(normalizedSubdomain)) {
        return res.status(400).json({ error: 'Subdomain must be 3-20 lowercase letters, numbers, or hyphens.' });
    }

    try {
        const session = verifyPortalSessionToken(sessionToken);
        if (!session) {
            return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
        }

        const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
        if (!user) {
            return res.status(404).json({ error: 'Account not found' });
        }

        if (user.subdomain === normalizedSubdomain) {
            const portalSessionToken = createPortalSessionToken(user.email);
            setPortalSessionCookie(res, portalSessionToken);
            return res.status(200).json({
                message: 'Cloud address saved',
                data: serializeUserWithPortalSession(user, portalSessionToken)
            });
        }

        const existing = await dbGet(`SELECT id FROM users WHERE subdomain = ? AND id != ?`, [normalizedSubdomain, user.id]);
        if (existing) {
            return res.status(409).json({ error: 'This cloud address is already in use.' });
        }

        await dbRun(`UPDATE users SET subdomain = ? WHERE id = ?`, [normalizedSubdomain, user.id]);
        const updatedUser = await dbGet(`SELECT * FROM users WHERE id = ?`, [user.id]);
        const portalSessionToken = createPortalSessionToken(updatedUser.email);
        setPortalSessionCookie(res, portalSessionToken);

        return res.status(200).json({
            message: 'Cloud address saved',
            data: serializeUserWithPortalSession(updatedUser, portalSessionToken)
        });
    } catch (error) {
        console.error('SUBDOMAIN UPDATE ERROR:', error);
        return res.status(500).json({ error: 'Unable to save cloud address right now.' });
    }
});

app.post('/api/account/me', async (req, res) => {
    const { portal_session_token } = req.body;
    const cookieToken = req.cookies?.[PORTAL_SESSION_COOKIE_NAME] || '';
    const sessionToken = cookieToken || portal_session_token;

    if (!sessionToken) {
        return res.status(400).json({ error: 'Portal session token is required' });
    }

    try {
        const session = verifyPortalSessionToken(sessionToken);
        if (!session) {
            return res.status(401).json({ error: 'Invalid portal session. Please log in again.' });
        }

        const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
        if (!user) {
            return res.status(404).json({ error: 'Account not found' });
        }

        const portalSessionToken = createPortalSessionToken(user.email);
        setPortalSessionCookie(res, portalSessionToken);

        return res.status(200).json({
            data: serializeUserWithPortalSession(user, portalSessionToken)
        });
    } catch (error) {
        console.error('ACCOUNT ME ERROR:', error);
        return res.status(500).json({ error: 'Unable to load account details right now.' });
    }
});

app.post('/api/account/google-home/enable', requirePortalUser, async (req, res) => {
    const enable = req.body?.enabled !== false;

    try {
        if (!enable) {
            await cleanupGoogleAuthDataForUser(req.portalUser.id);
        }

        await dbRun(
            `
                UPDATE users
                SET google_home_enabled = ?
                WHERE id = ?
            `,
            [enable ? 1 : 0, req.portalUser.id]
        );

        const updatedUser = await dbGet(`SELECT * FROM users WHERE id = ?`, [req.portalUser.id]);
        const portalSessionToken = createPortalSessionToken(updatedUser.email);
        setPortalSessionCookie(res, portalSessionToken);
        if (enable) {
            scheduleGoogleRequestSyncForUser(req.portalUser.id, 'google_home_enabled');
            scheduleGoogleReportStateForUser(req.portalUser.id, { force: true });
        }
        return res.status(200).json({
            message: enable ? 'Google Home integration enabled' : 'Google Home integration disabled',
            data: serializeUserWithPortalSession(updatedUser, portalSessionToken)
        });
    } catch (error) {
        console.error('ACCOUNT GOOGLE HOME ENABLE ERROR:', error);
        return res.status(500).json({ error: 'Unable to update Google Home setting' });
    }
});

app.post('/api/account/google-home/entities', requirePortalUser, async (req, res) => {
    try {
        if (!req.portalUser.google_home_enabled || !req.portalUser.google_home_linked) {
            return res.status(200).json({ entities: [] });
        }

        const entities = await getGoogleEntitiesForUser(req.portalUser.id, { includeDisabled: true });
        return res.status(200).json({
            entities: entities.map((entity) => ({
                id: entity.id,
                entity_id: entity.entity_id,
                display_name: entity.display_name,
                entity_type: entity.entity_type,
                room_hint: entity.room_hint,
                exposed: Boolean(entity.exposed),
                online: Boolean(entity.online),
                device_online: Boolean(entity.device_online),
                entity_fresh: Boolean(entity.entity_fresh),
                state: parseJsonSafe(entity.state_json, {}),
                device_id: entity.device_id,
                updated_at: entity.updated_at
            }))
        });
    } catch (error) {
        console.error('ACCOUNT GOOGLE HOME ENTITIES ERROR:', error);
        return res.status(500).json({ error: 'Unable to load Google Home entities' });
    }
});

app.post('/api/account/google-home/entities/:entityId/expose', requirePortalUser, async (req, res) => {
    const entityId = sanitizeEntityId(req.params.entityId);
    if (!entityId) {
        return res.status(400).json({ error: 'Invalid entity id' });
    }

    if (!req.portalUser.google_home_enabled || !req.portalUser.google_home_linked) {
        return res.status(403).json({ error: 'Google Home integration is disabled for this account' });
    }

    const exposed = req.body?.exposed !== false;

    try {
        const entity = await dbGet(
            `
                SELECT *
                FROM google_home_entities
                WHERE user_id = ? AND entity_id = ?
                LIMIT 1
            `,
            [req.portalUser.id, entityId]
        );

        if (!entity) {
            return res.status(404).json({ error: 'Entity not found' });
        }

        await dbRun(
            `
                UPDATE google_home_entities
                SET exposed = ?,
                    updated_at = ?
                WHERE id = ?
            `,
            [exposed ? 1 : 0, new Date().toISOString(), entity.id]
        );

        scheduleGoogleRequestSyncForUser(req.portalUser.id, 'entity_exposure_changed');
        scheduleGoogleReportStateForUser(req.portalUser.id, { force: true });

        return res.status(200).json({
            message: exposed ? 'Entity exposed to Google Home' : 'Entity hidden from Google Home'
        });
    } catch (error) {
        console.error('ACCOUNT GOOGLE HOME ENTITY TOGGLE ERROR:', error);
        return res.status(500).json({ error: 'Unable to update entity exposure' });
    }
});

app.get(['/api/google/home/oauth', '/google/home/oauth', '/oauth'], async (req, res) => {
    googleEndpointStats.oauth_hits += 1;
    googleEndpointStats.last_oauth_at = new Date().toISOString();
    const clientId = sanitizeString(req.query?.client_id, 255);
    const redirectUri = sanitizeString(req.query?.redirect_uri, 1000);
    const state = sanitizeString(req.query?.state, 1000) || '';
    const portalTokenRaw = req.query?.portal_session_token;
    const queryPortalToken = typeof portalTokenRaw === 'string' ? portalTokenRaw.trim() : '';
    const cookiePortalToken = req.cookies?.[PORTAL_SESSION_COOKIE_NAME] || '';
    const portalToken = cookiePortalToken || queryPortalToken;

    if (!clientId || !redirectUri) {
        return res.status(400).send('Missing OAuth parameters');
    }

    if (!GOOGLE_HOME_CLIENT_ID || !GOOGLE_HOME_CLIENT_SECRET) {
        return res.status(503).send('Google Home OAuth is not configured');
    }

    if (clientId !== GOOGLE_HOME_CLIENT_ID) {
        return res.status(401).send('Invalid client_id');
    }

    if (!isTrustedGoogleRedirectUri(redirectUri)) {
        return res.status(400).send('Invalid redirect_uri');
    }

    const loginRedirectBase = `/login.html?google_oauth=1&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
    const forceCustomerLogin = req.hostname !== CUSTOMER_PORTAL_HOST || req.query?.from_cookie !== '1';
    if (!portalToken) {
        const loginRedirect = loginRedirectBase;
        if (forceCustomerLogin) {
            return res.redirect(`https://${CUSTOMER_PORTAL_HOST}${loginRedirect}`);
        }
        return res.redirect(loginRedirect);
    }

    const session = verifyPortalSessionToken(portalToken);
    if (!session) {
        const loginRedirect = loginRedirectBase;
        if (forceCustomerLogin) {
            return res.redirect(`https://${CUSTOMER_PORTAL_HOST}${loginRedirect}`);
        }
        return res.redirect(loginRedirect);
    }

    const callbackUrl = new URL(redirectUri);
    const consentChallenge = encodeURIComponent(JSON.stringify({
        client_id: clientId,
        redirect_uri: redirectUri,
        state,
        portal_session_token: portalToken
    }));

    if (req.query?.error) {
        callbackUrl.searchParams.set('error', sanitizeString(req.query.error, 120) || 'access_denied');
        callbackUrl.searchParams.set('state', state);
        return res.redirect(callbackUrl.toString());
    }

    if (req.query?.deny === '1') {
        callbackUrl.searchParams.set('error', 'access_denied');
        callbackUrl.searchParams.set('state', state);
        return res.redirect(callbackUrl.toString());
    }

    try {
        if (req.query?.debug === '1') {
            return res.status(200).json({
                ok: true,
                stage: 'authorized',
                email: session.email,
                redirect_uri: redirectUri,
                state
            });
        }

        const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
        if (!user) {
            const loginRedirect = `${loginRedirectBase}&google_oauth_error=account_not_found`;
            if (forceCustomerLogin) {
                return res.redirect(`https://${CUSTOMER_PORTAL_HOST}${loginRedirect}`);
            }
            return res.redirect(loginRedirect);
        }

        if (!isAccessEnabled(user.status)) {
            const loginRedirect = `${loginRedirectBase}&google_oauth_error=account_not_active`;
            if (forceCustomerLogin) {
                return res.redirect(`https://${CUSTOMER_PORTAL_HOST}${loginRedirect}`);
            }
            return res.redirect(loginRedirect);
        }

        if (req.query?.approved !== '1') {
            const consentUrl = `/login.html?google_oauth=1&google_oauth_consent=1&oauth_challenge=${consentChallenge}`;
            if (req.hostname !== CUSTOMER_PORTAL_HOST) {
                return res.redirect(`https://${CUSTOMER_PORTAL_HOST}${consentUrl}`);
            }
            return res.redirect(consentUrl);
        }

        if (!user.google_home_enabled) {
            await dbRun(`UPDATE users SET google_home_enabled = 1 WHERE id = ?`, [user.id]);
            user.google_home_enabled = 1;
        }

        const authCode = generateGoogleOAuthCode();
        const nowIso = new Date().toISOString();
        const expiresAt = new Date(Date.now() + getGoogleAuthCodeTtlSeconds() * 1000).toISOString();

        await dbRun(
            `
                INSERT INTO google_home_auth_codes (
                    user_id,
                    code_hash,
                    redirect_uri,
                    scopes,
                    expires_at,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
            `,
            [
                user.id,
                hashSecret(authCode),
                redirectUri,
                'google_assistant',
                expiresAt,
                nowIso
            ]
        );

        await dbRun(
            `
                UPDATE users
                SET google_home_linked = 1,
                    google_home_linked_at = COALESCE(google_home_linked_at, ?)
                WHERE id = ?
            `,
            [nowIso, user.id]
        );

        scheduleGoogleRequestSyncForUser(user.id, 'oauth_linked');
        scheduleGoogleReportStateForUser(user.id, { force: true });

        callbackUrl.searchParams.set('code', authCode);
        callbackUrl.searchParams.set('state', state);
        return res.redirect(callbackUrl.toString());
    } catch (error) {
        console.error('GOOGLE OAUTH AUTHORIZE ERROR:', error);
        const loginRedirect = `${loginRedirectBase}&google_oauth_error=server_error`;
        if (forceCustomerLogin) {
            return res.redirect(`https://${CUSTOMER_PORTAL_HOST}${loginRedirect}`);
        }
        return res.redirect(loginRedirect);
    }
});

app.post(['/api/google/home/oauth/continue', '/google/home/oauth/continue', '/oauth/continue'], async (req, res) => {
    const clientId = sanitizeString(req.body?.client_id, 255);
    const redirectUri = sanitizeString(req.body?.redirect_uri, 1000);
    const state = sanitizeString(req.body?.state, 1000) || '';
    const portalTokenRaw = req.body?.portal_session_token;
    const bodyPortalToken = typeof portalTokenRaw === 'string' ? portalTokenRaw.trim() : '';
    const cookiePortalToken = req.cookies?.[PORTAL_SESSION_COOKIE_NAME] || '';
    const portalToken = cookiePortalToken || bodyPortalToken;

    if (!clientId || !redirectUri || !portalToken) {
        return res.status(400).json({ error: 'missing_oauth_parameters' });
    }

    if (!GOOGLE_HOME_CLIENT_ID || !GOOGLE_HOME_CLIENT_SECRET) {
        return res.status(503).json({ error: 'google_oauth_not_configured' });
    }

    if (clientId !== GOOGLE_HOME_CLIENT_ID) {
        return res.status(401).json({ error: 'invalid_client_id' });
    }

    if (!isTrustedGoogleRedirectUri(redirectUri)) {
        return res.status(400).json({ error: 'invalid_redirect_uri' });
    }

    const session = verifyPortalSessionToken(portalToken);
    if (!session) {
        return res.status(401).json({ error: 'invalid_portal_session' });
    }

    setPortalSessionCookie(res, portalToken);

    const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
    if (!user) {
        return res.status(404).json({ error: 'account_not_found' });
    }

    if (!isAccessEnabled(user.status)) {
        return res.status(403).json({ error: 'account_not_active' });
    }

    if (!user.google_home_enabled) {
        await dbRun(`UPDATE users SET google_home_enabled = 1 WHERE id = ?`, [user.id]);
        user.google_home_enabled = 1;
    }

    const authorizeUrl = new URL('/api/google/home/oauth', `${req.protocol}://${req.get('host')}`);
    authorizeUrl.searchParams.set('client_id', clientId);
    authorizeUrl.searchParams.set('redirect_uri', redirectUri);
    authorizeUrl.searchParams.set('response_type', 'code');
    authorizeUrl.searchParams.set('state', state);
    authorizeUrl.searchParams.set('portal_session_token', portalToken);

    return res.status(200).json({
        ok: true,
        redirect_url: authorizeUrl.toString()
    });
});

app.post('/api/account/logout', async (_req, res) => {
    clearPortalSessionCookie(res);
    return res.status(200).json({ message: 'Logged out' });
});

app.get('/api/google/home/oauth-debug', async (req, res) => {
    if (!GOOGLE_DEBUG_ENDPOINTS_ENABLED) {
        return res.status(404).json({ error: 'not_found' });
    }

    const clientId = sanitizeString(req.query?.client_id, 255);
    const redirectUri = sanitizeString(req.query?.redirect_uri, 1000);
    const state = sanitizeString(req.query?.state, 1000) || '';
    const portalTokenRaw = req.query?.portal_session_token;
    const queryPortalToken = typeof portalTokenRaw === 'string' ? portalTokenRaw.trim() : '';
    const cookiePortalToken = req.cookies?.[PORTAL_SESSION_COOKIE_NAME] || '';
    const portalToken = cookiePortalToken || queryPortalToken;

    if (!clientId || !redirectUri) {
        return res.status(400).json({ ok: false, error: 'missing_oauth_params' });
    }

    if (!isTrustedGoogleRedirectUri(redirectUri)) {
        return res.status(400).json({ ok: false, error: 'invalid_redirect_uri' });
    }

    const payload = {
        ok: true,
        host: req.get('host') || null,
        origin: req.get('origin') || null,
        from_cookie: req.query?.from_cookie === '1',
        has_cookie_header: Boolean(req.get('cookie')),
        has_google_client_id: Boolean(GOOGLE_HOME_CLIENT_ID),
        has_google_client_secret: Boolean(GOOGLE_HOME_CLIENT_SECRET),
        client_id_matches: clientId === GOOGLE_HOME_CLIENT_ID,
        redirect_uri: redirectUri,
        state,
        has_portal_token: Boolean(portalToken),
        has_cookie_portal_token: Boolean(cookiePortalToken),
        has_query_portal_token: Boolean(queryPortalToken),
        portal_token_has_dot: portalToken.includes('.'),
        portal_token_parts: portalToken ? portalToken.split('.').length : 0,
        portal_token_preview: portalToken ? `${portalToken.slice(0, 24)}...` : null,
        portal_token_length: portalToken ? portalToken.length : 0,
        cookie_name: PORTAL_SESSION_COOKIE_NAME,
        cookie_secure: PORTAL_SESSION_COOKIE_SECURE,
        cookie_domain: PORTAL_SESSION_COOKIE_DOMAIN
    };

    if (!portalToken) {
        return res.status(200).json(payload);
    }

    const session = verifyPortalSessionToken(portalToken);
    if (!session) {
        return res.status(200).json({ ...payload, portal_session_valid: false });
    }

    const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
    if (!user) {
        return res.status(200).json({ ...payload, portal_session_valid: true, user_found: false });
    }

    return res.status(200).json({
        ...payload,
        portal_session_valid: true,
        user_found: true,
        user_email: user.email,
        user_status: user.status,
        google_home_enabled: Boolean(user.google_home_enabled)
    });
});

app.post('/api/google/home/oauth-debug-cookie', async (req, res) => {
    if (!GOOGLE_DEBUG_ENDPOINTS_ENABLED) {
        return res.status(404).json({ error: 'not_found' });
    }

    const portalTokenRaw = req.body?.portal_session_token;
    const portalToken = typeof portalTokenRaw === 'string' ? portalTokenRaw.trim() : '';

    if (!portalToken) {
        return res.status(400).json({ ok: false, error: 'portal_session_token_required' });
    }

    setPortalSessionCookie(res, portalToken);
    return res.status(200).json({
        ok: true,
        cookie_name: PORTAL_SESSION_COOKIE_NAME,
        cookie_domain: PORTAL_SESSION_COOKIE_DOMAIN,
        cookie_secure: PORTAL_SESSION_COOKIE_SECURE,
        token_has_dot: portalToken.includes('.'),
        token_parts: portalToken.split('.').length
    });
});

app.post(['/api/google/home/token', '/google/home/token', '/token'], async (req, res) => {
    googleEndpointStats.token_hits += 1;
    googleEndpointStats.last_token_at = new Date().toISOString();
    const grantType = sanitizeString(req.body?.grant_type, 64);
    const clientId = sanitizeString(req.body?.client_id, 255);
    const clientSecret = sanitizeString(req.body?.client_secret, 255);

    if (!GOOGLE_HOME_CLIENT_ID || !GOOGLE_HOME_CLIENT_SECRET) {
        return res.status(503).json({ error: 'google_oauth_not_configured' });
    }

    if (clientId !== GOOGLE_HOME_CLIENT_ID || clientSecret !== GOOGLE_HOME_CLIENT_SECRET) {
        return res.status(401).json({ error: 'invalid_client' });
    }

    try {
        if (grantType === 'authorization_code') {
            const code = sanitizeString(req.body?.code, 255);
            const redirectUri = sanitizeString(req.body?.redirect_uri, 1000);
            if (!code || !redirectUri) {
                return res.status(400).json({ error: 'invalid_request' });
            }

            const linkedUser = await findUserByGoogleAuthCode(code, redirectUri);
            if (!linkedUser) {
                return res.status(400).json({ error: 'invalid_grant' });
            }

            if (!linkedUser.google_home_enabled || !isAccessEnabled(linkedUser.status)) {
                return res.status(403).json({ error: 'access_denied' });
            }

            await dbRun(
                `
                    UPDATE google_home_auth_codes
                    SET consumed_at = ?
                    WHERE id = ?
                `,
                [new Date().toISOString(), linkedUser.oauth_code_id]
            );

            const tokenResponse = await issueGoogleTokensForUser(linkedUser.id);
            return res.status(200).json(tokenResponse);
        }

        if (grantType === 'refresh_token') {
            const refreshToken = sanitizeString(req.body?.refresh_token, 255);
            if (!refreshToken) {
                return res.status(400).json({ error: 'invalid_request' });
            }

            const refreshRow = await findGoogleRefreshTokenRow(refreshToken);
            if (!refreshRow) {
                return res.status(400).json({ error: 'invalid_grant' });
            }

            const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [refreshRow.user_id]);
            if (!user || !user.google_home_enabled || !isAccessEnabled(user.status)) {
                return res.status(403).json({ error: 'access_denied' });
            }

            const tokenResponse = await issueGoogleTokensForUser(user.id, refreshToken);
            return res.status(200).json(tokenResponse);
        }

        return res.status(400).json({ error: 'unsupported_grant_type' });
    } catch (error) {
        console.error('GOOGLE TOKEN ERROR:', error);
        return res.status(500).json({ error: 'server_error' });
    }
});

app.get(['/api/google/home/fulfillment', '/google/home/fulfillment', '/fulfillment'], (_req, res) => {
    return res.status(200).send('ok');
});

app.head(['/api/google/home/fulfillment', '/google/home/fulfillment', '/fulfillment'], (_req, res) => {
    return res.status(200).end();
});

app.post(['/api/google/home/fulfillment', '/google/home/fulfillment', '/fulfillment'], trackGoogleFulfillmentPreAuth, requireGoogleBearer, async (req, res) => {
    googleEndpointStats.fulfillment_hits += 1;
    googleEndpointStats.last_fulfillment_at = new Date().toISOString();
    const requestId = sanitizeGoogleRequestId(req.body?.requestId) || `req_${Date.now()}`;
    const inputs = Array.isArray(req.body?.inputs) ? req.body.inputs : [];
    const input = inputs[0] || {};
    const intent = sanitizeString(input.intent, 120) || '';

    try {
        await markGoogleEntitiesStaleByFreshness();
        await refreshGoogleEntityFreshnessFromDeviceHeartbeat(req.googleUser.id, null);

        if (intent === 'action.devices.SYNC') {
            const entities = await getGoogleEntitiesForUser(req.googleUser.id, { includeDisabled: false });
            const devices = entities.map((entity) => buildGoogleDeviceObject(withEffectiveGoogleOnline(entity)));

            if (GOOGLE_DEBUG_ENDPOINTS_ENABLED) {
                console.log('GOOGLE SYNC RESPONSE SUMMARY:', {
                    user_id: req.googleUser.id,
                    devices_count: devices.length,
                    enabled: Boolean(req.googleUser.google_home_enabled),
                    linked: Boolean(req.googleUser.google_home_linked)
                });
            }

            return res.status(200).json({
                requestId,
                payload: {
                    agentUserId: String(req.googleUser.id),
                    devices
                }
            });
        }

        if (intent === 'action.devices.QUERY') {
            const queryPayload = input.payload || {};
            const requestedDevices = Array.isArray(queryPayload.devices) ? queryPayload.devices : [];
            const requestedIds = requestedDevices
                .map((item) => sanitizeEntityId(item?.id))
                .filter(Boolean);

            const entities = await getGoogleEntitiesForUser(req.googleUser.id, { includeDisabled: false });
            const entitiesMap = new Map(entities.map((entity) => [entity.entity_id, entity]));
            const devicesState = {};

            for (const entityId of requestedIds) {
                const entity = entitiesMap.get(entityId);
                if (!entity) {
                    devicesState[entityId] = {
                        online: false,
                        status: 'ERROR',
                        errorCode: 'deviceOffline'
                    };
                    continue;
                }

                const effectiveEntity = withEffectiveGoogleOnline(entity);
                if (effectiveEntity.online !== 1) {
                    devicesState[entityId] = {
                        online: false,
                        status: 'ERROR',
                        errorCode: 'deviceOffline'
                    };
                    continue;
                }

                devicesState[entityId] = parseGoogleEntityState(effectiveEntity);
            }

            if (GOOGLE_CAPABILITY_ENGINE_V2) {
                for (const requestedId of requestedIds) {
                    if (!devicesState[requestedId]) {
                        devicesState[requestedId] = {
                            online: false,
                            status: 'ERROR',
                            errorCode: 'deviceOffline'
                        };
                    }
                }
            }

            return res.status(200).json({
                requestId,
                payload: {
                    devices: devicesState
                }
            });
        }

        if (intent === 'action.devices.EXECUTE') {
            const executePayload = input.payload || {};
            const commands = Array.isArray(executePayload.commands) ? executePayload.commands : [];
            const entities = await getGoogleEntitiesForUser(req.googleUser.id, { includeDisabled: false });
            const entitiesMap = new Map(entities.map((entity) => [entity.entity_id, entity]));
            const commandResults = [];

            for (const commandEntry of commands) {
                const targetDevices = Array.isArray(commandEntry.devices) ? commandEntry.devices : [];
                const executions = Array.isArray(commandEntry.execution) ? commandEntry.execution : [];

                for (const target of targetDevices) {
                    const entityId = sanitizeEntityId(target?.id);
                    if (!entityId) {
                        continue;
                    }

                    const entity = entitiesMap.get(entityId);
                    if (!entity) {
                        commandResults.push({
                            ids: [entityId],
                            status: 'ERROR',
                            errorCode: 'deviceOffline'
                        });
                        continue;
                    }

                    if (!isEntityEffectivelyOnline(entity)) {
                        commandResults.push({
                            ids: [entityId],
                            status: 'ERROR',
                            errorCode: 'deviceOffline'
                        });
                        continue;
                    }

                    for (const execution of executions) {
                        const commandName = sanitizeActionName(execution?.command);
                        const params = execution?.params || {};

                        if (!supportsGoogleCommandForEntity(entity, commandName)) {
                            commandResults.push({
                                ids: [entityId],
                                status: 'ERROR',
                                errorCode: 'notSupported'
                            });
                            continue;
                        }

                        let action = null;
                        let payload = {};
                        if (commandName === 'action.devices.commands.OnOff') {
                            action = 'set_on';
                            payload = { on: Boolean(params?.on) };
                        } else if (commandName === 'action.devices.commands.BrightnessAbsolute') {
                            action = 'set_brightness';
                            payload = { brightness: Math.max(0, Math.min(100, Number(params?.brightness || 0))) };
                        } else if (commandName === 'action.devices.commands.SetFanSpeed') {
                            action = 'set_fan_speed';
                            const speedPercent = Number(params?.fanSpeedPercent ?? params?.fanSpeed ?? 0);
                            payload = {
                                speed_percent: Number.isFinite(speedPercent)
                                    ? Math.max(0, Math.min(100, Math.round(speedPercent)))
                                    : 0
                            };
                        } else if (commandName === 'action.devices.commands.OpenClose') {
                            action = 'set_open_percent';
                            payload = {
                                openPercent: Math.max(0, Math.min(100, Number(params?.openPercent ?? 0)))
                            };
                        } else if (commandName === 'action.devices.commands.LockUnlock') {
                            action = 'set_lock';
                            payload = {
                                lock: Boolean(params?.lock)
                            };
                        } else if (commandName === 'action.devices.commands.ThermostatSetMode') {
                            action = 'set_thermostat_mode';
                            payload = {
                                mode: normalizeGoogleThermostatMode(params?.thermostatMode)
                            };
                        } else if (commandName === 'action.devices.commands.ThermostatTemperatureSetpoint') {
                            action = 'set_thermostat_setpoint';
                            payload = {
                                setpoint: Number(params?.thermostatTemperatureSetpoint || 22)
                            };
                        } else if (commandName === 'action.devices.commands.setVolume') {
                            action = 'set_volume';
                            payload = {
                                volume: Math.max(0, Math.min(100, Number(params?.volumeLevel ?? 0)))
                            };
                            if (Object.prototype.hasOwnProperty.call(params || {}, 'mute')) {
                                payload.muted = Boolean(params?.mute);
                            }
                        } else if (commandName === 'action.devices.commands.mute') {
                            action = 'set_mute';
                            payload = {
                                muted: Boolean(params?.mute)
                            };
                        } else if (commandName === 'action.devices.commands.activateScene') {
                            action = 'activate_scene';
                            payload = {
                                deactivate: Boolean(params?.deactivate)
                            };
                        } else if (commandName === 'action.devices.commands.StartStop') {
                            action = 'set_start_stop';
                            payload = {
                                start: Boolean(params?.start)
                            };
                        } else if (commandName === 'action.devices.commands.PauseUnpause') {
                            action = 'set_pause';
                            payload = {
                                pause: Boolean(params?.pause)
                            };
                        } else {
                            commandResults.push({
                                ids: [entityId],
                                status: 'ERROR',
                                errorCode: 'notSupported'
                            });
                            continue;
                        }

                        await queueGoogleCommandForEntity(req.googleUser.id, entity.device_id, entity.entity_id, action, payload);
                        commandResults.push({
                            ids: [entityId],
                            status: 'SUCCESS',
                            states: {
                                online: true,
                                ...(payload.on !== undefined ? { on: payload.on } : {}),
                                ...(payload.brightness !== undefined ? { brightness: payload.brightness } : {}),
                                ...(payload.openPercent !== undefined ? { openPercent: payload.openPercent } : {}),
                                ...(payload.speed_percent !== undefined
                                    ? {
                                        currentFanSpeedPercent: payload.speed_percent,
                                        currentFanSpeedSetting: String(payload.speed_percent)
                                    }
                                    : {}),
                                ...(payload.lock !== undefined ? { isLocked: payload.lock } : {}),
                                ...(payload.mode !== undefined ? { thermostatMode: payload.mode } : {}),
                                ...(payload.setpoint !== undefined ? { thermostatTemperatureSetpoint: payload.setpoint } : {}),
                                ...(payload.volume !== undefined ? { currentVolume: payload.volume } : {}),
                                ...(payload.muted !== undefined ? { isMuted: payload.muted } : {}),
                                ...(payload.start !== undefined ? { isRunning: payload.start } : {}),
                                ...(payload.pause !== undefined ? { isPaused: payload.pause } : {})
                            }
                        });
                    }
                }
            }

            return res.status(200).json({
                requestId,
                payload: {
                    commands: commandResults
                }
            });
        }

        if (intent === 'action.devices.DISCONNECT') {
            await cleanupGoogleAuthDataForUser(req.googleUser.id);
            scheduleGoogleRequestSyncForUser(req.googleUser.id, 'google_home_unlinked');
            return res.status(200).json({ requestId, payload: {} });
        }

        return res.status(400).json({ error: 'Unsupported intent' });
    } catch (error) {
        console.error('GOOGLE FULFILLMENT ERROR:', error);
        return res.status(500).json({ error: 'Unable to process Google fulfillment request' });
    }
});

app.post('/api/google/home/fulfillment-test', async (req, res) => {
    const bearer = req.get('authorization') || '';
    const token = bearer.startsWith('Bearer ') ? bearer.slice(7).trim() : sanitizeString(req.body?.access_token || '', 512);
    if (!token) {
        return res.status(401).json({ error: 'missing_access_token' });
    }

    const user = await findUserByGoogleAccessToken(token);
    if (!user) {
        return res.status(401).json({ error: 'invalid_or_expired_access_token' });
    }

    const entities = await getGoogleEntitiesForUser(user.id, { includeDisabled: false });
    return res.status(200).json({
        ok: true,
        user_id: user.id,
        entities_count: entities.length,
        linked: Boolean(user.google_home_linked),
        enabled: Boolean(user.google_home_enabled)
    });
});

app.post('/api/internal/devices/google-home/entities', requireDeviceAuth, async (req, res) => {
    try {
        try {
            await ensureGoogleRuntimeSchemaReady();
        } catch (schemaError) {
            console.warn('GOOGLE RUNTIME SCHEMA LAZY CHECK FAILED:', schemaError?.message || schemaError);
        }
        const device = req.device;
        const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [device.user_id]);
        const nowIso = new Date().toISOString();
        await refreshGoogleEntityFreshnessFromDeviceHeartbeat(device.user_id, device.id);
        await markGoogleEntitiesStaleByFreshness();
        if (!user || !user.google_home_enabled) {
            await dbRun(
                `
                    UPDATE google_home_entities
                    SET online = 0,
                        updated_at = ?
                    WHERE user_id = ?
                      AND device_id = ?
                `,
                [nowIso, device.user_id, device.id]
            );
            await saveGoogleDeviceSnapshotEntityIds(device.user_id, device.id, []);

            return res.status(200).json({
                message: 'Google Home integration is disabled for this account',
                synced_count: 0,
                synced_entities: []
            });
        }

        const entitiesPayload = Array.isArray(req.body?.entities) ? req.body.entities : [];
        const fullSnapshot = req.body?.full_snapshot !== false;
        const snapshotEntityIds = Array.isArray(req.body?.snapshot_entity_ids)
            ? req.body.snapshot_entity_ids
            : null;

        const assignEntityLastSeen = googleEntityLastSeenColumnSupported
            ? 'entity_last_seen_at = ?,'
            : '';
        const assignEntityLastSeenParams = googleEntityLastSeenColumnSupported ? [nowIso] : [];

        if (entitiesPayload.length === 0) {
            if (fullSnapshot && snapshotEntityIds) {
                const normalizedSnapshotIds = Array.from(new Set(snapshotEntityIds
                    .map((item) => sanitizeEntityId(item))
                    .filter(Boolean)));
                const placeholders = normalizedSnapshotIds.map(() => '?').join(',');

                if (normalizedSnapshotIds.length > 0) {
                    try {
                        await dbRun(
                            `
                                UPDATE google_home_entities
                                SET online = 0,
                                    ${assignEntityLastSeen}
                                    updated_at = ?
                                WHERE user_id = ?
                                  AND device_id = ?
                                  AND entity_id NOT IN (${placeholders})
                            `,
                            [...assignEntityLastSeenParams, nowIso, device.user_id, device.id, ...normalizedSnapshotIds]
                        );
                    } catch (error) {
                        if (isMissingGoogleEntityLastSeenColumnError(error)) {
                            googleEntityLastSeenColumnSupported = false;
                            await dbRun(
                                `
                                    UPDATE google_home_entities
                                    SET online = 0,
                                        updated_at = ?
                                    WHERE user_id = ?
                                      AND device_id = ?
                                      AND entity_id NOT IN (${placeholders})
                                `,
                                [nowIso, device.user_id, device.id, ...normalizedSnapshotIds]
                            );
                        } else {
                            throw error;
                        }
                    }
                } else {
                    try {
                        await dbRun(
                            `
                                UPDATE google_home_entities
                                SET online = 0,
                                    ${assignEntityLastSeen}
                                    updated_at = ?
                                WHERE user_id = ?
                                  AND device_id = ?
                            `,
                            [...assignEntityLastSeenParams, nowIso, device.user_id, device.id]
                        );
                    } catch (error) {
                        if (isMissingGoogleEntityLastSeenColumnError(error)) {
                            googleEntityLastSeenColumnSupported = false;
                            await dbRun(
                                `
                                    UPDATE google_home_entities
                                    SET online = 0,
                                        updated_at = ?
                                    WHERE user_id = ?
                                      AND device_id = ?
                                `,
                                [nowIso, device.user_id, device.id]
                            );
                        } else {
                            throw error;
                        }
                    }
                }

                await saveGoogleDeviceSnapshotEntityIds(device.user_id, device.id, normalizedSnapshotIds);
                scheduleGoogleRequestSyncForUser(device.user_id, 'entity_inventory_snapshot_commit');
                scheduleGoogleReportStateForUser(device.user_id, { force: false });

                return res.status(200).json({
                    message: 'Snapshot inventory committed',
                    synced_count: 0,
                    synced_entities: []
                });
            }

            console.warn('DEVICE GOOGLE ENTITIES SYNC: EMPTY PAYLOAD, SKIPPING INVENTORY UPDATE', {
                user_id: device.user_id,
                device_id: device.id
            });

            return res.status(200).json({
                message: 'No entities received, inventory update skipped',
                synced_count: 0,
                synced_entities: []
            });
        }

        const synced = [];
        const incomingEntityIds = [];
        let shouldRequestSync = false;

        for (const entityPayload of entitiesPayload) {
            const normalizedEntityId = sanitizeEntityId(entityPayload?.entity_id);
            if (normalizedEntityId) {
                incomingEntityIds.push(normalizedEntityId);
            }

            const upserted = await upsertGoogleEntityFromDevice(device.user_id, device.id, entityPayload);
            if (upserted?.entity) {
                synced.push(upserted.entity.entity_id);
                if (upserted.syncChanged) {
                    shouldRequestSync = true;
                }
            }
        }

        const uniqueIncomingEntityIds = Array.from(new Set(incomingEntityIds));
        if (uniqueIncomingEntityIds.length === 0) {
            console.warn('DEVICE GOOGLE ENTITIES SYNC: NO VALID ENTITY IDS, SKIPPING INVENTORY UPDATE', {
                user_id: device.user_id,
                device_id: device.id,
                received_count: entitiesPayload.length
            });

            return res.status(200).json({
                message: 'No valid entities in payload, inventory update skipped',
                synced_count: synced.length,
                synced_entities: synced
            });
        }

        const beforeRows = await dbAll(
            `
                SELECT entity_id
                FROM google_home_entities
                WHERE user_id = ?
                  AND device_id = ?
                  AND online = 1
            `,
            [device.user_id, device.id]
        );
        const beforeSet = new Set((beforeRows || []).map((row) => sanitizeEntityId(row.entity_id)).filter(Boolean));

        if (fullSnapshot && uniqueIncomingEntityIds.length > 0) {
            const baselineIds = snapshotEntityIds
                ? Array.from(new Set(snapshotEntityIds.map((item) => sanitizeEntityId(item)).filter(Boolean)))
                : await getGoogleDeviceSnapshotEntityIds(device.user_id, device.id);
            const snapshotIdsSet = new Set(baselineIds);
            for (const entityId of uniqueIncomingEntityIds) {
                snapshotIdsSet.add(entityId);
            }
            const effectiveSnapshotIds = Array.from(snapshotIdsSet);
            const placeholders = effectiveSnapshotIds.map(() => '?').join(',');
            try {
                await dbRun(
                    `
                        UPDATE google_home_entities
                        SET online = 0,
                            ${assignEntityLastSeen}
                            updated_at = ?
                        WHERE user_id = ?
                          AND device_id = ?
                          AND entity_id NOT IN (${placeholders})
                    `,
                    [...assignEntityLastSeenParams, nowIso, device.user_id, device.id, ...effectiveSnapshotIds]
                );
            } catch (error) {
                if (isMissingGoogleEntityLastSeenColumnError(error)) {
                    googleEntityLastSeenColumnSupported = false;
                    await dbRun(
                        `
                            UPDATE google_home_entities
                            SET online = 0,
                                updated_at = ?
                            WHERE user_id = ?
                              AND device_id = ?
                              AND entity_id NOT IN (${placeholders})
                        `,
                        [nowIso, device.user_id, device.id, ...effectiveSnapshotIds]
                    );
                } else {
                    throw error;
                }
            }

            await saveGoogleDeviceSnapshotEntityIds(device.user_id, device.id, effectiveSnapshotIds);
        } else if (fullSnapshot) {
            try {
                await dbRun(
                    `
                        UPDATE google_home_entities
                        SET online = 0,
                            ${assignEntityLastSeen}
                            updated_at = ?
                        WHERE user_id = ?
                          AND device_id = ?
                    `,
                    [...assignEntityLastSeenParams, nowIso, device.user_id, device.id]
                );
            } catch (error) {
                if (isMissingGoogleEntityLastSeenColumnError(error)) {
                    googleEntityLastSeenColumnSupported = false;
                    await dbRun(
                        `
                            UPDATE google_home_entities
                            SET online = 0,
                                updated_at = ?
                            WHERE user_id = ?
                              AND device_id = ?
                        `,
                        [nowIso, device.user_id, device.id]
                    );
                } else {
                    throw error;
                }
            }
            await saveGoogleDeviceSnapshotEntityIds(device.user_id, device.id, []);
        }

        const afterRows = await dbAll(
            `
                SELECT entity_id
                FROM google_home_entities
                WHERE user_id = ?
                  AND device_id = ?
                  AND online = 1
            `,
            [device.user_id, device.id]
        );
        const afterSet = new Set((afterRows || []).map((row) => sanitizeEntityId(row.entity_id)).filter(Boolean));
        if (!shouldRequestSync && beforeSet.size !== afterSet.size) {
            shouldRequestSync = true;
        }

        if (!shouldRequestSync) {
            for (const id of beforeSet) {
                if (!afterSet.has(id)) {
                    shouldRequestSync = true;
                    break;
                }
            }
        }

        if (shouldRequestSync) {
            scheduleGoogleRequestSyncForUser(device.user_id, 'entity_inventory_changed');
        }
        scheduleGoogleReportStateForUser(device.user_id, { force: false });

        return res.status(200).json({
            message: 'Entities synced',
            synced_count: synced.length,
            synced_entities: synced
        });
    } catch (error) {
        console.error('DEVICE GOOGLE ENTITIES SYNC ERROR:', error);
        return res.status(500).json({ error: 'Unable to sync Google entities' });
    }
});

app.post('/api/internal/devices/google-home/commands', requireDeviceAuth, async (req, res) => {
    try {
        const device = req.device;
        const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [device.user_id]);
        if (!user || !user.google_home_enabled) {
            return res.status(200).json({ commands: [] });
        }

        const nowIso = new Date().toISOString();
        await dbRun(
            `
                UPDATE google_home_command_queue
                SET status = 'expired',
                    updated_at = ?
                WHERE device_id = ?
                  AND status IN ('pending', 'dispatched')
                  AND expires_at <= ?
            `,
            [nowIso, device.id, nowIso]
        );

        const rows = await dbAll(
            `
                SELECT *
                FROM google_home_command_queue
                WHERE device_id = ?
                  AND status = 'pending'
                  AND expires_at > ?
                ORDER BY id ASC
                LIMIT 20
            `,
            [device.id, nowIso]
        );

        const commandIds = (rows || []).map((row) => row.id);
        if (commandIds.length > 0) {
            const placeholders = commandIds.map(() => '?').join(',');
            await dbRun(
                `
                    UPDATE google_home_command_queue
                    SET status = 'dispatched',
                        updated_at = ?
                    WHERE id IN (${placeholders})
                `,
                [nowIso, ...commandIds]
            );
        }

        return res.status(200).json({
            commands: (rows || []).map((row) => ({
                id: row.id,
                entity_id: row.entity_id,
                action: row.action,
                payload: parseJsonSafe(row.payload_json, {})
            }))
        });
    } catch (error) {
        console.error('DEVICE GOOGLE COMMAND POLL ERROR:', error);
        return res.status(500).json({ error: 'Unable to load Google commands' });
    }
});

app.post('/api/internal/devices/google-home/commands/cleanup', requireDeviceAuth, async (req, res) => {
    try {
        const device = req.device;
        const nowIso = new Date().toISOString();
        await dbRun(
            `
                UPDATE google_home_command_queue
                SET status = 'expired',
                    updated_at = ?
                WHERE device_id = ?
                  AND status IN ('pending', 'dispatched')
                  AND expires_at <= ?
            `,
            [nowIso, device.id, nowIso]
        );

        return res.status(200).json({ message: 'Command queue cleaned' });
    } catch (error) {
        console.error('DEVICE GOOGLE COMMAND CLEANUP ERROR:', error);
        return res.status(500).json({ error: 'Unable to cleanup Google commands' });
    }
});

app.post('/api/internal/devices/google-home/commands/:id/result', requireDeviceAuth, async (req, res) => {
    const commandId = parsePositiveInt(req.params.id);
    if (!commandId) {
        return res.status(400).json({ error: 'Invalid command id' });
    }

    try {
        const device = req.device;
        const command = await dbGet(
            `
                SELECT *
                FROM google_home_command_queue
                WHERE id = ? AND device_id = ?
                LIMIT 1
            `,
            [commandId, device.id]
        );

        if (!command) {
            return res.status(404).json({ error: 'Command not found' });
        }

        const success = req.body?.success !== false;
        const errorMessage = sanitizeString(req.body?.error, 240);
        const nowIso = new Date().toISOString();
        await dbRun(
            `
                UPDATE google_home_command_queue
                SET status = ?,
                    result_json = ?,
                    updated_at = ?
                WHERE id = ?
            `,
            [
                success ? 'completed' : 'failed',
                JSON.stringify({
                    success,
                    error: errorMessage || null,
                    state: req.body?.state || null
                }).slice(0, 2500),
                nowIso,
                command.id
            ]
        );

        if (success && req.body?.state) {
            const normalizedState = req.body.state || {};
            const stateJson = JSON.stringify(normalizedState).slice(0, 2500);
            const stateHash = computeGoogleStateHash({
                online: true,
                ...normalizedState
            });
            const updateWithLastSeenSql = `
                UPDATE google_home_entities
                SET state_json = ?,
                    online = 1,
                    entity_last_seen_at = ?,
                    updated_at = ?
                WHERE user_id = ?
                  AND device_id = ?
                  AND entity_id = ?
            `;

            const updateFallbackSql = `
                UPDATE google_home_entities
                SET state_json = ?,
                    online = 1,
                    updated_at = ?
                WHERE user_id = ?
                  AND device_id = ?
                  AND entity_id = ?
            `;

            const updateWithLastSeenAndHashSql = `
                UPDATE google_home_entities
                SET state_json = ?,
                    online = 1,
                    entity_last_seen_at = ?,
                    state_hash = ?,
                    updated_at = ?
                WHERE user_id = ?
                  AND device_id = ?
                  AND entity_id = ?
            `;

            const updateFallbackAndHashSql = `
                UPDATE google_home_entities
                SET state_json = ?,
                    online = 1,
                    state_hash = ?,
                    updated_at = ?
                WHERE user_id = ?
                  AND device_id = ?
                  AND entity_id = ?
            `;

            try {
                if (googleEntityLastSeenColumnSupported && googleStateHashColumnSupported) {
                    await dbRun(
                        updateWithLastSeenAndHashSql,
                        [
                            stateJson,
                            nowIso,
                            stateHash,
                            nowIso,
                            command.user_id,
                            device.id,
                            command.entity_id
                        ]
                    );
                } else if (googleEntityLastSeenColumnSupported && !googleStateHashColumnSupported) {
                    await dbRun(
                        updateWithLastSeenSql,
                        [
                            stateJson,
                            nowIso,
                            nowIso,
                            command.user_id,
                            device.id,
                            command.entity_id
                        ]
                    );
                } else if (!googleEntityLastSeenColumnSupported && googleStateHashColumnSupported) {
                    await dbRun(
                        updateFallbackAndHashSql,
                        [
                            stateJson,
                            stateHash,
                            nowIso,
                            command.user_id,
                            device.id,
                            command.entity_id
                        ]
                    );
                } else {
                    await dbRun(
                        updateFallbackSql,
                        [
                            stateJson,
                            nowIso,
                            command.user_id,
                            device.id,
                            command.entity_id
                        ]
                    );
                }
            } catch (error) {
                if (isMissingGoogleEntityLastSeenColumnError(error) || isMissingGoogleStateHashColumnError(error)) {
                    googleEntityLastSeenColumnSupported = false;
                    googleStateHashColumnSupported = false;
                    await dbRun(
                        updateFallbackSql,
                        [
                            stateJson,
                            nowIso,
                            command.user_id,
                            device.id,
                            command.entity_id
                        ]
                    );
                } else {
                    throw error;
                }
            }

            scheduleGoogleReportStateForUser(command.user_id, { force: false });
        }

        return res.status(200).json({ message: 'Command result recorded' });
    } catch (error) {
        console.error('DEVICE GOOGLE COMMAND RESULT ERROR:', error);
        return res.status(500).json({ error: 'Unable to store command result' });
    }
});

function requireGoogleHomegraphAdmin(req, res, next) {
    const authHeader = req.get('authorization') || '';
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const adminToken = sanitizeString(process.env.GOOGLE_HOMEGRAPH_ADMIN_TOKEN || '', 512) || '';

    if (!adminToken) {
        return res.status(503).json({ error: 'google_homegraph_admin_token_not_configured' });
    }

    if (!bearerToken || bearerToken !== adminToken) {
        return res.status(401).json({ error: 'invalid_homegraph_admin_token' });
    }

    return next();
}

app.post('/api/internal/google/homegraph/request-sync', requireGoogleHomegraphAdmin, async (req, res) => {
    const userId = parsePositiveInt(req.body?.user_id);
    if (!userId) {
        return res.status(400).json({ error: 'user_id is required' });
    }

    try {
        const user = await dbGet(`SELECT id, google_home_enabled, google_home_linked FROM users WHERE id = ?`, [userId]);
        if (!user || !user.google_home_enabled || !user.google_home_linked) {
            return res.status(404).json({ error: 'eligible_google_user_not_found' });
        }

        const result = await sendGoogleRequestSync(String(userId));
        if (!result.ok && !result.skipped) {
            markHomegraphMetricFailure('request_sync', String(userId), result.statusCode || null, result.error || null);
            return res.status(502).json({ error: 'request_sync_failed', details: result });
        }

        if (result.skipped) {
            markHomegraphMetricSkipped('request_sync', String(userId), result.reason || null);
        } else {
            markHomegraphMetricSuccess('request_sync', String(userId), result.statusCode || null);
        }

        return res.status(200).json({
            message: result.skipped ? 'request_sync_skipped' : 'request_sync_sent',
            details: result
        });
    } catch (error) {
        console.error('GOOGLE HOMEGRAPH REQUEST SYNC INTERNAL ERROR:', error);
        return res.status(500).json({ error: 'unable_to_send_request_sync' });
    }
});

app.post('/api/internal/google/homegraph/report-state', requireGoogleHomegraphAdmin, async (req, res) => {
    const userId = parsePositiveInt(req.body?.user_id);
    if (!userId) {
        return res.status(400).json({ error: 'user_id is required' });
    }

    const force = req.body?.force !== false;

    try {
        const user = await dbGet(`SELECT id, google_home_enabled, google_home_linked FROM users WHERE id = ?`, [userId]);
        if (!user || !user.google_home_enabled || !user.google_home_linked) {
            return res.status(404).json({ error: 'eligible_google_user_not_found' });
        }

        const reportable = await collectGoogleReportableStateChangesForUser(userId, { force });
        const entityIds = Object.keys(reportable.states);
        if (entityIds.length === 0) {
            return res.status(200).json({ message: 'no_state_changes' });
        }

        const result = await sendGoogleReportState(String(userId), reportable.states);
        if (!result.ok && !result.skipped) {
            markHomegraphMetricFailure('report_state', String(userId), result.statusCode || null, result.error || null);
            return res.status(502).json({ error: 'report_state_failed', details: result });
        }

        if (!result.ok) {
            markHomegraphMetricSkipped('report_state', String(userId), result.reason || null);
            return res.status(200).json({ message: 'report_state_skipped', details: result });
        }

        await markGoogleReportedStateHashes(userId, reportable.hashes);
        markHomegraphMetricSuccess('report_state', String(userId), result.statusCode || null);
        return res.status(200).json({
            message: result.skipped ? 'report_state_skipped' : 'report_state_sent',
            entity_count: entityIds.length,
            details: result
        });
    } catch (error) {
        console.error('GOOGLE HOMEGRAPH REPORT STATE INTERNAL ERROR:', error);
        return res.status(500).json({ error: 'unable_to_send_report_state' });
    }
});

app.get('/api/google/home/homegraph-debug', async (req, res) => {
    if (!GOOGLE_DEBUG_ENDPOINTS_ENABLED) {
        return res.status(404).json({ error: 'not_found' });
    }

    try {
        await ensureGoogleRuntimeSchemaReady();
    } catch (error) {
        console.warn('GOOGLE RUNTIME SCHEMA CHECK FAILED:', error?.message || error);
    }

    const hasCredentials = hasGoogleHomegraphCredentials();
    const clientEmail = getGoogleServiceAccountClientEmail();
    const tokenCacheValid = Boolean(googleHomegraphAccessTokenCache.token && googleHomegraphAccessTokenCache.expiresAt > Date.now());

    return res.status(200).json({
        ok: true,
        report_state_enabled: GOOGLE_HOMEGRAPH_REPORT_STATE_ENABLED,
        has_service_account_email: Boolean(clientEmail),
        has_service_account_private_key: Boolean(getGoogleServiceAccountPrivateKey()),
        has_credentials: hasCredentials,
        token_uri: getGoogleHomegraphTokenUri(),
        api_base_url: getGoogleHomegraphApiBaseUrl(),
        request_sync_debounce_ms: getGoogleHomegraphRequestSyncDebounceMs(),
        report_state_debounce_ms: getGoogleHomegraphReportStateDebounceMs(),
        entity_fresh_window_seconds: getEntityFreshWindowSeconds(),
        token_cache_valid: tokenCacheValid,
        runtime_flags: {
            entity_last_seen_supported: googleEntityLastSeenColumnSupported,
            state_hash_supported: googleStateHashColumnSupported,
            last_reported_supported: googleLastReportedColumnsSupported,
            sync_snapshots_table_supported: googleSyncSnapshotsTableSupported,
            sync_snapshots_upsert_supported: googleSyncSnapshotsUpsertSupported
        },
        queued_request_sync_users: Array.from(googleHomegraphRequestSyncQueue.keys()),
        queued_report_state_users: Array.from(googleHomegraphReportStateQueue.keys()),
        metrics: homegraphMetrics
    });
});

app.get('/api/google/home/entity-debug', async (req, res) => {
    if (!GOOGLE_DEBUG_ENDPOINTS_ENABLED) {
        return res.status(404).json({ error: 'not_found' });
    }

    try {
        await ensureGoogleRuntimeSchemaReady();
    } catch (error) {
        console.warn('GOOGLE ENTITY DEBUG SCHEMA CHECK FAILED:', error?.message || error);
    }

    const email = sanitizeString(req.query?.email, 255);
    const userId = parsePositiveInt(req.query?.user_id);

    if (!email && !userId) {
        return res.status(400).json({ error: 'email or user_id is required' });
    }

    try {
        const user = email
            ? await dbGet(`SELECT id, email, google_home_enabled, google_home_linked FROM users WHERE email = ? LIMIT 1`, [email])
            : await dbGet(`SELECT id, email, google_home_enabled, google_home_linked FROM users WHERE id = ? LIMIT 1`, [userId]);

        if (!user) {
            return res.status(404).json({ error: 'user_not_found' });
        }

        await markGoogleEntitiesStaleByFreshness();

        let rows;
        try {
            rows = await dbAll(
                `
                    SELECT
                        ge.entity_id,
                        ge.display_name,
                        ge.entity_type,
                        ge.exposed,
                        ge.online AS stored_entity_online,
                        ge.entity_last_seen_at,
                        ge.updated_at,
                        ge.last_reported_at,
                        d.id AS device_id,
                        d.device_uid,
                        d.last_seen_at,
                        d.agent_state
                    FROM google_home_entities ge
                    INNER JOIN devices d ON d.id = ge.device_id
                    WHERE ge.user_id = ?
                    ORDER BY ge.updated_at DESC
                    LIMIT 120
                `,
                [user.id]
            );
        } catch (queryError) {
            if (isMissingGoogleEntityLastSeenColumnError(queryError)) {
                googleEntityLastSeenColumnSupported = false;
                rows = await dbAll(
                    `
                        SELECT
                            ge.entity_id,
                            ge.display_name,
                            ge.entity_type,
                            ge.exposed,
                            ge.online AS stored_entity_online,
                            NULL AS entity_last_seen_at,
                            ge.updated_at,
                            ge.last_reported_at,
                            d.id AS device_id,
                            d.device_uid,
                            d.last_seen_at,
                            d.agent_state
                        FROM google_home_entities ge
                        INNER JOIN devices d ON d.id = ge.device_id
                        WHERE ge.user_id = ?
                        ORDER BY ge.updated_at DESC
                        LIMIT 120
                    `,
                    [user.id]
                );
            } else {
                throw queryError;
            }
        }

        await refreshGoogleEntityFreshnessFromDeviceHeartbeat(user.id, null);

        const entities = (rows || []).map((row) => ({
            entity_id: row.entity_id,
            display_name: row.display_name,
            entity_type: row.entity_type,
            exposed: Boolean(row.exposed),
            stored_entity_online: Boolean(row.stored_entity_online),
            device_online: isDeviceOnline(row.last_seen_at),
            entity_last_seen_at: row.entity_last_seen_at,
            entity_fresh: isEntityFresh(row.entity_last_seen_at || row.updated_at),
            effective_online: isEntityEffectivelyOnline({
                online: row.stored_entity_online,
                last_seen_at: row.last_seen_at,
                entity_last_seen_at: row.entity_last_seen_at,
                updated_at: row.updated_at
            }),
            device_id: row.device_id,
            device_uid: row.device_uid,
            device_last_seen_at: row.last_seen_at,
            device_agent_state: row.agent_state,
            entity_updated_at: row.updated_at,
            last_reported_at: row.last_reported_at
        }));

        const onlineCount = entities.filter((entity) => entity.effective_online).length;
        const availableCount = entities.filter((entity) => entity.stored_entity_online).length;
        const staleCount = entities.filter((entity) => !entity.entity_fresh).length;

        return res.status(200).json({
            user: {
                id: user.id,
                email: user.email,
                google_home_enabled: Boolean(user.google_home_enabled),
                google_home_linked: Boolean(user.google_home_linked)
            },
            totals: {
                entities: entities.length,
                online: onlineCount,
                offline: Math.max(0, entities.length - onlineCount),
                entity_available: availableCount,
                entity_stale: staleCount
            },
            entities
        });
    } catch (error) {
        console.error('GOOGLE ENTITY DEBUG ERROR:', error);
        return res.status(500).json({ error: 'unable_to_load_entity_debug' });
    }
});

app.get('/api/google/home/reachability-check', (_req, res) => {
    return res.status(200).json({ ok: true, service: 'google-home-backend' });
});

app.get('/api/google/home/direct-sync-check', async (req, res) => {
    const bearer = req.get('authorization') || '';
    const token = bearer.startsWith('Bearer ') ? bearer.slice(7).trim() : sanitizeString(req.query?.access_token || '', 512);
    if (!token) {
        return res.status(401).json({ error: 'missing_access_token' });
    }

    const user = await findUserByGoogleAccessToken(token);
    if (!user) {
        return res.status(401).json({ error: 'invalid_or_expired_access_token' });
    }

    const entities = await getGoogleEntitiesForUser(user.id, { includeDisabled: false });
    const devices = entities.map((entity) => buildGoogleDeviceObject(withEffectiveGoogleOnline(entity)));

    return res.status(200).json({
        ok: true,
        requestId: `direct_${Date.now()}`,
        payload: {
            agentUserId: String(user.id),
            devices
        }
    });
});

app.get('/api/google/home/live-reachability', async (_req, res) => {
    return res.status(200).json({
        ok: true,
        release: GOOGLE_BACKEND_RELEASE,
        endpoint_stats: googleEndpointStats,
        now: new Date().toISOString()
    });
});

app.post('/api/google/home/live-reachability/reset', (_req, res) => {
    googleEndpointStats.oauth_hits = 0;
    googleEndpointStats.token_hits = 0;
    googleEndpointStats.fulfillment_hits = 0;
    googleEndpointStats.fulfillment_pre_auth_hits = 0;
    googleEndpointStats.fulfillment_auth_failures = 0;
    googleEndpointStats.oauth_status_counts = {};
    googleEndpointStats.token_status_counts = {};
    googleEndpointStats.fulfillment_status_counts = {};
    googleEndpointStats.last_oauth_at = null;
    googleEndpointStats.last_token_at = null;
    googleEndpointStats.last_fulfillment_at = null;
    googleEndpointStats.last_fulfillment_pre_auth_at = null;
    googleEndpointStats.last_fulfillment_auth_failure_at = null;
    googleEndpointStats.last_oauth_status = null;
    googleEndpointStats.last_token_status = null;
    googleEndpointStats.last_fulfillment_status = null;

    return res.status(200).json({ ok: true, message: 'google_endpoint_stats_reset' });
});

app.get('/api/google/home/diag-endpoints', (_req, res) => {
    const base = `https://${CLOUD_BASE_DOMAIN}`;
    return res.status(200).json({
        ok: true,
        release: GOOGLE_BACKEND_RELEASE,
        recommended: {
            authorize_url: `${base}/api/google/home/oauth`,
            token_url: `${base}/api/google/home/token`,
            fulfillment_url: `${base}/api/google/home/fulfillment`
        },
        compatibility_aliases: {
            authorize_url: [`${base}/google/home/oauth`, `${base}/oauth`],
            token_url: [`${base}/google/home/token`, `${base}/token`],
            fulfillment_url: [`${base}/google/home/fulfillment`, `${base}/fulfillment`]
        },
        reachability_url: `${base}/api/google/home/live-reachability`
    });
});

app.post('/api/google/home/oauth-probe', async (req, res) => {
    const clientId = sanitizeString(req.body?.client_id || req.query?.client_id, 255);
    const redirectUri = sanitizeString(req.body?.redirect_uri || req.query?.redirect_uri, 1000);
    const state = sanitizeString(req.body?.state || req.query?.state, 1000);
    const portalToken = sanitizeString(req.body?.portal_session_token || req.query?.portal_session_token || '', 4000);

    const result = {
        has_google_client_id: Boolean(GOOGLE_HOME_CLIENT_ID),
        client_id_matches: clientId === GOOGLE_HOME_CLIENT_ID,
        redirect_uri_trusted: isTrustedGoogleRedirectUri(redirectUri),
        portal_token_well_formed: hasExactlyOneDot(portalToken),
        has_cookie_token: Boolean(req.cookies?.[PORTAL_SESSION_COOKIE_NAME]),
        redirect_host: (() => {
            try {
                return redirectUri ? new URL(redirectUri).host : null;
            } catch (_error) {
                return null;
            }
        })(),
        allowed_redirect_hosts: GOOGLE_HOME_REDIRECT_URI_HOSTS
    };

    if (!clientId || !redirectUri || !portalToken) {
        return res.status(200).json({ ok: false, error: 'missing_input', ...result });
    }

    const session = verifyPortalSessionToken(portalToken);
    if (!session) {
        return res.status(200).json({ ok: false, error: 'invalid_portal_session', ...result });
    }

    const user = await dbGet(`SELECT id, email, status, google_home_enabled, google_home_linked FROM users WHERE email = ? LIMIT 1`, [session.email]);
    if (!user) {
        return res.status(200).json({ ok: false, error: 'user_not_found', ...result });
    }

    return res.status(200).json({
        ok: true,
        ...result,
        state: state || null,
        user: {
            id: user.id,
            email: user.email,
            status: user.status,
            google_home_enabled: Boolean(user.google_home_enabled),
            google_home_linked: Boolean(user.google_home_linked)
        }
    });
});

app.post('/api/billing/create-checkout', async (req, res) => {
    const { access_token, portal_session_token } = req.body;
    const cookieToken = req.cookies?.[PORTAL_SESSION_COOKIE_NAME] || '';
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
            const session = verifyPortalSessionToken(sessionToken);
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

try {
    getPortalSecret();
    getAdminSecret();
} catch (error) {
    console.error('CRITICAL CONFIG ERROR:', error.message);
    process.exit(1);
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Cloud Portal API is running on http://localhost:${PORT}`);
    ensureGoogleRuntimeSchemaReady()
        .then(() => {
            console.log('Google runtime schema ready.');
        })
        .catch((error) => {
            console.error('Google runtime schema migration failed:', error);
        });
});
