const path = require('path');
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
const GOOGLE_HOME_AUTH_CODE_TTL_SECONDS = Number(process.env.GOOGLE_HOME_AUTH_CODE_TTL_SECONDS || 600);
const GOOGLE_HOME_ACCESS_TOKEN_TTL_SECONDS = Number(process.env.GOOGLE_HOME_ACCESS_TOKEN_TTL_SECONDS || 3600);
const GOOGLE_HOME_COMMAND_TTL_SECONDS = Number(process.env.GOOGLE_HOME_COMMAND_TTL_SECONDS || 45);
const PORTAL_SESSION_COOKIE_NAME = 'apx_portal_session';
const PORTAL_SESSION_COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const PORTAL_SESSION_COOKIE_SECURE = process.env.PORTAL_COOKIE_SECURE === '0' ? false : true;
const DEVICE_HEARTBEAT_TIMEOUT_SECONDS = Number(process.env.DEVICE_HEARTBEAT_TIMEOUT_SECONDS || 45);
const DEVICE_HEARTBEAT_INTERVAL_SECONDS = Number(process.env.DEVICE_HEARTBEAT_INTERVAL_SECONDS || 20);
const ADMIN_CONNECT_TOKEN_TTL_MINUTES = Number(process.env.ADMIN_CONNECT_TOKEN_TTL_MINUTES || 10);
const DEVICE_TUNNEL_PORT_MIN = Number(process.env.DEVICE_TUNNEL_PORT_MIN || 22000);
const DEVICE_TUNNEL_PORT_MAX = Number(process.env.DEVICE_TUNNEL_PORT_MAX || 22999);
const DEVICE_TOKEN_PREFIX = 'dvc_';
const ADMIN_CONNECT_TOKEN_PREFIX = 'acn_';

const app = express();
app.use(cookieParser());
app.use(express.json({
    verify: (req, res, buf) => {
        if (buf && buf.length > 0) {
            req.rawBody = buf.toString();
        }
    }
}));
app.use(express.urlencoded({ extended: false }));
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

function mapGoogleEntityTypeToTraits(entityType) {
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

function buildGoogleDeviceObject(entity) {
    const mapped = mapGoogleEntityTypeToTraits(entity.entity_type);
    const roomHint = sanitizeString(entity.room_hint, 120);

    return {
        id: entity.entity_id,
        type: mapped.type,
        traits: mapped.traits,
        name: {
            name: entity.display_name || entity.entity_id
        },
        roomHint: roomHint || undefined,
        willReportState: false,
        customData: {
            entity_id: entity.entity_id,
            device_id: entity.device_id
        },
        deviceInfo: {
            manufacturer: 'Apex Infosys',
            model: entity.entity_type || 'generic',
            hwVersion: entity.addon_version || 'apex-cloud-link'
        },
        attributes: entity.entity_type === 'light'
            ? { commandOnlyBrightness: false }
            : entity.entity_type === 'sensor_temperature'
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
                : {}
    };
}

function parseGoogleEntityState(entity) {
    const statePayload = parseJsonSafe(entity.state_json, {}) || {};

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

    return rows || [];
}

async function upsertGoogleEntityFromDevice(userId, deviceId, payload) {
    const entityId = sanitizeEntityId(payload?.entity_id);
    if (!entityId) {
        return null;
    }

    const displayName = sanitizeString(payload?.display_name, 120) || entityId;
    const entityType = normalizeGoogleEntityType(payload?.entity_type);
    const roomHint = sanitizeString(payload?.room_hint, 120);
    const online = payload?.online === false ? 0 : 1;
    const stateJson = JSON.stringify(payload?.state || {}).slice(0, 2500);
    const nowIso = new Date().toISOString();

    const existing = await dbGet(
        `
            SELECT id, exposed
            FROM google_home_entities
            WHERE user_id = ? AND entity_id = ?
            LIMIT 1
        `,
        [userId, entityId]
    );

    if (existing) {
        await dbRun(
            `
                UPDATE google_home_entities
                SET device_id = ?,
                    display_name = ?,
                    entity_type = ?,
                    room_hint = ?,
                    online = ?,
                    state_json = ?,
                    updated_at = ?
                WHERE id = ?
            `,
            [deviceId, displayName, entityType, roomHint, online, stateJson, nowIso, existing.id]
        );
    } else {
        await dbRun(
            `
                INSERT INTO google_home_entities (
                    user_id,
                    device_id,
                    entity_id,
                    display_name,
                    entity_type,
                    room_hint,
                    exposed,
                    online,
                    state_json,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
            `,
            [userId, deviceId, entityId, displayName, entityType, roomHint, online, stateJson, nowIso, nowIso]
        );
    }

    return dbGet(
        `
            SELECT *
            FROM google_home_entities
            WHERE user_id = ? AND entity_id = ?
            LIMIT 1
        `,
        [userId, entityId]
    );
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
            SET google_home_linked = 0
            WHERE id = ?
        `,
        [userId]
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
    return process.env.PORTAL_SESSION_SECRET || 'apex-portal-secret';
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

function setPortalSessionCookie(res, token) {
    if (!token) {
        return;
    }

    res.cookie(PORTAL_SESSION_COOKIE_NAME, token, {
        httpOnly: true,
        secure: PORTAL_SESSION_COOKIE_SECURE,
        sameSite: 'lax',
        path: '/',
        maxAge: PORTAL_SESSION_COOKIE_MAX_AGE_MS
    });
}

function clearPortalSessionCookie(res) {
    res.clearCookie(PORTAL_SESSION_COOKIE_NAME, {
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
        portal_session_token: createPortalSessionToken(user.email),
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
            return res.status(401).json({ error: 'Missing bearer token' });
        }

        const token = authHeader.slice(7).trim();
        const user = await findUserByGoogleAccessToken(token);
        if (!user) {
            return res.status(401).json({ error: 'Invalid or expired access token' });
        }

        if (!user.google_home_enabled) {
            return res.status(403).json({ error: 'Google Home integration is disabled for this account' });
        }

        if (!isAccessEnabled(user.status)) {
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

        return res.status(200).json({
            data: serializeUser(user)
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
        return res.status(200).json({
            message: enable ? 'Google Home integration enabled' : 'Google Home integration disabled',
            data: serializeUser(updatedUser)
        });
    } catch (error) {
        console.error('ACCOUNT GOOGLE HOME ENABLE ERROR:', error);
        return res.status(500).json({ error: 'Unable to update Google Home setting' });
    }
});

app.post('/api/account/google-home/entities', requirePortalUser, async (req, res) => {
    try {
        if (!req.portalUser.google_home_enabled) {
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

    if (!req.portalUser.google_home_enabled) {
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

        return res.status(200).json({
            message: exposed ? 'Entity exposed to Google Home' : 'Entity hidden from Google Home'
        });
    } catch (error) {
        console.error('ACCOUNT GOOGLE HOME ENTITY TOGGLE ERROR:', error);
        return res.status(500).json({ error: 'Unable to update entity exposure' });
    }
});

app.get('/api/google/home/oauth', async (req, res) => {
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

    if (!portalToken) {
        const loginRedirect = `/login.html?google_oauth=1&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
        return res.redirect(loginRedirect);
    }

    const session = verifyPortalSessionToken(portalToken);
    if (!session) {
        const loginRedirect = `/login.html?google_oauth=1&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
        return res.redirect(loginRedirect);
    }

    const callbackUrl = new URL(redirectUri);

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
            return res.status(404).send('Account not found');
        }

        if (!isAccessEnabled(user.status)) {
            return res.status(403).send('Account is not active for Google Home');
        }

        if (!user.google_home_enabled) {
            return res.status(403).send('Google Home integration is disabled for this account');
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

        callbackUrl.searchParams.set('code', authCode);
        callbackUrl.searchParams.set('state', state);
        return res.redirect(callbackUrl.toString());
    } catch (error) {
        console.error('GOOGLE OAUTH AUTHORIZE ERROR:', error);
        return res.status(500).send('Unable to authorize Google integration');
    }
});

app.post('/api/google/home/oauth/continue', async (req, res) => {
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
        return res.status(403).json({ error: 'google_home_not_enabled' });
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

    const payload = {
        ok: true,
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
        cookie_name: PORTAL_SESSION_COOKIE_NAME
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

app.post('/api/google/home/token', async (req, res) => {
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

app.post('/api/google/home/fulfillment', requireGoogleBearer, async (req, res) => {
    const requestId = sanitizeGoogleRequestId(req.body?.requestId) || `req_${Date.now()}`;
    const inputs = Array.isArray(req.body?.inputs) ? req.body.inputs : [];
    const input = inputs[0] || {};
    const intent = sanitizeString(input.intent, 120) || '';

    try {
        if (intent === 'action.devices.SYNC') {
            const entities = await getGoogleEntitiesForUser(req.googleUser.id, { includeDisabled: false });
            const devices = entities.map((entity) => buildGoogleDeviceObject(entity));

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

                devicesState[entityId] = parseGoogleEntityState(entity);
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

                    for (const execution of executions) {
                        const commandName = sanitizeActionName(execution?.command);
                        const params = execution?.params || {};

                        let action = null;
                        let payload = {};
                        if (commandName === 'action.devices.commands.OnOff') {
                            action = 'set_on';
                            payload = { on: Boolean(params?.on) };
                        } else if (commandName === 'action.devices.commands.BrightnessAbsolute') {
                            action = 'set_brightness';
                            payload = { brightness: Math.max(0, Math.min(100, Number(params?.brightness || 0))) };
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
                                ...(payload.brightness !== undefined ? { brightness: payload.brightness } : {})
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
            return res.status(200).json({ requestId, payload: {} });
        }

        return res.status(400).json({ error: 'Unsupported intent' });
    } catch (error) {
        console.error('GOOGLE FULFILLMENT ERROR:', error);
        return res.status(500).json({ error: 'Unable to process Google fulfillment request' });
    }
});

app.post('/api/internal/devices/google-home/entities', requireDeviceAuth, async (req, res) => {
    try {
        const device = req.device;
        const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [device.user_id]);
        const nowIso = new Date().toISOString();
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

            return res.status(200).json({
                message: 'Google Home integration is disabled for this account',
                synced_count: 0,
                synced_entities: []
            });
        }

        const entitiesPayload = Array.isArray(req.body?.entities) ? req.body.entities : [];
        const synced = [];
        const incomingEntityIds = [];

        for (const entityPayload of entitiesPayload) {
            const normalizedEntityId = sanitizeEntityId(entityPayload?.entity_id);
            if (normalizedEntityId) {
                incomingEntityIds.push(normalizedEntityId);
            }

            const upserted = await upsertGoogleEntityFromDevice(device.user_id, device.id, entityPayload);
            if (upserted) {
                synced.push(upserted.entity_id);
            }
        }

        if (incomingEntityIds.length > 0) {
            const placeholders = incomingEntityIds.map(() => '?').join(',');
            await dbRun(
                `
                    UPDATE google_home_entities
                    SET online = 0,
                        updated_at = ?
                    WHERE user_id = ?
                      AND device_id = ?
                      AND entity_id NOT IN (${placeholders})
                `,
                [nowIso, device.user_id, device.id, ...incomingEntityIds]
            );
        } else {
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
        }

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
            await dbRun(
                `
                    UPDATE google_home_entities
                    SET state_json = ?,
                        online = 1,
                        updated_at = ?
                    WHERE user_id = ?
                      AND device_id = ?
                      AND entity_id = ?
                `,
                [
                    JSON.stringify(req.body.state).slice(0, 2500),
                    nowIso,
                    command.user_id,
                    device.id,
                    command.entity_id
                ]
            );
        }

        return res.status(200).json({ message: 'Command result recorded' });
    } catch (error) {
        console.error('DEVICE GOOGLE COMMAND RESULT ERROR:', error);
        return res.status(500).json({ error: 'Unable to store command result' });
    }
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Cloud Portal API is running on http://localhost:${PORT}`);
});
