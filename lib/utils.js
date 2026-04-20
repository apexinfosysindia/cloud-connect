const crypto = require('crypto');
const config = require('./config');

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
    return (
        message.includes('no such column: last_reported_state_hash') ||
        message.includes('no such column: last_reported_at')
    );
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

function generateToken() {
    return 'apx_' + crypto.randomBytes(16).toString('hex');
}

function hashSecret(value) {
    return crypto
        .createHash('sha256')
        .update(String(value || ''))
        .digest('hex');
}

// ── Symmetric encryption for at-rest secrets ─────────────────────────────
// Used for Amazon LWA refresh tokens stored in alexa_tokens. Derives a
// 32-byte key from PORTAL_SESSION_SECRET (which is already required to be
// >= 32 chars at boot). AES-256-GCM, prefix "enc_v1:<iv>:<tag>:<ciphertext>".
function getSymmetricEncryptionKey() {
    const secret = process.env.PORTAL_SESSION_SECRET || '';
    if (!secret || secret.length < 32) {
        throw new Error('PORTAL_SESSION_SECRET must be configured before encrypting secrets');
    }
    return crypto.createHash('sha256').update(`apx_at_rest_v1:${secret}`).digest();
}

function encryptAtRest(plaintext) {
    if (plaintext === null || plaintext === undefined || plaintext === '') return null;
    const key = getSymmetricEncryptionKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `enc_v1:${iv.toString('base64')}:${tag.toString('base64')}:${ct.toString('base64')}`;
}

function decryptAtRest(ciphertext) {
    if (!ciphertext || typeof ciphertext !== 'string') return null;
    if (!ciphertext.startsWith('enc_v1:')) {
        // Legacy plaintext fallback — return as-is so existing rows still work.
        return ciphertext;
    }
    try {
        const [, ivB64, tagB64, ctB64] = ciphertext.split(':');
        if (!ivB64 || !tagB64 || !ctB64) return null;
        const key = getSymmetricEncryptionKey();
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            key,
            Buffer.from(ivB64, 'base64')
        );
        decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
        const pt = Buffer.concat([
            decipher.update(Buffer.from(ctB64, 'base64')),
            decipher.final()
        ]);
        return pt.toString('utf8');
    } catch (_err) {
        return null;
    }
}

function generateDeviceAuthToken() {
    return config.DEVICE_TOKEN_PREFIX + crypto.randomBytes(24).toString('hex');
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

    return normalized
        .replace(/[\r\n\t]+/g, ' ')
        .replace(/\s{2,}/g, ' ')
        .trim();
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
    } catch (_error) {
        return false;
    }

    if (parsed.protocol !== 'https:') {
        return false;
    }

    const host = (parsed.hostname || '').toLowerCase();
    return config.GOOGLE_HOME_REDIRECT_URI_HOSTS.includes(host);
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
    } catch (_error) {
        return fallback;
    }
}

function getHeartbeatWindowSeconds() {
    if (!Number.isFinite(config.DEVICE_HEARTBEAT_TIMEOUT_SECONDS)) {
        return 45;
    }

    return Math.max(20, Math.min(300, Math.round(config.DEVICE_HEARTBEAT_TIMEOUT_SECONDS)));
}

function isDeviceOnline(lastSeenAt) {
    if (!lastSeenAt) {
        return false;
    }

    const lastSeenEpoch = new Date(lastSeenAt).getTime();
    if (!Number.isFinite(lastSeenEpoch)) {
        return false;
    }

    return Date.now() - lastSeenEpoch <= getHeartbeatWindowSeconds() * 1000;
}

function getEntityFreshWindowSeconds() {
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

    return Date.now() - lastSeenEpoch <= getEntityFreshWindowSeconds() * 1000;
}

// Stateless entity types (scenes, scripts, buttons) are software-defined and should
// always be considered online when the HA device is connected and the entity is fresh.
// Their HA state ("unavailable") is not meaningful for online/offline determination.
// This matches how HA core (NabuCasa) handles these entity types.
const STATELESS_ENTITY_TYPES = new Set(['scene', 'script', 'button', 'input_button']);

function isEntityEffectivelyOnline(entityRow) {
    if (!entityRow) {
        return false;
    }

    const deviceOnline = isDeviceOnline(entityRow.last_seen_at);
    if (!deviceOnline) {
        return false;
    }

    const entityFresh = isEntityFresh(entityRow.entity_last_seen_at || entityRow.updated_at);
    if (!entityFresh) {
        return false;
    }

    // Stateless entities (scenes, scripts, buttons) are always online when device is
    // connected and entity is fresh — skip the stored online flag check
    if (entityRow.entity_type && STATELESS_ENTITY_TYPES.has(entityRow.entity_type)) {
        return true;
    }

    return Number(entityRow.online) !== 0;
}

function getHeartbeatIntervalSeconds() {
    if (!Number.isFinite(config.DEVICE_HEARTBEAT_INTERVAL_SECONDS)) {
        return 20;
    }

    return Math.max(10, Math.min(120, Math.round(config.DEVICE_HEARTBEAT_INTERVAL_SECONDS)));
}

function getDeviceTunnelPortRange() {
    let min = Number.isFinite(config.DEVICE_TUNNEL_PORT_MIN) ? Math.round(config.DEVICE_TUNNEL_PORT_MIN) : 22000;
    let max = Number.isFinite(config.DEVICE_TUNNEL_PORT_MAX) ? Math.round(config.DEVICE_TUNNEL_PORT_MAX) : 22999;

    min = Math.max(1025, Math.min(65000, min));
    max = Math.max(1025, Math.min(65535, max));

    if (max < min) {
        max = min;
    }

    if (max - min < 32) {
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
    const jumpHost =
        sanitizeSshHost(config.ADMIN_SSH_JUMP_HOST) ||
        sanitizeSshHost(config.DEVICE_TUNNEL_HOST) ||
        config.CLOUD_BASE_DOMAIN;
    const jumpUser = sanitizeSshUser(config.ADMIN_SSH_JUMP_USER) || 'root';
    const jumpPort = sanitizePort(config.ADMIN_SSH_JUMP_PORT) || 22;
    const targetHost = sanitizeSshHost(config.ADMIN_SSH_TARGET_HOST) || '127.0.0.1';

    return {
        method: 'proxyjump',
        jump_host: jumpHost,
        jump_user: jumpUser,
        jump_port: jumpPort,
        target_host: targetHost,
        target_user: 'root'
    };
}

function isIgnorableSqliteMigrationError(error) {
    const message = String(error?.message || '').toLowerCase();
    return message.includes('duplicate column name') || message.includes('already exists');
}

function parsePositiveInt(value) {
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed <= 0) {
        return null;
    }

    return parsed;
}

function isAccessEnabled(status) {
    return status === 'active' || status === 'trial';
}

function asyncHandler(fn) {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}

module.exports = {
    sqliteMessage,
    isMissingGoogleEntityLastSeenColumnError,
    isMissingGoogleSyncSnapshotsTableError,
    isGoogleSyncSnapshotsUpsertUnsupportedError,
    isMissingGoogleStateHashColumnError,
    isMissingGoogleLastReportedColumnsError,
    hasExactlyOneDot,
    generateToken,
    hashSecret,
    encryptAtRest,
    decryptAtRest,
    generateDeviceAuthToken,
    sanitizeString,
    sanitizeDeviceUid,
    sanitizeDeviceName,
    sanitizeSshHost,
    sanitizeSshUser,
    sanitizeEventType,
    sanitizeEntityId,
    sanitizeActionName,
    sanitizeGoogleRequestId,
    isTrustedGoogleRedirectUri,
    sanitizePort,
    normalizeLocalIps,
    parseJsonSafe,
    getHeartbeatWindowSeconds,
    isDeviceOnline,
    getEntityFreshWindowSeconds,
    isEntityFresh,
    STATELESS_ENTITY_TYPES,
    isEntityEffectivelyOnline,
    getHeartbeatIntervalSeconds,
    getDeviceTunnelPortRange,
    isDeviceTunnelPortInRange,
    getAdminSshRoute,
    isIgnorableSqliteMigrationError,
    parsePositiveInt,
    isAccessEnabled,
    asyncHandler
};
