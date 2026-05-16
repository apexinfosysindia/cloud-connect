/**
 * AES-256-GCM at-rest encryption for Login-with-Amazon (LWA) bearer tokens.
 *
 * ─── Why this exists ────────────────────────────────────────────────────────
 *
 * Cloud Connect deals with two different Alexa-side token classes and stores
 * them DIFFERENTLY on purpose:
 *
 *   1. Portal-issued bearer tokens (access_token / refresh_token).
 *      Alexa's Lambda forwarder presents these to us on every directive.
 *      We only ever need to VERIFY them, so we store SHA-256 hashes
 *      (utils.hashSecret). One-way — we never see the original token again
 *      after issue, which is exactly what we want for verification credentials.
 *
 *   2. LWA tokens (lwa_access_token / lwa_refresh_token).
 *      We must REPLAY these to api.amazonalexa.com when pushing proactive
 *      ChangeReport / AddOrUpdateReport events. Plaintext is required at
 *      send time. So we encrypt with AES-256-GCM rather than hash:
 *        - confidentiality at rest (a DB dump alone is not useful)
 *        - tamper detection via the GCM auth tag
 *        - key rotation is feasible (re-encrypt on next AcceptGrant)
 *
 * ─── Storage layout ─────────────────────────────────────────────────────────
 *
 *   base64( IV (12 bytes) || ciphertext (variable) || authTag (16 bytes) )
 *
 *   - IV is randomly generated per encryption (never reused with the same key)
 *   - 96-bit IV is the GCM standard / NIST recommendation
 *   - 128-bit auth tag is the default and what we want
 *   - The whole envelope is one base64 blob so a SQL TEXT column suffices
 *
 * ─── Key management ─────────────────────────────────────────────────────────
 *
 *   ALEXA_LWA_TOKEN_ENC_KEY env var, hex-encoded 32 bytes (= 256 bits).
 *   Generate with: `openssl rand -hex 32`
 *
 *   Rotation playbook: set the new key, restart server, on next AcceptGrant
 *   each user's LWA tokens are rewritten with the new key. Old ciphertexts
 *   under the previous key become un-decryptable, which is fine because
 *   AcceptGrant always provides a fresh refresh token. (We do NOT support
 *   simultaneous old+new keys; if you need that, add a key-id prefix and
 *   maintain a small key ring here.)
 *
 * ─── Behavior contract ─────────────────────────────────────────────────────
 *
 *   encryptLwaToken(plaintext):
 *     - null/undefined input → returns null (passthrough; lets callers store
 *       a NULL when the LWA token is genuinely absent without conditional logic)
 *     - missing/invalid key  → throws (fail-loud at boot is better than silently
 *       writing plaintext or losing the token)
 *
 *   decryptLwaToken(ciphertextB64):
 *     - null/empty input  → returns null
 *     - malformed base64 / wrong length / bad auth tag → returns null
 *       (we deliberately do NOT throw on decrypt failure — a corrupted row
 *       should manifest as "no LWA token, re-link" not a crash that takes
 *       down the whole event-gateway loop for every other user)
 *     - missing key → throws (intentional: silent decrypt-failure-as-noise
 *       would hide a config mistake)
 *
 *   hasEncryptionKey():
 *     - cheap predicate so callers can probe at boot or in admin endpoints
 *       without triggering an exception path.
 */

const crypto = require('node:crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits — GCM standard
const AUTH_TAG_LENGTH = 16; // 128 bits — GCM default
const KEY_LENGTH = 32; // 256 bits

const ENV_VAR = 'ALEXA_LWA_TOKEN_ENC_KEY';

function getKey() {
    const raw = process.env[ENV_VAR] || '';
    if (!raw) {
        return null;
    }

    let key;
    try {
        key = Buffer.from(raw, 'hex');
    } catch (_error) {
        return null;
    }

    if (key.length !== KEY_LENGTH) {
        return null;
    }

    return key;
}

function hasEncryptionKey() {
    return getKey() !== null;
}

function requireKey() {
    const key = getKey();
    if (!key) {
        throw new Error(
            `${ENV_VAR} is missing or not a 32-byte hex value. ` +
                `Generate with: openssl rand -hex 32`
        );
    }
    return key;
}

function encryptLwaToken(plaintext) {
    if (plaintext === null || plaintext === undefined) {
        return null;
    }

    const key = requireKey();
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const ciphertext = Buffer.concat([
        cipher.update(String(plaintext), 'utf8'),
        cipher.final()
    ]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, ciphertext, authTag]).toString('base64');
}

function decryptLwaToken(ciphertextB64) {
    if (ciphertextB64 === null || ciphertextB64 === undefined || ciphertextB64 === '') {
        return null;
    }

    const key = requireKey();

    let buf;
    try {
        buf = Buffer.from(String(ciphertextB64), 'base64');
    } catch (_error) {
        return null;
    }

    // Need at least IV + tag + 1 byte of ciphertext to be plausibly valid.
    if (buf.length < IV_LENGTH + AUTH_TAG_LENGTH + 1) {
        return null;
    }

    const iv = buf.subarray(0, IV_LENGTH);
    const authTag = buf.subarray(buf.length - AUTH_TAG_LENGTH);
    const ciphertext = buf.subarray(IV_LENGTH, buf.length - AUTH_TAG_LENGTH);

    try {
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(authTag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return plaintext.toString('utf8');
    } catch (_error) {
        // Tamper / wrong key / truncation → null, by contract.
        return null;
    }
}

module.exports = {
    encryptLwaToken,
    decryptLwaToken,
    hasEncryptionKey,
    // Exposed for tests; not part of the runtime contract.
    _internal: {
        ENV_VAR,
        ALGORITHM,
        IV_LENGTH,
        AUTH_TAG_LENGTH,
        KEY_LENGTH
    }
};
