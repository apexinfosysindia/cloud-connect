const crypto = require('node:crypto');

// AES-256-GCM encryption helpers for LWA bearer tokens that must be replayed
// outbound to api.amazonalexa.com. Unlike Cloud-Connect-issued tokens (which
// are SHA-256 hashed for storage), LWA tokens cannot be hashed — we need the
// plaintext at send time. Key lives in ALEXA_LWA_TOKEN_ENC_KEY (hex-encoded
// 32 bytes → 256-bit key). Storage layout: base64(iv || ciphertext || tag).

const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const ALGORITHM = 'aes-256-gcm';

function getKey() {
    const raw = process.env.ALEXA_LWA_TOKEN_ENC_KEY || '';
    if (!raw) {
        return null;
    }

    try {
        const key = Buffer.from(raw, 'hex');
        if (key.length !== 32) {
            return null;
        }
        return key;
    } catch (_) {
        return null;
    }
}

function hasEncryptionKey() {
    return getKey() !== null;
}

function encryptLwaToken(plaintext) {
    if (plaintext === null || plaintext === undefined) {
        return null;
    }

    const key = getKey();
    if (!key) {
        throw new Error('ALEXA_LWA_TOKEN_ENC_KEY is missing or not a 32-byte hex value');
    }

    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, encrypted, authTag]).toString('base64');
}

function decryptLwaToken(ciphertextB64) {
    if (!ciphertextB64) {
        return null;
    }

    const key = getKey();
    if (!key) {
        throw new Error('ALEXA_LWA_TOKEN_ENC_KEY is missing or not a 32-byte hex value');
    }

    let buf;
    try {
        buf = Buffer.from(String(ciphertextB64), 'base64');
    } catch (_) {
        return null;
    }

    if (buf.length < IV_LENGTH + AUTH_TAG_LENGTH + 1) {
        return null;
    }

    const iv = buf.subarray(0, IV_LENGTH);
    const authTag = buf.subarray(buf.length - AUTH_TAG_LENGTH);
    const encrypted = buf.subarray(IV_LENGTH, buf.length - AUTH_TAG_LENGTH);

    try {
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(authTag);
        const plaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]);
        return plaintext.toString('utf8');
    } catch (_) {
        return null;
    }
}

module.exports = {
    hasEncryptionKey,
    encryptLwaToken,
    decryptLwaToken
};
