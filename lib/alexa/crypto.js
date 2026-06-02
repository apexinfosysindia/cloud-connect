const crypto = require('crypto');

/**
 * AES-256-GCM encryption for Login with Amazon tokens at rest.
 *
 * LWA tokens (the credentials Amazon grants us at AcceptGrant) must be replayed
 * outbound when we post ChangeReport / AddOrUpdateReport to the Event Gateway as
 * the end user, so they cannot be one-way hashed like the portal-issued bearer
 * tokens. They are stored encrypted instead.
 *
 * Wire format (single TEXT column): "v1:<iv_b64>:<tag_b64>:<ciphertext_b64>".
 * The version prefix lets us rotate the scheme later without ambiguity.
 *
 * Key: config.ALEXA_LWA_TOKEN_ENC_KEY — a 32-byte key supplied as hex (64 chars)
 * or base64. resolveKey() throws if it is missing or the wrong size, so a
 * misconfigured deployment fails loudly at first encrypt rather than silently
 * persisting plaintext.
 */
module.exports = function createAlexaCrypto({ config }) {
    const SCHEME = 'v1';

    function resolveKey() {
        const raw = (config.ALEXA_LWA_TOKEN_ENC_KEY || '').trim();
        if (!raw) {
            throw new Error('ALEXA_LWA_TOKEN_ENC_KEY is not configured');
        }

        let key;
        if (/^[0-9a-fA-F]{64}$/.test(raw)) {
            key = Buffer.from(raw, 'hex');
        } else {
            key = Buffer.from(raw, 'base64');
        }

        if (key.length !== 32) {
            throw new Error('ALEXA_LWA_TOKEN_ENC_KEY must decode to 32 bytes (got ' + key.length + ')');
        }

        return key;
    }

    function encryptToken(plaintext) {
        if (plaintext === null || plaintext === undefined || plaintext === '') {
            return null;
        }

        const key = resolveKey();
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();

        return [SCHEME, iv.toString('base64'), tag.toString('base64'), ciphertext.toString('base64')].join(':');
    }

    function decryptToken(stored) {
        if (stored === null || stored === undefined || stored === '') {
            return null;
        }

        const parts = String(stored).split(':');
        if (parts.length !== 4 || parts[0] !== SCHEME) {
            throw new Error('Malformed encrypted token payload');
        }

        const key = resolveKey();
        const iv = Buffer.from(parts[1], 'base64');
        const tag = Buffer.from(parts[2], 'base64');
        const ciphertext = Buffer.from(parts[3], 'base64');

        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return plaintext.toString('utf8');
    }

    function hasEncryptionKey() {
        try {
            resolveKey();
            return true;
        } catch (_error) {
            return false;
        }
    }

    return { encryptToken, decryptToken, hasEncryptionKey };
};
