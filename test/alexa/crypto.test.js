const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const lwaCrypto = require('../../lib/alexa/crypto');

const ENV = lwaCrypto._internal.ENV_VAR;
const VALID_KEY_HEX = crypto.randomBytes(32).toString('hex');

function withKey(hex, fn) {
    const previous = process.env[ENV];
    if (hex === null) {
        delete process.env[ENV];
    } else {
        process.env[ENV] = hex;
    }
    try {
        return fn();
    } finally {
        if (previous === undefined) delete process.env[ENV];
        else process.env[ENV] = previous;
    }
}

test('encrypt → decrypt roundtrip preserves the plaintext', () => {
    withKey(VALID_KEY_HEX, () => {
        const plaintext = 'Atza|IwEBIExampleLwaAccessToken1234567890';
        const ct = lwaCrypto.encryptLwaToken(plaintext);
        assert.ok(typeof ct === 'string' && ct.length > 0);
        // Verify it really is base64 and not the original passthrough.
        assert.notEqual(ct, plaintext);
        const out = lwaCrypto.decryptLwaToken(ct);
        assert.equal(out, plaintext);
    });
});

test('two encryptions of the same plaintext produce different ciphertexts (random IV)', () => {
    withKey(VALID_KEY_HEX, () => {
        const a = lwaCrypto.encryptLwaToken('same');
        const b = lwaCrypto.encryptLwaToken('same');
        assert.notEqual(a, b, 'IV must be random per call so ciphertexts diverge');
    });
});

test('encryptLwaToken(null) returns null without touching crypto', () => {
    // Specifically test that NO key is required for the null passthrough —
    // callers should be able to store a NULL LWA token at user-create time
    // without first provisioning the encryption key.
    withKey(null, () => {
        assert.equal(lwaCrypto.encryptLwaToken(null), null);
        assert.equal(lwaCrypto.encryptLwaToken(undefined), null);
    });
});

test('decryptLwaToken("") and (null) return null without touching crypto', () => {
    withKey(null, () => {
        assert.equal(lwaCrypto.decryptLwaToken(null), null);
        assert.equal(lwaCrypto.decryptLwaToken(''), null);
        assert.equal(lwaCrypto.decryptLwaToken(undefined), null);
    });
});

test('encryptLwaToken throws when key is missing', () => {
    withKey(null, () => {
        assert.throws(() => lwaCrypto.encryptLwaToken('x'), /missing or not a 32-byte hex/);
    });
});

test('encryptLwaToken throws when key is wrong length (16 bytes / hex 32 chars)', () => {
    withKey(crypto.randomBytes(16).toString('hex'), () => {
        assert.throws(() => lwaCrypto.encryptLwaToken('x'), /not a 32-byte hex/);
    });
});

test('encryptLwaToken throws when key is non-hex garbage', () => {
    withKey('not-actually-hex-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz', () => {
        // Buffer.from with 'hex' silently drops non-hex chars rather than
        // throwing, so this comes back as the wrong length and we reject it.
        assert.throws(() => lwaCrypto.encryptLwaToken('x'), /not a 32-byte hex/);
    });
});

test('decryptLwaToken returns null on tampered ciphertext (auth tag detection)', () => {
    withKey(VALID_KEY_HEX, () => {
        const ct = lwaCrypto.encryptLwaToken('original');
        const buf = Buffer.from(ct, 'base64');
        // Flip a bit somewhere in the ciphertext middle (not in IV or auth tag).
        buf[16] = buf[16] ^ 0x01;
        const tampered = buf.toString('base64');
        assert.equal(lwaCrypto.decryptLwaToken(tampered), null);
    });
});

test('decryptLwaToken returns null when ciphertext is too short to even contain IV+tag', () => {
    withKey(VALID_KEY_HEX, () => {
        const tooShort = Buffer.from('abc').toString('base64');
        assert.equal(lwaCrypto.decryptLwaToken(tooShort), null);
    });
});

test('decryptLwaToken returns null when key has changed since encryption (rotation case)', () => {
    let ct;
    withKey(VALID_KEY_HEX, () => {
        ct = lwaCrypto.encryptLwaToken('rotated-out');
    });
    // Encrypt under one key, decrypt under another → must not throw, must
    // surface as null so the event-gateway sees "no LWA token, skip user".
    withKey(crypto.randomBytes(32).toString('hex'), () => {
        assert.equal(lwaCrypto.decryptLwaToken(ct), null);
    });
});

test('hasEncryptionKey reflects env-var presence and validity', () => {
    withKey(null, () => assert.equal(lwaCrypto.hasEncryptionKey(), false));
    withKey('short', () => assert.equal(lwaCrypto.hasEncryptionKey(), false));
    withKey(VALID_KEY_HEX, () => assert.equal(lwaCrypto.hasEncryptionKey(), true));
});

test('handles unicode plaintext (LWA tokens are ASCII but defense in depth)', () => {
    withKey(VALID_KEY_HEX, () => {
        const plaintext = 'токен-世界-🔑';
        assert.equal(lwaCrypto.decryptLwaToken(lwaCrypto.encryptLwaToken(plaintext)), plaintext);
    });
});

test('large plaintext (multi-KB) roundtrips', () => {
    withKey(VALID_KEY_HEX, () => {
        const plaintext = 'x'.repeat(8192);
        assert.equal(lwaCrypto.decryptLwaToken(lwaCrypto.encryptLwaToken(plaintext)), plaintext);
    });
});
