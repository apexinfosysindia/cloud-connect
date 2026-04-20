const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

process.env.PORTAL_SESSION_SECRET =
    process.env.PORTAL_SESSION_SECRET || 'x'.repeat(48);

const core = require('../../lib/alexa/core')({
    dbGet: async () => null,
    dbRun: async () => ({})
});

describe('alexa/core TTL clamps', () => {
    it('auth-code TTL within [120,1800]', () => {
        const ttl = core.getAlexaAuthCodeTtlSeconds();
        assert.ok(typeof ttl === 'number');
        assert.ok(ttl >= 120 && ttl <= 1800);
    });

    it('access-token TTL within [300,7200]', () => {
        const ttl = core.getAlexaAccessTokenTtlSeconds();
        assert.ok(typeof ttl === 'number');
        assert.ok(ttl >= 300 && ttl <= 7200);
    });
});

describe('alexa/core token generation', () => {
    it('auth code has aac_ prefix', () => {
        const c = core.generateAlexaOAuthCode();
        assert.ok(c.startsWith('aac_'));
        assert.ok(c.length > 20);
    });
    it('access token has aat_ prefix', () => {
        const t = core.generateAlexaAccessToken();
        assert.ok(t.startsWith('aat_'));
    });
    it('refresh token has art_ prefix', () => {
        const r = core.generateAlexaRefreshToken();
        assert.ok(r.startsWith('art_'));
    });
    it('generated tokens are unique', () => {
        const seen = new Set();
        for (let i = 0; i < 100; i += 1) {
            seen.add(core.generateAlexaAccessToken());
        }
        assert.equal(seen.size, 100);
    });
});

describe('alexa/core trusted redirect uri', () => {
    it('accepts pitangui.amazon.com', () => {
        assert.ok(core.isTrustedAlexaRedirectUri('https://pitangui.amazon.com/api/skill/link/X'));
    });
    it('rejects http scheme', () => {
        assert.equal(core.isTrustedAlexaRedirectUri('http://pitangui.amazon.com/x'), false);
    });
    it('rejects untrusted host', () => {
        assert.equal(core.isTrustedAlexaRedirectUri('https://evil.example.com/x'), false);
    });
    it('rejects garbage', () => {
        assert.equal(core.isTrustedAlexaRedirectUri('not-a-url'), false);
        assert.equal(core.isTrustedAlexaRedirectUri(''), false);
        assert.equal(core.isTrustedAlexaRedirectUri(null), false);
    });
});

describe('alexa/core findUserByAlexaAccessToken', () => {
    it('returns null for empty token', async () => {
        assert.equal(await core.findUserByAlexaAccessToken(''), null);
        assert.equal(await core.findUserByAlexaAccessToken(null), null);
    });
});
