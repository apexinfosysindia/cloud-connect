const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const config = require('../lib/config');

describe('config exports', () => {
    it('exports all expected string constants', () => {
        assert.equal(typeof config.CUSTOMER_PORTAL_HOST, 'string');
        assert.equal(typeof config.ADMIN_PORTAL_HOST, 'string');
        assert.equal(typeof config.CLOUD_BASE_DOMAIN, 'string');
        assert.equal(typeof config.DEVICE_TUNNEL_HOST, 'string');
        assert.equal(typeof config.ADMIN_SSH_JUMP_HOST, 'string');
        assert.equal(typeof config.ADMIN_SSH_JUMP_USER, 'string');
        assert.equal(typeof config.ADMIN_SSH_TARGET_HOST, 'string');
        assert.equal(typeof config.GOOGLE_HOMEGRAPH_SCOPE, 'string');
        assert.equal(typeof config.GOOGLE_HOMEGRAPH_DEFAULT_TOKEN_URI, 'string');
        assert.equal(typeof config.GOOGLE_HOMEGRAPH_API_BASE_URL, 'string');
    });

    it('exports all expected numeric constants', () => {
        assert.equal(typeof config.ADMIN_SSH_JUMP_PORT, 'number');
        assert.equal(typeof config.GOOGLE_HOME_AUTH_CODE_TTL_SECONDS, 'number');
        assert.equal(typeof config.GOOGLE_HOME_ACCESS_TOKEN_TTL_SECONDS, 'number');
        assert.equal(typeof config.GOOGLE_HOME_COMMAND_TTL_SECONDS, 'number');
        assert.equal(typeof config.GOOGLE_HOMEGRAPH_REQUEST_SYNC_DEBOUNCE_MS, 'number');
        assert.equal(typeof config.GOOGLE_HOMEGRAPH_REPORT_STATE_DEBOUNCE_MS, 'number');
        assert.equal(typeof config.DEVICE_HEARTBEAT_TIMEOUT_SECONDS, 'number');
        assert.equal(typeof config.DEVICE_HEARTBEAT_INTERVAL_SECONDS, 'number');
        assert.equal(typeof config.DEVICE_TUNNEL_PORT_MIN, 'number');
        assert.equal(typeof config.DEVICE_TUNNEL_PORT_MAX, 'number');
        assert.equal(typeof config.PORTAL_SESSION_COOKIE_MAX_AGE_MS, 'number');
    });

    it('exports boolean constants', () => {
        assert.equal(typeof config.GOOGLE_HOMEGRAPH_REPORT_STATE_ENABLED, 'boolean');
        assert.equal(typeof config.GOOGLE_DEBUG_ENDPOINTS_ENABLED, 'boolean');
        assert.equal(typeof config.PORTAL_SESSION_COOKIE_SECURE, 'boolean');
    });

    it('exports array constants', () => {
        assert.ok(Array.isArray(config.ALLOWED_CORS_ORIGINS));
        assert.ok(Array.isArray(config.GOOGLE_HOME_REDIRECT_URI_HOSTS));
    });

    it('has correct default values', () => {
        assert.equal(config.ADMIN_SSH_JUMP_PORT, 22);
        assert.equal(config.ADMIN_SSH_TARGET_HOST, '127.0.0.1');
        assert.equal(config.DEVICE_TOKEN_PREFIX, 'dvc_');
        assert.equal(config.PORTAL_SESSION_COOKIE_NAME, 'apx_portal_session');
        assert.equal(config.PORTAL_SESSION_COOKIE_MAX_AGE_MS, 7 * 24 * 60 * 60 * 1000);
    });

    it('tunnel port range is valid', () => {
        assert.ok(config.DEVICE_TUNNEL_PORT_MIN < config.DEVICE_TUNNEL_PORT_MAX);
        assert.ok(config.DEVICE_TUNNEL_PORT_MIN >= 1024);
    });
});
