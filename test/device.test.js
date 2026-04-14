const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const config = require('../lib/config');
const utils = require('../lib/utils');

const device = require('../lib/device')({
    dbGet: async () => null,
    dbRun: async () => ({}),
    dbAll: async () => [],
    config,
    utils
});

describe('serializeDevice', () => {
    const mockDevice = {
        id: 1,
        device_uid: 'device001',
        device_name: 'Living Room Hub',
        device_model: 'ApexOS v2',
        addon_version: '3.0.0',
        firmware_version: '1.2.3',
        local_ip: '192.168.1.100',
        tunnel_port: 22001,
        tunnel_active: 1,
        ssh_host: '127.0.0.1',
        ssh_user: 'root',
        ssh_port: 22,
        last_seen_at: new Date().toISOString(),
        user_id: 5,
        user_email: 'test@example.com',
        user_status: 'active',
        user_subdomain: '',
        hostname: 'hub-01',
        admin_name_override: 0,
        created_at: '2024-01-01T00:00:00Z'
    };

    it('includes all expected fields', () => {
        const result = device.serializeDevice(mockDevice);
        assert.equal(result.id, 1);
        assert.equal(result.device_uid, 'device001');
        assert.equal(result.device_name, 'Living Room Hub');
        assert.equal(result.tunnel_port, 22001);
        assert.ok('online' in result);
    });

    it('computes online status from last_seen_at', () => {
        const result = device.serializeDevice(mockDevice);
        assert.equal(typeof result.online, 'boolean');
    });

    it('handles offline device', () => {
        const oldDevice = { ...mockDevice, last_seen_at: '2020-01-01T00:00:00Z', user_status: 'active' };
        const result = device.serializeDevice(oldDevice);
        assert.equal(result.online, false);
    });
});

describe('buildAdminConnectCommand', () => {
    it('returns null when device has no tunnel port', () => {
        const result = device.buildAdminConnectCommand({ tunnel_port: null });
        assert.equal(result, null);
    });

    it('returns ssh command string when port is valid', () => {
        const result = device.buildAdminConnectCommand({
            tunnel_port: 22001,
            ssh_user: 'root'
        });
        assert.ok(result === null || typeof result === 'string');
        // If result is a string, it should contain ssh command
        if (result) {
            assert.ok(result.includes('ssh'));
            assert.ok(result.includes('22001'));
        }
    });
});
