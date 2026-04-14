const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const utils = require('../lib/utils');

// --- sanitizeString ---
describe('sanitizeString', () => {
    it('returns null for non-string inputs', () => {
        assert.equal(utils.sanitizeString(null), null);
        assert.equal(utils.sanitizeString(undefined), null);
        assert.equal(utils.sanitizeString(123), null);
        assert.equal(utils.sanitizeString({}), null);
    });

    it('returns null for empty/whitespace strings', () => {
        assert.equal(utils.sanitizeString(''), null);
        assert.equal(utils.sanitizeString('   '), null);
        assert.equal(utils.sanitizeString('\t\n'), null);
    });

    it('trims whitespace', () => {
        assert.equal(utils.sanitizeString('  hello  '), 'hello');
    });

    it('truncates to maxLength', () => {
        assert.equal(utils.sanitizeString('abcdefghij', 5), 'abcde');
    });

    it('uses default maxLength of 120', () => {
        const long = 'a'.repeat(200);
        assert.equal(utils.sanitizeString(long).length, 120);
    });

    it('returns the string when under maxLength', () => {
        assert.equal(utils.sanitizeString('hello', 10), 'hello');
    });
});

// --- sanitizeEntityId ---
describe('sanitizeEntityId', () => {
    it('accepts valid entity IDs', () => {
        assert.equal(utils.sanitizeEntityId('light.living_room'), 'light.living_room');
        assert.equal(utils.sanitizeEntityId('sensor.temp_1'), 'sensor.temp_1');
        assert.equal(utils.sanitizeEntityId('switch.outlet-2'), 'switch.outlet-2');
    });

    it('rejects invalid characters', () => {
        assert.equal(utils.sanitizeEntityId('light/room'), null);
        assert.equal(utils.sanitizeEntityId('switch room'), null);
        assert.equal(utils.sanitizeEntityId('light<script>'), null);
    });

    it('returns null for empty input', () => {
        assert.equal(utils.sanitizeEntityId(''), null);
        assert.equal(utils.sanitizeEntityId(null), null);
    });
});

// --- sanitizeDeviceUid ---
describe('sanitizeDeviceUid', () => {
    it('accepts valid device UIDs', () => {
        assert.equal(utils.sanitizeDeviceUid('abc123'), 'abc123');
        assert.equal(utils.sanitizeDeviceUid('device.name-1'), 'device.name-1');
    });

    it('rejects invalid characters', () => {
        assert.equal(utils.sanitizeDeviceUid('device uid'), null);
        assert.equal(utils.sanitizeDeviceUid('dev/path'), null);
    });
});

// --- sanitizeDeviceName ---
describe('sanitizeDeviceName', () => {
    it('cleans whitespace', () => {
        assert.equal(utils.sanitizeDeviceName('  My\t Device  '), 'My Device');
    });

    it('collapses multiple spaces', () => {
        assert.equal(utils.sanitizeDeviceName('Hello    World'), 'Hello World');
    });

    it('returns null for empty input', () => {
        assert.equal(utils.sanitizeDeviceName(''), null);
        assert.equal(utils.sanitizeDeviceName(null), null);
    });
});

// --- sanitizeSshHost ---
describe('sanitizeSshHost', () => {
    it('accepts valid hosts', () => {
        assert.equal(utils.sanitizeSshHost('192.168.1.1'), '192.168.1.1');
        assert.equal(utils.sanitizeSshHost('host.example.com'), 'host.example.com');
        assert.equal(utils.sanitizeSshHost('[::1]'), null); // brackets not in allowed set
    });

    it('rejects invalid characters', () => {
        assert.equal(utils.sanitizeSshHost('host name'), null);
        assert.equal(utils.sanitizeSshHost('host;rm -rf'), null);
    });
});

// --- sanitizeSshUser ---
describe('sanitizeSshUser', () => {
    it('accepts valid usernames', () => {
        assert.equal(utils.sanitizeSshUser('root'), 'root');
        assert.equal(utils.sanitizeSshUser('fleet_admin'), 'fleet_admin');
        assert.equal(utils.sanitizeSshUser('_service'), '_service');
    });

    it('rejects invalid usernames', () => {
        assert.equal(utils.sanitizeSshUser('0root'), null); // starts with digit
        assert.equal(utils.sanitizeSshUser('user name'), null); // space
    });
});

// --- sanitizeEventType ---
describe('sanitizeEventType', () => {
    it('lowercases and accepts valid types', () => {
        assert.equal(utils.sanitizeEventType('BOOT'), 'boot');
        assert.equal(utils.sanitizeEventType('device.connect'), 'device.connect');
    });

    it('rejects invalid types', () => {
        assert.equal(utils.sanitizeEventType('type with space'), null);
    });
});

// --- sanitizePort ---
describe('sanitizePort', () => {
    it('accepts valid ports', () => {
        assert.equal(utils.sanitizePort(22), 22);
        assert.equal(utils.sanitizePort(8080), 8080);
        assert.equal(utils.sanitizePort('3000'), 3000);
        assert.equal(utils.sanitizePort(1), 1);
        assert.equal(utils.sanitizePort(65535), 65535);
    });

    it('rejects invalid ports', () => {
        assert.equal(utils.sanitizePort(0), null);
        assert.equal(utils.sanitizePort(-1), null);
        assert.equal(utils.sanitizePort(65536), null);
        assert.equal(utils.sanitizePort(3.14), null);
        assert.equal(utils.sanitizePort('abc'), null);
    });

    it('returns null for empty/null', () => {
        assert.equal(utils.sanitizePort(null), null);
        assert.equal(utils.sanitizePort(undefined), null);
        assert.equal(utils.sanitizePort(''), null);
    });
});

// --- hasExactlyOneDot ---
describe('hasExactlyOneDot', () => {
    it('returns true for strings with exactly one dot not at start', () => {
        assert.equal(utils.hasExactlyOneDot('a.b'), true);
        assert.equal(utils.hasExactlyOneDot('payload.signature'), true);
    });

    it('returns false for no dot or multiple dots', () => {
        assert.equal(utils.hasExactlyOneDot('nodot'), false);
        assert.equal(utils.hasExactlyOneDot('a.b.c'), false);
    });

    it('returns false for dot at position 0', () => {
        assert.equal(utils.hasExactlyOneDot('.abc'), false);
    });

    it('returns false for non-string', () => {
        assert.equal(utils.hasExactlyOneDot(null), false);
        assert.equal(utils.hasExactlyOneDot(123), false);
    });
});

// --- parseJsonSafe ---
describe('parseJsonSafe', () => {
    it('parses valid JSON', () => {
        assert.deepEqual(utils.parseJsonSafe('{"a":1}'), { a: 1 });
    });

    it('returns fallback for invalid JSON', () => {
        assert.equal(utils.parseJsonSafe('not json', 'default'), 'default');
    });

    it('returns fallback for falsy input', () => {
        assert.equal(utils.parseJsonSafe(null, 42), 42);
        assert.equal(utils.parseJsonSafe('', 'empty'), 'empty');
        assert.equal(utils.parseJsonSafe(undefined), null);
    });

    it('returns object input as-is', () => {
        const obj = { key: 'value' };
        assert.equal(utils.parseJsonSafe(obj), obj);
    });
});

// --- generateToken ---
describe('generateToken', () => {
    it('starts with apx_ prefix', () => {
        const token = utils.generateToken();
        assert.ok(token.startsWith('apx_'));
    });

    it('has correct length (4 prefix + 32 hex chars)', () => {
        assert.equal(utils.generateToken().length, 36);
    });

    it('generates unique tokens', () => {
        const a = utils.generateToken();
        const b = utils.generateToken();
        assert.notEqual(a, b);
    });
});

// --- hashSecret ---
describe('hashSecret', () => {
    it('produces consistent SHA-256 hex output', () => {
        const hash = utils.hashSecret('test');
        assert.equal(hash.length, 64);
        assert.equal(utils.hashSecret('test'), hash);
    });

    it('handles null/empty', () => {
        assert.equal(utils.hashSecret(null), utils.hashSecret(''));
    });
});

// --- generateDeviceAuthToken ---
describe('generateDeviceAuthToken', () => {
    it('starts with dvc_ prefix', () => {
        assert.ok(utils.generateDeviceAuthToken().startsWith('dvc_'));
    });

    it('has correct length (4 prefix + 48 hex chars)', () => {
        assert.equal(utils.generateDeviceAuthToken().length, 52);
    });
});

// --- generateAdminConnectToken ---
describe('generateAdminConnectToken', () => {
    it('starts with acn_ prefix', () => {
        assert.ok(utils.generateAdminConnectToken().startsWith('acn_'));
    });
});

// --- normalizeLocalIps ---
describe('normalizeLocalIps', () => {
    it('handles string input with comma separation', () => {
        assert.equal(utils.normalizeLocalIps('192.168.1.1, 10.0.0.1'), '192.168.1.1,10.0.0.1');
    });

    it('handles array input', () => {
        assert.equal(utils.normalizeLocalIps(['192.168.1.1', '10.0.0.1']), '192.168.1.1,10.0.0.1');
    });

    it('deduplicates entries', () => {
        assert.equal(utils.normalizeLocalIps('192.168.1.1, 192.168.1.1'), '192.168.1.1');
    });

    it('filters out invalid entries', () => {
        assert.equal(utils.normalizeLocalIps('192.168.1.1, not_an_ip'), '192.168.1.1');
    });

    it('limits to 8 entries', () => {
        const ips = Array.from({ length: 12 }, (_, i) => `10.0.0.${i + 1}`);
        const result = utils.normalizeLocalIps(ips);
        assert.equal(result.split(',').length, 8);
    });

    it('returns null for empty', () => {
        assert.equal(utils.normalizeLocalIps(''), null);
        assert.equal(utils.normalizeLocalIps([]), null);
    });
});

// --- isTrustedGoogleRedirectUri ---
describe('isTrustedGoogleRedirectUri', () => {
    it('accepts trusted HTTPS URI', () => {
        assert.equal(utils.isTrustedGoogleRedirectUri('https://oauth-redirect.googleusercontent.com/r/123'), true);
    });

    it('rejects HTTP URI', () => {
        assert.equal(utils.isTrustedGoogleRedirectUri('http://oauth-redirect.googleusercontent.com/r/123'), false);
    });

    it('rejects untrusted host', () => {
        assert.equal(utils.isTrustedGoogleRedirectUri('https://evil.com/callback'), false);
    });

    it('rejects null/empty', () => {
        assert.equal(utils.isTrustedGoogleRedirectUri(''), false);
        assert.equal(utils.isTrustedGoogleRedirectUri(null), false);
    });

    it('rejects invalid URL', () => {
        assert.equal(utils.isTrustedGoogleRedirectUri('not a url'), false);
    });
});

// --- getHeartbeatWindowSeconds ---
describe('getHeartbeatWindowSeconds', () => {
    it('returns a number within bounds', () => {
        const result = utils.getHeartbeatWindowSeconds();
        assert.ok(typeof result === 'number');
        assert.ok(result >= 20 && result <= 300);
    });
});

// --- getDeviceTunnelPortRange ---
describe('getDeviceTunnelPortRange', () => {
    it('returns min and max', () => {
        const range = utils.getDeviceTunnelPortRange();
        assert.ok(typeof range.min === 'number');
        assert.ok(typeof range.max === 'number');
        assert.ok(range.min >= 1025);
        assert.ok(range.max >= range.min);
        assert.ok(range.max - range.min >= 32);
    });
});

// --- isDeviceTunnelPortInRange ---
describe('isDeviceTunnelPortInRange', () => {
    it('accepts port within range', () => {
        const { min } = utils.getDeviceTunnelPortRange();
        assert.equal(utils.isDeviceTunnelPortInRange(min), true);
    });

    it('rejects port outside range', () => {
        assert.equal(utils.isDeviceTunnelPortInRange(1), false);
    });

    it('rejects non-integer', () => {
        assert.equal(utils.isDeviceTunnelPortInRange(3.5), false);
        assert.equal(utils.isDeviceTunnelPortInRange('abc'), false);
    });
});

// --- SQLite error helpers ---
describe('sqliteMessage', () => {
    it('extracts lowercase message from error', () => {
        assert.equal(utils.sqliteMessage(new Error('HELLO')), 'hello');
    });

    it('returns empty string for null', () => {
        assert.equal(utils.sqliteMessage(null), '');
    });
});

describe('isMissingGoogleEntityLastSeenColumnError', () => {
    it('detects missing column error', () => {
        assert.equal(
            utils.isMissingGoogleEntityLastSeenColumnError(new Error('no such column: entity_last_seen_at')),
            true
        );
    });

    it('returns false for other errors', () => {
        assert.equal(utils.isMissingGoogleEntityLastSeenColumnError(new Error('something else')), false);
    });
});

describe('isGoogleSyncSnapshotsUpsertUnsupportedError', () => {
    it('detects ON syntax error', () => {
        assert.equal(utils.isGoogleSyncSnapshotsUpsertUnsupportedError(new Error('near "on": syntax error')), true);
    });

    it('detects DO syntax error', () => {
        assert.equal(utils.isGoogleSyncSnapshotsUpsertUnsupportedError(new Error('near "do": syntax error')), true);
    });
});

// --- parsePositiveInt ---
describe('parsePositiveInt', () => {
    it('parses positive integers', () => {
        assert.equal(utils.parsePositiveInt(42), 42);
        assert.equal(utils.parsePositiveInt('10'), 10);
    });

    it('returns null for zero, negative, non-integer', () => {
        assert.equal(utils.parsePositiveInt(0), null);
        assert.equal(utils.parsePositiveInt(-1), null);
        assert.equal(utils.parsePositiveInt(3.5), null);
        assert.equal(utils.parsePositiveInt('abc'), null);
    });
});

// --- isAccessEnabled ---
describe('isAccessEnabled', () => {
    it('returns true for active/trial', () => {
        assert.equal(utils.isAccessEnabled('active'), true);
        assert.equal(utils.isAccessEnabled('trial'), true);
    });

    it('returns false for other statuses', () => {
        assert.equal(utils.isAccessEnabled('payment_pending'), false);
        assert.equal(utils.isAccessEnabled('disabled'), false);
        assert.equal(utils.isAccessEnabled(null), false);
    });
});

// --- isIgnorableSqliteMigrationError ---
describe('isIgnorableSqliteMigrationError', () => {
    it('detects duplicate column name error', () => {
        assert.equal(utils.isIgnorableSqliteMigrationError(new Error('duplicate column name: foo')), true);
    });

    it('detects already exists error', () => {
        assert.equal(utils.isIgnorableSqliteMigrationError(new Error('table foo already exists')), true);
    });

    it('returns false for other errors', () => {
        assert.equal(utils.isIgnorableSqliteMigrationError(new Error('syntax error')), false);
    });
});

// --- asyncHandler ---
describe('asyncHandler', () => {
    it('calls next with error on rejection', async () => {
        const error = new Error('test');
        const handler = utils.asyncHandler(async () => {
            throw error;
        });
        let caughtError;
        await handler({}, {}, (err) => {
            caughtError = err;
        });
        assert.equal(caughtError, error);
    });

    it('does not call next on success', async () => {
        const handler = utils.asyncHandler(async (_req, res) => {
            res.sent = true;
        });
        const res = {};
        let nextCalled = false;
        await handler({}, res, () => {
            nextCalled = true;
        });
        assert.equal(res.sent, true);
        assert.equal(nextCalled, false);
    });
});

// --- getAdminSshRoute ---
describe('getAdminSshRoute', () => {
    it('returns a proxyjump route object', () => {
        const route = utils.getAdminSshRoute();
        assert.equal(route.method, 'proxyjump');
        assert.ok(route.jump_host);
        assert.ok(route.jump_user);
        assert.ok(typeof route.jump_port === 'number');
        assert.equal(route.target_user, 'root');
    });
});

// --- STATELESS_ENTITY_TYPES ---
describe('STATELESS_ENTITY_TYPES', () => {
    it('contains scene, script, button, input_button', () => {
        assert.ok(utils.STATELESS_ENTITY_TYPES.has('scene'));
        assert.ok(utils.STATELESS_ENTITY_TYPES.has('script'));
        assert.ok(utils.STATELESS_ENTITY_TYPES.has('button'));
        assert.ok(utils.STATELESS_ENTITY_TYPES.has('input_button'));
    });

    it('does not contain non-stateless types', () => {
        assert.ok(!utils.STATELESS_ENTITY_TYPES.has('light'));
        assert.ok(!utils.STATELESS_ENTITY_TYPES.has('switch'));
    });
});
