const test = require('node:test');
const assert = require('node:assert/strict');
const createSchemaBaseline = require('../../lib/alexa/schema-baseline');

// In-memory fake of the dbAll/dbGet contract used by schema-baseline.js.
// We don't need real SQLite — the assertions are pure presence checks.
function makeFakeDb({ tables = [], userColumns = [], tokenColumns = [], stampedVersions = [] }) {
    return {
        async dbAll(sql) {
            if (/sqlite_master.*alexa_/.test(sql)) {
                return tables.map((name) => ({ name }));
            }
            if (/PRAGMA table_info\(users\)/.test(sql)) {
                return userColumns.map((name) => ({ name }));
            }
            if (/PRAGMA table_info\(alexa_tokens\)/.test(sql)) {
                return tokenColumns.map((name) => ({ name }));
            }
            return [];
        },
        async dbGet(sql) {
            if (/schema_migrations/.test(sql) && /version = 3/.test(sql)) {
                const found = stampedVersions.find((v) => v.version === 3);
                return found || undefined;
            }
            return undefined;
        }
    };
}

const FULL_TABLES = [
    'alexa_auth_codes',
    'alexa_tokens',
    'alexa_entities',
    'alexa_command_queue',
    'alexa_sync_snapshots'
];
const FULL_USER_COLS = ['alexa_enabled', 'alexa_linked', 'alexa_security_pin'];
const FULL_TOKEN_COLS = [
    'access_token_hash',
    'refresh_token_hash',
    'expires_at',
    'lwa_access_token_encrypted',
    'lwa_refresh_token_encrypted',
    'lwa_expires_at',
    'lwa_scopes'
];
const FULL_STAMP = [{ version: 3, name: 'alexa_integration' }];

test('assertBaseline passes when residual schema is fully present', async () => {
    const db = makeFakeDb({
        tables: FULL_TABLES,
        userColumns: FULL_USER_COLS,
        tokenColumns: FULL_TOKEN_COLS,
        stampedVersions: FULL_STAMP
    });
    const baseline = createSchemaBaseline(db);
    const result = await baseline.assertBaseline();
    assert.equal(result.ok, true);
    assert.equal(result.adoptedVersion, 3);
    assert.equal(result.adoptedName, 'alexa_integration');
});

test('assertBaseline throws when an alexa_* table is missing', async () => {
    const db = makeFakeDb({
        tables: FULL_TABLES.filter((t) => t !== 'alexa_command_queue'),
        userColumns: FULL_USER_COLS,
        tokenColumns: FULL_TOKEN_COLS,
        stampedVersions: FULL_STAMP
    });
    const baseline = createSchemaBaseline(db);
    await assert.rejects(baseline.assertBaseline(), /missing tables.*alexa_command_queue/);
});

test('assertBaseline throws when users table missing alexa column', async () => {
    const db = makeFakeDb({
        tables: FULL_TABLES,
        userColumns: ['alexa_enabled', 'alexa_linked'], // alexa_security_pin missing
        tokenColumns: FULL_TOKEN_COLS,
        stampedVersions: FULL_STAMP
    });
    const baseline = createSchemaBaseline(db);
    await assert.rejects(baseline.assertBaseline(), /alexa_security_pin/);
});

test('assertBaseline throws when alexa_tokens missing LWA columns (the v1→v2 reconciliation case)', async () => {
    const db = makeFakeDb({
        tables: FULL_TABLES,
        userColumns: FULL_USER_COLS,
        // Simulates an environment where only the old v1 token shape was applied
        tokenColumns: ['access_token_hash', 'refresh_token_hash', 'expires_at'],
        stampedVersions: FULL_STAMP
    });
    const baseline = createSchemaBaseline(db);
    await assert.rejects(baseline.assertBaseline(), /lwa_access_token_encrypted/);
});

test('assertBaseline throws when schema row absent (suspicious manual creation)', async () => {
    const db = makeFakeDb({
        tables: FULL_TABLES,
        userColumns: FULL_USER_COLS,
        tokenColumns: FULL_TOKEN_COLS,
        stampedVersions: [] // tables exist but migrator doesn't know
    });
    const baseline = createSchemaBaseline(db);
    await assert.rejects(baseline.assertBaseline(), /no row\s+for version 3/);
});
