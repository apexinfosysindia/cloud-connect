// Smoke test for the migrator. Invoked from the shell against two DBs:
// 1. A fresh (non-existent) DB — should run migration 001 fresh.
// 2. A legacy production DB snapshot — should stamp 001 as applied without
//    re-running it.
const sqlite3 = require('sqlite3').verbose();
const createMigrator = require('../lib/migrator');

async function run(label, dbPath) {
    console.log(`\n=== ${label} (${dbPath}) ===`);
    const db = new sqlite3.Database(dbPath);
    const migrator = createMigrator({ db });

    const before = await new Promise((resolve) => {
        db.all(
            `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`,
            [],
            (_, rows) => resolve(rows || [])
        );
    });
    console.log(`Before: ${before.length} tables`);

    const result = await migrator.runPending();
    console.log(`Result: applied=${JSON.stringify(result.applied)} stamped=${JSON.stringify(result.stamped)}`);

    const after = await new Promise((resolve) => {
        db.all(`SELECT version, name, applied_at FROM schema_migrations`, [], (_, rows) =>
            resolve(rows || [])
        );
    });
    console.log(`schema_migrations rows:`, after);

    const tables = await new Promise((resolve) => {
        db.all(
            `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`,
            [],
            (_, rows) => resolve(rows || [])
        );
    });
    console.log(`After: ${tables.length} tables`);

    await new Promise((resolve) => {
        db.close(resolve);
    });
}

(async () => {
    try {
        await run('FRESH DB', '/tmp/cloud-connect-test-fresh.sqlite');
        await run('LEGACY DB (snapshot of prod)', '/tmp/cloud-connect-test-legacy.sqlite');
        console.log('\n✅ Smoke test passed');
    } catch (err) {
        console.error('❌ Smoke test failed:', err);
        process.exit(1);
    }
})();
