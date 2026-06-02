const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const createMigrator = require('../lib/migrator');

function makeTempDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'migrator-test-'));
}

function makeDb() {
    return new sqlite3.Database(':memory:');
}

function run(db, sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function onRun(err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
}

function exec(db, sql) {
    return new Promise((resolve, reject) => {
        db.exec(sql, (err) => (err ? reject(err) : resolve()));
    });
}

function all(db, sql) {
    return new Promise((resolve, reject) => {
        db.all(sql, [], (err, rows) => (err ? reject(err) : resolve(rows)));
    });
}

describe('migrator', () => {
    it('applies a pending migration against a fresh DB', async () => {
        const dir = makeTempDir();
        fs.writeFileSync(
            path.join(dir, '001_create_widgets.sql'),
            `CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT);`
        );

        const db = makeDb();
        const migrator = createMigrator({ db, migrationsDir: dir });
        const result = await migrator.runPending();

        assert.deepEqual(result.applied, ['001_create_widgets.sql']);
        const tables = await all(db, `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`);
        const names = tables.map((t) => t.name);
        assert.ok(names.includes('widgets'));
        assert.ok(names.includes('schema_migrations'));

        db.close();
    });

    it('stamps baseline as applied on a legacy DB (users present, no migrations recorded)', async () => {
        const dir = makeTempDir();
        fs.writeFileSync(
            path.join(dir, '001_initial.sql'),
            `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY);`
        );

        const db = makeDb();
        // Seed legacy state: users table already exists (simulating the pre-migrator era).
        await exec(db, `CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)`);
        await run(db, `INSERT INTO users (email) VALUES ('pre@existing.com')`);

        const migrator = createMigrator({ db, migrationsDir: dir });
        const result = await migrator.runPending();

        assert.deepEqual(result.applied, []);
        assert.deepEqual(result.stamped, ['001_initial.sql']);

        // Legacy row preserved — baseline was NOT re-run and did not wipe data.
        const rows = await all(db, `SELECT email FROM users`);
        assert.equal(rows.length, 1);
        assert.equal(rows[0].email, 'pre@existing.com');

        db.close();
    });

    it('skips migrations that are already applied', async () => {
        const dir = makeTempDir();
        fs.writeFileSync(path.join(dir, '001_create.sql'), `CREATE TABLE foo (id INTEGER);`);

        const db = makeDb();
        const migrator = createMigrator({ db, migrationsDir: dir });

        const first = await migrator.runPending();
        assert.deepEqual(first.applied, ['001_create.sql']);

        const second = await migrator.runPending();
        assert.deepEqual(second.applied, []);
        assert.deepEqual(second.stamped, []);

        db.close();
    });

    it('rolls back a migration that fails mid-file', async () => {
        const dir = makeTempDir();
        fs.writeFileSync(
            path.join(dir, '001_broken.sql'),
            `CREATE TABLE good (id INTEGER);
             INSERT INTO missing_table VALUES (1);` // will fail
        );

        const db = makeDb();
        const migrator = createMigrator({ db, migrationsDir: dir });

        await assert.rejects(migrator.runPending());

        // `good` table should NOT exist — entire migration rolled back.
        const tables = await all(db, `SELECT name FROM sqlite_master WHERE type='table'`);
        const names = tables.map((t) => t.name);
        assert.ok(!names.includes('good'), 'failed migration must be fully rolled back');

        // schema_migrations row must NOT have been inserted.
        const migrationRows = await all(db, `SELECT version FROM schema_migrations`);
        assert.equal(migrationRows.length, 0);

        db.close();
    });

    it('applies multiple migrations in numeric order', async () => {
        const dir = makeTempDir();
        fs.writeFileSync(path.join(dir, '001_a.sql'), `CREATE TABLE a (x INTEGER);`);
        fs.writeFileSync(path.join(dir, '002_b.sql'), `CREATE TABLE b (x INTEGER);`);
        fs.writeFileSync(path.join(dir, '010_c.sql'), `CREATE TABLE c (x INTEGER);`);

        const db = makeDb();
        const migrator = createMigrator({ db, migrationsDir: dir });
        const result = await migrator.runPending();

        assert.deepEqual(result.applied, ['001_a.sql', '002_b.sql', '010_c.sql']);

        const versions = await all(db, `SELECT version FROM schema_migrations ORDER BY version`);
        assert.deepEqual(
            versions.map((r) => r.version),
            [1, 2, 10]
        );

        db.close();
    });

    it('reverts a migration via its @DOWN, then re-applies it (down/up round-trip)', async () => {
        const dir = makeTempDir();
        fs.writeFileSync(
            path.join(dir, '001_gadgets.sql'),
            `-- @UP
             CREATE TABLE gadgets (id INTEGER PRIMARY KEY, label TEXT);
             -- @DOWN
             DROP TABLE IF EXISTS gadgets;`
        );

        const db = makeDb();
        const migrator = createMigrator({ db, migrationsDir: dir });
        const [migration] = migrator.listMigrationFiles();

        // UP
        await migrator.runPending();
        let names = (await all(db, `SELECT name FROM sqlite_master WHERE type='table'`)).map((t) => t.name);
        assert.ok(names.includes('gadgets'), 'table should exist after apply');
        assert.deepEqual(
            (await all(db, `SELECT version FROM schema_migrations`)).map((r) => r.version),
            [1]
        );

        // DOWN — table gone AND tracking row removed, atomically.
        await migrator.revertMigration(migration);
        names = (await all(db, `SELECT name FROM sqlite_master WHERE type='table'`)).map((t) => t.name);
        assert.ok(!names.includes('gadgets'), 'table should be dropped after revert');
        assert.equal(
            (await all(db, `SELECT version FROM schema_migrations`)).length,
            0,
            'schema_migrations row must be removed on revert'
        );

        // UP again — runPending treats it as pending and re-applies cleanly.
        const reapplied = await migrator.runPending();
        assert.deepEqual(reapplied.applied, ['001_gadgets.sql']);
        names = (await all(db, `SELECT name FROM sqlite_master WHERE type='table'`)).map((t) => t.name);
        assert.ok(names.includes('gadgets'), 'table should be restored after re-apply');

        db.close();
    });

    it('refuses to revert an irreversible migration (no @DOWN) without touching the DB', async () => {
        const dir = makeTempDir();
        // No @UP/@DOWN markers => entire body is "up", down is null => irreversible.
        fs.writeFileSync(path.join(dir, '001_permanent.sql'), `CREATE TABLE permanent (id INTEGER PRIMARY KEY);`);

        const db = makeDb();
        const migrator = createMigrator({ db, migrationsDir: dir });
        const [migration] = migrator.listMigrationFiles();

        await migrator.runPending();

        await assert.rejects(
            migrator.revertMigration(migration),
            (err) => err.irreversible === true && /irreversible/.test(err.message),
            'revert of a no-@DOWN migration must reject with err.irreversible'
        );

        // DB untouched: table still present, tracking row intact.
        const names = (await all(db, `SELECT name FROM sqlite_master WHERE type='table'`)).map((t) => t.name);
        assert.ok(names.includes('permanent'), 'table must survive a refused revert');
        assert.deepEqual(
            (await all(db, `SELECT version FROM schema_migrations`)).map((r) => r.version),
            [1],
            'tracking row must survive a refused revert'
        );

        db.close();
    });

    it('rolls back the whole revert if the @DOWN section fails mid-way', async () => {
        const dir = makeTempDir();
        fs.writeFileSync(
            path.join(dir, '001_keepme.sql'),
            `-- @UP
             CREATE TABLE keepme (id INTEGER PRIMARY KEY);
             -- @DOWN
             DROP TABLE keepme;
             INSERT INTO nonexistent VALUES (1);` // fails AFTER the drop
        );

        const db = makeDb();
        const migrator = createMigrator({ db, migrationsDir: dir });
        const [migration] = migrator.listMigrationFiles();

        await migrator.runPending();
        await assert.rejects(migrator.revertMigration(migration));

        // The DROP must have been rolled back along with the failing INSERT.
        const names = (await all(db, `SELECT name FROM sqlite_master WHERE type='table'`)).map((t) => t.name);
        assert.ok(names.includes('keepme'), 'failed revert must restore the dropped table');

        // And the migration must still count as applied.
        assert.deepEqual(
            (await all(db, `SELECT version FROM schema_migrations`)).map((r) => r.version),
            [1],
            'failed revert must leave the tracking row in place'
        );

        db.close();
    });
});
