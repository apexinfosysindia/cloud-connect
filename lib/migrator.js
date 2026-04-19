const fs = require('fs');
const path = require('path');

/**
 * Versioned SQLite migration runner.
 *
 * Directory layout: one `NNN_name.sql` file per migration, sorted numerically
 * by the NNN prefix. Applied versions are tracked in `schema_migrations`.
 *
 * Behavior:
 *   1. Ensure the `schema_migrations` tracking table exists.
 *   2. On a legacy database (users table present, schema_migrations empty),
 *      stamp the baseline (001) as already applied without running it.
 *      The baseline is IF-NOT-EXISTS-only DDL, so re-running would be safe,
 *      but skipping it is cleaner and makes the applied_at timestamp honest.
 *   3. For every migration on disk that is not yet in schema_migrations,
 *      run it inside a transaction. On failure, ROLLBACK and throw.
 *
 * Each migration file is executed as a single db.exec() call, which supports
 * multi-statement SQL (our files have several CREATE/ALTER statements).
 * We wrap each file in BEGIN/COMMIT manually because db.exec does not.
 *
 * Note: if a single migration file already contains BEGIN/COMMIT, do not
 * nest. Our convention is that migration files contain pure DDL/DML only;
 * the runner owns transaction boundaries.
 */
module.exports = function createMigrator({ db, migrationsDir }) {
    const dir = migrationsDir || path.join(__dirname, '..', 'migrations');

    function dbRun(sql, params = []) {
        return new Promise((resolve, reject) => {
            db.run(sql, params, function onRun(err) {
                if (err) reject(err);
                else resolve(this);
            });
        });
    }

    function dbExec(sql) {
        return new Promise((resolve, reject) => {
            db.exec(sql, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }

    function dbGet(sql, params = []) {
        return new Promise((resolve, reject) => {
            db.get(sql, params, (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    }

    function dbAll(sql, params = []) {
        return new Promise((resolve, reject) => {
            db.all(sql, params, (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }

    async function ensureTrackingTable() {
        await dbRun(`
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        `);
    }

    function listMigrationFiles() {
        if (!fs.existsSync(dir)) return [];
        return fs
            .readdirSync(dir)
            .filter((name) => /^\d{3,}_.+\.sql$/.test(name))
            .map((name) => {
                const match = name.match(/^(\d{3,})_(.+)\.sql$/);
                return {
                    version: Number(match[1]),
                    name: match[2],
                    file: name,
                    fullPath: path.join(dir, name)
                };
            })
            .sort((a, b) => a.version - b.version);
    }

    async function getAppliedVersions() {
        const rows = await dbAll(`SELECT version FROM schema_migrations ORDER BY version ASC`);
        return new Set(rows.map((r) => r.version));
    }

    async function isLegacyDatabase() {
        // Legacy = users table exists but schema_migrations has no rows yet.
        // In that case, the db was populated by the pre-migrator codepath
        // and we should mark 001 applied without running it.
        const usersRow = await dbGet(
            `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'users'`
        );
        if (!usersRow) return false;
        const migrationsRow = await dbGet(`SELECT COUNT(*) AS c FROM schema_migrations`);
        return (migrationsRow?.c || 0) === 0;
    }

    async function stampMigration(migration) {
        await dbRun(`INSERT INTO schema_migrations (version, name) VALUES (?, ?)`, [
            migration.version,
            migration.name
        ]);
    }

    async function applyMigration(migration) {
        const sql = fs.readFileSync(migration.fullPath, 'utf8');
        // We manage transactions at the runner level: each migration file
        // becomes BEGIN + body + stamp-into-schema_migrations + COMMIT so
        // either the whole file + its tracking row land together or nothing
        // does. db.exec() does not auto-transact multi-statement SQL.
        await dbExec('BEGIN');
        try {
            await dbExec(sql);
            await dbRun(`INSERT INTO schema_migrations (version, name) VALUES (?, ?)`, [
                migration.version,
                migration.name
            ]);
            await dbExec('COMMIT');
        } catch (err) {
            try {
                await dbExec('ROLLBACK');
            } catch (rollbackErr) {
                console.error(
                    `Migration ${migration.file}: ROLLBACK failed after error:`,
                    rollbackErr.message
                );
            }
            err.migration = migration.file;
            throw err;
        }
    }

    async function runPending() {
        await ensureTrackingTable();

        const files = listMigrationFiles();
        if (files.length === 0) {
            return { applied: [], stamped: [] };
        }

        const applied = await getAppliedVersions();
        const stamped = [];

        // Legacy bootstrap: if db has user data but no migrations are
        // recorded, stamp the baseline as applied without running it.
        if ((await isLegacyDatabase()) && !applied.has(files[0].version)) {
            await stampMigration(files[0]);
            applied.add(files[0].version);
            stamped.push(files[0].file);
            console.log(
                `Stamped baseline migration ${files[0].file} as applied (pre-existing database detected)`
            );
        }

        const appliedThisRun = [];
        for (const migration of files) {
            if (applied.has(migration.version)) continue;
            console.log(`Applying migration ${migration.file}...`);
            await applyMigration(migration);
            appliedThisRun.push(migration.file);
        }

        if (appliedThisRun.length === 0 && stamped.length === 0) {
            console.log('No pending migrations.');
        } else if (appliedThisRun.length > 0) {
            console.log(`Applied ${appliedThisRun.length} migration(s): ${appliedThisRun.join(', ')}`);
        }

        return { applied: appliedThisRun, stamped };
    }

    return {
        runPending,
        // Exposed for testing
        listMigrationFiles,
        getAppliedVersions,
        isLegacyDatabase
    };
};
