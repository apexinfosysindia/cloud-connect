#!/usr/bin/env node
'use strict';

/**
 * migrate-down — reverse the most-recently-applied migration (or roll back
 * down to a target version) by running its `-- @DOWN` section.
 *
 * This is a DELIBERATE, MANUAL, GUARDED operation. It is never wired into app
 * boot or the deploy pipeline — rolling a migration back can destroy data that
 * accumulated in the structures the migration introduced, so a human must run
 * it on purpose.
 *
 * Guardrails, in order:
 *   1. Takes a fresh backup of database.sqlite first (unless --no-backup).
 *   2. Refuses if the target migration has no @DOWN section (irreversible).
 *   3. Detects which tables/columns the @DOWN will drop and prints the LIVE
 *      ROW COUNTS of those tables, so dropping a populated table is a visible,
 *      confirmed choice — not a silent surprise.
 *   4. Requires an interactive "yes" (or --yes for automation).
 *
 * Usage:
 *   npm run migrate:down                 # roll back the latest applied migration
 *   node scripts/migrate-down.js --to 2  # roll back until DB is at version 2
 *   node scripts/migrate-down.js --yes   # skip the interactive prompt
 *   node scripts/migrate-down.js --no-backup
 *   node scripts/migrate-down.js --db /path/to/database.sqlite
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const sqlite3 = require('sqlite3').verbose();
const createMigrator = require('../lib/migrator');

function parseArgs(argv) {
    const args = { yes: false, backup: true, to: null, db: null };
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === '--yes' || a === '-y') args.yes = true;
        else if (a === '--no-backup') args.backup = false;
        else if (a === '--to') args.to = Number(argv[++i]);
        else if (a === '--db') args.db = argv[++i];
        else if (a === '--help' || a === '-h') args.help = true;
    }
    return args;
}

function helpText() {
    return [
        'migrate-down — reverse applied migrations via their @DOWN section',
        '',
        'Options:',
        '  --to <version>   roll back repeatedly until the DB is at <version>',
        '                   (default: roll back exactly one — the latest)',
        '  --yes, -y        skip the confirmation prompt (for automation)',
        '  --no-backup      do not take a backup first (NOT recommended)',
        '  --db <path>      target a specific database file',
        '  --help, -h       show this help'
    ].join('\n');
}

function promisify(db) {
    return {
        dbRun: (sql, p = []) => new Promise((res, rej) => db.run(sql, p, function (e) { e ? rej(e) : res(this); })),
        dbGet: (sql, p = []) => new Promise((res, rej) => db.get(sql, p, (e, r) => (e ? rej(e) : res(r)))),
        dbAll: (sql, p = []) => new Promise((res, rej) => db.all(sql, p, (e, r) => (e ? rej(e) : res(r)))),
        dbExec: (sql) => new Promise((res, rej) => db.exec(sql, (e) => (e ? rej(e) : res())))
    };
}

// Pull the table names a @DOWN section will DROP, so we can show row counts.
function tablesDroppedByDown(downSql) {
    const names = [];
    const re = /DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?["'`]?([a-zA-Z0-9_]+)["'`]?/gi;
    let m;
    while ((m = re.exec(downSql)) !== null) {
        names.push(m[1]);
    }
    return names;
}

function columnsDroppedByDown(downSql) {
    const cols = [];
    const re = /ALTER\s+TABLE\s+["'`]?([a-zA-Z0-9_]+)["'`]?\s+DROP\s+COLUMN\s+["'`]?([a-zA-Z0-9_]+)["'`]?/gi;
    let m;
    while ((m = re.exec(downSql)) !== null) {
        cols.push({ table: m[1], column: m[2] });
    }
    return cols;
}

function backupPath(dbPath) {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    return `${dbPath}.bak.predown-${stamp}`;
}

async function confirm(question) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => {
        rl.question(question, (answer) => {
            rl.close();
            resolve(answer.trim().toLowerCase());
        });
    });
}

async function main() {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
        console.log(helpText());
        return;
    }

    const dbPath = args.db
        ? path.resolve(args.db)
        : path.resolve(__dirname, '..', 'database.sqlite');

    if (!fs.existsSync(dbPath)) {
        console.error(`Database not found: ${dbPath}`);
        process.exit(1);
    }

    const db = new sqlite3.Database(dbPath);
    const { dbRun, dbGet, dbAll, dbExec } = promisify(db);
    const migrator = createMigrator({ db, migrationsDir: path.resolve(__dirname, '..', 'migrations') });

    const files = migrator.listMigrationFiles();
    const byVersion = new Map(files.map((f) => [f.version, f]));

    const applied = (await dbAll(`SELECT version, name FROM schema_migrations ORDER BY version ASC`)) || [];
    if (applied.length === 0) {
        console.log('No applied migrations to roll back.');
        return;
    }

    // Determine the ordered list of versions to revert (highest first).
    const appliedVersions = applied.map((r) => r.version).sort((a, b) => a - b);
    const targetFloor = args.to !== null ? args.to : appliedVersions[appliedVersions.length - 1] - 1;
    const toRevert = appliedVersions.filter((v) => v > targetFloor).sort((a, b) => b - a);

    if (toRevert.length === 0) {
        console.log(`Nothing to roll back: DB is already at or below version ${targetFloor}.`);
        return;
    }

    // Pre-flight: ensure every target has a usable @DOWN BEFORE we touch anything.
    for (const version of toRevert) {
        const migration = byVersion.get(version);
        if (!migration) {
            console.error(`Cannot roll back version ${version}: migration file not found on disk.`);
            process.exit(1);
        }
        const { down } = migrator.getMigrationSections(migration);
        if (!down || !down.trim()) {
            console.error(
                `Refusing to roll back: migration ${migration.file} is irreversible (no -- @DOWN section).`
            );
            console.error('Stopping before any changes were made.');
            process.exit(1);
        }
    }

    // Build a human preview with live row counts of every table to be dropped.
    console.log(`\nDatabase: ${dbPath}`);
    console.log(`Will roll back ${toRevert.length} migration(s): ${toRevert.join(', ')}\n`);

    let anyPopulated = false;
    for (const version of toRevert) {
        const migration = byVersion.get(version);
        const { down } = migrator.getMigrationSections(migration);
        const tables = tablesDroppedByDown(down);
        const cols = columnsDroppedByDown(down);
        console.log(`  ${migration.file}`);
        for (const t of tables) {
            let count = 0;
            try {
                const row = await dbGet(`SELECT COUNT(*) AS c FROM "${t}"`);
                count = row ? row.c : 0;
            } catch (_) {
                count = 0; // table may not exist; drop is a no-op
            }
            const flag = count > 0 ? '  <-- HAS DATA' : '';
            if (count > 0) anyPopulated = true;
            console.log(`     DROP TABLE ${t} (${count} rows)${flag}`);
        }
        for (const c of cols) {
            console.log(`     DROP COLUMN ${c.table}.${c.column}`);
        }
    }

    if (anyPopulated) {
        console.log('\n⚠  One or more tables above contain data. Rolling back DELETES those rows permanently.');
    }

    // Backup (default on).
    if (args.backup) {
        const bak = backupPath(dbPath);
        fs.copyFileSync(dbPath, bak);
        // Also copy WAL/SHM if present so the backup is a faithful snapshot.
        for (const suffix of ['-wal', '-shm']) {
            if (fs.existsSync(dbPath + suffix)) {
                fs.copyFileSync(dbPath + suffix, bak + suffix);
            }
        }
        console.log(`\nBackup written: ${bak}`);
    } else {
        console.log('\n--no-backup specified: NO backup will be taken.');
    }

    // Confirm.
    if (!args.yes) {
        const answer = await confirm(`\nType 'yes' to roll back ${toRevert.join(', ')}: `);
        if (answer !== 'yes') {
            console.log('Aborted. No changes made.');
            db.close();
            return;
        }
    }

    // Execute each revert (highest version first) via the migrator primitive.
    await dbExec('PRAGMA foreign_keys = ON');
    for (const version of toRevert) {
        const migration = byVersion.get(version);
        process.stdout.write(`Rolling back ${migration.file}... `);
        await migrator.revertMigration(migration);
        console.log('done');
    }

    const remaining = (await dbAll(`SELECT version FROM schema_migrations ORDER BY version ASC`)) || [];
    console.log(`\nSchema is now at: ${remaining.map((r) => r.version).join(', ') || '(none)'}`);
    db.close();
}

main().catch((err) => {
    console.error('\nmigrate-down failed:', err.message);
    if (err.migration) console.error(`  migration: ${err.migration}`);
    process.exit(1);
});
