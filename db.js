const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const createMigrator = require('./lib/migrator');

const dbPath = path.resolve(__dirname, 'database.sqlite');

// The db handle is created synchronously and exported immediately so the
// rest of the app (lib/db-helpers, routes) can bind to it at require time.
// Schema migrations run asynchronously in the background; callers that
// need to be sure the schema is current (e.g. server.js before listening)
// await the exported `ready` promise below.
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to SQLite database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
    }
});

function runPragmasAndMigrate() {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.run('PRAGMA journal_mode = WAL');
            db.run('PRAGMA busy_timeout = 5000');
            db.run('PRAGMA foreign_keys = ON');
            db.run('SELECT 1', async (err) => {
                if (err) {
                    reject(err);
                    return;
                }
                try {
                    const migrator = createMigrator({ db });
                    await migrator.runPending();
                    resolve();
                } catch (migrationErr) {
                    reject(migrationErr);
                }
            });
        });
    });
}

// Exported promise that callers can await before depending on schema. On
// failure, we log loudly — server.js treats this as fatal and exits.
const ready = runPragmasAndMigrate().catch((err) => {
    console.error('Schema migration failed:', err.message);
    if (err.migration) {
        console.error(`Failed migration: ${err.migration}`);
    }
    throw err;
});

module.exports = db;
module.exports.ready = ready;
