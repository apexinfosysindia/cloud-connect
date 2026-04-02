const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.resolve(__dirname, 'database.sqlite');

const USERS_TABLE_SCHEMA = `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        subdomain TEXT UNIQUE NOT NULL,
        access_token TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('payment_pending', 'active', 'trial', 'expired', 'suspended')),
        razorpay_customer_id TEXT,
        razorpay_subscription_id TEXT,
        razorpay_payment_id TEXT,
        razorpay_subscription_status TEXT,
        trial_ends_at DATETIME,
        trial_approved_at DATETIME,
        activated_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`;

const USERS_TABLE_REBUILD = `
    BEGIN TRANSACTION;
    CREATE TABLE users_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        subdomain TEXT UNIQUE NOT NULL,
        access_token TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('payment_pending', 'active', 'trial', 'expired', 'suspended')),
        razorpay_customer_id TEXT,
        razorpay_subscription_id TEXT,
        razorpay_payment_id TEXT,
        razorpay_subscription_status TEXT,
        trial_ends_at DATETIME,
        trial_approved_at DATETIME,
        activated_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    INSERT INTO users_new (
        id,
        email,
        password,
        subdomain,
        access_token,
        status,
        razorpay_customer_id,
        razorpay_subscription_id,
        trial_ends_at,
        created_at
    )
    SELECT
        id,
        email,
        password,
        subdomain,
        access_token,
        status,
        razorpay_customer_id,
        razorpay_subscription_id,
        trial_ends_at,
        created_at
    FROM users;
    DROP TABLE users;
    ALTER TABLE users_new RENAME TO users;
    COMMIT;
`;

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to SQLite database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        initDb();
    }
});

function initDb() {
    db.get(
        `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'`,
        (err, row) => {
            if (err) {
                console.error('Error reading users table schema:', err.message);
                return;
            }

            if (!row) {
                db.run(USERS_TABLE_SCHEMA, (createErr) => {
                    if (createErr) {
                        console.error('Error creating users table:', createErr.message);
                    } else {
                        console.log('Users table ready.');
                    }
                });
                return;
            }

            const currentSql = row.sql || '';
            const needsRebuild = [
                'payment_pending',
                'razorpay_payment_id',
                'razorpay_subscription_status',
                'trial_approved_at',
                'activated_at'
            ].some((fragment) => !currentSql.includes(fragment));

            if (!needsRebuild) {
                console.log('Users table ready.');
                return;
            }

            db.exec(USERS_TABLE_REBUILD, (migrationErr) => {
                if (migrationErr) {
                    console.error('Error migrating users table:', migrationErr.message);
                } else {
                    console.log('Users table migrated.');
                }
            });
        }
    );
}

module.exports = db;
