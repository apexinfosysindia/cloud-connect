const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.resolve(__dirname, 'database.sqlite');

const USERS_TABLE_SCHEMA = `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        subdomain TEXT UNIQUE,
        access_token TEXT UNIQUE,
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

const USERS_REBUILD_COLUMNS = [
    'id',
    'email',
    'password',
    'subdomain',
    'access_token',
    'status',
    'razorpay_customer_id',
    'razorpay_subscription_id',
    'razorpay_payment_id',
    'razorpay_subscription_status',
    'trial_ends_at',
    'trial_approved_at',
    'activated_at',
    'created_at'
];

function selectExpressionForColumn(columnName, existingColumnsSet) {
    if (existingColumnsSet.has(columnName)) {
        return columnName;
    }

    if (columnName === 'status') {
        return `'payment_pending' AS ${columnName}`;
    }

    if (columnName === 'created_at') {
        return `CURRENT_TIMESTAMP AS ${columnName}`;
    }

    return `NULL AS ${columnName}`;
}

function buildUsersTableRebuildSql(existingColumns = []) {
    const existingColumnsSet = new Set(existingColumns);
    const targetColumns = USERS_REBUILD_COLUMNS.join(',\n        ');
    const selectColumns = USERS_REBUILD_COLUMNS
        .map((columnName) => selectExpressionForColumn(columnName, existingColumnsSet))
        .join(',\n        ');

    return `
    BEGIN TRANSACTION;
    CREATE TABLE users_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        subdomain TEXT UNIQUE,
        access_token TEXT UNIQUE,
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
        ${targetColumns}
    )
    SELECT
        ${selectColumns}
    FROM users;
    DROP TABLE users;
    ALTER TABLE users_new RENAME TO users;
    COMMIT;
    `;
}

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
            ].some((fragment) => !currentSql.includes(fragment)) ||
                currentSql.includes('access_token TEXT UNIQUE NOT NULL') ||
                currentSql.includes('subdomain TEXT UNIQUE NOT NULL');

            if (!needsRebuild) {
                console.log('Users table ready.');
                return;
            }

            db.all(`PRAGMA table_info(users)`, (infoErr, columns) => {
                if (infoErr) {
                    console.error('Error reading users table columns:', infoErr.message);
                    return;
                }

                const rebuildSql = buildUsersTableRebuildSql((columns || []).map((column) => column.name));
                db.exec(rebuildSql, (migrationErr) => {
                    if (migrationErr) {
                        console.error('Error migrating users table:', migrationErr.message);
                    } else {
                        console.log('Users table migrated.');
                    }
                });
            });
        }
    );
}

module.exports = db;
