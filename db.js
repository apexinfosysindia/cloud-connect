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

const DEVICES_TABLE_SCHEMA = `
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        device_uid TEXT NOT NULL,
        device_name TEXT,
        hostname TEXT,
        local_ips TEXT,
        ssh_port INTEGER DEFAULT 22,
        remote_user TEXT DEFAULT 'root',
        tunnel_host TEXT,
        tunnel_port INTEGER,
        addon_version TEXT,
        agent_state TEXT,
        device_token_hash TEXT NOT NULL UNIQUE,
        last_seen_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (user_id, device_uid),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
`;

const DEVICE_LOGS_TABLE_SCHEMA = `
    CREATE TABLE IF NOT EXISTS device_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        level TEXT NOT NULL DEFAULT 'info',
        event_type TEXT NOT NULL,
        message TEXT NOT NULL,
        payload TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    )
`;

const ADMIN_CONNECT_SESSIONS_TABLE_SCHEMA = `
    CREATE TABLE IF NOT EXISTS admin_connect_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        admin_email TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        used_at DATETIME,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    )
`;

const ADMIN_ACCESS_LOGS_TABLE_SCHEMA = `
    CREATE TABLE IF NOT EXISTS admin_access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER,
        admin_email TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
    )
`;

const DEVICE_SSH_SESSIONS_TABLE_SCHEMA = `
    CREATE TABLE IF NOT EXISTS device_ssh_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        admin_email TEXT NOT NULL,
        reason TEXT,
        ssh_username TEXT NOT NULL,
        public_key TEXT NOT NULL,
        public_key_fingerprint TEXT,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'active', 'expired', 'revoked', 'failed')),
        expires_at DATETIME NOT NULL,
        issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        activated_at DATETIME,
        revoked_at DATETIME,
        last_error TEXT,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    )
`;

const DEVICE_SCHEMA_STATEMENTS = [
    DEVICES_TABLE_SCHEMA,
    DEVICE_LOGS_TABLE_SCHEMA,
    ADMIN_CONNECT_SESSIONS_TABLE_SCHEMA,
    ADMIN_ACCESS_LOGS_TABLE_SCHEMA,
    DEVICE_SSH_SESSIONS_TABLE_SCHEMA,
    'CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen_at)',
    'CREATE INDEX IF NOT EXISTS idx_device_logs_device_created ON device_logs(device_id, created_at DESC)',
    'CREATE INDEX IF NOT EXISTS idx_admin_connect_sessions_expiry ON admin_connect_sessions(expires_at)',
    'CREATE INDEX IF NOT EXISTS idx_admin_access_logs_device_created ON admin_access_logs(device_id, created_at DESC)',
    'CREATE INDEX IF NOT EXISTS idx_device_ssh_sessions_device_status_expiry ON device_ssh_sessions(device_id, status, expires_at)',
    'CREATE INDEX IF NOT EXISTS idx_device_ssh_sessions_expiry ON device_ssh_sessions(expires_at)'
];

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

function runStatementsSequentially(statements, index, done) {
    if (index >= statements.length) {
        done(null);
        return;
    }

    db.run(statements[index], (error) => {
        if (error) {
            done(error);
            return;
        }

        runStatementsSequentially(statements, index + 1, done);
    });
}

function initDeviceTables() {
    runStatementsSequentially(DEVICE_SCHEMA_STATEMENTS, 0, (error) => {
        if (error) {
            console.error('Error preparing device tables:', error.message);
        } else {
            console.log('Device fleet tables ready.');
        }
    });
}

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to SQLite database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        db.serialize(() => {
            db.run('PRAGMA foreign_keys = ON');
            initDb();
        });
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
                        initDeviceTables();
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
                initDeviceTables();
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
                        initDeviceTables();
                    }
                });
            });
        }
    );
}

module.exports = db;
