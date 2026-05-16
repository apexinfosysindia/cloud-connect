/**
 * Alexa schema baseline assertion.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * DECISION RECORD (Phase 0 of the v2 Alexa rebuild)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * The previous Alexa attempt was reverted in commit 8114a54 ("revert: roll
 * back Alexa integration (linking broken in prod)"). The revert deleted the
 * code AND the migration files (003 + 004), but it did NOT alter the
 * production / dev SQLite schema. As of v2 kickoff, every database we have
 * inspected still contains:
 *
 *   schema_migrations row : (3, 'alexa_integration', '2026-04-21')
 *   tables                : alexa_auth_codes, alexa_command_queue,
 *                           alexa_entities, alexa_sync_snapshots, alexa_tokens
 *   users columns         : alexa_enabled, alexa_linked, alexa_security_pin
 *
 * The shape of these residual objects matches what the deleted code ALREADY
 * expected after the abandoned-v3 reconciliation in old migration 004.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * 2026-05-16 UPDATE — the "adopt-only" rule turned out to be wrong
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * The original Phase 2 plan was: "adopt the residue, do NOT write a new
 * migration to recreate it." That assumption held for the boxes we inspected
 * at v2 kickoff, but it failed on the very first production deploy — the
 * prod database was created clean (post-v1-revert) and never had the residue
 * to begin with. The boot-time check below threw on every restart, pm2 gave
 * up after 47 retries, and `cloud.apexinfosys.in` served 502 across the
 * board until we shipped migrations/003_alexa_baseline.sql.
 *
 * The new rule:
 *   migrations/003_alexa_baseline.sql recreates the full residue (5 tables
 *   + 3 users columns + the schema_migrations stamp) with IF NOT EXISTS on
 *   every DDL. On a v1-residue database, the migrator skips it because the
 *   (3, 'alexa_integration') row is already present. On a fresh database,
 *   it creates everything from scratch and stamps version 3.
 *
 * What this means for the next migration:
 *   The next v2 schema CHANGE is 004, not 003. Version 3 is now genuinely
 *   reserved across all environments, and the schema-baseline check below
 *   continues to enforce its presence.
 *
 * Why this file exists at all:
 *   The forward-only migrator never re-runs version 3, so if a future
 *   developer drops a column or table by hand, the codebase will silently
 *   diverge from prod again — the EXACT failure mode that ended v1.
 *   This module is loaded on boot from server.js after `db.ready` resolves,
 *   and asserts the expected shape. If anything is missing, it throws and
 *   the process exits before serving traffic.
 *
 * What this file is NOT:
 *   - It is NOT a migration. It does not CREATE anything. It only INSPECTS.
 *   - It does not validate column types or indexes. Only presence. Anything
 *     deeper belongs in a real migration.
 *
 * If you intentionally remove the Alexa integration (second revert), delete
 * this file at the same time as the lib/alexa/ tree.
 */

const REQUIRED_TABLES = [
    'alexa_auth_codes',
    'alexa_tokens',
    'alexa_entities',
    'alexa_command_queue',
    'alexa_sync_snapshots'
];

const REQUIRED_USER_COLUMNS = ['alexa_enabled', 'alexa_linked', 'alexa_security_pin'];

const REQUIRED_TOKENS_COLUMNS = [
    'access_token_hash',
    'refresh_token_hash',
    'expires_at',
    'lwa_access_token_encrypted',
    'lwa_refresh_token_encrypted',
    'lwa_expires_at',
    'lwa_scopes'
];

module.exports = function createSchemaBaseline({ dbAll, dbGet }) {
    async function listTableNames() {
        const rows = await dbAll(
            `SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'alexa_%'`
        );
        return new Set(rows.map((r) => r.name));
    }

    async function listColumnNames(table) {
        // PRAGMA table_info returns one row per column with a `name` field.
        const rows = await dbAll(`PRAGMA table_info(${table})`);
        return new Set(rows.map((r) => r.name));
    }

    async function assertBaseline() {
        const present = await listTableNames();
        const missingTables = REQUIRED_TABLES.filter((t) => !present.has(t));
        if (missingTables.length > 0) {
            throw new Error(
                `Alexa schema baseline check failed: missing tables [${missingTables.join(', ')}]. ` +
                    `See lib/alexa/schema-baseline.js for the decision record. ` +
                    `Either restore the schema or remove the Alexa integration.`
            );
        }

        const userCols = await listColumnNames('users');
        const missingUserCols = REQUIRED_USER_COLUMNS.filter((c) => !userCols.has(c));
        if (missingUserCols.length > 0) {
            throw new Error(
                `Alexa schema baseline check failed: users table missing columns ` +
                    `[${missingUserCols.join(', ')}]. See lib/alexa/schema-baseline.js.`
            );
        }

        const tokenCols = await listColumnNames('alexa_tokens');
        const missingTokenCols = REQUIRED_TOKENS_COLUMNS.filter((c) => !tokenCols.has(c));
        if (missingTokenCols.length > 0) {
            throw new Error(
                `Alexa schema baseline check failed: alexa_tokens missing columns ` +
                    `[${missingTokenCols.join(', ')}]. The previous attempt left a partial ` +
                    `schema in some environments — write a new migration to add the ` +
                    `missing columns rather than editing an old one.`
            );
        }

        // Confirm the schema_migrations row that records the adoption is present.
        // If absent, the residue may have been re-created by hand without going
        // through the migrator, which is suspicious and worth flagging.
        const stamp = await dbGet(
            `SELECT version, name FROM schema_migrations WHERE version = 3`
        );
        if (!stamp) {
            throw new Error(
                `Alexa schema baseline check failed: schema_migrations has no row ` +
                    `for version 3. The Alexa tables exist but the migrator does not ` +
                    `know about them. Insert (3, 'alexa_integration') manually after ` +
                    `verifying the schema, or drop the alexa_* tables and start fresh.`
            );
        }

        return { ok: true, adoptedVersion: stamp.version, adoptedName: stamp.name };
    }

    return { assertBaseline };
};

module.exports.REQUIRED_TABLES = REQUIRED_TABLES;
module.exports.REQUIRED_USER_COLUMNS = REQUIRED_USER_COLUMNS;
module.exports.REQUIRED_TOKENS_COLUMNS = REQUIRED_TOKENS_COLUMNS;
