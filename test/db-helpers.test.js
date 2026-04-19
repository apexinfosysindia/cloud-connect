const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const sqlite3 = require('sqlite3').verbose();
const createDbHelpers = require('../lib/db-helpers');

// In-memory SQLite instance so tests are hermetic and don't touch disk.
function makeDb() {
    return new sqlite3.Database(':memory:');
}

describe('dbTransaction', () => {
    let db;
    let helpers;

    before(async () => {
        db = makeDb();
        helpers = createDbHelpers(db);
        await helpers.dbRun(`CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT)`);
    });

    after(() => {
        db.close();
    });

    it('commits all statements when the callback resolves', async () => {
        await helpers.dbTransaction(async (tx) => {
            await tx.dbRun(`INSERT INTO kv (k, v) VALUES (?, ?)`, ['a', '1']);
            await tx.dbRun(`INSERT INTO kv (k, v) VALUES (?, ?)`, ['b', '2']);
        });

        const rows = await helpers.dbAll(`SELECT k, v FROM kv ORDER BY k`);
        assert.deepEqual(rows, [
            { k: 'a', v: '1' },
            { k: 'b', v: '2' }
        ]);
    });

    it('rolls back all statements when the callback throws', async () => {
        await assert.rejects(
            helpers.dbTransaction(async (tx) => {
                await tx.dbRun(`INSERT INTO kv (k, v) VALUES (?, ?)`, ['c', '3']);
                throw new Error('boom');
            }),
            /boom/
        );

        const row = await helpers.dbGet(`SELECT v FROM kv WHERE k = ?`, ['c']);
        assert.equal(row, undefined, 'row c should have been rolled back');
    });

    it('rolls back when a statement fails (constraint violation)', async () => {
        // 'a' already exists from the first test → PK violation.
        await assert.rejects(
            helpers.dbTransaction(async (tx) => {
                await tx.dbRun(`INSERT INTO kv (k, v) VALUES (?, ?)`, ['d', '4']);
                await tx.dbRun(`INSERT INTO kv (k, v) VALUES (?, ?)`, ['a', 'dup']);
            })
        );

        const rowD = await helpers.dbGet(`SELECT v FROM kv WHERE k = ?`, ['d']);
        assert.equal(rowD, undefined, 'row d should have been rolled back');
        const rowA = await helpers.dbGet(`SELECT v FROM kv WHERE k = ?`, ['a']);
        assert.equal(rowA.v, '1', 'row a must still have its original value');
    });

    it('returns the callback result on success', async () => {
        const result = await helpers.dbTransaction(async (tx) => {
            await tx.dbRun(`INSERT INTO kv (k, v) VALUES (?, ?)`, ['e', '5']);
            return 42;
        });
        assert.equal(result, 42);
    });

    it('serializes concurrent transactions — no interleaving', async () => {
        // Two concurrent txs that both read then write the same key. Without
        // serialization the second read would see the first write's
        // intermediate state. With serialization, one finishes fully before
        // the other starts, and the final count is the sum.
        await helpers.dbRun(`INSERT INTO kv (k, v) VALUES (?, ?)`, ['counter', '0']);

        const bump = () =>
            helpers.dbTransaction(async (tx) => {
                const row = await tx.dbGet(`SELECT v FROM kv WHERE k = ?`, ['counter']);
                const next = String(Number(row.v) + 1);
                await tx.dbRun(`UPDATE kv SET v = ? WHERE k = ?`, [next, 'counter']);
            });

        await Promise.all([bump(), bump(), bump(), bump(), bump()]);

        const final = await helpers.dbGet(`SELECT v FROM kv WHERE k = ?`, ['counter']);
        assert.equal(final.v, '5', 'all five bumps must be serialized');
    });
});
