module.exports = function (db) {
    function dbGet(query, params = []) {
        return new Promise((resolve, reject) => {
            db.get(query, params, (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    }

    function dbRun(query, params = []) {
        return new Promise((resolve, reject) => {
            db.run(query, params, function onRun(err) {
                if (err) reject(err);
                else resolve(this);
            });
        });
    }

    function dbAll(query, params = []) {
        return new Promise((resolve, reject) => {
            db.all(query, params, (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }

    // --- dbTransaction ---
    // Wraps a function in BEGIN IMMEDIATE / COMMIT / ROLLBACK. Because the
    // sqlite3 driver shares a single connection, concurrent requests would
    // otherwise interleave statements inside our transaction scope. We
    // therefore serialize transactions through a JS-level chain so only one
    // transaction runs at a time. Reads outside a transaction still run
    // concurrently against the WAL snapshot.
    //
    // Usage:
    //   await dbTransaction(async ({ dbRun, dbGet, dbAll }) => {
    //       await dbRun('UPDATE ...');
    //       await dbRun('INSERT ...');
    //   });
    //
    // The callback receives the same helper functions so call sites don't
    // need to import anything extra. If the callback throws, ROLLBACK runs
    // and the original error is re-thrown. If COMMIT fails, ROLLBACK is
    // attempted and the COMMIT error is thrown.
    let txChain = Promise.resolve();

    function dbTransaction(fn) {
        const run = async () => {
            await dbRun('BEGIN IMMEDIATE');
            let result;
            try {
                result = await fn({ dbGet, dbRun, dbAll });
            } catch (err) {
                try {
                    await dbRun('ROLLBACK');
                } catch (rollbackErr) {
                    // Surface the original error; log rollback failure.
                    console.error('ROLLBACK failed after transaction error:', rollbackErr.message);
                }
                throw err;
            }
            try {
                await dbRun('COMMIT');
            } catch (commitErr) {
                try {
                    await dbRun('ROLLBACK');
                } catch (rollbackErr) {
                    console.error('ROLLBACK failed after COMMIT error:', rollbackErr.message);
                }
                throw commitErr;
            }
            return result;
        };

        const next = txChain.then(run, run);
        // Swallow rejection on the chain itself so one failed tx doesn't
        // poison the queue for subsequent callers.
        txChain = next.then(
            () => undefined,
            () => undefined
        );
        return next;
    }

    return { dbGet, dbRun, dbAll, dbTransaction };
};
