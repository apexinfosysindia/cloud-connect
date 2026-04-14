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

    return { dbGet, dbRun, dbAll };
};
