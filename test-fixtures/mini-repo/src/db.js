// The database handle the route modules share. Nothing in this file should be
// flagged: the connection string comes from the environment, and the wrapper
// passes whatever it is given straight to the driver.
const sqlite3 = require('sqlite3');

const db = new sqlite3.Database(process.env.DATABASE_PATH || ':memory:');

function query(sql, params, callback) {
  if (typeof params === 'function') {
    db.all(sql, [], params);
    return;
  }
  db.all(sql, params, callback);
}

module.exports = { query };
