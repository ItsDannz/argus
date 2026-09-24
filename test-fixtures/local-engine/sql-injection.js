// Fixture: raw and concatenated SQL. Three lines here should be flagged, and the
// parameterised query at the bottom must NOT be.
const express = require('express');
const db = require('./db');

const router = express.Router();

// Vulnerable: string concatenation.
router.get('/user', (req, res) => {
  const userId = req.query.id;
  const sql = "SELECT id, email FROM users WHERE id = " + userId;
  db.query(sql, (err, rows) => res.json(rows));
});

// Vulnerable: template-literal interpolation.
router.get('/orders', (req, res) => {
  const status = req.query.status;
  const sql = `SELECT * FROM orders WHERE status = '${status}'`;
  db.query(sql, (err, rows) => res.json(rows));
});

// Vulnerable: concatenation around a QUOTED value.
//
// This route is the one that matters most, because it is the shape that
// dominates real code — every text comparison puts an apostrophe inside the
// string, and the quotes are what made it invisible. The two above are
// quote-free, which is why they kept passing while this one went unreported.
router.get('/search', (req, res) => {
  const name = req.query.name;
  const sql = "SELECT id, email FROM users WHERE name = '" + name + "'";
  db.query(sql, (err, rows) => res.json(rows));
});

// Safe: the value is bound as a parameter, so it can never be parsed as SQL.
router.get('/safe', (req, res) => {
  db.query('SELECT id, email FROM users WHERE id = ?', [req.query.id], (err, rows) =>
    res.json(rows),
  );
});

module.exports = router;
