// Fixture: raw and concatenated SQL. Two lines here should be flagged, and the
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

// Safe: the value is bound as a parameter, so it can never be parsed as SQL.
router.get('/safe', (req, res) => {
  db.query('SELECT id, email FROM users WHERE id = ?', [req.query.id], (err, rows) =>
    res.json(rows),
  );
});

module.exports = router;
