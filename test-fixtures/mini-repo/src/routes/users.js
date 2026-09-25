// Fixture: SQL injection through string assembly.
//
// Two vulnerable lines, both Critical, and the fixed form of the same query at
// the bottom of the file. The second one is the shape real code actually has —
// an apostrophe inside a double-quoted string — and is the line the detector
// missed for two phases (see the note in engine/local/rules.ts).
const express = require('express');
const db = require('../db');

const router = express.Router();

router.get('/:id', (req, res) => {
  const userId = req.params.id;
  const sql = "SELECT id, email FROM users WHERE id = " + userId;
  db.query(sql, (err, rows) => res.json(rows));
});

router.get('/by-name/:name', (req, res) => {
  const name = req.params.name;
  const sql = `SELECT id, email FROM users WHERE name = '${name}'`;
  db.query(sql, (err, rows) => res.json(rows));
});

// Safe: the value is bound as a parameter, so it can never be parsed as SQL.
router.get('/safe/:id', (req, res) => {
  db.query('SELECT id, email FROM users WHERE id = ?', [req.params.id], (err, rows) =>
    res.json(rows),
  );
});

module.exports = router;
