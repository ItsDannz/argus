// Fixture: raw queries. Both of these build SQL out of whatever the client sent.
//
// The first lets the caller name the sort column; the second is a text predicate
// whose quotes are inside the string. Neither has a bound parameter anywhere.
const express = require('express');
const db = require('../db');

const router = express.Router();

router.get('/', (req, res) => {
  const column = req.query.sort;
  const sql = "SELECT id, subject FROM tickets ORDER BY " + column;
  db.query(sql, (err, rows) => res.json(rows));
});

router.get('/audit', (req, res) => {
  const actor = req.query.actor;
  const sql = "SELECT * FROM audit_log WHERE actor = '" + actor + "'";
  db.query(sql, (err, rows) => res.json(rows));
});

module.exports = router;
