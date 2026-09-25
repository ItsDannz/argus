// Negative control: the same operations as the vulnerable files, done safely.
//
// Nothing here should be flagged. It is the second half of every rule's test:
// a detector that reports `userById` has not found a vulnerability, it has found
// the word "SELECT", and the difference between those two is the whole product.
const crypto = require('crypto');

const db = require('../db');

function userById(id) {
  return db.query('SELECT id, email FROM users WHERE id = ?', [id]);
}

function greeting(name) {
  return `Hello, ${name}!`;
}

function checksum(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

module.exports = { userById, greeting, checksum };
