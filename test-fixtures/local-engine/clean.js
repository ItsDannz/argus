// Negative control: nothing in this file should be flagged by any rule.
const db = require('./db');

// Read at runtime, never a literal.
const apiKey = process.env.API_KEY;

async function getUser(id) {
  // Parameterised: the placeholder means the driver binds the value, so it can
  // never be parsed as SQL.
  const rows = await db.query('SELECT id, email FROM users WHERE id = ?', [id]);
  return rows[0];
}

function buildGreeting(name) {
  // A template literal, but with no SQL verb in it.
  return `Hello, ${name}!`;
}

module.exports = { getUser, buildGreeting, apiKey };
