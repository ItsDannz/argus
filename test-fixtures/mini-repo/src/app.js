// Negative control: ordinary wiring. Nothing in this file should be flagged.
const express = require('express');

const users = require('./routes/users');
const search = require('./routes/search');

const app = express();
app.use(express.json());

app.use('/users', users);
app.use('/search', search);

app.get('/health', (req, res) => res.json({ ok: true }));

module.exports = app;
