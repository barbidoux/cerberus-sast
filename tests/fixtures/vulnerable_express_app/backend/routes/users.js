/**
 * Users Route - Contains SQL Injection vulnerabilities
 */

const express = require('express');
const router = express.Router();
const { sequelize } = require('../models/User');

// VULNERABILITY: CWE-89 - SQL Injection via query parameter (Line 11)
router.get('/search', async (req, res) => {
    const searchTerm = req.query.name;
    const query = `SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`;
    const users = await sequelize.query(query);
    res.json(users);
});

// VULNERABILITY: CWE-89 - SQL Injection via route parameter (Line 19)
router.get('/:id', async (req, res) => {
    const userId = req.params.id;
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    const user = await sequelize.query(query);
    res.json(user);
});

// VULNERABILITY: CWE-89 - SQL Injection via body parameter (Line 27)
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    const users = await sequelize.query(query);
    if (users.length > 0) {
        res.json({ success: true, user: users[0] });
    } else {
        res.status(401).json({ success: false });
    }
});

// VULNERABILITY: CWE-89 - SQL Injection in UPDATE (Line 38)
router.put('/:id', async (req, res) => {
    const userId = req.params.id;
    const { email } = req.body;
    const query = `UPDATE users SET email = '${email}' WHERE id = ${userId}`;
    await sequelize.query(query);
    res.json({ success: true });
});

// VULNERABILITY: CWE-89 - SQL Injection in DELETE (Line 47)
router.delete('/:id', async (req, res) => {
    const userId = req.params.id;
    const query = `DELETE FROM users WHERE id = ${userId}`;
    await sequelize.query(query);
    res.json({ success: true });
});

// VULNERABILITY: CWE-89 - SQL Injection via ORDER BY (Line 55)
router.get('/list', async (req, res) => {
    const sortBy = req.query.sort || 'id';
    const query = `SELECT * FROM users ORDER BY ${sortBy}`;
    const users = await sequelize.query(query);
    res.json(users);
});

// VULNERABILITY: CWE-79 - Stored XSS via profile bio (Line 63)
router.post('/:id/profile', async (req, res) => {
    const userId = req.params.id;
    const { bio } = req.body;
    // Store bio without sanitization
    const query = `UPDATE users SET bio = '${bio}' WHERE id = ${userId}`;
    await sequelize.query(query);
    res.json({ success: true });
});

// Safe example - Parameterized query (NOT a vulnerability)
router.get('/safe/:id', async (req, res) => {
    const userId = req.params.id;
    const user = await sequelize.query(
        'SELECT * FROM users WHERE id = ?',
        { replacements: [userId] }
    );
    res.json(user);
});

module.exports = router;
