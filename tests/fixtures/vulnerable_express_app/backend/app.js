/**
 * Vulnerable Express.js Application
 * For SAST Testing - Cerberus
 */

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const usersRouter = require('./routes/users');
const productsRouter = require('./routes/products');
const adminRouter = require('./routes/admin');
const authMiddleware = require('./middleware/auth');

const app = express();

// VULNERABILITY: CWE-798 - Hardcoded Secret (Line 19)
const JWT_SECRET = "super_secret_key_123";

// VULNERABILITY: CWE-798 - Hardcoded API Key (Line 22)
const API_KEY = "sk-1234567890abcdef";

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Routes
app.use('/api/users', usersRouter);
app.use('/api/products', productsRouter);
app.use('/api/admin', authMiddleware, adminRouter);

// VULNERABILITY: CWE-79 - Reflected XSS (Line 34)
app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send(`<html><body><h1>Search results for: ${query}</h1></body></html>`);
});

// VULNERABILITY: CWE-79 - Reflected XSS via parameter (Line 40)
app.get('/welcome/:name', (req, res) => {
    const name = req.params.name;
    res.send(`<html><body><h1>Welcome, ${name}!</h1></body></html>`);
});

// VULNERABILITY: CWE-918 - SSRF via user-controlled URL (Line 46)
app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    const fetch = require('node-fetch');
    const response = await fetch(url);
    const data = await response.text();
    res.send(data);
});

// VULNERABILITY: CWE-94 - Code Injection via eval (Line 55)
app.post('/calculate', (req, res) => {
    const expression = req.body.expression;
    const result = eval(expression);
    res.json({ result });
});

// Login endpoint with JWT
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    // Simplified auth - in real app would check database
    if (username && password) {
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;
