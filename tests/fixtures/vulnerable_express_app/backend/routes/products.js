/**
 * Products Route - Contains XSS and SSRF vulnerabilities
 */

const express = require('express');
const router = express.Router();
const fetch = require('node-fetch');
const { sequelize } = require('../models/User');

// VULNERABILITY: CWE-89 - SQL Injection in product search (Line 12)
router.get('/search', async (req, res) => {
    const { category, minPrice, maxPrice } = req.query;
    const query = `SELECT * FROM products WHERE category = '${category}' AND price BETWEEN ${minPrice} AND ${maxPrice}`;
    const products = await sequelize.query(query);
    res.json(products);
});

// VULNERABILITY: CWE-79 - XSS in product description rendering (Line 20)
router.get('/:id/render', async (req, res) => {
    const productId = req.params.id;
    const [product] = await sequelize.query(`SELECT * FROM products WHERE id = ${productId}`);
    if (product) {
        res.send(`
            <html>
                <body>
                    <h1>${product.name}</h1>
                    <p>${product.description}</p>
                </body>
            </html>
        `);
    } else {
        res.status(404).send('Product not found');
    }
});

// VULNERABILITY: CWE-918 - SSRF via product image URL (Line 36)
router.post('/import-image', async (req, res) => {
    const { imageUrl } = req.body;
    const response = await fetch(imageUrl);
    const imageBuffer = await response.buffer();
    // Process image...
    res.json({ success: true, size: imageBuffer.length });
});

// VULNERABILITY: CWE-918 - SSRF via webhook URL (Line 45)
router.post('/webhook', async (req, res) => {
    const { webhookUrl, payload } = req.body;
    await fetch(webhookUrl, {
        method: 'POST',
        body: JSON.stringify(payload),
        headers: { 'Content-Type': 'application/json' }
    });
    res.json({ success: true });
});

// VULNERABILITY: CWE-94 - Code Injection via template (Line 56)
router.post('/format-price', (req, res) => {
    const { template, price } = req.body;
    // Dangerous: allows arbitrary code execution
    const formatFn = new Function('price', `return ${template}`);
    const formatted = formatFn(price);
    res.json({ formatted });
});

// VULNERABILITY: CWE-79 - XSS in review content (Line 65)
router.post('/:id/reviews', async (req, res) => {
    const productId = req.params.id;
    const { content, rating } = req.body;
    // Content stored without sanitization, rendered as HTML
    await sequelize.query(
        `INSERT INTO reviews (product_id, content, rating) VALUES (${productId}, '${content}', ${rating})`
    );
    res.json({ success: true });
});

// VULNERABILITY: CWE-89 - SQL Injection in bulk delete (Line 76)
router.delete('/bulk', async (req, res) => {
    const { ids } = req.body;
    const idList = ids.join(',');
    const query = `DELETE FROM products WHERE id IN (${idList})`;
    await sequelize.query(query);
    res.json({ success: true });
});

module.exports = router;
