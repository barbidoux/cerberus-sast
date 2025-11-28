/**
 * Authentication Middleware - Contains Hardcoded Secrets
 */

const jwt = require('jsonwebtoken');

// VULNERABILITY: CWE-798 - Hardcoded JWT Secret (Line 9)
const JWT_SECRET = "my_super_secret_jwt_key_2024";

// VULNERABILITY: CWE-798 - Hardcoded Admin Password (Line 12)
const ADMIN_PASSWORD = "admin123!@#";

// VULNERABILITY: CWE-798 - Hardcoded API Token (Line 15)
const SERVICE_API_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret";

const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ error: 'No authorization header' });
    }

    const token = authHeader.split(' ')[1];

    // Check for admin API token first
    if (token === SERVICE_API_TOKEN) {
        req.user = { role: 'admin', username: 'service' };
        return next();
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Helper to check admin access
const requireAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        // VULNERABILITY: Information disclosure - reveals admin check logic
        res.status(403).json({
            error: 'Admin access required',
            hint: `Use password: ${ADMIN_PASSWORD.substring(0, 3)}***`
        });
    }
};

module.exports = authMiddleware;
module.exports.requireAdmin = requireAdmin;
module.exports.JWT_SECRET = JWT_SECRET;
