// middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const App = require('../models/App');

const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Access token required'
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const user = await User.findById(decoded.userId)
            .select('-password -refreshTokens');

        if (!user || !user.isActive) {
            return res.status(401).json({
                success: false,
                message: 'Invalid token or user not found'
            });
        }

        req.user = user;
        req.tokenData = decoded;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Token expired',
                code: 'TOKEN_EXPIRED'
            });
        }

        return res.status(401).json({
            success: false,
            message: 'Invalid token'
        });
    }
};

const authenticateApp = async (req, res, next) => {
    try {
        const clientId = req.headers['x-client-id'];
        const clientSecret = req.headers['x-client-secret'];

        if (!clientId || !clientSecret) {
            return res.status(401).json({
                success: false,
                message: 'Client credentials required'
            });
        }

        const app = await App.findOne({
            clientId,
            clientSecret,
            isActive: true
        });

        if (!app) {
            return res.status(401).json({
                success: false,
                message: 'Invalid client credentials'
            });
        }

        req.app = app;
        next();
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Authentication error'
        });
    }
};

const requireRole = (roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: 'Insufficient permissions'
            });
        }

        next();
    };
};

module.exports = {
    authenticateToken,
    authenticateApp,
    requireRole
};