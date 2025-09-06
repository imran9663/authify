// utils/tokenUtils.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const generateTokens = (userId, appId = null) => {
    const payload = {
        userId,
        type: 'access'
    };

    if (appId) {
        payload.appId = appId;
    }

    const accessToken = jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    const refreshToken = jwt.sign(
        { userId, type: 'refresh' },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN }
    );

    return { accessToken, refreshToken };
};

const generateSecureToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

const generateAppCredentials = () => {
    const clientId = crypto.randomUUID();
    const clientSecret = crypto.randomBytes(64).toString('hex');
    const apiKey = crypto.randomBytes(32).toString('hex');

    return { clientId, clientSecret, apiKey };
};

module.exports = {
    generateTokens,
    generateSecureToken,
    generateAppCredentials
};
