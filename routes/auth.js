
// routes/auth.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const User = require('../models/User');
const { registerValidation, loginValidation } = require('../middleware/validation');
const { generateTokens, generateSecureToken } = require('../utils/tokenUtils');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Email transporter
const transporter = nodemailer.createTransporter({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Register
router.post('/register', registerValidation, async (req, res) => {
    try {
        const { email, password, firstName, lastName } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User already exists with this email'
            });
        }

        const emailVerificationToken = generateSecureToken();

        const user = new User({
            email,
            password,
            firstName,
            lastName,
            emailVerificationToken
        });

        await user.save();

        const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${emailVerificationToken}`;

        await transporter.sendMail({
            to: email,
            subject: 'Verify Your Email Address',
            html: `
        <h1>Welcome ${firstName}!</h1>
        <p>Please verify your email address by clicking the link below:</p>
        <a href="${verificationUrl}">${verificationUrl}</a>
        <p>This link will expire in 24 hours.</p>
      `
        });

        res.status(201).json({
            success: true,
            message: 'User registered successfully. Please check your email for verification.'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Registration failed',
            error: error.message
        });
    }
});

// Login
router.post('/login', loginValidation, async (req, res) => {
    try {
        const { email, password, twoFactorCode, deviceInfo } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        if (user.isLocked) {
            return res.status(423).json({
                success: false,
                message: 'Account is temporarily locked due to too many failed login attempts'
            });
        }

        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            await user.incLoginAttempts();
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        if (!user.isEmailVerified) {
            return res.status(401).json({
                success: false,
                message: 'Please verify your email before logging in'
            });
        }

        if (user.isTwoFactorEnabled) {
            if (!twoFactorCode) {
                return res.status(200).json({
                    success: false,
                    message: 'Two-factor authentication required',
                    requiresTwoFactor: true
                });
            }

            const verified = speakeasy.totp.verify({
                secret: user.twoFactorSecret,
                encoding: 'base32',
                token: twoFactorCode
            });

            if (!verified) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid two-factor authentication code'
                });
            }
        }

        const { accessToken, refreshToken } = generateTokens(user._id);

        user.refreshTokens.push({
            token: refreshToken,
            deviceInfo: deviceInfo || 'Unknown device'
        });

        user.lastLogin = new Date();
        user.loginAttempts = 0;
        user.lockUntil = undefined;

        await user.save();

        res.json({
            success: true,
            message: 'Login successful',
            data: {
                user: {
                    id: user._id,
                    email: user.email,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    role: user.role,
                    isTwoFactorEnabled: user.isTwoFactorEnabled
                },
                accessToken,
                refreshToken
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Login failed',
            error: error.message
        });
    }
});

// Refresh token
router.post('/refresh', async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(401).json({
                success: false,
                message: 'Refresh token required'
            });
        }

        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

        const user = await User.findById(decoded.userId);
        if (!user || !user.refreshTokens.some(rt => rt.token === refreshToken)) {
            return res.status(401).json({
                success: false,
                message: 'Invalid refresh token'
            });
        }

        const { accessToken, refreshToken: newRefreshToken } = generateTokens(user._id);

        user.refreshTokens = user.refreshTokens.filter(rt => rt.token !== refreshToken);
        user.refreshTokens.push({
            token: newRefreshToken,
            deviceInfo: 'Token refresh'
        });

        await user.save();

        res.json({
            success: true,
            data: {
                accessToken,
                refreshToken: newRefreshToken
            }
        });
    } catch (error) {
        res.status(401).json({
            success: false,
            message: 'Token refresh failed'
        });
    }
});

// Logout
router.post('/logout', authenticateToken, async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (refreshToken) {
            await User.findByIdAndUpdate(req.user._id, {
                $pull: { refreshTokens: { token: refreshToken } }
            });
        }

        res.json({
            success: true,
            message: 'Logged out successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Logout failed'
        });
    }
});

// Verify email
router.post('/verify-email', async (req, res) => {
    try {
        const { token } = req.body;

        const user = await User.findOne({ emailVerificationToken: token });
        if (!user) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired verification token'
            });
        }

        user.isEmailVerified = true;
        user.emailVerificationToken = undefined;
        await user.save();

        res.json({
            success: true,
            message: 'Email verified successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Email verification failed'
        });
    }
});

// Forgot password
router.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.json({
                success: true,
                message: 'If the email exists, a password reset link has been sent'
            });
        }

        const resetToken = generateSecureToken();
        user.passwordResetToken = resetToken;
        user.passwordResetExpires = Date.now() + 3600000; // 1 hour

        await user.save();

        const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

        await transporter.sendMail({
            to: email,
            subject: 'Password Reset Request',
            html: `
        <h1>Password Reset</h1>
        <p>You requested a password reset. Click the link below to reset your password:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `
        });

        res.json({
            success: true,
            message: 'If the email exists, a password reset link has been sent'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Password reset failed'
        });
    }
});

// Reset password
router.post('/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long'
            });
        }

        const user = await User.findOne({
            passwordResetToken: token,
            passwordResetExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired reset token'
            });
        }

        user.password = newPassword;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        user.refreshTokens = [];

        await user.save();

        res.json({
            success: true,
            message: 'Password reset successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Password reset failed'
        });
    }
});

// Setup 2FA
router.post('/setup-2fa', authenticateToken, async (req, res) => {
    try {
        const user = req.user;

        const secret = speakeasy.generateSecret({
            name: `Auth System (${user.email})`,
            issuer: 'Multi-App Auth'
        });

        const qrCode = await QRCode.toDataURL(secret.otpauth_url);

        res.json({
            success: true,
            data: {
                secret: secret.base32,
                qrCode
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: '2FA setup failed'
        });
    }
});

// Verify and enable 2FA
router.post('/verify-2fa', authenticateToken, async (req, res) => {
    try {
        const { secret, token } = req.body;

        const verified = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token,
            window: 1
        });

        if (!verified) {
            return res.status(400).json({
                success: false,
                message: 'Invalid verification code'
            });
        }

        const user = await User.findById(req.user._id);
        user.twoFactorSecret = secret;
        user.isTwoFactorEnabled = true;

        await user.save();

        res.json({
            success: true,
            message: '2FA enabled successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: '2FA verification failed'
        });
    }
});

module.exports = router;