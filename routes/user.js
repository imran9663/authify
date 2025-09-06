// routes/user.js
const express = require('express');
const User = require('../models/User');
const { requireRole } = require('../middleware/auth');

const router = express.Router();

// Get current user profile
router.get('/profile', async (req, res) => {
    try {
        const user = await User.findById(req.user._id)
            .select('-password -refreshTokens -twoFactorSecret')
            .populate('authorizedApps.appId', 'name description');

        res.json({
            success: true,
            data: user
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to fetch profile'
        });
    }
});

// Update profile
router.put('/profile', async (req, res) => {
    try {
        const { firstName, lastName } = req.body;

        const user = await User.findByIdAndUpdate(
            req.user._id,
            { firstName, lastName },
            { new: true, runValidators: true }
        ).select('-password -refreshTokens -twoFactorSecret');

        res.json({
            success: true,
            data: user,
            message: 'Profile updated successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Profile update failed'
        });
    }
});

// Change password
router.put('/change-password', async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'New password must be at least 8 characters long'
            });
        }

        const user = await User.findById(req.user._id);

        const isCurrentPasswordValid = await user.comparePassword(currentPassword);
        if (!isCurrentPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        user.password = newPassword;
        user.refreshTokens = [];
        await user.save();

        res.json({
            success: true,
            message: 'Password changed successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Password change failed'
        });
    }
});

// Get user sessions
router.get('/sessions', async (req, res) => {
    try {
        const user = await User.findById(req.user._id)
            .select('refreshTokens');

        const sessions = user.refreshTokens.map(rt => ({
            id: rt._id,
            deviceInfo: rt.deviceInfo,
            createdAt: rt.createdAt
        }));

        res.json({
            success: true,
            data: sessions
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to fetch sessions'
        });
    }
});
// Revoke specific session
router.delete('/sessions/:sessionId', async (req, res) => {
    try {
        const { sessionId } = req.params;

        await User.findByIdAndUpdate(req.user._id, {
            $pull: { refreshTokens: { _id: sessionId } }
        });

        res.json({
            success: true,
            message: 'Session revoked successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to revoke session'
        });
    }
});
// Admin: Get all users
router.get('/all', requireRole(['admin', 'superadmin']), async (req, res) => {
    try {
        const { page = 1, limit = 10, search = '' } = req.query;

        const query = search ? {
            $or: [
                { email: { $regex: search, $options: 'i' } },
                { firstName: { $regex: search, $options: 'i' } },
                { lastName: { $regex: search, $options: 'i' } }
            ]
        } : {};

        const users = await User.find(query)
            .select('-password -refreshTokens -twoFactorSecret')
            .limit(limit * 1)
            .skip((page - 1) * limit)
            .sort({ createdAt: -1 });

        const total = await User.countDocuments(query);

        res.json({
            success: true,
            data: {
                users,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / limit)
                }
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to fetch users'
        });
    }
});

// Admin: Update user status
router.put('/:userId/status', requireRole(['admin', 'superadmin']), async (req, res) => {
    try {
        const { userId } = req.params;
        const { isActive } = req.body;

        const user = await User.findByIdAndUpdate(
            userId,
            { isActive },
            { new: true }
        ).select('-password -refreshTokens -twoFactorSecret');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (!isActive) {
            user.refreshTokens = [];
            await user.save();
        }

        res.json({
            success: true,
            data: user,
            message: `User ${isActive ? 'activated' : 'deactivated'} successfully`
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to update user status'
        });
    }
});

module.exports = router;