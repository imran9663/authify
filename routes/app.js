// routes/app.js
const express = require('express');
const App = require('../models/App');
const User = require('../models/User');
const { generateAppCredentials } = require('../utils/tokenUtils');
const { requireRole, authenticateApp } = require('../middleware/auth');

const router = express.Router();

// Create new app
router.post('/', requireRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const { name, description, redirectUris, allowedOrigins, scopes } = req.body;

    const { clientId, clientSecret, apiKey } = generateAppCredentials();

    const app = new App({
      name,
      description,
      clientId,
      clientSecret,
      apiKey,
      redirectUris,
      allowedOrigins,
      scopes,
      owner: req.user._id
    });

    await app.save();

    res.status(201).json({
      success: true,
      data: app,
      message: 'App created successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'App creation failed',
      error: error.message
    });
  }
});

// Get user's apps
router.get('/', async (req, res) => {
  try {
    const apps = await App.find({ owner: req.user._id })
      .select('-clientSecret')
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      data: apps
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch apps'
    });
  }
});

// Get specific app details
router.get('/:appId', async (req, res) => {
  try {
    const { appId } = req.params;

    const app = await App.findOne({
      _id: appId,
      owner: req.user._id
    }).select('-clientSecret');

    if (!app) {
      return res.status(404).json({
        success: false,
        message: 'App not found'
      });
    }

    res.json({
      success: true,
      data: app
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch app details'
    });
  }
});

// Update app
router.put('/:appId', async (req, res) => {
  try {
    const { appId } = req.params;
    const { name, description, redirectUris, allowedOrigins, scopes } = req.body;

    const app = await App.findOneAndUpdate(
      { _id: appId, owner: req.user._id },
      { name, description, redirectUris, allowedOrigins, scopes },
      { new: true, runValidators: true }
    ).select('-clientSecret');

    if (!app) {
      return res.status(404).json({
        success: false,
        message: 'App not found'
      });
    }

    res.json({
      success: true,
      data: app,
      message: 'App updated successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'App update failed'
    });
  }
});

// Regenerate client secret
router.post('/:appId/regenerate-secret', async (req, res) => {
  try {
    const { appId } = req.params;

    const { clientSecret } = generateAppCredentials();

    const app = await App.findOneAndUpdate(
      { _id: appId, owner: req.user._id },
      { clientSecret },
      { new: true }
    ).select('-clientSecret');

    if (!app) {
      return res.status(404).json({
        success: false,
        message: 'App not found'
      });
    }

    res.json({
      success: true,
      data: {
        ...app.toObject(),
        clientSecret
      },
      message: 'Client secret regenerated successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to regenerate client secret'
    });
  }
});

// Delete app
router.delete('/:appId', async (req, res) => {
  try {
    const { appId } = req.params;

    const app = await App.findOneAndDelete({
      _id: appId,
      owner: req.user._id
    });

    if (!app) {
      return res.status(404).json({
        success: false,
        message: 'App not found'
      });
    }

    await User.updateMany(
      {},
      { $pull: { authorizedApps: { appId } } }
    );

    res.json({
      success: true,
      message: 'App deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'App deletion failed'
    });
  }
});

// OAuth endpoints
router.get('/oauth/authorize', async (req, res) => {
  try {
    const { client_id, redirect_uri, scope, state } = req.query;

    const app = await App.findOne({ clientId: client_id, isActive: true });
    if (!app) {
      return res.status(400).json({
        success: false,
        message: 'Invalid client_id'
      });
    }

    if (!app.redirectUris.includes(redirect_uri)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid redirect_uri'
      });
    }

    res.json({
      success: true,
      data: {
        app: {
          name: app.name,
          description: app.description
        },
        client_id,
        redirect_uri,
        scope: scope || 'read',
        state
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Authorization failed'
    });
  }
});

// Token endpoint
router.post('/oauth/token', authenticateApp, async (req, res) => {
  try {
    const { grant_type, code, redirect_uri } = req.body;

    if (grant_type !== 'authorization_code') {
      return res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: 'Only authorization_code grant type is supported'
      });
    }

    res.json({
      access_token: 'oauth_access_token_here',
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'read write'
    });
  } catch (error) {
    res.status(500).json({
      error: 'server_error',
      error_description: 'Token generation failed'
    });
  }
});

module.exports = router;