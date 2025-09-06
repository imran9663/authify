// models/App.js
const mongoose = require('mongoose');

const appSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
        unique: true
    },
    description: String,
    clientId: {
        type: String,
        required: true,
        unique: true
    },
    clientSecret: {
        type: String,
        required: true
    },
    redirectUris: [{
        type: String,
        required: true
    }],
    allowedOrigins: [{
        type: String,
        required: true
    }],
    scopes: [{
        name: String,
        description: String
    }],
    isActive: {
        type: Boolean,
        default: true
    },
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    apiKey: String,
    rateLimit: {
        requests: {
            type: Number,
            default: 1000
        },
        window: {
            type: Number,
            default: 3600000
        }
    }
}, {
    timestamps: true
});

appSchema.index({ clientId: 1 });
appSchema.index({ owner: 1 });

module.exports = mongoose.model('App', appSchema);