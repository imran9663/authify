const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    password: {
        type: String,
        required: true,
        minlength: 8
    },
    firstName: {
        type: String,
        required: true,
        trim: true,
        maxlength: 50
    },
    lastName: {
        type: String,
        required: true,
        trim: true,
        maxlength: 50
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'superadmin'],
        default: 'user'
    },
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    emailVerificationToken: String,
    passwordResetToken: String,
    passwordResetExpires: Date,
    twoFactorSecret: String,
    isTwoFactorEnabled: {
        type: Boolean,
        default: false
    },
    refreshTokens: [{
        token: String,
        deviceInfo: String,
        createdAt: {
            type: Date,
            default: Date.now
        }
    }],
    authorizedApps: [{
        appId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'App'
        },
        permissions: [String],
        authorizedAt: {
            type: Date,
            default: Date.now
        }
    }],
    lastLogin: Date,
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: Date,
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ emailVerificationToken: 1 });
userSchema.index({ passwordResetToken: 1 });

// Virtual for account lock status
userSchema.virtual('isLocked').get(function () {
    return !!(this.lockUntil && this.lockUntil > Date.now());
});
// Pre-save middleware to hash password
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    try {
        const salt = await bcrypt.genSalt(parseInt(process.env.BCRYPT_ROUNDS));
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Method to compare password
userSchema.methods.comparePassword = async function (candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

// Method to handle failed login attempts
userSchema.methods.incLoginAttempts = function () {
    if (this.lockUntil && this.lockUntil < Date.now()) {
        return this.updateOne({
            $unset: { lockUntil: 1 },
            $set: { loginAttempts: 1 }
        });
    }

    const updates = { $inc: { loginAttempts: 1 } };

    if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
        updates.$set = {
            lockUntil: Date.now() + 2 * 60 * 60 * 1000 // Lock for 2 hours
        };
    }

    return this.updateOne(updates);
};

module.exports = mongoose.model('User', userSchema);
