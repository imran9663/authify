
==================================================
MULTI-APP AUTHENTICATION SYSTEM DOCUMENTATION
==================================================

OVERVIEW:
This is a comprehensive, production-ready authentication system built with Node.js and Express.js.
It provides secure user authentication and authorization for multiple applications.

KEY FEATURES:
============

1. USER AUTHENTICATION
   - Secure registration with email verification
   - Login with JWT tokens (access + refresh)
   - Password reset functionality
   - Two-factor authentication (TOTP)
   - Account lockout protection

2. SECURITY MEASURES
   - bcrypt password hashing
   - Rate limiting on all endpoints
   - Input validation and sanitization
   - CORS protection
   - Security headers with Helmet
   - Token-based authentication

3. MULTI-APP SUPPORT
   - OAuth 2.0 authorization flow
   - App registration and management
   - Client credentials authentication
   - Scoped permissions
   - API key management

4. ADMIN FEATURES
   - User management dashboard
   - App oversight and control
   - Role-based access control
   - System monitoring capabilities

INSTALLATION:
============

1. Install dependencies:
   npm install

2. Set up environment variables (.env):
   - Database connection string
   - JWT secrets (use strong random strings)
   - Email configuration
   - Frontend URL for CORS

3. Start the application:
   npm run dev (development)
   npm start (production)

API ENDPOINTS:
=============

AUTHENTICATION:
- POST /api/auth/register - Register new user
- POST /api/auth/login - User login
- POST /api/auth/refresh - Refresh access token
- POST /api/auth/logout - Logout from current device
- POST /api/auth/verify-email - Verify email address
- POST /api/auth/forgot-password - Request password reset
- POST /api/auth/reset-password - Reset password with token
- POST /api/auth/setup-2fa - Setup two-factor authentication
- POST /api/auth/verify-2fa - Verify and enable 2FA

USER MANAGEMENT:
- GET /api/user/profile - Get user profile
- PUT /api/user/profile - Update user profile
- PUT /api/user/change-password - Change password
- GET /api/user/sessions - Get active sessions
- DELETE /api/user/sessions/:id - Revoke session
- GET /api/user/all - Get all users (admin)
- PUT /api/user/:id/status - Update user status (admin)

APP MANAGEMENT:
- POST /api/apps - Create new application
- GET /api/apps - Get user's applications
- GET /api/apps/:id - Get specific application
- PUT /api/apps/:id - Update application
- DELETE /api/apps/:id - Delete application
- POST /api/apps/:id/regenerate-secret - Regenerate client secret
- GET /api/apps/oauth/authorize - OAuth authorization
- POST /api/apps/oauth/token - OAuth token exchange

SECURITY BEST PRACTICES:
=======================

1. PASSWORD SECURITY
   - Minimum 8 characters with complexity requirements
   - bcrypt hashing with high cost factor
   - No plaintext password storage

2. TOKEN SECURITY
   - Short-lived access tokens (15 minutes)
   - Longer refresh tokens (7 days)
   - Secure random token generation
   - Token rotation on refresh

3. ACCOUNT PROTECTION
   - Account lockout after failed attempts
   - Email verification requirement
   - Session tracking and management
   - Two-factor authentication support

4. API SECURITY
   - Rate limiting per IP address
   - Input validation on all endpoints
   - CORS configuration
   - Security headers
   - Error message sanitization

DEPLOYMENT CHECKLIST:
====================

1. Environment Configuration:
   ✓ Set strong JWT secrets
   ✓ Configure email service
   ✓ Set production database URL
   ✓ Configure CORS origins

2. Database Setup:
   ✓ Create MongoDB indexes
   ✓ Set up backup strategy
   ✓ Configure connection pooling

3. Security Configuration:
   ✓ Enable HTTPS in production
   ✓ Set secure cookie flags
   ✓ Configure rate limiting
   ✓ Review CORS settings

4. Monitoring:
   ✓ Set up error logging
   ✓ Monitor authentication events
   ✓ Track API usage
   ✓ Set up health checks

USAGE EXAMPLE:
=============

// Register a new user
const response = await fetch('/api/auth/register', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'SecurePass123!',
    firstName: 'John',
    lastName: 'Doe'
  })
});

// Login
const loginResponse = await fetch('/api/auth/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'SecurePass123!'
  })
});

const { accessToken, refreshToken } = await loginResponse.json();

// Use access token for authenticated requests
const profileResponse = await fetch('/api/user/profile', {
  headers: {
    'Authorization': `Bearer ${accessToken}`
  }
});

This system provides enterprise-grade authentication with multi-app support,
making it suitable for both single applications and complex multi-tenant environments.
*/