# 🔐 Authify - Multi-App Authentication System

**Authify** is a comprehensive, production-ready authentication system built with Node.js and Express.js. It provides secure user authentication and authorization that can be used by multiple applications, making it perfect for microservices, multi-tenant applications, or any system requiring centralized authentication.

![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=node.js&logoColor=white)
![Express.js](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)

## 📋 Table of Contents

- [🌟 Features](#-features)
- [🏗️ System Architecture](#️-system-architecture)
- [📦 Installation](#-installation)
- [⚙️ Configuration](#️-configuration)
- [🚀 Getting Started](#-getting-started)
- [🔑 Authentication Flow](#-authentication-flow)
- [📚 API Documentation](#-api-documentation)
- [🛡️ Security Features](#️-security-features)
- [💻 Usage Examples](#-usage-examples)
- [🔧 Advanced Configuration](#-advanced-configuration)
- [🚀 Deployment](#-deployment)
- [🤝 Contributing](#-contributing)

## 🌟 Features

### 🔐 **Core Authentication**
- ✅ **User Registration** with email verification
- ✅ **Secure Login** with JWT tokens
- ✅ **Password Reset** functionality
- ✅ **Two-Factor Authentication (2FA)** with QR codes
- ✅ **Session Management** across multiple devices
- ✅ **Account Lockout** protection against brute force attacks

### 🏢 **Multi-App Support**
- ✅ **OAuth 2.0 Flow** for third-party integrations
- ✅ **App Registration** and management
- ✅ **Client Credentials** for API authentication
- ✅ **Scoped Permissions** for granular access control
- ✅ **API Key Management**

### 🛡️ **Security Features**
- ✅ **bcrypt Password Hashing**
- ✅ **Rate Limiting** on all endpoints
- ✅ **Input Validation** and sanitization
- ✅ **CORS Protection**
- ✅ **Security Headers** with Helmet.js
- ✅ **Token Rotation** for enhanced security

### 👥 **Admin Features**
- ✅ **User Management** dashboard
- ✅ **App Oversight** and control
- ✅ **Role-Based Access Control**
- ✅ **System Monitoring** capabilities

## 🏗️ System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend App  │    │  Mobile App     │    │  Third-party    │
│                 │    │                 │    │  Application    │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼──────────────┐
                    │                            │
                    │       AUTHIFY API          │
                    │                            │
                    │  ┌──────────────────────┐  │
                    │  │  Authentication      │  │
                    │  │  - Login/Register    │  │
                    │  │  - 2FA               │  │
                    │  │  - Password Reset    │  │
                    │  └──────────────────────┘  │
                    │                            │
                    │  ┌──────────────────────┐  │
                    │  │  User Management     │  │
                    │  │  - Profile           │  │
                    │  │  - Sessions          │  │
                    │  │  - Permissions       │  │
                    │  └──────────────────────┘  │
                    │                            │
                    │  ┌──────────────────────┐  │
                    │  │  App Management      │  │
                    │  │  - OAuth 2.0         │  │
                    │  │  - API Keys          │  │
                    │  │  - Scopes            │  │
                    │  └──────────────────────┘  │
                    └─────────────┬──────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │        MongoDB             │
                    │                            │
                    │  ┌─────────┐ ┌──────────┐  │
                    │  │  Users  │ │   Apps   │  │
                    │  └─────────┘ └──────────┘  │
                    └────────────────────────────┘
```

## 📦 Installation

### Prerequisites

Before you begin, ensure you have the following installed:
- **Node.js** (v14 or higher) - [Download here](https://nodejs.org/)
- **MongoDB** (v4.4 or higher) - [Download here](https://www.mongodb.com/try/download/community)
- **npm** or **yarn** package manager

### Step 1: Clone or Create Project

Create a new directory for your project:

```bash
mkdir authify-system
cd authify-system
```

### Step 2: Initialize Project

```bash
npm init -y
```

### Step 3: Install Dependencies

```bash
npm install express bcryptjs jsonwebtoken express-rate-limit helmet cors mongoose joi dotenv express-validator speakeasy qrcode nodemailer crypto
```

### Step 4: Install Development Dependencies

```bash
npm install --save-dev nodemon
```

### Step 5: Create Project Structure

Create the following directory structure:

```
authify-system/
├── models/
│   ├── User.js
│   └── App.js
├── routes/
│   ├── auth.js
│   ├── user.js
│   └── app.js
├── middleware/
│   ├── auth.js
│   ├── validation.js
│   └── errorHandler.js
├── utils/
│   └── tokenUtils.js
├── .env
├── server.js
├── package.json
└── README.md
```

### Step 6: Copy System Files

Copy all the code from the provided system files into their respective locations according to the structure above.

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in your project root and configure the following variables:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Database Configuration
MONGODB_URI=mongodb://localhost:27017/authify

# JWT Configuration
JWT_SECRET=your_super_secure_jwt_secret_key_here_minimum_32_characters_long
JWT_REFRESH_SECRET=your_super_secure_refresh_secret_key_here_minimum_32_characters_long
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Security Configuration
BCRYPT_ROUNDS=12

# Email Configuration (for verification and password reset)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password

# Frontend Configuration
FRONTEND_URL=http://localhost:3000
```

### 📧 Email Setup (Gmail Example)

1. **Enable 2-Step Verification** in your Gmail account
2. **Generate an App Password**:
   - Go to Google Account settings
   - Security → 2-Step Verification → App passwords
   - Select "Mail" and generate password
   - Use this password in `EMAIL_PASS`

## 🚀 Getting Started

### Step 1: Start MongoDB

Make sure MongoDB is running on your system:

```bash
# On macOS with Homebrew
brew services start mongodb-community

# On Windows
# Start MongoDB service from Services panel

# On Ubuntu
sudo systemctl start mongod
```

### Step 2: Update package.json Scripts

Add the following scripts to your `package.json`:

```json
{
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "echo \"Error: no test specified\" && exit 1"
  }
}
```

### Step 3: Start the Application

```bash
# Development mode with auto-restart
npm run dev

# Production mode
npm start
```

You should see:
```
Server running on port 3000
Connected to MongoDB
```

### Step 4: Test the API

Test if the server is running:

```bash
curl http://localhost:3000/health
```

Expected response:
```json
{
  "status": "OK",
  "timestamp": "2023-12-07T10:30:00.000Z"
}
```

## 🔑 Authentication Flow

### Understanding the Authentication Process

Authify uses a **dual-token system** for security:

1. **Access Token** (short-lived, 15 minutes)
   - Used for API requests
   - Contains user information
   - Expires quickly for security

2. **Refresh Token** (long-lived, 7 days)
   - Used to get new access tokens
   - Stored securely in database
   - Can be revoked

### Visual Flow Diagram

```
┌─────────────┐
│   User      │
│ Registration│
└──────┬──────┘
       │
       ▼
┌─────────────┐    ┌──────────────┐
│   Email     │────│  Click Link  │
│ Verification│    │  in Email    │
└──────┬──────┘    └──────┬───────┘
       │                  │
       └──────────────────┘
                          │
                          ▼
┌──────────────────────────────────┐
│           User Login             │
│                                  │
│  Email + Password + 2FA (optional)│
└─────────────┬────────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│       Token Generation          │
│                                 │
│  Access Token + Refresh Token   │
└─────────────┬───────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│      Make API Requests          │
│                                 │
│  Authorization: Bearer <token>  │
└─────────────┬───────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│     Token Expiration?           │
│                                 │
│  Use Refresh Token for new one  │
└─────────────────────────────────┘
```

## 📚 API Documentation

### Authentication Endpoints

#### 1. Register User

**POST** `/api/auth/register`

Register a new user account.

```javascript
// Request
{
  "email": "john.doe@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe"
}

// Response
{
  "success": true,
  "message": "User registered successfully. Please check your email for verification."
}
```

#### 2. Verify Email

**POST** `/api/auth/verify-email`

Verify user email address with token from email.

```javascript
// Request
{
  "token": "abc123def456ghi789..."
}

// Response
{
  "success": true,
  "message": "Email verified successfully"
}
```

#### 3. Login User

**POST** `/api/auth/login`

Login with email and password.

```javascript
// Request
{
  "email": "john.doe@example.com",
  "password": "SecurePass123!",
  "deviceInfo": "Chrome on Windows" // optional
}

// Response
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "id": "507f1f77bcf86cd799439011",
      "email": "john.doe@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "role": "user",
      "isTwoFactorEnabled": false
    },
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

#### 4. Refresh Token

**POST** `/api/auth/refresh`

Get a new access token using refresh token.

```javascript
// Request
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}

// Response
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

### User Management Endpoints

#### 1. Get Profile

**GET** `/api/user/profile`

Get current user's profile information.

```javascript
// Headers
Authorization: Bearer <access_token>

// Response
{
  "success": true,
  "data": {
    "id": "507f1f77bcf86cd799439011",
    "email": "john.doe@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "role": "user",
    "isEmailVerified": true,
    "isTwoFactorEnabled": false,
    "createdAt": "2023-12-07T10:30:00.000Z",
    "authorizedApps": []
  }
}
```

#### 2. Update Profile

**PUT** `/api/user/profile`

Update user profile information.

```javascript
// Headers
Authorization: Bearer <access_token>

// Request
{
  "firstName": "John",
  "lastName": "Smith"
}

// Response
{
  "success": true,
  "data": {
    // Updated user object
  },
  "message": "Profile updated successfully"
}
```

### Two-Factor Authentication

#### 1. Setup 2FA

**POST** `/api/auth/setup-2fa`

Setup two-factor authentication.

```javascript
// Headers
Authorization: Bearer <access_token>

// Response
{
  "success": true,
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "qrCode": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
  }
}
```

#### 2. Verify 2FA

**POST** `/api/auth/verify-2fa`

Verify and enable two-factor authentication.

```javascript
// Headers
Authorization: Bearer <access_token>

// Request
{
  "secret": "JBSWY3DPEHPK3PXP",
  "token": "123456"
}

// Response
{
  "success": true,
  "message": "2FA enabled successfully"
}
```

## 🛡️ Security Features

### 1. Password Security

- **bcrypt hashing** with 12 salt rounds
- **Password complexity requirements**:
  - Minimum 8 characters
  - At least 1 uppercase letter
  - At least 1 lowercase letter  
  - At least 1 number
  - At least 1 special character

### 2. Account Protection

- **Account lockout** after 5 failed login attempts
- **2-hour lockout duration**
- **Email verification** required for new accounts
- **Session tracking** across devices

### 3. Token Security

- **Short-lived access tokens** (15 minutes)
- **Token rotation** on refresh
- **Secure random generation**
- **JWT signature verification**

### 4. API Security

- **Rate limiting**: 100 requests per 15 minutes per IP
- **Auth rate limiting**: 5 requests per 15 minutes per IP
- **Input validation** on all endpoints
- **CORS protection**
- **Security headers** with Helmet.js

### 5. Data Protection

- **Sensitive data exclusion** from API responses
- **Environment variable configuration**
- **Error message sanitization**
- **Database query optimization**

## 💻 Usage Examples

### Frontend Integration (JavaScript)

```javascript
class AuthifyClient {
  constructor(baseURL) {
    this.baseURL = baseURL;
    this.accessToken = localStorage.getItem('accessToken');
    this.refreshToken = localStorage.getItem('refreshToken');
  }

  async register(userData) {
    const response = await fetch(`${this.baseURL}/api/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(userData)
    });
    
    return await response.json();
  }

  async login(email, password) {
    const response = await fetch(`${this.baseURL}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();
    
    if (data.success) {
      this.accessToken = data.data.accessToken;
      this.refreshToken = data.data.refreshToken;
      localStorage.setItem('accessToken', this.accessToken);
      localStorage.setItem('refreshToken', this.refreshToken);
    }

    return data;
  }

  async makeAuthenticatedRequest(endpoint, options = {}) {
    const response = await fetch(`${this.baseURL}${endpoint}`, {
      ...options,
      headers: {
        'Authorization': `Bearer ${this.accessToken}`,
        'Content-Type': 'application/json',
        ...options.headers
      }
    });

    // Handle token expiration
    if (response.status === 401) {
      const refreshed = await this.refreshAccessToken();
      if (refreshed) {
        // Retry the request
        return await fetch(`${this.baseURL}${endpoint}`, {
          ...options,
          headers: {
            'Authorization': `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json',
            ...options.headers
          }
        });
      }
    }

    return response;
  }

  async refreshAccessToken() {
    try {
      const response = await fetch(`${this.baseURL}/api/auth/refresh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ refreshToken: this.refreshToken })
      });

      const data = await response.json();
      
      if (data.success) {
        this.accessToken = data.data.accessToken;
        this.refreshToken = data.data.refreshToken;
        localStorage.setItem('accessToken', this.accessToken);
        localStorage.setItem('refreshToken', this.refreshToken);
        return true;
      }
    } catch (error) {
      console.error('Token refresh failed:', error);
    }
    
    return false;
  }

  logout() {
    this.accessToken = null;
    this.refreshToken = null;
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
  }
}

// Usage
const auth = new AuthifyClient('http://localhost:3000');

// Register
await auth.register({
  email: 'user@example.com',
  password: 'SecurePass123!',
  firstName: 'John',
  lastName: 'Doe'
});

// Login
await auth.login('user@example.com', 'SecurePass123!');

// Make authenticated requests
const profile = await auth.makeAuthenticatedRequest('/api/user/profile');
```

### React Integration Example

```javascript
import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const auth = new AuthifyClient('http://localhost:3000');

  useEffect(() => {
    // Check if user is logged in on app start
    const token = localStorage.getItem('accessToken');
    if (token) {
      auth.makeAuthenticatedRequest('/api/user/profile')
        .then(response => response.json())
        .then(data => {
          if (data.success) {
            setUser(data.data);
          }
        })
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const login = async (email, password) => {
    const result = await auth.login(email, password);
    if (result.success) {
      setUser(result.data.user);
    }
    return result;
  };

  const logout = () => {
    auth.logout();
    setUser(null);
  };

  const value = {
    user,
    login,
    logout,
    loading,
    auth
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Login Component
const LoginForm = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    const result = await login(email, password);
    if (result.success) {
      alert('Login successful!');
    } else {
      alert('Login failed: ' + result.message);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input 
        type="email" 
        value={email} 
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Email"
        required 
      />
      <input 
        type="password" 
        value={password} 
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
        required 
      />
      <button type="submit">Login</button>
    </form>
  );
};
```

## 🔧 Advanced Configuration

### Custom Rate Limiting

```javascript
// In server.js, customize rate limiting
const customLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 50, // limit each IP to 50 requests per windowMs
  message: {
    error: 'Too many requests, please try again later.',
    retryAfter: '10 minutes'
  }
});

app.use('/api', customLimiter);
```

### Email Template Customization

```javascript
// In routes/auth.js, customize email templates
const emailTemplate = {
  verification: (name, url) => `
    <div style="font-family: Arial, sans-serif; max-width: 600px;">
      <h2>Welcome to Authify, ${name}!</h2>
      <p>Please verify your email address by clicking the button below:</p>
      <a href="${url}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
        Verify Email
      </a>
      <p>If the button doesn't work, copy this link: ${url}</p>
    </div>
  `,
  
  passwordReset: (name, url) => `
    <div style="font-family: Arial, sans-serif; max-width: 600px;">
      <h2>Password Reset Request</h2>
      <p>Hello ${name},</p>
      <p>You requested a password reset. Click the button below to reset your password:</p>
      <a href="${url}" style="background: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
        Reset Password
      </a>
      <p>This link will expire in 1 hour.</p>
    </div>
  `
};
```

### Database Indexing

```javascript
// Add these indexes for better performance
db.users.createIndex({ email: 1 }, { unique: true })
db.users.createIndex({ emailVerificationToken: 1 })
db.users.createIndex({ passwordResetToken: 1 })
db.users.createIndex({ createdAt: 1 })

db.apps.createIndex({ clientId: 1 }, { unique: true })
db.apps.createIndex({ owner: 1 })
db.apps.createIndex({ createdAt: 1 })
```

## 🚀 Deployment

### Production Environment Variables

```env
NODE_ENV=production
PORT=3000

# Use strong, unique secrets
JWT_SECRET=your_production_jwt_secret_32_chars_minimum
JWT_REFRESH_SECRET=your_production_refresh_secret_32_chars_minimum

# Production database
MONGODB_URI=mongodb://your-production-db/authify

# Production email service
EMAIL_HOST=smtp.sendgrid.net
EMAIL_PORT=587
EMAIL_USER=apikey
EMAIL_PASS=your_sendgrid_api_key

# Production frontend URL
FRONTEND_URL=https://your-domain.com
```

### Docker Deployment

Create `Dockerfile`:

```dockerfile
FROM node:16-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 3000

USER node

CMD ["npm", "start"]
```

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  authify:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - MONGODB_URI=mongodb://mongo:27017/authify
    depends_on:
      - mongo
    restart: unless-stopped

  mongo:
    image: mongo:5.0
    volumes:
      - mongo_data:/data/db
    restart: unless-stopped

volumes:
  mongo_data:
```

Deploy with:

```bash
docker-compose up -d
```

### Heroku Deployment

1. **Create Heroku app**:
```bash
heroku create your-authify-app
```

2. **Add MongoDB addon**:
```bash
heroku addons:create mongolab:sandbox
```

3. **Set environment variables**:
```bash
heroku config:set JWT_SECRET=your_secret_here
heroku config:set JWT_REFRESH_SECRET=your_refresh_secret_here
heroku config:set EMAIL_HOST=smtp.sendgrid.net
heroku config:set EMAIL_USER=apikey
heroku config:set EMAIL_PASS=your_sendgrid_key
heroku config:set FRONTEND_URL=https://your-frontend.herokuapp.com
```

4. **Deploy**:
```bash
git add .
git commit -m "Deploy Authify"
git push heroku main
```

### nginx Configuration

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## 🤝 Contributing

We welcome contributions to Authify! Here's how to get started:

### Development Setup

1. **Fork the repository**
2. **Clone your fork**:
```bash
git clone https://github.com/yourusername/authify.git
cd authify
```

3. **Install dependencies**:
```bash
npm install
```

4. **Create a feature branch**:
```bash
git checkout -b feature/your-feature-name
```

5. **Make your changes**
6. **Test your changes**:
```bash
npm test
```

7. **Commit your changes**:
```bash
git commit -m "Add: your feature description"
```

8. **Push to your fork**:
```bash
git push origin feature/your-feature-name
```

9. **Create a Pull Request**

### Coding Standards

- Use **ES6+** features
- Follow **REST API** conventions
- Add **JSDoc** comments for functions
- Write **unit tests** for new features
- Follow **security best practices**

### Reporting Issues

When reporting issues, please include:

- **Node.js version**
- **MongoDB version**
- **Steps to reproduce**
- **Expected behavior**
- **Actual behavior**
- **Error messages**

---

## 📞 Support

If you need help with Authify:

- 📖 Check the documentation above
- 🐛 [Open an issue](https://github.com/yourusername/authify/issues) for bugs
- 💡 [Request features](https://github.com/yourusername/authify/issues) 
- 📧 Contact: support@authify.dev

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Made with ❤️ for secure authentication**

[⭐ Star this repo](https://github.com/yourusername/authify) if you found it helpful!

