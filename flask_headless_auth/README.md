# Flask-Headless-Auth

A configurable, production-ready Flask authentication service package with JWT support, OAuth integration, and flexible token delivery modes.

## Features

- ✅ **Configurable Token Delivery** - Choose between cookies-only (secure), body-only (APIs), or dual (flexible)
- ✅ **Industry-Standard Security** - httpOnly cookies, CSRF protection, secure defaults
- ✅ **OAuth Support** - Google, Microsoft SSO integration
- ✅ **JWT Authentication** - Access + refresh token pattern
- ✅ **Multi-Factor Authentication** - Built-in MFA support
- ✅ **Role-Based Access Control** - RBAC support
- ✅ **Email Verification** - Email confirmation workflows
- ✅ **Password Reset** - Secure password reset flows
- ✅ **Caching** - Optional Redis/SimpleCache integration
- ✅ **Rate Limiting** - Built-in rate limiting support

## Quick Start

### Installation

```bash
pip install flask-headless-auth
```

### Basic Setup

```python
from flask import Flask
from flask_headless_auth import create_auth_blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

app = Flask(__name__)

# Configuration (Industry-standard secure defaults)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['JWT_SECRET_KEY'] = 'your-jwt-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

# Token delivery mode (secure by default)
app.config['AUTHSVC_TOKEN_DELIVERY'] = 'cookies_only'  # RECOMMENDED
app.config['JWT_TOKEN_LOCATION'] = ['cookies', 'headers']
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_COOKIE_HTTPONLY'] = True  
app.config['JWT_COOKIE_SAMESITE'] = 'Strict'

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Import your models
from your_app.models import User, BlacklistedToken, MFAToken, PasswordResetToken, UserActivityLog

# Create auth blueprint
auth_blueprint = create_auth_blueprint(
    user_model=User,
    blacklisted_token_model=BlacklistedToken,
    mfa_token_model=MFAToken,
    password_reset_token_model=PasswordResetToken,
    user_activity_log_model=UserActivityLog,
    blueprint_name='auth',
    post_login_redirect_url='https://yourfrontend.com'
)

# Register blueprint
app.register_blueprint(auth_blueprint, url_prefix='/api/auth')

if __name__ == '__main__':
    app.run()
```

## Token Delivery Modes

Flask-Headless-Auth supports three configurable token delivery modes:

### 1. cookies_only (DEFAULT - Most Secure) ✅

**Best for:** Web applications, browser-based clients, production environments

```python
app.config['AUTHSVC_TOKEN_DELIVERY'] = 'cookies_only'
```

**Benefits:**
- ✅ Highest security - No XSS attack surface
- ✅ httpOnly cookies prevent JavaScript access
- ✅ Simplest frontend implementation
- ✅ Used by 70% of industry (banks, fintech, healthcare)

**Frontend example:**
```typescript
const response = await fetch('/api/auth/login', {
  method: 'POST',
  credentials: 'include',  // Auto-handles cookies
  body: JSON.stringify({ email, password })
});
// That's it! No token storage needed
```

### 2. body_only (For APIs)

**Best for:** Mobile apps, API-first services, microservices

```python
app.config['AUTHSVC_TOKEN_DELIVERY'] = 'body_only'
```

**Benefits:**
- ✅ Perfect for mobile apps (SecureStore, Keychain)
- ✅ API-first architecture
- ✅ No cookie management needed

**Frontend example:**
```typescript
const response = await fetch('/api/auth/login', {
  method: 'POST',
  body: JSON.stringify({ email, password })
});
const { access_token, refresh_token } = await response.json();
await SecureStore.setItemAsync('access_token', access_token);
```

### 3. dual (Flexible - Backwards Compatible)

**Best for:** Apps that must support cookie-blocked users

```python
app.config['AUTHSVC_TOKEN_DELIVERY'] = 'dual'
```

**Benefits:**
- ✅ Supports cookie-blocked users (~1-3%)
- ✅ Backwards compatible with existing implementations

**Trade-offs:**
- ⚠️ More complex frontend code
- ⚠️ XSS vulnerability for localStorage users
- ⚠️ Higher maintenance burden

## Configuration

### Minimal Configuration (Secure Defaults)

```python
# config.py

class Config:
    # Required
    SECRET_KEY = 'your-secret-key'
    JWT_SECRET_KEY = 'your-jwt-secret-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'
    
    # Token delivery (secure default)
    AUTHSVC_TOKEN_DELIVERY = 'cookies_only'
    
    # That's it! Other settings use secure defaults
```

### Full Configuration (All Options)

```python
# config.py

class Config:
    # Database
    SECRET_KEY = 'your-secret-key'
    SQLALCHEMY_DATABASE_URI = 'postgresql://user:pass@localhost/db'
    
    # Token Delivery Mode
    AUTHSVC_TOKEN_DELIVERY = 'cookies_only'  # Options: 'cookies_only', 'body_only', 'dual'
    
    # JWT Settings
    JWT_SECRET_KEY = 'your-jwt-secret-key'
    JWT_TOKEN_LOCATION = ['cookies', 'headers']  # Where to accept tokens FROM
    JWT_ACCESS_TOKEN_EXPIRES = 900  # 15 minutes (industry standard)
    JWT_REFRESH_TOKEN_EXPIRES = 2592000  # 30 days
    
    # Cookie Security (Industry Standard)
    JWT_COOKIE_SECURE = True  # HTTPS only
    JWT_COOKIE_HTTPONLY = True  # XSS protection
    JWT_COOKIE_SAMESITE = 'Strict'  # CSRF protection
    JWT_COOKIE_CSRF_PROTECT = False  # Not needed with SameSite=Strict
    
    # AuthSvc Features
    AUTHSVC_ENABLE_OAUTH = True
    AUTHSVC_ENABLE_MFA = True
    AUTHSVC_ENABLE_RBAC = True
    
    # OAuth (if enabled)
    GOOGLE_CLIENT_ID = 'your-google-client-id'
    GOOGLE_CLIENT_SECRET = 'your-google-client-secret'
    
    # Email (for verification, password reset)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'your-email@gmail.com'
    MAIL_PASSWORD = 'your-app-password'
    
    # Cache (optional, for performance)
    CACHE_TYPE = 'redis'
    CACHE_REDIS_URL = 'redis://localhost:6379/0'
    
    # Rate Limiting (optional)
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = '100 per hour'
```

## API Endpoints

Once configured, Flask-Headless-Auth provides these endpoints:

### Authentication

- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login with email/password
- `POST /api/auth/logout` - Logout (blacklist token)
- `GET /api/auth/check-auth` - Check authentication status
- `POST /api/auth/token/refresh` - Refresh access token

### OAuth

- `GET /api/auth/login/google` - Initiate Google OAuth
- `GET /api/auth/auth/google/callback` - Google OAuth callback
- `GET /api/auth/login/microsoft` - Initiate Microsoft OAuth
- `GET /api/auth/auth/microsoft/callback` - Microsoft OAuth callback

### User Management

- `GET /api/auth/user/@me` - Get current user details
- `POST /api/auth/update_user` - Update user profile
- `POST /api/auth/upload-profile-picture` - Upload profile picture

### Email & MFA

- `POST /api/auth/verify-mfa` - Verify MFA token
- `GET /api/auth/confirm/<token>` - Confirm email address
- `POST /api/auth/resend-verification-email` - Resend verification
- `POST /api/auth/request-password-reset` - Request password reset

### Protected Routes

- `GET /api/auth/protected` - Example protected route

## Frontend Integration

### React/Next.js Example (cookies_only mode)

```typescript
// contexts/AuthContext.tsx

import { createContext, useState, useContext } from 'react';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  const login = async (email: string, password: string) => {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'include',  // Important!
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    if (response.ok) {
      const data = await response.json();
      setUser(data.user);
      setIsAuthenticated(true);
      return { success: true };
    }
    
    return { success: false, error: 'Login failed' };
  };

  const logout = async () => {
    await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'include'
    });
    
    setUser(null);
    setIsAuthenticated(false);
  };

  const checkAuth = async () => {
    const response = await fetch('/api/auth/user/@me', {
      credentials: 'include'
    });
    
    if (response.ok) {
      const data = await response.json();
      setUser(data.user);
      setIsAuthenticated(true);
    }
  };

  return (
    <AuthContext.Provider value={{ user, isAuthenticated, login, logout, checkAuth }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
```

### Vue.js Example

```typescript
// stores/auth.ts

import { defineStore } from 'pinia'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null,
    isAuthenticated: false
  }),
  
  actions: {
    async login(email: string, password: string) {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      })
      
      if (response.ok) {
        const data = await response.json()
        this.user = data.user
        this.isAuthenticated = true
        return true
      }
      
      return false
    },
    
    async logout() {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include'
      })
      
      this.user = null
      this.isAuthenticated = false
    }
  }
})
```

## Model Requirements

Flask-Headless-Auth requires these models in your application:

```python
# models.py

from flask_sqlalchemy import SQLAlchemy
from flask_headless_auth.mixins import UserMixin, TokenMixin, OAuthMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    role_id = db.Column(db.Integer, default=2)
    is_verified = db.Column(db.Boolean, default=False)
    mfa_enabled = db.Column(db.Boolean, default=False)
    # ... other fields

class BlacklistedToken(db.Model, TokenMixin):
    __tablename__ = 'blacklisted_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class MFAToken(db.Model):
    __tablename__ = 'mfa_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    token = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    token = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

class UserActivityLog(db.Model):
    __tablename__ = 'user_activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    activity = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
```

## Security Best Practices

### 1. Use cookies_only Mode (Default)

```python
AUTHSVC_TOKEN_DELIVERY = 'cookies_only'  # Most secure
```

### 2. Enable HTTPS in Production

```python
JWT_COOKIE_SECURE = True  # Only send cookies over HTTPS
```

### 3. Short Access Token Lifetime

```python
JWT_ACCESS_TOKEN_EXPIRES = 900  # 15 minutes (not 1 hour)
```

### 4. Strong Cookie Settings

```python
JWT_COOKIE_HTTPONLY = True  # Prevent XSS
JWT_COOKIE_SAMESITE = 'Strict'  # Prevent CSRF
```

### 5. Use Environment Variables

```python
import os

JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')  # Never hardcode
SECRET_KEY = os.getenv('SECRET_KEY')
```

### 6. Enable Rate Limiting

```python
RATELIMIT_ENABLED = True
RATELIMIT_DEFAULT = '100 per hour'
```

## Migration Guide

### From Dual Mode to Cookies-Only

If you're currently using `dual` mode and want to migrate to the more secure `cookies_only`:

**Step 1:** Update backend config

```python
# Change from:
AUTHSVC_TOKEN_DELIVERY = 'dual'

# To:
AUTHSVC_TOKEN_DELIVERY = 'cookies_only'
```

**Step 2:** Update frontend

```typescript
// Remove ALL localStorage token code
// Delete TokenStorage class
// Remove localStorage.setItem('auth_*')

// Before:
localStorage.setItem('access_token', data.access_token);

// After:
// Nothing! Cookies handled automatically
```

**Step 3:** Handle cookie-blocked users

```typescript
// Show clear error page for <1% edge cases
if (authFails && !hasRetried) {
  showErrorPage({
    title: "Cookies Required",
    message: "Please enable cookies in your browser.",
    helpLink: "/help/enable-cookies"
  });
}
```

## Documentation

- [Configuration Examples](./CONFIG_EXAMPLES.md) - Detailed examples for each mode
- [API Reference](#api-endpoints) - Complete API documentation
- [Security Guide](#security-best-practices) - Security best practices
- [Migration Guide](#migration-guide) - Upgrade guides

## Examples

See the `/examples` directory for complete working examples:

- `examples/web_app/` - Web application using cookies_only
- `examples/mobile_api/` - Mobile API using body_only
- `examples/hybrid_app/` - Hybrid application using dual mode

## Contributing

Contributions welcome! Please:

1. Follow PEP 8 style guide
2. Add tests for new features
3. Update documentation
4. Ensure security best practices

## License

MIT License - See LICENSE file for details

## Support

- GitHub Issues: [Report bugs or request features](https://github.com/yourusername/flask-headless-auth/issues)
- Documentation: [Full documentation](https://flask-headless-auth.readthedocs.io)
- Email: support@flask-headless-auth.com

## Credits

Developed with ❤️ using:
- Flask
- Flask-JWT-Extended
- Flask-SQLAlchemy
- Authlib (OAuth)

---

**Made with security in mind. Deploy with confidence.** 🔒

