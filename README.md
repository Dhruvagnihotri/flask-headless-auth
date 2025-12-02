# Flask-Headless-Auth

**Modern, headless authentication for Flask APIs.**

A production-ready Flask authentication service package with JWT support, OAuth integration, and flexible token delivery modes. Perfect for SPAs, mobile apps, and API-first applications.

[![PyPI version](https://badge.fury.io/py/flask-headless-auth.svg)](https://badge.fury.io/py/flask-headless-auth)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

- ✅ **Headless Architecture** - API-first design for modern SPAs and mobile apps
- ✅ **JWT Authentication** - Secure access + refresh token pattern
- ✅ **OAuth Support** - Google, Microsoft SSO integration
- ✅ **Configurable Token Delivery** - Cookies, headers, or both
- ✅ **Role-Based Access Control** - RBAC support built-in
- ✅ **Multi-Factor Authentication** - MFA support out of the box
- ✅ **Email Verification** - Email confirmation workflows
- ✅ **Password Reset** - Secure password reset flows
- ✅ **Production Security** - httpOnly cookies, CSRF protection, rate limiting
- ✅ **Caching & Performance** - Redis/SimpleCache integration
- ✅ **Framework Agnostic Frontend** - Works with React, Vue, Angular, Next.js, etc.

## 🚀 Quick Start

### Installation

```bash
pip install flask-headless-auth
```

### Basic Setup (5 minutes)

```python
from flask import Flask
from flask_headless_auth import AuthSvc

app = Flask(__name__)

# Minimal configuration
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['JWT_SECRET_KEY'] = 'your-jwt-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

# Initialize - that's it!
auth = AuthSvc(app)

if __name__ == '__main__':
    app.run()
```

Your API now has authentication endpoints ready at `/api/auth/*` 🎉

## 📚 Documentation

- [Full Documentation](./flask_headless_auth/README.md) - Complete guide with examples
- [Configuration Examples](./flask_headless_auth/CONFIG_EXAMPLES.md) - Detailed config options
- [Migration Guide](./MIXIN_MIGRATION_GUIDE.md) - Upgrade from older versions

## 🎯 Why Headless?

Flask-Headless-Auth is designed for modern, decoupled architectures:

- **API-First**: Pure REST API with no server-side rendering
- **Frontend Agnostic**: Works with any frontend framework
- **Mobile-Ready**: Perfect for React Native, Flutter, native mobile apps
- **Microservices**: Ideal for distributed systems and microservices

## 🔒 Security First

Built with industry-standard security practices:

- HttpOnly cookies for XSS protection
- CSRF protection with SameSite cookies
- Rate limiting to prevent brute force attacks
- Secure password hashing with bcrypt
- Token blacklisting for logout
- Configurable token expiration

## 🛠️ Technology Stack

- **Flask** - Web framework
- **Flask-JWT-Extended** - JWT token management
- **Flask-SQLAlchemy** - Database ORM
- **Authlib** - OAuth integration
- **Flask-Limiter** - Rate limiting
- **Flask-Caching** - Performance optimization

## 📦 What's Included

### Authentication Endpoints

- User registration and login
- Token refresh and logout
- Email verification
- Password reset
- OAuth (Google, Microsoft)

### User Management

- Profile management
- Role-based permissions
- Multi-factor authentication
- Activity logging

### Developer Experience

- Drop-in solution (5-minute setup)
- Sensible defaults
- Extensive configuration options
- Clear error messages
- Type hints included

## 🤝 Contributing

Contributions welcome! Please see our [Contributing Guidelines](CONTRIBUTING.md).

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

## 🙏 Credits

Developed with ❤️ by [Dhruv Agnihotri](https://github.com/Dhruvagnihotri)

Built with Flask, Flask-JWT-Extended, Flask-SQLAlchemy, and Authlib.

---

**Made with security in mind. Deploy with confidence.** 🔒
