# 🚀 Complete Working Example: Flask Auth in 2 Minutes

This example shows how ridiculously easy it is to set up production-ready authentication.

---

## 🐍 Minimal Example (10 Lines)

```python
from flask import Flask
from flask_headless_auth import AuthSvc

app = Flask(__name__)

# Config
app.config['SECRET_KEY'] = 'dev-secret-key'
app.config['JWT_SECRET_KEY'] = 'dev-jwt-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

# Initialize - ONE LINE!
auth = AuthSvc(app)

if __name__ == '__main__':
    with app.app_context():
        auth.db.create_all()
    app.run(debug=True)
```

**Run it:**
```bash
pip install flask-headless-auth
python app.py
```

**✅ You now have 20+ auth endpoints!**

Test with curl:
```bash
# Signup
curl -X POST http://localhost:5000/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' \
  -c cookies.txt

# Get user (uses cookies)
curl http://localhost:5000/api/auth/user/@me -b cookies.txt
```

---

## 🎯 Production Example (50 Lines)

```python
# app.py
import os
from flask import Flask, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_headless_auth import AuthSvc, UserMixin, db

app = Flask(__name__)

# Config from environment
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-jwt-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'sqlite:///app.db'
)

# Security (production)
app.config['JWT_COOKIE_SECURE'] = os.getenv('FLASK_ENV') == 'production'
app.config['JWT_COOKIE_HTTPONLY'] = True
app.config['JWT_COOKIE_SAMESITE'] = 'Strict'

# CORS (your frontend)
app.config['AUTHSVC_CORS_ORIGINS'] = [
    'http://localhost:3000',  # Local dev
    'https://yourapp.com',    # Production
]

# Custom User model (optional)
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    # Add custom fields
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    subscription = db.Column(db.String(50), default='free')

# Initialize auth
auth = AuthSvc(app, user_model=User)

# Your custom protected routes
@app.route('/api/dashboard')
@jwt_required()
def dashboard():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    return jsonify({
        'message': f'Welcome {user.email}!',
        'subscription': user.subscription
    })

@app.route('/api/admin')
@jwt_required()
def admin():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user.email.endswith('@admin.com'):
        return jsonify({'error': 'Admin only'}), 403
    
    return jsonify({'message': 'Welcome admin!'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
```

---

## 🔗 Frontend Integration

### React (Easiest)

```bash
npm install @headlesskits/react-headless-auth
```

```tsx
import { AuthProvider, useAuth } from '@headlesskits/react-headless-auth';

// Wrap app
<AuthProvider config={{ apiBaseUrl: 'http://localhost:5000' }}>
  <App />
</AuthProvider>

// Use anywhere
function MyComponent() {
  const { user, login, logout } = useAuth();
  // ... use it!
}
```

### Vanilla JavaScript

```javascript
// Login
async function login(email, password) {
  const response = await fetch('http://localhost:5000/api/auth/login', {
    method: 'POST',
    credentials: 'include', // Important!
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  
  if (response.ok) {
    const data = await response.json();
    console.log('Logged in:', data.user);
  }
}

// Get user
async function getUser() {
  const response = await fetch('http://localhost:5000/api/auth/user/@me', {
    credentials: 'include'
  });
  
  if (response.ok) {
    const data = await response.json();
    return data.user;
  }
}

// Logout
async function logout() {
  await fetch('http://localhost:5000/api/auth/logout', {
    method: 'POST',
    credentials: 'include'
  });
}
```

---

## 🎨 Custom User Model

```python
from flask_headless_auth import UserMixin, db

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    # UserMixin provides required fields:
    # - id, email, password_hash
    # - is_verified, is_active, mfa_enabled
    # - provider, created_at, updated_at
    
    # Add YOUR fields:
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    company = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    subscription = db.Column(db.String(50), default='free')
    credits = db.Column(db.Integer, default=0)
    profile_picture = db.Column(db.String(500))
    
    # Computed properties
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    # Custom methods
    def can_access_feature(self, feature):
        if feature == 'premium':
            return self.subscription in ['premium', 'enterprise']
        return True

# Use it
auth = AuthSvc(app, user_model=User)
```

---

## 🔐 OAuth (Google, Microsoft)

```python
# Add to config
app.config['GOOGLE_CLIENT_ID'] = 'your-client-id'
app.config['GOOGLE_CLIENT_SECRET'] = 'your-client-secret'
app.config['MICROSOFT_CLIENT_ID'] = 'your-client-id'
app.config['MICROSOFT_CLIENT_SECRET'] = 'your-client-secret'
app.config['POST_LOGIN_REDIRECT_URL'] = 'http://localhost:3000/dashboard'

# That's it! OAuth now works
```

**Frontend:**
```html
<a href="http://localhost:5000/api/auth/login/google">
  Sign in with Google
</a>
```

---

## 📧 Email Verification

```bash
pip install flask-headless-auth[email]
```

```python
# Gmail
app.config['EMAIL_SERVICE'] = 'gmail'
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-app-password'

# Or Brevo
app.config['EMAIL_SERVICE'] = 'brevo'
app.config['BREVO_API_KEY'] = 'your-brevo-api-key'
```

Now users automatically get verification emails on signup!

---

## 🔒 Protected Routes

```python
from flask_jwt_extended import jwt_required, get_jwt_identity

@app.route('/api/protected')
@jwt_required()
def protected():
    user_id = get_jwt_identity()
    return {'message': 'You are authenticated!', 'user_id': user_id}

@app.route('/api/admin-only')
@jwt_required()
def admin_only():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user.is_admin:
        return {'error': 'Admin only'}, 403
    
    return {'message': 'Welcome admin!'}
```

---

## 🚀 Deploy to Production

### Heroku

```bash
# requirements.txt
flask-headless-auth
gunicorn
psycopg2-binary

# Procfile
web: gunicorn app:app

# Deploy
heroku create my-auth-api
heroku addons:create heroku-postgresql:mini
heroku config:set SECRET_KEY=your-secret
heroku config:set JWT_SECRET_KEY=your-jwt-secret
git push heroku main
```

### Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

```bash
docker build -t my-auth-api .
docker run -p 5000:5000 \
  -e SECRET_KEY=your-secret \
  -e JWT_SECRET_KEY=your-jwt-secret \
  my-auth-api
```

### DigitalOcean App Platform

```yaml
# .do/app.yaml
name: my-auth-api
services:
  - name: api
    github:
      repo: your-username/your-repo
      branch: main
    envs:
      - key: SECRET_KEY
        value: ${SECRET_KEY}
      - key: JWT_SECRET_KEY
        value: ${JWT_SECRET_KEY}
    run_command: gunicorn app:app
```

---

## 💡 Advanced Features

### Rate Limiting

```python
app.config['RATELIMIT_ENABLED'] = True
app.config['RATELIMIT_STORAGE_URL'] = 'redis://localhost:6379/0'

# Now all auth endpoints are rate-limited!
# Login: 5 attempts per minute
# Signup: 3 attempts per minute
```

### Caching (Performance)

```python
from flask_caching import Cache

cache = Cache(app, config={
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_URL': 'redis://localhost:6379/0'
})

# AuthSvc automatically uses cache if available
auth = AuthSvc(app)
```

### MFA/2FA

```python
app.config['AUTHSVC_ENABLE_MFA'] = True

# Users can now enable MFA:
# POST /api/auth/mfa/enable
# POST /api/auth/mfa/verify
# POST /api/auth/mfa/disable
```

### RBAC (Role-Based Access)

```python
from flask_headless_auth import RoleMixin

class Role(db.Model, RoleMixin):
    __tablename__ = 'roles'
    name = db.Column(db.String(50), unique=True)

# Assign roles to users
user.role_id = admin_role.id

# Check in routes
@app.route('/api/admin')
@jwt_required()
def admin():
    user = get_current_user()
    if user.role.name != 'admin':
        return {'error': 'Admin only'}, 403
    return {'message': 'Welcome admin'}
```

---

## 🧪 Testing

```python
# test_auth.py
import pytest
from app import app, db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client

def test_signup(client):
    response = client.post('/api/auth/signup', json={
        'email': 'test@example.com',
        'password': 'password123'
    })
    assert response.status_code == 200
    assert 'user' in response.json

def test_login(client):
    # Signup first
    client.post('/api/auth/signup', json={
        'email': 'test@example.com',
        'password': 'password123'
    })
    
    # Login
    response = client.post('/api/auth/login', json={
        'email': 'test@example.com',
        'password': 'password123'
    })
    assert response.status_code == 200
    assert 'access_token' in response.json
```

---

## 🐛 Debugging

```python
# Enable debug mode
app.config['DEBUG'] = True

# Or use Flask debug toolbar
from flask_debugtoolbar import DebugToolbarExtension
toolbar = DebugToolbarExtension(app)

# Check logs
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## 🤔 Common Issues

### "User model missing required fields"

```python
# Your User model MUST have these fields:
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password_hash = db.Column(db.String(1024))
    is_verified = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    provider = db.Column(db.String(50), default='local')
```

Or just use `UserMixin`:
```python
from flask_headless_auth import UserMixin

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    # Mixin provides all required fields!
```

### CORS Errors

```python
app.config['AUTHSVC_CORS_ORIGINS'] = [
    'http://localhost:3000',
    'https://yourapp.com'
]
```

### Cookies Not Working

```python
# Development (HTTP)
app.config['JWT_COOKIE_SECURE'] = False

# Production (HTTPS)
app.config['JWT_COOKIE_SECURE'] = True
```

---

## 📚 Full Example Repository

```bash
git clone https://github.com/Dhruvagnihotri/flask-headless-auth-example
cd flask-headless-auth-example
pip install -r requirements.txt
python app.py
```

**Includes:**
- ✅ Custom User model
- ✅ OAuth (Google, Microsoft)
- ✅ Email verification
- ✅ Password reset
- ✅ MFA
- ✅ RBAC
- ✅ Tests
- ✅ Docker
- ✅ Heroku deployment

---

## 💬 Need Help?

- 📖 [Full Documentation](./flask_headless_auth/README.md)
- 🐛 [Report Issues](https://github.com/Dhruvagnihotri/flask-headless-auth/issues)
- 💬 [Ask Questions](https://github.com/Dhruvagnihotri/flask-headless-auth/discussions)
- 📧 [Email](mailto:dagni@umich.edu)

---

**⭐ If this saved you time, please star the repo!**

[![GitHub stars](https://img.shields.io/github/stars/Dhruvagnihotri/flask-headless-auth?style=social)](https://github.com/Dhruvagnihotri/flask-headless-auth)
