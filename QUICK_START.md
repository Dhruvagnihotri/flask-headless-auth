# Flask Headless Auth + React Headless Auth - Quick Start Guide

> **Get authentication, RBAC, and admin features running in under 10 minutes.**

---

## What You Get

- ✅ **Authentication**: Login, signup, password reset, email verification, OAuth
- ✅ **RBAC**: Complete role & permission system with decorators
- ✅ **Admin APIs**: User management, ban/unban, session control
- ✅ **Audit Logging**: Automatic tracking of all auth events (HIPAA-ready)
- ✅ **Session Management**: Multi-device sessions with device fingerprinting
- ✅ **React SDK**: Hooks, components, TypeScript support

---

## 5-Minute Backend Setup

### 1. Install (Python 3.8+)

```bash
pip install flask flask-sqlalchemy flask-jwt-extended flask-cors
# Then install flask-headless-auth (or clone repo)
```

### 2. Create `app.py`

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_headless_auth import FlaskHeadlessAuth

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'  # or PostgreSQL
app.config['JWT_SECRET_KEY'] = 'your-jwt-secret-change-in-production'

# Optional: Frontend URL (used for email verification/reset URLs in hooks)
app.config['FRONTEND_URL'] = 'http://localhost:3000'

# Initialize database and auth
db = SQLAlchemy(app)
auth = FlaskHeadlessAuth(app, db)

# Create tables
with app.app_context():
    auth.create_tables()
    print("✅ Database tables created!")

# Example protected route
@app.route('/api/protected')
@auth.jwt_required()
def protected():
    from flask_jwt_extended import get_jwt_identity
    user_id = get_jwt_identity()
    return {'message': f'Hello user {user_id}!'}

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

### 3. Run Backend

```bash
python app.py
```

**You now have 50+ API endpoints running!** 🎉

Test it:
```bash
# Register a user
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test123!"}'

# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test123!"}'
```

---

## 5-Minute Frontend Setup (React)

### 1. Install

```bash
npm install react-headless-auth
# Or: npm install axios (required dependency)
```

### 2. Wrap Your App

```tsx
// src/main.tsx or src/index.tsx
import { AuthProvider } from 'react-headless-auth';

function Main() {
  return (
    <AuthProvider config={{ apiBaseUrl: 'http://localhost:5000' }}>
      <App />
    </AuthProvider>
  );
}
```

### 3. Use Auth in Components

```tsx
// src/App.tsx
import { useAuth, PermissionGate } from 'react-headless-auth';

function App() {
  const { user, isAuthenticated, login, logout, loading } = useAuth();

  if (loading) return <div>Loading...</div>;

  if (!isAuthenticated) {
    return <LoginForm />;
  }

  return (
    <div>
      <h1>Welcome {user.email}!</h1>
      <button onClick={logout}>Logout</button>
      
      {/* Show content based on permissions */}
      <PermissionGate permission="users.view">
        <UserList />
      </PermissionGate>
    </div>
  );
}

function LoginForm() {
  const { login } = useAuth();
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await login(email, password);
    } catch (error) {
      alert('Login failed: ' + error.message);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input 
        type="email" 
        value={email} 
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Email"
      />
      <input 
        type="password" 
        value={password} 
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
      />
      <button>Login</button>
    </form>
  );
}
```

**That's it!** You now have authentication working. 🎉

---

## Setting Up RBAC (10 Minutes)

### 1. Create Permissions (Backend)

```python
# In Python console or migration script
from app import app, db
from flask_headless_auth.default_models import Permission, Role

with app.app_context():
    # Create permissions
    permissions = [
        Permission(name="users.view", category="User Management"),
        Permission(name="users.edit", category="User Management"),
        Permission(name="users.delete", category="User Management"),
        Permission(name="reports.view", category="Reports"),
        Permission(name="reports.export", category="Reports"),
    ]
    db.session.add_all(permissions)
    
    # Create roles
    admin_role = Role(name="admin", display_name="Administrator")
    user_role = Role(name="user", display_name="Regular User")
    db.session.add_all([admin_role, user_role])
    db.session.commit()
    
    # Assign all permissions to admin
    admin_role.permissions = permissions
    db.session.commit()
    
    print("✅ RBAC setup complete!")
```

### 2. Protect Backend Routes

```python
from flask_headless_auth import permission_required, role_required_authsvc

# Require specific permission
@app.route('/api/users')
@permission_required('users.view')
def list_users():
    users = User.query.all()
    return {'users': [u.to_dict() for u in users]}

# Require specific role
@app.route('/api/admin/dashboard')
@role_required_authsvc('admin')
def admin_dashboard():
    return {'message': 'Admin only content'}

# Multiple permissions (ALL required)
from flask_headless_auth import permissions_required

@app.route('/api/users/<id>', methods=['DELETE'])
@permissions_required('users.view', 'users.delete')
def delete_user(id):
    # User must have BOTH permissions
    pass
```

### 3. Protect Frontend Routes

```tsx
import { PermissionGate, useRole } from 'react-headless-auth';

function Dashboard() {
  const { hasPermission, hasRole } = useRole();

  return (
    <div>
      <h1>Dashboard</h1>
      
      {/* Show link only if user has permission */}
      {hasPermission('users.view') && (
        <a href="/users">User Management</a>
      )}
      
      {/* Or use PermissionGate component */}
      <PermissionGate permission="reports.view">
        <ReportsSection />
      </PermissionGate>
      
      {/* Check role */}
      {hasRole('admin') && (
        <a href="/admin">Admin Panel</a>
      )}
    </div>
  );
}
```

### 4. Assign Roles to Users

**Option A: Via API**
```bash
# Assign role to user
curl -X PUT http://localhost:5000/api/rbac/users/1/role \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"role_id": 1}'
```

**Option B: Via Admin Hook (React)**
```tsx
import { useAdmin } from 'react-headless-auth';

function UserManagement() {
  const adminClient = useAdmin();
  
  // Use RBACClient to assign roles
  const assignRole = async (userId, roleId) => {
    await fetch(`http://localhost:5000/api/rbac/users/${userId}/role`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ role_id: roleId })
    });
  };
}
```

**Option C: Via Database (Python)**
```python
with app.app_context():
    user = User.query.filter_by(email='admin@example.com').first()
    admin_role = Role.query.filter_by(name='admin').first()
    user.role_id = admin_role.id
    db.session.commit()
```

---

## Common API Endpoints

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/register` | POST | Register new user |
| `/api/auth/login` | POST | Login with email/password |
| `/api/auth/logout` | POST | Logout current user |
| `/api/auth/token/refresh` | POST | Refresh access token |
| `/api/auth/user/@me` | GET | Get current user profile |
| `/api/auth/update_user` | POST | Update user profile |
| `/api/auth/request-password-reset` | POST | Request password reset email |

### RBAC

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/rbac/roles` | GET | List all roles |
| `/api/rbac/roles` | POST | Create role |
| `/api/rbac/permissions` | GET | List all permissions |
| `/api/rbac/permissions` | POST | Create permission |
| `/api/rbac/roles/<id>/permissions` | PUT | Assign permissions to role |
| `/api/rbac/users/<id>/role` | PUT | Assign role to user |
| `/api/rbac/me` | GET | Get my role & permissions |

### Admin

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/users` | GET | List users (paginated) |
| `/api/admin/users` | POST | Create user |
| `/api/admin/users/<id>` | GET | Get user details |
| `/api/admin/users/<id>` | DELETE | Delete user |
| `/api/admin/users/<id>/ban` | POST | Ban user |
| `/api/admin/users/<id>/unban` | POST | Unban user |

### Audit & Sessions

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/audit/sessions/me` | GET | My active sessions |
| `/api/audit/sessions/<id>` | DELETE | Logout from device |
| `/api/audit/sessions/revoke-all` | POST | Logout all devices |
| `/api/audit/audit-logs/me` | GET | My audit history |

---

## Common React Hooks

### `useAuth()`
Main authentication hook.

```tsx
const { 
  user,                    // Current user object
  isAuthenticated,         // Boolean
  loading,                 // Initial load
  login,                   // (email, password) => Promise
  signup,                  // (credentials) => Promise
  logout,                  // () => Promise
  updateUser,              // (data) => Promise
  updatePassword,          // (current, new) => Promise
  googleLogin,             // (redirectPath?) => void
  refreshUser,             // () => Promise
  getAccessToken           // () => Promise<string>
} = useAuth();
```

### `useRole()`
Permission checking.

```tsx
const {
  role,                    // Role object
  roleName,                // String
  permissions,             // String[]
  isAdmin,                 // Boolean
  hasPermission,           // (perm: string) => boolean
  hasAllPermissions,       // (...perms: string[]) => boolean
  hasAnyPermission,        // (...perms: string[]) => boolean
  hasRole,                 // (role: string) => boolean
  hasAnyRole               // (...roles: string[]) => boolean
} = useRole();
```

### `useAdmin()`
Admin operations.

```tsx
const {
  users,                   // User[]
  total,                   // Total count
  page, pages,             // Pagination
  loading, error,          // State
  fetchUsers,              // (params?) => Promise
  getUser,                 // (userId) => Promise
  createUser,              // (data) => Promise
  deleteUser,              // (userId, hard?) => Promise
  banUser,                 // (userId, data?) => Promise
  unbanUser,               // (userId, reason?) => Promise
  getUserSessions,         // (userId) => Promise
  forceLogoutUser          // (userId) => Promise
} = useAdmin();
```

### `useSessions()`
Session management.

```tsx
const {
  sessions,                // Session[]
  loading, error,          // State
  refresh,                 // () => Promise
  revokeSession,           // (sessionId) => Promise
  revokeAllSessions        // () => Promise
} = useSessions();
```

---

## Production Configuration

### Backend (`app.py`)

```python
import os

app.config.update(
    # Security
    SECRET_KEY=os.getenv('SECRET_KEY'),
    JWT_SECRET_KEY=os.getenv('JWT_SECRET_KEY'),
    JWT_COOKIE_SECURE=True,              # HTTPS only
    AUTHSVC_FORCE_HTTPS=True,
    
    # Database
    SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL'),
    
    # CORS
    AUTHSVC_CORS_ORIGINS=['https://myapp.com'],
    
    # Sessions
    JWT_ACCESS_TOKEN_EXPIRES=900,        # 15 minutes
    JWT_REFRESH_TOKEN_EXPIRES=2592000,   # 30 days
    AUTHSVC_SESSION_INACTIVITY_TIMEOUT=30,  # 30 min
    
    # Email (deliver via hooks — see Email Hooks section)
    FRONTEND_URL='https://myapp.com',
    
    # Rate Limiting
    RATELIMIT_ENABLED=True,
    RATELIMIT_DEFAULT='5000 per hour',
    
    # Caching (Redis)
    CACHE_TYPE='RedisCache',
    CACHE_REDIS_HOST='localhost',
    AUTHSVC_CACHE_PERMISSIONS=True,
)
```

### Frontend

```tsx
const config = {
  apiBaseUrl: import.meta.env.VITE_API_URL,  // or process.env.REACT_APP_API_URL
  storageStrategy: 'cookie-first',
  enableGoogle: true,
  googleClientId: import.meta.env.VITE_GOOGLE_CLIENT_ID,
  
  hooks: {
    onAuthError: (error) => {
      // Send to error tracking
      Sentry.captureException(error);
    },
    afterLogin: (user) => {
      // Track analytics
      analytics.identify(user.id, { email: user.email });
    }
  }
};
```

---

## Key Features by Use Case

### Startup/MVP
✅ **Use these features:**
- Basic auth (email/password)
- Simple roles (admin, user)
- Protected routes
- Session management

⏭️ **Add later:**
- OAuth providers
- Advanced RBAC
- Audit logging
- Admin dashboard

---

### B2B SaaS
✅ **Use these features:**
- Multi-tenancy (built-in `tenant_id`)
- Advanced RBAC with custom permissions
- Admin APIs for user management
- Session management (multi-device)
- Audit logging

🔧 **Configuration:**
- Single session per user: `AUTHSVC_SINGLE_SESSION_PER_USER=True`
- Inactivity timeout: `AUTHSVC_SESSION_INACTIVITY_TIMEOUT=30`
- Permission caching: `AUTHSVC_CACHE_PERMISSIONS=True`

---

### Healthcare (HIPAA)
✅ **Use these features:**
- Audit logging (automatic)
- Activity logging with PHI tracking
- Resource access history
- Compliance reports
- Session tracking with IP/device

🔧 **Configuration:**
```python
@app.route('/api/patients/<id>')
@permission_required('patients.view')
@audit_action('patient.viewed', resource_type='patient', log_phi=True)
def view_patient(id):
    # Automatically logs access with phi_accessed=True
    pass
```

---

### Enterprise
✅ **Use these features:**
- Full RBAC with hierarchical permissions
- Admin APIs with ban/unban
- Bulk operations
- Audit trails
- Session management
- Rate limiting

⚠️ **Missing features:**
- SAML SSO (future)
- LDAP integration (future)
- Advanced threat detection

---

## Comparison to Competitors

| Feature | Your Stack | Supabase | Auth0 |
|---------|-----------|----------|-------|
| **Setup Time** | 5-10 min | 2 min | 2 min |
| **Cost** | $0 | $25-599/mo | $240-1000/mo |
| **RBAC** | ✅ Full API | ❌ Manual | ✅ $240+/mo |
| **Audit Logs** | ✅ Built-in | ❌ None | ✅ Enterprise |
| **Self-hosted** | ✅ Yes | ⚠️ Limited | ❌ No |
| **Custom DB** | ✅ Any SQL | ❌ PostgreSQL | ❌ Managed |
| **Learning Curve** | Medium | Easy | Easy |

**When to use this stack:**
- ✅ Need RBAC without paying $240/month
- ✅ Want self-hosted/full control
- ✅ Need audit logging/HIPAA compliance
- ✅ Building B2B SaaS with multi-tenancy
- ✅ Want custom user fields
- ✅ Using non-PostgreSQL database

**When to use Supabase:**
- ✅ Want hosted solution
- ✅ Don't need RBAC
- ✅ Using PostgreSQL
- ❌ Don't mind vendor lock-in

**When to use Auth0:**
- ✅ Need SAML/LDAP/enterprise SSO
- ✅ Have budget ($240+/month)
- ✅ Want beautiful pre-built UI
- ✅ Need 30+ OAuth providers
- ❌ Don't need custom database

---

## Troubleshooting

### "Missing Authorization Header"
**Fix:** Enable cookies or check CORS settings.
```python
app.config['AUTHSVC_CORS_ORIGINS'] = ['http://localhost:3000']
```

### "Permission denied"
**Fix:** Assign role/permissions to user.
```python
user.role_id = admin_role.id
db.session.commit()
```

### "Token expired"
**Fix:** Token refresh should happen automatically. Check:
- Frontend: `tokenRefreshInterval` config
- Backend: `JWT_ACCESS_TOKEN_EXPIRES` setting

### "CORS error"
**Fix:** Add frontend URL to CORS origins.
```python
app.config['AUTHSVC_CORS_ORIGINS'] = ['http://localhost:3000']
```

---

## Next Steps

1. **Read full documentation:** See `API_REFERENCE.md` for complete details
2. **Set up RBAC:** Create roles and permissions for your app
3. **Add OAuth:** Configure Google/Microsoft login
4. **Deploy:** Set up production environment
5. **Monitor:** Add Sentry or error tracking
6. **Scale:** Add Redis caching for high traffic

---

## Resources

- **Full API Reference:** `API_REFERENCE.md`
- **Example Apps:** `/examples` folder
- **GitHub:** [Your repo URL]
- **Issues:** [Your repo URL]/issues

---

## License

MIT License

---

**That's it!** You now have enterprise-grade authentication running. 🚀

For questions or help, open an issue on GitHub.
