# Flask Headless Auth + React Headless Auth - AI Context Document

> **Quick reference for AI assistants to understand and implement this authentication/RBAC library**

---

## Library Identity

**Name:** Flask Headless Auth (Backend) + React Headless Auth (Frontend)

**Purpose:** Production-ready authentication and RBAC system for Python (Flask) backends with JavaScript/TypeScript frontends.

**License:** MIT

**Language:** Python 3.8+ (Backend), TypeScript/JavaScript (Frontend)

**Status:** Production-ready, feature-complete

---

## Core Value Proposition

This is a **complete, self-hosted authentication system** that provides:

1. **Authentication**: Email/password, OAuth (Google, Microsoft), JWT sessions
2. **RBAC**: Full role-based access control with granular permissions
3. **Admin APIs**: User management, ban/unban, bulk operations
4. **Audit Logging**: Automatic tracking of all auth events, HIPAA-compliant
5. **Session Management**: Multi-device sessions with fingerprinting
6. **Multi-tenancy**: Built-in tenant isolation

**Key Differentiator:** Provides Auth0-level RBAC features for free, with full database control and self-hosting.

---

## Architecture

```
Frontend (React/Vue/Angular)
    ↓ REST API (JSON)
Backend (Flask)
    ↓ SQLAlchemy
Database (PostgreSQL/MySQL/SQLite/etc)
```

**Token Strategy:** JWT with HttpOnly cookies (default) or localStorage  
**Session Storage:** Database-backed with automatic tracking  
**Permission Model:** `resource.action` format (e.g., `users.view`, `patients.edit`)

---

## Installation

### Backend
```python
# Install dependencies
pip install flask flask-sqlalchemy flask-jwt-extended flask-cors

# Initialize in Flask app
from flask_headless_auth import FlaskHeadlessAuth
auth = FlaskHeadlessAuth(app, db)
auth.create_tables()  # Creates all required tables
```

### Frontend
```bash
npm install react-headless-auth
```

```tsx
import { AuthProvider } from 'react-headless-auth';

<AuthProvider config={{ apiBaseUrl: 'http://localhost:5000' }}>
  <App />
</AuthProvider>
```

---

## Backend API Endpoints

### Authentication (`/api/auth`)
- `POST /register` - Register new user (returns tokens + user)
- `POST /login` - Email/password login (returns tokens + user)
- `POST /logout` - Logout (blacklists token, revokes session)
- `POST /token/refresh` - Refresh access token
- `GET /check-auth` - Check if authenticated
- `GET /user/@me` - Get current user profile
- `POST /update_user` - Update user profile
- `POST /upload-profile-picture` - Upload profile picture
- `POST /request-password-reset` - Request password reset email
- `POST /reset-password` - Reset password with token
- `GET /confirm/<token>` - Email verification
- `POST /resend-verification-email` - Resend verification
- `GET /login/google` - Initiate Google OAuth
- `GET /login/microsoft` - Initiate Microsoft OAuth

### RBAC (`/api/rbac`)
**Roles:**
- `GET /roles` - List all roles
- `POST /roles` - Create role
- `GET /roles/<id>` - Get role
- `PUT /roles/<id>` - Update role
- `DELETE /roles/<id>` - Delete role
- `POST /roles/<id>/clone` - Clone role with permissions

**Permissions:**
- `GET /permissions` - List permissions (filterable by category/resource)
- `POST /permissions` - Create permission
- `POST /permissions/bulk` - Bulk create permissions
- `GET /permissions/<id>` - Get permission
- `PUT /permissions/<id>` - Update permission
- `DELETE /permissions/<id>` - Delete permission

**Role-Permission Assignment:**
- `GET /roles/<id>/permissions` - Get role's permissions
- `PUT /roles/<id>/permissions` - Sync permissions (replace all)
- `POST /roles/<id>/permissions` - Add permissions (additive)
- `DELETE /roles/<id>/permissions` - Remove permissions

**User-Role Assignment:**
- `GET /users/<id>/role` - Get user's role
- `PUT /users/<id>/role` - Assign role to user
- `DELETE /users/<id>/role` - Revoke role from user
- `GET /users?role_id=<id>` - List users by role (paginated)

**Current User:**
- `GET /me` - Get my role & permissions
- `GET /me/permissions` - Get my permissions list
- `POST /me/check` - Batch check permissions

**Import/Export:**
- `GET /export` - Export RBAC config as JSON
- `POST /import` - Import RBAC config from JSON

### Admin (`/api/admin`)
- `GET /users` - List users (paginated, filterable)
- `POST /users` - Create user (admin onboarding)
- `GET /users/<id>` - Get user details + sessions
- `DELETE /users/<id>` - Delete user (soft/hard)
- `POST /users/<id>/ban` - Ban/deactivate user
- `POST /users/<id>/unban` - Unban/reactivate user
- `GET /users/<id>/sessions` - View user sessions
- `POST /users/<id>/sessions/revoke-all` - Force logout user

### Audit & Sessions (`/api/audit`)
- `GET /sessions/me` - My active sessions
- `DELETE /sessions/<id>` - Logout from specific device
- `POST /sessions/revoke-all` - Logout all devices
- `GET /audit-logs/me` - My audit history
- `GET /audit-logs` - All audit logs (admin)
- `GET /audit-logs/security` - Security events (admin)
- `GET /activity-logs/me` - My activity logs
- `GET /activity-logs/resource/<type>/<id>` - Resource access history
- `GET /compliance/phi-access-report` - PHI access report (admin)
- `GET /compliance/security-summary` - Security dashboard (admin)

---

## Backend Protection Decorators

```python
from flask_headless_auth import (
    permission_required,
    permissions_required,
    any_permission,
    role_required_authsvc,
    roles_required,
    audit_action
)

# Single permission
@app.route('/api/users')
@permission_required('users.view')
def list_users():
    pass

# Multiple permissions (ALL required)
@app.route('/api/users/<id>', methods=['DELETE'])
@permissions_required('users.view', 'users.delete')
def delete_user(id):
    pass

# Any permission (OR)
@app.route('/api/reports')
@any_permission('reports.view', 'reports.export')
def reports():
    pass

# Role-based
@app.route('/api/admin')
@role_required_authsvc('admin')
def admin_panel():
    pass

# Audit logging
@app.route('/api/patients/<id>')
@permission_required('patients.view')
@audit_action('patient.viewed', resource_type='patient', log_phi=True)
def view_patient(id):
    # Automatically logged with phi_accessed=True for HIPAA
    pass
```

**Runtime Permission Checking:**
```python
from flask_headless_auth import PermissionChecker
from flask_jwt_extended import get_jwt_identity

checker = PermissionChecker(user_id, auth.db, auth.user_repository)
if checker.has_permission('users.edit'):
    # Allow edit
    pass
```

---

## Frontend React Hooks

### `useAuth()`
Main authentication hook.

```tsx
const {
  user,                    // User object | null
  isAuthenticated,         // boolean
  loading,                 // boolean (initial load)
  isRefreshingToken,       // boolean
  login,                   // (email, password) => Promise<void>
  signup,                  // (credentials) => Promise<void>
  logout,                  // () => Promise<void>
  refreshUser,             // () => Promise<void>
  refreshAccessToken,      // () => Promise<void>
  updateUser,              // (data) => Promise<void>
  updatePassword,          // (current, new) => Promise<void>
  googleLogin,             // (redirectPath?) => void
  microsoftLogin,          // (redirectPath?) => void
  checkAuth,               // () => Promise<boolean>
  getAccessToken           // (options?) => Promise<string | null>
} = useAuth();
```

### `useRole()`
Permission and role checking.

```tsx
const {
  role,                    // Role object | null
  roleId,                  // number | null
  roleName,                // string | null
  permissions,             // string[]
  isAdmin,                 // boolean
  loading,                 // boolean
  hasRole,                 // (roleName: string) => boolean
  hasAnyRole,              // (...roleNames: string[]) => boolean
  hasPermission,           // (permission: string) => boolean
  hasAllPermissions,       // (...permissions: string[]) => boolean
  hasAnyPermission         // (...permissions: string[]) => boolean
} = useRole();
```

### `useAdmin()`
Admin operations.

```tsx
const {
  users,                   // User[]
  total,                   // number
  page, pages,             // number
  loading, error,          // boolean, string | null
  fetchUsers,              // (params?) => Promise<void>
  getUser,                 // (userId) => Promise<User>
  createUser,              // (data) => Promise<User>
  deleteUser,              // (userId, hard?) => Promise<void>
  banUser,                 // (userId, data?) => Promise<void>
  unbanUser,               // (userId, reason?) => Promise<void>
  getUserSessions,         // (userId) => Promise<Session[]>
  forceLogoutUser          // (userId) => Promise<void>
} = useAdmin();
```

### `useSessions()`
Session management.

```tsx
const {
  sessions,                // Session[]
  loading, error,          // boolean, string | null
  refresh,                 // () => Promise<void>
  revokeSession,           // (sessionId) => Promise<void>
  revokeAllSessions        // () => Promise<void>
} = useSessions();
```

### `useAuditLogs()`
Audit and activity logging.

```tsx
const {
  auditLogs,               // AuditLog[]
  activityLogs,            // ActivityLog[]
  loading, error,          // boolean, string | null
  fetchAuditLogs,          // (options?) => Promise<void>
  fetchActivityLogs,       // (options?) => Promise<void>
  fetchResourceHistory     // (type, id) => Promise<ActivityLog[]>
} = useAuditLogs();
```

---

## Frontend Components

### `PermissionGate`
Conditional rendering based on permissions/roles.

```tsx
// Single permission
<PermissionGate permission="users.view">
  <UserList />
</PermissionGate>

// Multiple permissions (ANY)
<PermissionGate permissions={["users.view", "reports.view"]}>
  <Dashboard />
</PermissionGate>

// Multiple permissions (ALL required)
<PermissionGate permissions={["users.view", "users.edit"]} requireAll={true}>
  <UserEditor />
</PermissionGate>

// Role-based
<PermissionGate role="admin">
  <AdminPanel />
</PermissionGate>

// With fallback
<PermissionGate permission="premium.feature" fallback={<UpgradePrompt />}>
  <PremiumFeature />
</PermissionGate>
```

### `RoleGate`
Role-only convenience component.

```tsx
<RoleGate role="admin">
  <AdminPanel />
</RoleGate>

<RoleGate roles={["admin", "manager"]}>
  <ManagementTools />
</RoleGate>
```

### `SessionManager`
Pre-built UI for managing active sessions.

```tsx
<SessionManager 
  onSessionRevoked={(sessionId) => console.log('Revoked:', sessionId)}
  onAllSessionsRevoked={() => console.log('All revoked')}
  renderSession={(session) => <CustomSessionItem session={session} />}
/>
```

### `AuditLogViewer`
Pre-built UI for viewing audit logs.

```tsx
<AuditLogViewer 
  type="audit"  // or "activity"
  action="user.login"  // optional filter
  limit={50}
  renderLog={(log) => <CustomLogItem log={log} />}
/>
```

---

## Data Models

### User
```python
{
  "id": int,
  "email": str,
  "first_name": str | None,
  "last_name": str | None,
  "phone_number": str | None,
  "profile_picture_url": str | None,
  "role_id": int | None,
  "role_name": str | None,
  "permissions": list[str],
  "is_active": bool,
  "is_verified": bool,
  "last_login_at": datetime | None,
  "created_at": datetime,
  "tenant_id": str | None
}
```

### Role
```python
{
  "id": int,
  "name": str,              # lowercase, alphanumeric + underscore
  "display_name": str,
  "description": str | None,
  "is_system": bool,
  "permissions": list[Permission]  # if included
}
```

### Permission
```python
{
  "id": int,
  "name": str,              # format: "resource.action"
  "resource": str,          # auto-extracted (e.g., "users")
  "action": str,            # auto-extracted (e.g., "view")
  "category": str | None,
  "description": str | None,
  "is_system": bool
}
```

### Session
```python
{
  "session_id": str,        # UUID
  "device_name": str,       # "Chrome on macOS"
  "device_fingerprint": str,# SHA-256 hash
  "ip_address": str,
  "user_agent": str,
  "country": str | None,
  "city": str | None,
  "created_at": datetime,
  "last_activity": datetime,
  "expires_at": datetime,
  "is_active": bool,
  "revoked": bool,
  "revoked_at": datetime | None,
  "revoke_reason": str | None
}
```

### AuditLog
```python
{
  "id": int,
  "timestamp": datetime,
  "action": str,            # e.g., "user.login", "rbac.role_assigned"
  "actor_user_id": int | None,
  "target_user_id": int | None,
  "ip_address": str | None,
  "user_agent": str | None,
  "session_id": str | None,
  "tenant_id": str | None,
  "success": bool,
  "error_message": str | None,
  "metadata": dict | None
}
```

---

## Configuration

### Backend (Flask)

**Minimal:**
```python
app.config['SECRET_KEY'] = 'your-secret'
app.config['JWT_SECRET_KEY'] = 'your-jwt-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://localhost/db'
```

**Production:**
```python
app.config.update(
    # JWT
    JWT_ACCESS_TOKEN_EXPIRES=900,          # 15 min
    JWT_REFRESH_TOKEN_EXPIRES=2592000,     # 30 days
    JWT_COOKIE_SECURE=True,                # HTTPS only
    JWT_COOKIE_HTTPONLY=True,
    JWT_COOKIE_SAMESITE='Strict',
    
    # Token delivery
    AUTHSVC_TOKEN_DELIVERY='cookies_only', # or 'body_only', 'dual'
    
    # RBAC
    AUTHSVC_CACHE_PERMISSIONS=True,
    AUTHSVC_PERMISSION_CACHE_TTL=300,      # 5 min
    
    # Sessions
    AUTHSVC_SESSION_INACTIVITY_TIMEOUT=30, # 30 min
    AUTHSVC_SINGLE_SESSION_PER_USER=False,
    
    # Security
    AUTHSVC_MAX_LOGIN_ATTEMPTS=5,
    AUTHSVC_LOGIN_ATTEMPT_WINDOW=30,       # 30 min
    AUTHSVC_FORCE_HTTPS=True,
    AUTHSVC_CORS_ORIGINS=['https://app.com'],
    
    # Email
    EMAIL_SERVICE='gmail',                 # or 'brevo'
    MAIL_USERNAME='email@gmail.com',
    MAIL_PASSWORD='app-password',
    
    # OAuth
    GOOGLE_CLIENT_ID='...',
    GOOGLE_CLIENT_SECRET='...',
    POST_LOGIN_REDIRECT_URL='https://app.com/dashboard',
    
    # Rate limiting
    RATELIMIT_ENABLED=True,
    RATELIMIT_DEFAULT='5000 per hour',
    
    # Caching
    CACHE_TYPE='RedisCache',
    CACHE_REDIS_HOST='localhost',
)
```

### Frontend (React)

**Minimal:**
```typescript
const config = {
  apiBaseUrl: 'http://localhost:5000'
};
```

**Production:**
```typescript
const config = {
  apiBaseUrl: 'https://api.myapp.com',
  
  // Storage
  storageStrategy: 'cookie-first',  // or 'localStorage-only', 'auto'
  
  // Token refresh
  tokenRefreshInterval: 3300000,    // 55 min
  
  // OAuth
  enableGoogle: true,
  googleClientId: '...',
  enableMicrosoft: false,
  microsoftClientId: '...',
  
  // RBAC
  rbac: {
    autoFetchPermissions: true,
    permissionCacheTTL: 300000      // 5 min
  },
  
  // Custom headers
  customHeaders: {
    'X-App-Version': '1.0.0'
  },
  
  // Lifecycle hooks
  hooks: {
    afterLogin: (user) => analytics.identify(user.id),
    onAuthError: (error) => Sentry.captureException(error),
    transformUser: (user) => ({
      ...user,
      fullName: `${user.first_name} ${user.last_name}`
    })
  },
  
  // Logging
  debug: false,
  logLevel: 'warn'
};
```

---

## Common Patterns

### Pattern 1: Complete RBAC Setup

```python
# 1. Create permissions
permissions = [
    Permission(name="users.view", category="User Management"),
    Permission(name="users.edit", category="User Management"),
    Permission(name="users.delete", category="User Management"),
]
db.session.add_all(permissions)

# 2. Create roles
admin_role = Role(name="admin", display_name="Administrator")
user_role = Role(name="user", display_name="Regular User")
db.session.add_all([admin_role, user_role])

# 3. Assign permissions to roles
admin_role.permissions = permissions
user_role.permissions = [permissions[0]]  # Only users.view

# 4. Assign role to user
user.role_id = admin_role.id
db.session.commit()
```

### Pattern 2: Protected Route (Backend)

```python
@app.route('/api/sensitive-data')
@permission_required('data.view_sensitive')
@audit_action('data.viewed_sensitive', log_phi=True)
def get_sensitive_data():
    data = SensitiveData.query.all()
    return jsonify([d.to_dict() for d in data])
```

### Pattern 3: Protected Route (Frontend)

```tsx
<Route path="/admin" element={
  <PermissionGate role="admin" fallback={<Navigate to="/403" />}>
    <AdminDashboard />
  </PermissionGate>
} />
```

### Pattern 4: Multi-Tenancy

```python
# Backend
@app.route('/api/data')
@jwt_required()
def get_data():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    # Filter by tenant
    data = Data.query.filter_by(tenant_id=user.tenant_id).all()
    return jsonify([d.to_dict() for d in data])
```

### Pattern 5: Lifecycle Hooks

```python
# Backend
@auth.hook('before_signup')
def validate_domain(user_data):
    if not user_data['email'].endswith('@company.com'):
        raise ValueError('Only company emails allowed')

@auth.hook('after_login')
def track_login(user):
    analytics.track(user.id, 'Login', {'email': user.email})
```

```typescript
// Frontend
const config = {
  hooks: {
    afterLogin: (user) => {
      analytics.identify(user.id, { email: user.email });
      localStorage.setItem('lastLogin', new Date().toISOString());
    }
  }
};
```

---

## Database Schema

**Tables Created:**
1. `authsvc_users` - User accounts
2. `authsvc_roles` - Role definitions
3. `authsvc_permissions` - Permission definitions
4. `authsvc_role_permissions` - Role-permission mapping (M2M)
5. `authsvc_user_sessions` - Active sessions
6. `authsvc_blacklisted_tokens` - Revoked JWT tokens
7. `authsvc_audit_log_entries` - Audit trail
8. `authsvc_activity_logs` - Application activity
9. `authsvc_mfa_tokens` - MFA tokens (future)
10. `authsvc_password_reset_tokens` - Password reset tokens
11. `authsvc_oauth_tokens` - OAuth tokens

**Custom Prefix:**
```python
app.config['AUTHSVC_TABLE_PREFIX'] = 'myapp'
# Tables will be named: myapp_users, myapp_roles, etc.
```

---

## Extension Points

### Custom User Model

```python
from flask_headless_auth.mixins import UserMixin

class CustomUser(db.Model, UserMixin):
    __tablename__ = 'users'
    
    # Required fields from UserMixin
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password_hash = db.Column(db.String(255))
    # ... other UserMixin fields
    
    # Custom fields
    company_id = db.Column(db.String(50))
    department = db.Column(db.String(100))
    employee_id = db.Column(db.String(50))

# Use custom model
auth = FlaskHeadlessAuth(app, db, user_model=CustomUser)
```

### Custom Hooks (Backend)

Available hooks:
- `before_signup`, `after_signup`
- `before_login`, `after_login`
- `before_logout`, `after_logout`
- `custom_access_token` - Modify JWT claims
- `before_token_refresh`, `after_token_refresh`
- `before_password_change`, `after_password_change`
- `before_mfa_verify`, `after_mfa_verify`
- `on_oauth_login`
- `before_role_assign`, `after_role_assign`

### Storage Adapters (Frontend)

```typescript
// Custom storage adapter
class CustomStorageAdapter implements StorageAdapter {
  async getItem(key: string): Promise<string | null> {
    // Custom implementation
  }
  
  async setItem(key: string, value: string): Promise<void> {
    // Custom implementation
  }
  
  async removeItem(key: string): Promise<void> {
    // Custom implementation
  }
}
```

---

## Security Features

1. **JWT Token Blacklisting** - Revoked tokens stored in database
2. **Brute Force Protection** - Configurable max attempts per IP
3. **Session Tracking** - Device fingerprinting, IP tracking
4. **Inactivity Timeout** - Auto-logout after inactivity
5. **Single Session Mode** - Enforce one session per user
6. **Password Hashing** - pbkdf2:sha256
7. **HTTPS Enforcement** - Force secure connections
8. **CORS Protection** - Configurable origins
9. **Rate Limiting** - Flask-Limiter integration
10. **Audit Logging** - All actions tracked automatically

---

## Comparison Matrix

| Feature | This Library | Supabase | Auth0 |
|---------|--------------|----------|-------|
| **Setup Time** | 5-10 min | 2 min | 2 min |
| **Cost** | $0 | $25-599/mo | $240+/mo |
| **RBAC** | ✅ Full | ❌ Manual | ✅ $240+ |
| **Audit Logs** | ✅ Yes | ❌ No | ✅ Enterprise |
| **Self-hosted** | ✅ Yes | ⚠️ Limited | ❌ No |
| **Custom DB** | ✅ Any SQL | ❌ PostgreSQL | ❌ Managed |
| **Admin APIs** | ✅ Yes | ⚠️ Dashboard | ✅ Yes |
| **Session Mgmt** | ✅ Full | ✅ Pro+ | ✅ Yes |
| **Multi-tenancy** | ✅ Built-in | ⚠️ Manual | ✅ Orgs |
| **Permissions** | ✅ Full API | ⚠️ RLS only | ✅ Yes |
| **OAuth Providers** | 2 (G, MS) | 10+ | 30+ |
| **Admin UI** | ❌ No | ✅ Yes | ✅ Yes |
| **SAML/LDAP** | ❌ No | ❌ No | ✅ Enterprise |

**Best For:**
- ✅ B2B SaaS with RBAC needs
- ✅ Healthcare apps (HIPAA compliance)
- ✅ Cost-sensitive projects
- ✅ Self-hosted requirements
- ✅ Custom database requirements
- ✅ Multi-tenant applications

---

## Common Use Cases & Implementation

### Use Case 1: Healthcare App (HIPAA)

**Requirements:** Track all PHI access for compliance.

```python
# Backend
@app.route('/api/patients/<id>')
@permission_required('patients.view')
@audit_action('patient.viewed', resource_type='patient', log_phi=True)
def view_patient(id):
    patient = Patient.query.get_or_404(id)
    return jsonify(patient.to_dict())

# Generate compliance report
@app.route('/api/compliance/phi-report')
@role_required_authsvc('admin')
def phi_report():
    return redirect('/api/audit/compliance/phi-access-report')
```

```tsx
// Frontend - Show access history
function PatientRecord({ patientId }) {
  const { fetchResourceHistory } = useAuditLogs();
  
  useEffect(() => {
    fetchResourceHistory('patient', patientId)
      .then(history => setAccessHistory(history));
  }, [patientId]);
  
  return <AccessHistoryTable history={accessHistory} />;
}
```

### Use Case 2: B2B SaaS Multi-Tenant

**Requirements:** Isolate data by tenant, RBAC per tenant.

```python
# Backend - Custom user model
class User(db.Model, UserMixin):
    tenant_id = db.Column(db.String(50), nullable=False)
    company_name = db.Column(db.String(255))

# Filter by tenant automatically
@app.route('/api/records')
@jwt_required()
@permission_required('records.view')
def get_records():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    records = Record.query.filter_by(tenant_id=user.tenant_id).all()
    return jsonify([r.to_dict() for r in records])
```

### Use Case 3: Admin Dashboard

```tsx
function AdminDashboard() {
  const { users, fetchUsers, banUser, deleteUser } = useAdmin();
  
  useEffect(() => {
    fetchUsers({ page: 1, per_page: 20 });
  }, []);
  
  return (
    <PermissionGate role="admin">
      <UserTable 
        users={users}
        onBan={(userId) => banUser(userId, { reason: 'Violation' })}
        onDelete={(userId) => deleteUser(userId)}
      />
    </PermissionGate>
  );
}
```

---

## Error Handling

**Backend Errors:**
```json
{
  "error": "Error message",
  "details": "Additional info",
  "code": "ERROR_CODE"
}
```

**Common Codes:**
- `UNAUTHORIZED` (401) - Not logged in
- `FORBIDDEN` (403) - No permission
- `VALIDATION_ERROR` (400) - Invalid input
- `RATE_LIMIT_EXCEEDED` (429) - Too many requests
- `NOT_FOUND` (404) - Resource not found

**Frontend Handling:**
```tsx
try {
  await login(email, password);
} catch (error) {
  if (error.code === 'UNAUTHORIZED') {
    setError('Invalid credentials');
  } else if (error.code === 'RATE_LIMIT_EXCEEDED') {
    setError('Too many attempts');
  } else {
    setError(error.message);
  }
}
```

---

## Performance Optimization

1. **Enable Permission Caching:**
```python
app.config['AUTHSVC_CACHE_PERMISSIONS'] = True
app.config['AUTHSVC_PERMISSION_CACHE_TTL'] = 300  # 5 min
```

2. **Use Redis for Caching:**
```python
app.config['CACHE_TYPE'] = 'RedisCache'
app.config['CACHE_REDIS_HOST'] = 'localhost'
```

3. **Frontend Permission Caching:**
```typescript
const config = {
  rbac: {
    permissionCacheTTL: 300000  // 5 min
  }
};
```

4. **Database Indexes:** All tables have appropriate indexes on frequently queried columns.

---

## Testing

**Backend:**
```python
def test_permission_decorator():
    # Create user with permission
    user = create_user_with_permission('users.view')
    token = login_user(user)
    
    # Test protected endpoint
    response = client.get('/api/users', 
                         headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
```

**Frontend:**
```tsx
test('PermissionGate shows content when permitted', () => {
  render(
    <PermissionGate permission="users.view">
      <div>Protected Content</div>
    </PermissionGate>
  );
  
  expect(screen.getByText('Protected Content')).toBeInTheDocument();
});
```

---

## Migration Guide

### From Supabase Auth:

1. **Replace client:**
```typescript
// Before (Supabase)
import { createClient } from '@supabase/supabase-js'
const supabase = createClient(URL, KEY)
const { data, error } = await supabase.auth.signUp({ email, password })

// After (This library)
import { useAuth } from 'react-headless-auth'
const { signup } = useAuth()
await signup({ email, password })
```

2. **RBAC:** Build using provided APIs instead of RLS policies.

3. **Protected Routes:** Use `PermissionGate` instead of manual checks.

### From Auth0:

1. **Replace provider:**
```typescript
// Before (Auth0)
import { Auth0Provider } from '@auth0/auth0-react'

// After (This library)
import { AuthProvider } from 'react-headless-auth'
```

2. **RBAC:** Use built-in RBAC APIs instead of Auth0 Management API.

3. **Self-host:** Deploy your own backend instead of Auth0 cloud.

---

## Production Checklist

**Backend:**
- ✅ Set strong SECRET_KEY and JWT_SECRET_KEY
- ✅ Use production database (PostgreSQL)
- ✅ Enable HTTPS (JWT_COOKIE_SECURE=True)
- ✅ Configure CORS for specific origins
- ✅ Set up Redis caching
- ✅ Configure email service
- ✅ Enable rate limiting
- ✅ Set session timeouts
- ✅ Configure OAuth (if needed)
- ✅ Set up monitoring

**Frontend:**
- ✅ Set production API URL
- ✅ Use cookie-first strategy
- ✅ Enable error tracking
- ✅ Test all protected routes
- ✅ Configure OAuth redirects
- ✅ Test token refresh

---

## Key Insights for AI Assistants

1. **Permission Format:** Always use `resource.action` (e.g., `users.view`, not `view_users`)

2. **Backend First:** Always protect routes on backend, frontend is convenience only

3. **Audit Everything:** Use `@audit_action` decorator for sensitive operations

4. **Multi-tenancy:** Use `tenant_id` field in custom user model

5. **Token Strategy:** Default is HttpOnly cookies (most secure)

6. **RBAC Pattern:** Create permissions → Create roles → Assign permissions to roles → Assign roles to users

7. **Session Management:** Built-in device tracking, use `SessionManager` component

8. **Extensibility:** Use hooks for custom logic (before/after actions)

9. **Testing:** Use decorators on test routes, test both allowed and denied cases

10. **Error Handling:** Always wrap auth operations in try-catch

---

## Quick Reference Commands

**Create all tables:**
```python
with app.app_context():
    auth.create_tables()
```

**Create admin user:**
```python
admin_role = Role(name='admin', display_name='Administrator')
user = User(email='admin@example.com', role=admin_role)
user.set_password('SecurePass123!')
db.session.add_all([admin_role, user])
db.session.commit()
```

**Bulk create permissions:**
```bash
curl -X POST http://localhost:5000/api/rbac/permissions/bulk \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"permissions": [...]}'
```

**Export RBAC config:**
```bash
curl http://localhost:5000/api/rbac/export \
  -H "Authorization: Bearer <token>" > rbac-config.json
```

---

## Support Resources

- **Full API Docs:** `API_REFERENCE.md` (150+ pages)
- **Quick Start:** `QUICK_START.md` (10-minute setup)
- **This Document:** `AI_CONTEXT.md` (AI assistant reference)

---

**END OF AI CONTEXT DOCUMENT**

This document is optimized for AI assistants to quickly understand and implement Flask Headless Auth + React Headless Auth in any application.
