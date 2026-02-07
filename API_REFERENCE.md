# Flask Headless Auth + React Headless Auth - Complete API Reference

> **Complete authentication, RBAC, admin management, and audit logging system for Python (Flask) backends and JavaScript/TypeScript frontends.**

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Quick Setup](#quick-setup)
3. [Backend API Reference](#backend-api-reference)
4. [Frontend SDK Reference](#frontend-sdk-reference)
5. [Configuration](#configuration)
6. [Complete RBAC Guide](#complete-rbac-guide)
7. [Common Use Cases](#common-use-cases)

---

## Overview

### What Is This?

A **complete, production-ready authentication and authorization system** that provides:

- ✅ **Authentication**: Email/password, OAuth (Google, Microsoft), session management
- ✅ **RBAC**: Full role-based access control with permissions
- ✅ **Admin APIs**: User management, ban/unban, session control
- ✅ **Audit Logging**: Automatic tracking of all auth events, HIPAA-compliant
- ✅ **Multi-tenancy**: Built-in tenant isolation
- ✅ **Extensible**: Hooks, custom models, database-agnostic

### Architecture

```
┌─────────────────────────────────────────┐
│   Frontend (React/Vue/Angular/etc)     │
│   - react-headless-auth SDK             │
│   - Hooks, Components, Type-safe        │
└─────────────────┬───────────────────────┘
                  │ REST API
┌─────────────────▼───────────────────────┐
│   Backend (Flask)                       │
│   - flask-headless-auth                 │
│   - JWT tokens, Sessions, RBAC          │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│   Database (PostgreSQL/MySQL/SQLite)    │
│   - Users, Roles, Permissions, Audit    │
└─────────────────────────────────────────┘
```

### Key Features vs Competitors

| Feature | This Stack | Supabase | Auth0 |
|---------|-----------|----------|-------|
| **RBAC** | ✅ Full API | ❌ Manual | ✅ $240/mo+ |
| **Audit Logs** | ✅ Built-in | ❌ None | ✅ Enterprise |
| **Cost** | 💰 Free | 💰 $25-599/mo | 💰 $240-1000/mo |
| **Custom DB** | ✅ Any SQL | ❌ PostgreSQL only | ❌ Managed |
| **Self-hosted** | ✅ Full control | ⚠️ Limited | ❌ Cloud only |

---

## Quick Setup

### Backend Setup (5 minutes)

**1. Install the package:**
```bash
pip install flask-headless-auth  # When published
# OR clone and install locally
```

**2. Initialize in your Flask app:**
```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_headless_auth import FlaskHeadlessAuth

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://localhost/mydb'
app.config['JWT_SECRET_KEY'] = 'your-jwt-secret-here'

# Optional email config for password reset/verification
app.config['EMAIL_SERVICE'] = 'gmail'  # or 'brevo'
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-app-password'

db = SQLAlchemy(app)
auth = FlaskHeadlessAuth(app, db)

# Create tables
with app.app_context():
    auth.create_tables()

if __name__ == '__main__':
    app.run(debug=True)
```

**3. That's it!** You now have 50+ API endpoints ready to use.

---

### Frontend Setup (React) - 2 minutes

**1. Install the package:**
```bash
npm install react-headless-auth  # When published
# OR clone and install locally
```

**2. Wrap your app with AuthProvider:**
```tsx
import { AuthProvider } from 'react-headless-auth';

function App() {
  return (
    <AuthProvider config={{ 
      apiBaseUrl: 'http://localhost:5000',
      storageStrategy: 'cookie-first' // or 'localStorage-only'
    }}>
      <YourApp />
    </AuthProvider>
  );
}
```

**3. Use hooks in your components:**
```tsx
import { useAuth, useRole } from 'react-headless-auth';

function Dashboard() {
  const { user, logout } = useAuth();
  const { hasPermission } = useRole();

  if (hasPermission('dashboard.view')) {
    return <div>Welcome {user.email}!</div>;
  }
  return <div>Access Denied</div>;
}
```

---

## Backend API Reference

### Authentication Endpoints (`/api/auth`)

#### **POST /api/auth/register**
Register a new user.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1234567890"  // optional
}
```

**Response (200):**
```json
{
  "message": "User registered successfully",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "first_name": "John",
    "is_verified": false,
    "role_id": null
  },
  "access_token": "eyJ0eXAi...",  // if token_delivery is 'body_only' or 'dual'
  "refresh_token": "eyJ0eXAi..."
}
```

**Features:**
- Auto-login after registration
- Email verification token sent automatically
- Configurable: require email verification before login
- Fires hooks: `before_signup`, `after_signup`

---

#### **POST /api/auth/login**
Login with email and password.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response (200):**
```json
{
  "message": "Login successful",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "role_id": 2,
    "role_name": "admin",
    "permissions": ["users.view", "users.edit"]
  },
  "access_token": "eyJ0eXAi...",
  "refresh_token": "eyJ0eXAi..."
}
```

**Features:**
- Brute-force protection (configurable max attempts)
- Account status validation (`is_active`, `is_verified`)
- Creates session with device fingerprinting
- Updates `last_login_at`
- Fires hooks: `before_login`, `after_login`

**Error Responses:**
- `401`: Invalid credentials
- `403`: Account inactive or unverified
- `429`: Too many login attempts

---

#### **POST /api/auth/logout**
Logout current user.

**Headers:**
```
Authorization: Bearer <access_token>
Cookie: access_token_cookie=...
```

**Response (200):**
```json
{
  "message": "Logged out successfully"
}
```

**Features:**
- Blacklists JWT token
- Revokes current session
- Clears cookies
- Audit logging

---

#### **POST /api/auth/token/refresh**
Refresh access token using refresh token.

**Request:** No body needed (uses refresh token from cookie or Authorization header)

**Response (200):**
```json
{
  "access_token": "eyJ0eXAi...",
  "refresh_token": "eyJ0eXAi..."  // new refresh token
}
```

**Features:**
- Validates inactivity timeout
- Updates session `last_activity`
- Issues new token pair
- Checks session is still active

---

#### **GET /api/auth/check-auth**
Check if user is authenticated.

**Headers:** Include access token

**Response (200):**
```json
{
  "authenticated": true,
  "user": {
    "id": 1,
    "email": "user@example.com",
    "role_name": "admin"
  }
}
```

---

#### **GET /api/auth/user/@me**
Get current user profile.

**Headers:** Include access token

**Response (200):**
```json
{
  "id": 1,
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1234567890",
  "profile_picture_url": "https://...",
  "role_id": 2,
  "role_name": "admin",
  "is_active": true,
  "is_verified": true,
  "last_login_at": "2026-02-06T10:30:00Z",
  "created_at": "2026-01-01T00:00:00Z"
}
```

**Features:**
- Optional caching (configure with `CACHE_TYPE`)
- Composable serialization

---

#### **POST /api/auth/update_user**
Update current user profile.

**Headers:** Include access token

**Request:**
```json
{
  "first_name": "Jane",
  "last_name": "Smith",
  "phone_number": "+9876543210",
  "password": "NewSecurePass123!"  // optional
}
```

**Response (200):**
```json
{
  "message": "User updated successfully",
  "user": { /* updated user object */ }
}
```

**Features:**
- Protected fields: `id`, `email`, `role_id`, `password_hash`, etc. cannot be changed
- Field validation (email format, phone format, text lengths, dates)
- Password update support (hashed automatically)
- Cache invalidation
- Fires hooks: `before_user_update`, `after_user_update`

---

#### **POST /api/auth/upload-profile-picture**
Upload user profile picture.

**Headers:** Include access token

**Request:** `multipart/form-data`
```
file: <image file>
```

**Response (200):**
```json
{
  "message": "Profile picture uploaded successfully",
  "url": "/uploads/profile_pictures/user_1_abc123.jpg"
}
```

**Features:**
- File type validation (PNG, JPG, GIF, WebP)
- Size limits: 100 bytes - 5MB
- Filename sanitization
- TODO: S3/CDN integration (currently local storage)

---

#### **POST /api/auth/request-password-reset**
Request password reset email.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response (200):**
```json
{
  "message": "Password reset email sent if user exists"
}
```

**Features:**
- Generates secure token (UUID)
- 1-hour expiration
- Audit logging
- Returns same message even if user doesn't exist (security)

---

#### **POST /api/auth/reset-password**
Reset password using token from email.

**Request:**
```json
{
  "token": "abc123...",
  "new_password": "NewSecurePass123!"
}
```

**Response (200):**
```json
{
  "message": "Password reset successfully"
}
```

---

#### **GET /api/auth/confirm/<token>**
Confirm email verification.

**Response (200):**
```json
{
  "message": "Email verified successfully"
}
```

**Features:**
- Sets `is_verified=True`
- Redirects to configured URL

---

#### **POST /api/auth/resend-verification-email**
Resend email verification.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response (200):**
```json
{
  "message": "Verification email sent"
}
```

---

### OAuth Endpoints (`/api/auth`)

#### **GET /api/auth/login/google**
Initiate Google OAuth flow.

**Query Parameters:**
- `redirect_uri` (optional): Frontend URL to redirect after auth

**Response:** Redirects to Google login page

---

#### **GET /api/auth/auth/google/callback**
Google OAuth callback (handled automatically).

**Response:** Redirects to frontend with tokens

---

#### **GET /api/auth/login/microsoft**
Initiate Microsoft OAuth flow.

**Query Parameters:**
- `redirect_uri` (optional): Frontend URL to redirect after auth

**Response:** Redirects to Microsoft login page

---

#### **GET /api/auth/auth/microsoft/callback**
Microsoft OAuth callback (handled automatically).

**Response:** Redirects to frontend with tokens

---

### RBAC Endpoints (`/api/rbac`)

#### **Role Management**

##### **GET /api/rbac/roles**
List all roles.

**Query Parameters:**
- `include_permissions=true` (optional): Include permissions in response

**Response (200):**
```json
{
  "roles": [
    {
      "id": 1,
      "name": "admin",
      "display_name": "Administrator",
      "description": "Full system access",
      "is_system": true,
      "permissions": ["users.view", "users.edit", ...]  // if include_permissions=true
    },
    {
      "id": 2,
      "name": "user",
      "display_name": "Regular User",
      "description": "Basic access",
      "is_system": false
    }
  ]
}
```

---

##### **POST /api/rbac/roles**
Create a new role.

**Headers:** Requires `rbac.admin` permission

**Request:**
```json
{
  "name": "manager",
  "display_name": "Manager",
  "description": "Department manager role",
  "is_system": false
}
```

**Response (201):**
```json
{
  "message": "Role created successfully",
  "role": {
    "id": 3,
    "name": "manager",
    "display_name": "Manager"
  }
}
```

**Validation:**
- `name`: lowercase, alphanumeric + underscore only
- `name` must be unique
- System roles cannot be deleted

---

##### **GET /api/rbac/roles/<role_id>**
Get role details.

**Response (200):**
```json
{
  "id": 1,
  "name": "admin",
  "display_name": "Administrator",
  "description": "Full system access",
  "is_system": true,
  "created_at": "2026-01-01T00:00:00Z"
}
```

---

##### **PUT /api/rbac/roles/<role_id>**
Update role.

**Headers:** Requires `rbac.admin` permission

**Request:**
```json
{
  "display_name": "Super Administrator",
  "description": "Updated description"
}
```

**Response (200):**
```json
{
  "message": "Role updated successfully",
  "role": { /* updated role */ }
}
```

**Note:** Cannot update `name` of existing role

---

##### **DELETE /api/rbac/roles/<role_id>**
Delete role.

**Headers:** Requires `rbac.admin` permission

**Query Parameters:**
- `force=true` (optional): Force delete even if users assigned

**Response (200):**
```json
{
  "message": "Role deleted successfully"
}
```

**Error (400):** If users assigned and `force=false`

---

##### **POST /api/rbac/roles/<role_id>/clone**
Clone role with all permissions.

**Headers:** Requires `rbac.admin` permission

**Request:**
```json
{
  "new_name": "senior_manager",
  "display_name": "Senior Manager",
  "description": "Cloned from manager"
}
```

**Response (201):**
```json
{
  "message": "Role cloned successfully",
  "role": { /* new role */ }
}
```

---

#### **Permission Management**

##### **GET /api/rbac/permissions**
List all permissions.

**Query Parameters:**
- `category=<string>` (optional): Filter by category
- `resource=<string>` (optional): Filter by resource (e.g., "users")

**Response (200):**
```json
{
  "permissions": [
    {
      "id": 1,
      "name": "users.view",
      "resource": "users",
      "action": "view",
      "category": "User Management",
      "description": "View user list",
      "is_system": false
    },
    {
      "id": 2,
      "name": "users.edit",
      "resource": "users",
      "action": "edit",
      "category": "User Management"
    }
  ]
}
```

---

##### **POST /api/rbac/permissions**
Create permission.

**Headers:** Requires `rbac.admin` permission

**Request:**
```json
{
  "name": "patients.view",
  "category": "Healthcare",
  "description": "View patient records"
}
```

**Response (201):**
```json
{
  "message": "Permission created successfully",
  "permission": {
    "id": 10,
    "name": "patients.view",
    "resource": "patients",  // auto-extracted
    "action": "view"         // auto-extracted
  }
}
```

**Validation:**
- Format: `resource.action` (e.g., `patients.view`, `billing.manage`)
- Pattern: `^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`
- Must be unique

---

##### **POST /api/rbac/permissions/bulk**
Bulk create permissions.

**Headers:** Requires `rbac.admin` permission

**Request:**
```json
{
  "permissions": [
    {
      "name": "patients.view",
      "category": "Healthcare",
      "description": "View patients"
    },
    {
      "name": "patients.edit",
      "category": "Healthcare",
      "description": "Edit patients"
    },
    {
      "name": "patients.delete",
      "category": "Healthcare",
      "description": "Delete patients"
    }
  ]
}
```

**Response (201):**
```json
{
  "message": "3 permissions created successfully",
  "permissions": [ /* array of created permissions */ ]
}
```

---

##### **PUT /api/rbac/permissions/<permission_id>**
Update permission.

**Headers:** Requires `rbac.admin` permission

**Request:**
```json
{
  "description": "Updated description",
  "category": "Updated Category"
}
```

**Response (200):**
```json
{
  "message": "Permission updated successfully"
}
```

**Note:** Cannot update `name` of existing permission

---

##### **DELETE /api/rbac/permissions/<permission_id>**
Delete permission.

**Headers:** Requires `rbac.admin` permission

**Query Parameters:**
- `force=true` (optional): Force delete even if assigned to roles

**Response (200):**
```json
{
  "message": "Permission deleted successfully"
}
```

---

#### **Role-Permission Assignment**

##### **GET /api/rbac/roles/<role_id>/permissions**
Get permissions for a role.

**Response (200):**
```json
{
  "role_id": 1,
  "permissions": [
    {
      "id": 1,
      "name": "users.view",
      "resource": "users",
      "action": "view"
    },
    {
      "id": 2,
      "name": "users.edit"
    }
  ]
}
```

---

##### **PUT /api/rbac/roles/<role_id>/permissions**
Sync permissions (replace all).

**Headers:** Requires `rbac.admin` permission

**Request:**
```json
{
  "permission_ids": [1, 2, 5, 8]
}
```

**Response (200):**
```json
{
  "message": "Role permissions synced successfully",
  "added": 2,
  "removed": 1
}
```

**Features:**
- Replaces all permissions with new list
- Audit logging

---

##### **POST /api/rbac/roles/<role_id>/permissions**
Add permissions (additive).

**Headers:** Requires `rbac.admin` permission

**Request:**
```json
{
  "permission_ids": [10, 11, 12]
}
```

**Response (200):**
```json
{
  "message": "Permissions added to role",
  "added": 3
}
```

**Features:**
- Adds to existing permissions
- Skips duplicates

---

##### **DELETE /api/rbac/roles/<role_id>/permissions**
Remove permissions from role.

**Headers:** Requires `rbac.admin` permission

**Request:**
```json
{
  "permission_ids": [5, 8]
}
```

**Response (200):**
```json
{
  "message": "Permissions removed from role",
  "removed": 2
}
```

---

#### **User-Role Assignment**

##### **GET /api/rbac/users/<user_id>/role**
Get user's role.

**Response (200):**
```json
{
  "user_id": 1,
  "role": {
    "id": 2,
    "name": "manager",
    "display_name": "Manager"
  },
  "permissions": ["users.view", "reports.view"]
}
```

---

##### **PUT /api/rbac/users/<user_id>/role**
Assign role to user.

**Headers:** Requires `rbac.admin` permission

**Request:**
```json
{
  "role_id": 2
}
```

**Response (200):**
```json
{
  "message": "Role assigned successfully",
  "user_id": 1,
  "role_id": 2
}
```

**Features:**
- Fires hooks: `before_role_assign`, `after_role_assign`
- Audit logging
- Invalidates permission cache

---

##### **DELETE /api/rbac/users/<user_id>/role**
Revoke role from user.

**Headers:** Requires `rbac.admin` permission

**Response (200):**
```json
{
  "message": "Role revoked successfully"
}
```

**Features:**
- Sets `role_id` to NULL
- Audit logging

---

##### **GET /api/rbac/users?role_id=<role_id>**
List users by role (paginated).

**Query Parameters:**
- `role_id`: Filter by role
- `page`: Page number (default: 1)
- `per_page`: Items per page (default: 20, max: 100)

**Response (200):**
```json
{
  "users": [
    {
      "id": 1,
      "email": "user@example.com",
      "first_name": "John",
      "role_id": 2
    }
  ],
  "total": 50,
  "page": 1,
  "pages": 3
}
```

---

#### **Current User RBAC**

##### **GET /api/rbac/me**
Get current user's role and permissions.

**Headers:** Include access token

**Response (200):**
```json
{
  "user_id": 1,
  "role": {
    "id": 2,
    "name": "manager",
    "display_name": "Manager"
  },
  "permissions": [
    "users.view",
    "reports.view",
    "reports.edit"
  ]
}
```

---

##### **GET /api/rbac/me/permissions**
Get current user's permissions list.

**Headers:** Include access token

**Response (200):**
```json
{
  "permissions": ["users.view", "reports.view", "reports.edit"]
}
```

---

##### **POST /api/rbac/me/check**
Batch check permissions.

**Headers:** Include access token

**Request:**
```json
{
  "permissions": ["users.view", "users.delete", "reports.edit"]
}
```

**Response (200):**
```json
{
  "results": {
    "users.view": true,
    "users.delete": false,
    "reports.edit": true
  }
}
```

---

#### **Import/Export**

##### **GET /api/rbac/export**
Export RBAC configuration.

**Headers:** Requires `rbac.admin` permission

**Response (200):**
```json
{
  "roles": [ /* all roles */ ],
  "permissions": [ /* all permissions */ ],
  "role_permissions": [ /* mappings */ ]
}
```

---

##### **POST /api/rbac/import**
Import RBAC configuration.

**Headers:** Requires `rbac.admin` permission

**Request:**
```json
{
  "roles": [ /* roles to create */ ],
  "permissions": [ /* permissions to create */ ],
  "role_permissions": [ /* mappings */ ]
}
```

**Response (200):**
```json
{
  "message": "RBAC configuration imported successfully"
}
```

---

### Admin Endpoints (`/api/admin`)

#### **User Management**

##### **GET /api/admin/users**
List users (paginated, filterable).

**Headers:** Requires admin role

**Query Parameters:**
- `page`: Page number (default: 1)
- `per_page`: Items per page (default: 20, max: 100)
- `is_active`: Filter by active status (`true`/`false`)
- `role_id`: Filter by role
- `q`: Search by email (partial match, case-insensitive)

**Response (200):**
```json
{
  "users": [
    {
      "id": 1,
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "role_id": 2,
      "role_name": "manager",
      "is_active": true,
      "is_verified": true,
      "last_login_at": "2026-02-06T10:30:00Z",
      "created_at": "2026-01-01T00:00:00Z"
    }
  ],
  "total": 150,
  "page": 1,
  "pages": 8
}
```

---

##### **POST /api/admin/users**
Create user (admin onboarding).

**Headers:** Requires admin role

**Request:**
```json
{
  "email": "newuser@example.com",
  "password": "SecurePass123!",
  "first_name": "Jane",
  "last_name": "Smith",
  "role_id": 2,
  "is_verified": true,
  "send_invite": true  // optional: send welcome email
}
```

**Response (201):**
```json
{
  "message": "User created successfully",
  "user": {
    "id": 42,
    "email": "newuser@example.com",
    "is_verified": true
  }
}
```

**Features:**
- Bypasses self-registration flow
- `is_verified=True` by default
- Optional welcome email

---

##### **GET /api/admin/users/<user_id>**
Get user details.

**Headers:** Requires admin role

**Response (200):**
```json
{
  "id": 1,
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "role_id": 2,
  "role_name": "manager",
  "is_active": true,
  "is_verified": true,
  "last_login_at": "2026-02-06T10:30:00Z",
  "created_at": "2026-01-01T00:00:00Z",
  "active_sessions_count": 2,
  "ban_history": []
}
```

---

##### **DELETE /api/admin/users/<user_id>**
Delete user.

**Headers:** Requires admin role

**Query Parameters:**
- `hard=true` (optional): Permanently delete (default: soft delete)

**Response (200):**
```json
{
  "message": "User deleted successfully",
  "sessions_revoked": 2
}
```

**Features:**
- **Soft delete** (default): Sets `is_active=False`, anonymizes email
- **Hard delete**: Permanently removes from database
- Revokes all sessions
- Audit logging

---

##### **POST /api/admin/users/<user_id>/ban**
Ban/deactivate user.

**Headers:** Requires admin role

**Request:**
```json
{
  "reason": "Violated terms of service",
  "duration_minutes": 10080  // optional: 7 days
}
```

**Response (200):**
```json
{
  "message": "User banned successfully",
  "sessions_revoked": 2
}
```

**Features:**
- Sets `is_active=False`
- Revokes all sessions (immediate lockout)
- Stores ban reason in metadata
- Audit logging

---

##### **POST /api/admin/users/<user_id>/unban**
Unban/reactivate user.

**Headers:** Requires admin role

**Request:**
```json
{
  "reason": "Ban period expired"  // optional
}
```

**Response (200):**
```json
{
  "message": "User unbanned successfully"
}
```

**Features:**
- Sets `is_active=True`
- User can log in again
- Audit logging

---

#### **Session Management**

##### **GET /api/admin/users/<user_id>/sessions**
View all sessions for a user.

**Headers:** Requires admin role

**Response (200):**
```json
{
  "sessions": [
    {
      "session_id": "abc123...",
      "device_name": "Chrome on macOS",
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "country": "US",
      "city": "San Francisco",
      "created_at": "2026-02-06T10:00:00Z",
      "last_activity": "2026-02-06T10:30:00Z",
      "is_active": true,
      "revoked": false
    },
    {
      "session_id": "def456...",
      "device_name": "Safari on iOS",
      "is_active": false,
      "revoked": true,
      "revoked_at": "2026-02-05T12:00:00Z",
      "revoke_reason": "user_logout"
    }
  ]
}
```

---

##### **POST /api/admin/users/<user_id>/sessions/revoke-all**
Force logout user from all devices.

**Headers:** Requires admin role

**Response (200):**
```json
{
  "message": "All sessions revoked",
  "sessions_revoked": 3
}
```

**Features:**
- Revokes all active sessions
- User must login again
- Audit logging

---

### Audit Endpoints (`/api/audit`)

#### **Audit Logs**

##### **GET /api/audit/audit-logs/me**
Get current user's audit history.

**Headers:** Include access token

**Query Parameters:**
- `action`: Filter by action type (e.g., `user.login`)
- `limit`: Number of logs (default: 50, max: 100)

**Response (200):**
```json
{
  "logs": [
    {
      "id": 1,
      "timestamp": "2026-02-06T10:30:00Z",
      "action": "user.login",
      "actor_user_id": 1,
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "session_id": "abc123...",
      "success": true,
      "metadata": {
        "device": "Chrome on macOS"
      }
    },
    {
      "timestamp": "2026-02-06T09:15:00Z",
      "action": "user.profile_update",
      "success": true
    }
  ]
}
```

**Audit Actions:**
- Auth: `user.signup`, `user.login`, `user.logout`, `user.login_failed`
- Tokens: `token.refresh`, `token.revoked`
- Sessions: `session.created`, `session.revoked`, `session.expired`
- Account: `user.password_change`, `user.password_reset_request`, `user.email_verification`, `user.profile_update`
- Admin: `user.banned`, `user.unbanned`, `user.admin_created`, `user.soft_deleted`, `user.hard_deleted`
- RBAC: `rbac.role_assigned`, `rbac.role_revoked`, `rbac.permission_changed`

---

##### **GET /api/audit/audit-logs**
Get all audit logs (admin only).

**Headers:** Requires admin role

**Query Parameters:**
- `action`: Filter by action
- `actor_user_id`: Filter by user
- `target_user_id`: Filter by target
- `success`: Filter by success (`true`/`false`)
- `limit`: Number of logs

**Response (200):** Same format as `/me` endpoint

---

##### **GET /api/audit/audit-logs/security**
Get security events (admin only).

**Headers:** Requires admin role

**Response (200):**
```json
{
  "logs": [
    {
      "timestamp": "2026-02-06T10:00:00Z",
      "action": "user.login_failed",
      "ip_address": "192.168.1.200",
      "success": false,
      "error_message": "Invalid credentials",
      "metadata": {
        "attempt_number": 3
      }
    }
  ]
}
```

**Includes:**
- Failed login attempts
- Brute-force incidents
- Token revocations
- Session hijacking attempts

---

#### **Session Management**

##### **GET /api/audit/sessions/me**
Get current user's active sessions.

**Headers:** Include access token

**Response (200):**
```json
{
  "sessions": [
    {
      "session_id": "abc123...",
      "device_name": "Chrome on macOS",
      "ip_address": "192.168.1.100",
      "created_at": "2026-02-06T10:00:00Z",
      "last_activity": "2026-02-06T10:30:00Z",
      "is_current": true
    },
    {
      "session_id": "def456...",
      "device_name": "Safari on iOS",
      "ip_address": "192.168.1.101",
      "created_at": "2026-02-05T08:00:00Z",
      "last_activity": "2026-02-06T09:00:00Z",
      "is_current": false
    }
  ]
}
```

---

##### **DELETE /api/audit/sessions/<session_id>**
Revoke specific session (logout from device).

**Headers:** Include access token

**Response (200):**
```json
{
  "message": "Session revoked successfully"
}
```

**Features:**
- Logout from specific device
- Cannot revoke current session (use `/logout`)

---

##### **POST /api/audit/sessions/revoke-all**
Logout from all devices except current.

**Headers:** Include access token

**Response (200):**
```json
{
  "message": "All other sessions revoked",
  "sessions_revoked": 2
}
```

---

#### **Activity Logs**

##### **GET /api/audit/activity-logs/me**
Get current user's application activity.

**Headers:** Include access token

**Query Parameters:**
- `action`: Filter by action type
- `resource_type`: Filter by resource
- `limit`: Number of logs

**Response (200):**
```json
{
  "logs": [
    {
      "timestamp": "2026-02-06T10:30:00Z",
      "action": "patient.viewed",
      "user_id": 1,
      "resource_type": "patient",
      "resource_id": "123",
      "ip_address": "192.168.1.100",
      "phi_accessed": true,
      "metadata": {
        "patient_name": "John Doe"
      }
    }
  ]
}
```

**Features:**
- HIPAA compliance (`phi_accessed` flag)
- Custom action tracking
- Resource-level tracking

---

##### **GET /api/audit/activity-logs/resource/<resource_type>/<resource_id>**
Get resource access history.

**Headers:** Requires appropriate permissions

**Response (200):**
```json
{
  "resource_type": "patient",
  "resource_id": "123",
  "access_history": [
    {
      "timestamp": "2026-02-06T10:30:00Z",
      "action": "patient.viewed",
      "user_id": 1,
      "user_email": "doctor@example.com",
      "ip_address": "192.168.1.100"
    }
  ]
}
```

**Use Case:**
- Track who accessed patient record (HIPAA)
- Track who modified financial record
- Compliance reporting

---

#### **Compliance Reports**

##### **GET /api/audit/compliance/phi-access-report**
PHI access report (admin only).

**Headers:** Requires admin role

**Query Parameters:**
- `start_date`: Start date (default: 30 days ago)
- `end_date`: End date (default: now)
- `user_id`: Filter by user (optional)

**Response (200):**
```json
{
  "period": {
    "start": "2026-01-07T00:00:00Z",
    "end": "2026-02-06T23:59:59Z"
  },
  "total_phi_accesses": 1250,
  "by_user": [
    {
      "user_id": 1,
      "email": "doctor@example.com",
      "access_count": 300,
      "resources_accessed": ["patient:123", "patient:456"]
    }
  ],
  "by_resource_type": {
    "patient": 1000,
    "medical_record": 250
  }
}
```

---

##### **GET /api/audit/compliance/security-summary**
Security dashboard (admin only).

**Headers:** Requires admin role

**Query Parameters:**
- `days`: Period (default: 30)

**Response (200):**
```json
{
  "period_days": 30,
  "metrics": {
    "total_logins": 5000,
    "failed_logins": 150,
    "signups": 200,
    "password_changes": 50,
    "active_sessions": 850,
    "phi_accesses": 1250,
    "banned_users": 5
  },
  "top_failed_ips": [
    {
      "ip_address": "192.168.1.200",
      "failed_attempts": 25
    }
  ]
}
```

---

## Frontend SDK Reference

### Core Clients

#### **AuthClient**

Main authentication client (framework-agnostic).

**Import:**
```typescript
import { AuthClient } from 'react-headless-auth';
```

**Initialization:**
```typescript
const authClient = new AuthClient({
  apiBaseUrl: 'http://localhost:5000',
  apiPrefix: '/api/auth',  // optional
  storageStrategy: 'cookie-first',  // or 'localStorage-only'
  tokenRefreshInterval: 3300000,  // 55 minutes (optional)
  enableGoogle: true,  // optional
  googleClientId: 'YOUR_GOOGLE_CLIENT_ID',  // optional
  enableMicrosoft: false,  // optional
  customHeaders: {  // optional
    'X-App-Version': '1.0.0'
  }
});
```

**Methods:**

```typescript
// Authentication
await authClient.login(email: string, password: string)
await authClient.signup(credentials: SignupCredentials)
await authClient.logout()
await authClient.checkAuth()

// User management
const user = await authClient.getUser()
await authClient.updateUser(data: UpdateUserData)
await authClient.updatePassword(currentPassword: string, newPassword: string)

// Token management
const token = await authClient.getAccessToken(options?)
await authClient.refreshToken()

// OAuth
const url = authClient.getOAuthUrl('google', 'http://localhost:3000/callback')
authClient.googleLogin(redirectPath?)
authClient.microsoftLogin(redirectPath?)
```

**Types:**
```typescript
interface SignupCredentials {
  email: string;
  password: string;
  first_name?: string;
  last_name?: string;
  phone_number?: string;
}

interface UpdateUserData {
  first_name?: string;
  last_name?: string;
  phone_number?: string;
  password?: string;
}

interface User {
  id: number;
  email: string;
  first_name?: string;
  last_name?: string;
  phone_number?: string;
  profile_picture_url?: string;
  role_id?: number;
  role_name?: string;
  permissions?: string[];
  is_active: boolean;
  is_verified: boolean;
  last_login_at?: string;
  created_at: string;
}
```

---

#### **RBACClient**

RBAC management client.

**Import:**
```typescript
import { RBACClient } from 'react-headless-auth';
```

**Initialization:**
```typescript
const rbacClient = new RBACClient({
  apiBaseUrl: 'http://localhost:5000',
  rbacPrefix: '/api/rbac',  // optional
  autoFetchPermissions: true,  // optional
  permissionCacheTTL: 300000  // 5 minutes (optional)
});
```

**Methods:**

```typescript
// Roles
await rbacClient.listRoles(includePermissions?: boolean)
await rbacClient.getRole(roleId: number)
await rbacClient.createRole(data: CreateRoleInput)
await rbacClient.updateRole(roleId: number, data: UpdateRoleInput)
await rbacClient.deleteRole(roleId: number, force?: boolean)
await rbacClient.cloneRole(roleId: number, newName: string, description?: string)

// Permissions
await rbacClient.listPermissions(filters?: { category?: string, resource?: string })
await rbacClient.getPermission(permissionId: number)
await rbacClient.createPermission(data: CreatePermissionInput)
await rbacClient.updatePermission(permissionId: number, data: UpdatePermissionInput)
await rbacClient.deletePermission(permissionId: number, force?: boolean)
await rbacClient.createPermissionsBulk(permissions: CreatePermissionInput[])

// Role-Permission assignment
await rbacClient.getRolePermissions(roleId: number)
await rbacClient.syncRolePermissions(roleId: number, permissionIds: number[])
await rbacClient.addRolePermissions(roleId: number, permissionIds: number[])
await rbacClient.removeRolePermissions(roleId: number, permissionIds: number[])

// User-Role assignment
await rbacClient.getUserRole(userId: number)
await rbacClient.assignRoleToUser(userId: number, roleId: number)
await rbacClient.revokeRoleFromUser(userId: number)
await rbacClient.listUsersByRole(roleId: number, page?: number, perPage?: number)

// Current user
await rbacClient.getMyRole()
await rbacClient.getMyPermissions()
await rbacClient.checkMyPermissions(permissions: string[])

// Import/Export
await rbacClient.exportConfig()
await rbacClient.importConfig(data: RBACConfig)
```

**Types:**
```typescript
interface Role {
  id: number;
  name: string;
  display_name: string;
  description?: string;
  is_system: boolean;
  permissions?: Permission[];
}

interface Permission {
  id: number;
  name: string;
  resource: string;
  action: string;
  category?: string;
  description?: string;
  is_system: boolean;
}

interface CreateRoleInput {
  name: string;
  display_name: string;
  description?: string;
  is_system?: boolean;
}

interface CreatePermissionInput {
  name: string;  // format: "resource.action"
  category?: string;
  description?: string;
}
```

---

#### **AdminClient**

Admin management client.

**Import:**
```typescript
import { AdminClient } from 'react-headless-auth';
```

**Initialization:**
```typescript
const adminClient = new AdminClient({
  apiBaseUrl: 'http://localhost:5000',
  adminPrefix: '/api/admin'  // optional
});
```

**Methods:**

```typescript
// User management
await adminClient.listUsers(params?: ListUsersParams)
await adminClient.getUser(userId: number)
await adminClient.createUser(data: CreateUserInput)
await adminClient.deleteUser(userId: number, hard?: boolean)
await adminClient.banUser(userId: number, data?: BanUserInput)
await adminClient.unbanUser(userId: number, reason?: string)

// Session management
await adminClient.getUserSessions(userId: number)
await adminClient.forceLogoutUser(userId: number)
```

**Types:**
```typescript
interface ListUsersParams {
  page?: number;
  per_page?: number;
  is_active?: boolean;
  role_id?: number;
  q?: string;  // email search
}

interface CreateUserInput {
  email: string;
  password: string;
  first_name?: string;
  last_name?: string;
  phone_number?: string;
  role_id?: number;
  is_verified?: boolean;
  send_invite?: boolean;
}

interface BanUserInput {
  reason?: string;
  duration_minutes?: number;
}

interface AdminSession {
  session_id: string;
  device_name: string;
  ip_address: string;
  user_agent: string;
  created_at: string;
  last_activity: string;
  is_active: boolean;
  revoked: boolean;
}
```

---

### React Hooks

#### **useAuth()**

Main authentication hook with full user management.

**Import:**
```typescript
import { useAuth } from 'react-headless-auth';
```

**Usage:**
```typescript
function MyComponent() {
  const {
    // State
    user,
    isAuthenticated,
    loading,
    isRefreshingToken,
    
    // Actions
    login,
    signup,
    logout,
    refreshUser,
    refreshAccessToken,
    updateUser,
    updatePassword,
    googleLogin,
    microsoftLogin,
    checkAuth,
    getAccessToken
  } = useAuth();

  // Example: Login
  const handleLogin = async () => {
    try {
      await login('user@example.com', 'password123');
      // User is now logged in, user state is updated
    } catch (error) {
      console.error('Login failed:', error.message);
    }
  };

  // Example: Update profile
  const handleUpdate = async () => {
    await updateUser({ first_name: 'Jane', last_name: 'Doe' });
  };

  if (loading) return <div>Loading...</div>;
  if (!isAuthenticated) return <LoginForm onLogin={handleLogin} />;

  return <div>Welcome {user.email}!</div>;
}
```

**Return Value:**
```typescript
interface UseAuthReturn {
  user: User | null;
  isAuthenticated: boolean;
  loading: boolean;
  isRefreshingToken: boolean;
  
  login: (email: string, password: string) => Promise<void>;
  signup: (credentials: SignupCredentials) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  refreshAccessToken: () => Promise<void>;
  updateUser: (data: UpdateUserData) => Promise<void>;
  updatePassword: (current: string, newPassword: string) => Promise<void>;
  googleLogin: (redirectPath?: string) => void;
  microsoftLogin: (redirectPath?: string) => void;
  checkAuth: () => Promise<boolean>;
  getAccessToken: (options?: GetTokenOptions) => Promise<string | null>;
}
```

---

#### **useUser()**

Simplified hook for user data and updates.

**Import:**
```typescript
import { useUser } from 'react-headless-auth';
```

**Usage:**
```typescript
function UserProfile() {
  const { user, refreshUser, updateUser, isLoading } = useUser();

  if (!user) return null;

  return (
    <div>
      <h1>{user.first_name} {user.last_name}</h1>
      <p>{user.email}</p>
      <button onClick={() => refreshUser()}>Refresh</button>
    </div>
  );
}
```

---

#### **useSession()**

Session state and token management.

**Import:**
```typescript
import { useSession } from 'react-headless-auth';
```

**Usage:**
```typescript
function SessionInfo() {
  const { isAuthenticated, loading, isRefreshingToken, refreshToken, checkAuth } = useSession();

  return (
    <div>
      <p>Status: {isAuthenticated ? 'Logged in' : 'Logged out'}</p>
      <p>Refreshing: {isRefreshingToken ? 'Yes' : 'No'}</p>
      <button onClick={refreshToken}>Refresh Token</button>
      <button onClick={checkAuth}>Check Auth</button>
    </div>
  );
}
```

---

#### **useRole()**

Role and permission checking.

**Import:**
```typescript
import { useRole } from 'react-headless-auth';
```

**Usage:**
```typescript
function Dashboard() {
  const {
    role,
    roleId,
    roleName,
    permissions,
    isAdmin,
    loading,
    hasRole,
    hasAnyRole,
    hasPermission,
    hasAllPermissions,
    hasAnyPermission
  } = useRole();

  // Check single role
  if (hasRole('admin')) {
    return <AdminDashboard />;
  }

  // Check multiple roles
  if (hasAnyRole('admin', 'manager')) {
    return <ManagerDashboard />;
  }

  // Check single permission
  if (hasPermission('users.view')) {
    return <UserList />;
  }

  // Check all permissions
  if (hasAllPermissions('users.view', 'users.edit')) {
    return <UserEditor />;
  }

  // Check any permission
  if (hasAnyPermission('reports.view', 'analytics.view')) {
    return <ReportsPage />;
  }

  return <AccessDenied />;
}
```

**Return Value:**
```typescript
interface UseRoleReturn {
  role: Role | null;
  roleId: number | null;
  roleName: string | null;
  permissions: string[];
  isAdmin: boolean;
  loading: boolean;
  
  hasRole: (roleName: string) => boolean;
  hasAnyRole: (...roleNames: string[]) => boolean;
  hasPermission: (permission: string) => boolean;
  hasAllPermissions: (...permissions: string[]) => boolean;
  hasAnyPermission: (...permissions: string[]) => boolean;
}
```

---

#### **useAdmin()**

Admin user management operations.

**Import:**
```typescript
import { useAdmin } from 'react-headless-auth';
```

**Usage:**
```typescript
function AdminPanel() {
  const {
    users,
    total,
    page,
    pages,
    loading,
    error,
    fetchUsers,
    getUser,
    createUser,
    deleteUser,
    banUser,
    unbanUser,
    getUserSessions,
    forceLogoutUser
  } = useAdmin();

  useEffect(() => {
    // Load first page
    fetchUsers({ page: 1, per_page: 20 });
  }, []);

  const handleBanUser = async (userId: number) => {
    await banUser(userId, {
      reason: 'Violated terms',
      duration_minutes: 10080  // 7 days
    });
    // Refresh list
    fetchUsers();
  };

  return (
    <div>
      <h1>Users ({total})</h1>
      {loading && <p>Loading...</p>}
      {error && <p>Error: {error}</p>}
      <table>
        {users.map(user => (
          <tr key={user.id}>
            <td>{user.email}</td>
            <td>{user.role_name}</td>
            <td>
              <button onClick={() => handleBanUser(user.id)}>Ban</button>
              <button onClick={() => deleteUser(user.id)}>Delete</button>
            </td>
          </tr>
        ))}
      </table>
      <Pagination page={page} pages={pages} />
    </div>
  );
}
```

---

#### **useSessions()**

User session management.

**Import:**
```typescript
import { useSessions } from 'react-headless-auth';
```

**Usage:**
```typescript
function ActiveSessions() {
  const {
    sessions,
    loading,
    error,
    refresh,
    revokeSession,
    revokeAllSessions
  } = useSessions();

  useEffect(() => {
    refresh();
  }, []);

  return (
    <div>
      <h2>Active Sessions</h2>
      {sessions.map(session => (
        <div key={session.session_id}>
          <p>{session.device_name}</p>
          <p>{session.ip_address}</p>
          <p>{session.created_at}</p>
          {session.is_current ? (
            <span>Current Session</span>
          ) : (
            <button onClick={() => revokeSession(session.session_id)}>
              Logout
            </button>
          )}
        </div>
      ))}
      <button onClick={revokeAllSessions}>Logout All Other Devices</button>
    </div>
  );
}
```

---

#### **useAuditLogs()**

Audit logging and activity history.

**Import:**
```typescript
import { useAuditLogs } from 'react-headless-auth';
```

**Usage:**
```typescript
function AuditHistory() {
  const {
    auditLogs,
    activityLogs,
    loading,
    error,
    fetchAuditLogs,
    fetchActivityLogs,
    fetchResourceHistory
  } = useAuditLogs();

  useEffect(() => {
    // Fetch user's authentication events
    fetchAuditLogs({ action: 'user.login', limit: 50 });
  }, []);

  // Fetch resource access history (HIPAA)
  const viewPatientHistory = async (patientId: string) => {
    const history = await fetchResourceHistory('patient', patientId);
    console.log('Patient access history:', history);
  };

  return (
    <div>
      <h2>Recent Logins</h2>
      {auditLogs.map(log => (
        <div key={log.id}>
          <p>{log.timestamp}</p>
          <p>{log.action}</p>
          <p>{log.ip_address}</p>
          <p>Success: {log.success ? 'Yes' : 'No'}</p>
        </div>
      ))}
    </div>
  );
}
```

---

### React Components

#### **PermissionGate**

Conditional rendering based on permissions or roles.

**Import:**
```typescript
import { PermissionGate } from 'react-headless-auth';
```

**Usage:**

```typescript
// Single permission
<PermissionGate permission="users.view">
  <UserList />
</PermissionGate>

// Multiple permissions (ANY)
<PermissionGate permissions={["users.view", "reports.view"]}>
  <Dashboard />
</PermissionGate>

// Multiple permissions (ALL required)
<PermissionGate 
  permissions={["users.view", "users.edit"]} 
  requireAll={true}
>
  <UserEditor />
</PermissionGate>

// Single role
<PermissionGate role="admin">
  <AdminPanel />
</PermissionGate>

// Multiple roles (ANY)
<PermissionGate roles={["admin", "manager"]}>
  <ManagementTools />
</PermissionGate>

// With fallback
<PermissionGate 
  permission="premium.features"
  fallback={<UpgradeBanner />}
>
  <PremiumFeatures />
</PermissionGate>

// With loading state
<PermissionGate 
  permission="users.view"
  loading={<Spinner />}
>
  <UserList />
</PermissionGate>
```

**Props:**
```typescript
interface PermissionGateProps {
  // Permission-based
  permission?: string;
  permissions?: string[];
  requireAll?: boolean;  // default: false (ANY)
  
  // Role-based
  role?: string;
  roles?: string[];
  
  // UI
  fallback?: React.ReactNode;
  loading?: React.ReactNode;
  
  // Children
  children: React.ReactNode;
}
```

---

#### **RoleGate**

Convenience component for role-only checks.

**Import:**
```typescript
import { RoleGate } from 'react-headless-auth';
```

**Usage:**
```typescript
// Single role
<RoleGate role="admin">
  <AdminPanel />
</RoleGate>

// Multiple roles
<RoleGate roles={["admin", "manager"]}>
  <ManagementTools />
</RoleGate>
```

---

#### **SessionManager**

Pre-built UI component for managing active sessions.

**Import:**
```typescript
import { SessionManager } from 'react-headless-auth';
```

**Usage:**
```typescript
function AccountSettings() {
  return (
    <div>
      <h1>Active Devices</h1>
      <SessionManager 
        onSessionRevoked={(sessionId) => {
          console.log('Session revoked:', sessionId);
        }}
        onAllSessionsRevoked={() => {
          console.log('All sessions revoked');
        }}
        // Optional: custom rendering
        renderSession={(session) => (
          <div>
            <h3>{session.device_name}</h3>
            <p>{session.ip_address} - {session.city}, {session.country}</p>
            <p>Last active: {session.last_activity}</p>
          </div>
        )}
        // Optional: custom loading/error
        showLoading={true}
        loadingComponent={<Spinner />}
        errorComponent={<ErrorAlert />}
      />
    </div>
  );
}
```

**Props:**
```typescript
interface SessionManagerProps {
  onSessionRevoked?: (sessionId: string) => void;
  onAllSessionsRevoked?: () => void;
  renderSession?: (session: Session) => React.ReactNode;
  showLoading?: boolean;
  loadingComponent?: React.ReactNode;
  errorComponent?: React.ReactNode;
}
```

---

#### **AuditLogViewer**

Pre-built UI component for viewing audit logs and activity.

**Import:**
```typescript
import { AuditLogViewer } from 'react-headless-auth';
```

**Usage:**
```typescript
function SecurityLog() {
  return (
    <div>
      <h1>Security Events</h1>
      
      {/* Audit logs (authentication events) */}
      <AuditLogViewer 
        type="audit"
        action="user.login"  // optional filter
        limit={50}
        renderLog={(log) => (
          <div>
            <p>{log.action}</p>
            <p>{log.timestamp}</p>
            <p>{log.ip_address}</p>
            <span className={log.success ? 'success' : 'failure'}>
              {log.success ? '✓' : '✗'}
            </span>
          </div>
        )}
      />
      
      {/* Activity logs (application events) */}
      <AuditLogViewer 
        type="activity"
        limit={100}
      />
    </div>
  );
}
```

**Props:**
```typescript
interface AuditLogViewerProps {
  type: 'audit' | 'activity';
  action?: string;
  limit?: number;
  renderLog?: (log: AuditLog | ActivityLog) => React.ReactNode;
  showLoading?: boolean;
  loadingComponent?: React.ReactNode;
  errorComponent?: React.ReactNode;
}
```

---

## Configuration

### Backend Configuration (Flask)

**Core Settings:**
```python
# JWT Configuration
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 900  # 15 minutes (seconds)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 2592000  # 30 days (seconds)
app.config['JWT_TOKEN_LOCATION'] = ['cookies', 'headers']
app.config['JWT_COOKIE_SECURE'] = True  # HTTPS only
app.config['JWT_COOKIE_HTTPONLY'] = True
app.config['JWT_COOKIE_SAMESITE'] = 'Strict'  # or 'Lax', 'None'

# Token Delivery Mode
app.config['AUTHSVC_TOKEN_DELIVERY'] = 'cookies_only'  # or 'body_only', 'dual'

# URL Prefixes
app.config['AUTHSVC_URL_PREFIX'] = '/api/auth'
app.config['AUTHSVC_RBAC_URL_PREFIX'] = '/api/rbac'
app.config['AUTHSVC_ADMIN_URL_PREFIX'] = '/api/admin'
app.config['AUTHSVC_AUDIT_URL_PREFIX'] = '/api/audit'

# Table Prefix (for multi-app databases)
app.config['AUTHSVC_TABLE_PREFIX'] = 'authsvc'

# Feature Toggles
app.config['AUTHSVC_ENABLE_OAUTH'] = True
app.config['AUTHSVC_ENABLE_MFA'] = False  # Future feature
app.config['AUTHSVC_ENABLE_RBAC'] = True
app.config['AUTHSVC_ENABLE_ADMIN'] = True
app.config['AUTHSVC_ENABLE_AUDIT'] = True
```

**RBAC Settings:**
```python
# RBAC Configuration
app.config['AUTHSVC_RBAC_ADMIN_ROLE'] = 'admin'
app.config['AUTHSVC_RBAC_ADMIN_PERMISSION'] = 'rbac.admin'
app.config['AUTHSVC_CACHE_PERMISSIONS'] = True
app.config['AUTHSVC_PERMISSION_CACHE_TTL'] = 300  # 5 minutes (seconds)
```

**Session Settings:**
```python
# Session Configuration
app.config['AUTHSVC_SESSION_TIMEOUT_MINUTES'] = None  # No hard timeout
app.config['AUTHSVC_SINGLE_SESSION_PER_USER'] = False  # Allow multiple devices
app.config['AUTHSVC_SESSION_INACTIVITY_TIMEOUT'] = None  # No inactivity timeout

# Inactivity timeout example: 30 minutes
app.config['AUTHSVC_SESSION_INACTIVITY_TIMEOUT'] = 30
```

**Security Settings:**
```python
# Brute Force Protection
app.config['AUTHSVC_MAX_LOGIN_ATTEMPTS'] = 5
app.config['AUTHSVC_LOGIN_ATTEMPT_WINDOW'] = 30  # minutes

# CORS
app.config['AUTHSVC_CORS_ORIGINS'] = ['http://localhost:3000', 'https://myapp.com']

# CSRF
app.config['WTF_CSRF_ENABLED'] = False  # Usually disabled for APIs

# Force HTTPS
app.config['AUTHSVC_FORCE_HTTPS'] = False  # Set True in production

# Rate Limiting
app.config['RATELIMIT_ENABLED'] = True
app.config['RATELIMIT_DEFAULT'] = '50000 per day; 5000 per hour'
```

**Email Settings:**
```python
# Email Service: Gmail
app.config['EMAIL_SERVICE'] = 'gmail'
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-app-password'

# OR Email Service: Brevo
app.config['EMAIL_SERVICE'] = 'brevo'
app.config['BREVO_API_KEY'] = 'your-brevo-api-key'
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@myapp.com'
```

**OAuth Settings:**
```python
# Google OAuth
app.config['GOOGLE_CLIENT_ID'] = 'your-google-client-id'
app.config['GOOGLE_CLIENT_SECRET'] = 'your-google-client-secret'

# Microsoft OAuth
app.config['MICROSOFT_CLIENT_ID'] = 'your-microsoft-client-id'
app.config['MICROSOFT_CLIENT_SECRET'] = 'your-microsoft-client-secret'

# Redirect URL (frontend)
app.config['POST_LOGIN_REDIRECT_URL'] = 'http://localhost:3000/dashboard'
```

**Cache Settings:**
```python
# Caching (for permissions, user data)
app.config['CACHE_TYPE'] = 'SimpleCache'  # or 'RedisCache', 'MemcachedCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300  # 5 minutes

# Redis example
app.config['CACHE_TYPE'] = 'RedisCache'
app.config['CACHE_REDIS_HOST'] = 'localhost'
app.config['CACHE_REDIS_PORT'] = 6379
app.config['CACHE_REDIS_DB'] = 0
```

---

### Frontend Configuration (React)

**AuthProvider Config:**
```typescript
import { AuthProvider } from 'react-headless-auth';

const config = {
  // Required
  apiBaseUrl: 'http://localhost:5000',
  
  // Optional - API Paths
  apiPrefix: '/api/auth',  // default
  rbac: {
    rbacPrefix: '/api/rbac',  // default
    autoFetchPermissions: true,  // default
    permissionCacheTTL: 300000  // 5 minutes
  },
  admin: {
    adminPrefix: '/api/admin'  // default
  },
  
  // Optional - Storage
  storageStrategy: 'cookie-first',  // 'localStorage-only', 'auto'
  
  // Optional - Token Refresh
  tokenRefreshInterval: 3300000,  // 55 minutes (milliseconds)
  
  // Optional - OAuth
  enableGoogle: true,
  googleClientId: 'your-google-client-id',
  enableMicrosoft: false,
  microsoftClientId: 'your-microsoft-client-id',
  
  // Optional - Custom Headers
  customHeaders: {
    'X-App-Version': '1.0.0',
    'X-Client-Platform': 'web'
  },
  
  // Optional - Logging
  debug: false,
  logLevel: 'warn',  // 'error', 'warn', 'info', 'debug'
  
  // Optional - Analytics
  enablePostHog: false,
  posthogApiKey: 'your-posthog-key'
};

<AuthProvider config={config}>
  <App />
</AuthProvider>
```

**Lifecycle Hooks:**
```typescript
const config = {
  apiBaseUrl: 'http://localhost:5000',
  
  // Hooks
  hooks: {
    // Before/After Login
    beforeLogin: async (credentials) => {
      console.log('Logging in:', credentials.email);
    },
    afterLogin: async (user) => {
      console.log('Logged in:', user.email);
      // Analytics
      analytics.identify(user.id, { email: user.email });
    },
    onLoginError: async (error) => {
      console.error('Login failed:', error);
    },
    
    // Before/After Signup
    beforeSignup: async (credentials) => {
      console.log('Signing up:', credentials.email);
    },
    afterSignup: async (user) => {
      console.log('Signed up:', user.email);
    },
    onSignupError: async (error) => {
      console.error('Signup failed:', error);
    },
    
    // Before/After Logout
    beforeLogout: async () => {
      console.log('Logging out...');
    },
    afterLogout: async () => {
      console.log('Logged out');
      // Redirect
      window.location.href = '/login';
    },
    
    // Token Refresh
    beforeTokenRefresh: async () => {
      console.log('Refreshing token...');
    },
    afterTokenRefresh: async () => {
      console.log('Token refreshed');
    },
    onTokenRefreshError: async (error) => {
      console.error('Token refresh failed:', error);
      // Force logout
      window.location.href = '/login';
    },
    
    // User Updates
    beforeUserUpdate: async (data) => {
      console.log('Updating user:', data);
    },
    afterUserUpdate: async (user) => {
      console.log('User updated:', user);
    },
    
    // Password Updates
    beforePasswordUpdate: async () => {
      console.log('Updating password...');
    },
    afterPasswordUpdate: async () => {
      console.log('Password updated');
    },
    
    // Auth Errors
    onAuthError: async (error) => {
      console.error('Auth error:', error);
    },
    
    // Transform User Data
    transformUser: (user) => {
      // Add computed properties
      return {
        ...user,
        fullName: `${user.first_name} ${user.last_name}`,
        initials: `${user.first_name?.[0]}${user.last_name?.[0]}`
      };
    }
  }
};
```

---

## Complete RBAC Guide

### Step-by-Step RBAC Setup

**1. Design Your Permissions**

Think in terms of `resource.action`:

```
User Management:
- users.view
- users.create
- users.edit
- users.delete

Patient Management:
- patients.view
- patients.create
- patients.edit
- patients.delete
- patients.view_medical_records

Billing:
- billing.view
- billing.create_invoice
- billing.process_payment

Reports:
- reports.view
- reports.export
```

---

**2. Create Permissions (Backend)**

```python
# In your Flask app initialization or migration script

permissions_to_create = [
    {"name": "users.view", "category": "User Management", "description": "View user list"},
    {"name": "users.create", "category": "User Management", "description": "Create new users"},
    {"name": "users.edit", "category": "User Management", "description": "Edit user profiles"},
    {"name": "users.delete", "category": "User Management", "description": "Delete users"},
    
    {"name": "patients.view", "category": "Patient Management", "description": "View patient list"},
    {"name": "patients.create", "category": "Patient Management", "description": "Register new patients"},
    {"name": "patients.edit", "category": "Patient Management", "description": "Edit patient information"},
    {"name": "patients.view_medical_records", "category": "Patient Management", "description": "View medical records"},
    
    {"name": "billing.view", "category": "Billing", "description": "View billing information"},
    {"name": "billing.create_invoice", "category": "Billing", "description": "Create invoices"},
    {"name": "billing.process_payment", "category": "Billing", "description": "Process payments"},
    
    {"name": "reports.view", "category": "Reports", "description": "View reports"},
    {"name": "reports.export", "category": "Reports", "description": "Export reports"},
]

# Option A: Use API endpoint
import requests
for perm in permissions_to_create:
    requests.post('http://localhost:5000/api/rbac/permissions', 
                  json=perm, 
                  headers={'Authorization': 'Bearer <admin_token>'})

# Option B: Use bulk API
requests.post('http://localhost:5000/api/rbac/permissions/bulk',
              json={'permissions': permissions_to_create},
              headers={'Authorization': 'Bearer <admin_token>'})

# Option C: Direct database (in migration)
with app.app_context():
    for perm_data in permissions_to_create:
        perm = Permission(**perm_data)
        db.session.add(perm)
    db.session.commit()
```

---

**3. Create Roles**

```python
roles_to_create = [
    {
        "name": "admin",
        "display_name": "Administrator",
        "description": "Full system access",
        "is_system": True
    },
    {
        "name": "doctor",
        "display_name": "Doctor",
        "description": "Medical staff with patient access"
    },
    {
        "name": "nurse",
        "display_name": "Nurse",
        "description": "Nursing staff with limited access"
    },
    {
        "name": "receptionist",
        "display_name": "Receptionist",
        "description": "Front desk staff"
    },
    {
        "name": "billing_clerk",
        "display_name": "Billing Clerk",
        "description": "Billing department staff"
    }
]

for role in roles_to_create:
    requests.post('http://localhost:5000/api/rbac/roles',
                  json=role,
                  headers={'Authorization': 'Bearer <admin_token>'})
```

---

**4. Assign Permissions to Roles**

```python
# Admin gets everything
admin_permissions = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]  # all permission IDs

# Doctor
doctor_permissions = [
    # User Management (view only)
    1,  # users.view
    
    # Patient Management (full access)
    5, 6, 7, 8,  # patients.view, create, edit, view_medical_records
    
    # Reports
    12, 13  # reports.view, export
]

# Nurse
nurse_permissions = [
    5, 6, 8  # patients.view, create, view_medical_records
]

# Receptionist
receptionist_permissions = [
    1,  # users.view
    5, 6, 7,  # patients.view, create, edit (but not medical records)
    9  # billing.view
]

# Billing Clerk
billing_clerk_permissions = [
    5,  # patients.view
    9, 10, 11  # billing.view, create_invoice, process_payment
]

# Assign via API
role_permission_map = {
    1: admin_permissions,  # admin role_id
    2: doctor_permissions,  # doctor role_id
    3: nurse_permissions,  # nurse role_id
    4: receptionist_permissions,  # receptionist role_id
    5: billing_clerk_permissions  # billing_clerk role_id
}

for role_id, permission_ids in role_permission_map.items():
    requests.put(f'http://localhost:5000/api/rbac/roles/{role_id}/permissions',
                 json={'permission_ids': permission_ids},
                 headers={'Authorization': 'Bearer <admin_token>'})
```

---

**5. Assign Roles to Users**

```python
# Assign role to user
requests.put('http://localhost:5000/api/rbac/users/42/role',
             json={'role_id': 2},  # doctor role
             headers={'Authorization': 'Bearer <admin_token>'})
```

---

**6. Protect Backend Routes (Flask)**

**Method 1: Permission Decorators**

```python
from flask_headless_auth import permission_required, permissions_required, any_permission

# Single permission required
@app.route('/api/patients')
@permission_required('patients.view')
def list_patients():
    # Only users with 'patients.view' permission can access
    patients = Patient.query.all()
    return jsonify([p.to_dict() for p in patients])

# Multiple permissions required (ALL)
@app.route('/api/patients/<id>', methods=['DELETE'])
@permissions_required('patients.delete', 'patients.view')
def delete_patient(id):
    # User must have BOTH permissions
    patient = Patient.query.get_or_404(id)
    db.session.delete(patient)
    db.session.commit()
    return jsonify({'message': 'Patient deleted'})

# Any permission required (OR)
@app.route('/api/reports')
@any_permission('reports.view', 'reports.export')
def view_reports():
    # User needs either permission
    reports = Report.query.all()
    return jsonify([r.to_dict() for r in reports])
```

**Method 2: Role Decorators**

```python
from flask_headless_auth import role_required_authsvc, roles_required

# Single role required
@app.route('/api/admin/users')
@role_required_authsvc('admin')
def admin_users():
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])

# Any role required
@app.route('/api/medical/records')
@roles_required('doctor', 'nurse')
def medical_records():
    # Either doctor or nurse can access
    records = MedicalRecord.query.all()
    return jsonify([r.to_dict() for r in records])
```

**Method 3: Runtime Checks**

```python
from flask_jwt_extended import get_jwt_identity, get_jwt
from flask import abort

@app.route('/api/billing/invoice/<id>', methods=['PUT'])
@jwt_required()
def update_invoice(id):
    claims = get_jwt()
    permissions = claims.get('permissions', [])
    
    # Check permission
    if 'billing.create_invoice' not in permissions:
        abort(403, 'Permission denied')
    
    # Process request
    invoice = Invoice.query.get_or_404(id)
    invoice.amount = request.json['amount']
    db.session.commit()
    return jsonify(invoice.to_dict())
```

**Method 4: PermissionChecker Class**

```python
from flask_headless_auth import PermissionChecker

@app.route('/api/complex-operation')
@jwt_required()
def complex_operation():
    user_id = get_jwt_identity()
    checker = PermissionChecker(user_id, auth.db, auth.user_repository)
    
    if checker.has_permission('patients.view'):
        # Do something
        pass
    
    if checker.has_all_permissions(['billing.view', 'billing.create_invoice']):
        # Do something else
        pass
    
    if checker.has_any_permission(['reports.view', 'analytics.view']):
        # Do another thing
        pass
    
    return jsonify({'status': 'ok'})
```

---

**7. Protect Frontend Routes (React)**

**Method 1: PermissionGate Component**

```tsx
import { PermissionGate } from 'react-headless-auth';

function App() {
  return (
    <Router>
      <Routes>
        {/* Public routes */}
        <Route path="/login" element={<Login />} />
        
        {/* Permission-protected routes */}
        <Route path="/patients" element={
          <PermissionGate permission="patients.view" fallback={<AccessDenied />}>
            <PatientList />
          </PermissionGate>
        } />
        
        <Route path="/patients/new" element={
          <PermissionGate permission="patients.create">
            <PatientForm />
          </PermissionGate>
        } />
        
        <Route path="/billing" element={
          <PermissionGate permission="billing.view">
            <BillingDashboard />
          </PermissionGate>
        } />
        
        {/* Role-protected routes */}
        <Route path="/admin" element={
          <PermissionGate role="admin">
            <AdminPanel />
          </PermissionGate>
        } />
        
        {/* Multiple permissions (ALL required) */}
        <Route path="/patients/:id/edit" element={
          <PermissionGate 
            permissions={["patients.view", "patients.edit"]} 
            requireAll={true}
          >
            <PatientEditForm />
          </PermissionGate>
        } />
      </Routes>
    </Router>
  );
}
```

**Method 2: useRole Hook**

```tsx
import { useRole } from 'react-headless-auth';

function Dashboard() {
  const { hasPermission, hasRole } = useRole();
  
  return (
    <div>
      <h1>Dashboard</h1>
      
      {hasPermission('patients.view') && (
        <Link to="/patients">View Patients</Link>
      )}
      
      {hasPermission('billing.view') && (
        <Link to="/billing">Billing</Link>
      )}
      
      {hasRole('admin') && (
        <Link to="/admin">Admin Panel</Link>
      )}
    </div>
  );
}
```

**Method 3: Protected Route Component**

```tsx
import { Navigate } from 'react-router-dom';
import { useRole } from 'react-headless-auth';

function ProtectedRoute({ permission, role, children }) {
  const { hasPermission, hasRole, loading } = useRole();
  
  if (loading) return <LoadingSpinner />;
  
  if (permission && !hasPermission(permission)) {
    return <Navigate to="/access-denied" />;
  }
  
  if (role && !hasRole(role)) {
    return <Navigate to="/access-denied" />;
  }
  
  return children;
}

// Usage
<Route path="/patients" element={
  <ProtectedRoute permission="patients.view">
    <PatientList />
  </ProtectedRoute>
} />
```

---

**8. Conditional UI Elements**

```tsx
import { useRole } from 'react-headless-auth';
import { PermissionGate } from 'react-headless-auth';

function PatientProfile({ patient }) {
  const { hasPermission } = useRole();
  
  return (
    <div>
      <h1>{patient.name}</h1>
      <p>{patient.email}</p>
      
      {/* Show edit button only if user has permission */}
      {hasPermission('patients.edit') && (
        <button onClick={handleEdit}>Edit Patient</button>
      )}
      
      {/* Or use PermissionGate */}
      <PermissionGate permission="patients.delete">
        <button onClick={handleDelete} className="danger">
          Delete Patient
        </button>
      </PermissionGate>
      
      {/* Medical records section - only for authorized users */}
      <PermissionGate permission="patients.view_medical_records">
        <MedicalRecordsSection patient={patient} />
      </PermissionGate>
      
      {/* Billing info - only for billing staff or admins */}
      <PermissionGate permissions={["billing.view"]} roles={["admin"]}>
        <BillingInfo patient={patient} />
      </PermissionGate>
    </div>
  );
}
```

---

**9. Export/Import RBAC Configuration**

```typescript
import { RBACClient } from 'react-headless-auth';

const rbacClient = new RBACClient({ apiBaseUrl: 'http://localhost:5000' });

// Export configuration
const config = await rbacClient.exportConfig();
// Save to file
const blob = new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' });
const url = URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url;
a.download = 'rbac-config.json';
a.click();

// Import configuration
const fileInput = document.getElementById('file-input');
const file = fileInput.files[0];
const text = await file.text();
const config = JSON.parse(text);
await rbacClient.importConfig(config);
```

---

**10. Testing RBAC**

**Backend Tests:**

```python
def test_permission_required_decorator():
    # Create test user with permission
    user = User(email='test@example.com')
    role = Role(name='tester')
    permission = Permission(name='patients.view')
    role.permissions.append(permission)
    user.role = role
    db.session.add_all([user, role, permission])
    db.session.commit()
    
    # Login
    response = client.post('/api/auth/login', json={
        'email': 'test@example.com',
        'password': 'password123'
    })
    token = response.json['access_token']
    
    # Access protected route
    response = client.get('/api/patients', 
                          headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    
    # Try without permission
    user.role = None
    db.session.commit()
    
    response = client.get('/api/patients',
                          headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 403
```

**Frontend Tests:**

```tsx
import { render, screen } from '@testing-library/react';
import { PermissionGate } from 'react-headless-auth';

test('renders children when permission granted', () => {
  const mockUseRole = jest.fn().mockReturnValue({
    hasPermission: (perm) => perm === 'patients.view',
    loading: false
  });
  
  render(
    <PermissionGate permission="patients.view">
      <div>Protected Content</div>
    </PermissionGate>
  );
  
  expect(screen.getByText('Protected Content')).toBeInTheDocument();
});

test('hides children when permission denied', () => {
  const mockUseRole = jest.fn().mockReturnValue({
    hasPermission: () => false,
    loading: false
  });
  
  render(
    <PermissionGate permission="patients.view">
      <div>Protected Content</div>
    </PermissionGate>
  );
  
  expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
});
```

---

## Common Use Cases

### Use Case 1: Complete Auth Setup for New App

**Backend (app.py):**
```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_headless_auth import FlaskHeadlessAuth

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://localhost/myapp'
app.config['JWT_SECRET_KEY'] = 'your-jwt-secret'

db = SQLAlchemy(app)
auth = FlaskHeadlessAuth(app, db)

# Create tables
with app.app_context():
    auth.create_tables()

if __name__ == '__main__':
    app.run(debug=True)
```

**Frontend (App.tsx):**
```tsx
import { AuthProvider, useAuth } from 'react-headless-auth';

function App() {
  return (
    <AuthProvider config={{ apiBaseUrl: 'http://localhost:5000' }}>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/dashboard" element={<Dashboard />} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

function Login() {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await login(email, password);
      navigate('/dashboard');
    } catch (error) {
      alert('Login failed: ' + error.message);
    }
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <input value={email} onChange={(e) => setEmail(e.target.value)} />
      <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <button>Login</button>
    </form>
  );
}

function Dashboard() {
  const { user, logout } = useAuth();
  
  return (
    <div>
      <h1>Welcome {user?.email}!</h1>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

---

### Use Case 2: Multi-Tenant SaaS Application

**Backend:**
```python
# Custom user model with tenant_id
from flask_headless_auth.mixins import UserMixin

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password_hash = db.Column(db.String(255))
    tenant_id = db.Column(db.String(50), nullable=False)  # Custom field
    company_name = db.Column(db.String(255))  # Custom field
    # ... other fields from UserMixin

# Initialize with custom model
auth = FlaskHeadlessAuth(app, db, user_model=User)

# Tenant-aware route
@app.route('/api/data')
@jwt_required()
def get_tenant_data():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    # Filter by tenant
    data = Data.query.filter_by(tenant_id=user.tenant_id).all()
    return jsonify([d.to_dict() for d in data])
```

**Frontend:**
```tsx
// Custom signup with tenant
function SignupForm() {
  const { signup } = useAuth();
  
  const handleSubmit = async (data) => {
    await signup({
      email: data.email,
      password: data.password,
      tenant_id: generateTenantId(),  // or from URL subdomain
      company_name: data.companyName
    });
  };
  
  // ...
}
```

---

### Use Case 3: Healthcare App with HIPAA Compliance

**Backend:**
```python
from flask_headless_auth import audit_action

# Track PHI access
@app.route('/api/patients/<id>/medical-record')
@permission_required('patients.view_medical_records')
@audit_action('patient.medical_record_viewed', resource_type='patient', log_phi=True)
def get_medical_record(id):
    patient = Patient.query.get_or_404(id)
    record = MedicalRecord.query.filter_by(patient_id=id).first()
    
    # This access is automatically logged with phi_accessed=True
    return jsonify(record.to_dict())

# Generate compliance report
@app.route('/api/compliance/phi-report')
@role_required_authsvc('admin')
def phi_report():
    # Use built-in endpoint
    return redirect('/api/audit/compliance/phi-access-report')
```

**Frontend:**
```tsx
import { useAuditLogs } from 'react-headless-auth';

function PatientMedicalRecord({ patientId }) {
  const { fetchResourceHistory } = useAuditLogs();
  const [accessHistory, setAccessHistory] = useState([]);
  
  useEffect(() => {
    // Show who accessed this patient record
    fetchResourceHistory('patient', patientId)
      .then(history => setAccessHistory(history));
  }, [patientId]);
  
  return (
    <div>
      <MedicalRecordDetails patientId={patientId} />
      
      <h3>Access History (HIPAA Compliance)</h3>
      <table>
        <thead>
          <tr>
            <th>Date</th>
            <th>User</th>
            <th>Action</th>
            <th>IP Address</th>
          </tr>
        </thead>
        <tbody>
          {accessHistory.map(log => (
            <tr key={log.id}>
              <td>{log.timestamp}</td>
              <td>{log.user_email}</td>
              <td>{log.action}</td>
              <td>{log.ip_address}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

---

### Use Case 4: Admin Dashboard

**Frontend:**
```tsx
import { useAdmin, PermissionGate } from 'react-headless-auth';

function AdminDashboard() {
  const { users, total, page, pages, loading, fetchUsers, banUser, deleteUser } = useAdmin();
  
  useEffect(() => {
    fetchUsers({ page: 1, per_page: 20 });
  }, []);
  
  const handleBan = async (userId) => {
    if (confirm('Ban this user?')) {
      await banUser(userId, { reason: 'Violated terms' });
      fetchUsers({ page });  // Refresh
    }
  };
  
  return (
    <PermissionGate role="admin" fallback={<AccessDenied />}>
      <div>
        <h1>User Management ({total} users)</h1>
        
        <table>
          <thead>
            <tr>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th>Last Login</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(user => (
              <tr key={user.id}>
                <td>{user.email}</td>
                <td>{user.role_name}</td>
                <td>{user.is_active ? 'Active' : 'Banned'}</td>
                <td>{user.last_login_at}</td>
                <td>
                  <button onClick={() => handleBan(user.id)}>Ban</button>
                  <button onClick={() => deleteUser(user.id)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        
        <Pagination page={page} pages={pages} onChange={(p) => fetchUsers({ page: p })} />
      </div>
    </PermissionGate>
  );
}
```

---

### Use Case 5: Session Management UI

**Frontend:**
```tsx
import { SessionManager } from 'react-headless-auth';

function AccountSettings() {
  const handleSessionRevoked = (sessionId) => {
    toast.success('Device logged out successfully');
  };
  
  const handleAllRevoked = () => {
    toast.success('All other devices logged out');
  };
  
  return (
    <div>
      <h1>Account Settings</h1>
      
      <section>
        <h2>Active Sessions</h2>
        <p>Manage devices where you're logged in</p>
        
        <SessionManager 
          onSessionRevoked={handleSessionRevoked}
          onAllSessionsRevoked={handleAllRevoked}
        />
      </section>
    </div>
  );
}
```

---

### Use Case 6: Custom Hooks for Business Logic

**Backend:**
```python
from flask_headless_auth import FlaskHeadlessAuth

auth = FlaskHeadlessAuth(app, db)

# Custom access token claims
@auth.hook('custom_access_token')
def add_custom_claims(user, claims):
    claims['company_id'] = user.company_id
    claims['subscription_tier'] = user.subscription_tier
    return claims

# Validate company email domain on signup
@auth.hook('before_signup')
def validate_email_domain(user_data):
    email = user_data['email']
    if not email.endswith('@mycompany.com'):
        raise ValueError('Only company emails allowed')

# Send welcome email after signup
@auth.hook('after_signup')
def send_welcome_email(user):
    send_email(
        to=user.email,
        subject='Welcome to MyApp!',
        body=f'Hi {user.first_name}, welcome aboard!'
    )

# Log to analytics after login
@auth.hook('after_login')
def track_login(user):
    analytics.track(user.id, 'User Logged In', {
        'email': user.email,
        'role': user.role_name
    })
```

---

## Error Handling

### Backend Error Responses

All errors follow this format:

```json
{
  "error": "Error message",
  "details": "Additional details (optional)",
  "code": "ERROR_CODE"
}
```

**Common HTTP Status Codes:**
- `200` - Success
- `201` - Created
- `400` - Bad request (validation error)
- `401` - Unauthorized (not logged in)
- `403` - Forbidden (no permission)
- `404` - Not found
- `429` - Too many requests (rate limit)
- `500` - Internal server error

**Example Error Responses:**

```json
// 401 - Not authenticated
{
  "error": "Missing Authorization Header",
  "code": "UNAUTHORIZED"
}

// 403 - No permission
{
  "error": "Permission denied: users.delete",
  "code": "FORBIDDEN"
}

// 400 - Validation error
{
  "error": "Invalid email format",
  "details": "Email must be a valid email address",
  "code": "VALIDATION_ERROR"
}

// 429 - Rate limit
{
  "error": "Rate limit exceeded",
  "details": "Try again in 60 seconds",
  "code": "RATE_LIMIT_EXCEEDED"
}
```

---

### Frontend Error Handling

**With Hooks:**
```tsx
const { login } = useAuth();

try {
  await login(email, password);
} catch (error) {
  if (error.code === 'UNAUTHORIZED') {
    setError('Invalid credentials');
  } else if (error.code === 'RATE_LIMIT_EXCEEDED') {
    setError('Too many attempts. Try again later.');
  } else {
    setError('An error occurred: ' + error.message);
  }
}
```

**With Lifecycle Hooks:**
```tsx
const config = {
  apiBaseUrl: 'http://localhost:5000',
  hooks: {
    onLoginError: (error) => {
      if (error.code === 'UNAUTHORIZED') {
        toast.error('Invalid credentials');
      } else {
        toast.error('Login failed: ' + error.message);
      }
    },
    onAuthError: (error) => {
      // Global auth error handler
      console.error('Auth error:', error);
      Sentry.captureException(error);
    }
  }
};
```

---

## Performance Optimization

### Backend Caching

```python
# Enable permission caching
app.config['AUTHSVC_CACHE_PERMISSIONS'] = True
app.config['AUTHSVC_PERMISSION_CACHE_TTL'] = 300  # 5 minutes

# Enable user data caching
app.config['CACHE_TYPE'] = 'RedisCache'
app.config['CACHE_REDIS_HOST'] = 'localhost'
```

### Frontend Optimization

```typescript
// Enable permission caching
const config = {
  apiBaseUrl: 'http://localhost:5000',
  rbac: {
    autoFetchPermissions: true,
    permissionCacheTTL: 300000  // 5 minutes
  }
};

// Memoize permission checks
const Dashboard = memo(function Dashboard() {
  const { hasPermission } = useRole();
  const canViewUsers = useMemo(() => hasPermission('users.view'), [hasPermission]);
  
  return <div>{canViewUsers && <UserList />}</div>;
});
```

---

## Security Best Practices

1. **Always use HTTPS in production:**
```python
app.config['JWT_COOKIE_SECURE'] = True
app.config['AUTHSVC_FORCE_HTTPS'] = True
```

2. **Use strong JWT secrets:**
```python
import secrets
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)
```

3. **Enable CORS only for trusted origins:**
```python
app.config['AUTHSVC_CORS_ORIGINS'] = ['https://myapp.com']
```

4. **Enable rate limiting:**
```python
app.config['RATELIMIT_ENABLED'] = True
app.config['RATELIMIT_DEFAULT'] = '5000 per hour'
```

5. **Use HttpOnly cookies:**
```python
app.config['JWT_COOKIE_HTTPONLY'] = True
app.config['JWT_COOKIE_SAMESITE'] = 'Strict'
```

6. **Validate permissions on backend:**
- Never rely only on frontend permission checks
- Always use decorators or runtime checks on backend routes

7. **Audit sensitive actions:**
```python
@app.route('/api/sensitive-data')
@permission_required('data.view_sensitive')
@audit_action('data.viewed_sensitive', log_phi=True)
def get_sensitive_data():
    # This access is logged automatically
    pass
```

---

## Production Checklist

### Backend

- [ ] Set strong `SECRET_KEY` and `JWT_SECRET_KEY`
- [ ] Configure production database (PostgreSQL recommended)
- [ ] Enable HTTPS (`AUTHSVC_FORCE_HTTPS = True`)
- [ ] Set secure cookies (`JWT_COOKIE_SECURE = True`)
- [ ] Configure CORS for specific origins
- [ ] Set up Redis for caching (optional)
- [ ] Configure email service (Gmail/Brevo)
- [ ] Set up rate limiting
- [ ] Enable audit logging (`AUTHSVC_ENABLE_AUDIT = True`)
- [ ] Configure session timeouts
- [ ] Set up OAuth (if needed)
- [ ] Test all permission decorators
- [ ] Set up monitoring (Sentry, etc.)

### Frontend

- [ ] Set production `apiBaseUrl`
- [ ] Use `cookie-first` storage strategy
- [ ] Enable error tracking (Sentry)
- [ ] Test all protected routes
- [ ] Test permission gates
- [ ] Configure OAuth redirect URLs
- [ ] Set up analytics (optional)
- [ ] Enable logging in production (`logLevel: 'error'`)
- [ ] Test token refresh
- [ ] Test session management UI

---

## Troubleshooting

### Common Issues

**1. "Missing Authorization Header"**
- Make sure cookies are enabled or tokens are in Authorization header
- Check CORS configuration
- Verify `credentials: 'include'` in fetch requests

**2. "Permission denied"**
- Check user has correct role assigned
- Verify role has required permissions
- Clear permission cache: restart backend or wait for TTL

**3. "Token refresh failed"**
- Check refresh token hasn't expired (30 days default)
- Verify session is still active
- Check inactivity timeout settings

**4. "CORS error"**
- Add frontend URL to `AUTHSVC_CORS_ORIGINS`
- Ensure credentials are included in requests
- Check CORS middleware is configured

**5. "Rate limit exceeded"**
- Reduce request frequency
- Increase rate limits in config
- Use caching to reduce API calls

---

## Support & Resources

### Documentation
- **Backend:** See `flask_headless_auth/README.md`
- **Frontend:** See `react-headless-auth/README.md`

### Example Apps
- Healthcare SaaS: `/examples/healthcare-app`
- Multi-tenant B2B: `/examples/b2b-saas`
- Admin Dashboard: `/examples/admin-dashboard`

### Community
- GitHub: `your-github-url`
- Issues: `your-github-url/issues`
- Discussions: `your-github-url/discussions`

---

## Version History

### v1.0.0 (Current)
- ✅ Complete authentication system
- ✅ Full RBAC with permissions
- ✅ Admin APIs
- ✅ Audit logging & compliance
- ✅ React SDK with hooks & components
- ✅ Multi-tenancy support
- ✅ Session management
- ✅ OAuth (Google, Microsoft)

### Roadmap
- [ ] MFA (optional)
- [ ] GitHub OAuth
- [ ] SAML SSO (enterprise)
- [ ] Admin dashboard UI
- [ ] Mobile SDK (React Native)
- [ ] Vue.js SDK
- [ ] Angular SDK

---

## License

MIT License - See LICENSE file for details

---

**END OF DOCUMENTATION**

This document provides complete reference for integrating Flask Headless Auth + React Headless Auth into any application. Use this as a guide for AI assistants, developers, and technical documentation.
