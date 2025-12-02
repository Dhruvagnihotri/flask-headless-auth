# Flask-AuthSvc Configuration Examples

## Token Delivery Modes

Flask-AuthSvc supports three token delivery modes via the `AUTHSVC_TOKEN_DELIVERY` configuration option.

---

## Mode 1: cookies_only (DEFAULT - Most Secure)

**Best for:** Web applications, browser-based clients, production environments

**Security:** ✅ Highest - No XSS attack surface for 95%+ of users

**How it works:**
- Browser clients receive tokens ONLY via httpOnly cookies
- API clients (Postman, mobile apps) receive tokens in response body
- No localStorage needed on frontend
- Industry standard used by banks, fintech, healthcare apps

### Configuration

```python
# config.py

class Config:
    # Token delivery mode
    AUTHSVC_TOKEN_DELIVERY = 'cookies_only'  # DEFAULT
    
    # Where backend accepts tokens FROM
    JWT_TOKEN_LOCATION = ['cookies', 'headers']
    
    # Cookie security settings (industry standard)
    JWT_COOKIE_SECURE = True          # HTTPS only
    JWT_COOKIE_HTTPONLY = True        # XSS protection
    JWT_COOKIE_SAMESITE = 'Strict'    # CSRF protection
    JWT_COOKIE_CSRF_PROTECT = False   # Not needed with SameSite=Strict
    
    # Token expiration (industry best practices)
    JWT_ACCESS_TOKEN_EXPIRES = 900    # 15 minutes
    JWT_REFRESH_TOKEN_EXPIRES = 2592000  # 30 days
```

### Frontend Implementation

```typescript
// Super simple - no token storage needed!

const login = async (email: string, password: string) => {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    credentials: 'include',  // Auto-sends cookies
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  
  if (response.ok) {
    // That's it! Cookies are set automatically
    // No localStorage, no token handling
    setIsAuthenticated(true);
  }
};

const checkAuth = async () => {
  const response = await fetch('/api/auth/user/@me', {
    credentials: 'include'  // Auto-sends cookies
  });
  
  if (response.ok) {
    const data = await response.json();
    setUser(data.user);
  }
};
```

### API Response

```json
{
  "msg": "Login successful",
  "user": {
    "id": 123,
    "email": "user@example.com",
    "role": 2
  }
}
```

Note: No tokens in response body for browser clients!

---

## Mode 2: body_only (For APIs)

**Best for:** Mobile apps, API-first services, microservices, testing with Postman

**Security:** ⚠️ Medium - Client responsible for secure token storage

**How it works:**
- Tokens sent ONLY in response body
- No cookies set
- Client handles token storage (SecureStore, Keychain, etc.)

### Configuration

```python
# config.py

class Config:
    # Token delivery mode
    AUTHSVC_TOKEN_DELIVERY = 'body_only'
    
    # Where backend accepts tokens FROM
    JWT_TOKEN_LOCATION = ['headers']  # Only check Authorization header
    
    # No cookie settings needed
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'
    
    # Token expiration
    JWT_ACCESS_TOKEN_EXPIRES = 900
    JWT_REFRESH_TOKEN_EXPIRES = 2592000
```

### Frontend/Mobile Implementation

```typescript
// Token storage and management required

const login = async (email: string, password: string) => {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  
  if (response.ok) {
    const data = await response.json();
    
    // Store tokens securely
    // Mobile: SecureStore, Keychain
    // Web: NOT localStorage (use cookies_only instead)
    await SecureStore.setItemAsync('access_token', data.access_token);
    await SecureStore.setItemAsync('refresh_token', data.refresh_token);
  }
};

const makeAuthenticatedRequest = async (url: string) => {
  const token = await SecureStore.getItemAsync('access_token');
  
  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  return response;
};
```

### API Response

```json
{
  "msg": "Login successful",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

## Mode 3: dual (Flexible - Backwards Compatible)

**Best for:** Apps that MUST support cookie-blocked users (~1-3% of users)

**Security:** ⚠️ Low for localStorage users - XSS vulnerability for cookie-blocked users

**How it works:**
- Tokens sent in BOTH response body AND cookies
- Frontend detects if cookies work and chooses storage method
- More complex frontend code required

### Configuration

```python
# config.py

class Config:
    # Token delivery mode
    AUTHSVC_TOKEN_DELIVERY = 'dual'
    
    # Where backend accepts tokens FROM
    JWT_TOKEN_LOCATION = ['cookies', 'headers']  # Accept from both
    
    # Cookie security settings
    JWT_COOKIE_SECURE = True
    JWT_COOKIE_HTTPONLY = True
    JWT_COOKIE_SAMESITE = 'Strict'
    
    # Header settings
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'
    
    # Token expiration
    JWT_ACCESS_TOKEN_EXPIRES = 900
    JWT_REFRESH_TOKEN_EXPIRES = 2592000
```

### Frontend Implementation (Complex)

```typescript
// Requires cookie detection and smart storage

class AuthStorage {
  private static COOKIES_WORK = 'cookies_work';
  
  // Detect once on app init
  static async detectCookieSupport(): Promise<boolean> {
    const cached = localStorage.getItem(this.COOKIES_WORK);
    if (cached !== null) return cached === 'true';
    
    try {
      const response = await fetch('/api/auth/check-auth', {
        credentials: 'include'
      });
      const works = response.ok || response.status === 401;
      
      localStorage.setItem(this.COOKIES_WORK, works.toString());
      return works;
    } catch {
      localStorage.setItem(this.COOKIES_WORK, 'false');
      return false;
    }
  }
  
  static storeTokensIfNeeded(accessToken: string, refreshToken: string) {
    const cookiesWork = localStorage.getItem(this.COOKIES_WORK) === 'true';
    
    if (!cookiesWork) {
      // Cookies blocked - must use localStorage
      console.warn('[Security] Using localStorage (cookies blocked)');
      localStorage.setItem('auth_access_token', accessToken);
      localStorage.setItem('auth_refresh_token', refreshToken);
    } else {
      // Cookies work - don't store in localStorage
      console.log('[Secure] Using httpOnly cookies');
    }
  }
}

const login = async (email: string, password: string) => {
  const cookiesWork = await AuthStorage.detectCookieSupport();
  
  // Warn user if cookies blocked
  if (!cookiesWork) {
    const consent = await showSecurityWarning();
    if (!consent) return;
  }
  
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    credentials: 'include',
    body: JSON.stringify({ email, password })
  });
  
  if (response.ok) {
    const data = await response.json();
    
    // Store in localStorage ONLY if cookies don't work
    if (data.access_token && data.refresh_token) {
      AuthStorage.storeTokensIfNeeded(data.access_token, data.refresh_token);
    }
    
    setIsAuthenticated(true);
  }
};
```

### API Response

```json
{
  "msg": "Login successful",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

Note: Same tokens are also set as cookies for browser clients!

---

## Comparison Table

| Feature | cookies_only | body_only | dual |
|---------|--------------|-----------|------|
| **Security** | ✅ Highest | ⚠️ Medium | ⚠️ Low (for localStorage) |
| **XSS Protection** | ✅ Yes | ❌ No | ⚠️ Only for cookie users |
| **Cookie-blocked Support** | ❌ No | ✅ Yes | ✅ Yes |
| **Frontend Complexity** | ✅ Simplest | ⚠️ Medium | ❌ Complex |
| **Mobile App Support** | ⚠️ Via body | ✅ Native | ✅ Yes |
| **Industry Usage** | ✅ 70% | ✅ 25% | ⚠️ 5% |
| **Recommended For** | Web apps | APIs/Mobile | Legacy/Edge cases |

---

## Migration Guide

### From dual → cookies_only (Recommended)

**Backend:**
```python
# Change config
AUTHSVC_TOKEN_DELIVERY = 'cookies_only'  # Was: 'dual'
```

**Frontend:**
```typescript
// Remove localStorage code
// Delete TokenStorage class
// Remove all localStorage.setItem('auth_*') calls
// Just use credentials: 'include'

// Before (dual):
if (data.access_token) {
  localStorage.setItem('auth_access_token', data.access_token);
}

// After (cookies_only):
// Nothing! Cookies handled automatically
```

**Handle cookie-blocked users:**
```typescript
// Show clear error page
if (authFails && !hasRetried) {
  showErrorPage({
    title: "Cookies Required",
    message: "Please enable cookies in your browser.",
    helpLink: "/help/enable-cookies"
  });
}
```

### From cookies_only → dual (Not Recommended)

Only do this if you have a business requirement to support cookie-blocked users.

**Backend:**
```python
AUTHSVC_TOKEN_DELIVERY = 'dual'
```

**Frontend:**
- Add cookie detection
- Add localStorage fallback
- Add user consent warning
- Add security monitoring
- See Mode 3 example above

---

## Security Best Practices

### For cookies_only and dual modes:

```python
# ALWAYS use these settings
JWT_COOKIE_SECURE = True           # HTTPS only
JWT_COOKIE_HTTPONLY = True         # XSS protection
JWT_COOKIE_SAMESITE = 'Strict'     # CSRF protection

# Shorter access tokens
JWT_ACCESS_TOKEN_EXPIRES = 900     # 15 minutes (not 1 hour)
```

### For dual mode (if you must use it):

1. **Detect cookies upfront:**
   ```typescript
   const cookiesWork = await detectCookieSupport();
   ```

2. **Warn users explicitly:**
   ```typescript
   if (!cookiesWork) {
     showWarning("Cookies blocked. Using less secure localStorage.");
   }
   ```

3. **Log localStorage usage:**
   ```typescript
   if (usingLocalStorage) {
     logSecurityEvent('localStorage_auth_active');
   }
   ```

4. **Implement CSP:**
   ```python
   CONTENT_SECURITY_POLICY = {
       'default-src': ["'self'"],
       'script-src': ["'self'", "'nonce-{random}'"],
   }
   ```

5. **Regular security audits:**
   - XSS penetration testing
   - Token theft monitoring
   - Quarterly security reviews

---

## Troubleshooting

### Issue: Frontend not receiving tokens

**cookies_only mode:**
- Check `credentials: 'include'` in fetch
- Verify CORS allows credentials
- Check browser doesn't block third-party cookies
- Verify HTTPS in production

**body_only mode:**
- Tokens should be in response body
- Check response JSON structure

**dual mode:**
- Tokens in both body AND cookies
- Check browser console for cookie warnings

### Issue: 401 Unauthorized

**All modes:**
- Check token expiration times
- Verify JWT_SECRET_KEY is set
- Check token is sent correctly (cookie or header)
- Verify JWT_TOKEN_LOCATION matches delivery mode

### Issue: CORS errors

```python
# Flask app config
CORS_ORIGINS = ['https://yourfrontend.com']
CORS_SUPPORTS_CREDENTIALS = True
```

```typescript
// Frontend
fetch(url, {
  credentials: 'include',  // Required for cookies
  // ...
})
```

---

## Examples in Production

### Example 1: SaaS Web App (cookies_only)

```python
# config.py
class ProductionConfig:
    AUTHSVC_TOKEN_DELIVERY = 'cookies_only'
    JWT_TOKEN_LOCATION = ['cookies', 'headers']
    JWT_COOKIE_SECURE = True
    JWT_COOKIE_HTTPONLY = True
    JWT_COOKIE_SAMESITE = 'Strict'
    JWT_ACCESS_TOKEN_EXPIRES = 900
    JWT_REFRESH_TOKEN_EXPIRES = 2592000
```

### Example 2: Mobile API (body_only)

```python
# config.py
class MobileAPIConfig:
    AUTHSVC_TOKEN_DELIVERY = 'body_only'
    JWT_TOKEN_LOCATION = ['headers']
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour for mobile
    JWT_REFRESH_TOKEN_EXPIRES = 7776000  # 90 days
```

### Example 3: Hybrid App (dual)

```python
# config.py
class HybridConfig:
    AUTHSVC_TOKEN_DELIVERY = 'dual'
    JWT_TOKEN_LOCATION = ['cookies', 'headers']
    JWT_COOKIE_SECURE = True
    JWT_COOKIE_HTTPONLY = True
    JWT_COOKIE_SAMESITE = 'Strict'
    JWT_ACCESS_TOKEN_EXPIRES = 900
    JWT_REFRESH_TOKEN_EXPIRES = 2592000
```

---

## Additional Resources

- [OWASP JWT Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [Flask-JWT-Extended Documentation](https://flask-jwt-extended.readthedocs.io/)
- [MDN: HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
- [OWASP: Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)

