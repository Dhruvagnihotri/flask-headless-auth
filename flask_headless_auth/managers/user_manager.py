from flask import jsonify, current_app, request
from datetime import datetime, timedelta
import uuid
import logging
from flask_headless_auth.interfaces import UserDataAccess

logger = logging.getLogger(__name__)


def _get_audit_manager():
    """Safely get the AuditManager (returns None if audit is disabled)."""
    try:
        authsvc = current_app.extensions.get('authsvc')
        if authsvc and hasattr(authsvc, 'audit_manager'):
            return authsvc.audit_manager
    except Exception:
        pass
    return None

class UserManager:
    def __init__(self, user_data_access: UserDataAccess, cache=None):
        self.user_data_access = user_data_access
        self.cache = cache  # Cache is optional

    # --- Internal: fire-and-forget audit logging ---
    @staticmethod
    def _log_auth_event(action, user_id=None, success=True,
                        error_message=None, metadata=None):
        """Write to audit log. Never raises, never breaks the caller."""
        try:
            authsvc = current_app.extensions.get('authsvc')
            if authsvc and hasattr(authsvc, 'audit_manager'):
                authsvc.audit_manager.log_event(
                    action=action,
                    user_id=user_id,
                    success=success,
                    error_message=error_message,
                    metadata=metadata,
                )
        except Exception:
            pass

    @staticmethod
    def _get_hooks():
        """Safely get the HooksManager."""
        try:
            authsvc = current_app.extensions.get('authsvc')
            if authsvc and hasattr(authsvc, 'hooks'):
                return authsvc.hooks
        except Exception:
            pass
        return None

    def register_user(self, user_data):
        # Handle legacy format where frontend might send array  
        if isinstance(user_data, list) and user_data:
            user_data = user_data[0]
        if not user_data.get('email') or not user_data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400

        # --- before_signup hook (Supabase parity) ---
        # Allows apps to validate/reject signups (e.g., domain restriction)
        hooks = self._get_hooks()
        if hooks and hooks.has_hooks('before_signup'):
            try:
                hooks.fire('before_signup', user_data)
            except ValueError as exc:
                return jsonify({'error': str(exc)}), 400

        existing_user = self.user_data_access.find_user_by_email(user_data['email'])
        if existing_user:
            return jsonify({'error': 'Email is already registered'}), 400

        user_data['password_hash'] = self.user_data_access.set_password(user_data.get('password'))
        user_data['role_id'] = user_data.get('role_id', None)
        user_data['is_verified'] = False  # Add verification flag

        logger.debug(f"Creating user with email: {user_data.get('email')}")
        new_user = self.user_data_access.create_user(user_data)
        logger.info(f"Created user with ID: {new_user.get('id')}")
        
        # Fire send_verification_email hook (app handles actual delivery).
        # The hook receives (user_dict, token).  The consuming app is
        # responsible for building the full verification URL — the library
        # never constructs frontend URLs (avoids Origin-header spoofing).
        hooks = self._get_hooks()
        if hooks and hooks.has_hooks('send_verification_email'):
            try:
                from flask_headless_auth.managers.verification_token import generate_confirmation_token
                token = generate_confirmation_token(new_user['email'])
                hooks.fire('send_verification_email', new_user, token)
                logger.info(f"send_verification_email hook fired for {new_user['email']}")
            except Exception as e:
                logger.warning(f"send_verification_email hook failed (non-fatal): {e}")
        else:
            logger.info("No send_verification_email hook registered — skipping email")

        # Fire send_welcome_email hook (optional, app handles delivery)
        if hooks and hooks.has_hooks('send_welcome_email'):
            try:
                hooks.fire('send_welcome_email', new_user)
            except Exception as e:
                logger.warning(f"send_welcome_email hook failed (non-fatal): {e}")

        self.user_data_access.log_user_activity(new_user['id'], "User registered")

        # --- Automatic audit: log signup ---
        self._log_auth_event(
            action='user.signup',
            user_id=new_user['id'],
            metadata={'provider': 'local'},
        )

        # --- after_signup hook (Supabase parity) ---
        if hooks and hooks.has_hooks('after_signup'):
            hooks.fire('after_signup', new_user)

        # Return both success message and user data for auto-login
        result = {
            'message': 'User registered successfully.',
            'user': new_user,  # Include user data for token generation
            'status': 201
        }
        logger.debug("Returning registration result")
        return result

    def confirm_email(self, token):
        from flask_headless_auth.managers.verification_token import confirm_token
        email = confirm_token(token)
        if not email:
            return jsonify({
                'success': False,
                'message': 'Verification link is invalid or has expired.',
                'error_code': 'INVALID_TOKEN'
            }), 400

        user = self.user_data_access.find_user_by_email(email)
        if not user:
            return jsonify({
                'success': False,
                'message': 'User not found.',
                'error_code': 'USER_NOT_FOUND'
            }), 404

        if user['is_verified']:
            return jsonify({
                'success': True,
                'message': 'Account already verified.',
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'is_verified': True
                }
            }), 200

        # Mark the user as verified
        self.user_data_access.update_user(user['id'], {'is_verified': True})
        self.user_data_access.log_user_activity(user['id'], "User email verified")

        # --- Automatic audit: log email verification ---
        self._log_auth_event(
            action='user.email_verification',
            user_id=user['id'],
        )

        return jsonify({
            'success': True,
            'message': 'Email verified successfully.',
            'user': {
                'id': user['id'],
                'email': user['email'],
                'is_verified': True
            },
        }), 200

    def update_user(self, user_id, user_data):
        existing_user = self.user_data_access.find_user_by_email(user_id)
        if not existing_user:
            return jsonify({'error': 'User not found'}), 404

        # Validation rules
        validation_errors = []

        # Email validation
        if 'email' in user_data:
            if user_data['email'] != existing_user['email']:
                import re
                email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                if not re.match(email_pattern, user_data['email']):
                    validation_errors.append('Invalid email format')
                elif self.user_data_access.find_user_by_email(user_data['email']):
                    validation_errors.append('Email is already in use')

        # Phone validation
        if 'phone_number' in user_data and user_data['phone_number']:
            import re
            phone_pattern = r'^\+?[\d\s\-\(\)]{10,15}$'
            if not re.match(phone_pattern, user_data['phone_number']):
                validation_errors.append('Invalid phone number format')

        # Text field length validation
        text_limits = {
            'first_name': 50,
            'last_name': 50,
            'bio': 500,
            'occupation': 100,
            'address': 255,
            'city': 100,
            'state': 100,
            'country': 100,
            'zip_code': 10
        }

        for field, limit in text_limits.items():
            if field in user_data and user_data[field] and len(str(user_data[field])) > limit:
                validation_errors.append(f'{field.replace("_", " ").title()} must be {limit} characters or less')

        # Required fields validation
        required_fields = ['first_name', 'last_name']
        for field in required_fields:
            if field in user_data and (not user_data[field] or not str(user_data[field]).strip()):
                validation_errors.append(f'{field.replace("_", " ").title()} is required')

        # Date validation
        if 'date_of_birth' in user_data and user_data['date_of_birth']:
            try:
                from datetime import datetime
                birth_date = datetime.fromisoformat(user_data['date_of_birth'].replace('Z', '+00:00'))
                if birth_date > datetime.now():
                    validation_errors.append('Date of birth cannot be in the future')
                # Check if user is not too old (reasonable limit)
                if (datetime.now() - birth_date).days > 365 * 150:
                    validation_errors.append('Invalid date of birth')
            except (ValueError, TypeError):
                validation_errors.append('Invalid date format for date of birth')

        if validation_errors:
            return jsonify({'error': '; '.join(validation_errors)}), 400

        protected_fields = {'id', 'role_id', 'password_hash', 'created_at', 'provider', 'is_verified', 'is_active', 'mfa_enabled', 'kyc_status', 'last_login_at'}

        # Handle password update separately (extract before protected-field filter)
        new_password_hash = None
        if 'password' in user_data:
            new_password_hash = self.user_data_access.set_password(user_data['password'])
            del user_data['password']

        # Sanitize and prepare update data
        update_data = {}
        for k, v in user_data.items():
            if k not in protected_fields:
                # Sanitize string fields
                if isinstance(v, str):
                    update_data[k] = v.strip() if v else None
                else:
                    update_data[k] = v

        # Inject password_hash after filter (it's protected from user input but allowed here)
        if new_password_hash:
            update_data['password_hash'] = new_password_hash

        self.user_data_access.update_user(existing_user['id'], update_data)
        self.user_data_access.log_user_activity(existing_user['id'], "User details updated")

        # --- Automatic audit: log profile update ---
        action = 'user.password_change' if 'password_hash' in update_data else 'user.profile_update'
        self._log_auth_event(
            action=action,
            user_id=existing_user['id'],
            metadata={'fields': list(update_data.keys())},
        )

        updated_user = self.user_data_access.find_user_by_email(user_id)
        return jsonify({'message': 'User updated successfully', 'user': updated_user}), 200

    def login_user(self, user_data):
        # --- before_login hook (Supabase parity) ---
        hooks = self._get_hooks()
        if hooks and hooks.has_hooks('before_login'):
            try:
                hooks.fire('before_login', user_data)
            except ValueError as exc:
                return {'error': str(exc), 'status': 400}

        # --- Brute-force protection (Supabase parity) ---
        # Check if too many failed attempts before even verifying password
        audit_mgr = _get_audit_manager()
        max_attempts = current_app.config.get('AUTHSVC_MAX_LOGIN_ATTEMPTS', 5)
        attempt_window = current_app.config.get('AUTHSVC_LOGIN_ATTEMPT_WINDOW', 30)

        if audit_mgr and max_attempts:
            ip_address = None
            try:
                ip_address = request.remote_addr
            except Exception:
                pass

            failed_count = audit_mgr.get_failed_login_count(
                ip_address=ip_address,
                window_minutes=attempt_window,
            )
            if failed_count >= max_attempts:
                self._log_auth_event(
                    action='user.login_failed',
                    success=False,
                    error_message='Too many failed attempts (rate limited)',
                    metadata={'email': user_data.get('email', '')[:50], 'ip': ip_address},
                )
                remaining_minutes = attempt_window
                return {
                    'error': f'Too many login attempts. Try again in {remaining_minutes} minutes.',
                    'status': 429,
                    'retry_after_minutes': remaining_minutes,
                }

        # Include password_hash for authentication
        user = self.user_data_access.find_user_by_email(user_data.get('email'), include_password_hash=True)

        if not user or not self.user_data_access.verify_password(user['password_hash'], user_data.get('password')):
            # --- Automatic audit: log failed login attempt ---
            self._log_auth_event(
                action='user.login_failed',
                user_id=user['id'] if user else None,
                success=False,
                error_message='Invalid email or password',
                metadata={'email': user_data.get('email', '')[:50]},
            )
            return {'error': 'Invalid email or password', 'status': 401}

        # --- Block banned/deactivated users (Supabase parity) ---
        if not user.get('is_active', True):
            self._log_auth_event(
                action='user.login_failed',
                user_id=user['id'],
                success=False,
                error_message='Account is deactivated',
            )
            return {
                'error': 'Your account has been deactivated. Contact your administrator.',
                'status': 403,
                'error_code': 'ACCOUNT_DEACTIVATED',
            }

        require_verification = current_app.config.get('REQUIRE_EMAIL_VERIFICATION', False)

        if require_verification and not user['is_verified']:
            return {
                'error': 'Email not verified. Please check your email.',
                'status': 403,
                'is_verified': False,
                'user_id': user['id']
            }

        self.user_data_access.update_user(user['id'], {'last_login_at': datetime.utcnow()})
        self.user_data_access.log_user_activity(user['id'], "User logged in")

        # Remove password_hash from response for security
        safe_user = {k: v for k, v in user.items() if k != 'password_hash'}

        # --- after_login hook (Supabase parity) ---
        if hooks and hooks.has_hooks('after_login'):
            hooks.fire('after_login', safe_user)

        return {
            'user': safe_user,
            'is_verified': user['is_verified'],
            'require_verification': require_verification
        }

    def request_password_reset(self, email, redirect_url=None):
        user = self.user_data_access.find_user_by_email(email)
        if not user:
            # Return same message to prevent email enumeration
            return jsonify({'message': 'If an account exists, a reset link has been sent.'}), 200

        token = uuid.uuid4().hex
        expires_at = datetime.utcnow() + timedelta(hours=1)
        self.user_data_access.create_password_reset_token(user['id'], token, expires_at)

        # Fire send_password_reset_email hook.
        # Signature: (user_dict, token, redirect_url)
        #   redirect_url is passed through as-is from the route.
        #   The consuming app is responsible for validating it
        #   (e.g. against an allowlist) before using it.
        hooks = self._get_hooks()
        if hooks and hooks.has_hooks('send_password_reset_email'):
            try:
                hooks.fire('send_password_reset_email', user, token, redirect_url)
                logger.info(f"send_password_reset_email hook fired for user {user['id']}")
            except Exception as e:
                logger.warning(f"send_password_reset_email hook failed (non-fatal): {e}")
        else:
            logger.warning(
                "No send_password_reset_email hook registered — "
                "token created but no email will be sent"
            )

        self.user_data_access.log_user_activity(user['id'], "Password reset requested")

        # --- Automatic audit: log password reset request ---
        self._log_auth_event(
            action='user.password_reset_request',
            user_id=user['id'],
        )

        return jsonify({'message': 'If an account exists, a reset link has been sent.'}), 200

    def reset_password(self, token, new_password):
        """
        Complete the password reset: validate token, update password, invalidate token.
        """
        if not new_password or len(new_password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        user_id = self.user_data_access.verify_password_reset_token(token)
        if not user_id:
            return jsonify({
                'error': 'Reset link is invalid or has expired.',
                'error_code': 'INVALID_TOKEN'
            }), 400

        new_hash = self.user_data_access.set_password(new_password)
        self.user_data_access.update_user(user_id, {'password_hash': new_hash})

        self.user_data_access.invalidate_password_reset_token(token)

        # Clear brute-force lockout so the user can log in immediately
        audit_mgr = _get_audit_manager()
        if audit_mgr:
            audit_mgr.clear_failed_login_attempts(user_id)

        self.user_data_access.log_user_activity(user_id, "Password reset completed")

        self._log_auth_event(
            action='user.password_change',
            user_id=user_id,
            metadata={'method': 'reset_token'},
        )

        return jsonify({'message': 'Password has been reset successfully.'}), 200
