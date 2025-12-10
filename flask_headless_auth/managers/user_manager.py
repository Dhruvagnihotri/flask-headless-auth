from flask import jsonify, url_for, current_app
from datetime import datetime, timedelta
import uuid
import logging
from flask_headless_auth.interfaces import UserDataAccess

logger = logging.getLogger(__name__)

class UserManager:
    def __init__(self, user_data_access: UserDataAccess, cache=None, email_manager=None):
        self.user_data_access = user_data_access
        self.cache = cache  # Cache is optional
        self.email_manager = email_manager

    def register_user(self, user_data):
        # Handle legacy format where frontend might send array  
        if isinstance(user_data, list) and user_data:
            user_data = user_data[0]
        if not user_data.get('email') or not user_data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400

        existing_user = self.user_data_access.find_user_by_email(user_data['email'])
        if existing_user:
            return jsonify({'error': 'Email is already registered'}), 400

        user_data['password_hash'] = self.user_data_access.set_password(user_data.get('password'))
        user_data['role_id'] = user_data.get('role_id', 2)
        user_data['is_verified'] = False  # Add verification flag

        logger.debug(f"Creating user with email: {user_data.get('email')}")
        new_user = self.user_data_access.create_user(user_data)
        logger.info(f"Created user with ID: {new_user.get('id')}")
        
        # Send verification email if email manager is configured
        if self.email_manager:
            try:
                email_sent = self.email_manager.send_verification_email(new_user['email'])
                if email_sent:
                    logger.info(f"Verification email sent to {new_user['email']}")
                else:
                    logger.warning(f"Failed to send verification email to {new_user['email']}")
            except Exception as e:
                logger.error(f"Error sending verification email: {e}")

        self.user_data_access.log_user_activity(new_user['id'], "User registered")

        # Return both success message and user data for auto-login
        result = {
            'message': 'User registered successfully.',
            'user': new_user,  # Include user data for token generation
            'status': 201
        }
        logger.debug("Returning registration result")
        return result

    def confirm_email(self, token):
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

        # Generate login URL
        login_url = f"{current_app.config['FRONTEND_URL']}/login"

        return jsonify({
            'success': True,
            'message': 'Email verified successfully.',
            'user': {
                'id': user['id'],
                'email': user['email'],
                'is_verified': True
            },
            'login_url': login_url
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

        # Handle password update separately
        if 'password' in user_data:
            user_data['password_hash'] = self.user_data_access.set_password(user_data['password'])
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

        self.user_data_access.update_user(existing_user['id'], update_data)
        self.user_data_access.log_user_activity(existing_user['id'], "User details updated")

        updated_user = self.user_data_access.find_user_by_email(user_id)
        return jsonify({'message': 'User updated successfully', 'user': updated_user}), 200

    def login_user(self, user_data):
        # Include password_hash for authentication
        user = self.user_data_access.find_user_by_email(user_data.get('email'), include_password_hash=True)

        if not user or not self.user_data_access.verify_password(user['password_hash'], user_data.get('password')):
            return {'error': 'Invalid email or password', 'status': 401}

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

        return {
            'user': safe_user,
            'is_verified': user['is_verified'],
            'require_verification': require_verification
        }

    def request_password_reset(self, email):
        user = self.user_data_access.find_user_by_email(email)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        token = uuid.uuid4().hex
        expires_at = datetime.utcnow() + timedelta(hours=1)
        self.user_data_access.create_password_reset_token(user['id'], token, expires_at)

        self.user_data_access.log_user_activity(user['id'], "Password reset requested")

        return jsonify({'message': 'Password reset link sent to your email'}), 200
