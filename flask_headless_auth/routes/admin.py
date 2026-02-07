"""
flask_headless_auth.routes.admin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Admin user-management API routes.

Follows the Clerk / Supabase / Auth0 pattern where ALL admin-facing
user operations live under ``/api/admin/users/``.

Endpoint summary (all admin-only):
    GET    /users                          - list users (paginated)
    POST   /users                          - create user (admin onboarding)
    GET    /users/<uid>                    - user details + account status
    DELETE /users/<uid>                    - delete user (soft or hard)
    POST   /users/<uid>/ban               - ban / deactivate user
    POST   /users/<uid>/unban             - unban / reactivate user
    GET    /users/<uid>/sessions           - view user's sessions
    POST   /users/<uid>/sessions/revoke-all - force-logout user
"""

import logging
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt

logger = logging.getLogger(__name__)


def _is_admin(claims):
    """
    Check admin access using RBAC config.
    Works with any role name configured in AUTHSVC_RBAC_ADMIN_ROLE.
    """
    role_name = claims.get('role_name')
    if not role_name:
        return False
    admin_role = current_app.config.get('AUTHSVC_RBAC_ADMIN_ROLE', 'admin')
    return role_name == admin_role


def _require_admin():
    """Return (claims, None) if admin, or (None, error_response) if not."""
    claims = get_jwt()
    if not _is_admin(claims):
        return None, (jsonify({'error': 'Admin access required'}), 403)
    return claims, None


def create_admin_blueprint(user_model, audit_manager,
                           blueprint_name='authsvc_admin'):
    """
    Create and return the admin user-management blueprint.

    Args:
        user_model: User model class
        audit_manager: AuditManager instance (for sessions & audit logging)
        blueprint_name: Name for the blueprint

    Returns:
        Flask Blueprint with admin routes
    """
    bp = Blueprint(blueprint_name, __name__)

    # Helper to get db session
    def _db():
        from flask_headless_auth import extensions
        return extensions.db or extensions.get_db()

    # ==================================================================
    # USER LISTING
    # ==================================================================

    @bp.route('/users', methods=['GET'])
    @jwt_required()
    def list_users():
        """
        List all users (paginated).

        Query params:
            page (int): Page number, default 1
            per_page (int): Items per page, default 20 (max 100)
            is_active (bool): Filter by active status
            role_id (int): Filter by role
            q (str): Search by email (partial match)
        """
        claims, err = _require_admin()
        if err:
            return err

        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)

        query = user_model.query

        # Optional filters
        is_active = request.args.get('is_active')
        if is_active is not None:
            query = query.filter_by(is_active=is_active.lower() == 'true')

        role_id = request.args.get('role_id', type=int)
        if role_id is not None:
            query = query.filter_by(role_id=role_id)

        search = request.args.get('q', '').strip()
        if search:
            query = query.filter(user_model.email.ilike(f'%{search}%'))

        pagination = query.order_by(user_model.id).paginate(
            page=page, per_page=per_page, error_out=False)

        users = []
        for u in pagination.items:
            users.append(_user_summary(u))

        return jsonify({
            'users': users,
            'total': pagination.total,
            'page': pagination.page,
            'pages': pagination.pages,
            'per_page': per_page,
        }), 200

    # ==================================================================
    # ADMIN CREATE USER  (Supabase: admin.createUser, Clerk: POST /users)
    # ==================================================================

    @bp.route('/users', methods=['POST'])
    @jwt_required()
    def create_user():
        """
        Create a new user (admin onboarding).

        Allows an admin to add staff without self-registration.
        The user is created with is_verified=True by default (admin-created
        users are trusted).

        Body:
            email (str): Required
            password (str): Required
            first_name (str): Optional
            last_name (str): Optional
            role_id (int): Optional (assign role immediately)
            is_verified (bool): Optional (default True)
            send_invite (bool): Optional - send welcome email (default False)
        """
        claims, err = _require_admin()
        if err:
            return err

        data = request.get_json(silent=True) or {}
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()

        if not email or not password:
            return jsonify({'error': 'email and password are required'}), 400

        # Check for duplicate
        existing = user_model.query.filter_by(email=email).first()
        if existing:
            return jsonify({'error': 'Email is already registered'}), 409

        # Hash password
        from werkzeug.security import generate_password_hash
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')

        # Resolve role if provided (accepts "role" name or "role_id")
        resolved_role_id = data.get('role_id')
        if not resolved_role_id and data.get('role'):
            try:
                from flask_headless_auth.routes.rbac import resolve_role
                from flask_headless_auth.managers.rbac_manager import RBACManager
                authsvc = current_app.extensions.get('authsvc')
                if authsvc:
                    rbac_mgr = RBACManager(
                        role_model=authsvc.role_model,
                        permission_model=authsvc.permission_model,
                        user_model=user_model,
                    )
                    role_obj, err = resolve_role(data, rbac_mgr)
                    if role_obj:
                        resolved_role_id = role_obj.id
            except Exception:
                pass  # Fall through — role won't be set

        # Build user kwargs from data (only accepted fields)
        allowed_fields = {
            'first_name', 'last_name', 'phone_number',
        }
        user_kwargs = {k: v for k, v in data.items() if k in allowed_fields}
        if resolved_role_id:
            user_kwargs['role_id'] = resolved_role_id
        user_kwargs.update({
            'email': email,
            'password_hash': password_hash,
            'is_verified': data.get('is_verified', True),
            'is_active': True,
            'provider': 'admin',
        })

        try:
            new_user = user_model(**user_kwargs)
            _db().session.add(new_user)
            _db().session.commit()
        except Exception as exc:
            _db().session.rollback()
            logger.error(f'Admin create user failed: {exc}')
            return jsonify({'error': 'Failed to create user'}), 500

        admin_id = claims.get('id')

        # Audit log
        audit_manager.log_event(
            action='user.admin_created',
            user_id=admin_id,
            target_user_id=new_user.id,
            metadata={
                'email': email,
                'role_id': user_kwargs.get('role_id'),
            },
        )

        logger.info(f'User {new_user.id} created by admin {admin_id}')

        return jsonify({
            'message': 'User created successfully',
            'user': _user_summary(new_user),
        }), 201

    # ==================================================================
    # USER DETAILS / STATUS  (Clerk: GET /users/{id})
    # ==================================================================

    @bp.route('/users/<int:uid>', methods=['GET'])
    @jwt_required()
    def get_user(uid):
        """
        Get a user's full account status.

        Returns profile, is_active, session count, last login, ban history.
        """
        claims, err = _require_admin()
        if err:
            return err

        user = user_model.query.get(uid)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        active_sessions = audit_manager.get_user_sessions(uid, active_only=True)

        # Last login from audit log
        last_login_logs = audit_manager.get_audit_logs(
            user_id=uid, action='user.login', limit=1)
        last_login = (last_login_logs[0].timestamp.isoformat()
                      if last_login_logs else None)

        # Ban history
        ban_logs = audit_manager.get_audit_logs(
            action='user.banned', limit=20)
        ban_history = [l.to_dict() for l in ban_logs
                       if l.target_user_id == uid][:5]

        return jsonify({
            'user': _user_summary(user),
            'is_active': user.is_active,
            'is_verified': user.is_verified,
            'active_sessions': len(active_sessions),
            'last_login': last_login,
            'ban_history': ban_history,
        }), 200

    # ==================================================================
    # DELETE USER  (Supabase: admin.deleteUser, Clerk: DELETE /users/{id})
    # ==================================================================

    @bp.route('/users/<int:uid>', methods=['DELETE'])
    @jwt_required()
    def delete_user(uid):
        """
        Delete a user (admin only).

        By default performs a soft-delete (sets is_active=False and
        anonymises email).  Pass ``?hard=true`` to permanently remove
        the row from the database.

        Query params:
            hard (bool): Permanently delete the row (default False)
        """
        claims, err = _require_admin()
        if err:
            return err

        admin_id = claims.get('id')
        if admin_id == uid:
            return jsonify({'error': 'Cannot delete yourself'}), 400

        user = user_model.query.get(uid)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        hard_delete = request.args.get('hard', 'false').lower() == 'true'

        # Revoke all sessions first
        sessions_revoked = audit_manager.revoke_all_user_sessions(uid)

        if hard_delete:
            _db().session.delete(user)
            _db().session.commit()
            action = 'user.hard_deleted'
        else:
            # Soft-delete: deactivate + anonymise email to free the address
            user.is_active = False
            user.email = f'deleted_{uid}@deactivated.local'
            if hasattr(user, 'first_name'):
                user.first_name = 'Deleted'
            if hasattr(user, 'last_name'):
                user.last_name = 'User'
            _db().session.commit()
            action = 'user.soft_deleted'

        # Audit log
        audit_manager.log_event(
            action=action,
            user_id=admin_id,
            target_user_id=uid,
            metadata={
                'hard_delete': hard_delete,
                'sessions_revoked': sessions_revoked,
            },
        )

        logger.info(f'User {uid} {"hard" if hard_delete else "soft"}-deleted by admin {admin_id}')

        return jsonify({
            'message': f'User {uid} has been {"permanently deleted" if hard_delete else "deactivated"}',
            'user_id': uid,
            'hard_delete': hard_delete,
            'sessions_revoked': sessions_revoked,
        }), 200

    # ==================================================================
    # BAN / UNBAN  (Clerk: POST /users/{id}/ban, POST /users/{id}/unban)
    # ==================================================================

    @bp.route('/users/<int:uid>/ban', methods=['POST'])
    @jwt_required()
    def ban_user(uid):
        """
        Ban / deactivate a user.

        Sets is_active=False, revokes ALL sessions (immediate lockout),
        and records the event in the audit log.

        Body (optional):
            reason (str): Reason for banning
            duration_hours (int): Stored in audit metadata for reference
        """
        claims, err = _require_admin()
        if err:
            return err

        admin_id = claims.get('id')
        if admin_id == uid:
            return jsonify({'error': 'Cannot ban yourself'}), 400

        user = user_model.query.get(uid)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if not user.is_active:
            return jsonify({
                'message': 'User is already banned',
                'user_id': uid,
            }), 200

        data = request.get_json(silent=True) or {}
        reason = data.get('reason', 'Banned by admin')

        # 1. Deactivate
        user.is_active = False
        _db().session.commit()

        # 2. Revoke ALL active sessions (immediate lockout)
        sessions_revoked = audit_manager.revoke_all_user_sessions(uid)

        # 3. Audit log
        audit_manager.log_event(
            action='user.banned',
            user_id=admin_id,
            target_user_id=uid,
            metadata={
                'reason': reason,
                'sessions_revoked': sessions_revoked,
                'duration_hours': data.get('duration_hours'),
            },
        )

        logger.info(f'User {uid} banned by admin {admin_id}: {reason}')

        return jsonify({
            'message': f'User {uid} has been banned',
            'user_id': uid,
            'sessions_revoked': sessions_revoked,
            'reason': reason,
        }), 200

    @bp.route('/users/<int:uid>/unban', methods=['POST'])
    @jwt_required()
    def unban_user(uid):
        """
        Unban / reactivate a user.

        Sets is_active=True. The user can log in again.

        Body (optional):
            reason (str): Reason for unbanning
        """
        claims, err = _require_admin()
        if err:
            return err

        user = user_model.query.get(uid)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.is_active:
            return jsonify({
                'message': 'User is not banned',
                'user_id': uid,
            }), 200

        admin_id = claims.get('id')
        data = request.get_json(silent=True) or {}
        reason = data.get('reason', 'Unbanned by admin')

        # Reactivate
        user.is_active = True
        _db().session.commit()

        # Audit log
        audit_manager.log_event(
            action='user.unbanned',
            user_id=admin_id,
            target_user_id=uid,
            metadata={'reason': reason},
        )

        logger.info(f'User {uid} unbanned by admin {admin_id}: {reason}')

        return jsonify({
            'message': f'User {uid} has been reactivated',
            'user_id': uid,
        }), 200

    # ==================================================================
    # ADMIN SESSION MANAGEMENT  (per-user)
    # ==================================================================

    @bp.route('/users/<int:uid>/sessions', methods=['GET'])
    @jwt_required()
    def user_sessions(uid):
        """View all sessions for a user (including revoked)."""
        claims, err = _require_admin()
        if err:
            return err

        user = user_model.query.get(uid)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        sessions = audit_manager.get_user_sessions(uid, active_only=False)
        return jsonify({
            'user_id': uid,
            'sessions': [s.to_dict(include_sensitive=True) for s in sessions],
            'count': len(sessions),
        }), 200

    @bp.route('/users/<int:uid>/sessions/revoke-all', methods=['POST'])
    @jwt_required()
    def force_logout_user(uid):
        """Force-logout a user from all devices."""
        claims, err = _require_admin()
        if err:
            return err

        user = user_model.query.get(uid)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        count = audit_manager.revoke_all_user_sessions(uid)
        audit_manager.log_event(
            action='session.admin_revoke_all',
            user_id=claims.get('id'),
            target_user_id=uid,
            metadata={'sessions_revoked': count},
        )

        return jsonify({
            'message': f'Revoked {count} sessions for user {uid}',
            'user_id': uid,
            'sessions_revoked': count,
        }), 200

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _user_summary(user):
        """Safe user dict for admin API responses."""
        data = {
            'id': user.id,
            'email': user.email,
            'is_active': user.is_active,
            'is_verified': getattr(user, 'is_verified', None),
            'role_id': getattr(user, 'role_id', None),
        }
        if hasattr(user, 'first_name'):
            data['first_name'] = user.first_name
        if hasattr(user, 'last_name'):
            data['last_name'] = user.last_name
        if hasattr(user, 'created_at') and user.created_at:
            data['created_at'] = user.created_at.isoformat()
        if hasattr(user, 'provider'):
            data['provider'] = user.provider
        return data

    return bp
