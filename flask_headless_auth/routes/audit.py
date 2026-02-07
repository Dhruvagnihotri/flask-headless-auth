"""
flask_headless_auth.routes.audit
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

API routes for audit logs, session management, and activity history.
All tables are auto-populated by the library.  These routes just expose
read access and session controls.

User-facing endpoints (any authenticated user):
    /audit-logs/me              GET   - my auth event history
    /sessions/me                GET   - my active sessions
    /sessions/<sid>             DELETE - revoke one session
    /sessions/revoke-all        POST  - logout from all devices
    /activity-logs/me           GET   - my activity history

Admin-only read endpoints:
    /audit-logs                 GET   - all logs
    /audit-logs/security        GET   - security events
    /activity-logs/resource/... GET   - resource access history
    /compliance/security-summary  GET - security dashboard

Note: Admin user-management (ban/unban, user sessions, user listing)
lives in the admin blueprint at /api/admin/users/.
"""

import logging
from datetime import datetime, timedelta
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


def create_audit_blueprint(audit_manager, blueprint_name='authsvc_audit'):
    bp = Blueprint(blueprint_name, __name__)

    # ==================================================================
    # AUDIT LOGS
    # ==================================================================

    @bp.route('/audit-logs/me', methods=['GET'])
    @jwt_required()
    def my_audit_logs():
        """My auth event history (any authenticated user)."""
        claims = get_jwt()
        user_id = claims.get('id')

        action = request.args.get('action')
        limit = min(int(request.args.get('limit', 50)), 200)
        offset = int(request.args.get('offset', 0))

        logs = audit_manager.get_audit_logs(
            user_id=user_id, action=action,
            limit=limit, offset=offset,
        )
        return jsonify({
            'logs': [l.to_dict() for l in logs],
            'count': len(logs),
        }), 200

    @bp.route('/audit-logs', methods=['GET'])
    @jwt_required()
    def all_audit_logs():
        """All audit logs (admin only)."""
        claims = get_jwt()
        if not _is_admin(claims):
            return jsonify({'error': 'Admin access required'}), 403

        action = request.args.get('action')
        tenant_id = claims.get('tenant_id')
        limit = min(int(request.args.get('limit', 100)), 1000)
        offset = int(request.args.get('offset', 0))

        start_date = _parse_date(request.args.get('start_date'))
        end_date = _parse_date(request.args.get('end_date'))

        logs = audit_manager.get_audit_logs(
            action=action, tenant_id=tenant_id,
            start_date=start_date, end_date=end_date,
            limit=limit, offset=offset,
        )
        return jsonify({
            'logs': [l.to_dict() for l in logs],
            'count': len(logs),
            'limit': limit,
            'offset': offset,
        }), 200

    @bp.route('/audit-logs/security', methods=['GET'])
    @jwt_required()
    def security_events():
        """Recent security-related events (admin only)."""
        claims = get_jwt()
        if not _is_admin(claims):
            return jsonify({'error': 'Admin access required'}), 403

        tenant_id = claims.get('tenant_id')
        start = datetime.utcnow() - timedelta(days=7)

        security_actions = [
            'user.login', 'user.login_failed', 'user.logout',
            'user.password_change', 'user.mfa_enabled',
            'session.revoked', 'session.revoked_all',
        ]
        all_logs = []
        for act in security_actions:
            all_logs.extend(audit_manager.get_audit_logs(
                action=act, tenant_id=tenant_id,
                start_date=start, limit=50,
            ))
        all_logs.sort(key=lambda x: x.timestamp, reverse=True)

        return jsonify({
            'logs': [l.to_dict() for l in all_logs[:100]],
            'count': len(all_logs[:100]),
        }), 200

    # ==================================================================
    # SESSION MANAGEMENT
    # ==================================================================

    @bp.route('/sessions/me', methods=['GET'])
    @jwt_required()
    def my_sessions():
        """List my active sessions (any authenticated user)."""
        claims = get_jwt()
        user_id = claims.get('id')
        current_jti = claims.get('jti')

        sessions = audit_manager.get_user_sessions(user_id, active_only=True)
        data = []
        for s in sessions:
            d = s.to_dict()
            d['is_current'] = (s.jti == current_jti)
            data.append(d)

        return jsonify({'sessions': data, 'count': len(data)}), 200

    @bp.route('/sessions/<session_id>', methods=['DELETE'])
    @jwt_required()
    def revoke_session(session_id):
        """Revoke one of my sessions."""
        claims = get_jwt()
        user_id = claims.get('id')

        s = audit_manager.UserSession.query.filter_by(
            session_id=session_id).first()

        if not s:
            return jsonify({'error': 'Session not found'}), 404
        if s.user_id != user_id:
            return jsonify({'error': 'Access denied'}), 403

        audit_manager.revoke_session_by_jti(s.jti, reason='user_logout')
        audit_manager.log_event(
            action='session.revoked', user_id=user_id,
            session_id=session_id,
        )
        return jsonify({'message': 'Session revoked', 'session_id': session_id}), 200

    @bp.route('/sessions/revoke-all', methods=['POST'])
    @jwt_required()
    def revoke_all_mine():
        """Logout from all devices except current."""
        claims = get_jwt()
        user_id = claims.get('id')
        current_jti = claims.get('jti')

        count = audit_manager.revoke_all_user_sessions(
            user_id, except_jti=current_jti)
        audit_manager.log_event(
            action='session.revoked_all', user_id=user_id,
            metadata={'count': count},
        )
        return jsonify({
            'message': f'Revoked {count} sessions',
            'sessions_revoked': count,
        }), 200

    # ==================================================================
    # ACTIVITY LOGS
    # ==================================================================

    @bp.route('/activity-logs/me', methods=['GET'])
    @jwt_required()
    def my_activity():
        """My application activity history."""
        claims = get_jwt()
        user_id = claims.get('id')
        limit = min(int(request.args.get('limit', 50)), 200)
        offset = int(request.args.get('offset', 0))

        activities = audit_manager.get_user_activity(
            user_id, limit=limit, offset=offset)
        return jsonify({
            'activities': [a.to_dict() for a in activities],
            'count': len(activities),
        }), 200

    @bp.route('/activity-logs/resource/<resource_type>/<int:resource_id>',
              methods=['GET'])
    @jwt_required()
    def resource_history(resource_type, resource_id):
        """Access history for a specific resource."""
        limit = min(int(request.args.get('limit', 100)), 500)
        history = audit_manager.get_resource_access_history(
            resource_type, resource_id, limit=limit)

        # Scope to caller's tenant if applicable (multi-tenancy)
        tenant_id = get_jwt().get('tenant_id')
        if tenant_id:
            history = [h for h in history if h.tenant_id == tenant_id]

        return jsonify({
            'resource_type': resource_type,
            'resource_id': resource_id,
            'access_history': [h.to_dict() for h in history],
            'count': len(history),
        }), 200

    # ==================================================================
    # COMPLIANCE / SECURITY REPORTS
    # ==================================================================

    @bp.route('/compliance/security-summary', methods=['GET'])
    @jwt_required()
    def security_summary():
        """30-day security dashboard (admin only)."""
        claims = get_jwt()
        if not _is_admin(claims):
            return jsonify({'error': 'Admin access required'}), 403

        start = datetime.utcnow() - timedelta(days=30)
        tenant_id = claims.get('tenant_id')

        def _count(model, extra_filters=None):
            q = model.query.filter(model.timestamp >= start)
            if tenant_id:
                q = q.filter_by(tenant_id=tenant_id)
            if extra_filters:
                for f in extra_filters:
                    q = q.filter(f)
            return q.count()

        AL = audit_manager.AuditLog
        summary = {
            'period_days': 30,
            'start_date': start.isoformat(),
            'end_date': datetime.utcnow().isoformat(),
            'total_logins': _count(AL, [AL.action == 'user.login', AL.success == True]),
            'failed_logins': _count(AL, [AL.action == 'user.login_failed']),
            'signups': _count(AL, [AL.action == 'user.signup']),
            'password_changes': _count(AL, [AL.action == 'user.password_change']),
            'active_sessions': audit_manager.UserSession.query.filter_by(
                is_active=True, revoked=False
            ).count(),
        }
        return jsonify(summary), 200

    # ------------------------------------------------------------------

    return bp


def _parse_date(val):
    """Parse ISO date string, return None on failure."""
    if not val:
        return None
    try:
        return datetime.fromisoformat(val)
    except Exception:
        return None
