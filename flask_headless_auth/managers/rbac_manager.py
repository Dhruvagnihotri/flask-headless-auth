# rbac_manager.py
from functools import wraps
from flask_jwt_extended import get_jwt
from flask import jsonify

def role_required_authsvc(required_role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            if claims.get('role') != required_role:
                return jsonify({"msg": "Access forbidden: insufficient role"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator