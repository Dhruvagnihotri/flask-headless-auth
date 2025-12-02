"""
flask_headless_auth.models.oauth
~~~~~~~~~~~~~~~~~~~~~~~~~~~

OAuth token storage model.
"""

from datetime import datetime
from sqlalchemy.ext.declarative import declared_attr
from flask_headless_auth import extensions

# Import db from extensions - it will be set by core.py before models are imported
db = extensions.db or extensions.get_db()


class OAuthToken(db.Model):
    """OAuth tokens from third-party providers."""
    
    @declared_attr
    def __tablename__(cls):
        """Generate table name based on app config."""
        from flask import current_app
        try:
            prefix = current_app.config.get('AUTHSVC_TABLE_PREFIX', 'authsvc')
        except RuntimeError:
            prefix = 'authsvc'
        return f'{prefix}_oauth_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    provider = db.Column(db.String(50), nullable=False)  # google, microsoft, github, etc.
    access_token = db.Column(db.String(500))
    refresh_token = db.Column(db.String(500))
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

