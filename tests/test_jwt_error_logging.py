"""
Regression coverage for a real production incident: a Klaveno (MrScribe)
user's session died silently after being idle for ~3.5 hours, with zero log
trace anywhere - flask-jwt-extended's default expired/invalid/missing/revoked
token callbacks are completely silent by design, and nothing in this library
ever overrode them.

_init_jwt now registers a logging wrapper around each of those four
callbacks, delegating to flask-jwt-extended's own default implementation for
the actual response. These tests lock in two things an adversarial review
flagged as easy to get wrong silently:

1. The response body/status code must stay byte-identical to the untouched
   default - any consuming frontend's existing error handling depends on
   that shape not changing.
2. The log level must be split: an expired ACCESS token and a missing token
   are the normal shape of every refresh cycle and every anonymous page
   load (INFO), not the signal worth alerting on - an expired/revoked
   REFRESH token is what actually means "this session needs a real
   re-login" (WARNING).
"""

import time

import pytest
from flask import Flask
from flask_jwt_extended import create_access_token, create_refresh_token

from flask_headless_auth import AuthSvc


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["JWT_SECRET_KEY"] = "test-secret"
    app.config["SECRET_KEY"] = "test-secret"
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 1
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = 1
    AuthSvc(app)
    return app


def test_expired_access_token_response_matches_default(app, caplog):
    with app.app_context():
        token = create_access_token(identity="access-test@example.com")
    time.sleep(1.1)

    with caplog.at_level("INFO", logger="flask_headless_auth.core"):
        with app.test_client() as c:
            resp = c.get("/api/auth/check-auth", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 401
    assert resp.get_json() == {"msg": "Token has expired"}

    records = [r for r in caplog.records if "JWT expired" in r.message]
    assert len(records) == 1
    assert records[0].levelname == "INFO"  # routine, not actionable
    assert "access-test@example.com" in records[0].message


def test_expired_refresh_token_logs_at_warning(app, caplog):
    with app.app_context():
        token = create_refresh_token(identity="refresh-test@example.com")
    time.sleep(1.1)

    with caplog.at_level("INFO", logger="flask_headless_auth.core"):
        with app.test_client() as c:
            resp = c.post("/api/auth/token/refresh", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 401
    assert resp.get_json() == {"msg": "Token has expired"}

    records = [r for r in caplog.records if "JWT expired" in r.message]
    assert len(records) == 1
    assert records[0].levelname == "WARNING"  # the signal worth alerting on
    assert "refresh-test@example.com" in records[0].message


def test_missing_token_response_matches_default_and_logs_at_info(app, caplog):
    with caplog.at_level("INFO", logger="flask_headless_auth.core"):
        with app.test_client() as c:
            resp = c.get("/api/auth/check-auth")

    assert resp.status_code == 401
    body = resp.get_json()
    assert "msg" in body and "Missing" in body["msg"]

    records = [r for r in caplog.records if "JWT missing" in r.message]
    assert len(records) == 1
    assert records[0].levelname == "INFO"  # fires on every anonymous page load


def test_invalid_token_response_matches_default_and_logs_at_warning(app, caplog):
    with caplog.at_level("INFO", logger="flask_headless_auth.core"):
        with app.test_client() as c:
            resp = c.get("/api/auth/check-auth", headers={"Authorization": "Bearer not-a-real-jwt"})

    assert resp.status_code == 422
    assert "msg" in resp.get_json()

    records = [r for r in caplog.records if "JWT invalid" in r.message]
    assert len(records) == 1
    assert records[0].levelname == "WARNING"


def test_log_line_quotes_path_against_log_injection(app, caplog):
    """A path containing a raw newline must not be interpolated unquoted -
    %r (not %s) is what keeps a %0A in a URL from forging a fake log line."""
    with caplog.at_level("INFO", logger="flask_headless_auth.core"):
        with app.test_client() as c:
            # Flask's test client won't route a literal newline, so this
            # exercises the %r formatting on an ordinary path instead of a
            # hostile one - the real guarantee is that %r is used at all,
            # verified by inspecting the source in test_core.py-adjacent
            # review; this test just pins that the path is quoted in output.
            resp = c.get("/api/auth/check-auth")

    assert resp.status_code == 401
    records = [r for r in caplog.records if "JWT missing" in r.message]
    assert len(records) == 1
    assert "path='/api/auth/check-auth'" in records[0].message
