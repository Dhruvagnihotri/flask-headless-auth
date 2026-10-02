"""
Regression coverage for a real production incident across two apps sharing
this library (Klaveno and pdfcourt): a refresh-token rotation race got
misreported as "session expired due to inactivity" and could delete the
cookies a concurrent, winning refresh had just set - a hard, unexplained
logout with nothing to do with inactivity.

Each /token/refresh call rewrites the session row's jti to the newly-issued
refresh token's jti. If two refresh calls for the same session happen close
together (two tabs whose proactive timers fire together, a slow request
racing a client-side retry), the loser's own refresh token's jti no longer
matches the session row by the time it tries to use it - even though the
session itself is still perfectly alive, just already rotated by the
winner. touch_session() now falls back to the stable session_id (unlike jti,
it never changes across rotation) to tell "already rotated by someone else"
apart from "genuinely gone" - these tests pin that fix in both the
serialized and interleaved shapes of the race, confirmed by direct
reproduction before this fix existed.

An adversarial review of an earlier version of this fix caught a real
regression before it shipped: an unconditional session_id fallback skips
the inactivity-cutoff check entirely, since every genuine refresh keeps
rotating the row away from any token that isn't the latest one - meaning a
captured/old refresh token (dual delivery mode puts it in a JS-readable
response body) could be replayed indefinitely to defeat
AUTHSVC_SESSION_INACTIVITY_TIMEOUT. The fallback is now bounded by
AUTHSVC_REFRESH_REUSE_GRACE_SECONDS (default 30s) against the matched row's
own last_activity, and falls through into the SAME cutoff logic the primary
path uses rather than duplicating it - test_fallback_does_not_bypass_* pin
this specifically.

Also fixes a related pre-existing bug this same session_id lookup makes
easy to fix for free: /logout only ever had the ACCESS token's jti
available (it's access-token-protected), but UserSession rows are keyed by
the REFRESH token's jti, so logout never actually revoked the session row
at all - a logged-out session's refresh token kept working indefinitely.
test_logout_actually_revokes_the_session_row pins the fix.
"""

import pytest
from flask import Flask

from flask_headless_auth import AuthSvc


@pytest.fixture
def client():
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["JWT_SECRET_KEY"] = "test-secret"
    app.config["SECRET_KEY"] = "test-secret"
    AuthSvc(app)
    with app.test_client() as c:
        yield c


def _signup_and_login(client):
    email = "race-test@example.com"
    password = "correct-horse-battery-staple-1!"
    client.post("/api/auth/register", json={"email": email, "password": password})
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()


def test_serialized_race_second_refresh_does_not_get_logged_out(client):
    """Request A refreshes first and rotates the session's jti. Request B
    then tries to refresh using the now-stale refresh token A just replaced
    - without the fix, this used to come back as a hard SESSION_INACTIVE
    401 that also unset A's brand-new, perfectly valid cookies."""
    login = _signup_and_login(client)
    refresh_token = login["refresh_token"]

    resp_a = client.post(
        "/api/auth/token/refresh", headers={"Authorization": f"Bearer {refresh_token}"}
    )
    assert resp_a.status_code == 200

    # Request B races in using the SAME now-rotated-away refresh token.
    resp_b = client.post(
        "/api/auth/token/refresh", headers={"Authorization": f"Bearer {refresh_token}"}
    )
    assert resp_b.status_code == 200, resp_b.get_json()
    assert resp_b.get_json().get("error_code") != "SESSION_INACTIVE"


def test_same_stale_token_can_be_reused_repeatedly_within_the_grace_window(client):
    """Each refresh immediately rewrites the row's jti again (via
    generate_token_authsvc, keyed by session_id, independent of this fix) -
    so a single win-then-lose pair doesn't actually exercise the fallback a
    second time: the loser's own new token becomes the row's current jti.
    To prove the fallback itself keeps working on repeated collisions, not
    just once, reuse the SAME original stale token several times in a row -
    every call must keep hitting the fallback and succeeding, not just the
    first."""
    login = _signup_and_login(client)
    refresh_token = login["refresh_token"]

    # First use rotates the row via the normal path.
    first = client.post(
        "/api/auth/token/refresh", headers={"Authorization": f"Bearer {refresh_token}"}
    )
    assert first.status_code == 200

    # Reusing the now-stale original token repeatedly must keep succeeding
    # via the fallback every time, not just once.
    for _ in range(3):
        resp = client.post(
            "/api/auth/token/refresh", headers={"Authorization": f"Bearer {refresh_token}"}
        )
        assert resp.status_code == 200, resp.get_json()
        assert resp.get_json().get("error_code") != "SESSION_INACTIVE"


def test_wrong_session_id_for_a_real_user_still_rejected(client):
    """A session_id fallback must not swallow real rejections. Uses a REAL
    user (not a nonexistent identity, which would 500 on user=None inside
    generate_token_authsvc for an unrelated reason and could make this test
    pass without ever exercising the rejection path it claims to) with a
    forged, unrelated session_id that matches no row at all."""
    from flask_jwt_extended import create_refresh_token

    login = _signup_and_login(client)
    real_identity = decode_identity(client, login["refresh_token"])

    with client.application.app_context():
        forged_token = create_refresh_token(
            identity=real_identity,
            additional_claims={"session_id": "00000000-0000-0000-0000-000000000000"},
        )

    resp = client.post(
        "/api/auth/token/refresh", headers={"Authorization": f"Bearer {forged_token}"}
    )
    assert resp.status_code == 401
    assert resp.get_json().get("error_code") == "SESSION_INACTIVE"


def decode_identity(client, token):
    from flask_jwt_extended import decode_token

    with client.application.app_context():
        return decode_token(token)["sub"]


def test_fallback_does_not_bypass_a_genuine_inactivity_timeout(client):
    """The critical case an earlier version of this fix got wrong: the
    fallback must not skip the inactivity-cutoff check just because
    session_id matches. A row that's genuinely idle past the configured
    timeout - whether or not anyone has refreshed it since to actually flip
    revoked=True - must stay rejected even via a stale jti + matching
    session_id, or a captured refresh token could be replayed indefinitely
    to defeat the timeout entirely."""
    from datetime import datetime, timedelta
    from flask_jwt_extended import decode_token

    client.application.config["AUTHSVC_SESSION_INACTIVITY_TIMEOUT"] = 480  # 8 hours
    login = _signup_and_login(client)
    refresh_token = login["refresh_token"]

    with client.application.app_context():
        session_id = decode_token(refresh_token)["session_id"]
        authsvc = client.application.extensions["authsvc"]
        audit_mgr = authsvc.audit_manager
        session_row = audit_mgr.UserSession.query.filter_by(session_id=session_id).first()
        # Idle for 9 hours - past the cutoff - but nobody has tried to
        # refresh it since, so revoked is still False. This is exactly the
        # state the fallback must NOT treat as alive.
        session_row.last_activity = datetime.utcnow() - timedelta(hours=9)
        audit_mgr.db.session.commit()

    # Use the SAME still-current refresh_token - its jti still matches the
    # row (nothing rotated it), so this exercises the inactivity branch of
    # the PRIMARY path, confirming the baseline still works with the timeout on.
    resp = client.post(
        "/api/auth/token/refresh", headers={"Authorization": f"Bearer {refresh_token}"}
    )
    assert resp.status_code == 401
    assert resp.get_json().get("error_code") == "SESSION_INACTIVE"


def test_fallback_does_not_bypass_inactivity_via_a_stale_jti(client):
    """Same scenario as above, but reaching the fallback branch specifically:
    a STALE jti (not the row's current one) whose session_id still matches
    an idle-past-cutoff row must also be rejected, not resurrected."""
    from datetime import datetime, timedelta
    from flask_jwt_extended import create_refresh_token, decode_token

    client.application.config["AUTHSVC_SESSION_INACTIVITY_TIMEOUT"] = 480  # 8 hours
    login = _signup_and_login(client)
    refresh_token = login["refresh_token"]

    with client.application.app_context():
        claims = decode_token(refresh_token)
        session_id = claims["session_id"]
        identity = claims["sub"]

        authsvc = client.application.extensions["authsvc"]
        audit_mgr = authsvc.audit_manager
        session_row = audit_mgr.UserSession.query.filter_by(session_id=session_id).first()
        session_row.last_activity = datetime.utcnow() - timedelta(hours=9)
        audit_mgr.db.session.commit()

        # A different, stale jti for the SAME session_id - simulates a
        # captured/old token, forcing the fallback branch specifically.
        stale_token = create_refresh_token(
            identity=identity, additional_claims={"session_id": session_id}
        )

    resp = client.post(
        "/api/auth/token/refresh", headers={"Authorization": f"Bearer {stale_token}"}
    )
    assert resp.status_code == 401
    assert resp.get_json().get("error_code") == "SESSION_INACTIVE"


def test_grace_window_itself_is_enforced_not_just_the_full_inactivity_cutoff(client):
    """A second review of this fix caught that the two tests above don't
    actually pin the 30-second grace window itself - both use last_activity
    far outside it (9 hours), which the full inactivity-cutoff check alone
    would also reject even with no grace window at all. This uses a stale
    jti whose session_id row was touched 31 seconds ago - well past
    AUTHSVC_REFRESH_REUSE_GRACE_SECONDS (30s default), but nowhere near any
    realistic inactivity timeout - and confirms it's still rejected. This
    test fails if the grace-window condition were deleted (an unconditional
    `if fallback:` would accept this and return True)."""
    from datetime import datetime, timedelta
    from flask_jwt_extended import create_refresh_token, decode_token

    login = _signup_and_login(client)
    refresh_token = login["refresh_token"]

    with client.application.app_context():
        claims = decode_token(refresh_token)
        session_id = claims["session_id"]
        identity = claims["sub"]

        authsvc = client.application.extensions["authsvc"]
        audit_mgr = authsvc.audit_manager
        session_row = audit_mgr.UserSession.query.filter_by(session_id=session_id).first()
        session_row.last_activity = datetime.utcnow() - timedelta(seconds=31)
        audit_mgr.db.session.commit()

        stale_token = create_refresh_token(
            identity=identity, additional_claims={"session_id": session_id}
        )

    resp = client.post(
        "/api/auth/token/refresh", headers={"Authorization": f"Bearer {stale_token}"}
    )
    assert resp.status_code == 401
    assert resp.get_json().get("error_code") == "SESSION_INACTIVE"


def test_session_id_fallback_does_not_resurrect_a_revoked_session(client):
    """The fallback must stay scoped to revoked=False, same as the primary
    jti lookup - a session already revoked (inactivity timeout, logout,
    anything) must not come back alive just because its session_id still
    matches a stale, pre-revocation refresh token."""
    login = _signup_and_login(client)
    refresh_token = login["refresh_token"]

    with client.application.app_context():
        from flask_jwt_extended import decode_token

        claims = decode_token(refresh_token)
        session_id = claims["session_id"]

        authsvc = client.application.extensions["authsvc"]
        audit_mgr = authsvc.audit_manager
        session_row = audit_mgr.UserSession.query.filter_by(session_id=session_id).first()
        session_row.revoked = True
        audit_mgr.db.session.commit()

    resp = client.post(
        "/api/auth/token/refresh", headers={"Authorization": f"Bearer {refresh_token}"}
    )
    assert resp.status_code == 401
    assert resp.get_json().get("error_code") == "SESSION_INACTIVE"


def test_logout_actually_revokes_the_session_row(client):
    """/logout only has the ACCESS token's jti available, but UserSession
    rows are keyed by the REFRESH token's jti - the pre-existing bug this
    fixes. Confirm the session row really is revoked after logout, and that
    the refresh token (still cryptographically valid for its full lifetime)
    can no longer be used."""
    from flask_jwt_extended import decode_token

    login = _signup_and_login(client)
    access_token = login["access_token"]
    refresh_token = login["refresh_token"]

    with client.application.app_context():
        session_id = decode_token(refresh_token)["session_id"]

    logout_resp = client.post(
        "/api/auth/logout", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert logout_resp.status_code == 200

    with client.application.app_context():
        authsvc = client.application.extensions["authsvc"]
        audit_mgr = authsvc.audit_manager
        session_row = audit_mgr.UserSession.query.filter_by(session_id=session_id).first()
        assert session_row.revoked is True

    resp = client.post(
        "/api/auth/token/refresh", headers={"Authorization": f"Bearer {refresh_token}"}
    )
    assert resp.status_code == 401
    assert resp.get_json().get("error_code") == "SESSION_INACTIVE"
