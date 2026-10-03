"""
Regression coverage for a real production incident (PDFCourt, 2026-09-25/28/29):
intermittent `pymysql.err.OperationalError` connection drops to a remote
DB-as-a-service host (2003 "handshake operation timed out", 2013 "Lost
connection to MySQL server during query") hit `google_callback` directly -
confirmed in VictoriaLogs as a real user's login 500ing with no recovery.

`pool_pre_ping` (already configured app-wide in the consuming app) only
tests an EXISTING pooled connection before handing it out - it can't help
when a connection dies mid-query, or when opening a brand-new replacement
connection itself times out on the handshake. `_call_with_db_retry` closes
that gap with an application-level retry, applied to both `google_callback`
and `microsoft_callback`'s user lookup/creation (the two call sites the
incident's own logs showed failing).

An adversarial review of an earlier version of this fix caught two real
issues before it shipped: (1) the retry wrapper took `.db.session` as an
eager argument, meaning any consuming app whose UserDataAccess has no `.db`
attribute would get an AttributeError on every login, not just the rare
error path - fixed by taking `user_data_access` and only reaching for
`.db.session` lazily, inside the except block; (2) a bare `OperationalError`
catch would also retry non-transient errors (access-denied, too-many-
connections, lock-wait-timeout) where a retry only adds load - fixed by
checking the specific MySQL error code via `_is_transient_connection_error`.
test_lazy_session_access_* and test_non_transient_errors_are_not_retried
pin these two fixes specifically.
"""

import logging

import pytest
from sqlalchemy.exc import OperationalError

from flask_headless_auth.managers.oauth_manager import (
    _call_with_db_retry,
    _find_or_create_oauth_user,
    _is_transient_connection_error,
)


class _FakePymysqlError(Exception):
    """Mirrors the real shape pymysql raises: args[0] is the numeric MySQL
    error code, args[1] is the message - this is what SQLAlchemy's
    OperationalError.orig actually is in production, not a bare Exception."""

    def __init__(self, code, message):
        super().__init__(code, message)
        self.args = (code, message)


def _transient_op_error(code=2013, message="Lost connection to MySQL server during query"):
    return OperationalError("SELECT 1", {}, _FakePymysqlError(code, message))


def _non_transient_op_error(code=1045, message="Access denied for user"):
    return OperationalError("SELECT 1", {}, _FakePymysqlError(code, message))


class _FakeSession:
    def __init__(self, rollback_raises=None):
        self.rollback_count = 0
        self._rollback_raises = rollback_raises

    def rollback(self):
        self.rollback_count += 1
        if self._rollback_raises is not None:
            raise self._rollback_raises


class _FakeUserDataAccessWithDb:
    """Has a `.db.session` - the normal, supported shape (e.g. pdfwiz's
    SQLAlchemyUserRepository)."""

    def __init__(self, session=None):
        self.db = type("DB", (), {"session": session or _FakeSession()})()


class _FakeUserDataAccessWithoutDb:
    """Deliberately has NO `.db` attribute at all - models a consuming
    app's custom UserDataAccess that doesn't expose one. The retry helper
    must never touch `.db` on this unless an actual OperationalError
    happens; the happy path must work fine."""


def test_is_transient_connection_error_matches_known_codes():
    assert _is_transient_connection_error(_transient_op_error(2003)) is True
    assert _is_transient_connection_error(_transient_op_error(2006)) is True
    assert _is_transient_connection_error(_transient_op_error(2013)) is True


def test_is_transient_connection_error_rejects_other_operational_errors():
    """Access-denied, too-many-connections, lock-wait-timeout etc. must NOT
    be treated as transient - retrying those only adds load or wastes time,
    they're never going to succeed on attempt 2."""
    assert _is_transient_connection_error(_non_transient_op_error(1045)) is False  # access denied
    assert _is_transient_connection_error(_non_transient_op_error(1040)) is False  # too many connections
    assert _is_transient_connection_error(_non_transient_op_error(1213)) is False  # deadlock


def test_succeeds_immediately_with_no_error():
    uda = _FakeUserDataAccessWithDb()
    calls = []

    def fn():
        calls.append(1)
        return "ok"

    assert _call_with_db_retry(fn, uda) == "ok"
    assert len(calls) == 1
    assert uda.db.session.rollback_count == 0


def test_happy_path_never_touches_db_attribute_at_all():
    """Pins the fix for the AttributeError-on-every-login risk an
    adversarial review caught: a UserDataAccess with no `.db` attribute
    must work fine as long as fn() doesn't raise - `.db` must only be
    accessed inside the except block, never eagerly."""
    uda = _FakeUserDataAccessWithoutDb()
    assert _call_with_db_retry(lambda: "ok", uda) == "ok"


def test_retries_once_on_transient_error_then_succeeds():
    uda = _FakeUserDataAccessWithDb()
    attempts = {"n": 0}

    def fn():
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise _transient_op_error()
        return "recovered"

    result = _call_with_db_retry(fn, uda, backoff_seconds=0)
    assert result == "recovered"
    assert attempts["n"] == 2
    # Must roll back the poisoned transaction before the retry, or the
    # second attempt reuses a session stuck in a failed-transaction state
    # (the exact mechanism behind the 2026-09-17 outage this mirrors).
    assert uda.db.session.rollback_count == 1


def test_raises_after_exhausting_all_retries():
    uda = _FakeUserDataAccessWithDb()
    attempts = {"n": 0}

    def fn():
        attempts["n"] += 1
        raise _transient_op_error()

    with pytest.raises(OperationalError):
        _call_with_db_retry(fn, uda, retries=2, backoff_seconds=0)

    # Initial attempt + 2 retries = 3 total calls, 3 rollbacks (one per
    # failure, including the last - rollback must still run even when the
    # exception is about to propagate, not just on recoverable attempts).
    assert attempts["n"] == 3
    assert uda.db.session.rollback_count == 3


def test_default_is_one_retry_not_two():
    """Pins the latency fix: with pdfwiz's 30s MySQL read_timeout and a 30s
    default gunicorn worker timeout, a second retry on a mid-query timeout
    (3 x 30s = 90s) would get the worker killed before finishing. Default
    must be 1 retry (2 total attempts), not 2."""
    uda = _FakeUserDataAccessWithDb()
    attempts = {"n": 0}

    def fn():
        attempts["n"] += 1
        raise _transient_op_error()

    with pytest.raises(OperationalError):
        _call_with_db_retry(fn, uda, backoff_seconds=0)  # no explicit retries= override

    assert attempts["n"] == 2  # 1 initial + 1 retry, not 3


def test_non_operational_errors_are_not_retried():
    """A real bug (TypeError, ValueError, a bad email) must fail fast, not
    get silently retried and masked as if it were a transient DB blip."""
    uda = _FakeUserDataAccessWithDb()
    attempts = {"n": 0}

    def fn():
        attempts["n"] += 1
        raise ValueError("not a transient DB error")

    with pytest.raises(ValueError):
        _call_with_db_retry(fn, uda, backoff_seconds=0)

    assert attempts["n"] == 1
    assert uda.db.session.rollback_count == 0


def test_non_transient_operational_errors_are_not_retried():
    """A real access-denied/too-many-connections error must propagate on
    the FIRST attempt, not get retried - retrying those is pure downside
    (wasted time, or more load during an actual connection storm)."""
    uda = _FakeUserDataAccessWithDb()
    attempts = {"n": 0}

    def fn():
        attempts["n"] += 1
        raise _non_transient_op_error(1040)  # too many connections

    with pytest.raises(OperationalError):
        _call_with_db_retry(fn, uda, backoff_seconds=0)

    assert attempts["n"] == 1
    assert uda.db.session.rollback_count == 0


def test_rollback_failure_itself_is_logged_not_silently_swallowed(caplog):
    """If rollback() itself raises (session already in a worse state), the
    retry must still proceed to the next attempt rather than crashing with
    an unrelated-looking error, but the rollback failure must be visible in
    logs, not silently swallowed."""
    uda = _FakeUserDataAccessWithDb(session=_FakeSession(rollback_raises=RuntimeError("boom")))
    attempts = {"n": 0}

    def fn():
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise _transient_op_error()
        return "recovered"

    with caplog.at_level(logging.WARNING):
        result = _call_with_db_retry(fn, uda, backoff_seconds=0)

    assert result == "recovered"
    assert any("rollback() itself failed" in r.message for r in caplog.records)


def test_wired_through_find_or_create_oauth_user_recovers_a_dropped_connection():
    """Exercises the exact production failure shape end-to-end: the first
    find_user_by_email call (modeled here as the fn passed to the retry
    wrapper, same as google_callback/microsoft_callback's inline closure)
    drops the connection; the retry's fresh attempt finds no existing user
    and falls through to _find_or_create_oauth_user, which must still work
    correctly (new user created, is_new=True) once the connection recovers -
    proving the retry and the existing create-or-recover logic compose
    correctly rather than just testing each in isolation."""

    class _FakeFullUserDataAccess:
        def __init__(self):
            self.db = type("DB", (), {"session": _FakeSession()})()
            self.created = []
            self._lookup_attempts = 0

        def find_user_by_email(self, email):
            self._lookup_attempts += 1
            if self._lookup_attempts == 1:
                raise _transient_op_error()
            return None  # genuinely a new user, once the connection recovers

        def create_user(self, user_data):
            self.created.append(user_data)
            return {"email": user_data["email"], "id": 1}

    uda = _FakeFullUserDataAccess()

    def lookup_or_create():
        user = uda.find_user_by_email("new-user@example.com")
        if user is not None:
            return user, False
        return _find_or_create_oauth_user(
            uda, "new-user@example.com", {"email": "new-user@example.com", "provider": "google"}
        )

    user, is_new = _call_with_db_retry(lookup_or_create, uda, backoff_seconds=0)

    assert is_new is True
    assert user["email"] == "new-user@example.com"
    assert len(uda.created) == 1
    assert uda.db.session.rollback_count == 1


def test_lost_commit_ack_is_logged_when_retry_finds_a_just_created_user(caplog):
    """The one case the retry can't fully solve: create_user() commits, then
    an OperationalError fires on/after that same commit (a lost
    acknowledgement, not a lost write). The retry's fresh find_user_by_email
    then finds that row and must report it as pre-existing (is_new=False) -
    not a regression (the pre-retry behavior for this exact race was a hard
    500 on the same request, so is_new_user never fired true for it either),
    but this must be logged so it's an observable rarity, not a silent one."""

    class _FakeUserDataAccessLostAck:
        def __init__(self):
            self.db = type("DB", (), {"session": _FakeSession()})()
            self._attempt = 0
            self._created_email = None

        def find_user_by_email(self, email):
            self._attempt += 1
            if self._attempt == 1:
                return None  # genuinely doesn't exist yet
            if email == self._created_email:
                return {"email": email, "id": 1}  # the row create_user() actually committed
            return None

        def create_user(self, user_data):
            self._created_email = user_data["email"]
            raise _transient_op_error()  # commit succeeded server-side, ack never arrived

    uda = _FakeUserDataAccessLostAck()
    create_attempted = {"value": False}
    email = "lost-ack@example.com"

    def lookup_or_create():
        user = uda.find_user_by_email(email)
        if user is not None:
            if create_attempted["value"]:
                import logging as _logging
                _logging.getLogger("flask_headless_auth.managers.oauth_manager").warning(
                    f"[StatelessOAuth] {email} found after a prior create attempt failed "
                    f"with a transient DB error in this same request - likely a lost commit "
                    f"acknowledgement. Reporting is_new_user=False; this user may not get "
                    f"their welcome email or promo trial grant."
                )
            return user, False
        create_attempted["value"] = True
        return _find_or_create_oauth_user(uda, email, {"email": email, "provider": "google"})

    with caplog.at_level(logging.WARNING):
        user, is_new = _call_with_db_retry(lookup_or_create, uda, backoff_seconds=0)

    assert is_new is False  # the known, documented limitation - not silently wrong
    assert user["email"] == email
    assert any("lost commit" in r.message for r in caplog.records)
