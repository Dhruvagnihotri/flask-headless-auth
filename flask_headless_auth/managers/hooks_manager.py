"""
flask_headless_auth.managers.hooks_manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Auth lifecycle hooks -- Supabase Auth Hooks parity.

Supabase provides Auth Hooks that let you customise the auth flow at
specific execution points.  This module gives the same capability to
flask-headless-auth users via simple Python callbacks.

Usage (in your app)::

    from flask_headless_auth import AuthSvc

    auth = AuthSvc()

    # Register hooks BEFORE init_app (or in create_app)
    @auth.hook('before_signup')
    def validate_corporate_email(user_data):
        if not user_data['email'].endswith('@acme.com'):
            raise ValueError('Only corporate emails allowed')

    @auth.hook('after_login')
    def track_login(user):
        analytics.track('login', user_id=user['id'])

    @auth.hook('custom_access_token')
    def add_claims(user, claims):
        claims['tenant_id'] = user.get('tenant_id')
        claims['org_name'] = 'Acme Corp'
        return claims

Available hooks:
    before_signup       (user_data)          -> user_data | raise ValueError
    after_signup        (user)               -> None
    before_login        (credentials)        -> credentials | raise ValueError
    after_login         (user)               -> None
    before_logout       (user_id, claims)    -> None
    after_logout        (user_id)            -> None
    custom_access_token (user, claims)       -> claims (modified)
    before_token_refresh(user, old_claims)   -> None | raise ValueError
    after_token_refresh (user, new_claims)   -> None
    before_password_change(user_id, data)    -> None | raise ValueError
    after_password_change (user_id)          -> None
    before_mfa_verify   (user, token)        -> None | raise ValueError
    after_mfa_verify    (user)               -> None
    on_oauth_login      (user, provider)     -> user (can modify)
    before_role_assign  (user_id, role_id)   -> None | raise ValueError
    after_role_assign   (user_id, role_id)   -> None
"""

import logging
from functools import wraps

logger = logging.getLogger(__name__)


class HooksManager:
    """
    Registry for auth lifecycle hooks.

    All hooks are **fire-and-forget safe** by default.  If a hook raises
    an exception:
    - ``before_*`` hooks: the exception propagates (blocks the action)
    - ``after_*`` / ``on_*`` hooks: the exception is logged and swallowed
    - ``custom_access_token``: the exception is logged, original claims used

    This matches Supabase's behaviour where "before" hooks can reject an
    action, but "after" hooks cannot break the flow.
    """

    # Hooks where exceptions should propagate (block the action)
    BLOCKING_HOOKS = frozenset({
        'before_signup',
        'before_login',
        'before_password_change',
        'before_mfa_verify',
        'before_token_refresh',
        'before_role_assign',
    })

    # Hook that returns modified data
    TRANSFORM_HOOKS = frozenset({
        'custom_access_token',
        'on_oauth_login',
    })

    ALL_HOOKS = frozenset({
        'before_signup', 'after_signup',
        'before_login', 'after_login',
        'before_logout', 'after_logout',
        'custom_access_token',
        'before_token_refresh', 'after_token_refresh',
        'before_password_change', 'after_password_change',
        'before_mfa_verify', 'after_mfa_verify',
        'on_oauth_login',
        'before_role_assign', 'after_role_assign',
    })

    def __init__(self):
        self._hooks = {name: [] for name in self.ALL_HOOKS}

    def register(self, hook_name, fn):
        """
        Register a callback for a hook.

        Args:
            hook_name: One of the supported hook names
            fn: Callable to invoke when the hook fires

        Raises:
            ValueError: If hook_name is not recognised
        """
        if hook_name not in self.ALL_HOOKS:
            raise ValueError(
                f"Unknown hook '{hook_name}'. Available hooks: {sorted(self.ALL_HOOKS)}"
            )
        self._hooks[hook_name].append(fn)
        logger.debug(f"Registered hook: {hook_name} -> {fn.__name__}")

    def fire(self, hook_name, *args, **kwargs):
        """
        Execute all callbacks registered for a hook.

        For blocking hooks (before_*): exceptions propagate.
        For transform hooks (custom_access_token, on_oauth_login):
            the last return value is used.
        For after/on hooks: exceptions are logged and swallowed.

        Returns:
            For transform hooks: the (potentially modified) result
            For other hooks: None
        """
        callbacks = self._hooks.get(hook_name, [])
        if not callbacks:
            return kwargs.get('default_return')

        is_blocking = hook_name in self.BLOCKING_HOOKS
        is_transform = hook_name in self.TRANSFORM_HOOKS

        result = kwargs.pop('default_return', None)

        for fn in callbacks:
            try:
                ret = fn(*args, **kwargs)
                if is_transform and ret is not None:
                    result = ret
            except Exception as exc:
                if is_blocking:
                    # Let before_* hooks block the action
                    raise
                else:
                    # after_* hooks: log and continue
                    logger.warning(
                        f"Auth hook '{hook_name}' ({fn.__name__}) failed (non-fatal): {exc}"
                    )

        return result if is_transform else None

    def has_hooks(self, hook_name):
        """Check if any callbacks are registered for a hook."""
        return bool(self._hooks.get(hook_name))

    def clear(self, hook_name=None):
        """Clear hooks (all or specific)."""
        if hook_name:
            self._hooks[hook_name] = []
        else:
            self._hooks = {name: [] for name in self.ALL_HOOKS}
