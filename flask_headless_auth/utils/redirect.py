"""
flask_headless_auth.utils.redirect
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Convenience utility for redirect URL validation.

**This is NOT called by the library itself.** The library passes
``redirect_url`` through from routes to hooks without touching it.

Consuming apps can import and call ``validate_redirect_url()`` in
their hook handlers or route handlers to validate the URL against
their own allowlist (``AUTHSVC_ALLOWED_REDIRECT_URLS`` config key).

This follows how Passport.js / Django-allauth work — the library is
a pluggable component; the host app owns the validation policy.
"""

import logging
from urllib.parse import urlparse
from flask import current_app

logger = logging.getLogger(__name__)


def validate_redirect_url(url: str | None) -> str | None:
    """
    Validate a frontend-supplied redirect URL against the configured allowlist.

    Config key:
        AUTHSVC_ALLOWED_REDIRECT_URLS — list of allowed origin URLs.
        Example: ['https://klaveno.com', 'http://localhost:3000']

    Rules (mirrors Supabase):
        1. URL must be absolute (has scheme + host).
        2. The *origin* (scheme + host + port) must match an entry in the
           allowlist exactly.
        3. Any path/query is preserved — only the origin is validated.
        4. Returns None if the URL is missing, malformed, or not in the list.

    Args:
        url: The redirect URL from the frontend request body.

    Returns:
        The validated URL (unchanged) if it passes, or None.
    """
    if not url or not isinstance(url, str):
        return None

    url = url.strip()

    try:
        parsed = urlparse(url)
    except Exception:
        return None

    # Must be absolute (scheme + netloc)
    if not parsed.scheme or not parsed.netloc:
        logger.warning(f"Redirect URL rejected (not absolute): {url}")
        return None

    # Only allow http/https
    if parsed.scheme not in ('http', 'https'):
        logger.warning(f"Redirect URL rejected (bad scheme): {url}")
        return None

    # Build the origin for comparison
    request_origin = f"{parsed.scheme}://{parsed.netloc}"

    allowed = current_app.config.get('AUTHSVC_ALLOWED_REDIRECT_URLS', [])
    if not allowed:
        logger.warning(
            "AUTHSVC_ALLOWED_REDIRECT_URLS is empty — all redirect URLs "
            "will be rejected. Configure it with your frontend origins."
        )
        return None

    # Normalize allowlist entries (strip trailing slashes)
    allowed_origins = set()
    for entry in allowed:
        entry = entry.strip().rstrip('/')
        try:
            p = urlparse(entry)
            allowed_origins.add(f"{p.scheme}://{p.netloc}")
        except Exception:
            continue

    if request_origin in allowed_origins:
        return url

    logger.warning(
        f"Redirect URL rejected (origin not in allowlist): "
        f"{request_origin} not in {allowed_origins}"
    )
    return None
