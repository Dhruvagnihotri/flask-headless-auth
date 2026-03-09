"""
flask_headless_auth.utils.request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HTTP request inspection helpers shared across the library.
"""

from flask import request

_BROWSER_TOKENS = ('chrome', 'firefox', 'safari', 'edge', 'opera', 'trident', 'msie')


def is_browser_request():
    """Return True if the current request originates from a web browser."""
    ua = request.headers.get('User-Agent', '').lower()
    return any(tok in ua for tok in _BROWSER_TOKENS)
