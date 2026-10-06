"""
Session-cookie login support.

The Lab API used a shortcut: send the subject's id in a plain header
(X-User-ID). Real apps - SecurePay included - authenticate with a real
login call (username/password) that sets a session cookie, and every
later request must carry that cookie. This logs each subject in once,
keeps the cookie, and hands it back to the runner to attach to every
request made as that subject.
"""

import re

COOKIE_NAME_VALUE = re.compile(r"^([^=\s]+=[^;]*)")


class LoginError(Exception):
    """A subject's credentials did not produce a usable session."""


def _cookie_header_from_response(headers: dict) -> str | None:
    """
    Pull just the 'name=value' part out of a Set-Cookie response header,
    ready to send back as a request's Cookie header.

    Note: if a server sets more than one cookie on login, only the last
    Set-Cookie header survives here (a known limitation of collapsing
    response headers into a plain dict) - fine for SecurePay, which sets
    a single Flask-Login session cookie, but worth knowing for other apps.
    """

    set_cookie = headers.get("Set-Cookie")
    if not set_cookie:
        return None

    match = COOKIE_NAME_VALUE.match(set_cookie)
    return match.group(1) if match else None


def login_subject(
    executor,
    base_url: str,
    scope,
    timeout: float,
    login_path: str,
    method: str,
    identity_field: str,
    password_field: str,
    username: str,
    password: str,
) -> str:
    """Log one subject in and return the Cookie header value to reuse."""

    import json as _json

    response = executor(
        method,
        base_url + login_path,
        headers={"Content-Type": "application/json"},
        body=_json.dumps({identity_field: username, password_field: password}),
        timeout=timeout,
        scope=scope,
    )

    cookie = _cookie_header_from_response(response.headers)
    if response.status_code >= 400 or cookie is None:
        raise LoginError(
            f"Login failed for {username!r}: HTTP {response.status_code}, "
            f"error={response.error}"
        )

    return cookie
