import json
from dataclasses import dataclass

ALLOW = "allow"
DENY = "deny"
UNKNOWN = "unknown"


@dataclass
class Observation:
    """What authorization behaviour a response indicates, and why."""

    decision: str
    reason: str


def analyze_response(status_code: int, body: str | None = None) -> Observation:
    """
    Translate an HTTP response into allow / deny / unknown.

    Rules (documented limitations are in the README):
      status 0        transport error                -> unknown
      2xx             success                        -> allow
                      ...unless the JSON body is an error object -> deny
      3xx             redirect (not followed)        -> unknown
      401, 403        refused                        -> deny
      404             hidden resource                -> deny
                      (every tested resource is known to exist in the
                      scenario, so a 404 means the API is hiding it)
      other 4xx, 5xx  malformed request / server fault -> unknown
    """

    if status_code == 0:
        return Observation(UNKNOWN, "Transport error: no HTTP response.")

    if 200 <= status_code < 300:
        if _is_error_body(body):
            return Observation(
                DENY,
                f"HTTP {status_code} but the body is an error object."
            )
        return Observation(ALLOW, f"HTTP {status_code}: request succeeded.")

    if 300 <= status_code < 400:
        return Observation(
            UNKNOWN,
            f"HTTP {status_code}: redirect (not followed) - inspect manually."
        )

    if status_code in (401, 403):
        return Observation(DENY, f"HTTP {status_code}: access refused.")

    if status_code == 404:
        return Observation(
            DENY,
            "HTTP 404: resource hidden from this subject "
            "(resource is known to exist)."
        )

    if 500 <= status_code < 600:
        return Observation(UNKNOWN, f"HTTP {status_code}: server error.")

    return Observation(
        UNKNOWN,
        f"HTTP {status_code}: cannot tell allow from deny."
    )


def _is_error_body(body: str | None) -> bool:
    if not body:
        return False

    try:
        parsed = json.loads(body)
    except ValueError:
        return False

    return isinstance(parsed, dict) and bool(parsed.get("error"))
