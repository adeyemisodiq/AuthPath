import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


class ScopeViolation(Exception):
    """Raised BEFORE any network call when a URL is outside the scope."""


class Scope:
    """
    The only origin AuthPath is allowed to talk to.

    Loopback only by default, so a typo in a scenario file cannot make the
    tool send requests to someone else's system.
    """

    def __init__(self, base_url: str, allow_non_loopback: bool = False):
        parsed = urlparse(base_url)

        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ScopeViolation(f"Invalid base URL: {base_url!r}")

        if parsed.hostname not in LOOPBACK_HOSTS and not allow_non_loopback:
            raise ScopeViolation(
                f"{parsed.hostname!r} is not a loopback host. Set "
                f"allow_non_loopback explicitly if you own and are "
                f"authorised to test it."
            )

        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)

    def check(self, url: str) -> None:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if (
            parsed.scheme != self.scheme
            or parsed.hostname != self.host
            or port != self.port
        ):
            raise ScopeViolation(f"Out of scope: {url}")


class APIResponse:
    def __init__(
        self,
        status_code: int,
        body: str,
        headers: dict,
        error: str | None = None,
        elapsed_ms: float = 0.0
    ):
        self.status_code = status_code
        self.body = body
        self.headers = headers
        self.error = error
        self.elapsed_ms = elapsed_ms

    def __repr__(self):
        return (
            f"APIResponse("
            f"status_code={self.status_code}, "
            f"body={self.body!r}, "
            f"error={self.error!r}"
            f")"
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """
    Do not follow redirects. A 302 to a login page would otherwise turn
    into a 200 and be misread as 'access allowed'.
    """

    def redirect_request(self, *args, **kwargs):
        return None


# ProxyHandler({}) = ignore system proxy settings; we only talk to the lab.
_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _NoRedirect()
)


def execute_request(
    method: str,
    url: str,
    headers: dict | None = None,
    body: str | bytes | None = None,
    timeout: float = 5.0,
    scope: Scope | None = None
) -> APIResponse:
    """
    Send ONE request and report exactly what happened.

    It never decides whether the result is a vulnerability. Transport
    failures (refused connection, timeout) come back as status_code=0 with
    `error` set, instead of crashing the whole run.
    """

    if scope is not None:
        scope.check(url)

    data = body.encode("utf-8") if isinstance(body, str) else body

    request = urllib.request.Request(
        url=url,
        method=method,
        headers=headers or {},
        data=data
    )

    started = time.perf_counter()

    def elapsed():
        return round((time.perf_counter() - started) * 1000, 2)

    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return APIResponse(
                status_code=response.status,
                body=response.read().decode("utf-8", errors="replace"),
                headers=dict(response.headers),
                elapsed_ms=elapsed()
            )

    except urllib.error.HTTPError as error:
        return APIResponse(
            status_code=error.code,
            body=error.read().decode("utf-8", errors="replace"),
            headers=dict(error.headers),
            elapsed_ms=elapsed()
        )

    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return APIResponse(
            status_code=0,
            body="",
            headers={},
            error=f"{type(error).__name__}: {error}",
            elapsed_ms=elapsed()
        )
