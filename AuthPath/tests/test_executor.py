import socket

import pytest

from authpath.api.executor import (
    execute_request, Scope, ScopeViolation, APIResponse,
)


def test_get_returns_status_and_body(lab):
    base = lab("vulnerable")
    response = execute_request(
        "GET", base + "/api/accounts/account_002",
        headers={"X-User-ID": "user_001"},
    )
    assert response.status_code == 200
    assert '"owner": "user_002"' in response.body
    assert response.elapsed_ms >= 0


def test_http_errors_are_returned_not_raised(lab):
    base = lab("vulnerable")
    assert execute_request("GET", base + "/api/accounts/account_001").status_code == 401
    assert execute_request(
        "GET", base + "/api/accounts/nope", headers={"X-User-ID": "user_001"},
    ).status_code == 404


def test_put_with_body(lab):
    base = lab("vulnerable")
    response = execute_request(
        "PUT", base + "/api/accounts/account_001",
        headers={"X-User-ID": "user_001", "Content-Type": "application/json"},
        body='{"nickname": "hello"}',
    )
    assert response.status_code == 200
    assert '"nickname": "hello"' in response.body


def test_connection_refused_becomes_error_response_not_crash():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]
    response = execute_request("GET", f"http://127.0.0.1:{free_port}/", timeout=2)
    assert response.status_code == 0
    assert response.error


def test_redirects_are_not_followed():
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Redirector(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Redirector)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        response = execute_request(
            "GET", f"http://127.0.0.1:{server.server_address[1]}/x"
        )
        assert response.status_code == 302
    finally:
        server.shutdown()
        server.server_close()


def test_scope_allows_only_its_origin():
    scope = Scope("http://127.0.0.1:8000")
    scope.check("http://127.0.0.1:8000/api/accounts/1")
    for bad in (
        "http://127.0.0.1:9999/x",
        "http://localhost:8000/x",
        "https://127.0.0.1:8000/x",
        "http://example.com/x",
    ):
        with pytest.raises(ScopeViolation):
            scope.check(bad)


def test_scope_refuses_non_loopback_unless_explicit():
    with pytest.raises(ScopeViolation):
        Scope("http://example.com")
    Scope("http://example.com", allow_non_loopback=True)


def test_out_of_scope_request_is_blocked_before_any_network_call():
    calls = []

    import authpath.api.executor as executor_module
    original = executor_module._OPENER.open
    executor_module._OPENER.open = lambda *a, **k: calls.append(a)
    try:
        with pytest.raises(ScopeViolation):
            execute_request("GET", "http://example.com/",
                            scope=Scope("http://127.0.0.1:8000"))
    finally:
        executor_module._OPENER.open = original

    assert calls == []
