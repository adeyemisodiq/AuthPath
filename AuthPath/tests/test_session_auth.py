import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from authpath.api.executor import execute_request
from authpath.api.session_auth import login_subject, LoginError

VALID_USERS = {"alice": "Password123!", "bob": "hunter2"}


class _CookieLoginHandler(BaseHTTPRequestHandler):
    """A minimal stand-in for a real session-cookie login flow."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        data = json.loads(self.rfile.read(length) or b"{}")
        username, password = data.get("user"), data.get("pass")

        if VALID_USERS.get(username) == password:
            body = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Set-Cookie", f"session=tok-{username}; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = json.dumps({"error": "bad credentials"}).encode()
            self.send_response(401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        if self.path == "/me" and cookie.startswith("session=tok-"):
            body = json.dumps({"user": cookie.split("tok-")[1]}).encode()
            self.send_response(200)
        else:
            body = b'{"error":"unauthorized"}'
            self.send_response(401)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def cookie_server():
    server = HTTPServer(("127.0.0.1", 0), _CookieLoginHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_login_returns_usable_cookie_header(cookie_server):
    cookie = login_subject(
        execute_request, cookie_server, scope=None, timeout=3,
        login_path="/login", method="POST",
        identity_field="user", password_field="pass",
        username="alice", password="Password123!",
    )
    assert cookie == "session=tok-alice"

    response = execute_request(
        "GET", cookie_server + "/me", headers={"Cookie": cookie}, timeout=3
    )
    assert response.status_code == 200
    assert "alice" in response.body


def test_wrong_password_raises_login_error(cookie_server):
    with pytest.raises(LoginError):
        login_subject(
            execute_request, cookie_server, scope=None, timeout=3,
            login_path="/login", method="POST",
            identity_field="user", password_field="pass",
            username="alice", password="wrong",
        )


def test_without_cookie_protected_endpoint_refuses(cookie_server):
    response = execute_request("GET", cookie_server + "/me", timeout=3)
    assert response.status_code == 401


def test_runner_end_to_end_with_session_login(cookie_server, tmp_path):
    """The runner itself: logs each subject in once, then uses the cookie
    for every request made as that subject - never the old X-User-ID path."""
    import json as _json
    from authpath.config import Scenario
    from authpath.models.subject import Subject
    from authpath.models.resource import Resource
    from authpath.models.policy import Policy
    from authpath.models.api_binding import APIBinding
    from authpath.runner import run_scenario

    scenario = Scenario(
        name="cookie login demo",
        base_url=cookie_server,
        identity_header="X-User-ID",  # must be IGNORED when auth=session_login
        subjects=[
            Subject(id="alice", type="user", roles=["user"],
                   attributes={"username": "alice", "password": "Password123!"}),
            Subject(id="bob", type="user", roles=["user"],
                   attributes={"username": "bob", "password": "hunter2"}),
        ],
        resources=[Resource(type="profile", id="me", owner="alice")],
        policies=[Policy("p", "user", "read", "profile", decision="allow")],
        bindings=[APIBinding("get_me", "read", "profile", "GET", "/me")],
        auth={
            "type": "session_login", "login_path": "/login",
            "identity_field": "user", "password_field": "pass",
        },
    )

    run = run_scenario(scenario, label="cookie-e2e")
    assert run["summary"]["pass"] == 2   # both alice and bob reach /me fine

    for result in run["results"]:
        assert "Cookie" in result["request"]["headers"]
        assert "X-User-ID" not in result["request"]["headers"]
        username = result["subject_id"]
        assert result["request"]["headers"]["Cookie"] == f"session=tok-{username}"


def test_runner_aborts_cleanly_on_bad_credentials():
    from authpath.config import Scenario, ScenarioError
    from authpath.models.subject import Subject
    from authpath.models.resource import Resource
    from authpath.models.policy import Policy
    from authpath.models.api_binding import APIBinding
    from authpath.runner import run_scenario, RunnerError

    scenario = Scenario(
        name="bad creds", base_url="http://127.0.0.1:1",
        identity_header="X-User-ID",
        subjects=[Subject(id="eve", type="user",
                          attributes={"username": "eve", "password": "nope"})],
        resources=[Resource(type="profile", id="me", owner="eve")],
        policies=[Policy("p", "user", "read", "profile", decision="allow")],
        bindings=[APIBinding("get_me", "read", "profile", "GET", "/me")],
        auth={"type": "session_login", "login_path": "/login"},
    )
    with pytest.raises(RunnerError):
        run_scenario(scenario, label="x", timeout=1)
