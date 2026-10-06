"""
AuthPath Lab API - a deliberately vulnerable banking-style API.

Run it:  python -m lab_api.main --mode vulnerable
Modes:
  vulnerable  authenticates the caller but performs NO authorization checks
  patched     enforces the intended policy on every endpoint
  regressed   patched, except PUT /api/accounts/{id} lost its ownership
              check again (a deliberate regression for the retest demo)

Lab only. It trusts the X-User-ID header as identity, so it must never be
exposed beyond loopback. AuthPath tests AUTHORIZATION, not authentication.
"""

import argparse
import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 8000
MODES = ("vulnerable", "patched", "regressed")

USERS = {
    "user_001": {"id": "user_001", "role": "user"},
    "user_002": {"id": "user_002", "role": "user"},
    "admin_001": {"id": "admin_001", "role": "admin"},
}

INITIAL_ACCOUNTS = {
    "account_001": {
        "id": "account_001", "owner": "user_001",
        "balance": 50000, "nickname": "Main",
        # Meant for admins only (e.g. a fraud-risk score) - every mode
        # below still hands this back to the account's own owner too.
        # That is a deliberate, separate bug: object-level authorization
        # can be entirely correct while a specific FIELD is still
        # over-shared (OWASP API3, not API1). AuthPath's data-exposure
        # check is what catches this - BOLA/BFLA tests do not.
        "internal_risk_score": 17,
    },
    "account_002": {
        "id": "account_002", "owner": "user_002",
        "balance": 75000, "nickname": "Savings",
        "internal_risk_score": 63,
    },
}


def is_authorized(mode: str, user: dict, action: str, account: dict | None):
    """The access-control decision for one request."""

    if mode == "vulnerable":
        return True

    is_admin = user["role"] == "admin"
    is_owner = account is not None and account["owner"] == user["id"]

    if action == "read":
        return is_owner or is_admin

    if action == "update":
        if mode == "regressed":
            return True  # the regression: ownership check dropped again
        return is_owner

    if action == "delete":
        return is_admin

    if action == "list_users":
        return is_admin

    return False


class LabServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, mode: str = "vulnerable", quiet: bool = False):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        super().__init__(address, LabAPIHandler)
        self.mode = mode
        self.quiet = quiet
        self.lock = threading.Lock()
        self.accounts = copy.deepcopy(INITIAL_ACCOUNTS)

    def reset_state(self):
        with self.lock:
            self.accounts = copy.deepcopy(INITIAL_ACCOUNTS)


class LabAPIHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        if not self.server.quiet:
            super().log_message(format, *args)

    def send_json(self, status_code, data):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def current_user(self):
        return USERS.get(self.headers.get("X-User-ID") or "")

    def read_json_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    def do_GET(self):
        self.route("GET")

    def do_PUT(self):
        self.route("PUT")

    def do_DELETE(self):
        self.route("DELETE")

    def do_POST(self):
        self.route("POST")

    def route(self, method):
        path = self.path.split("?", 1)[0]
        server = self.server

        if method == "GET" and path == "/":
            return self.send_json(200, {
                "service": "AuthPath Lab API",
                "status": "running",
                "mode": server.mode,
            })

        # Lab control plane - NOT part of the API under test.
        if method == "POST" and path == "/_lab/reset":
            server.reset_state()
            return self.send_json(200, {"reset": True})

        if path == "/api/admin/users" and method == "GET":
            return self.handle_list_users()

        if path.startswith("/api/accounts/") and method in (
            "GET", "PUT", "DELETE"
        ):
            account_id = path.split("/")[-1]
            return self.handle_account(method, account_id)

        return self.send_json(404, {"error": "Endpoint not found"})

    def handle_list_users(self):
        user = self.current_user()
        if user is None:
            return self.send_json(401, {"error": "Authentication required"})

        if not is_authorized(self.server.mode, user, "list_users", None):
            return self.send_json(403, {"error": "Forbidden"})

        return self.send_json(200, {"users": list(USERS.values())})

    def handle_account(self, method, account_id):
        server = self.server
        user = self.current_user()

        if user is None:
            return self.send_json(401, {"error": "Authentication required"})

        with server.lock:
            account = server.accounts.get(account_id)

            if account is None:
                return self.send_json(404, {"error": "Account not found"})

            action = {"GET": "read", "PUT": "update", "DELETE": "delete"}[method]

            if not is_authorized(server.mode, user, action, account):
                return self.send_json(403, {"error": "Forbidden"})

            if method == "GET":
                return self.send_json(200, {"account": account})

            if method == "PUT":
                body = self.read_json_body()
                if body is None or "nickname" not in body:
                    return self.send_json(400, {"error": "nickname required"})
                account["nickname"] = str(body["nickname"])[:50]
                return self.send_json(200, {"account": account})

            del server.accounts[account_id]
            return self.send_json(200, {"deleted": account_id})


def create_server(host=HOST, port=PORT, mode="vulnerable", quiet=False):
    return LabServer((host, port), mode=mode, quiet=quiet)


def run_server(host=HOST, port=PORT, mode="vulnerable"):
    server = create_server(host, port, mode)
    print(f"AuthPath Lab API [{mode}] running on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AuthPath Lab API")
    parser.add_argument("--mode", choices=MODES, default="vulnerable")
    parser.add_argument("--port", type=int, default=PORT)
    parsed = parser.parse_args()
    run_server(port=parsed.port, mode=parsed.mode)
