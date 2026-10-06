"""The Lab API itself must behave as documented in each mode,
otherwise AuthPath's results would prove nothing."""

import json

import pytest

from authpath.api.executor import execute_request


def call(base, method, path, user=None, body=None):
    headers = {"X-User-ID": user} if user else {}
    if body is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(body)
    return execute_request(method, base + path, headers=headers, body=body).status_code


def test_vulnerable_mode_authenticates_but_does_not_authorize(lab):
    base = lab("vulnerable")
    assert call(base, "GET", "/api/accounts/account_002") == 401
    assert call(base, "GET", "/api/accounts/account_002", "user_001") == 200
    assert call(base, "GET", "/api/admin/users", "user_001") == 200
    assert call(base, "DELETE", "/api/accounts/account_002", "user_001") == 200


def test_unknown_user_is_unauthenticated(lab):
    base = lab("vulnerable")
    assert call(base, "GET", "/api/accounts/account_001", "user_999") == 401


def test_patched_mode_enforces_the_matrix(lab):
    base = lab("patched")
    a2 = "/api/accounts/account_002"
    body = {"nickname": "n"}
    assert call(base, "GET", a2) == 401
    assert call(base, "GET", a2, "user_001") == 403
    assert call(base, "GET", a2, "user_002") == 200
    assert call(base, "GET", a2, "admin_001") == 200
    assert call(base, "PUT", a2, "user_001", body) == 403
    assert call(base, "PUT", a2, "user_002", body) == 200
    assert call(base, "PUT", a2, "admin_001", body) == 403
    assert call(base, "GET", "/api/admin/users", "user_001") == 403
    assert call(base, "GET", "/api/admin/users", "admin_001") == 200
    assert call(base, "DELETE", a2, "user_002") == 403
    assert call(base, "DELETE", a2, "admin_001") == 200


def test_regressed_mode_only_reopens_update(lab):
    base = lab("regressed")
    a2 = "/api/accounts/account_002"
    assert call(base, "PUT", a2, "user_001", {"nickname": "n"}) == 200
    assert call(base, "GET", a2, "user_001") == 403
    assert call(base, "DELETE", a2, "user_002") == 403


def test_reset_restores_deleted_accounts(lab):
    base = lab("vulnerable")
    call(base, "DELETE", "/api/accounts/account_001", "admin_001")
    assert call(base, "GET", "/api/accounts/account_001", "admin_001") == 404
    assert call(base, "POST", "/_lab/reset") == 200
    assert call(base, "GET", "/api/accounts/account_001", "admin_001") == 200


def test_bad_put_body_is_400(lab):
    base = lab("vulnerable")
    assert call(base, "PUT", "/api/accounts/account_001", "user_001", {"x": 1}) == 400
