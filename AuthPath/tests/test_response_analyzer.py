import pytest

from authpath.api.response_analyzer import analyze_response


@pytest.mark.parametrize("status, expected", [
    (200, "allow"), (201, "allow"), (204, "allow"),
    (401, "deny"), (403, "deny"),
    (404, "deny"),
    (302, "unknown"), (400, "unknown"), (405, "unknown"),
    (500, "unknown"), (503, "unknown"),
    (0, "unknown"),
])
def test_status_mapping(status, expected):
    assert analyze_response(status).decision == expected


def test_2xx_with_error_body_is_a_deny():
    body = '{"error": "not allowed"}'
    assert analyze_response(200, body).decision == "deny"


def test_2xx_with_data_body_is_allow():
    assert analyze_response(200, '{"account": {"id": "a"}}').decision == "allow"


def test_non_json_body_is_ignored():
    assert analyze_response(200, "<html>ok</html>").decision == "allow"


def test_reason_is_always_given():
    assert analyze_response(403).reason
