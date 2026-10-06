import pytest

from authpath.engine.evaluator import (
    evaluate_result, classify_finding,
    PASS, VIOLATION, OVER_RESTRICTION, INCONCLUSIVE,
)


@pytest.mark.parametrize("expected, observed, verdict", [
    ("allow", "allow", PASS),
    ("deny", "deny", PASS),
    ("deny", "allow", VIOLATION),
    ("allow", "deny", OVER_RESTRICTION),
    ("allow", "unknown", INCONCLUSIVE),
    ("deny", "unknown", INCONCLUSIVE),
])
def test_verdicts(expected, observed, verdict):
    assert evaluate_result(expected, observed) == verdict


def test_owasp_classification():
    assert classify_finding(VIOLATION, "object").startswith("API1:2023")
    assert classify_finding(VIOLATION, "function").startswith("API5:2023")
    assert classify_finding(PASS, "object") is None
    assert classify_finding(OVER_RESTRICTION, "object") is None
