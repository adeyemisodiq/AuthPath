PASS = "PASS"
VIOLATION = "VIOLATION"
OVER_RESTRICTION = "OVER_RESTRICTION"
INCONCLUSIVE = "INCONCLUSIVE"

FAILING_VERDICTS = (VIOLATION, OVER_RESTRICTION)

OWASP_CATEGORIES = {
    "object": "API1:2023 Broken Object Level Authorization",
    "function": "API5:2023 Broken Function Level Authorization",
}

DATA_EXPOSURE_CATEGORY = "API3:2023 Broken Object Property Level Authorization"


def evaluate_result(expected: str, observed: str) -> str:
    """
    Compare what the policy says with what the API did.

      expected deny, observed allow   -> VIOLATION         (security failure)
      expected allow, observed deny   -> OVER_RESTRICTION  (functional failure)
      expected == observed            -> PASS
      observed unknown                -> INCONCLUSIVE      (never a silent pass)
    """

    if observed not in ("allow", "deny"):
        return INCONCLUSIVE

    if expected == observed:
        return PASS

    if expected == "deny" and observed == "allow":
        return VIOLATION

    return OVER_RESTRICTION


def classify_finding(verdict: str, authorization_level: str) -> str | None:
    """OWASP API Top 10 (2023) category for a VIOLATION, else None."""

    if verdict != VIOLATION:
        return None

    return OWASP_CATEGORIES.get(authorization_level)
