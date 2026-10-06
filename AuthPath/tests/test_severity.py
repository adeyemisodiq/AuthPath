from authpath.engine.severity import classify_severity, HIGH, MEDIUM, LOW


def test_over_restriction_is_low():
    assert classify_severity("OVER_RESTRICTION", "read", "account", "object") == LOW


def test_pass_and_inconclusive_have_no_severity():
    assert classify_severity("PASS", "read", "account", "object") is None
    assert classify_severity("INCONCLUSIVE", "read", "account", "object") is None


def test_destructive_action_is_high():
    assert classify_severity("VIOLATION", "delete", "account", "function") == HIGH


def test_function_level_bypass_on_sensitive_resource_is_high():
    assert classify_severity("VIOLATION", "list_users", "user_directory", "function") == HIGH


def test_plain_object_level_read_is_medium():
    assert classify_severity("VIOLATION", "read", "account", "object") == MEDIUM


def test_exposed_fields_are_high_even_on_a_pass():
    """The important case: correct access decision, still over-shares."""
    assert classify_severity("PASS", "read", "account", "object",
                             exposed_sensitive_fields=["internal_risk_score"]) == HIGH
