from authpath.models.subject import Subject
from authpath.models.resource import Resource
from authpath.models.action import Action
from authpath.models.policy import Policy
from authpath.engine.policy_evaluator import (
    evaluate_policy, evaluate_policy_set, NOT_APPLICABLE,
)

user = Subject(id="user_001", type="user", roles=["user"])
other = Subject(id="user_002", type="user", roles=["user"])
admin = Subject(id="admin_001", type="user", roles=["admin"])
account = Resource(type="account", id="account_001", owner="user_001")

read_own = Policy(
    "read-own", "user", "read", "account",
    condition={"equals": ["resource.owner", "subject.id"]},
    decision="allow",
)
admin_read = Policy(
    "admin-read", "user", "read", "account",
    condition={"contains": ["subject.roles", "admin"]},
    decision="allow",
)
block_frozen = Policy(
    "block-frozen", "user", "read", "account",
    condition={"equals": ["resource.attributes.status", "frozen"]},
    decision="deny",
)


def test_matching_policy_returns_its_decision():
    assert evaluate_policy(read_own, user, Action("read"), account) == "allow"


def test_false_condition_is_not_applicable_not_deny():
    assert evaluate_policy(read_own, other, Action("read"), account) == NOT_APPLICABLE


def test_target_mismatches_are_not_applicable():
    assert evaluate_policy(read_own, user, Action("delete"), account) == NOT_APPLICABLE
    assert evaluate_policy(
        read_own, user, Action("read"),
        Resource(type="invoice", id="i", owner="user_001"),
    ) == NOT_APPLICABLE
    assert evaluate_policy(
        read_own, Subject(id="x", type="service"), Action("read"), account,
    ) == NOT_APPLICABLE


def test_policy_set_allow():
    result = evaluate_policy_set([read_own, admin_read], user, Action("read"), account)
    assert result.decision == "allow"
    assert result.policy_ids == ["read-own"]


def test_admin_rule_not_applying_to_user_does_not_block_user_rule():
    """Regression for design flaw #2: silence must not act as a deny."""
    result = evaluate_policy_set([admin_read, read_own], user, Action("read"), account)
    assert result.decision == "allow"


def test_default_deny_when_nothing_applies():
    result = evaluate_policy_set([read_own, admin_read], other, Action("read"), account)
    assert result.decision == "deny"
    assert result.policy_ids == []
    assert "default deny" in result.reason


def test_deny_overrides_allow():
    frozen = Resource(type="account", id="a", owner="user_001",
                      attributes={"status": "frozen"})
    result = evaluate_policy_set([read_own, block_frozen], user, Action("read"), frozen)
    assert result.decision == "deny"
    assert result.policy_ids == ["block-frozen"]


def test_empty_policy_set_denies():
    assert evaluate_policy_set([], user, Action("read"), account).decision == "deny"
