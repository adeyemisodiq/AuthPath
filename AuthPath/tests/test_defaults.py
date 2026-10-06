from authpath.defaults import expand_policy_defaults
from authpath.models.subject import Subject
from authpath.models.resource import Resource
from authpath.models.action import Action
from authpath.engine.policy_evaluator import evaluate_policy_set


def test_owner_default_allows_owner_and_denies_others():
    policies = expand_policy_defaults([
        {"resource": "account", "actions": ["read"], "admin_roles": ["admin"]}
    ])
    owner = Subject(id="u1", roles=["user"])
    stranger = Subject(id="u2", roles=["user"])
    admin = Subject(id="a1", roles=["admin"])
    account = Resource(type="account", id="acc1", owner="u1")

    assert evaluate_policy_set(policies, owner, Action("read"), account).decision == "allow"
    assert evaluate_policy_set(policies, stranger, Action("read"), account).decision == "deny"
    assert evaluate_policy_set(policies, admin, Action("read"), account).decision == "allow"


def test_default_generates_one_pair_per_action():
    policies = expand_policy_defaults([
        {"resource": "account", "actions": ["read", "update"], "admin_roles": ["admin"]}
    ])
    ids = {p.id for p in policies}
    assert ids == {
        "default-owner-account-read", "default-role-account-read-admin",
        "default-owner-account-update", "default-role-account-update-admin",
    }


def test_explicit_deny_overrides_the_default_allow():
    """A hand-written exception can still block what a default allows,
    because the engine is deny-overrides."""
    from authpath.models.policy import Policy

    policies = expand_policy_defaults([
        {"resource": "account", "actions": ["update"]}
    ])
    policies.append(Policy(
        "frozen-block", "user", "update", "account",
        condition={"equals": ["resource.attributes.status", "frozen"]},
        decision="deny",
    ))

    owner = Subject(id="u1")
    frozen = Resource(type="account", id="a", owner="u1",
                      attributes={"status": "frozen"})
    result = evaluate_policy_set(policies, owner, Action("update"), frozen)
    assert result.decision == "deny"


def test_no_admin_roles_means_only_owner_policy_generated():
    policies = expand_policy_defaults([{"resource": "invoice", "actions": ["read"]}])
    assert [p.id for p in policies] == ["default-owner-invoice-read"]
