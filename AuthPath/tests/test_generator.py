from authpath.models.subject import Subject
from authpath.models.resource import Resource
from authpath.models.action import Action
from authpath.models.policy import Policy
from authpath.engine.generator import generate_test_cases

subjects = [
    Subject(id="user_001", roles=["user"]),
    Subject(id="user_002", roles=["user"]),
    Subject(id="admin_001", roles=["admin"]),
]
resources = [
    Resource(type="account", id="account_001", owner="user_001"),
    Resource(type="account", id="account_002", owner="user_002"),
]
policies = [
    Policy("read-own", "user", "read", "account",
           {"equals": ["resource.owner", "subject.id"]}, "allow"),
    Policy("admin-read", "user", "read", "account",
           {"contains": ["subject.roles", "admin"]}, "allow"),
]


def cases():
    return generate_test_cases(policies, subjects, Action("read"), resources)


def test_cross_product_size_and_ids():
    result = cases()
    assert len(result) == 6
    assert [c.id for c in result] == [f"TC-00{i}" for i in range(1, 7)]


def test_expected_decisions():
    expected = {(c.subject_id, c.resource_id): c.expected_decision for c in cases()}
    assert expected == {
        ("user_001", "account_001"): "allow",
        ("user_001", "account_002"): "deny",
        ("user_002", "account_001"): "deny",
        ("user_002", "account_002"): "allow",
        ("admin_001", "account_001"): "allow",
        ("admin_001", "account_002"): "allow",
    }


def test_rationale_names_the_policy_or_default_deny():
    by_key = {(c.subject_id, c.resource_id): c for c in cases()}
    assert "read-own" in by_key[("user_001", "account_001")].rationale
    assert by_key[("user_001", "account_001")].policy_ids == ["read-own"]
    assert "default deny" in by_key[("user_001", "account_002")].rationale


def test_start_number_and_single_policy_accepted():
    result = generate_test_cases(policies[0], subjects, Action("read"),
                                 resources, start_number=10)
    assert result[0].id == "TC-010"
