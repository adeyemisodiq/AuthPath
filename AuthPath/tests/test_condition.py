import pytest

from authpath.models.subject import Subject
from authpath.models.resource import Resource
from authpath.engine.condition import evaluate_condition, resolve_value

subject = Subject(
    id="user_001", roles=["user"],
    attributes={"department": "sales", "region": "ibadan"},
)
resource = Resource(
    type="account", id="account_001", owner="user_001",
    attributes={"department": "sales", "status": "active"},
    relationships={"members": ["user_001", "user_009"]},
)
admin = Subject(id="admin_001", roles=["admin", "auditor"])


def ok(condition, who=subject):
    return evaluate_condition(condition, who, resource)


def test_resolve_paths():
    assert resolve_value("subject.id", subject, resource) == "user_001"
    assert resolve_value("resource.owner", subject, resource) == "user_001"
    assert resolve_value("subject.attributes.region", subject, resource) == "ibadan"
    assert resolve_value("resource.attributes.missing", subject, resource) is None


def test_resolve_unsupported_path():
    with pytest.raises(ValueError):
        resolve_value("subject.nonsense", subject, resource)


def test_equals_and_not_equals():
    assert ok({"equals": ["resource.owner", "subject.id"]})
    assert not ok({"not_equals": ["resource.owner", "subject.id"]})
    assert ok({"equals": ["subject.attributes.department",
                          "resource.attributes.department"]})


def test_equals_accepts_literals():
    assert ok({"equals": ["resource.attributes.status", "active"]})


def test_in_with_scalar():
    assert ok({"in": ["subject.type", ["user", "service"]]})
    assert not ok({"in": ["subject.type", ["service"]]})


def test_in_with_role_list_regression():
    """The bug: a list of roles was never found in a list of values."""
    assert ok({"in": ["subject.roles", ["admin", "auditor"]]}, admin)
    assert not ok({"in": ["subject.roles", ["admin", "auditor"]]}, subject)


def test_not_in_role_list():
    assert ok({"not_in": ["subject.roles", ["restricted"]]})
    assert not ok({"not_in": ["subject.roles", ["admin"]]}, admin)


def test_contains():
    assert ok({"contains": ["subject.roles", "admin"]}, admin)
    assert not ok({"contains": ["subject.roles", "admin"]}, subject)
    assert ok({"contains": ["resource.relationships.members", "subject.id"]})


def test_contains_on_non_collection_is_false():
    assert not ok({"contains": ["resource.owner", "user"]})
    assert not ok({"contains": ["resource.relationships.absent", "x"]})


def test_exists():
    assert ok({"exists": "resource.owner"})
    assert not ok({"exists": "resource.attributes.missing"})


def test_all_and_any():
    yes = {"equals": ["resource.owner", "subject.id"]}
    no = {"equals": ["resource.owner", "resource.id"]}
    assert ok({"all": [yes, yes]})
    assert not ok({"all": [yes, no]})
    assert ok({"any": [no, yes]})
    assert not ok({"any": [no, no]})


def test_nested_conditions():
    assert ok({"all": [
        {"equals": ["resource.owner", "subject.id"]},
        {"any": [{"contains": ["subject.roles", "admin"]},
                 {"contains": ["subject.roles", "user"]}]},
    ]})


def test_unknown_operator():
    with pytest.raises(ValueError):
        ok({"roughly": ["a", "b"]})


def test_condition_needs_exactly_one_operator():
    with pytest.raises(ValueError):
        ok({"equals": ["a", "a"], "exists": "resource.owner"})
    with pytest.raises(ValueError):
        ok({})
