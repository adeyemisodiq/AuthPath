import pytest

from authpath.models.subject import Subject
from authpath.models.resource import Resource
from authpath.models.action import Action
from authpath.models.policy import Policy
from authpath.models.api_binding import APIBinding
from authpath.models.authz_case import AuthzCase


def test_subject_defaults():
    subject = Subject(id="user_001")
    assert subject.type == "user"
    assert subject.roles == []
    assert subject.attributes == {}


def test_resource_defaults_are_not_shared_between_instances():
    a = Resource(type="account", id="a")
    b = Resource(type="account", id="b")
    a.attributes["x"] = "1"
    assert b.attributes == {}


def test_action_name():
    assert Action("read").name == "read"


def test_policy_rejects_invalid_decision():
    with pytest.raises(ValueError):
        Policy("p", "user", "read", "account", decision="maybe")


def test_binding_builds_path_and_url_encodes_id():
    binding = APIBinding(
        "get_account", "read", "account", "get",
        "/api/accounts/{account_id}", "account_id",
    )
    assert binding.method == "GET"
    assert binding.build_path("account_002") == "/api/accounts/account_002"
    assert binding.build_path("a/../b") == "/api/accounts/a%2F..%2Fb"


def test_binding_without_id_parameter_keeps_path():
    binding = APIBinding("l", "list_users", "user_directory", "GET",
                         "/api/admin/users")
    assert binding.build_path("all") == "/api/admin/users"


def test_binding_missing_placeholder_is_an_error():
    binding = APIBinding("b", "read", "account", "GET", "/api/accounts",
                         "account_id")
    with pytest.raises(ValueError):
        binding.build_path("account_001")


def test_binding_rejects_invalid_level():
    with pytest.raises(ValueError):
        APIBinding("b", "read", "account", "GET", "/x",
                   authorization_level="galaxy")


def test_case_key_and_dict():
    case = AuthzCase("TC-001", "user_001", "read", "account", "account_002",
                     "deny", ["p1"], "why")
    assert case.key == ("user_001", "read", "account", "account_002")
    assert case.to_dict()["expected_decision"] == "deny"
