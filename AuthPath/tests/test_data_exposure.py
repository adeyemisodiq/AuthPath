import json

from authpath.models.subject import Subject
from authpath.models.resource import Resource
from authpath.engine.data_exposure import (
    find_exposed_fields, looks_generically_sensitive,
)

account = Resource(type="account", id="account_001", owner="user_001")
owner = Subject(id="user_001", roles=["user"])
stranger = Subject(id="user_002", roles=["user"])
admin = Subject(id="admin_001", roles=["admin"])

BODY = json.dumps({
    "account": {"id": "account_001", "balance": 500, "internal_risk_score": 17}
})


def test_owner_sees_shared_sensitive_fields_but_not_admin_only_ones():
    """The key distinction: ownership grants 'balance', NOT the admin-only
    internal score - this is the bug BOLA/BFLA testing alone cannot catch."""
    exposed = find_exposed_fields(
        BODY, owner, account,
        sensitive_fields=["balance"], admin_roles=["admin"],
        admin_only_fields=["internal_risk_score"],
    )
    assert exposed == ["internal_risk_score"]


def test_admin_is_entitled_to_everything():
    exposed = find_exposed_fields(
        BODY, admin, account,
        sensitive_fields=["balance"], admin_roles=["admin"],
        admin_only_fields=["internal_risk_score"],
    )
    assert exposed == []


def test_stranger_should_never_see_shared_sensitive_field_either():
    exposed = find_exposed_fields(
        BODY, stranger, account,
        sensitive_fields=["balance"], admin_roles=["admin"],
        admin_only_fields=["internal_risk_score"],
    )
    assert exposed == ["balance", "internal_risk_score"]


def test_field_not_present_is_not_exposed():
    body = json.dumps({"account": {"id": "account_001"}})
    assert find_exposed_fields(body, stranger, account, ["balance"], ["admin"]) == []


def test_no_fields_declared_means_nothing_checked():
    assert find_exposed_fields(BODY, stranger, account, [], ["admin"]) == []


def test_non_json_body_is_ignored_not_crashed_on():
    assert find_exposed_fields("<html>nope</html>", stranger, account,
                               ["balance"], ["admin"]) == []


def test_top_level_fields_also_checked_not_only_wrapped():
    body = json.dumps({"internal_risk_score": 99})
    exposed = find_exposed_fields(body, owner, account, [], ["admin"],
                                  admin_only_fields=["internal_risk_score"])
    assert exposed == ["internal_risk_score"]


def test_fields_inside_a_list_of_records_are_found():
    """Regression: a list-endpoint shape like {"users": [{...}, {...}]} -
    this was silently missed before find_exposed_fields looked one level
    into lists, not just nested dicts."""
    body = json.dumps({"users": [
        {"id": 1, "password_hash": "abc"},
        {"id": 2, "password_hash": "def"},
    ]})
    exposed = find_exposed_fields(
        body, stranger, None,
        sensitive_fields=[], admin_roles=["admin"],
        admin_only_fields=["password_hash"],
    )
    assert exposed == ["password_hash"]


def test_body_that_is_a_bare_json_array_is_also_scanned():
    body = json.dumps([{"id": 1, "password_hash": "abc"}])
    exposed = find_exposed_fields(
        body, stranger, None,
        sensitive_fields=[], admin_roles=["admin"],
        admin_only_fields=["password_hash"],
    )
    assert exposed == ["password_hash"]


def test_generic_sensitivity_hints():
    assert looks_generically_sensitive("card_number")
    assert looks_generically_sensitive("userPassword")
    assert not looks_generically_sensitive("nickname")
