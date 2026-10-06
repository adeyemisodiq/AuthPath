import json

import pytest

from authpath.importers.openapi import (
    import_bindings, load_spec, draft_resources, _guess_resource_and_action,
)

SPEC_PATH = "tests/fixtures/sample_openapi.json"


def test_guess_object_level_from_path_param():
    resource, action, id_param, level = _guess_resource_and_action(
        "get", "/api/accounts/{account_id}"
    )
    assert (resource, action, id_param, level) == ("account", "read", "account_id", "object")


def test_guess_function_level_without_path_param():
    resource, action, id_param, level = _guess_resource_and_action(
        "get", "/api/admin/users"
    )
    assert id_param is None
    assert level == "function"


def test_guess_update_and_delete():
    assert _guess_resource_and_action("put", "/api/accounts/{id}")[1] == "update"
    assert _guess_resource_and_action("delete", "/api/accounts/{id}")[1] == "delete"


def test_import_bindings_from_spec_file():
    bindings = import_bindings(load_spec(SPEC_PATH))
    methods_by_path = {(b["path"], b["method"]) for b in bindings}
    assert ("/api/accounts/{account_id}", "GET") in methods_by_path
    assert ("/api/accounts/{account_id}", "PUT") in methods_by_path
    assert ("/api/accounts/{account_id}", "DELETE") in methods_by_path
    assert ("/api/admin/users", "GET") in methods_by_path
    assert all(b["review"] is True for b in bindings)


def test_operation_id_used_when_present():
    bindings = import_bindings(load_spec(SPEC_PATH))
    payment_binding = next(b for b in bindings if "payment" in b["path"])
    assert payment_binding["id"] == "getPayment"


def test_draft_resources_lists_distinct_types():
    bindings = import_bindings(load_spec(SPEC_PATH))
    resources = draft_resources(bindings)
    assert "account" in resources
    assert resources == sorted(resources)


def test_head_and_options_are_skipped():
    spec = {"paths": {"/x": {"head": {}, "options": {}, "get": {}}}}
    bindings = import_bindings(spec)
    assert len(bindings) == 1
    assert bindings[0]["method"] == "GET"


def test_load_spec_rejects_non_json_with_clear_message(tmp_path):
    bad = tmp_path / "spec.yaml"
    bad.write_text("openapi: 3.0.0\npaths: {}\n")
    with pytest.raises(ValueError, match="JSON"):
        load_spec(str(bad))
