from authpath.wizard import run_wizard
from authpath.config import Scenario, load_scenario
from authpath.engine.generator import generate_test_cases
from authpath.models.action import Action
from authpath.models.subject import Subject
from authpath.models.resource import Resource


def scripted_input(answers):
    it = iter(answers)
    def fake_input(prompt):
        return next(it, "")
    return fake_input


def test_wizard_builds_a_loadable_scenario(tmp_path):
    answers = [
        "Wizard demo",                 # name
        "http://127.0.0.1:9999",       # base url
        "",                            # identity header -> default

        "user_001", "user", "user",    # subject 1
        "admin_001", "user", "admin",  # subject 2
        "",                            # stop subjects

        "account", "account_001", "user_001",   # resource 1
        "",                                     # stop resources

        "",                             # no openapi spec -> manual bindings
        "get_account", "read", "account", "GET",
        "/api/accounts/{account_id}", "account_id", "object",
        "",                             # stop bindings

        "account",                      # apply owner-default to 'account'
        "read",                         # actions
        "admin",                        # admin bypass role

        "",                             # no explicit policies

        "",                             # no lab reset path
        "n",                            # loopback only
    ]

    scenario_dict = run_wizard(
        input_func=scripted_input(answers), print_func=lambda *_: None
    )

    assert scenario_dict["name"] == "Wizard demo"
    assert scenario_dict["identity_header"] == "X-User-ID"
    assert len(scenario_dict["subjects"]) == 2
    assert len(scenario_dict["bindings"]) == 1
    assert scenario_dict["policy_defaults"] == [
        {"resource": "account", "actions": ["read"], "admin_roles": ["admin"]}
    ]

    path = tmp_path / "wizard_scenario.json"
    import json
    path.write_text(json.dumps(scenario_dict), encoding="utf-8")

    scenario = load_scenario(str(path))
    assert isinstance(scenario, Scenario)
    assert len(scenario.policies) == 2   # default-owner + default-role

    subjects = {s.id: s for s in scenario.subjects}
    cases = generate_test_cases(
        scenario.policies, scenario.subjects, Action("read"), scenario.resources
    )
    by_subject = {c.subject_id: c.expected_decision for c in cases}
    assert by_subject["user_001"] == "allow"   # owner
    assert by_subject["admin_001"] == "allow"  # admin bypass


def test_wizard_can_import_openapi_bindings(tmp_path):
    answers = [
        "API import demo", "http://127.0.0.1:9999", "",
        "",                              # no subjects
        "",                              # no resources
        "tests/fixtures/sample_openapi.json",  # import spec
        "y",                             # keep all drafted bindings
        "",                              # no extra manual bindings
        "",                              # no default resource types offered path:
        "", "",
    ]
    scenario_dict = run_wizard(
        input_func=scripted_input(answers), print_func=lambda *_: None
    )
    assert len(scenario_dict["bindings"]) == 5
    assert all("review" not in b for b in scenario_dict["bindings"])
