"""
A guided, question-by-question builder for a scenario file - #2 of the
usability plan. Same JSON shape as before; this is just a friendlier front
door onto it, so nobody has to hand-write JSON to get started.

`run_wizard` takes its input/output as functions so it can be tested without
a real terminal (tests/test_wizard.py feeds it scripted answers).
"""

import json

from authpath.importers.openapi import import_bindings, load_spec


def _ask(input_func, prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    answer = input_func(f"{prompt}{suffix}: ").strip()
    return answer or default


def _ask_list(input_func, prompt: str) -> list[str]:
    raw = input_func(f"{prompt} (comma-separated, blank for none): ").strip()
    return [item.strip() for item in raw.split(",") if item.strip()]


def _collect_subjects(input_func, print_func) -> list[dict]:
    print_func(
        "\nWho will you test as? Add each identity (blank id to stop)."
    )
    subjects = []
    while True:
        subject_id = _ask(input_func, "  Subject id (e.g. user_001, or blank to stop)")
        if not subject_id:
            break
        subject_type = _ask(input_func, "  Type", "user")
        roles = _ask_list(input_func, "  Roles")
        subjects.append({"id": subject_id, "type": subject_type, "roles": roles})
    return subjects


def _collect_resources(input_func, print_func) -> list[dict]:
    print_func(
        "\nWhat resources exist to test against? (blank type to stop)"
    )
    resources = []
    while True:
        resource_type = _ask(input_func, "  Resource type (e.g. account, or blank to stop)")
        if not resource_type:
            break
        resource_id = _ask(input_func, "  Resource id (e.g. account_001)")
        owner = _ask(input_func, "  Owner subject id (blank if none)")
        resources.append({
            "type": resource_type, "id": resource_id,
            "owner": owner or None,
        })
    return resources


def _collect_bindings_manually(input_func, print_func) -> list[dict]:
    print_func("\nAdd each endpoint (blank id to stop).")
    bindings = []
    while True:
        binding_id = _ask(input_func, "  Binding id (or blank to stop)")
        if not binding_id:
            break
        action = _ask(input_func, "  Action (read/update/delete/...)")
        resource = _ask(input_func, "  Resource type")
        method = _ask(input_func, "  HTTP method", "GET")
        path = _ask(input_func, "  Path (use {id} for the resource id)")
        id_param = None
        if "{" in path:
            id_param = _ask(input_func, "  Name inside the {} placeholder")
        level = _ask(
            input_func, "  Authorization level (object/function)",
            "object" if id_param else "function",
        )
        bindings.append({
            "id": binding_id, "action": action, "resource": resource,
            "method": method.upper(), "path": path,
            "resource_id_parameter": id_param,
            "authorization_level": level,
        })
    return bindings


def _collect_bindings(input_func, print_func) -> list[dict]:
    spec_path = _ask(
        input_func,
        "\nPath to an OpenAPI/Swagger JSON spec to import endpoints from "
        "(blank to enter them by hand)"
    )
    if spec_path:
        try:
            drafted = import_bindings(load_spec(spec_path))
        except (OSError, ValueError) as error:
            print_func(f"  Could not import: {error}")
            drafted = []

        if drafted:
            print_func(
                f"  Imported {len(drafted)} draft binding(s) - REVIEW these "
                f"before trusting results; action/resource names are guesses:"
            )
            for binding in drafted:
                print_func(
                    f"    - {binding['id']}: {binding['method']} "
                    f"{binding['path']}  (action={binding['action']}, "
                    f"resource={binding['resource']}, "
                    f"level={binding['authorization_level']})"
                )
            keep = _ask(input_func, "  Keep all of these?", "y")
            if keep.lower().startswith("y"):
                for binding in drafted:
                    binding.pop("review", None)
                    binding.pop("summary", None)
                extra = _collect_bindings_manually(
                    input_func,
                    lambda m: print_func("Add more endpoints by hand? " + m),
                )
                return drafted + extra

    return _collect_bindings_manually(input_func, print_func)


def _collect_policy_defaults(input_func, print_func, resource_types: list[str]) -> list[dict]:
    if not resource_types:
        return []
    print_func(
        f"\nDefault rule: 'the owner of a resource may act on it'. "
        f"Known resource types: {', '.join(resource_types)}."
    )
    chosen = _ask_list(
        input_func,
        "  Apply the owner-default to which resource types?"
    )
    if not chosen:
        return []
    actions = _ask_list(
        input_func, "  For which actions (e.g. read, update)"
    ) or ["read"]
    admin_roles = _ask_list(
        input_func, "  Which roles should bypass ownership (e.g. admin)"
    )
    return [
        {"resource": r, "actions": actions, "admin_roles": admin_roles}
        for r in chosen
    ]


def _collect_explicit_policies(input_func, print_func) -> list[dict]:
    print_func(
        "\nAny extra rules the defaults don't cover, or exceptions that "
        "should DENY something a default would allow? (blank id to stop)"
    )
    policies = []
    while True:
        policy_id = _ask(input_func, "  Policy id (or blank to stop)")
        if not policy_id:
            break
        subject = _ask(input_func, "  Subject type", "user")
        action = _ask(input_func, "  Action")
        resource = _ask(input_func, "  Resource type")
        decision = _ask(input_func, "  Decision (allow/deny)", "deny")
        condition_raw = _ask(
            input_func,
            '  Condition as JSON (e.g. {"contains": ["subject.roles", '
            '"admin"]}), blank = always applies'
        )
        condition = json.loads(condition_raw) if condition_raw else None
        policies.append({
            "id": policy_id, "subject": subject, "action": action,
            "resource": resource, "decision": decision,
            "condition": condition,
        })
    return policies


def run_wizard(input_func=input, print_func=print) -> dict:
    print_func("=== AuthPath scenario wizard ===")
    name = _ask(input_func, "Scenario name")
    base_url = _ask(input_func, "Base URL", "http://127.0.0.1:8000")
    identity_header = _ask(input_func, "Identity header name", "X-User-ID")

    subjects = _collect_subjects(input_func, print_func)
    resources = _collect_resources(input_func, print_func)
    bindings = _collect_bindings(input_func, print_func)

    resource_types = sorted({b["resource"] for b in bindings}) or \
        sorted({r["type"] for r in resources})
    policy_defaults = _collect_policy_defaults(input_func, print_func, resource_types)
    explicit_policies = _collect_explicit_policies(input_func, print_func)

    reset_path = _ask(
        input_func, "\nLab reset endpoint (blank if none, e.g. /_lab/reset)"
    )
    non_loopback = _ask(
        input_func,
        "Is the base URL NOT localhost/127.0.0.1? Only say yes if you are "
        "authorised to test it (y/N)", "n"
    )

    return {
        "name": name,
        "base_url": base_url,
        "identity_header": identity_header,
        "subjects": subjects,
        "resources": resources,
        "policies": explicit_policies,
        "policy_defaults": policy_defaults,
        "bindings": bindings,
        "lab_reset_path": reset_path or None,
        "allow_non_loopback": non_loopback.lower().startswith("y"),
    }


def write_scenario_file(scenario_dict: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(scenario_dict, handle, indent=2)
        handle.write("\n")
