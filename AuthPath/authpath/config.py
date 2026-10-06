import json
from dataclasses import dataclass, field

from authpath.models.subject import Subject
from authpath.models.resource import Resource
from authpath.models.policy import Policy
from authpath.models.api_binding import APIBinding
from authpath.defaults import expand_policy_defaults


class ScenarioError(Exception):
    """The scenario file is missing something or is inconsistent."""


@dataclass
class Scenario:
    name: str
    base_url: str
    identity_header: str
    subjects: list[Subject]
    resources: list[Resource]
    policies: list[Policy]
    bindings: list[APIBinding]
    lab_reset_path: str | None = None
    allow_non_loopback: bool = False
    sensitive_fields: dict = field(default_factory=dict)
    admin_only_fields: dict = field(default_factory=dict)
    admin_roles: list = field(default_factory=list)
    auth: dict = field(default_factory=lambda: {"type": "header"})


def _require(data: dict, key: str, where: str):
    if key not in data:
        raise ScenarioError(f"{where}: missing required key {key!r}")
    return data[key]


def _unique(items, what: str):
    seen = set()
    for item in items:
        if item in seen:
            raise ScenarioError(f"Duplicate {what}: {item!r}")
        seen.add(item)


def load_scenario(path: str, base_url: str | None = None) -> Scenario:
    """Load and validate a JSON scenario. base_url overrides the file's."""

    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    subjects = [
        Subject(
            id=_require(item, "id", "subject"),
            type=item.get("type", "user"),
            roles=item.get("roles", []),
            attributes=item.get("attributes", {}),
        )
        for item in _require(data, "subjects", "scenario")
    ]

    resources = [
        Resource(
            type=_require(item, "type", "resource"),
            id=_require(item, "id", "resource"),
            owner=item.get("owner"),
            attributes=item.get("attributes", {}),
            relationships=item.get("relationships", {}),
        )
        for item in _require(data, "resources", "scenario")
    ]

    policies = [
        Policy(
            id=_require(item, "id", "policy"),
            subject=_require(item, "subject", "policy"),
            action=_require(item, "action", "policy"),
            resource=_require(item, "resource", "policy"),
            condition=item.get("condition"),
            decision=item.get("decision", "deny"),
            description=item.get("description", ""),
        )
        for item in data.get("policies", [])
    ]

    # #3: "owner may manage their own resource" defaults, so a scenario
    # doesn't need every rule spelled out - only its exceptions.
    policies += expand_policy_defaults(data.get("policy_defaults", []))

    if not policies:
        raise ScenarioError(
            "scenario: no policies and no policy_defaults - nothing to "
            "test against (every request would default-deny)."
        )

    bindings = [
        APIBinding(
            id=_require(item, "id", "binding"),
            action=_require(item, "action", "binding"),
            resource=_require(item, "resource", "binding"),
            method=_require(item, "method", "binding"),
            path=_require(item, "path", "binding"),
            resource_id_parameter=item.get("resource_id_parameter"),
            body=item.get("body"),
            authorization_level=item.get("authorization_level", "object"),
        )
        for item in _require(data, "bindings", "scenario")
    ]

    _unique([s.id for s in subjects], "subject id")
    _unique([(r.type, r.id) for r in resources], "resource")
    _unique([p.id for p in policies], "policy id")
    _unique([b.id for b in bindings], "binding id")

    resource_types = {r.type for r in resources}

    for binding in bindings:
        if binding.resource not in resource_types:
            raise ScenarioError(
                f"Binding {binding.id!r} targets resource type "
                f"{binding.resource!r}, which has no resources defined"
            )

    return Scenario(
        name=_require(data, "name", "scenario"),
        base_url=base_url or _require(data, "base_url", "scenario"),
        identity_header=data.get("identity_header", "X-User-ID"),
        subjects=subjects,
        resources=resources,
        policies=policies,
        bindings=bindings,
        lab_reset_path=data.get("lab_reset_path"),
        allow_non_loopback=data.get("allow_non_loopback", False),
        sensitive_fields=data.get("sensitive_fields", {}),
        admin_only_fields=data.get("admin_only_fields", {}),
        admin_roles=data.get("admin_roles", []),
        auth=data.get("auth", {"type": "header"}),
    )
