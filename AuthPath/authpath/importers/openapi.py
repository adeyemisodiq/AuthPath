"""
Draft AuthPath bindings from an OpenAPI/Swagger spec - #1 of the usability
plan: read what already exists instead of typing every endpoint by hand.

AuthPath is dependency-free by design, so this reads JSON specs with the
standard library only. Most tools (Swagger UI, FastAPI, DRF) can export
JSON; a YAML-only spec needs converting to JSON first (see README).

IMPORTANT: this can only ever guess *what exists* (the endpoints) - never
*who should be allowed to use them* (the policy). Every binding it drafts
is marked "review": true and must be checked by a human before it is
trusted; the resource type, action name and authorization_level are
best-effort guesses from the URL shape, not a security judgement.
"""

import json
import re

SKIP_METHODS = {"head", "options", "trace"}
ACTION_BY_METHOD = {
    "get": "read", "post": "create", "put": "update",
    "patch": "update", "delete": "delete",
}


def _singular(word: str) -> str:
    if word.endswith("ies") and len(word) > 3:
        return word[:-3] + "y"
    if word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def _guess_resource_and_action(method: str, path: str):
    """
    '/api/accounts/{account_id}' GET -> resource='account', action='read',
                                         id_param='account_id', level='object'
    '/api/admin/users'          GET -> resource='users',  action='list_users',
                                         id_param=None,     level='function'
    """

    segments = [s for s in path.strip("/").split("/") if s]
    param_segments = [s for s in segments if s.startswith("{") and s.endswith("}")]

    base_action = ACTION_BY_METHOD.get(method, method)

    if param_segments:
        id_param = param_segments[-1][1:-1]
        index = segments.index(param_segments[-1])
        resource_segment = segments[index - 1] if index > 0 else "resource"
        resource = _singular(resource_segment)
        return resource, base_action, id_param, "object"

    resource_segment = segments[-1] if segments else "resource"
    resource = resource_segment
    action = "list" if method == "get" else base_action
    action = f"{action}_{resource}" if action in ("list", "create") else action
    return resource, action, None, "function"


def import_bindings(spec: dict) -> list[dict]:
    """Return a list of draft binding dicts (AuthPath scenario shape)."""

    bindings = []
    counter = 1

    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue

        for method, operation in path_item.items():
            method = method.lower()
            if method in SKIP_METHODS or not isinstance(operation, dict):
                continue

            resource, action, id_param, level = _guess_resource_and_action(
                method, path
            )

            binding = {
                "id": operation.get("operationId")
                      or f"{method}_{re.sub(r'[^a-zA-Z0-9]+', '_', path).strip('_')}",
                "action": action,
                "resource": resource,
                "method": method.upper(),
                "path": path.replace("{", "{").replace("}", "}"),
                "resource_id_parameter": id_param,
                "authorization_level": level,
                "review": True,
                "summary": operation.get("summary", ""),
            }
            bindings.append(binding)
            counter += 1

    return bindings


def load_spec(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        try:
            return json.load(handle)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"{path} is not valid JSON. Export/convert the OpenAPI "
                f"spec to JSON first (Swagger UI: 'Download' -> JSON)."
            ) from error


def draft_resources(bindings: list[dict]) -> list[str]:
    """Distinct resource types seen, so the wizard/user knows what to fill in."""
    return sorted({b["resource"] for b in bindings})
