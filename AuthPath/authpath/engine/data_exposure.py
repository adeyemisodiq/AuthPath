"""
Excessive data exposure check - #3 of the improvement plan
(OWASP API3:2023 Broken Object Property Level Authorization).

BOLA/BFLA ask "should this subject be let through the door at all?".
This asks a different question: "now that they're through, does the
response hand them fields they still shouldn't see?" A subject can be
*correctly* granted access to their own resource and still be handed a
field (an internal score, another user's embedded note, a cost price)
that only a more privileged role should see. That is a real, separate
bug class - not a BOLA, since the object-level decision was right.

This only inspects response bodies on successful (2xx) responses - a
denied request leaks nothing it shouldn't, by definition.
"""

import json

GENERIC_HIGH_SENSITIVITY_HINTS = (
    "ssn", "password", "secret", "token", "card_number", "cvv",
)


def _is_owner(subject, resource) -> bool:
    return resource is not None and resource.owner is not None \
        and resource.owner == subject.id


def _is_admin(subject, admin_roles: list[str]) -> bool:
    return any(role in subject.roles for role in admin_roles)


def _field_names_in(value, names: set) -> None:
    """Collect dict keys one level deep - top-level object, a nested
    wrapper object, or each record in a nested (or top-level) list of
    records (e.g. {"users": [{...}, {...}]}, a very common list-endpoint
    shape). Deliberately shallow, not a general recursive scan."""

    if isinstance(value, dict):
        names.update(value.keys())
        for inner in value.values():
            if isinstance(inner, dict):
                names.update(inner.keys())
            elif isinstance(inner, list):
                for item in inner:
                    if isinstance(item, dict):
                        names.update(item.keys())

    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                names.update(item.keys())


def _candidates_in_body(body: str) -> set | None:
    try:
        parsed = json.loads(body)
    except ValueError:
        return None

    if not isinstance(parsed, (dict, list)):
        return None

    candidates: set = set()
    _field_names_in(parsed, candidates)
    return candidates


def find_exposed_fields(
    body: str | None,
    subject,
    resource,
    sensitive_fields: list[str],
    admin_roles: list[str],
    admin_only_fields: list[str] | None = None,
) -> list[str]:
    """
    Fields present in the response body that this subject is not entitled
    to see. Only inspects the top level of the JSON object (and one level
    of common wrapper keys like "account"/"data"/"result") - deliberately
    simple and explainable rather than a deep recursive scan.

    Two different kinds of rule, because they genuinely differ:

      sensitive_fields  - owner OR admin may see it (e.g. "balance" - the
                           account holder is allowed to know their own
                           balance; a stranger should not).
      admin_only_fields - admin ONLY, even the owner should not see it
                           (e.g. an internal fraud-risk score). Ownership
                           does not grant entitlement here - this is the
                           case BOLA/BFLA testing cannot catch, because
                           the object-level access decision is correct.
    """

    admin_only_fields = admin_only_fields or []
    if not body or not (sensitive_fields or admin_only_fields):
        return []

    is_admin = _is_admin(subject, admin_roles)
    is_owner = _is_owner(subject, resource)

    candidates = _candidates_in_body(body)
    if candidates is None:
        return []

    exposed = set()

    if not is_admin:
        exposed.update(f for f in admin_only_fields if f in candidates)

        if not is_owner:
            exposed.update(f for f in sensitive_fields if f in candidates)

    return sorted(exposed)


def looks_generically_sensitive(field_name: str) -> bool:
    """A field name AuthPath flags on its own, even if not declared by the
    scenario author - a safety net, not a replacement for declaring fields."""
    lowered = field_name.lower()
    return any(hint in lowered for hint in GENERIC_HIGH_SENSITIVITY_HINTS)
