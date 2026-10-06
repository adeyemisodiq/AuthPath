"""
A short, specific "how to fix this" note per finding.

Deliberately generic-but-concrete advice tied to the finding's category -
not a guess at the target's actual code, which AuthPath never sees. The
goal is to turn a bare "this failed" into something closer to a real
pentest deliverable: what's wrong, why, and what to actually go do.
"""

from authpath.engine.evaluator import (
    VIOLATION, OVER_RESTRICTION,
)

BOLA_FIX = (
    "Add an ownership (or relationship) check before returning this "
    "resource - verify the resource belongs to the authenticated subject "
    "(or that they otherwise have a legitimate relationship to it), not "
    "just that they are logged in. Enforce this server-side, on every "
    "request - never trust an ID supplied by the client alone."
)

BFLA_FIX = (
    "Add a role/permission check on this endpoint - verify the subject "
    "holds the required role or permission before performing the action, "
    "not just that they are authenticated. Apply the check at the start "
    "of the handler (or via middleware/decorator), before any work is done."
)

OVER_RESTRICTION_FIX = (
    "This subject was expected to be allowed but was denied - check "
    "whether the policy or the endpoint's authorization logic is too "
    "strict here (e.g. a missing allow rule, or a condition that doesn't "
    "match a legitimate case)."
)


def exposure_fix(exposed_fields: list[str]) -> str:
    fields = ", ".join(f"`{f}`" for f in exposed_fields)
    return (
        f"Strip {fields} from the response for subjects who are not "
        f"entitled to it - build the response per-role/per-relationship "
        f"(an explicit allow-list of fields, or a serializer per role) "
        f"rather than returning the full stored record as-is."
    )


def get_remediation(
    verdict: str,
    category: str | None,
    exposed_fields: list[str] | None = None,
) -> str | None:
    """None when there is nothing to fix (PASS/INCONCLUSIVE with no
    exposure). A result can have BOTH an access-control fix and an
    exposure fix - the caller joins them; this returns a single finding's
    worth at a time, called once per concern."""

    if exposed_fields:
        return exposure_fix(exposed_fields)

    if verdict == VIOLATION:
        if category and "API1" in category:
            return BOLA_FIX
        if category and "API5" in category:
            return BFLA_FIX
        return (
            "Add the appropriate authorization check before this request "
            "is allowed to succeed."
        )

    if verdict == OVER_RESTRICTION:
        return OVER_RESTRICTION_FIX

    return None


def get_all_remediations(
    verdict: str,
    category: str | None,
    exposed_fields: list[str] | None = None,
) -> list[str]:
    """A VIOLATION that ALSO exposes a field needs two separate fixes -
    fixing the access-control bug alone would not stop the field leaking
    to the (now-correctly-blocked) subject's own allowed requests."""

    notes = []

    if verdict == VIOLATION:
        note = get_remediation(verdict, category, exposed_fields=None)
        if note:
            notes.append(note)
    elif verdict == OVER_RESTRICTION:
        notes.append(OVER_RESTRICTION_FIX)

    if exposed_fields:
        notes.append(exposure_fix(exposed_fields))

    return notes
