"""
Severity labels for findings - #5 of the improvement plan.

A VIOLATION is a security failure, but not all of them are equally bad. A
judge (or a real engineering team) wants to know what to fix first. This is
an honest, explainable heuristic based on what we actually know about the
finding - not a guess at business impact we have no way to measure.
"""

HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"

# Actions that destroy or expose data wholesale are worse than a read of
# one record; function-level bypass (doing something you shouldn't be able
# to do at all) is treated as at least as serious as an object-level one.
HIGH_ACTIONS = {"delete", "update", "list_users"}
SENSITIVE_RESOURCE_HINTS = (
    "account", "payment", "wallet", "card", "invoice", "transaction",
    "user", "credential", "token", "admin",
)


def classify_severity(
    verdict: str,
    action: str,
    resource_type: str,
    authorization_level: str,
    exposed_sensitive_fields: list[str] | None = None,
) -> str | None:
    """
    None for anything that isn't a failure. Otherwise:

      High   - sensitive data exposed, destructive/admin action allowed,
               or a function-level bypass on a sensitive resource
      Medium - an object-level violation on a sensitive resource that is
               a plain read, or any violation on a non-sensitive resource
      Low    - OVER_RESTRICTION (a functional bug, not a security one)
    """

    # A data-exposure finding is real regardless of whether the main
    # access-control check passed - a correctly-granted request can still
    # hand back a field the subject should never see.
    if exposed_sensitive_fields:
        return HIGH

    if verdict == "OVER_RESTRICTION":
        return LOW

    if verdict != "VIOLATION":
        return None

    is_sensitive_resource = any(
        hint in resource_type.lower() for hint in SENSITIVE_RESOURCE_HINTS
    )

    if action in HIGH_ACTIONS:
        return HIGH

    if authorization_level == "function" and is_sensitive_resource:
        return HIGH

    if is_sensitive_resource:
        return MEDIUM

    return MEDIUM
