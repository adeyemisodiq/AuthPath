from dataclasses import dataclass, field

from authpath.models.subject import Subject
from authpath.models.resource import Resource
from authpath.models.action import Action
from authpath.models.policy import Policy
from authpath.engine.condition import evaluate_condition

ALLOW = "allow"
DENY = "deny"
NOT_APPLICABLE = "not_applicable"


@dataclass
class Decision:
    """Outcome of evaluating a whole policy set."""

    decision: str
    policy_ids: list[str] = field(default_factory=list)
    reason: str = ""


def evaluate_policy(
    policy: Policy,
    subject: Subject,
    action: Action,
    resource: Resource
) -> str:
    """
    Evaluate ONE policy: 'allow', 'deny', or 'not_applicable'.

    'not_applicable' means the policy has no opinion about this request
    (different subject type / action / resource type, or its condition is
    false). It is NOT a deny - otherwise an admin-only allow rule that does
    not apply to a normal user would look like an explicit deny and could
    not be combined with other policies.
    """

    if policy.subject != subject.type:
        return NOT_APPLICABLE

    if policy.action != action.name:
        return NOT_APPLICABLE

    if policy.resource != resource.type:
        return NOT_APPLICABLE

    if policy.condition is not None:
        if not evaluate_condition(policy.condition, subject, resource):
            return NOT_APPLICABLE

    return policy.decision


def evaluate_policy_set(
    policies: list[Policy],
    subject: Subject,
    action: Action,
    resource: Resource
) -> Decision:
    """
    Combine policies with DENY-OVERRIDES and DEFAULT-DENY:

      1. any applicable deny policy  -> deny
      2. else any applicable allow   -> allow
      3. else (nothing applies)      -> deny
    """

    allows = []
    denies = []

    for policy in policies:
        result = evaluate_policy(policy, subject, action, resource)

        if result == ALLOW:
            allows.append(policy.id)
        elif result == DENY:
            denies.append(policy.id)

    if denies:
        return Decision(
            DENY,
            denies,
            "Explicit deny by " + ", ".join(denies)
            + " (deny overrides allow)."
        )

    if allows:
        return Decision(
            ALLOW,
            allows,
            "Allowed by " + ", ".join(allows) + "."
        )

    return Decision(
        DENY,
        [],
        "No policy grants this access (default deny)."
    )
