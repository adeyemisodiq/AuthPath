VALID_DECISIONS = ("allow", "deny")


class Policy:
    """
    One authorization rule.

    A policy *applies* when its subject type, action and resource type match
    and its condition (if any) is true. When it applies it yields its
    decision. When it does not apply it says nothing ("not_applicable") -
    the policy SET decides what silence means (default deny).
    """

    def __init__(
        self,
        id: str,
        subject: str,
        action: str,
        resource: str,
        condition: dict | None = None,
        decision: str = "deny",
        description: str = ""
    ):
        if decision not in VALID_DECISIONS:
            raise ValueError(
                f"Policy {id!r}: decision must be one of "
                f"{VALID_DECISIONS}, got {decision!r}"
            )

        self.id = id
        self.subject = subject
        self.action = action
        self.resource = resource
        self.condition = condition
        self.decision = decision
        self.description = description

    def __repr__(self):
        return (
            f"Policy("
            f"id={self.id!r}, "
            f"subject={self.subject!r}, "
            f"action={self.action!r}, "
            f"resource={self.resource!r}, "
            f"condition={self.condition!r}, "
            f"decision={self.decision!r}"
            f")"
        )
