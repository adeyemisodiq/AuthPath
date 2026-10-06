class AuthzCase:
    """
    One authorization test case: 'should THIS subject be able to do THIS
    action on THIS resource?' plus the policy-derived expected answer.

    (Renamed from TestCase so pytest never tries to collect it.)
    """

    def __init__(
        self,
        id: str,
        subject_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        expected_decision: str,
        policy_ids: list[str] | None = None,
        rationale: str = ""
    ):
        self.id = id
        self.subject_id = subject_id
        self.action = action
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.expected_decision = expected_decision
        self.policy_ids = policy_ids if policy_ids is not None else []
        self.rationale = rationale

    @property
    def key(self) -> tuple:
        """Stable identity used to match a case across runs."""
        return (
            self.subject_id,
            self.action,
            self.resource_type,
            self.resource_id
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "subject_id": self.subject_id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "expected_decision": self.expected_decision,
            "policy_ids": list(self.policy_ids),
            "rationale": self.rationale,
        }

    def __repr__(self):
        return (
            f"AuthzCase("
            f"id={self.id!r}, "
            f"subject_id={self.subject_id!r}, "
            f"action={self.action!r}, "
            f"resource={self.resource_type!r}/{self.resource_id!r}, "
            f"expected={self.expected_decision!r}"
            f")"
        )
