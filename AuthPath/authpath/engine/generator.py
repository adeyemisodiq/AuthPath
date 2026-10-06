from authpath.models.subject import Subject
from authpath.models.resource import Resource
from authpath.models.action import Action
from authpath.models.policy import Policy
from authpath.models.authz_case import AuthzCase
from authpath.engine.policy_evaluator import evaluate_policy_set


def generate_test_cases(
    policies: list[Policy] | Policy,
    subjects: list[Subject],
    action: Action,
    resources: list[Resource],
    start_number: int = 1
) -> list[AuthzCase]:
    """
    Cross every subject with every resource for one action and let the
    policy set decide what the expected outcome is.
    """

    if isinstance(policies, Policy):
        policies = [policies]

    cases = []
    number = start_number

    for subject in subjects:
        for resource in resources:

            decision = evaluate_policy_set(
                policies,
                subject,
                action,
                resource
            )

            cases.append(
                AuthzCase(
                    id=f"TC-{number:03d}",
                    subject_id=subject.id,
                    action=action.name,
                    resource_type=resource.type,
                    resource_id=resource.id,
                    expected_decision=decision.decision,
                    policy_ids=decision.policy_ids,
                    rationale=decision.reason
                )
            )

            number += 1

    return cases
