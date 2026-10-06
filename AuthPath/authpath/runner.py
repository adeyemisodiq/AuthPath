import hashlib
import json
from datetime import datetime, timezone

from authpath import __version__
from authpath.config import Scenario
from authpath.models.action import Action
from authpath.engine.generator import generate_test_cases
from authpath.engine.evaluator import (
    PASS,
    VIOLATION,
    OVER_RESTRICTION,
    INCONCLUSIVE,
    evaluate_result,
    classify_finding,
    DATA_EXPOSURE_CATEGORY,
)
from authpath.engine.severity import classify_severity
from authpath.engine.remediation import get_all_remediations
from authpath.engine.data_exposure import find_exposed_fields
from authpath.api.executor import Scope, execute_request
from authpath.api.response_analyzer import analyze_response
from authpath.api.session_auth import login_subject, LoginError

BODY_EXCERPT_LIMIT = 2000


class RunnerError(Exception):
    """The run cannot be trusted (e.g. lab reset failed)."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run_scenario(
    scenario: Scenario,
    label: str,
    executor=execute_request,
    timeout: float = 5.0
) -> dict:
    """
    generate cases -> send -> analyze -> evaluate -> collect evidence.

    Returns a plain dict (JSON-serialisable) - the run record that the
    evidence writer, the report and the retest comparison all consume.
    """

    scope = Scope(
        scenario.base_url,
        allow_non_loopback=scenario.allow_non_loopback
    )

    subjects = {s.id: s for s in scenario.subjects}
    started_at = _now()
    results = []
    number = 1

    # Session-cookie auth (real apps): log every non-anonymous subject in
    # ONCE up front and keep the cookie, rather than re-logging-in per
    # request. A failed login for any subject aborts the run - a scenario
    # whose credentials don't work would silently test as "always denied"
    # otherwise, which looks identical to a real finding and would be
    # actively misleading.
    session_cookies: dict[str, str] = {}
    if scenario.auth.get("type") == "session_login":
        for subject in scenario.subjects:
            if subject.type == "anonymous":
                continue
            try:
                session_cookies[subject.id] = login_subject(
                    executor,
                    scenario.base_url,
                    scope,
                    timeout,
                    login_path=scenario.auth["login_path"],
                    method=scenario.auth.get("login_method", "POST"),
                    identity_field=scenario.auth.get("identity_field", "identity"),
                    password_field=scenario.auth.get("password_field", "password"),
                    username=subject.attributes["username"],
                    password=subject.attributes["password"],
                )
            except (LoginError, KeyError) as error:
                raise RunnerError(
                    f"Could not log in subject {subject.id!r}: {error}"
                ) from error

    for binding in scenario.bindings:

        resources = [
            r for r in scenario.resources if r.type == binding.resource
        ]

        cases = generate_test_cases(
            scenario.policies,
            scenario.subjects,
            Action(binding.action),
            resources,
            start_number=number
        )
        number += len(cases)

        resources_by_id = {r.id: r for r in resources}

        for case in cases:

            # Clean state for every case, so a destructive test (DELETE)
            # cannot corrupt the next one.
            if scenario.lab_reset_path:
                reset = executor(
                    "POST",
                    scenario.base_url + scenario.lab_reset_path,
                    scope=scope,
                    timeout=timeout
                )
                if reset.status_code != 200:
                    raise RunnerError(
                        f"Lab reset failed: status={reset.status_code} "
                        f"error={reset.error}"
                    )

            subject = subjects[case.subject_id]

            headers = {}
            if subject.type != "anonymous":
                if scenario.auth.get("type") == "session_login":
                    headers["Cookie"] = session_cookies[subject.id]
                else:
                    headers[scenario.identity_header] = subject.id

            body = None
            if binding.body is not None:
                body = json.dumps(binding.body)
                headers["Content-Type"] = "application/json"

            url = scenario.base_url + binding.build_path(case.resource_id)

            timestamp = _now()
            response = executor(
                binding.method,
                url,
                headers=headers,
                body=body,
                timeout=timeout,
                scope=scope
            )

            observation = analyze_response(
                response.status_code,
                response.body
            )
            verdict = evaluate_result(
                case.expected_decision,
                observation.decision
            )

            # #3: excessive data exposure (OWASP API3) - only meaningful
            # when the request actually succeeded, since a denied request
            # leaks nothing.
            exposed_fields = []
            if observation.decision == "allow":
                exposed_fields = find_exposed_fields(
                    response.body,
                    subject,
                    resources_by_id.get(case.resource_id),
                    scenario.sensitive_fields.get(case.resource_type, []),
                    scenario.admin_roles,
                    scenario.admin_only_fields.get(case.resource_type, []),
                )

            category = classify_finding(verdict, binding.authorization_level)
            if exposed_fields and category is None:
                category = DATA_EXPOSURE_CATEGORY

            results.append({
                "case_id": case.id,
                "binding_id": binding.id,
                "authorization_level": binding.authorization_level,
                "subject_id": case.subject_id,
                "action": case.action,
                "resource_type": case.resource_type,
                "resource_id": case.resource_id,
                "expected": case.expected_decision,
                "observed": observation.decision,
                "verdict": verdict,
                "category": category,
                "severity": classify_severity(
                    verdict,
                    case.action,
                    case.resource_type,
                    binding.authorization_level,
                    exposed_fields,
                ),
                "exposed_fields": exposed_fields,
                "remediation": get_all_remediations(
                    verdict, category, exposed_fields
                ),
                "policy_ids": case.policy_ids,
                "rationale": case.rationale,
                "observation_reason": observation.reason,
                "timestamp": timestamp,
                "request": {
                    "method": binding.method,
                    "url": url,
                    "headers": headers,
                    "body": body,
                },
                "response": {
                    "status": response.status_code,
                    "elapsed_ms": response.elapsed_ms,
                    "error": response.error,
                    "body_excerpt": response.body[:BODY_EXCERPT_LIMIT],
                    "body_sha256": _sha256(response.body),
                },
            })

    return {
        "tool": "AuthPath",
        "version": __version__,
        "run": {
            "label": label,
            "scenario": scenario.name,
            "base_url": scenario.base_url,
            "started_at": started_at,
            "finished_at": _now(),
        },
        "summary": summarize(results),
        "results": results,
    }


def summarize(results: list[dict]) -> dict:
    return {
        "total": len(results),
        "pass": sum(r["verdict"] == PASS for r in results),
        "violation": sum(r["verdict"] == VIOLATION for r in results),
        "over_restriction": sum(
            r["verdict"] == OVER_RESTRICTION for r in results
        ),
        "inconclusive": sum(r["verdict"] == INCONCLUSIVE for r in results),
        "data_exposure": sum(bool(r.get("exposed_fields")) for r in results),
    }
