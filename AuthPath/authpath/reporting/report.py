from authpath.engine.evaluator import VIOLATION, OVER_RESTRICTION, INCONCLUSIVE

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, None: 3}


def _curl(request: dict) -> str:
    parts = ["curl", "-i", "-X", request["method"]]
    for name, value in request["headers"].items():
        parts += ["-H", f"'{name}: {value}'"]
    if request["body"]:
        parts += ["-d", f"'{request['body']}'"]
    parts.append(f"'{request['url']}'")
    return " ".join(parts)


def _sorted_by_severity(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=lambda r: SEVERITY_ORDER.get(r.get("severity"), 3))


def render_run_report(run: dict) -> str:
    meta = run["run"]
    summary = run["summary"]
    results = run["results"]
    exposures = [r for r in results if r.get("exposed_fields")]

    lines = [
        f"# AuthPath report: `{meta['label']}`",
        "",
        f"- Scenario: {meta['scenario']}",
        f"- Target: {meta['base_url']}",
        f"- Started: {meta['started_at']}  |  Finished: {meta['finished_at']}",
        f"- Tool: AuthPath {run['version']}",
        "",
        "## Summary",
        "",
        "| Total | Pass | Violation | Over-restriction | Inconclusive | "
        "Data exposure |",
        "|---|---|---|---|---|---|",
        f"| {summary['total']} | {summary['pass']} | "
        f"{summary['violation']} | {summary['over_restriction']} | "
        f"{summary['inconclusive']} | {len(exposures)} |",
        "",
        "- **VIOLATION**: policy says deny, API allowed it (security failure).",
        "- **OVER_RESTRICTION**: policy says allow, API denied it "
        "(functional failure).",
        "- **INCONCLUSIVE**: response could not be classified; review manually.",
        "- **Data exposure**: the response body contained a field this "
        "subject should not see, independent of the allow/deny decision.",
    ]

    def findings(title: str, verdict: str):
        rows = _sorted_by_severity(
            [r for r in results if r["verdict"] == verdict]
        )
        if not rows:
            return
        lines.extend(["", f"## {title}", ""])
        for r in rows:
            lines.append(
                f"### {r['case_id']}: {r['subject_id']} "
                f"{r['action']} {r['resource_type']}/{r['resource_id']}"
                + (f"  — **{r['severity']} severity**" if r.get("severity") else "")
            )
            lines.append("")
            if r["category"]:
                lines.append(f"- Category: {r['category']}")
            lines.append(f"- Expected: **{r['expected']}** "
                         f"({r['rationale']})")
            lines.append(f"- Observed: **{r['observed']}** "
                         f"({r['observation_reason']})")
            lines.append(f"- HTTP status: {r['response']['status']}")
            if r.get("exposed_fields"):
                lines.append(
                    f"- Exposed fields: {', '.join(r['exposed_fields'])}"
                )
            lines.append(f"- Response body SHA-256: "
                         f"`{r['response']['body_sha256']}`")
            for note in r.get("remediation", []):
                lines.append(f"- **Remediation:** {note}")
            lines.extend(["", "Reproduce:", "", "```", _curl(r["request"]),
                          "```", ""])

    findings("Violations", VIOLATION)
    findings("Over-restrictions", OVER_RESTRICTION)
    findings("Inconclusive results", INCONCLUSIVE)

    if exposures:
        lines.extend(["", "## Excessive data exposure (OWASP API3)", "",
                      "A correct allow/deny decision is not enough if the "
                      "response body still hands back a field this "
                      "subject should not see.", ""])
        for r in exposures:
            lines.append(
                f"### {r['case_id']}: {r['subject_id']} "
                f"{r['action']} {r['resource_type']}/{r['resource_id']}"
                f"  — **{r['severity']} severity**"
            )
            lines.append("")
            lines.append(f"- Exposed fields: {', '.join(r['exposed_fields'])}")
            lines.append(f"- Main verdict for this request: {r['verdict']}")
            for note in r.get("remediation", []):
                lines.append(f"- **Remediation:** {note}")
            lines.extend(["", "Reproduce:", "", "```", _curl(r["request"]),
                          "```", ""])

    lines.extend([
        "", "## All results", "",
        "| Case | Subject | Action | Resource | Expected | Observed | "
        "HTTP | Verdict | Severity | Exposed fields |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ])
    for r in results:
        lines.append(
            f"| {r['case_id']} | {r['subject_id']} | {r['action']} | "
            f"{r['resource_type']}/{r['resource_id']} | {r['expected']} | "
            f"{r['observed']} | {r['response']['status']} | {r['verdict']} | "
            f"{r.get('severity') or ''} | "
            f"{', '.join(r.get('exposed_fields') or [])} |"
        )

    lines.append("")
    return "\n".join(lines)
