from authpath.engine.evaluator import PASS, FAILING_VERDICTS, INCONCLUSIVE

FIXED = "FIXED"
STILL_FAILING = "STILL_FAILING"
REGRESSION = "REGRESSION"
PASS_UNCHANGED = "PASS_UNCHANGED"
NEEDS_REVIEW = "NEEDS_REVIEW"
NOT_COMPARABLE = "NOT_COMPARABLE"


def _key(result: dict) -> tuple:
    return (
        result["subject_id"],
        result["action"],
        result["resource_type"],
        result["resource_id"],
    )


def _status(before: str | None, after: str | None) -> str:
    if before is None or after is None:
        return NOT_COMPARABLE
    if INCONCLUSIVE in (before, after):
        return NEEDS_REVIEW
    if before in FAILING_VERDICTS and after == PASS:
        return FIXED
    if before in FAILING_VERDICTS and after in FAILING_VERDICTS:
        return STILL_FAILING
    if before == PASS and after in FAILING_VERDICTS:
        return REGRESSION
    return PASS_UNCHANGED


def compare_runs(before: dict, after: dict) -> dict:
    """
    Match cases by (subject, action, resource) and classify what changed.

      FIXED           failed before, passes now
      STILL_FAILING   failed before, still fails
      REGRESSION      passed before, fails now
      PASS_UNCHANGED  passed both times
      NEEDS_REVIEW    an INCONCLUSIVE result is involved
      NOT_COMPARABLE  case exists in only one run
    """

    before_by_key = {_key(r): r for r in before["results"]}
    after_by_key = {_key(r): r for r in after["results"]}

    rows = []
    for key in sorted(set(before_by_key) | set(after_by_key)):
        b = before_by_key.get(key)
        a = after_by_key.get(key)
        subject_id, action, resource_type, resource_id = key
        rows.append({
            "subject_id": subject_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "before_verdict": b["verdict"] if b else None,
            "after_verdict": a["verdict"] if a else None,
            "before_status": b["response"]["status"] if b else None,
            "after_status": a["response"]["status"] if a else None,
            "status": _status(
                b["verdict"] if b else None,
                a["verdict"] if a else None,
            ),
        })

    counts = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1

    return {
        "before": before["run"]["label"],
        "after": after["run"]["label"],
        "counts": counts,
        "rows": rows,
    }


def render_retest_markdown(comparison: dict) -> str:
    counts = comparison["counts"]
    lines = [
        f"# Retest: `{comparison['before']}` -> `{comparison['after']}`",
        "",
        "| Status | Cases |",
        "|---|---|",
    ]

    for status in (
        FIXED, STILL_FAILING, REGRESSION,
        PASS_UNCHANGED, NEEDS_REVIEW, NOT_COMPARABLE,
    ):
        lines.append(f"| {status} | {counts.get(status, 0)} |")

    def section(title: str, status: str):
        rows = [r for r in comparison["rows"] if r["status"] == status]
        if not rows:
            return
        lines.extend(["", f"## {title}", "",
                      "| Subject | Action | Resource | Before | After |",
                      "|---|---|---|---|---|"])
        for r in rows:
            lines.append(
                f"| {r['subject_id']} | {r['action']} | "
                f"{r['resource_type']}/{r['resource_id']} | "
                f"{r['before_verdict']} (HTTP {r['before_status']}) | "
                f"{r['after_verdict']} (HTTP {r['after_status']}) |"
            )

    section("Regressions (passed before, fails now)", REGRESSION)
    section("Still failing after the fix", STILL_FAILING)
    section("Needs manual review", NEEDS_REVIEW)
    section("Fixed", FIXED)

    lines.append("")
    return "\n".join(lines)
