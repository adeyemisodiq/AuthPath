"""
HTML version of the run report - same data as report.md, styled for
screen-recording / sharing instead of reading as plain text.
Self-contained: no external CSS/JS, so it opens correctly from a USB
stick, an email attachment, or a video recording with no internet.
"""

import html

from authpath.engine.evaluator import VIOLATION, OVER_RESTRICTION, INCONCLUSIVE
from authpath.reporting.report import _curl, _sorted_by_severity

SEVERITY_COLORS = {
    "High": "#b91c1c", "Medium": "#b45309", "Low": "#555", None: "#999",
}
VERDICT_COLORS = {
    "PASS": "#15803d", "VIOLATION": "#b91c1c",
    "OVER_RESTRICTION": "#b45309", "INCONCLUSIVE": "#555",
}

STYLE = """
body { font-family: -apple-system, Segoe UI, Arial, sans-serif; max-width: 960px;
       margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; background: #fff; }
h1 { margin-bottom: 0.2rem; }
.meta { color: #555; font-size: 0.9rem; margin-bottom: 1.5rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: 0.9rem; }
th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; }
th { background: #f3f4f6; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px;
         color: #fff; font-size: 0.8rem; font-weight: 600; }
.card { border: 1px solid #ddd; border-radius: 8px; padding: 1rem;
        margin: 1rem 0; background: #fafafa; }
pre { background: #111; color: #e5e5e5; padding: 0.75rem; border-radius: 6px;
      overflow-x: auto; font-size: 0.85rem; }
.summary-grid { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }
.stat { border: 1px solid #ddd; border-radius: 8px; padding: 0.75rem 1.25rem;
        text-align: center; min-width: 100px; }
.stat .n { font-size: 1.6rem; font-weight: 700; display: block; }
.remediation { background: #ecfdf5; border-left: 3px solid #15803d;
               padding: 0.5rem 0.75rem; margin: 0.5rem 0; border-radius: 4px; }
"""


def _badge(text, color):
    if not text:
        return ""
    return f'<span class="badge" style="background:{color}">{html.escape(str(text))}</span>'


def _row_card(r):
    sev = _badge(r.get("severity"), SEVERITY_COLORS.get(r.get("severity"), "#999"))
    verdict = _badge(r["verdict"], VERDICT_COLORS.get(r["verdict"], "#999"))
    exposed = (
        f"<p><b>Exposed fields:</b> {html.escape(', '.join(r['exposed_fields']))}</p>"
        if r.get("exposed_fields") else ""
    )
    remediation = "".join(
        f'<p class="remediation"><b>Remediation:</b> {html.escape(note)}</p>'
        for note in r.get("remediation", [])
    )
    category = f"<p><b>Category:</b> {html.escape(r['category'])}</p>" if r["category"] else ""
    return f"""
    <div class="card">
      <h3>{html.escape(r['case_id'])}: {html.escape(r['subject_id'])}
          {html.escape(r['action'])}
          {html.escape(r['resource_type'])}/{html.escape(r['resource_id'])}
          {verdict} {sev}</h3>
      {category}
      <p><b>Expected:</b> {html.escape(r['expected'])} ({html.escape(r['rationale'])})</p>
      <p><b>Observed:</b> {html.escape(r['observed'])} ({html.escape(r['observation_reason'])})</p>
      <p><b>HTTP status:</b> {r['response']['status']}</p>
      {exposed}
      <p><b>Response body SHA-256:</b> <code>{r['response']['body_sha256']}</code></p>
      {remediation}
      <pre>{html.escape(_curl(r['request']))}</pre>
    </div>"""


def render_run_report_html(run: dict) -> str:
    meta = run["run"]
    summary = run["summary"]
    results = run["results"]
    exposures = [r for r in results if r.get("exposed_fields")]

    stats = "".join(
        f'<div class="stat"><span class="n">{v}</span>{label}</div>'
        for label, v in [
            ("Total", summary["total"]), ("Pass", summary["pass"]),
            ("Violation", summary["violation"]),
            ("Over-restriction", summary["over_restriction"]),
            ("Inconclusive", summary["inconclusive"]),
            ("Data exposure", len(exposures)),
        ]
    )

    def section(title, rows):
        if not rows:
            return ""
        cards = "".join(_row_card(r) for r in _sorted_by_severity(rows))
        return f"<h2>{html.escape(title)}</h2>{cards}"

    sections = (
        section("Violations", [r for r in results if r["verdict"] == VIOLATION])
        + section("Over-restrictions",
                   [r for r in results if r["verdict"] == OVER_RESTRICTION])
        + section("Inconclusive results",
                   [r for r in results if r["verdict"] == INCONCLUSIVE])
        + section("Excessive data exposure (OWASP API3)", exposures)
    )

    table_rows = "".join(
        f"<tr><td>{html.escape(r['case_id'])}</td>"
        f"<td>{html.escape(r['subject_id'])}</td>"
        f"<td>{html.escape(r['action'])}</td>"
        f"<td>{html.escape(r['resource_type'])}/{html.escape(r['resource_id'])}</td>"
        f"<td>{html.escape(r['expected'])}</td>"
        f"<td>{html.escape(r['observed'])}</td>"
        f"<td>{r['response']['status']}</td>"
        f"<td>{_badge(r['verdict'], VERDICT_COLORS.get(r['verdict'], '#999'))}</td>"
        f"<td>{_badge(r.get('severity'), SEVERITY_COLORS.get(r.get('severity'), '#999'))}</td>"
        f"<td>{html.escape(', '.join(r.get('exposed_fields') or []))}</td></tr>"
        for r in results
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AuthPath report: {html.escape(meta['label'])}</title>
<style>{STYLE}</style>
</head>
<body>
  <h1>AuthPath report: {html.escape(meta['label'])}</h1>
  <p class="meta">
    Scenario: {html.escape(meta['scenario'])} &nbsp;|&nbsp;
    Target: {html.escape(meta['base_url'])} &nbsp;|&nbsp;
    {html.escape(meta['started_at'])} &rarr; {html.escape(meta['finished_at'])} &nbsp;|&nbsp;
    AuthPath {html.escape(run['version'])}
  </p>
  <div class="summary-grid">{stats}</div>
  {sections}
  <h2>All results</h2>
  <table>
    <tr><th>Case</th><th>Subject</th><th>Action</th><th>Resource</th>
        <th>Expected</th><th>Observed</th><th>HTTP</th><th>Verdict</th>
        <th>Severity</th><th>Exposed fields</th></tr>
    {table_rows}
  </table>
</body>
</html>
"""
