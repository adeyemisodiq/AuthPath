"""
The proof: Attack -> Evidence -> Fix -> Retest -> Regression,
against the real Lab API in its three modes.
"""

import json
import os

import pytest

from authpath.runner import run_scenario, RunnerError
from authpath.api.executor import execute_request, ScopeViolation
from authpath.evidence.recorder import write_run, verify_manifest, load_run
from authpath.reporting.report import render_run_report
from authpath.reporting.retest import (
    compare_runs, render_retest_markdown,
    FIXED, STILL_FAILING, REGRESSION, PASS_UNCHANGED,
)
from authpath.cli import main as cli_main
from tests.conftest import SCENARIO_PATH


def run_mode(lab, scenario_for, mode, label=None):
    scenario = scenario_for(lab(mode))
    return run_scenario(scenario, label=label or mode)


def test_vulnerable_lab_yields_exactly_the_expected_findings(lab, scenario_for):
    run = run_mode(lab, scenario_for, "vulnerable")
    s = run["summary"]

    # 4 subjects x (2 accounts x 3 actions + 1 directory) = 28 cases
    assert s["total"] == 28
    assert s["violation"] == 12   # read 2 + update 4 + delete 4 + list 2
    assert s["over_restriction"] == 0
    assert s["inconclusive"] == 0
    assert s["pass"] == 16

    violations = {
        (r["subject_id"], r["action"], r["resource_id"])
        for r in run["results"] if r["verdict"] == "VIOLATION"
    }
    # The headline BOLA finding from the original proof:
    assert ("user_001", "read", "account_002") in violations
    # Function-level findings:
    assert ("user_001", "delete", "account_001") in violations
    assert ("user_002", "list_users", "all") in violations
    # Anonymous callers are correctly refused even by the vulnerable lab:
    assert not any(v[0] == "anonymous" for v in violations)


def test_findings_are_categorised_by_owasp_level(lab, scenario_for):
    run = run_mode(lab, scenario_for, "vulnerable")
    by = {(r["subject_id"], r["action"], r["resource_id"]): r
          for r in run["results"]}
    assert by[("user_001", "read", "account_002")]["category"].startswith("API1")
    assert by[("user_001", "delete", "account_002")]["category"].startswith("API5")


def test_patched_lab_passes_everything(lab, scenario_for):
    run = run_mode(lab, scenario_for, "patched")
    assert run["summary"]["pass"] == 28
    assert run["summary"]["violation"] == 0


def test_retest_vulnerable_to_patched_fixes_all_and_nothing_regresses(lab, scenario_for):
    before = run_mode(lab, scenario_for, "vulnerable")
    after = run_mode(lab, scenario_for, "patched")
    counts = compare_runs(before, after)["counts"]

    assert counts[FIXED] == 12
    assert counts[PASS_UNCHANGED] == 16
    assert counts.get(STILL_FAILING, 0) == 0
    assert counts.get(REGRESSION, 0) == 0


def test_regression_is_detected_after_a_good_release(lab, scenario_for):
    good = run_mode(lab, scenario_for, "patched")
    bad = run_mode(lab, scenario_for, "regressed")
    comparison = compare_runs(good, bad)

    assert comparison["counts"][REGRESSION] == 4
    regressed = {
        (r["subject_id"], r["action"], r["resource_id"])
        for r in comparison["rows"] if r["status"] == REGRESSION
    }
    assert regressed == {
        ("user_001", "update", "account_002"),
        ("user_002", "update", "account_001"),
        ("admin_001", "update", "account_001"),
        ("admin_001", "update", "account_002"),
    }
    assert "REGRESSION" in render_retest_markdown(comparison)


def test_partial_fix_shows_as_still_failing(lab, scenario_for):
    before = run_mode(lab, scenario_for, "vulnerable")
    after = run_mode(lab, scenario_for, "regressed")   # update still open
    counts = compare_runs(before, after)["counts"]
    assert counts[STILL_FAILING] == 4
    assert counts[FIXED] == 8


def test_run_is_deterministic(lab, scenario_for):
    a = run_mode(lab, scenario_for, "vulnerable")
    b = run_mode(lab, scenario_for, "vulnerable")
    strip = lambda run: [
        (r["case_id"], r["verdict"], r["response"]["status"],
         r["response"]["body_sha256"])
        for r in run["results"]
    ]
    assert strip(a) == strip(b)


def test_destructive_cases_do_not_contaminate_later_cases(lab, scenario_for):
    """DELETE runs reset the lab; a deleted account must not turn later
    reads into 404s that look like 'deny'."""
    run = run_mode(lab, scenario_for, "vulnerable")
    reads = [r for r in run["results"]
             if r["action"] == "read" and r["subject_id"] == "admin_001"]
    assert all(r["response"]["status"] == 200 for r in reads)


def test_unreachable_target_is_inconclusive_not_pass(scenario_for):
    scenario = scenario_for("http://127.0.0.1:1")
    scenario.lab_reset_path = None      # nothing to reset; nothing is listening
    run = run_scenario(scenario, label="down", timeout=1)
    assert run["summary"]["inconclusive"] == run["summary"]["total"]
    assert run["summary"]["pass"] == 0


def test_failed_lab_reset_aborts_the_run(scenario_for):
    scenario = scenario_for("http://127.0.0.1:1")
    with pytest.raises(RunnerError):
        run_scenario(scenario, label="down", timeout=1)


def test_non_loopback_target_refused_before_any_request(scenario_for):
    scenario = scenario_for("http://example.com")
    calls = []

    def spy(*args, **kwargs):
        calls.append(args)
        raise AssertionError("network call attempted")

    with pytest.raises(ScopeViolation):
        run_scenario(scenario, label="x", executor=spy)
    assert calls == []


def test_evidence_written_and_tamper_detected(lab, scenario_for, tmp_path):
    run = run_mode(lab, scenario_for, "vulnerable")
    directory = write_run(run, str(tmp_path), render_run_report(run))

    assert sorted(os.listdir(directory)) == [
        "manifest.sha256", "report.md", "results.csv", "results.json",
    ]
    assert verify_manifest(directory) == []

    with open(os.path.join(directory, "results.json"), "a") as handle:
        handle.write(" ")
    problems = verify_manifest(directory)
    assert any("results.json" in p and "mismatch" in p for p in problems)


def test_report_contains_reproducible_evidence(lab, scenario_for):
    run = run_mode(lab, scenario_for, "vulnerable")
    report = render_run_report(run)
    assert "## Violations" in report
    assert "API1:2023" in report
    assert "curl -i -X GET -H 'X-User-ID: user_001'" in report
    assert "/api/accounts/account_002" in report


def test_cli_full_workflow(lab, tmp_path, capsys):
    out = str(tmp_path)
    for mode in ("vulnerable", "patched", "regressed"):
        base = lab(mode)
        code = cli_main([
            "run", "--scenario", SCENARIO_PATH, "--label", mode,
            "--base-url", base, "--out", out,
        ])
        assert code == 0

    code = cli_main([
        "compare",
        "--before", os.path.join(out, "vulnerable", "results.json"),
        "--after", os.path.join(out, "patched", "results.json"),
        "--out", out, "--strict",
    ])
    assert code == 0

    code = cli_main([
        "compare",
        "--before", os.path.join(out, "patched", "results.json"),
        "--after", os.path.join(out, "regressed", "results.json"),
        "--out", out, "--strict",
    ])
    assert code == 1   # regression -> strict mode fails

    assert cli_main(["verify", os.path.join(out, "vulnerable")]) == 0


def test_cli_strict_run_fails_on_findings(lab, tmp_path):
    base = lab("vulnerable")
    assert cli_main([
        "run", "--scenario", SCENARIO_PATH, "--label", "v",
        "--base-url", base, "--out", str(tmp_path), "--strict",
    ]) == 1


def test_cli_reports_scope_error_with_exit_2(tmp_path, capsys):
    code = cli_main([
        "run", "--scenario", SCENARIO_PATH, "--label", "x",
        "--base-url", "http://example.com", "--out", str(tmp_path),
    ])
    assert code == 2
    assert "not a loopback host" in capsys.readouterr().err


def test_patched_lab_passes_access_control_but_still_leaks_a_field(lab, scenario_for):
    """
    The key proof for the data-exposure feature: the SAME patched lab that
    scores 28/28 on access control still has a real, separate bug an
    allow/deny test cannot see - every owner read/update of their own
    account comes back with an admin-only field attached.
    """
    run = run_mode(lab, scenario_for, "patched")
    assert run["summary"]["violation"] == 0          # access control: clean
    assert run["summary"]["data_exposure"] == 4       # but data IS over-shared

    exposed = {
        (r["subject_id"], r["action"]): r
        for r in run["results"] if r.get("exposed_fields")
    }
    assert exposed[("user_001", "read")]["exposed_fields"] == ["internal_risk_score"]
    assert exposed[("user_001", "read")]["verdict"] == "PASS"
    assert exposed[("user_001", "read")]["severity"] == "High"
    assert exposed[("user_002", "update")]["exposed_fields"] == ["internal_risk_score"]
    # admin and anonymous never trigger it: admin is entitled, anonymous
    # never gets a 200 in the first place
    assert not any(k[0] in ("admin_001", "anonymous") for k in exposed)


def test_vulnerable_lab_also_leaks_the_field_on_top_of_everything_else(lab, scenario_for):
    run = run_mode(lab, scenario_for, "vulnerable")
    assert run["summary"]["data_exposure"] >= 4


def test_report_includes_data_exposure_section(lab, scenario_for):
    from authpath.reporting.report import render_run_report
    run = run_mode(lab, scenario_for, "patched")
    report = render_run_report(run)
    assert "Excessive data exposure" in report
    assert "internal_risk_score" in report
    assert "High severity" in report


def test_html_report_renders_and_contains_findings(lab, scenario_for):
    from authpath.reporting.html_report import render_run_report_html
    run = run_mode(lab, scenario_for, "vulnerable")
    page = render_run_report_html(run)
    assert page.startswith("<!DOCTYPE html>")
    assert "internal_risk_score" in page
    assert "VIOLATION" in page
    assert "<table>" in page


def test_cli_writes_both_markdown_and_html_reports(lab, tmp_path):
    base = lab("patched")
    code = cli_main([
        "run", "--scenario", SCENARIO_PATH, "--label", "html-check",
        "--base-url", base, "--out", str(tmp_path),
    ])
    assert code == 0
    directory = tmp_path / "html-check"
    assert (directory / "report.md").exists()
    assert (directory / "report.html").exists()
    assert verify_manifest(str(directory)) == []


def test_remediation_text_appears_in_both_reports(lab, scenario_for):
    from authpath.reporting.report import render_run_report
    from authpath.reporting.html_report import render_run_report_html

    run = run_mode(lab, scenario_for, "vulnerable")
    md = render_run_report(run)
    html_page = render_run_report_html(run)

    assert "**Remediation:**" in md
    assert "ownership" in md.lower()
    assert 'class="remediation"' in html_page
    assert "ownership" in html_page.lower()


def test_each_result_carries_a_remediation_list(lab, scenario_for):
    run = run_mode(lab, scenario_for, "vulnerable")
    for r in run["results"]:
        assert isinstance(r["remediation"], list)
        if r["verdict"] == "VIOLATION" or r["exposed_fields"]:
            assert len(r["remediation"]) >= 1
        if r["verdict"] == "PASS" and not r["exposed_fields"]:
            assert r["remediation"] == []
