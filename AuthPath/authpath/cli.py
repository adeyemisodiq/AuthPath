import argparse
import csv
import json
import os
import sys

from authpath.config import load_scenario, ScenarioError
from authpath.runner import run_scenario, RunnerError
from authpath.api.executor import ScopeViolation
from authpath.evidence.recorder import write_run, load_run, verify_manifest
from authpath.reporting.report import render_run_report
from authpath.reporting.html_report import render_run_report_html
from authpath.reporting.retest import (
    compare_runs, render_retest_markdown, REGRESSION, STILL_FAILING,
)
from authpath.wizard import run_wizard, write_scenario_file
from authpath.importers.openapi import import_bindings, load_spec, draft_resources


def _cmd_run(args) -> int:
    scenario = load_scenario(args.scenario, base_url=args.base_url)
    run = run_scenario(scenario, label=args.label, timeout=args.timeout)
    directory = write_run(
        run, args.out, render_run_report(run), render_run_report_html(run)
    )

    s = run["summary"]
    print(f"AuthPath run '{args.label}' against {scenario.base_url}")
    print(f"  total={s['total']} pass={s['pass']} "
          f"violation={s['violation']} "
          f"over_restriction={s['over_restriction']} "
          f"inconclusive={s['inconclusive']} "
          f"data_exposure={s['data_exposure']}")
    print(f"  evidence: {directory}")

    if args.strict and (
        s["violation"] or s["over_restriction"] or s["inconclusive"]
        or s["data_exposure"]
    ):
        return 1
    return 0


def _cmd_compare(args) -> int:
    before = load_run(args.before)
    after = load_run(args.after)
    comparison = compare_runs(before, after)

    name = f"retest-{comparison['before']}-vs-{comparison['after']}"
    directory = os.path.join(args.out, name)
    os.makedirs(directory, exist_ok=True)

    with open(os.path.join(directory, "retest.md"), "w",
              encoding="utf-8", newline="\n") as handle:
        handle.write(render_retest_markdown(comparison))

    with open(os.path.join(directory, "retest-matrix.csv"), "w",
              encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(comparison["rows"][0]))
        writer.writeheader()
        writer.writerows(comparison["rows"])

    from authpath.evidence.recorder import write_manifest
    write_manifest(directory)

    print(f"Retest '{comparison['before']}' -> '{comparison['after']}'")
    for status, count in sorted(comparison["counts"].items()):
        print(f"  {status}: {count}")
    print(f"  output: {directory}")

    if args.strict and (
        comparison["counts"].get(REGRESSION)
        or comparison["counts"].get(STILL_FAILING)
    ):
        return 1
    return 0


def _cmd_verify(args) -> int:
    problems = verify_manifest(args.directory)
    if problems:
        print("EVIDENCE NOT INTACT:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("Evidence intact: every file matches manifest.sha256")
    return 0


def _cmd_init(args) -> int:
    scenario_dict = run_wizard()
    write_scenario_file(scenario_dict, args.out)
    print(f"\nWrote {args.out}")
    print(f"Run it with: authpath run --scenario {args.out} --label first-run")
    return 0


def _cmd_import_openapi(args) -> int:
    bindings = import_bindings(load_spec(args.spec))
    if not bindings:
        print("No operations found in that spec.", file=sys.stderr)
        return 2

    print(f"Drafted {len(bindings)} binding(s) - REVIEW before trusting "
          f"results (action/resource names are guesses from the URL):")
    for binding in bindings:
        print(f"  - {binding['id']}: {binding['method']} {binding['path']} "
              f"(action={binding['action']}, resource={binding['resource']}, "
              f"level={binding['authorization_level']})")
    print(f"\nResource types seen: {', '.join(draft_resources(bindings))}")

    for binding in bindings:
        binding.pop("review", None)
        binding.pop("summary", None)

    with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(bindings, handle, indent=2)
        handle.write("\n")
    print(f"\nDraft bindings written to {args.out} - paste the ones you "
          f"want into your scenario's \"bindings\" list.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authpath",
        description="Automated API authorization testing."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="test an API against a scenario")
    run.add_argument("--scenario", required=True)
    run.add_argument("--label", required=True,
                     help="name for this run, e.g. vulnerable / patched")
    run.add_argument("--out", default="reports")
    run.add_argument("--base-url", default=None,
                     help="override base_url from the scenario")
    run.add_argument("--timeout", type=float, default=5.0)
    run.add_argument("--strict", action="store_true",
                     help="exit 1 if any case does not pass")
    run.set_defaults(func=_cmd_run)

    compare = sub.add_parser("compare", help="retest: compare two runs")
    compare.add_argument("--before", required=True, help="results.json")
    compare.add_argument("--after", required=True, help="results.json")
    compare.add_argument("--out", default="reports")
    compare.add_argument("--strict", action="store_true",
                         help="exit 1 on regression or unfixed findings")
    compare.set_defaults(func=_cmd_compare)

    verify = sub.add_parser("verify", help="check evidence against its manifest")
    verify.add_argument("directory")
    verify.set_defaults(func=_cmd_verify)

    init = sub.add_parser("init", help="guided wizard to build a scenario file")
    init.add_argument("--out", default="policies/scenario.json")
    init.set_defaults(func=_cmd_init)

    imp = sub.add_parser(
        "import-openapi",
        help="draft bindings from an OpenAPI/Swagger JSON spec"
    )
    imp.add_argument("--spec", required=True)
    imp.add_argument("--out", default="policies/imported_bindings.json")
    imp.set_defaults(func=_cmd_import_openapi)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ScenarioError, RunnerError, ScopeViolation, ValueError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
