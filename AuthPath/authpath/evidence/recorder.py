import csv
import hashlib
import json
import os

CSV_COLUMNS = [
    "case_id", "subject_id", "action", "resource_type", "resource_id",
    "expected", "observed", "verdict", "severity", "category", "http_status",
    "observation_reason", "exposed_fields",
]

MANIFEST_NAME = "manifest.sha256"


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(directory: str) -> str:
    """Hash every file in `directory` (except the manifest itself)."""

    lines = []
    for name in sorted(os.listdir(directory)):
        if name == MANIFEST_NAME:
            continue
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            lines.append(f"{_sha256_file(path)}  {name}")

    manifest_path = os.path.join(directory, MANIFEST_NAME)
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")

    return manifest_path


def verify_manifest(directory: str) -> list[str]:
    """Return a list of problems; an empty list means the evidence is intact."""

    manifest_path = os.path.join(directory, MANIFEST_NAME)
    if not os.path.isfile(manifest_path):
        return [f"{MANIFEST_NAME} is missing"]

    problems = []
    listed = set()

    with open(manifest_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            expected_hash, name = line.split("  ", 1)
            listed.add(name)
            path = os.path.join(directory, name)
            if not os.path.isfile(path):
                problems.append(f"{name}: listed but missing")
            elif _sha256_file(path) != expected_hash:
                problems.append(f"{name}: hash mismatch (modified)")

    for name in os.listdir(directory):
        if name != MANIFEST_NAME and name not in listed:
            problems.append(f"{name}: present but not in manifest")

    return problems


def write_run(
    run: dict,
    out_dir: str,
    report_markdown: str,
    report_html: str | None = None,
) -> str:
    """
    Write results.json, results.csv, report.md, report.html (if given) and
    manifest.sha256 into <out_dir>/<label>/ and return that directory.
    """

    directory = os.path.join(out_dir, run["run"]["label"])
    os.makedirs(directory, exist_ok=True)

    with open(
        os.path.join(directory, "results.json"),
        "w", encoding="utf-8", newline="\n"
    ) as handle:
        json.dump(run, handle, indent=2)
        handle.write("\n")

    with open(
        os.path.join(directory, "results.csv"),
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for result in run["results"]:
            writer.writerow({
                **{k: result.get(k) for k in CSV_COLUMNS
                   if k not in ("http_status", "exposed_fields")},
                "http_status": result["response"]["status"],
                "exposed_fields": ", ".join(result.get("exposed_fields") or []),
            })

    with open(
        os.path.join(directory, "report.md"),
        "w", encoding="utf-8", newline="\n"
    ) as handle:
        handle.write(report_markdown)

    if report_html is not None:
        with open(
            os.path.join(directory, "report.html"),
            "w", encoding="utf-8", newline="\n"
        ) as handle:
            handle.write(report_html)

    write_manifest(directory)
    return directory


def load_run(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)
