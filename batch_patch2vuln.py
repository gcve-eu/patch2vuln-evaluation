#!/usr/bin/env python3
"""Run patch2vuln repeatedly over (CVE ID, GitHub commit URL) CSV rows.

Python 3.10+; standard library only. The patch2vuln installation and Ollama
model are external dependencies and must be configured separately.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

CVE_RE = re.compile(r"^CVE-(?:19|20)\d{2}-\d{4,}$", re.IGNORECASE)
SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
GITHUB_NAME_RE = re.compile(r"^[a-zA-Z0-9_.-]+$")
HEADER_CVE = {"cve", "cve_id", "cve-id", "cve id", "cveid"}
HEADER_COMMIT = {"commit", "commit_url", "commit-url", "commit url", "github_commit", "github_url", "url"}
FORBIDDEN_EXTRA = {
    "--cve-id", "-o", "--output", "--analysis-output", "--comparison-output",
    "--all-formats", "--all-formats-output", "--model",
}


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_commit_url(value: str) -> tuple[str, str]:
    """Return (canonical .patch URL, case key) for a GitHub commit."""
    parsed = urlsplit(value.strip())
    if  not(parsed.scheme.startswith("http")) or parsed.hostname not in ("github.com", "www.github.com"):
        raise ValueError("expected an https://github.com/OWNER/REPO/commit/SHA URL")
    if parsed.username or parsed.password or parsed.port:
        raise ValueError("GitHub URLs must not contain credentials or a custom port")
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 4 or parts[2] != "commit":
        raise ValueError("expected GitHub commit URL path /OWNER/REPO/commit/SHA")
    owner, repo, _, commit = parts
    if not GITHUB_NAME_RE.fullmatch(owner) or not GITHUB_NAME_RE.fullmatch(repo):
        raise ValueError("invalid GitHub owner or repository name")
    if commit.endswith(".patch"):
        commit = commit[:-6]
    if not SHA_RE.fullmatch(commit):
        raise ValueError("commit SHA should contain 7-40 hexadecimal characters")
    sha = commit.lower()
    url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
    case_key = f"{owner}__{repo}__{sha}"
    return url, case_key


def read_cases(csv_path: Path) -> list[dict[str, str | int]]:
    """Read headerless or two-column header CSV; reject malformed input."""
    cases: list[dict[str, str | int]] = []
    seen: set[tuple[str, str]] = set()
    with csv_path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream)
        for line_number, row in enumerate(reader, 1):
            if not row or not any(cell.strip() for cell in row):
                continue
            if len(row) < 2:
                raise ValueError(f"CSV row {line_number}: expected at least 2 columns")
            cve, url = row[0].strip().upper(), row[1].strip()
            if not cases and cve.lower() in HEADER_CVE and url.lower() in HEADER_COMMIT:
                continue
            if not CVE_RE.fullmatch(cve):
                raise ValueError(f"CSV row {line_number}: invalid CVE ID {cve!r}")
            try:
                patch_url, case_key = normalize_commit_url(url)
            except ValueError as exc:
                raise ValueError(f"CSV row {line_number} ({cve}): {exc}") from exc
            if (cve, patch_url) in seen:
                print(f"WARNING: skipping duplicate CSV row {line_number}: {cve}, {url}", file=sys.stderr)
                continue
            seen.add((cve, patch_url))
            cases.append({"cve_id": cve, "commit_url": url,
                          "patch_url": patch_url, "case_key": case_key, "csv_row": line_number})
    if not cases:
        raise ValueError("CSV contains no CVE / GitHub commit pairs")
    return cases


def validate_cve_json(path: Path, expected_id: str) -> str | None:
    """Return an error message, or None when CVE output is minimally valid."""
    if not path.is_file():
        return "patch2vuln did not produce the expected output JSON file"
    try:
        with path.open("r", encoding="utf-8") as stream:
            record = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return f"invalid JSON output: {exc}"
    if not isinstance(record, dict) or record.get("dataType") != "CVE_RECORD":
        return "output is not a CVE_RECORD"
    metadata = record.get("cveMetadata")
    if not isinstance(metadata, dict) or metadata.get("cveId") != expected_id:
        return f"output cveMetadata.cveId differs from {expected_id}"
    containers = record.get("containers")
    if not isinstance(containers, dict) or not isinstance(containers.get("cna"), dict):
        return "output lacks containers.cna"
    return None


def write_json(path: Path, obj: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as stream:
        json.dump(obj, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    tmp.replace(path)


def make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Benchmark patch2vuln on GitHub commits listed beside CVE IDs in a CSV.",
        epilog=("Use -- to forward additional patch2vuln options, e.g. "
                "-- --no-cpe-review --no-tag-version-detection"),
    )
    p.add_argument("csv_file", type=Path, help="CSV with columns: CVE ID, GitHub commit link")
    p.add_argument("--patch2vuln", type=Path, default=Path("./patch2vuln.py"),
                   help="Path to cloned patch2vuln.py (default: ./patch2vuln.py)")
    p.add_argument("--output-dir", type=Path, default=Path("patch2vuln-results"))
    p.add_argument("--runs", type=int, default=1, help="Independent executions per CSV entry (default: 1)")
    p.add_argument("--model", action="append", default=[],
                   help="Ollama model (repeat for multi-model comparison within each execution)")
    p.add_argument("--timeout", type=int, default=0,
                   help="Seconds to allow per execution (0 disables timeout)")
    p.add_argument("--resume", action="store_true",
                   help="Skip existing, successful runs with identical configuration")
    p.add_argument("--overwrite", action="store_true",
                   help="Replace previous run artifacts even if they exist")
    p.add_argument("--dry-run", action="store_true", help="Show commands and output paths without running")
    return p


def main(argv: list[str] | None = None) -> int:
    args_in = list(sys.argv[1:] if argv is None else argv)
    extra: list[str] = []
    if "--" in args_in:
        separator = args_in.index("--")
        extra = args_in[separator + 1:]
        args_in = args_in[:separator]
    p = make_parser()
    args = p.parse_args(args_in)
    if args.runs < 1 or args.timeout < 0:
        p.error("--runs must be >= 1 and --timeout must be >= 0")
    if args.resume and args.overwrite:
        p.error("--resume and --overwrite cannot be combined")
    for token in extra:
        flag = token.split("=", 1)[0]
        if flag in FORBIDDEN_EXTRA:
            p.error(f"do not forward {flag}; this runner controls it directly")
    if not args.csv_file.is_file():
        p.error(f"CSV file not found: {args.csv_file}")
    script = args.patch2vuln.expanduser().resolve()
    if not args.dry_run and not script.is_file():
        p.error(f"patch2vuln script not found: {script}")
    try:
        cases = read_cases(args.csv_file)
    except (OSError, UnicodeError, csv.Error, ValueError) as exc:
        p.error(str(exc))

    root = args.output_dir.expanduser().resolve()
    script_sha256 = sha256_file(script) if script.is_file() else None
    total = len(cases) * args.runs
    print(f"Processing {len(cases)} CSV entries x {args.runs} run(s) = {total} executions")
    results = []
    for case in cases:
        cve = str(case["cve_id"])
        patch_url = str(case["patch_url"])
        case_key = str(case["case_key"])
        for number in range(1, args.runs + 1):
            folder = root / cve / case_key / f"run_{number:03d}"
            cve_file = folder / f"{cve}.cve.json"
            metadata_file = folder / "run-metadata.json"
            comparison_file = folder / "comparison.json"
            analysis_file = folder / "analysis.json"
            command = [sys.executable, str(script), patch_url,
                       "--cve-id", cve, "-o", str(cve_file),
                       "--analysis-output", str(analysis_file)]
            if len(args.model) > 1:
                command.extend(["--comparison-output", str(comparison_file)])
            for model in args.model:
                command.extend(["--model", model])
            command.extend(extra)
            base = {"cve_id": cve, "input_commit_url": case["commit_url"],
                    "patch_url": patch_url, "case_key": case_key,
                    "csv_row": case["csv_row"], "run": number,
                    "models": args.model, "patch2vuln_sha256": script_sha256,
                    "command": command, "output_json": str(cve_file)}
            label = f"[{len(results) + 1}/{total}] {cve} {case_key} run {number}"

            if args.dry_run:
                print(f"DRY-RUN {label}: {shlex.join(command)}")
                results.append({**base, "status": "dry_run", "return_code": None})
                continue

            if folder.exists() and not args.overwrite:
                if args.resume and metadata_file.is_file():
                    try:
                        previous = json.loads(metadata_file.read_text(encoding="utf-8"))
                        matching = (previous.get("status") == "success" and
                                    previous.get("command") == command and
                                    previous.get("patch2vuln_sha256") == script_sha256 and
                                    validate_cve_json(cve_file, cve) is None and
                                    previous.get("output_sha256") == sha256_file(cve_file))
                    except (OSError, ValueError, TypeError):
                        matching = False
                    if matching:
                        print(f"SKIP {label} (previous successful output)")
                        results.append({**base, "status": "skipped_success", "return_code": 0})
                        continue
                    # Protect successful experiments even if their configuration differs.
                    if previous.get("status") == "success":
                        print(f"ERROR {label}: prior successful run differs or output was modified; use --overwrite", file=sys.stderr)
                        results.append({**base, "status": "configuration_mismatch", "return_code": None})
                        continue
                # Refuse to silently overwrite outputs; permit resume to rerun failed jobs.
                if not args.resume:
                    print(f"ERROR {label}: directory exists; use --resume or --overwrite", file=sys.stderr)
                    results.append({**base, "status": "existing_directory", "return_code": None})
                    continue
            folder.mkdir(parents=True, exist_ok=True)
            # Delete old artifacts before retrying to prevent stale JSON being accepted.
            for artifact in (cve_file, comparison_file, analysis_file):
                if artifact.exists():
                    artifact.unlink()
            print(f"RUN {label}", flush=True)
            start_time = now_utc()
            start = time.monotonic()
            return_code: int | None = None
            error: str | None = None
            try:
                with (folder / "stdout.log").open("w", encoding="utf-8") as stdout, \
                     (folder / "stderr.log").open("w", encoding="utf-8") as stderr:
                    completed = subprocess.run(command, cwd=script.parent, stdout=stdout,
                                               stderr=stderr, check=False,
                                               timeout=args.timeout or None)
                return_code = completed.returncode
                if return_code != 0:
                    error = f"patch2vuln returned nonzero exit status {return_code}"
                else:
                    error = validate_cve_json(cve_file, cve)
            except subprocess.TimeoutExpired:
                error = f"patch2vuln timed out after {args.timeout} seconds"
            except OSError as exc:
                error = f"execution failed: {exc}"
            end_time = now_utc()
            status = "failed" if error else "success"
            row = {**base, "status": status, "return_code": return_code,
                   "started_at": start_time, "finished_at": end_time,
                   "duration_seconds": round(time.monotonic() - start, 3),
                   "error": error,
                   "output_sha256": sha256_file(cve_file) if not error else None}
            write_json(metadata_file, row)
            results.append(row)
            print(f"{'FAIL' if error else 'OK'}  {label}" + (f": {error}" if error else ""), flush=True)

    if args.dry_run:
        print("Dry run complete; no outputs were written.")
        return 0

    root.mkdir(parents=True, exist_ok=True)
    fields = ["cve_id", "input_commit_url", "patch_url", "case_key", "run",
              "status", "return_code", "duration_seconds", "error", "output_json"]
    with (root / "summary.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    counts = {s: sum(r["status"] == s for r in results)
              for s in sorted(set(r["status"] for r in results))}
    write_json(root / "summary.json", {"generated_at": now_utc(),
                                       "csv_file": str(args.csv_file.resolve()),
                                       "counts": counts, "runs": results})
    print(f"Summary: {root / 'summary.csv'}")
    print("Statuses: " + ", ".join(f"{name}={count}" for name, count in counts.items()))
    return 1 if any(r["status"] not in ("success", "skipped_success") for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
