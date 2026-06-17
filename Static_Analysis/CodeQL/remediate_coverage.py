#!/usr/bin/env python3
"""
ICFG Coverage Remediation — re-extract CVEs where GT files are missing from ICFG.

Strategy by category:
  wrong_lang_php_js  — re-extract with enhanced multi-language tree-sitter
  empty_icfg          — re-extract with improved language detection + fallback
  codeql_db_failure   — retry C/C++ with build-mode=none (buildless extraction)
  complete_mismatch   — re-extract + improved path normalization
  partial_mismatch    — re-extract to fill coverage gaps

Usage:
  python remediate_coverage.py                          # all categories
  python remediate_coverage.py --category wrong_lang_php_js  # single category
  python remediate_coverage.py --dry-run                      # preview only
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from codeql_auto_analyzer import (
    analyze_multilang_project, analyze_single_project,
    detect_all_languages, LANG_SIGNATURES,
)

AUDIT_PATH = "/mnt/d/Desktop/VulnLocalization/Results/Localization/main/audit/audit_per_cve.json"
ICFG_RESULTS = Path("/mnt/d/Desktop/VulnLocalization/Static_Analysis/Results/CodeQL")

# Repo locations — try both
REPO_CANDIDATES = [
    Path("/mnt/e/Desktop/Localization_Repo/Localization_Repo"),
    Path("/mnt/d/Desktop/Localization_Repo"),
]

# Categories that can be fixed by re-extraction
FIXABLE_CATEGORIES = {
    "wrong_lang_php_js",
    "empty_icfg",
    "codeql_db_failure",
    "complete_mismatch",
    "partial_mismatch",
    "minor_mismatch",
}


def find_repo_path(cve_id: str, owner: str, project: str) -> Path | None:
    """Find the repo directory for a CVE."""
    for base in REPO_CANDIDATES:
        if not base.is_dir():
            continue
        for candidate in [
            base / cve_id / owner / project,
            base / owner / project,
        ]:
            if candidate.is_dir() and any(candidate.iterdir()):
                return candidate
    return None


def load_audit() -> list[dict]:
    with open(AUDIT_PATH) as f:
        return json.load(f)


def count_icfg_rows(csv_path: Path) -> int:
    try:
        with open(csv_path) as f:
            return sum(1 for _ in f) - 1  # minus header
    except Exception:
        return -1


def validate_coverage_improvement(
    cve_id: str, output_dir: Path, audit_entry: dict
) -> dict:
    """Quick check if re-extraction improved file coverage."""
    result = {
        "cve_id": cve_id,
        "before_coverage": audit_entry["file_coverage"],
        "after_coverage": 0.0,
        "before_icfg_rows": audit_entry["icfg_edges"],
        "after_icfg_rows": 0,
    }

    csv_path = output_dir / "icfg_icfg_db.csv"
    if not csv_path.exists():
        csv_path = output_dir / "icfg_icfg.csv"

    if csv_path.exists():
        result["after_icfg_rows"] = count_icfg_rows(csv_path)

        # Quick check: do any GT files appear in ICFG?
        gt_files = set(audit_entry["gt_files"])
        # Remove non-code files from GT (CHANGELOG, README, etc.)
        code_exts = {".php", ".js", ".py", ".c", ".cpp", ".h", ".java", ".rb", ".go",
                     ".rs", ".ts", ".tsx", ".jsx", ".pl", ".pm", ".html", ".htm"}
        gt_code_files = {f for f in gt_files
                        if os.path.splitext(f)[1].lower() in code_exts}

        if gt_code_files:
            icfg_files = set()
            with open(csv_path, newline="") as f:
                reader = csv.reader(f)
                next(reader, None)
                for row in reader:
                    if row:
                        icfg_files.add(row[0].strip().strip('"'))
            matched = 0
            for gf in gt_code_files:
                gf_norm = gf.replace("\\", "/")
                for icf in icfg_files:
                    icf_norm = icf.replace("\\", "/")
                    if (icf_norm == gf_norm or
                        icf_norm.endswith("/" + gf_norm) or
                        gf_norm.endswith("/" + os.path.basename(icf_norm)) and
                        os.path.basename(gf_norm) == os.path.basename(icf_norm)):
                        matched += 1
                        break
            result["after_coverage"] = round(matched / len(gt_code_files), 4)
            result["gt_code_files"] = len(gt_code_files)
            result["matched_files"] = matched

    return result


def remediate_cve(
    cve_id: str,
    audit_entry: dict,
    dry_run: bool = False,
) -> dict | None:
    """Re-extract ICFG for a single CVE."""
    owner = audit_entry["owner"]
    project_name = audit_entry["project"]
    category = audit_entry["mismatch_category"]

    repo_path = find_repo_path(cve_id, owner, project_name)
    if not repo_path:
        print(f"  [{cve_id}] SKIP: repo not found ({owner}/{project_name})")
        return None

    output_dir = ICFG_RESULTS / cve_id
    output_dir.mkdir(parents=True, exist_ok=True)

    if dry_run:
        print(f"  [{cve_id}] DRY-RUN: would re-extract {owner}/{project_name}")
        return None

    print(f"  [{cve_id}] Re-extracting {owner}/{project_name} "
          f"(category={category}, lang={audit_entry['language']})")

    # Remove old per-language artifacts to force clean re-extraction
    for old in output_dir.glob("icfg_*_db*"):
        if old.is_dir():
            import shutil
            shutil.rmtree(old, ignore_errors=True)

    t0 = time.time()

    try:
        result_csv, error = analyze_multilang_project(
            project_root=repo_path,
            output_dir=output_dir,
            project_label="icfg",
        )
    except Exception as e:
        print(f"  [{cve_id}] ERROR: {type(e).__name__}: {e}")
        return {"cve_id": cve_id, "status": "error", "error": str(e)}

    elapsed = time.time() - t0

    if error:
        print(f"  [{cve_id}] FAILED: {error[:120]}")
        return {"cve_id": cve_id, "status": "failed", "error": error}

    rows = count_icfg_rows(output_dir / "icfg_icfg_db.csv")
    print(f"  [{cve_id}] DONE: {rows} rows, {elapsed:.0f}s")

    # Validate coverage improvement
    improvement = validate_coverage_improvement(cve_id, output_dir, audit_entry)
    if improvement["before_coverage"] == 0 and improvement["after_coverage"] > 0:
        print(f"  [{cve_id}] IMPROVED: coverage {improvement['before_coverage']:.0%} → "
              f"{improvement['after_coverage']:.0%}")
    elif improvement["after_coverage"] == 0:
        print(f"  [{cve_id}] STILL ZERO: no GT files found in re-extracted ICFG. "
              f"GT code files: {improvement.get('gt_code_files', '?')}")

    return {
        "cve_id": cve_id,
        "status": "success",
        "icfg_rows": rows,
        "elapsed_s": elapsed,
        **improvement,
    }


def main():
    parser = argparse.ArgumentParser(description="ICFG Coverage Remediation")
    parser.add_argument("--category", type=str, default="",
                        help="Only remediate this category")
    parser.add_argument("--cves", type=str, default="",
                        help="Comma-separated CVE filter")
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit to N CVEs")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview only, no extraction")
    args = parser.parse_args()

    audits = load_audit()
    print(f"Loaded {len(audits)} audited CVEs")

    # Filter
    cve_filter = set(args.cves.split(",")) if args.cves else None
    target_categories = {args.category} if args.category else FIXABLE_CATEGORIES

    to_fix = []
    for a in audits:
        if a["mismatch_category"] == "full_match":
            continue
        if a["mismatch_category"] not in target_categories:
            continue
        if cve_filter and a["cve_id"] not in cve_filter:
            continue
        to_fix.append(a)

    print(f"CVEs to remediate: {len(to_fix)}")
    by_cat = {}
    for a in to_fix:
        cat = a["mismatch_category"]
        by_cat[cat] = by_cat.get(cat, 0) + 1
    for cat, count in sorted(by_cat.items()):
        print(f"  {cat}: {count}")

    if args.limit > 0:
        to_fix = to_fix[:args.limit]
        print(f"  (limited to {args.limit})")

    if args.dry_run:
        print("\n  DRY RUN — no extraction will be performed\n")

    results = []
    improved = 0
    fixed = 0

    for i, a in enumerate(to_fix):
        cid = a["cve_id"]
        print(f"\n[{i+1}/{len(to_fix)}] {cid}", flush=True)

        result = remediate_cve(cid, a, dry_run=args.dry_run)
        if result:
            results.append(result)
            if result.get("after_coverage", 0) > result.get("before_coverage", 0):
                improved += 1
                if result["after_coverage"] >= 0.5:
                    fixed += 1

    # Summary
    print(f"\n{'=' * 60}")
    print(f"  REMEDIATION COMPLETE")
    print(f"  Processed: {len(results)}")
    print(f"  Improved:  {improved}")
    print(f"  Fixed (≥50% cov): {fixed}")
    print(f"{'=' * 60}")

    # Save results
    summary_path = ICFG_RESULTS / "remediation_summary.json"
    with open(summary_path, "w") as f:
        json.dump({
            "run_at": datetime.now().isoformat(),
            "total": len(results),
            "improved": improved,
            "fixed": fixed,
            "results": results,
        }, f, indent=2)
    print(f"  Saved to: {summary_path}")


if __name__ == "__main__":
    main()
