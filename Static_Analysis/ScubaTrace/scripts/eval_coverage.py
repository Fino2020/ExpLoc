#!/usr/bin/python3
"""
Coverage Evaluation: Compare ScubaTrace ICFG coverage vs CodeQL ICFG coverage.

Reads:
  - Static_Analysis/Results/ScubaTrace/{CVE-ID}/icfg_scubatrace.csv  (new ICFG)
  - Results/Localization/main/audit/audit_per_cve.json (GT + CodeQL coverage)
  - Static_Analysis/Results/CodeQL/{CVE-ID}/summary.json (CodeQL summary)

Outputs:
  - Static_Analysis/Results/ScubaTrace/coverage_per_cve.json
  - Static_Analysis/Results/ScubaTrace/coverage_summary.json
  - Static_Analysis/Results/ScubaTrace/coverage_comparison.csv
"""

import csv
import json
import os
import sys
from collections import defaultdict

RESULTS_DIR = "/mnt/d/Desktop/VulnLocalization/Static_Analysis/Results/ScubaTrace"
AUDIT_PATH = ("/mnt/d/Desktop/VulnLocalization/"
              "Results/Localization/main/audit/audit_per_cve.json")
CODEQL_RESULTS_DIR = "/mnt/d/Desktop/VulnLocalization/Static_Analysis/Results/CodeQL"


class IcfgIndex:
    """Fast lookup index matching audit_icfg_gt.py's IcfgIndex."""

    def __init__(self, csv_path: str):
        self.files: set[str] = set()
        self.functions: set[str] = set()
        self.file_to_functions: dict[str, set[str]] = defaultdict(set)
        self.total_edges = 0
        self._load(csv_path)

    def _load(self, csv_path: str):
        if not os.path.exists(csv_path):
            return
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = [h.strip().lower().strip('"') for h in next(reader, [])]
            if not header:
                return
            has_target = "target_function" in header
            for row in reader:
                if len(row) < 2:
                    continue
                file_path = row[0].strip().strip('"')
                func_name = row[1].strip().strip('"')
                target_func = ""
                if has_target and len(row) > 5:
                    target_func = row[5].strip().strip('"')

                self.files.add(file_path)
                if func_name:
                    self.functions.add(func_name)
                    self.file_to_functions[file_path].add(func_name)
                if target_func:
                    self.file_to_functions[file_path].add(target_func)

                self.total_edges += 1

    def has_file(self, file_path: str) -> bool:
        return file_path in self.files

    def find_file_fuzzy(self, file_path: str) -> str | None:
        """Fuzzy file path matching (mirrors audit_icfg_gt.py)."""
        if file_path in self.files:
            return file_path

        norm_gt = file_path.replace('\\', '/')
        gt_parts = norm_gt.split('/')
        gt_bn = gt_parts[-1] if gt_parts else ""

        for f in self.files:
            norm_f = f.replace('\\', '/')
            if norm_f.endswith(norm_gt) or norm_gt.endswith(norm_f):
                return f

        for depth in (3, 2):
            if len(gt_parts) >= depth:
                gt_suffix = '/'.join(gt_parts[-depth:])
                for f in self.files:
                    norm_f = f.replace('\\', '/')
                    f_parts = norm_f.split('/')
                    if len(f_parts) >= depth and '/'.join(f_parts[-depth:]) == gt_suffix:
                        return f

        parent = gt_parts[-2] if len(gt_parts) >= 2 else ""
        for f in self.files:
            norm_f = f.replace('\\', '/')
            f_parts = norm_f.split('/')
            f_bn = f_parts[-1] if f_parts else ""
            f_parent = f_parts[-2] if len(f_parts) >= 2 else ""
            if f_bn == gt_bn and parent and f_parent == parent:
                return f

        for f in self.files:
            norm_f = f.replace('\\', '/')
            if norm_f.endswith('/' + gt_bn) or norm_f.endswith('\\' + gt_bn):
                return f

        return None

    def has_function(self, func_name: str, file_path: str | None = None) -> bool:
        if func_name in self.functions:
            return True
        for fname in self.functions:
            if func_name.lower() in fname.lower() or fname.lower() in func_name.lower():
                return True
        return False


def compute_coverage(icfg_index: IcfgIndex, gt_files: list[str],
                     gt_functions: list[str]) -> dict:
    """Compute file and function coverage vs ground truth."""
    files_found = 0
    functions_found = 0

    for gf in gt_files:
        if icfg_index.find_file_fuzzy(gf):
            files_found += 1

    for gfunc in gt_functions:
        if icfg_index.has_function(gfunc):
            functions_found += 1

    file_cov = files_found / len(gt_files) if gt_files else 1.0
    func_cov = functions_found / len(gt_functions) if gt_functions else 1.0

    return {
        "gt_files_total": len(gt_files),
        "files_in_icfg": files_found,
        "file_coverage": round(file_cov, 4),
        "gt_functions_total": len(gt_functions),
        "functions_in_icfg": functions_found,
        "func_coverage": round(func_cov, 4),
        "icfg_files_total": len(icfg_index.files),
        "icfg_functions_total": len(icfg_index.functions),
        "icfg_edges": icfg_index.total_edges,
    }


def main():
    # Load CodeQL audit data (ground truth + CodeQL coverage)
    with open(AUDIT_PATH) as f:
        codeql_audit = json.load(f)

    # Build lookup: cve_id -> CodeQL audit entry
    codeql_lookup = {}
    for entry in codeql_audit:
        codeql_lookup[entry["cve_id"]] = entry

    # Load ScubaTrace batch results
    per_cve_results = []
    comparison_rows = []

    # Languages supported by both tools (for comparison)
    compat_langs = {'c', 'cpp', 'java', 'python', 'javascript'}

    # Stats accumulators
    by_language = defaultdict(lambda: {
        "count": 0,
        "codeql_file_cov_sum": 0.0,
        "codeql_func_cov_sum": 0.0,
        "scuba_file_cov_sum": 0.0,
        "scuba_func_cov_sum": 0.0,
        "file_cov_improved": 0,
        "func_cov_improved": 0,
        "file_cov_degraded": 0,
        "func_cov_degraded": 0,
    })

    for cve_id in sorted(os.listdir(RESULTS_DIR)):
        cve_dir = os.path.join(RESULTS_DIR, cve_id)
        if not os.path.isdir(cve_dir):
            continue

        summary_path = os.path.join(cve_dir, "summary.json")
        icfg_path = os.path.join(cve_dir, "icfg_scubatrace.csv")

        if not os.path.exists(summary_path):
            continue

        with open(summary_path) as f:
            scuba_summary = json.load(f)

        if scuba_summary.get("status") not in ("success", "empty"):
            # Record failed attempts too
            codeql_entry = codeql_lookup.get(cve_id, {})
            per_cve_results.append({
                "cve_id": cve_id,
                "language": scuba_summary.get("language", ""),
                "scuba_status": scuba_summary.get("status", "unknown"),
                "scuba_error": scuba_summary.get("error", ""),
                "scuba_files": 0,
                "scuba_functions": 0,
                "scuba_edges": 0,
                "scuba_file_coverage": 0.0,
                "scuba_func_coverage": 0.0,
                "codeql_file_coverage": codeql_entry.get("file_coverage", 0),
                "codeql_func_coverage": codeql_entry.get("func_coverage", 0),
                "gt_files": codeql_entry.get("gt_files", []),
                "gt_functions": codeql_entry.get("gt_functions", []),
            })
            continue

        # Load ICFG index
        icfg_index = IcfgIndex(icfg_path)

        # Get CodeQL comparison data
        codeql_entry = codeql_lookup.get(cve_id, {})
        gt_files = codeql_entry.get("gt_files", [])
        gt_functions = codeql_entry.get("gt_functions", [])
        codeql_file_cov = codeql_entry.get("file_coverage", 0)
        codeql_func_cov = codeql_entry.get("func_coverage", 0)
        language = scuba_summary.get("language", codeql_entry.get("language", "unknown"))

        # Compute ScubaTrace coverage
        cov = compute_coverage(icfg_index, gt_files, gt_functions)

        scuba_file_cov = cov["file_coverage"]
        scuba_func_cov = cov["func_coverage"]

        result = {
            "cve_id": cve_id,
            "language": language,
            "scuba_status": "success",
            "scuba_files": cov["icfg_files_total"],
            "scuba_functions": cov["icfg_functions_total"],
            "scuba_edges": cov["icfg_edges"],
            "scuba_file_coverage": scuba_file_cov,
            "scuba_func_coverage": scuba_func_cov,
            "codeql_file_coverage": codeql_file_cov,
            "codeql_func_coverage": codeql_func_cov,
            "gt_files": gt_files,
            "gt_functions": gt_functions,
        }
        per_cve_results.append(result)

        # Accumulate stats
        if language in compat_langs:
            stats = by_language[language]
            stats["count"] += 1
            stats["codeql_file_cov_sum"] += codeql_file_cov
            stats["codeql_func_cov_sum"] += codeql_func_cov
            stats["scuba_file_cov_sum"] += scuba_file_cov
            stats["scuba_func_cov_sum"] += scuba_func_cov
            if scuba_file_cov > codeql_file_cov:
                stats["file_cov_improved"] += 1
            elif scuba_file_cov < codeql_file_cov:
                stats["file_cov_degraded"] += 1
            if scuba_func_cov > codeql_func_cov:
                stats["func_cov_improved"] += 1
            elif scuba_func_cov < codeql_func_cov:
                stats["func_cov_degraded"] += 1

        # Build comparison row
        comparison_rows.append({
            "cve_id": cve_id,
            "language": language,
            "scuba_status": "success",
            "scuba_files": cov["icfg_files_total"],
            "scuba_functions": cov["icfg_functions_total"],
            "scuba_edges": cov["icfg_edges"],
            "scuba_file_cov": scuba_file_cov,
            "scuba_func_cov": scuba_func_cov,
            "codeql_file_cov": codeql_file_cov,
            "codeql_func_cov": codeql_func_cov,
            "file_cov_delta": round(scuba_file_cov - codeql_file_cov, 4),
            "func_cov_delta": round(scuba_func_cov - codeql_func_cov, 4),
            "gt_files_count": len(gt_files),
            "gt_functions_count": len(gt_functions),
        })

    # Build aggregate summary
    summary = {
        "total_evaluated": len(per_cve_results),
        "by_language": {},
        "by_codeql_category": {},
        "overall": {},
    }

    for lang, stats in sorted(by_language.items()):
        n = stats["count"]
        summary["by_language"][lang] = {
            "count": n,
            "codeql_file_cov_avg": round(stats["codeql_file_cov_sum"] / n, 4) if n else 0,
            "codeql_func_cov_avg": round(stats["codeql_func_cov_sum"] / n, 4) if n else 0,
            "scuba_file_cov_avg": round(stats["scuba_file_cov_sum"] / n, 4) if n else 0,
            "scuba_func_cov_avg": round(stats["scuba_func_cov_sum"] / n, 4) if n else 0,
            "file_cov_improved": stats["file_cov_improved"],
            "func_cov_improved": stats["func_cov_improved"],
            "file_cov_degraded": stats["file_cov_degraded"],
            "func_cov_degraded": stats["func_cov_degraded"],
        }

    # By CodeQL mismatch category
    by_category = defaultdict(lambda: {
        "count": 0,
        "codeql_file_sum": 0.0, "scuba_file_sum": 0.0,
        "codeql_func_sum": 0.0, "scuba_func_sum": 0.0,
        "improved": 0, "degraded": 0,
    })
    for r in per_cve_results:
        cve_id = r["cve_id"]
        cq = codeql_lookup.get(cve_id, {})
        cat = cq.get("mismatch_category", "unknown")
        by_category[cat]["count"] += 1
        by_category[cat]["codeql_file_sum"] += r["codeql_file_coverage"]
        by_category[cat]["scuba_file_sum"] += r["scuba_file_coverage"]
        by_category[cat]["codeql_func_sum"] += r["codeql_func_coverage"]
        by_category[cat]["scuba_func_sum"] += r["scuba_func_coverage"]
        if r["scuba_file_coverage"] > r["codeql_file_coverage"]:
            by_category[cat]["improved"] += 1
        elif r["scuba_file_coverage"] < r["codeql_file_coverage"]:
            by_category[cat]["degraded"] += 1

    for cat, stats in by_category.items():
        n = stats["count"]
        summary["by_codeql_category"][cat] = {
            "count": n,
            "codeql_file_cov_avg": round(stats["codeql_file_sum"] / n, 4) if n else 0,
            "scuba_file_cov_avg": round(stats["scuba_file_sum"] / n, 4) if n else 0,
            "codeql_func_cov_avg": round(stats["codeql_func_sum"] / n, 4) if n else 0,
            "scuba_func_cov_avg": round(stats["scuba_func_sum"] / n, 4) if n else 0,
            "file_cov_improved": stats["improved"],
            "file_cov_degraded": stats["degraded"],
        }

    # Overall
    n = len(per_cve_results)
    if n > 0:
        codeql_file_sum = sum(r["codeql_file_coverage"] for r in per_cve_results)
        scuba_file_sum = sum(r["scuba_file_coverage"] for r in per_cve_results)
        codeql_func_sum = sum(r["codeql_func_coverage"] for r in per_cve_results)
        scuba_func_sum = sum(r["scuba_func_coverage"] for r in per_cve_results)
        improved_file = sum(1 for r in per_cve_results
                           if r["scuba_file_coverage"] > r["codeql_file_coverage"])
        improved_func = sum(1 for r in per_cve_results
                           if r["scuba_func_coverage"] > r["codeql_func_coverage"])
        degraded_file = sum(1 for r in per_cve_results
                           if r["scuba_file_coverage"] < r["codeql_file_coverage"])

        summary["overall"] = {
            "total": n,
            "codeql_file_cov_avg": round(codeql_file_sum / n, 4),
            "scuba_file_cov_avg": round(scuba_file_sum / n, 4),
            "codeql_func_cov_avg": round(codeql_func_sum / n, 4),
            "scuba_func_cov_avg": round(scuba_func_sum / n, 4),
            "file_cov_improved_count": improved_file,
            "func_cov_improved_count": improved_func,
            "file_cov_degraded_count": degraded_file,
            "file_cov_delta_avg": round((scuba_file_sum - codeql_file_sum) / n, 4),
            "func_cov_delta_avg": round((scuba_func_sum - codeql_func_sum) / n, 4),
        }

    # Save outputs
    with open(os.path.join(RESULTS_DIR, "coverage_per_cve.json"), "w") as f:
        json.dump(per_cve_results, f, indent=2)

    with open(os.path.join(RESULTS_DIR, "coverage_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    # Save comparison CSV
    csv_path = os.path.join(RESULTS_DIR, "coverage_comparison.csv")
    if comparison_rows:
        fieldnames = list(comparison_rows[0].keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(comparison_rows)

    # Print summary
    print(f"Evaluated {n} CVEs")
    overall = summary.get("overall", {})
    print(f"CodeQL avg file cov: {overall.get('codeql_file_cov_avg', 'N/A')}")
    print(f"ScubaTrace avg file cov: {overall.get('scuba_file_cov_avg', 'N/A')}")
    print(f"File cov improved: {overall.get('file_cov_improved_count', 'N/A')}")
    print(f"Func cov improved: {overall.get('func_cov_improved_count', 'N/A')}")
    print(f"\nBy Language:")
    for lang, s in summary.get("by_language", {}).items():
        print(f"  {lang}: {s['count']} CVEs, "
              f"CodeQL file={s['codeql_file_cov_avg']:.3f}, "
              f"Scuba file={s['scuba_file_cov_avg']:.3f}, "
              f"improved={s['file_cov_improved']}, "
              f"degraded={s['file_cov_degraded']}")


if __name__ == "__main__":
    main()
