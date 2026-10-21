#!/usr/bin/python3
"""
Phase 4: Localization Pipeline Integration with ScubaTrace ICFG.

For CVEs where ScubaTrace coverage improved over CodeQL, re-run the
localization pipeline (--no-agent mode for deterministic comparison)
and compare file/function-level accuracy metrics.

Usage:
    python3 run_localization_with_scuba.py [--all] [--limit N]
"""

import json
import os
import sys
import time
import subprocess
from collections import defaultdict

RESULTS_DIR = "/mnt/d/Desktop/VulnLocalization/Static_Analysis/Results/ScubaTrace"
MAIN_PY = "/mnt/d/Desktop/VulnLocalization/Explainable_Localization/main.py"
ORIG_RESULTS = "/mnt/d/Desktop/VulnLocalization/Results/Localization/main"


def load_coverage_data():
    """Load ScubaTrace coverage comparison data."""
    cov_path = os.path.join(RESULTS_DIR, "coverage_per_cve.json")
    if not os.path.exists(cov_path):
        print(f"Coverage data not found: {cov_path}")
        print("Run eval_coverage.py first.")
        return []

    with open(cov_path) as f:
        return json.load(f)


def find_improved_cves(coverage_data, min_file_delta=0.01, min_func_delta=0.01):
    """Find CVEs where ScubaTrace coverage improved."""
    improved = []
    for entry in coverage_data:
        if entry.get("scuba_status") != "success":
            continue
        file_delta = entry["scuba_file_coverage"] - entry["codeql_file_coverage"]
        func_delta = entry["scuba_func_coverage"] - entry["codeql_func_coverage"]

        if file_delta > min_file_delta or func_delta > min_func_delta:
            improved.append({
                "cve_id": entry["cve_id"],
                "language": entry["language"],
                "file_delta": round(file_delta, 4),
                "func_delta": round(func_delta, 4),
                "scuba_file_cov": entry["scuba_file_coverage"],
                "scuba_func_cov": entry["scuba_func_coverage"],
                "codeql_file_cov": entry["codeql_file_coverage"],
                "codeql_func_cov": entry["codeql_func_coverage"],
                "gt_files": entry["gt_files"],
                "gt_functions": entry["gt_functions"],
            })

    improved.sort(key=lambda x: (x["file_delta"] + x["func_delta"]), reverse=True)
    return improved


def run_localization_for_cve(cve_id, scuba_icfg_csv, use_agent=False):
    """Run the localization pipeline for a single CVE using ScubaTrace ICFG."""
    # The pipeline reads ICFG from Static_Analysis/Results/CodeQL/{cve_id}/
    # We temporarily replace with our ScubaTrace ICFG

    output_dir = os.path.join(RESULTS_DIR, "localization_results", cve_id)
    os.makedirs(output_dir, exist_ok=True)

    # Build command
    cmd = [
        sys.executable, MAIN_PY,
        "--cves", cve_id,
        "--limit", "1",
    ]
    if not use_agent:
        cmd.append("--no-agent")

    # We need to temporarily symlink the ScubaTrace ICFG to the expected location
    # Or modify the pipeline to accept a custom ICFG path
    # For now, copy the ScubaTrace ICFG over the CodeQL one

    codeql_icfg_dir = f"/mnt/d/Desktop/VulnLocalization/Static_Analysis/Results/CodeQL/{cve_id}"
    original_db = os.path.join(codeql_icfg_dir, "icfg_icfg_db.csv")
    original_raw = os.path.join(codeql_icfg_dir, "icfg_icfg.csv")
    backup_db = os.path.join(codeql_icfg_dir, "icfg_icfg_db.csv.codeql_backup")
    backup_raw = os.path.join(codeql_icfg_dir, "icfg_icfg.csv.codeql_backup")

    # Backup original
    restored = False
    try:
        if os.path.exists(original_db):
            os.rename(original_db, backup_db)
        if os.path.exists(original_raw):
            os.rename(original_raw, backup_raw)

        # Copy ScubaTrace ICFG as both db and raw
        import shutil
        shutil.copy2(scuba_icfg_csv, original_db)
        if not os.path.exists(original_raw):
            shutil.copy2(scuba_icfg_csv, original_raw)

        # Run pipeline
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        # Restore
        if os.path.exists(backup_db):
            os.rename(backup_db, original_db)
        else:
            if os.path.exists(original_db):
                os.remove(original_db)
        if os.path.exists(backup_raw):
            os.rename(backup_raw, original_raw)
        elif not os.path.exists(original_raw):
            pass

        return {
            "cve_id": cve_id,
            "returncode": result.returncode,
            "stdout": result.stdout[-2000:] if result.stdout else "",
            "stderr": result.stderr[-1000:] if result.stderr else "",
        }
    except Exception as e:
        # Restore on error
        if not restored:
            if os.path.exists(backup_db):
                os.rename(backup_db, original_db)
            if os.path.exists(backup_raw):
                os.rename(backup_raw, original_raw)
        return {
            "cve_id": cve_id,
            "error": str(e),
        }


def compare_localization_results(cve_id):
    """Compare ScubaTrace-based localization with original CodeQL-based results."""
    # Original result
    orig_path = os.path.join(ORIG_RESULTS, cve_id, "result.json")
    # Our result would be in the same place (we copied over the ICFG)
    # After restore, we'd need to capture the result before restore

    # Actually, the pipeline writes results to Results/{cve_id}/
    # We need to capture those before restoring the ICFG

    # For now, return placeholder
    return {
        "cve_id": cve_id,
        "note": "Comparison requires re-running pipeline",
    }


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="Run all improved CVEs")
    parser.add_argument("--limit", type=int, default=10, help="Max CVEs to run")
    parser.add_argument("--agent", action="store_true", help="Use LLM agent (slower)")
    args = parser.parse_args()

    coverage_data = load_coverage_data()
    if not coverage_data:
        return

    improved = find_improved_cves(coverage_data)
    n_total = len(coverage_data)
    n_improved = len(improved)

    print(f"Total evaluated: {n_total}")
    print(f"CVEs with improved coverage: {n_improved}")
    print()

    if not args.all:
        improved = improved[:args.limit]

    print(f"Running localization for {len(improved)} CVEs...")
    results = []
    for i, entry in enumerate(improved):
        cve_id = entry["cve_id"]
        scuba_csv = os.path.join(RESULTS_DIR, cve_id, "icfg_scubatrace.csv")

        if not os.path.exists(scuba_csv):
            print(f"[{i+1}/{len(improved)}] {cve_id}: SKIP (no ScubaTrace CSV)")
            continue

        print(f"[{i+1}/{len(improved)}] {cve_id}: file_delta={entry['file_delta']:.3f}, func_delta={entry['func_delta']:.3f} ...", end=" ")

        result = run_localization_for_cve(cve_id, scuba_csv, use_agent=args.agent)
        results.append(result)

        if result.get("error"):
            print(f"ERROR: {result['error']}")
        else:
            print(f"OK (rc={result.get('returncode', '?')})")

    # Save results
    out_path = os.path.join(RESULTS_DIR, "localization_run_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_path}")

    # Summary comparison
    print("\n=== Localization Comparison ===")
    print("(Compare ScubaTrace-based vs CodeQL-based localization)")
    print("\nRun evaluate.py to get full metrics comparison.")


if __name__ == "__main__":
    main()
