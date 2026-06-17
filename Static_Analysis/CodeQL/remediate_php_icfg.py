"""
Remediation script: Re-extract ICFGs for PHP CVEs that have JS-only ICFGs.

Reads the audit results to find all CVEs with 'wrong_lang_php_js' category,
then re-runs multi-language extraction (tree-sitter PHP + existing JS) for each.

Usage:
  python3 remediate_php_icfg.py [--limit N] [--cves CVE1,CVE2,...]
"""

import csv
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from codeql_auto_analyzer import analyze_multilang_project

REPO_BASE = "/mnt/e/Desktop/Localization_Repo/Localization_Repo"
AUDIT_FILE = "/mnt/d/Desktop/VulnLocalization/Results/Localization/main/audit/audit_per_cve.json"
OUTPUT_DIR = Path(__file__).resolve().parent / "Results"


def find_repo(owner: str, project: str) -> str:
    """Find the repository path for a given owner/project."""
    for d in os.listdir(REPO_BASE):
        candidate = os.path.join(REPO_BASE, d, owner, project)
        if os.path.isdir(os.path.join(candidate, ".git")):
            return candidate
    return ""


def _find_php_js_only_cves(limit: int = 0, cve_filter: set = None):
    """Find PHP CVEs whose ICFG contains zero .php files (JS-only or HTML-only).

    Does NOT require the audit file — scans ICFG CSVs directly.
    """
    import csv
    dataset_path = "/mnt/d/Desktop/VulnLocalization/Dataset/dataset_with_changed_files.json"

    with open(dataset_path) as f:
        dataset = json.load(f)

    results = []
    for cve in dataset:
        cid = cve["cve_id"]
        if cve_filter and cid not in cve_filter:
            continue

        commit_list = cve.get("commit_list", [])
        if not commit_list:
            continue
        repo_str = cve["issue_list"][0]["repo"]
        owner, project = repo_str.split("/", 1)

        # Check ICFG exists
        icfg_csv = None
        icfg_dir = OUTPUT_DIR / cid
        for fname in ["icfg_icfg_db.csv", "icfg_icfg.csv"]:
            fp = icfg_dir / fname
            if fp.exists():
                icfg_csv = fp
                break
        if not icfg_csv:
            continue

        # Quick scan: does ICFG contain ANY .php file?
        has_php = False
        has_source = False
        try:
            with open(icfg_csv) as fh:
                reader = csv.reader(fh)
                next(reader)
                for i, row in enumerate(reader):
                    if i > 200:
                        break
                    file_col = row[0].lower()
                    if '.php' in file_col or '.phtml' in file_col:
                        has_php = True
                        break
                    if any(ext in file_col for ext in ['.js', '.html', '.htm', '.c', '.cpp',
                           '.py', '.rb', '.go', '.rs', '.java']):
                        has_source = True
        except Exception:
            continue

        # PHP project but ICFG has no PHP → needs remediation
        if not has_php and has_source:
            repo_path = find_repo(owner, project)
            if not repo_path:
                continue
            # Verify the repo actually has PHP files (not just C/C++/Python project)
            repo_has_php = False
            try:
                for root, dirs, files in os.walk(repo_path):
                    dirs[:] = [x for x in dirs if x not in ('.git', 'node_modules', 'vendor')][:5]
                    if any(f.endswith('.php') or f.endswith('.phtml') for f in files):
                        repo_has_php = True
                        break
            except Exception:
                pass
            if repo_has_php:
                results.append({
                    "cve_id": cid, "owner": owner, "project": project,
                    "repo_path": repo_path, "icfg_edges": i if has_source else 0,
                })

        if limit and len(results) >= limit:
            break

    return results


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Remediate PHP CVEs with JS-only ICFGs using multi-language extraction"
    )
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit to first N CVEs (0=all)")
    parser.add_argument("--cves", type=str, default="",
                        help="Comma-separated CVE filter")
    args = parser.parse_args()

    cve_filter = set(c.strip() for c in args.cves.split(",") if c.strip()) if args.cves else None

    # Auto-detect PHP CVEs with JS-only ICFGs (no audit file needed)
    targets = _find_php_js_only_cves(
        limit=args.limit if not cve_filter else 0,
        cve_filter=cve_filter
    )

    if args.limit:
        targets = targets[:args.limit]

    total = len(targets)
    if total == 0:
        print("No PHP CVEs with wrong_lang_php_js found in audit data.")
        print("The audit file may be incomplete. Run the full audit first:")
        print("  cd /mnt/d/Desktop/VulnLocalization/Explainable_Localization")
        print("  PYTHONUNBUFFERED=1 python3 audit_icfg_gt.py")
        return

    print(f"Remediating {total} PHP CVEs with multi-language extraction...")
    print(f"{'='*60}")

    success = 0
    fail = 0
    start_time = time.time()

    for idx, d in enumerate(targets, 1):
        cid = d["cve_id"]
        owner = d["owner"]
        project = d["project"]
        repo_path = d.get("repo_path") or find_repo(owner, project)

        if not repo_path:
            print(f"  [{idx}/{total}] {cid}: SKIP (no repo)")
            fail += 1
            continue

        output_dir = OUTPUT_DIR / cid
        output_dir.mkdir(parents=True, exist_ok=True)

        print(f"  [{idx}/{total}] {cid} ({owner}/{project})...", end=" ", flush=True)

        try:
            result, error = analyze_multilang_project(
                Path(repo_path), output_dir, project_label="icfg"
            )
            if error:
                print(f"FAIL: {error[:100]}")
                fail += 1
            else:
                # Copy to expected pipeline name
                db_csv = output_dir / "icfg_icfg_db.csv"
                if result != db_csv:
                    import shutil
                    shutil.copy(str(result), str(db_csv))

                # Verify PHP files are now present
                php_count = 0
                total_count = 0
                with open(db_csv) as f:
                    reader = csv.reader(f)
                    next(reader)
                    for row in reader:
                        total_count += 1
                        if '.php' in row[0].lower():
                            php_count += 1

                elapsed = time.time() - start_time
                eta = (elapsed / idx) * (total - idx)
                print(f"OK ({total_count} edges, {php_count} PHP edges) "
                      f"[{elapsed:.0f}s elapsed, ETA {eta:.0f}s]")
                success += 1

        except Exception as e:
            print(f"FAIL: {type(e).__name__}: {e}")
            fail += 1

    elapsed = time.time() - start_time
    avg = elapsed / max(total, 1)
    print(f"\n{'='*60}")
    print(f"Remediation complete: {success} success, {fail} fail "
          f"({elapsed:.0f}s, {avg:.1f}s per CVE)")


if __name__ == "__main__":
    main()
