"""
AutoCodeRover baseline — main entry for vulnerability localization.
Multi-process support for parallel CVE execution.

Usage:
  python3 -m acr_baseline.run_acr --limit 10 --workers 4
  python3 -m acr_baseline.run_acr --cves CVE-2015-1862,CVE-2016-1234
  python3 -m acr_baseline.run_acr --limit 0 --workers 8  # all CVEs
"""

import json
import os
import sys
import traceback
from argparse import ArgumentParser
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Optional

_LOC_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT_DIR = os.path.dirname(_LOC_DIR)
if _PARENT_DIR not in sys.path:
    sys.path.insert(0, _PARENT_DIR)

from shared.config import MANIFEST_PATH, REPO_BASE, OUTPUT_DIR


def load_dataset(path: str = MANIFEST_PATH) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def normalize_entry(entry: dict) -> dict:
    """Resolve owner/project/repo_path. Returns modified copy."""
    entry = dict(entry)  # shallow copy
    if not entry.get("owner") or not entry.get("project"):
        for issue in entry.get("issue_list", []):
            repo = issue.get("repo", "")
            if "/" in repo:
                parts = repo.split("/")
                entry.setdefault("owner", parts[0])
                entry.setdefault("project", parts[1])
                break

    if not entry.get("repo_path") and entry.get("owner") and entry.get("project"):
        owner, project = entry["owner"], entry["project"]
        cve_id = entry["cve_id"]
        path_cve = os.path.join(REPO_BASE, cve_id, owner, project)
        path_flat = os.path.join(REPO_BASE, f"{owner}_{project}")
        if os.path.isdir(path_cve):
            entry["repo_path"] = path_cve
        elif os.path.isdir(path_flat):
            entry["repo_path"] = path_flat
        else:
            entry["repo_path"] = path_cve
    return entry


def build_issue_text(entry: dict) -> str:
    """Build issue report text from CVE description + issue_list issues."""
    parts = []
    desc = entry.get("description", "")
    if desc:
        parts.append(f"# Vulnerability Report: {entry['cve_id']}")
        parts.append(f"Severity: {entry.get('severity', 'N/A')} (CVSS: {entry.get('baseScore', 'N/A')})")
        parts.append(f"CWE: {', '.join(entry.get('cwe_id', []))}")
        parts.append("")
        parts.append("## Description")
        parts.append(desc)
        parts.append("")

    issues = entry.get("issue_list", [])
    if issues:
        parts.append("## Related Issues")
        for i, issue in enumerate(issues[:3]):
            title = issue.get("title", "")
            body = issue.get("body", "")
            parts.append(f"### Issue #{i + 1}: {title}")
            if len(body) > 3000:
                body = body[:3000] + "\n... [truncated]"
            parts.append(body)
            parts.append("")
    return "\n".join(parts)


def _worker_init():
    """Per-worker init: ensure acr_baseline is importable."""
    _loc = os.path.dirname(os.path.abspath(__file__))
    _par = os.path.dirname(_loc)
    if _par not in sys.path:
        sys.path.insert(0, _par)


def run_one_cve_worker(args: tuple) -> dict:
    """Worker function — runs in subprocess. Receives (entry, output_dir, search_rounds)."""
    entry, output_dir, search_rounds = args
    cve_id = entry["cve_id"]
    repo_path = entry.get("repo_path", "")

    # Lazy import inside worker
    from acr_baseline.search_manage import SearchManager

    result = {
        "cve_id": cve_id,
        "ok": False,
        "vulnerable_files": [],
        "vulnerable_functions": [],
        "bug_locations_count": 0,
        "search_rounds_used": 0,
    }

    if not repo_path or not os.path.isdir(repo_path):
        result["error"] = f"repo not found: {repo_path}"
        return result

    issue_text = build_issue_text(entry)
    cve_output_dir = os.path.join(output_dir, cve_id)
    os.makedirs(cve_output_dir, exist_ok=True)

    try:
        manager = SearchManager(repo_path, cve_output_dir)
        bug_locs, msg_thread, ranked_files = manager.search_iterative(
            issue_text, max_rounds=search_rounds,
        )
        result["search_rounds_used"] = len(manager.tool_call_layers)
    except Exception as e:
        result["error"] = f"search failed: {e}"
        return result

    result["ok"] = True
    result["bug_locations_count"] = len(bug_locs)

    seen_files = set()
    for i, loc in enumerate(bug_locs):
        score = 1.0 - (i * 0.02)
        if loc.rel_file_path not in seen_files:
            seen_files.add(loc.rel_file_path)
            result["vulnerable_files"].append({
                "file": loc.rel_file_path,
                "score": max(0.1, round(score, 4)),
            })
        if loc.method_name:
            result["vulnerable_functions"].append({
                "function": loc.method_name,
                "file": loc.rel_file_path,
                "score": max(0.1, round(score, 4)),
            })

    if not result["vulnerable_files"] and ranked_files:
        for i, fpath in enumerate(ranked_files):
            result["vulnerable_files"].append({
                "file": fpath,
                "score": max(0.1, round(1.0 - (i * 0.05), 4)),
            })

    # Save result
    output = {
        "cve_id": cve_id,
        "method": "acr_baseline",
        "vulnerable_files": result["vulnerable_files"],
        "vulnerable_functions": result["vulnerable_functions"],
        "bug_locations_count": result["bug_locations_count"],
        "search_rounds_used": result["search_rounds_used"],
        "module": entry.get("project", ""),
    }
    result_path = os.path.join(cve_output_dir, "result.json")
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    return result


def run_acr(
    cves: Optional[list[str]] = None,
    limit: int = 10,
    skip: int = 0,
    search_rounds: int = 10,
    workers: int = 4,
    resume: bool = False,
) -> None:
    """Run ACR baseline with parallel workers."""
    dataset = load_dataset()
    output_dir = os.path.join(os.path.dirname(OUTPUT_DIR), "ACR")
    os.makedirs(output_dir, exist_ok=True)

    if cves:
        cve_set = set(cves)
        entries = [e for e in dataset if e["cve_id"] in cve_set]
    else:
        entries = dataset[skip:]
        if limit > 0:
            entries = entries[:limit]

    # Normalize all entries upfront (before fork)
    entries = [normalize_entry(e) for e in entries]

    # Resume: skip CVEs with existing result.json
    if resume:
        skipped = 0
        remaining = []
        for e in entries:
            cve_dir = os.path.join(output_dir, e["cve_id"])
            if os.path.exists(os.path.join(cve_dir, "result.json")):
                skipped += 1
            else:
                remaining.append(e)
        if skipped:
            print(f"Resume: skipping {skipped} already-completed CVEs.")
        entries = remaining

    print(f"Processing {len(entries)} CVEs with {workers} workers.")
    print(f"Output: {output_dir}")

    work_items = [(e, output_dir, search_rounds) for e in entries]
    success = 0
    completed = 0

    if workers <= 1:
        for item in work_items:
            cve_id = item[0]["cve_id"]
            print(f"\n[{completed + 1}/{len(entries)}] {cve_id}")
            r = run_one_cve_worker(item)
            if r["ok"]:
                success += 1
            print(f"  files={len(r['vulnerable_files'])} funcs={len(r['vulnerable_functions'])} err={r.get('error', '')}")
            completed += 1
    else:
        with ProcessPoolExecutor(
            max_workers=workers,
            initializer=_worker_init,
        ) as executor:
            futures = {executor.submit(run_one_cve_worker, item): item for item in work_items}
            for future in as_completed(futures):
                item = futures[future]
                cve_id = item[0]["cve_id"]
                try:
                    r = future.result()
                    if r["ok"]:
                        success += 1
                    err = r.get("error", "")
                    print(f"[{completed + 1}/{len(entries)}] {cve_id}: "
                          f"files={len(r['vulnerable_files'])} funcs={len(r['vulnerable_functions'])} "
                          f"err={err}")
                except Exception as e:
                    print(f"[{completed + 1}/{len(entries)}] {cve_id}: EXCEPTION {e}")
                completed += 1

    print(f"\nDone. Success: {success}/{len(entries)}")
    print(f"Results: {output_dir}")


if __name__ == "__main__":
    parser = ArgumentParser(description="ACR Baseline for Vulnerability Localization")
    parser.add_argument("--cves", type=str, help="Comma-separated CVE IDs")
    parser.add_argument("--limit", type=int, default=10, help="Max CVEs (0=all)")
    parser.add_argument("--skip", type=int, default=0, help="Skip first N CVEs")
    parser.add_argument("--rounds", type=int, default=10, help="Max search rounds per CVE")
    parser.add_argument("--workers", type=int, default=4, help="Number of parallel workers")
    parser.add_argument("--resume", action="store_true", default=False,
                        help="Skip CVEs that already have result.json")

    args = parser.parse_args()
    cve_list = args.cves.split(",") if args.cves else None

    run_acr(
        cves=cve_list,
        limit=args.limit,
        skip=args.skip,
        search_rounds=args.rounds,
        workers=args.workers,
        resume=args.resume,
    )
