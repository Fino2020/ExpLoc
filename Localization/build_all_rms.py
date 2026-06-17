"""
Batch RMS Builder — pre-build one per-CVE Repo Memory Store for the manifest.

Each CVE gets its own SQLite DB containing only commits, hotspots, and issues
from BEFORE that CVE's earliest issue date (anti-leakage).

Usage:
  python3 build_all_rms.py                  # build all 886 DBs
  python3 build_all_rms.py --workers 8      # parallel 8 threads
  python3 build_all_rms.py --dry-run        # preview
  python3 build_all_rms.py --limit 10       # test first 10
  python3 build_all_rms.py --cves CVE-2015-1862,CVE-2016-1234
  python3 build_all_rms.py --window-days 365  # 1-year window
  python3 build_all_rms.py --no-clone       # skip re-clone on empty
  python3 build_all_rms.py --force          # rebuild existing
"""

import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

_LOC_DIR = os.path.dirname(os.path.abspath(__file__))
if _LOC_DIR not in sys.path:
    sys.path.insert(0, _LOC_DIR)

from shared.config import MANIFEST_PATH, REPO_BASE, RMS_DB_DIR, HISTORY_DIR

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_manifest(path: str = MANIFEST_PATH) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _get_earliest_issue_date(entry: dict) -> str:
    earliest = ""
    for issue in entry.get("issue_list", []):
        date = issue.get("created_at", "")
        if date and (not earliest or date < earliest):
            earliest = date
    return earliest


def db_path_for(owner: str, project: str, cve_id: str) -> str:
    safe = f"{owner}___{project}___{cve_id}"
    return os.path.join(RMS_DB_DIR, f"{safe}.db")


# ---------------------------------------------------------------------------
# Build one CVE
# ---------------------------------------------------------------------------

def build_one(entry: dict, force: bool = False, no_clone: bool = False,
              window_days: int = 730, skip_linker: bool = False) -> dict:
    """Build per-CVE RMS with date filtering. Returns status dict."""
    cve_id = entry["cve_id"]
    owner = entry.get("owner", "")
    project = entry.get("project", "")
    db_path = db_path_for(owner, project, cve_id)
    repo_path = entry.get("repo_path") or os.path.join(REPO_BASE, f"{owner}_{project}")

    result = {
        "cve_id": cve_id,
        "repo": f"{owner}/{project}",
        "db_path": db_path,
        "status": "unknown",
        "elapsed": 0,
        "error": "",
        "fallback": "none",
        "before_date": "",
    }

    if os.path.exists(db_path) and not force:
        result["status"] = "skip"
        return result

    t0 = time.time()

    try:
        from step1_locator.memory_store import build_rms
        from step1_locator.issue_linker import link_issues

        before_date = _get_earliest_issue_date(entry)
        if not before_date and window_days:
            pub = entry.get("published_date", "")
            if pub:
                from datetime import timedelta
                dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
                before_date = (dt + timedelta(days=window_days)).isoformat()

        result["before_date"] = before_date
        os.makedirs(RMS_DB_DIR, exist_ok=True)

        fallback = "none"
        use_repo_path = repo_path
        if not before_date:
            fallback = "no_date_available"

        repo_exists = os.path.isdir(os.path.join(use_repo_path, ".git"))

        if before_date and repo_exists:
            try:
                count_out = subprocess.run(
                    ["git", "-C", use_repo_path, "rev-list", "--all", "--count",
                     f"--before={before_date}"],
                    capture_output=True, text=True, timeout=60,
                )
                num_before = int(count_out.stdout.strip() or "0")
            except (ValueError, subprocess.TimeoutExpired):
                # Timeout or unparseable output — assume repo has commits
                num_before = 1

            if num_before == 0:
                if not no_clone:
                    print(f"    0 commits before {before_date[:10]}, re-cloning...")
                    import uuid
                    tmp_dir = repo_path + ".tmp." + uuid.uuid4().hex[:8]
                    clone_url = (f"https://{GITHUB_TOKEN}@github.com/"
                                f"{owner}/{project}.git")
                    try:
                        if os.path.exists(tmp_dir):
                            shutil.rmtree(tmp_dir, ignore_errors=True)
                        clone_proc = subprocess.run(
                            ["git", "clone", clone_url, tmp_dir],
                            capture_output=True, text=True, timeout=600,
                        )
                        if clone_proc.returncode == 0:
                            try:
                                count2 = subprocess.run(
                                    ["git", "-C", tmp_dir, "rev-list", "--all", "--count",
                                     f"--before={before_date}"],
                                    capture_output=True, text=True, timeout=60,
                                )
                                num_before = int(count2.stdout.strip() or "0")
                            except (ValueError, subprocess.TimeoutExpired):
                                num_before = 1
                            if num_before > 0:
                                if os.path.exists(repo_path):
                                    old_dir = repo_path + ".old." + uuid.uuid4().hex[:8]
                                    os.rename(repo_path, old_dir)
                                    shutil.move(tmp_dir, repo_path)
                                    shutil.rmtree(old_dir, ignore_errors=True)
                                else:
                                    shutil.move(tmp_dir, repo_path)
                                use_repo_path = repo_path
                                print(f"    Re-clone OK: {num_before} commits before date")
                            else:
                                print(f"    Re-clone still 0 commits, using fallback")
                                fallback = "date_unavailable"
                        else:
                            print(f"    Clone failed: {clone_proc.stderr[:100]}")
                            fallback = "clone_failed"
                    finally:
                        if os.path.exists(tmp_dir) and tmp_dir != repo_path:
                            shutil.rmtree(tmp_dir, ignore_errors=True)
                else:
                    fallback = "date_unavailable"
        elif before_date and not repo_exists:
            # Repo missing — clone fresh, then filter
            if not no_clone:
                print(f"    Repo missing, cloning ...")
                import uuid
                clone_url = (f"https://{GITHUB_TOKEN}@github.com/"
                            f"{owner}/{project}.git")
                tmp_dir = repo_path + ".tmp." + uuid.uuid4().hex[:8]
                try:
                    clone_proc = subprocess.run(
                        ["git", "clone", clone_url, tmp_dir],
                        capture_output=True, text=True, timeout=600,
                    )
                    if clone_proc.returncode == 0:
                        shutil.move(tmp_dir, repo_path)
                        use_repo_path = repo_path
                        print(f"    Fresh clone OK")
                    else:
                        print(f"    Clone failed: {clone_proc.stderr[:100]}")
                        fallback = "clone_failed"
                finally:
                    if os.path.exists(tmp_dir) and tmp_dir != repo_path:
                        shutil.rmtree(tmp_dir, ignore_errors=True)
            else:
                fallback = "date_unavailable"

        if fallback == "none":
            build_rms(repo_path=use_repo_path, output_db=db_path,
                      max_commits=500, top_hotspots=30,
                      before_date=before_date, fallback=fallback)
        else:
            build_rms(repo_path=use_repo_path, output_db=db_path,
                      max_commits=500, top_hotspots=30,
                      before_date="", fallback=fallback)

        if not skip_linker:
            link_issues(repo_path=use_repo_path, owner=owner, project=project,
                        db_path=db_path, before_date=before_date)

        result["fallback"] = fallback
        result["status"] = "ok"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)[:200]

    result["elapsed"] = round(time.time() - t0, 1)
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(manifest_path: str = MANIFEST_PATH, workers: int = 1,
        force: bool = False, dry_run: bool = False, limit: int = 0,
        no_clone: bool = False, window_days: int = 730,
        cve_filter: list = None, skip_linker: bool = False) -> dict:
    """Pre-build all per-CVE RMS databases for the manifest."""

    manifest = load_manifest(manifest_path)
    if cve_filter:
        cve_set = set(cve_filter)
        manifest = [e for e in manifest if e["cve_id"] in cve_set]

    print(f"Manifest: {len(manifest)} CVEs")

    if limit > 0:
        manifest = manifest[:limit]
        print(f"  Limited to {limit} CVEs")

    if dry_run:
        print("\nWould build:")
        for e in manifest:
            print(f"  {e['cve_id']} ({e.get('owner','')}/{e.get('project','')})")
        return {"total": len(manifest), "results": []}

    os.makedirs(RMS_DB_DIR, exist_ok=True)

    if not force:
        todo = []
        already = 0
        for e in manifest:
            dbp = db_path_for(e.get("owner", ""), e.get("project", ""), e["cve_id"])
            if os.path.exists(dbp):
                already += 1
            else:
                todo.append(e)
        print(f"  Already built: {already}")
        print(f"  To build: {len(todo)}")
    else:
        todo = manifest
        print(f"  Force rebuild: {len(todo)} CVEs")

    if not todo:
        print("Nothing to build.")
        return {"total": 0, "results": []}

    total_start = time.time()
    results = []

    if workers <= 1:
        for i, entry in enumerate(todo):
            cve_id = entry["cve_id"]
            print(f"\n[{i+1}/{len(todo)}] {cve_id} ...", end=" ", flush=True)
            r = build_one(entry, force=force, no_clone=no_clone,
                         window_days=window_days, skip_linker=skip_linker)
            results.append(r)
            icon = ("OK" if r["status"] == "ok"
                    else "SKIP" if r["status"] == "skip" else "FAIL")
            fb = f" [{r.get('fallback','')}]" if r.get("fallback") != "none" else ""
            print(f"{icon} ({r['elapsed']:.1f}s){fb}"
                  + (f" — {r['error']}" if r.get("error") else ""))

            if (i + 1) % 10 == 0 and i > 0:
                elapsed = time.time() - total_start
                rate = (i + 1) / elapsed
                eta = (len(todo) - i - 1) / rate if rate > 0 else 0
                print(f"  — Elapsed: {elapsed:.0f}s | Rate: {rate:.2f}/s | ETA: {eta:.0f}s")
    else:
        print(f"\nBuilding {len(todo)} CVEs with {workers} workers ...")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(build_one, e, force, no_clone, window_days, skip_linker): e
                for e in todo
            }
            for i, f in enumerate(as_completed(futures)):
                entry = futures[f]
                r = f.result()
                results.append(r)
                cve_id = entry["cve_id"]
                icon = ("OK" if r["status"] == "ok"
                        else "SKIP" if r["status"] == "skip" else "FAIL")
                fb = f" [{r.get('fallback','')}]" if r.get("fallback") != "none" else ""
                print(f"[{i+1}/{len(todo)}] {cve_id}: {icon} ({r['elapsed']:.1f}s){fb}"
                      + (f" — {r['error']}" if r.get("error") else ""))

    total_elapsed = time.time() - total_start

    ok_count = sum(1 for r in results if r["status"] == "ok")
    err_count = sum(1 for r in results if r["status"] == "error")
    skip_count = sum(1 for r in results if r["status"] == "skip")
    fallback_count = sum(1 for r in results if r.get("fallback", "none") not in ("none", ""))

    summary = {
        "total_candidates": len(todo),
        "built": ok_count,
        "errors": err_count,
        "skipped_existing": skip_count,
        "fallback_count": fallback_count,
        "total_elapsed_seconds": round(total_elapsed, 1),
        "avg_seconds_per_cve": round(total_elapsed / max(len(todo), 1), 1),
        "timestamp": datetime.now().isoformat(),
    }

    summary_path = os.path.join(RMS_DB_DIR, "build_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    detail_path = os.path.join(RMS_DB_DIR, "build_results.json")
    with open(detail_path, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "results": results}, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"DONE: {ok_count} built, {err_count} errors, {skip_count} skipped, "
          f"{fallback_count} fallbacks")
    print(f"Total time: {total_elapsed:.1f}s ({total_elapsed/60:.1f}m)")
    print(f"Average: {summary['avg_seconds_per_cve']:.1f}s per CVE")
    print(f"Summary: {summary_path}")
    print(f"{'='*60}")

    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Batch pre-build per-CVE RMS databases for the manifest"
    )
    parser.add_argument("--manifest", type=str, default=MANIFEST_PATH,
                        help="Path to manifest JSON")
    parser.add_argument("--workers", type=int, default=1,
                        help="Parallel workers (default: 1)")
    parser.add_argument("--force", action="store_true",
                        help="Rebuild all, even existing DBs")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview without building")
    parser.add_argument("--limit", type=int, default=0,
                        help="Build first N CVEs only")
    parser.add_argument("--cves", type=str, default="",
                        help="Comma-separated CVE IDs")
    parser.add_argument("--no-clone", action="store_true",
                        help="Skip re-clone on 0 commits (use fallback)")
    parser.add_argument("--window-days", type=int, default=730,
                        help="Days after published_date as before_date if no issue dates")
    parser.add_argument("--skip-linker", action="store_true",
                        help="Skip issue_linker (faster, build only RMS core)")

    args = parser.parse_args()

    cve_filter = None
    if args.cves:
        cve_filter = [c.strip() for c in args.cves.split(",") if c.strip()]

    run(
        manifest_path=args.manifest,
        workers=args.workers,
        force=args.force,
        dry_run=args.dry_run,
        limit=args.limit,
        no_clone=args.no_clone,
        window_days=args.window_days,
        cve_filter=cve_filter,
        skip_linker=args.skip_linker,
    )
