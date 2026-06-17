"""
RepoMem — Memory-Augmented Vulnerability Localization.

Reproduces the RepoMem paper (ICLR 2026): per-project Repo Memory Store
built from git commit history, with BM25-indexed episodic memory and
LLM-generated semantic memory.

Usage:
  # Step 1: Build all per-project RMS databases
  python3 run.py --build-all

  # Step 2: Run localization
  python3 run.py                      # First 10 CVEs
  python3 run.py --limit 0            # All CVEs (with RMS available)
  python3 run.py --cves CVE-2024-XXXX,CVE-2024-YYYY
  python3 run.py --skip 5 --limit 10

  # Step 3: Evaluate
  python3 evaluate4RepoMem.py results/
"""

import io
import json
import os
import sys
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Tuple

_REPO_DIR = os.path.dirname(os.path.abspath(__file__))
if _REPO_DIR not in sys.path:
    sys.path.insert(0, _REPO_DIR)

from mem_construction.build_rms import build_rms
from localizer import RepoMemLocalizer


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(_REPO_DIR)
MANIFEST_PATH = os.path.join(BASE_DIR, "Dataset", "dataset_with_changed_files_filter.json")
REPO_BASE = os.getenv("REPO_BASE", "/mnt/e/Desktop/Localization_Repo/Localization_Repo")
RMS_DB_DIR = os.path.join(_REPO_DIR, "rms_db")
DEFAULT_OUTPUT_DIR = os.path.join(_REPO_DIR, "results")


# ---------------------------------------------------------------------------
# Manifest helpers
# ---------------------------------------------------------------------------

def load_manifest(path: str = MANIFEST_PATH) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _find_repo_path(owner: str, project: str, cve_id: str = "") -> Optional[str]:
    """Find the local git repo path for an owner/project pair.

    Tries: REPO_BASE/{cve_id}/{owner}/{project}/  (CVE-ID based)
           REPO_BASE/{owner}_{project}/            (flat format)
    """
    if cve_id:
        candidate = os.path.join(REPO_BASE, cve_id, owner, project)
        if os.path.isdir(os.path.join(candidate, ".git")):
            return candidate
    candidate = os.path.join(REPO_BASE, f"{owner}_{project}")
    if os.path.isdir(os.path.join(candidate, ".git")):
        return candidate
    return None


def _get_rms_db_path(owner: str, project: str) -> str:
    """Get the RMS DB path for a repo."""
    safe_name = f"{owner}___{project}"
    return os.path.join(RMS_DB_DIR, f"{safe_name}.db")


def _normalize_entry(entry: dict) -> dict:
    """Fill missing owner/project from issue_list repo field."""
    if not entry.get("owner") or not entry.get("project"):
        for issue in entry.get("issue_list", []):
            repo = issue.get("repo", "")
            if "/" in repo:
                parts = repo.split("/")
                entry["owner"] = parts[0]
                entry["project"] = parts[1]
                break
    return entry


def _get_earliest_issue_date(entry: dict) -> str:
    """Extract the earliest issue created_at date from a manifest entry."""
    earliest = ""
    for issue in entry.get("issue_list", []):
        date = issue.get("created_at", "")
        if date and (not earliest or date < earliest):
            earliest = date
    return earliest


def build_issue_description(entry: dict) -> Tuple[str, str, str]:
    """Return (title, body, combined_description) from a manifest entry."""
    title = ""
    body = ""
    for issue in entry.get("issue_list", []):
        if not title:
            title = issue.get("title", "")
        if not body:
            body = issue.get("body", "") or ""
        # Append first comment
        for event in issue.get("events", []):
            event_body = event.get("body", "")
            if event_body and len(body) < 2000:
                body += f"\n[Comment]: {event_body[:500]}"
    return title, body, f"Title: {title}\n\nDescription:\n{body}"


# ---------------------------------------------------------------------------
# Build all RMS databases
# ---------------------------------------------------------------------------

def build_all_rms(
    max_commits: int = 500, top_hotspots: int = 30, no_summaries: bool = False
) -> int:
    """Build per-project RMS databases for all available repos.

    Returns count of successfully built databases.
    """
    manifest = load_manifest()

    # Collect unique repos
    repos: Dict[Tuple[str, str], str] = {}
    for entry in manifest:
        entry = _normalize_entry(entry)
        owner, proj = entry["owner"], entry["project"]
        key = (owner, proj)
        if key not in repos:
            repo_path = _find_repo_path(owner, proj, entry.get("cve_id", ""))
            if repo_path:
                repos[key] = repo_path

    print(f"Found {len(repos)} repos with .git available")

    os.makedirs(RMS_DB_DIR, exist_ok=True)

    built = 0
    for i, ((owner, proj), repo_path) in enumerate(sorted(repos.items()), 1):
        db_path = _get_rms_db_path(owner, proj)

        # Skip if already built
        if os.path.exists(db_path):
            # Check version
            import sqlite3
            try:
                conn = sqlite3.connect(db_path)
                ver = conn.execute(
                    "SELECT value FROM meta WHERE key='version'"
                ).fetchone()
                conn.close()
                if ver and ver[0] == "2.0":
                    print(f"[{i}/{len(repos)}] SKIP {owner}/{proj} (already built)")
                    built += 1
                    continue
            except Exception:
                pass

        print(f"\n[{i}/{len(repos)}] Building {owner}/{proj} ...")
        try:
            build_rms(
                repo_path=repo_path,
                output_db=db_path,
                max_commits=max_commits,
                top_hotspots=top_hotspots,
                generate_summaries=not no_summaries,
            )
            built += 1
        except Exception as e:
            print(f"  FAILED: {e}")
            traceback.print_exc()

    print(f"\nBuilt {built}/{len(repos)} RMS databases")
    return built


# ---------------------------------------------------------------------------
# Single CVE localization
# ---------------------------------------------------------------------------

def run_single(localizer: RepoMemLocalizer, entry: dict) -> dict:
    """Run localization for a single CVE."""
    cve_id = entry["cve_id"]
    language = entry.get("language", "unknown")

    title, body, description = build_issue_description(entry)

    if not title and not body:
        return {
            "cve_id": cve_id,
            "error": "empty_issue",
            "vulnerable_files": [],
            "vulnerable_functions": [],
            "analysis_summary": "No issue data available",
        }

    before_date = _get_earliest_issue_date(entry)

    result = localizer.localize(
        cve_id=cve_id,
        issue_title=title,
        issue_body=body,
        language=language,
        before_date=before_date,
    )
    return result


# ---------------------------------------------------------------------------
# Worker function (module-level for ProcessPoolExecutor pickling)
# ---------------------------------------------------------------------------

def _process_single_cve(args: Tuple[dict, str, bool]) -> dict:
    """Process a single CVE — entrypoint for ProcessPoolExecutor.

    Args:
        args: (entry, output_dir, resume) tuple

    Returns: dict with cve_id, success, elapsed, n_files, n_funcs, error, log
    """
    entry, output_dir, resume = args
    entry = _normalize_entry(entry)
    cve_id = entry["cve_id"]
    owner = entry.get("owner", "")
    project = entry.get("project", "")
    language = entry.get("language", "?")

    log_buf = io.StringIO()

    def _log(msg: str):
        log_buf.write(msg + "\n")

    t0 = time.time()

    try:
        # Resume check
        if resume:
            result_path = os.path.join(output_dir, cve_id, "result.json")
            if os.path.exists(result_path):
                with open(result_path, "r") as f:
                    existing = json.load(f)
                if (not existing.get("error") and
                    len(existing.get("vulnerable_files", [])) > 0):
                    _log(f"SKIP (resume): already valid ({len(existing['vulnerable_files'])} files)")
                    return {
                        "cve_id": cve_id, "success": True, "skipped": True,
                        "elapsed": time.time() - t0, "n_files": 0, "n_funcs": 0,
                        "skip_reason": "resume", "log": log_buf.getvalue(),
                    }

        # Build issue description
        title, body, _ = build_issue_description(entry)
        if not title and not body:
            _log("SKIP: no issue data")
            cve_dir = os.path.join(output_dir, cve_id)
            os.makedirs(cve_dir, exist_ok=True)
            with open(os.path.join(cve_dir, "result.json"), "w", encoding="utf-8") as f:
                json.dump({
                    "cve_id": cve_id, "error": "empty_issue",
                    "vulnerable_files": [], "vulnerable_functions": [],
                }, f)
            return {
                "cve_id": cve_id, "success": True, "skipped": True,
                "elapsed": time.time() - t0, "n_files": 0, "n_funcs": 0,
                "skip_reason": "empty_issue", "log": log_buf.getvalue(),
            }

        # Create localizer
        db_path = _get_rms_db_path(owner, project)
        repo_path = _find_repo_path(owner, project, cve_id)

        localizer = None
        if os.path.exists(db_path):
            try:
                localizer = RepoMemLocalizer(rms_db_path=db_path)
                _log(f"Loaded RMS: {db_path}")
            except Exception as e:
                _log(f"Failed to load RMS: {e}")
        elif repo_path:
            try:
                localizer = RepoMemLocalizer(repo_path=repo_path)
                _log(f"Using direct git: {repo_path}")
            except Exception as e:
                _log(f"Failed to init direct git: {e}")

        if localizer is None:
            _log("SKIP: no RMS DB and no git repo")
            cve_dir = os.path.join(output_dir, cve_id)
            os.makedirs(cve_dir, exist_ok=True)
            with open(os.path.join(cve_dir, "result.json"), "w", encoding="utf-8") as f:
                json.dump({
                    "cve_id": cve_id, "error": "no_rms_db_and_no_git_repo",
                    "vulnerable_files": [], "vulnerable_functions": [],
                }, f)
            return {
                "cve_id": cve_id, "success": True, "skipped": True,
                "elapsed": time.time() - t0, "n_files": 0, "n_funcs": 0,
                "skip_reason": "no_repo", "log": log_buf.getvalue(),
            }

        before_date = _get_earliest_issue_date(entry)
        result = localizer.localize(
            cve_id=cve_id,
            issue_title=title,
            issue_body=body,
            language=language,
            before_date=before_date,
        )
        elapsed = time.time() - t0

        result["owner"] = owner
        result["project"] = project
        result["issue_title"] = (
            entry.get("issue_list", [{}])[0].get("title", "")
            if entry.get("issue_list") else ""
        )
        result["elapsed_seconds"] = round(elapsed, 1)

        # Save result
        cve_dir = os.path.join(output_dir, cve_id)
        os.makedirs(cve_dir, exist_ok=True)
        with open(os.path.join(cve_dir, "result.json"), "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        # Brief report
        report_lines = [
            f"CVE: {cve_id}  |  {owner}/{project}",
            f"Time: {datetime.now().isoformat()}  |  Elapsed: {elapsed:.1f}s",
            f"Language: {language}",
            "",
            f"--- Vulnerable Files ({len(result.get('vulnerable_files', []))}) ---",
        ]
        for vf in result.get("vulnerable_files", [])[:15]:
            report_lines.append(
                f"  [{vf.get('score', 0):.2f}] {vf.get('file', '?')}"
                f"  — {vf.get('reason', '')[:100]}"
            )
        report_lines.append("")
        report_lines.append(
            f"--- Vulnerable Functions ({len(result.get('vulnerable_functions', []))}) ---"
        )
        for vf in result.get("vulnerable_functions", [])[:15]:
            report_lines.append(
                f"  [{vf.get('score', 0):.2f}] {vf.get('function', '?')}"
                f" @ {vf.get('file', '?')}"
                f"  — {vf.get('reason', '')[:100]}"
            )
        report_lines.append("")
        report_lines.append("--- Analysis Summary ---")
        report_lines.append(result.get("analysis_summary", "N/A"))
        with open(os.path.join(cve_dir, "report.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))

        n_files = len(result.get("vulnerable_files", []))
        n_funcs = len(result.get("vulnerable_functions", []))
        _log(f"OK {elapsed:.1f}s: {n_files}f/{n_funcs}fn")

        return {
            "cve_id": cve_id, "success": True,
            "elapsed": elapsed, "n_files": n_files, "n_funcs": n_funcs,
            "confidence": result.get("confidence", ""),
            "log": log_buf.getvalue(),
        }

    except Exception as e:
        elapsed = time.time() - t0
        _log(f"FAIL: {e}")
        _log(traceback.format_exc())
        cve_dir = os.path.join(output_dir, cve_id)
        os.makedirs(cve_dir, exist_ok=True)
        with open(os.path.join(cve_dir, "result.json"), "w", encoding="utf-8") as f:
            json.dump({"cve_id": cve_id, "error": str(e)}, f)
        return {
            "cve_id": cve_id, "success": False,
            "elapsed": elapsed, "error": str(e),
            "n_files": 0, "n_funcs": 0,
            "log": log_buf.getvalue(),
        }


# ---------------------------------------------------------------------------
# Batch runner
# ---------------------------------------------------------------------------

def run_batch(
    manifest_path: str = MANIFEST_PATH,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    limit: int = 10,
    skip: int = 0,
    cve_list: Optional[List[str]] = None,
    resume: bool = False,
    workers: int = 1,
) -> str:
    """Run RepoMem localization on a batch of CVEs.

    Each CVE is routed to its per-project RMS database.
    CVEs without a local repo / RMS DB are skipped.

    Args:
        workers: number of parallel worker processes (default 1 = sequential)

    Returns output_dir path.
    """
    manifest = load_manifest(manifest_path)
    print(f"Loaded {len(manifest)} CVEs from manifest")

    # Filter CVEs
    if cve_list:
        cve_set = set(cve_list)
        manifest = [e for e in manifest if e["cve_id"] in cve_set]
        print(f"Filtered to {len(manifest)} specified CVEs")
    elif limit > 0:
        manifest = manifest[skip:skip + limit]
        print(f"Processing {len(manifest)} CVEs (skip={skip}, limit={limit})")
    else:
        manifest = manifest[skip:]
        print(f"Processing all {len(manifest)} CVEs (skip={skip})")

    if not manifest:
        print("No CVEs to process")
        return output_dir

    # Normalize entries first (before forking for multiprocessing)
    manifest = [_normalize_entry(e) for e in manifest]

    os.makedirs(output_dir, exist_ok=True)

    success_count = 0
    fail_count = 0
    skip_count = 0
    total_start = time.time()

    if workers <= 1:
        # Sequential mode — real-time output, localizer caching
        localizers: Dict[Tuple[str, str], Optional[RepoMemLocalizer]] = {}

        for i, entry in enumerate(manifest):
            cve_id = entry["cve_id"]
            owner = entry.get("owner", "")
            project = entry.get("project", "")
            language = entry.get("language", "?")

            # Resume check
            if resume:
                result_path = os.path.join(output_dir, cve_id, "result.json")
                if os.path.exists(result_path):
                    try:
                        with open(result_path, "r") as f:
                            existing = json.load(f)
                        if (not existing.get("error") and
                            len(existing.get("vulnerable_files", [])) > 0):
                            print(f"  SKIP (resume): already has valid result "
                                  f"({len(existing['vulnerable_files'])} files)")
                            skip_count += 1
                            continue
                    except Exception:
                        pass

            print(f"\n{'='*60}")
            print(f"[{i+1}/{len(manifest)}] {cve_id} ({owner}/{project}, {language})")
            print(f"{'='*60}")

            # Get or create localizer for this repo
            repo_key = (owner, project)
            if repo_key not in localizers:
                db_path = _get_rms_db_path(owner, project)
                repo_path = _find_repo_path(owner, project, cve_id)

                localizer_obj = None
                if os.path.exists(db_path):
                    try:
                        localizer_obj = RepoMemLocalizer(rms_db_path=db_path)
                        stats = localizer_obj.rms.stats()
                        print(f"  Loaded RMS: {stats['commits']} commits, "
                              f"{stats['hotspots']} hotspots")
                    except Exception as e:
                        print(f"  Failed to load RMS: {e}")
                elif repo_path:
                    try:
                        localizer_obj = RepoMemLocalizer(repo_path=repo_path)
                        stats = localizer_obj.rms.stats()
                        print(f"  Using direct git: {stats.get('commits', '?')} commits")
                    except Exception as e:
                        print(f"  Failed to init direct git: {e}")
                else:
                    print(f"  No RMS DB and no git repo found")

                localizers[repo_key] = localizer_obj

            localizer = localizers.get(repo_key)
            if localizer is None:
                skip_count += 1
                cve_dir = os.path.join(output_dir, cve_id)
                os.makedirs(cve_dir, exist_ok=True)
                with open(os.path.join(cve_dir, "result.json"), "w", encoding="utf-8") as f:
                    json.dump({
                        "cve_id": cve_id,
                        "error": "no_rms_db_and_no_git_repo",
                        "vulnerable_files": [],
                        "vulnerable_functions": [],
                    }, f)
                continue

            t0 = time.time()
            try:
                result = run_single(localizer, entry)
                elapsed = time.time() - t0

                cve_dir = os.path.join(output_dir, cve_id)
                os.makedirs(cve_dir, exist_ok=True)

                result["owner"] = owner
                result["project"] = project
                result["issue_title"] = (
                    entry.get("issue_list", [{}])[0].get("title", "")
                    if entry.get("issue_list") else ""
                )
                result["elapsed_seconds"] = round(elapsed, 1)

                with open(os.path.join(cve_dir, "result.json"), "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)

                report_lines = [
                    f"CVE: {cve_id}  |  {owner}/{project}",
                    f"Time: {datetime.now().isoformat()}  |  Elapsed: {elapsed:.1f}s",
                    f"Language: {language}",
                    "",
                    f"--- Vulnerable Files ({len(result.get('vulnerable_files', []))}) ---",
                ]
                for vf in result.get("vulnerable_files", [])[:15]:
                    report_lines.append(
                        f"  [{vf.get('score', 0):.2f}] {vf.get('file', '?')}"
                        f"  — {vf.get('reason', '')[:100]}"
                    )
                report_lines.append("")
                report_lines.append(
                    f"--- Vulnerable Functions ({len(result.get('vulnerable_functions', []))}) ---"
                )
                for vf in result.get("vulnerable_functions", [])[:15]:
                    report_lines.append(
                        f"  [{vf.get('score', 0):.2f}] {vf.get('function', '?')}"
                        f" @ {vf.get('file', '?')}"
                        f"  — {vf.get('reason', '')[:100]}"
                    )
                report_lines.append("")
                report_lines.append("--- Analysis Summary ---")
                report_lines.append(result.get("analysis_summary", "N/A"))
                with open(os.path.join(cve_dir, "report.txt"), "w", encoding="utf-8") as f:
                    f.write("\n".join(report_lines))

                n_files = len(result.get("vulnerable_files", []))
                n_funcs = len(result.get("vulnerable_functions", []))
                print(f"  Done in {elapsed:.1f}s: {n_files} files, {n_funcs} functions")
                success_count += 1

            except Exception as e:
                elapsed = time.time() - t0
                print(f"  FAILED in {elapsed:.1f}s: {e}")
                traceback.print_exc()
                cve_dir = os.path.join(output_dir, cve_id)
                os.makedirs(cve_dir, exist_ok=True)
                with open(os.path.join(cve_dir, "result.json"), "w", encoding="utf-8") as f:
                    json.dump({"cve_id": cve_id, "error": str(e)}, f)
                fail_count += 1

        # Clean up
        for loc in localizers.values():
            if loc:
                loc.close()
    else:
        # Parallel mode — ProcessPoolExecutor
        task_args = [(entry, output_dir, resume) for entry in manifest]
        print(f"Running {len(manifest)} CVEs with {workers} workers ...")

        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(_process_single_cve, a): a[0]["cve_id"]
                       for a in task_args}
            for future in as_completed(futures):
                cve_id = futures[future]
                try:
                    result = future.result()
                    if result["success"]:
                        if result.get("skipped"):
                            print(f"  [{cve_id}] SKIP: {result.get('skip_reason')}")
                            skip_count += 1
                        else:
                            print(f"  [{cve_id}] OK {result['elapsed']:.0f}s "
                                  f"{result['n_files']}f/{result['n_funcs']}fn "
                                  f"conf={result.get('confidence', '?')}")
                            success_count += 1
                    else:
                        print(f"  [{cve_id}] FAIL {result.get('error', 'unknown')[:80]}")
                        log = result.get("log", "")
                        if log:
                            print(f"    --- log ---\n{log.strip()[-500:]}\n    ---")
                        fail_count += 1
                except Exception as e:
                    print(f"  [{cve_id}] CRASH: {e}")
                    fail_count += 1

    total_elapsed = time.time() - total_start

    # Summary
    summary = {
        "total_cves": len(manifest),
        "success": success_count,
        "failed": fail_count,
        "skipped": skip_count,
        "total_elapsed_seconds": round(total_elapsed, 1),
        "avg_seconds_per_cve": round(total_elapsed / max(success_count, 1), 1),
        "workers": workers,
        "timestamp": datetime.now().isoformat(),
        "rms_db_dir": RMS_DB_DIR,
    }
    with open(os.path.join(output_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"DONE: {success_count} success, {fail_count} failed, "
          f"{skip_count} skipped")
    print(f"Total time: {total_elapsed:.1f}s ({total_elapsed/60:.1f}m)")
    print(f"Results saved to: {output_dir}")
    print(f"{'='*60}")

    return output_dir


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="RepoMem — Memory-Augmented Vulnerability Localization"
    )
    parser.add_argument("--build-all", action="store_true",
                        help="Build all per-project RMS databases first")
    parser.add_argument("--max-commits", type=int, default=500,
                        help="Max commits per RMS (default: 500)")
    parser.add_argument("--top-hotspots", type=int, default=30,
                        help="Number of hotspot files (default: 30)")
    parser.add_argument("--no-summaries", action="store_true",
                        help="Skip LLM file summaries")
    parser.add_argument("--limit", type=int, default=10,
                        help="Max CVEs to process (0=all, default: 10)")
    parser.add_argument("--skip", type=int, default=0,
                        help="Skip first N CVEs")
    parser.add_argument("--cves", type=str, default="",
                        help="Comma-separated CVE IDs")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT_DIR,
                        help="Output directory")
    parser.add_argument("--resume", action="store_true",
                        help="Skip CVEs that already have valid result.json")
    parser.add_argument("--workers", type=int, default=1,
                        help="Parallel worker processes (default: 1 = sequential)")

    args = parser.parse_args()

    if args.build_all:
        build_all_rms(
            max_commits=args.max_commits,
            top_hotspots=args.top_hotspots,
            no_summaries=args.no_summaries,
        )
        print("\nAll RMS databases built. Now run without --build-all to localize.")
        sys.exit(0)

    cve_list = None
    if args.cves:
        cve_list = [c.strip() for c in args.cves.split(",") if c.strip()]

    run_batch(
        manifest_path=MANIFEST_PATH,
        output_dir=args.output,
        limit=args.limit,
        skip=args.skip,
        cve_list=cve_list,
        resume=args.resume,
        workers=args.workers,
    )
