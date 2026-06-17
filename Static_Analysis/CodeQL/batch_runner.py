#!/usr/bin/env python3
"""
Batch ICFG Runner — Iterates over all CVE directories in Localization_Repo,
auto-detects language, creates CodeQL databases, and extracts ICFGs.

Repositories are read directly from /mnt/d/Desktop/Localization_Repo —
no cloning needed.

Features:
  - Multiprocess parallel execution (--workers N)
  - CPU usage throttling (--cpu-limit PERCENT, requires psutil)
  - Skip already-processed CVEs (resume after interruption)
  - Per-CVE timeout to prevent hangs
  - Graceful Ctrl+C handling with progress save
  - Retry on transient failures
  - Per-language timeout budgets (C++ slower than Python)
  - Real-time progress logging to file
  - Reverse-order processing for parallel runs
"""

from __future__ import annotations

import argparse
import json
import logging
import multiprocessing
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from codeql_auto_analyzer import (
    analyze_single_project, analyze_multilang_project,
    detect_language, detect_all_languages, LANG_SIGNATURES
)

REPO_ROOT = Path("/mnt/e/Desktop/Localization_Repo/Localization_Repo")
OUTPUT_ROOT = Path("/mnt/d/Desktop/VulnLocalization/Static_Analysis/Results/CodeQL")
OUTPUT_CSV_NAME = "icfg_icfg_db.csv"


def _cve_sort_key(name: str) -> tuple:
    """Sort CVE-YYYY-NNNNN by (year, number) numerically."""
    parts = name.split("-")
    if len(parts) >= 3 and parts[0] == "CVE":
        try:
            return (int(parts[1]), int(parts[2]))
        except ValueError:
            pass
    return (0, 0)


# Per-language timeout budgets (seconds) — C++ stub generation is slow
LANG_TIMEOUTS = {
    "cpp":        1800,  # 30 min (stub generation + compilation + query)
    "java":       900,  # 15 min
    "python":     300,  # 5 min
    "javascript": 300,  # 5 min
    "go":         600,  # 10 min
    "ruby":       300,  # 5 min
    "php":        300,  # 5 min (generic extractor)
    "perl":       300,  # 5 min (generic extractor)
    "rust":       600,  # 10 min
    None:         600,  # unknown language
}

UNSUPPORTED_LANGUAGES = { "ruby" }
MAX_RETRIES = 2
EMPTY_PROJECT_ROWS = 0


def setup_logging(log_file: Path) -> None:
    """Configure dual logging: console (INFO) + file (DEBUG)."""
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),
        ],
    )
    logging.getLogger().handlers[1].setLevel(logging.INFO)


def find_cve_directories() -> list[tuple[str, Path]]:
    """Find all CVE directories and their project roots."""
    results = []
    skipped_empty = 0
    for item in sorted(REPO_ROOT.iterdir(), key=lambda p: _cve_sort_key(p.name)):
        if not item.is_dir() or not item.name.startswith("CVE-"):
            continue

        cve_id = item.name
        owners = [d for d in item.iterdir() if d.is_dir()]
        if not owners:
            skipped_empty += 1
            continue

        owner_dir = owners[0]
        projects = [d for d in owner_dir.iterdir() if d.is_dir() and d.name != ".git"]
        if not projects:
            skipped_empty += 1
            continue

        project_dir = projects[0]
        try:
            # Fast check: does the dir have any immediate content?
            has_files = any(True for _ in project_dir.iterdir())
        except (PermissionError, OSError):
            has_files = False

        if not has_files:
            skipped_empty += 1
            continue

        results.append((cve_id, project_dir))

    logging.info(f"Found {len(results)} CVE dirs with content ({skipped_empty} empty/skipped).")
    return results


def load_progress() -> dict:
    """Load existing progress for resume support."""
    progress_file = OUTPUT_ROOT / "batch_progress.json"
    if progress_file.exists():
        try:
            with open(progress_file) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            logging.warning("Could not parse progress file, starting fresh.")
    return { "completed": { }, "failed": { } }


def save_progress(progress: dict) -> None:
    """Atomically save current progress."""
    progress_file = OUTPUT_ROOT / "batch_progress.json"
    tmp_file = progress_file.with_suffix(".tmp")
    progress["last_updated"] = datetime.now().isoformat()
    with open(tmp_file, "w") as f:
        json.dump(progress, f, indent=2)
    tmp_file.replace(progress_file)


def is_already_done(cve_id: str) -> bool:
    """Check if a CVE has already been processed successfully.
    A CVE is done if icfg_icfg_db.csv exists with size > 200 bytes (at least header + 1 row)."""
    csv_file_1 = OUTPUT_ROOT / cve_id / OUTPUT_CSV_NAME
    csv_file_2 = OUTPUT_ROOT / cve_id / "icfg_icfg.csv"
    path = csv_file_1 if csv_file_1.exists() else (csv_file_2 if csv_file_2.exists() else None)
    if path is not None:
        try:
            return path.stat().st_size > 200
        except OSError:
            pass
    return False


# ──────────────────────── Worker Process ────────────────────────────────────

def _worker_init(*_args: object) -> None:
    """Initialize each worker: lower priority, suppress codeql home-dir warning."""
    os.environ["CODEQL_ALLOW_INSTALLATION_ANYWHERE"] = "true"
    try:
        os.nice(10)
    except (OSError, AttributeError):
        pass


def _worker_analyze(args: tuple) -> dict:
    """Process a single CVE in a worker process. Returns a summary dict."""
    cve_id, project_root_str = args
    project_root = Path(project_root_str)
    output_dir = OUTPUT_ROOT / cve_id
    output_dir.mkdir(parents=True, exist_ok=True)

    # Detect language inside worker (fast per-project, avoids blocking main)
    lang = detect_language(project_root)
    timeout = LANG_TIMEOUTS.get(lang, LANG_TIMEOUTS[None])
    lang_desc = LANG_SIGNATURES.get(lang, { }).get("description", str(lang))
    print(f"  [{cve_id}] Language: {lang_desc} ({lang})")

    summary = {
        "cve_id":       cve_id,
        "project_root": project_root_str,
        "output_dir":   str(output_dir),
        "started_at":   datetime.now().isoformat(),
        "status":       "pending",
        "language":     lang,
        "icfg_rows":    0,
        "error":        None,
        "retries":      0,
        "elapsed_s":    0,
    }

    start_time = time.time()

    try:
        if lang in UNSUPPORTED_LANGUAGES:
            summary["status"] = "skipped"
            summary["error"] = f"{lang_desc} not supported by CodeQL (no extractor available)."
            print(f"  [{cve_id}] {lang_desc} — skipping (unsupported).")

        elif lang is None:
            summary["status"] = "skipped"
            summary["error"] = "Could not detect language."
            print(f"  [{cve_id}] Unknown language — skipping.")

        else:
            # Retry loop inside the worker
            for attempt in range(MAX_RETRIES + 1):
                summary["retries"] = attempt
                if attempt > 0:
                    print(f"  [{cve_id}] Retry {attempt}/{MAX_RETRIES} ...")
                    # Clean up corrupted output from previous attempt
                    import shutil as _shutil
                    for _sub in output_dir.iterdir():
                        if _sub.is_dir() and _sub.name.endswith("_db"):
                            try:
                                _shutil.rmtree(_sub, ignore_errors=True)
                            except Exception:
                                pass
                    time.sleep(5)

                # Use multi-language joint extraction by default.
                # This fixes the 79.9% file-level mismatch where PHP projects
                # only had JS ICFGs because the detector picked one language.
                result, error_msg = analyze_multilang_project(
                    project_root=project_root,
                    output_dir=output_dir,
                    project_label="icfg",
                )

                if result and result.exists():
                    try:
                        with open(result) as f:
                            summary["icfg_rows"] = sum(1 for _ in f) - 1
                    except Exception:
                        summary["icfg_rows"] = -1

                    if summary["icfg_rows"] <= EMPTY_PROJECT_ROWS:
                        summary["status"] = "empty"
                        summary["error"] = f"ICFG empty or too small ({summary['icfg_rows']} rows)."
                        print(f"  [{cve_id}] Empty result ({summary['icfg_rows']} rows).")
                    else:
                        summary["status"] = "success"
                        print(f"  [{cve_id}] SUCCESS — {summary['icfg_rows']} rows (lang={lang}).")
                    break
                else:
                    if error_msg and error_msg.startswith("SKIP:"):
                        summary["status"] = "skipped"
                        summary["error"] = error_msg[5:].strip()
                        print(f"  [{cve_id}] SKIPPED — {summary['error']}")
                        break
                    elif attempt >= MAX_RETRIES:
                        summary["status"] = "failed"
                        summary["error"] = error_msg or "ICFG extraction returned no result."
                        print(f"  [{cve_id}] FAILED — {summary['error']}")

    except subprocess.TimeoutExpired as e:
        summary["status"] = "timeout"
        summary["error"] = f"Timeout after {timeout}s: {e}"
    except Exception as e:
        summary["status"] = "error"
        summary["error"] = f"{type(e).__name__}: {e}"

    summary["elapsed_s"] = int(time.time() - start_time)
    summary["finished_at"] = datetime.now().isoformat()

    try:
        summary_path = output_dir / "summary.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
    except IOError:
        pass

    return summary


# ──────────────────────── CPU Throttle ──────────────────────────────────────

def _try_load_psutil():
    """Lazy-load psutil for CPU monitoring; return module or None."""
    try:
        import psutil
        return psutil
    except ImportError:
        return None


def _cpu_throttle(target_percent: int, _state: dict) -> None:
    """Sleep briefly if system-wide CPU usage exceeds target_percent."""
    psutil = _state.get("psutil")
    if psutil is None:
        return
    cpu = psutil.cpu_percent(interval=0.5)
    if cpu > target_percent:
        time.sleep(1.0 + (cpu - target_percent) * 0.1)


# ──────────────────────── Main ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Batch ICFG Runner")
    parser.add_argument(
        "--reverse", action="store_true",
        help="Process CVEs in reverse order"
    )
    parser.add_argument(
        "--workers", type=int, default=2,
        help="Number of parallel worker processes (default: 2)"
    )
    parser.add_argument(
        "--cpu-limit", type=int, default=None, metavar="PERCENT",
        help="Max total CPU usage in percent (requires: pip install psutil)"
    )
    parser.add_argument(
        "--dataset", type=str, default=None, metavar="JSON_PATH",
        help="Path to dataset JSON file to filter CVEs (only process CVEs in this file)"
    )
    args = parser.parse_args()

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    log_file = OUTPUT_ROOT / f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    setup_logging(log_file)

    # Lazy-load psutil for CPU throttling
    cpu_state = { }
    if args.cpu_limit is not None:
        psutil = _try_load_psutil()
        if psutil is None:
            logging.warning(
                "psutil not installed; --cpu-limit ignored. "
                "Install with: pip install psutil"
            )
        else:
            cpu_state["psutil"] = psutil
            psutil.cpu_percent(interval=None)  # prime the first reading
            logging.info(f"  CPU limit : {args.cpu_limit}% (psutil monitoring active)")

    logging.info("=" * 60)
    logging.info("  Batch ICFG Runner — CVE Repository Analysis")
    logging.info(f"  Source   : {REPO_ROOT}")
    logging.info(f"  Output   : {OUTPUT_ROOT}")
    logging.info(f"  Workers  : {args.workers}")
    logging.info(f"  Log      : {log_file}")
    if args.reverse:
        logging.info("  Order    : REVERSE")
    logging.info("=" * 60)

    # ── Discover & filter already-done ──
    cve_dirs = find_cve_directories()

    # Apply dataset filter if specified
    if args.dataset:
        import json as _json
        with open(args.dataset) as f:
            dataset_entries = _json.load(f)
        dataset_cves = {e["cve_id"] for e in dataset_entries}
        before_filter = len(cve_dirs)
        cve_dirs = [(c, p) for c, p in cve_dirs if c in dataset_cves]
        logging.info(f"  Dataset filter: {before_filter} → {len(cve_dirs)} CVEs (from {args.dataset})")

    progress = load_progress()
    already_done = set(progress.get("completed", { }).keys())

    for cve_id, _ in cve_dirs:
        if is_already_done(cve_id):
            already_done.add(cve_id)

    pending = [(c, p) for c, p in cve_dirs if c not in already_done]
    if args.reverse:
        pending.reverse()
    total = len(cve_dirs)
    done = len(already_done)
    pending_count = len(pending)

    logging.info(f"  Total: {total} | Already done: {done} | Pending: {pending_count}")
    if done > 0:
        logging.info(f"  Resuming from previous run — {done} CVEs will be skipped.")

    if pending_count == 0:
        logging.info("  Nothing to process. Exiting.")
        return

    # ── Build task list (fast — just pack paths, language detection in worker) ──
    logging.info("  Building task list ...")
    tasks = [(cve_id, str(project_root)) for cve_id, project_root in pending]
    logging.info(f"  {len(tasks)} tasks ready, starting pool with {args.workers} workers ...")
    sys.stdout.flush()

    # ── Multiprocess execution ──
    success_count = 0
    fail_count = 0
    timeout_count = 0
    skip_count = 0
    processed = 0

    # Suppress fork-safety warnings from subprocess in workers
    multiprocessing.set_start_method("spawn", force=True)

    pool = multiprocessing.Pool(
        processes=args.workers,
        initializer=_worker_init,
        initargs=(),
    )

    try:
        for summary in pool.imap_unordered(_worker_analyze, tasks):
            processed += 1
            cve_id = summary["cve_id"]
            status = summary["status"]

            if status == "success":
                success_count += 1
                progress["completed"][cve_id] = summary
            elif status == "timeout":
                timeout_count += 1
                progress["failed"][cve_id] = summary
            elif status in ("failed", "error"):
                fail_count += 1
                progress["failed"][cve_id] = summary
            else:
                skip_count += 1
                progress["completed"][cve_id] = summary

            save_progress(progress)

            elapsed = summary["elapsed_s"]
            rows = summary["icfg_rows"]
            status_str = status.upper()
            logging.info(
                f"  [{status_str}] {cve_id}  rows={rows} time={elapsed}s "
                f"({processed}/{pending_count} done; "
                f"ok:{success_count} fail:{fail_count} to:{timeout_count} skip:{skip_count})"
            )

            # Throttle CPU if needed
            if cpu_state:
                _cpu_throttle(args.cpu_limit, cpu_state)

    except KeyboardInterrupt:
        logging.warning("\nCtrl+C received — terminating workers gracefully...")
        pool.terminate()
        pool.join()
        logging.warning(f"Processed {processed}/{pending_count} before interrupt.")
        save_progress(progress)
        sys.exit(130)

    finally:
        pool.close()
        pool.join()

    # ── Final summary ──
    logging.info(f"\n{'=' * 60}")
    logging.info(f"  BATCH COMPLETE")
    logging.info(f"  Total scanned : {total}")
    logging.info(f"  Success       : {done + success_count}")
    logging.info(f"  Failed        : {fail_count}")
    logging.info(f"  Timeout       : {timeout_count}")
    logging.info(f"  Skipped       : {skip_count}")
    logging.info(f"  Log file      : {log_file}")
    logging.info(f"  Progress file : {OUTPUT_ROOT / 'batch_progress.json'}")
    logging.info(f"{'=' * 60}")

    final_summary = {
        "total":       total,
        "completed":   done + success_count,
        "failed":      fail_count,
        "timeout":     timeout_count,
        "skipped":     skip_count,
        "finished_at": datetime.now().isoformat(),
        "workers":     args.workers,
    }
    with open(OUTPUT_ROOT / "batch_summary.json", "w") as f:
        json.dump(final_summary, f, indent=2)


if __name__ == "__main__":
    main()
