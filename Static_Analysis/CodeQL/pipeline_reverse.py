#!/usr/bin/env python3
"""
Pipeline: Read → Analyze (Reverse Order)

For each CVE in the dataset (reverse alphabetical):
  1. Read repo from /mnt/d/Desktop/Localization_Repo/{CVE-ID}/{Owner}/{Project}
  2. Run CodeQL ICFG analysis immediately

Repositories must already exist on disk — no cloning is performed.
The other machine runs forward order; this one runs reverse.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from codeql_auto_analyzer import analyze_single_project, detect_language, LANG_SIGNATURES

# ────────────────────────── Paths ───────────────────────────────────────────

DATASET_PATH = "/mnt/d/Desktop/VulnLocalization/Generate_IssueReport_File/dataset_with_changed_files.json"
REPO_ROOT    = Path("/mnt/d/Desktop/Localization_Repo")
OUTPUT_ROOT  = Path("/mnt/d/Desktop/VulnLocalization/Static_Analysis/Results/CodeQL")
OUTPUT_CSV_NAME = "icfg_icfg_db.csv"


def _cve_sort_key(cve_id: str) -> tuple:
    """Sort CVE-YYYY-NNNNN by (year, number) numerically."""
    parts = cve_id.split("-")
    if len(parts) >= 3 and parts[0] == "CVE":
        try:
            return (int(parts[1]), int(parts[2]))
        except ValueError:
            pass
    return (0, 0)


# ────────────────────────── Constants ───────────────────────────────────────

LANG_TIMEOUTS = {
    "cpp":        1800,
    "java":       900,
    "python":     300,
    "javascript": 300,
    "go":         600,
    "ruby":       300,
    "perl":       300,
    "rust":       600,
    None:         600,
}

UNSUPPORTED_LANGUAGES = {"ruby", "perl"}
MAX_RETRIES = 2
EMPTY_PROJECT_ROWS = 0

_shutdown_requested = False
_current_cve_id: Optional[str] = None


# ────────────────────────── Logging & Signal ─────────────────────────────────

def setup_logging(log_file: Path) -> None:
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


def on_signal(signum, frame):
    global _shutdown_requested
    if _shutdown_requested:
        logging.warning("Second interrupt — forcing exit.")
        sys.exit(130)
    _shutdown_requested = True
    cve = _current_cve_id or "unknown"
    logging.warning(f"Interrupt received. Finishing {cve} then saving...")


# ────────────────────────── Progress ────────────────────────────────────────

def load_progress() -> dict:
    pf = OUTPUT_ROOT / "pipeline_progress.json"
    if pf.exists():
        try:
            with open(pf) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            logging.warning("Could not parse progress file, starting fresh.")
    return {"completed": {}, "failed": {}}


def save_progress(progress: dict) -> None:
    pf = OUTPUT_ROOT / "pipeline_progress.json"
    tmp = pf.with_suffix(".tmp")
    progress["last_updated"] = datetime.now().isoformat()
    with open(tmp, "w") as f:
        json.dump(progress, f, indent=2)
    tmp.replace(pf)


def is_analysis_done(cve_id: str) -> bool:
    """Check if a CVE has already been processed successfully.
    A CVE is done if icfg_icfg_db.csv exists and has more than just a header row."""
    csv_file = OUTPUT_ROOT / cve_id / OUTPUT_CSV_NAME
    if csv_file.exists():
        try:
            with open(csv_file) as f:
                row_count = sum(1 for _ in f)
            return row_count > 1  # more than just header
        except (IOError, OSError):
            pass
    return False


# ────────────────────────── Locate Repo ─────────────────────────────────────

def locate_project(cve_id: str, repo_full: str) -> tuple[Optional[Path], Optional[str]]:
    """Locate an already-cloned repository on disk. Returns (project_dir, error_msg)."""
    owner, project = repo_full.split("/", 1)
    project_dir = REPO_ROOT / cve_id / owner / project

    if not project_dir.exists():
        return None, f"Project dir not found: {project_dir}"
    if not any(project_dir.iterdir()):
        return None, f"Project dir exists but is empty: {project_dir}"

    logging.info(f"  [{cve_id}] Found at {project_dir}")
    return project_dir, None


# ────────────────────────── Analyze ─────────────────────────────────────────

def analyze_cve(cve_id: str, project_root: Path, timeout: int, retry: int = 0) -> dict:
    """Run CodeQL analysis on a single project. Same logic as batch_runner."""
    output_dir = OUTPUT_ROOT / cve_id
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "cve_id":       cve_id,
        "project_root": str(project_root),
        "output_dir":   str(output_dir),
        "started_at":   datetime.now().isoformat(),
        "status":       "pending",
        "language":     None,
        "icfg_rows":    0,
        "error":        None,
        "retries":      retry,
        "elapsed_s":    0,
    }

    start_time = time.time()

    try:
        lang = detect_language(project_root)
        summary["language"] = lang
        lang_desc = LANG_SIGNATURES.get(lang, {}).get("description", str(lang))
        logging.info(f"  [{cve_id}] Language: {lang_desc} ({lang}), timeout={timeout}s")

        if lang in UNSUPPORTED_LANGUAGES:
            lang_desc = LANG_SIGNATURES.get(lang, {}).get("description", lang)
            summary["status"] = "skipped"
            summary["error"] = f"{lang_desc} not supported by CodeQL."
            logging.warning(f"  [{cve_id}] {lang_desc} — skipping.")
            return summary

        if lang is None:
            summary["status"] = "skipped"
            summary["error"] = "Could not detect language."
            logging.warning(f"  [{cve_id}] Unknown language — skipping.")
            return summary

        result, error_msg = analyze_single_project(
            project_root=project_root,
            output_dir=output_dir,
            project_label="icfg",
            output_csv=output_dir / OUTPUT_CSV_NAME,
        )

        if result and result.exists():
            try:
                with open(result) as f:
                    summary["icfg_rows"] = sum(1 for _ in f) - 1
            except Exception:
                summary["icfg_rows"] = -1

            if summary["icfg_rows"] <= EMPTY_PROJECT_ROWS:
                summary["status"] = "empty"
                summary["error"] = f"ICFG empty ({summary['icfg_rows']} rows)."
                logging.warning(f"  [{cve_id}] Empty result ({summary['icfg_rows']} rows).")
            else:
                summary["status"] = "success"
                logging.info(f"  [{cve_id}] SUCCESS — {summary['icfg_rows']} rows.")
        else:
            if error_msg and error_msg.startswith("SKIP:"):
                summary["status"] = "skipped"
                summary["error"] = error_msg[5:].strip()
                logging.warning(f"  [{cve_id}] SKIPPED — {summary['error']}")
            else:
                summary["status"] = "failed"
                summary["error"] = error_msg or "ICFG extraction returned no result."
                logging.error(f"  [{cve_id}] FAILED — {summary['error']}")

    except subprocess.TimeoutExpired as e:
        summary["status"] = "timeout"
        summary["error"] = f"Timeout after {timeout}s: {e}"
        logging.error(f"  [{cve_id}] TIMEOUT ({timeout}s).")
    except Exception as e:
        summary["status"] = "error"
        summary["error"] = f"{type(e).__name__}: {e}"
        logging.error(f"  [{cve_id}] ERROR: {type(e).__name__}: {e}")
        logging.debug(traceback.format_exc())

    summary["elapsed_s"] = int(time.time() - start_time)
    summary["finished_at"] = datetime.now().isoformat()

    try:
        with open(output_dir / "summary.json", "w") as f:
            json.dump(summary, f, indent=2)
    except IOError as e:
        logging.error(f"  [{cve_id}] Could not write summary: {e}")

    return summary


# ────────────────────────── Main ────────────────────────────────────────────

def main():
    global _current_cve_id

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    log_file = OUTPUT_ROOT / f"pipeline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    setup_logging(log_file)

    signal.signal(signal.SIGINT,  on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    logging.info("=" * 60)
    logging.info("  Pipeline: Read → Analyze (REVERSE order)")
    logging.info(f"  Dataset  : {DATASET_PATH}")
    logging.info(f"  Repo dir : {REPO_ROOT}")
    logging.info(f"  Output   : {OUTPUT_ROOT}")
    logging.info(f"  Log      : {log_file}")
    logging.info("  Note     : No cloning — repos must already exist on disk")
    logging.info("=" * 60)

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    data_sorted = sorted(data, key=lambda v: _cve_sort_key(v["cve_id"]))
    data_rev = list(reversed(data_sorted))
    total = len(data_rev)
    logging.info(f"  Total CVEs: {total}")

    progress = load_progress()
    already_done = set(progress.get("completed", {}).keys())

    pending = []
    for vuln in data_rev:
        cve_id = vuln["cve_id"]
        if cve_id not in already_done and not is_analysis_done(cve_id):
            pending.append(vuln)

    logging.info(f"  Already done: {total - len(pending)} | Pending: {len(pending)}")

    if not pending:
        logging.info("  Nothing to process. Exiting.")
        return

    success_count = 0
    fail_count = 0
    timeout_count = 0
    skip_count = 0
    missing_count = 0

    for idx, vuln in enumerate(pending, 1):
        if _shutdown_requested:
            logging.warning(f"Shutdown requested. Processed {idx - 1}/{len(pending)}.")
            break

        cve_id      = vuln["cve_id"]
        commit_info = vuln["commit_list"][0]
        repo_full   = commit_info["repo"]

        _current_cve_id = cve_id
        logging.info(f"\n{'─' * 50}")
        logging.info(f"  [{idx}/{len(pending)}] {cve_id} | {repo_full}")

        # ── Step 1: Locate repo on disk ──
        project_dir, locate_err = locate_project(cve_id, repo_full)
        if locate_err:
            logging.error(f"  [{cve_id}] NOT FOUND: {locate_err}")
            missing_count += 1
            progress["failed"][cve_id] = {
                "cve_id": cve_id, "repo": repo_full,
                "status": "missing", "error": locate_err,
            }
            save_progress(progress)
            continue

        # ── Step 2: Analyze ──
        lang = detect_language(project_dir)
        timeout = LANG_TIMEOUTS.get(lang, LANG_TIMEOUTS[None])

        summary = None
        for attempt in range(MAX_RETRIES + 1):
            summary = analyze_cve(cve_id, project_dir, timeout, retry=attempt)
            if summary["status"] in ("success", "empty", "skipped"):
                break
            if attempt < MAX_RETRIES:
                logging.info(f"  [{cve_id}] Retry {attempt + 1}/{MAX_RETRIES} ...")
                time.sleep(5)

        if summary:
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

        elapsed = summary["elapsed_s"] if summary else 0
        status_str = summary["status"].upper() if summary else "UNKNOWN"
        rows = summary["icfg_rows"] if summary else 0
        logging.info(
            f"  [{status_str}] rows={rows} time={elapsed}s "
            f"(ok:{success_count} fail:{fail_count} to:{timeout_count} "
            f"skip:{skip_count} missing:{missing_count})"
        )

    logging.info(f"\n{'=' * 60}")
    logging.info(f"  PIPELINE COMPLETE")
    logging.info(f"  Total scanned  : {total}")
    logging.info(f"  Success        : {success_count}")
    logging.info(f"  Failed         : {fail_count}")
    logging.info(f"  Timeout        : {timeout_count}")
    logging.info(f"  Skipped        : {skip_count}")
    logging.info(f"  Missing        : {missing_count}")
    logging.info(f"  Log file       : {log_file}")
    logging.info(f"{'=' * 60}")

    with open(OUTPUT_ROOT / "pipeline_summary.json", "w") as f:
        json.dump({
            "total":         total,
            "success":       success_count,
            "failed":        fail_count,
            "timeout":       timeout_count,
            "skipped":       skip_count,
            "missing":       missing_count,
            "finished_at":   datetime.now().isoformat(),
        }, f, indent=2)


if __name__ == "__main__":
    main()
