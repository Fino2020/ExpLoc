#!/usr/bin/python3
"""
Retry previously-failed CVEs and complete remaining batch processing.

1. Reprocess CVEs that failed due to encoding errors (now fixed via monkey-patch)
2. Process remaining CVEs that haven't been attempted yet
3. Update batch_progress.json
"""

import json
import os
import subprocess
import sys
import time
import signal
from datetime import datetime

RESULTS_DIR = "/mnt/d/Desktop/VulnLocalization/Static_Analysis/Results/ScubaTrace"
MANIFEST_PATH = os.path.join(RESULTS_DIR, "target_manifest.json")
EXTRACTOR = os.path.join(RESULTS_DIR, "extract_icfg.py")
TIMEOUT_PER_CVE = 600
PROGRESS_PATH = os.path.join(RESULTS_DIR, "batch_progress.json")


def load_json(path):
    with open(path) as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def run_one(cve_id, repo_path, language):
    cve_dir = os.path.join(RESULTS_DIR, cve_id)
    csv_path = os.path.join(cve_dir, "icfg_scubatrace.csv")
    summary_path = os.path.join(cve_dir, "summary.json")

    os.makedirs(cve_dir, exist_ok=True)

    start = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, EXTRACTOR, repo_path, language, csv_path],
            capture_output=True, text=True, timeout=TIMEOUT_PER_CVE,
        )
        elapsed = time.time() - start
        stdout = proc.stdout
        stderr = proc.stderr

        result = {
            "cve_id": cve_id, "language": language, "repo_path": repo_path,
            "elapsed_s": elapsed, "status": "error",
            "files": 0, "functions": 0, "edges": 0,
            "call_edges": 0, "cfg_edges": 0, "return_edges": 0,
        }

        for line in (stdout or "").splitlines():
            stripped = line.strip()
            for key in ["files", "functions", "edges", "call_edges",
                       "cfg_edges", "return_edges", "elapsed_s", "error"]:
                if stripped.startswith(f"{key}:"):
                    val = stripped.split(":", 1)[1].strip()
                    if key == "error":
                        result[key] = val if val and val != "None" else None
                    elif key == "elapsed_s":
                        result[key] = float(val)
                    else:
                        result[key] = int(val)

        if result.get("error"):
            result["status"] = "error"
        elif result["functions"] == 0:
            result["status"] = "empty"
        else:
            result["status"] = "success"

        result["elapsed_s"] = elapsed
        result["stdout"] = (stdout or "")[-2000:]
        result["stderr"] = (stderr or "")[-1000:]

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        result = {
            "cve_id": cve_id, "language": language, "repo_path": repo_path,
            "elapsed_s": elapsed, "status": "timeout",
            "error": f"Timeout after {TIMEOUT_PER_CVE}s",
        }
    except Exception as e:
        elapsed = time.time() - start
        result = {
            "cve_id": cve_id, "language": language, "repo_path": repo_path,
            "elapsed_s": elapsed, "status": "error", "error": str(e),
        }

    save_json(summary_path, result)
    return result


def main():
    manifest = load_json(MANIFEST_PATH)
    manifest_lookup = {e["cve_id"]: e for e in manifest}

    progress = load_json(PROGRESS_PATH)
    completed_ids = set(progress["completed"] + progress["failed"] + progress["skipped"])

    # Build work list: retry list (CVEs removed from failed) + remaining manifest entries
    retry_list_path = os.path.join(RESULTS_DIR, "retry_list.json")
    retry_ids = set()
    if os.path.exists(retry_list_path):
        retry_ids = set(load_json(retry_list_path))

    # Remaining from manifest
    remaining_ids = set(e["cve_id"] for e in manifest) - completed_ids

    # Merge: retry first, then remaining
    all_work_ids = sorted(retry_ids | remaining_ids)

    # Build work list in manifest order for consistent progress tracking
    work_entries = []
    for e in manifest:
        if e["cve_id"] in all_work_ids:
            work_entries.append(e)

    print(f"Total work items: {len(work_entries)}")
    print(f"  Retry (previously failed): {len(retry_ids)}")
    print(f"  New (not yet attempted): {len(remaining_ids - retry_ids)}")
    print()

    if not work_entries:
        print("Nothing to do!")
        return

    interrupted = False

    def sig_handler(sig, frame):
        nonlocal interrupted
        interrupted = True
        print("\n\nInterrupted! Saving progress...")

    signal.signal(signal.SIGINT, sig_handler)

    batch_start = time.time()
    success_count = 0
    empty_count = 0
    error_count = 0
    timeout_count = 0

    for i, entry in enumerate(work_entries):
        if interrupted:
            break

        cve_id = entry["cve_id"]
        language = entry["language"]
        repo_path = entry["repo_path"]

        if not os.path.exists(repo_path):
            print(f"[{i+1}/{len(work_entries)}] {cve_id} ({language}) - REPO MISSING")
            if cve_id not in progress["skipped"]:
                progress["skipped"].append(cve_id)
            save_json(PROGRESS_PATH, progress)
            continue

        elapsed_total = time.time() - batch_start
        print(f"[{i+1}/{len(work_entries)}] {cve_id} ({language}) [{elapsed_total/60:.1f}m] ...",
              end=" ", flush=True)

        result = run_one(cve_id, repo_path, language)
        status = result["status"]

        if status == "success":
            success_count += 1
            print(f"OK: {result['files']}f/{result['functions']}fn/{result['edges']}e "
                  f"({result['elapsed_s']:.1f}s)")
            if cve_id not in progress["completed"]:
                progress["completed"].append(cve_id)
        elif status == "empty":
            empty_count += 1
            print(f"EMPTY: {result.get('error', 'no functions')[:80]}")
            if cve_id not in progress["completed"]:
                progress["completed"].append(cve_id)
        elif status == "timeout":
            timeout_count += 1
            print(f"TIMEOUT")
            if cve_id not in progress["failed"]:
                progress["failed"].append(cve_id)
        else:
            error_count += 1
            err = result.get("error", "unknown")[:80]
            print(f"ERROR: {err}")
            if cve_id not in progress["failed"]:
                progress["failed"].append(cve_id)

        # Remove from retry list as processed
        progress["last_idx"] = max(progress.get("last_idx", 0),
                                    manifest_lookup[cve_id].get("_idx", 0))

        save_json(PROGRESS_PATH, progress)

    batch_elapsed = time.time() - batch_start
    print(f"\n{'='*60}")
    print(f"Batch complete! Elapsed: {batch_elapsed/60:.1f} min")
    print(f"  Processed: {success_count + empty_count + error_count + timeout_count}")
    print(f"  Success:   {success_count}")
    print(f"  Empty:     {empty_count}")
    print(f"  Timeout:   {timeout_count}")
    print(f"  Error:     {error_count}")

    # Final progress summary
    progress = load_json(PROGRESS_PATH)
    print(f"\nFinal state:")
    print(f"  Completed: {len(progress['completed'])}")
    print(f"  Failed:    {len(progress['failed'])}")
    print(f"  Skipped:   {len(progress['skipped'])}")


if __name__ == "__main__":
    main()
