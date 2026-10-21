#!/usr/bin/python3
"""
Parallel batch runner: Processes multiple CVEs concurrently.

Uses ThreadPoolExecutor to run extract_icfg.py subprocesses in parallel.
Resumable via batch_progress.json.
"""

import json
import os
import subprocess
import sys
import time
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed

RESULTS_DIR = "/mnt/d/Desktop/VulnLocalization/Static_Analysis/Results/ScubaTrace"
MANIFEST_PATH = os.path.join(RESULTS_DIR, "target_manifest.json")
EXTRACTOR = os.path.join(RESULTS_DIR, "extract_icfg.py")
TIMEOUT_PER_CVE = 600
PROGRESS_PATH = os.path.join(RESULTS_DIR, "batch_progress.json")
MAX_WORKERS = 4  # parallel workers


def load_json(path):
    with open(path) as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def run_one(entry):
    """Process a single CVE. Returns (cve_id, result_dict)."""
    cve_id = entry["cve_id"]
    language = entry["language"]
    repo_path = entry["repo_path"]

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
        result["stderr"] = (proc.stderr or "")[-1000:]

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
    return cve_id, result


def main():
    manifest = load_json(MANIFEST_PATH)
    progress = load_json(PROGRESS_PATH)

    completed_ids = set(progress["completed"] + progress["failed"] +
                        progress["skipped"])

    # Build work list: retry list + remaining manifest entries in order
    retry_list_path = os.path.join(RESULTS_DIR, "retry_list.json")
    retry_ids = set()
    if os.path.exists(retry_list_path):
        retry_ids = set(load_json(retry_list_path))

    remaining_ids = set(e["cve_id"] for e in manifest) - completed_ids
    all_work_ids = retry_ids | remaining_ids

    work_entries = []
    for e in manifest:
        if e["cve_id"] in all_work_ids:
            work_entries.append(e)

    if not work_entries:
        print("All CVEs already processed!")
        return

    print(f"Work items: {len(work_entries)} (retry={len(retry_ids)}, new={len(remaining_ids - retry_ids)})")
    print(f"Workers: {MAX_WORKERS}")
    print()

    interrupted = False

    def sig_handler(sig, frame):
        nonlocal interrupted
        interrupted = True
        print("\n\nInterrupt received! Waiting for in-flight tasks...")

    signal.signal(signal.SIGINT, sig_handler)

    start_time = time.time()
    processed = 0
    success_count = 0
    empty_count = 0
    error_count = 0
    timeout_count = 0

    # Filter out entries with missing repos upfront
    valid_entries = []
    for entry in work_entries:
        if not os.path.exists(entry["repo_path"]):
            print(f"SKIP {entry['cve_id']}: repo missing")
            if entry["cve_id"] not in progress["skipped"]:
                progress["skipped"].append(entry["cve_id"])
            save_json(PROGRESS_PATH, progress)
        else:
            valid_entries.append(entry)

    print(f"Valid entries (repo exists): {len(valid_entries)}")
    print()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {}
        # Submit initial batch
        for entry in valid_entries:
            if interrupted:
                break
            future = executor.submit(run_one, entry)
            future_map[future] = entry

        # Process results as they complete
        for future in as_completed(future_map):
            if interrupted:
                for f in future_map:
                    f.cancel()
                break

            entry = future_map[future]
            cve_id = entry["cve_id"]

            try:
                cve_id, result = future.result()
            except Exception as e:
                result = {
                    "cve_id": entry["cve_id"], "language": entry["language"],
                    "repo_path": entry["repo_path"], "elapsed_s": 0,
                    "status": "error", "error": str(e),
                }
                save_json(os.path.join(RESULTS_DIR, entry["cve_id"], "summary.json"), result)

            status = result["status"]
            processed += 1
            elapsed_total = time.time() - start_time
            pct = 100 * processed / len(valid_entries)

            if status == "success":
                success_count += 1
                print(f"[{processed}/{len(valid_entries)} {pct:.0f}% {elapsed_total/60:.1f}m] "
                      f"{cve_id} ({entry['language']}): OK "
                      f"{result['files']}f/{result['functions']}fn/{result['edges']}e "
                      f"({result['elapsed_s']:.0f}s)")
                if cve_id not in progress["completed"]:
                    progress["completed"].append(cve_id)
            elif status == "empty":
                empty_count += 1
                err = result.get("error", "no functions")[:60]
                print(f"[{processed}/{len(valid_entries)} {pct:.0f}% {elapsed_total/60:.1f}m] "
                      f"{cve_id} ({entry['language']}): EMPTY ({err})")
                if cve_id not in progress["completed"]:
                    progress["completed"].append(cve_id)
            elif status == "timeout":
                timeout_count += 1
                print(f"[{processed}/{len(valid_entries)} {pct:.0f}% {elapsed_total/60:.1f}m] "
                      f"{cve_id} ({entry['language']}): TIMEOUT")
                if cve_id not in progress["failed"]:
                    progress["failed"].append(cve_id)
            else:
                error_count += 1
                err = result.get("error", "unknown")[:60]
                print(f"[{processed}/{len(valid_entries)} {pct:.0f}% {elapsed_total/60:.1f}m] "
                      f"{cve_id} ({entry['language']}): ERROR ({err})")
                if cve_id not in progress["failed"]:
                    progress["failed"].append(cve_id)

            save_json(PROGRESS_PATH, progress)

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"Done! Total time: {elapsed/60:.1f} min")
    print(f"  Success: {success_count}")
    print(f"  Empty:   {empty_count}")
    print(f"  Timeout: {timeout_count}")
    print(f"  Error:   {error_count}")

    progress = load_json(PROGRESS_PATH)
    print(f"\nFinal: {len(progress['completed'])} completed, {len(progress['failed'])} failed, {len(progress['skipped'])} skipped")


if __name__ == "__main__":
    main()
