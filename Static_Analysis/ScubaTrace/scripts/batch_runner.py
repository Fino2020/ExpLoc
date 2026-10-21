#!/usr/bin/python3
"""
Batch runner: Extract ScubaTrace ICFG for all 208 target CVEs.

Reads target_manifest.json, runs extract_icfg.py for each CVE,
saves results to Static_Analysis/Results/ScubaTrace/{CVE-ID}/.

Supports resume: skips CVEs that already have a completed summary.json.
"""

import json
import os
import subprocess
import sys
import time
import signal
import traceback
from datetime import datetime

RESULTS_DIR = "/mnt/d/Desktop/VulnLocalization/Static_Analysis/Results/ScubaTrace"
MANIFEST_PATH = os.path.join(RESULTS_DIR, "target_manifest.json")
EXTRACTOR = os.path.join(RESULTS_DIR, "extract_icfg.py")
TIMEOUT_PER_CVE = 600  # 10 minutes max per CVE
PROGRESS_PATH = os.path.join(RESULTS_DIR, "batch_progress.json")


def load_progress():
    if os.path.exists(PROGRESS_PATH):
        with open(PROGRESS_PATH) as f:
            return json.load(f)
    return {"completed": [], "failed": [], "skipped": [], "last_idx": -1}


def save_progress(progress):
    with open(PROGRESS_PATH, "w") as f:
        json.dump(progress, f, indent=2)


def run_one(cve_id, repo_path, language):
    cve_dir = os.path.join(RESULTS_DIR, cve_id)
    csv_path = os.path.join(cve_dir, "icfg_scubatrace.csv")
    summary_path = os.path.join(cve_dir, "summary.json")

    # Skip if already done
    if os.path.exists(summary_path):
        try:
            with open(summary_path) as f:
                existing = json.load(f)
            if existing.get("status") in ("success", "empty", "error"):
                return existing
        except Exception:
            pass

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

        # Parse result from stdout
        result = {
            "cve_id": cve_id,
            "language": language,
            "repo_path": repo_path,
            "elapsed_s": elapsed,
            "status": "error",
            "files": 0, "functions": 0, "edges": 0,
            "call_edges": 0, "cfg_edges": 0, "return_edges": 0,
        }

        if proc.returncode == 0:
            parsed = {}
            for line in stdout.splitlines():
                stripped = line.strip()
                for key in ["files", "functions", "edges", "call_edges",
                           "cfg_edges", "return_edges", "elapsed_s", "error"]:
                    if stripped.startswith(f"{key}:"):
                        val = stripped.split(":", 1)[1].strip()
                        if key == "error":
                            parsed[key] = val if val and val != "None" else None
                        elif key == "elapsed_s":
                            parsed[key] = float(val)
                        else:
                            parsed[key] = int(val)
            if parsed:
                result.update(parsed)

        if result.get("error"):
            result["status"] = "error"
        elif result["functions"] == 0:
            result["status"] = "empty"
        else:
            result["status"] = "success"

        result["elapsed_s"] = elapsed
        result["stdout"] = stdout[-2000:] if stdout else ""
        result["stderr"] = stderr[-1000:] if stderr else ""

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
            "elapsed_s": elapsed, "status": "error",
            "error": str(e),
        }

    # Save summary
    with open(summary_path, "w") as f:
        json.dump(result, f, indent=2)

    return result


def main():
    if not os.path.exists(MANIFEST_PATH):
        print(f"ERROR: Manifest not found: {MANIFEST_PATH}")
        sys.exit(1)

    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)

    progress = load_progress()
    completed_ids = set(progress["completed"] + progress["failed"] +
                        progress["skipped"])
    start_idx = progress.get("last_idx", -1) + 1

    print(f"Total targets: {len(manifest)}")
    print(f"Already done: {len(completed_ids)}")
    print(f"Starting from index: {start_idx}")
    print(f"Results dir: {RESULTS_DIR}")
    print()

    interrupted = False

    def sig_handler(sig, frame):
        nonlocal interrupted
        interrupted = True
        print("\n\nInterrupted! Saving progress...")

    signal.signal(signal.SIGINT, sig_handler)

    batch_start = time.time()
    processed = 0
    success_count = 0
    empty_count = 0
    error_count = 0
    timeout_count = 0

    for idx in range(start_idx, len(manifest)):
        if interrupted:
            break

        entry = manifest[idx]
        cve_id = entry["cve_id"]
        language = entry["language"]
        repo_path = entry["repo_path"]

        if cve_id in completed_ids:
            continue

        if not os.path.exists(repo_path):
            print(f"[{idx+1}/{len(manifest)}] {cve_id} ({language}) - REPO MISSING, skipping")
            progress["skipped"].append(cve_id)
            progress["last_idx"] = idx
            save_progress(progress)
            completed_ids.add(cve_id)
            continue

        elapsed_total = time.time() - batch_start
        print(f"[{idx+1}/{len(manifest)}] {cve_id} ({language}) [{elapsed_total/60:.1f}m] ...",
              end=" ", flush=True)

        result = run_one(cve_id, repo_path, language)
        status = result["status"]
        processed += 1

        if status == "success":
            success_count += 1
            print(f"OK: {result['files']}f/{result['functions']}fn/{result['edges']}e "
                  f"({result['elapsed_s']:.1f}s)")
            progress["completed"].append(cve_id)
        elif status == "empty":
            empty_count += 1
            print(f"EMPTY: {result.get('error', 'no functions')}")
            progress["completed"].append(cve_id)
        elif status == "timeout":
            timeout_count += 1
            print(f"TIMEOUT")
            progress["failed"].append(cve_id)
        else:
            error_count += 1
            err = result.get("error", "unknown")[:80]
            print(f"ERROR: {err}")
            progress["failed"].append(cve_id)

        progress["last_idx"] = idx
        save_progress(progress)
        completed_ids.add(cve_id)

    batch_elapsed = time.time() - batch_start
    print(f"\n{'='*60}")
    print(f"Batch complete! Elapsed: {batch_elapsed/60:.1f} min")
    print(f"  Processed: {processed}")
    print(f"  Success:   {success_count}")
    print(f"  Empty:     {empty_count}")
    print(f"  Timeout:   {timeout_count}")
    print(f"  Error:     {error_count}")
    print(f"  Total done: {len(progress['completed']) + len(progress['failed']) + len(progress['skipped'])}")
    print(f"Results saved to: {RESULTS_DIR}")


if __name__ == "__main__":
    main()
