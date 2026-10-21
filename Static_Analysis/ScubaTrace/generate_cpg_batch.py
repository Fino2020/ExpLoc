#!/usr/bin/python3
"""
Parallel batch runner: Generate Joern CPG for all target CVEs.

- Reads ScubaTrace_Results/target_manifest.json
- For each CVE: generate_cpg.py → cpg_to_icfg.py
- Skips if cpg.bin already valid
- Retries timeouts with 1800s limit
- 2 parallel workers (Joern is memory-heavy)
"""

import json
import os
import subprocess
import sys
import time
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

RESULTS_DIR = "/mnt/d/Desktop/VulnLocalization/Static_Analysis/Results/ScubaTrace"
MANIFEST_PATH = os.environ.get(
    "SCUBATRACE_MANIFEST",
    "/mnt/d/Desktop/VulnLocalization/Dataset/DataLeakageAssessment.json"
)
REPO_BASE = os.environ.get(
    "REPO_BASE",
    "/mnt/e/Desktop/Localization_Repo/Localization_Repo"
)

LANG_EXT = {".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
            ".py": "python", ".java": "java", ".js": "javascript", ".ts": "javascript",
            ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php"}


def _detect_language(repo_path):
    if not os.path.isdir(repo_path): return "unknown"
    counts = {}
    try:
        for root, dirs, files in os.walk(repo_path):
            if len(os.path.relpath(root, repo_path).split(os.sep)) > 5:
                dirs.clear(); continue
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in LANG_EXT:
                    counts[LANG_EXT[ext]] = counts.get(LANG_EXT[ext], 0) + 1
            if len(counts) > 5000: break
    except: pass
    return max(counts, key=counts.get) if counts else "unknown"


def _normalize_entries(raw_manifest):
    """Convert DataLeakageAssessment.json format to ScubaTrace manifest format.
    Auto-detects repo_path from REPO_BASE/{CVE-ID}/{Owner}/{Project} and language.
    """
    entries = []
    for item in raw_manifest:
        cve_id = item["cve_id"]
        commits = item.get("commit_list", [])
        if not commits: continue
        repo = commits[0]["repo"]
        owner, project = repo.split("/", 1) if "/" in repo else ("", repo)
        repo_path = os.path.join(REPO_BASE, cve_id, owner, project)
        if not os.path.isdir(os.path.join(repo_path, ".git")): continue
        lang = _detect_language(repo_path)
        entries.append({"cve_id": cve_id, "language": lang, "repo_path": repo_path})
    return entries
PROGRESS_PATH = os.path.join(RESULTS_DIR, "cpg_full_progress.json")
GENERATE_CPG = os.path.join(os.path.dirname(__file__), "generate_cpg.py")
CPG_TO_ICFG = os.path.join(os.path.dirname(__file__), "cpg_to_icfg.py")
JOERN_PARSE = "joern-parse"
TIMEOUT_INITIAL = 600
TIMEOUT_RETRY = 1800
MAX_WORKERS = 8


def load_json(path):
    with open(path) as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def process_one(entry, first_attempt=True):
    """Generate CPG + ICFG for one CVE. Returns (cve_id, result_dict)."""
    cve_id = entry["cve_id"]
    language = entry["language"]
    repo_path = entry["repo_path"]
    timeout = TIMEOUT_INITIAL if first_attempt else TIMEOUT_RETRY

    cve_dir = os.path.join(RESULTS_DIR, cve_id)
    cpg_path = os.path.join(cve_dir, "cpg.bin")
    icfg_path = os.path.join(cve_dir, "icfg_scubatrace.csv")
    summary_path = os.path.join(cve_dir, "cpg_summary.json")

    os.makedirs(cve_dir, exist_ok=True)

    # Step 1: Generate CPG
    start = time.time()
    proc = subprocess.run(
        [sys.executable, GENERATE_CPG, repo_path, language, cpg_path, str(timeout)],
        capture_output=True, text=True, timeout=timeout + 60,
    )

    if proc.returncode != 0:
        return cve_id, {
            "cve_id":    cve_id, "language": language,
            "elapsed_s": time.time() - start, "status": "error",
            "error":     f"generate_cpg.py failed: {proc.stderr[-200:] if proc.stderr else 'unknown'}",
        }

    # Parse output: look for RESULT_JSON: prefix
    cpg_result = { "status": "error", "error": "Failed to parse output" }
    for line in (proc.stdout or "").splitlines():
        if line.startswith("RESULT_JSON:"):
            try:
                cpg_result = json.loads(line[len("RESULT_JSON:"):])
            except json.JSONDecodeError:
                pass
            break

    cpg_status = cpg_result.get("status", "error")

    if cpg_status == "timeout":
        return cve_id, {
            "cve_id":    cve_id, "language": language,
            "elapsed_s": cpg_result.get("elapsed_s", 0),
            "status":    "timeout",
            "error":     cpg_result.get("error", ""),
        }

    if cpg_status == "skipped":
        return cve_id, {
            "cve_id":    cve_id, "language": language,
            "elapsed_s": 0, "status": "skipped",
            "error":     cpg_result.get("error", "Unsupported language"),
        }

    if cpg_status in ("error", "empty"):
        result = {
            "cve_id":           cve_id, "language": language,
            "elapsed_s":        cpg_result.get("elapsed_s", 0),
            "status":           cpg_status,
            "error":            cpg_result.get("error", ""),
            "cpg_node_count":   cpg_result.get("node_count", 0),
            "cpg_edge_count":   cpg_result.get("edge_count", 0),
            "cpg_method_count": cpg_result.get("method_count", 0),
        }
        save_json(summary_path, result)
        return cve_id, result

    # Step 2: Extract ICFG from CPG
    icfg_start = time.time()
    # Dynamic timeout based on CPG size: 300s base + 5s per MB (133MB = 965s)
    cpg_size_mb = os.path.getsize(cpg_path) / (1024 * 1024)
    icfg_timeout = max(300, int(300 + cpg_size_mb * 5))
    try:
        proc2 = subprocess.run(
            [sys.executable, CPG_TO_ICFG, cpg_path, icfg_path],
            capture_output=True, text=True, timeout=icfg_timeout,
        )
    except subprocess.TimeoutExpired:
        result = {
            "cve_id":           cve_id, "language": language,
            "elapsed_s":        time.time() - start,
            "status":           "timeout",
            "error":            f"cpg_to_icfg.py timeout after {icfg_timeout}s (cpg={cpg_size_mb:.0f}MB)",
            "cpg_node_count":   cpg_result.get("node_count", -1),
            "cpg_edge_count":   cpg_result.get("edge_count", -1),
            "cpg_method_count": cpg_result.get("method_count", -1),
        }
        save_json(summary_path, result)
        return cve_id, result

    if proc2.returncode != 0:
        result = {
            "cve_id":           cve_id, "language": language,
            "elapsed_s":        cpg_result.get("elapsed_s", 0),
            "status":           "error",
            "error":            f"cpg_to_icfg.py failed: {proc2.stderr[-200:] if proc2.stderr else 'unknown'}",
            "cpg_node_count":   cpg_result.get("node_count", 0),
            "cpg_edge_count":   cpg_result.get("edge_count", 0),
            "cpg_method_count": cpg_result.get("method_count", 0),
        }
        save_json(summary_path, result)
        return cve_id, result

    # Parse ICFG stats
    icfg_edges = 0
    icfg_cfg = 0
    icfg_call = 0
    icfg_return = 0
    icfg_methods = 0
    icfg_files = 0
    for line in (proc2.stdout or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("edges:"):
            icfg_edges = int(stripped.split(":")[1].strip())
        elif stripped.startswith("cfg_edges:"):
            icfg_cfg = int(stripped.split(":")[1].strip())
        elif stripped.startswith("call_edges:"):
            icfg_call = int(stripped.split(":")[1].strip())
        elif stripped.startswith("return_edges:"):
            icfg_return = int(stripped.split(":")[1].strip())
        elif stripped.startswith("methods:"):
            icfg_methods = int(stripped.split(":")[1].strip())
        elif stripped.startswith("files:"):
            icfg_files = int(stripped.split(":")[1].strip())

    elapsed = time.time() - start
    result = {
        "cve_id":            cve_id, "language": language,
        "elapsed_s":         elapsed,
        "status":            "success" if icfg_edges > 0 else "empty",
        "error":             None if icfg_edges > 0 else "ICFG extracted but has 0 edges",
        "cpg_node_count":    cpg_result.get("node_count", 0),
        "cpg_edge_count":    cpg_result.get("edge_count", 0),
        "cpg_method_count":  cpg_result.get("method_count", 0),
        "cpg_file_count":    cpg_result.get("file_count", 0),
        "icfg_edges":        icfg_edges,
        "icfg_cfg_edges":    icfg_cfg,
        "icfg_call_edges":   icfg_call,
        "icfg_return_edges": icfg_return,
        "icfg_methods":      icfg_methods,
        "icfg_files":        icfg_files,
    }
    save_json(summary_path, result)
    return cve_id, result


def main():
    manifest = _normalize_entries(load_json(MANIFEST_PATH))
    progress = load_json(PROGRESS_PATH) if os.path.exists(PROGRESS_PATH) else {
        "completed": [], "failed": [], "skipped": [], "stats": { }
    }

    done_ids = set(progress["completed"] + progress["failed"] + progress["skipped"])

    # Also skip CVEs that already have valid ICFG output
    for e in manifest:
        cve_id = e["cve_id"]
        if cve_id in done_ids:
            continue
        icfg_path = os.path.join(RESULTS_DIR, cve_id, "icfg_scubatrace.csv")
        if os.path.exists(icfg_path) and os.path.getsize(icfg_path) > 0:
            done_ids.add(cve_id)
            if cve_id not in progress["completed"]:
                progress["completed"].append(cve_id)
    save_json(PROGRESS_PATH, progress)

    remaining = [e for e in manifest if e["cve_id"] not in done_ids]

    # Also retry timeouts from failed list
    retry_ids = set()
    for cve_id in list(progress["failed"]):
        summary_path = os.path.join(RESULTS_DIR, cve_id, "cpg_summary.json")
        if os.path.exists(summary_path):
            s = load_json(summary_path)
            if s.get("status") == "timeout":
                retry_ids.add(cve_id)
                progress["failed"].remove(cve_id)
                save_json(PROGRESS_PATH, progress)

    # Add retry entries
    for e in manifest:
        if e["cve_id"] in retry_ids:
            remaining.append(e)

    if not remaining:
        print("All CVEs processed!")
        return

    # Verify repos exist, filter missing
    valid_entries = []
    missing_count = 0
    for e in remaining:
        if os.path.exists(e["repo_path"]):
            valid_entries.append(e)
        else:
            print(f"SKIP {e['cve_id']}: repo missing")
            if e["cve_id"] not in progress["skipped"]:
                progress["skipped"].append(e["cve_id"])
            missing_count += 1

    if missing_count:
        save_json(PROGRESS_PATH, progress)

    print(
        f"Total to process: {len(valid_entries)} ({len(retry_ids)} retry, "
        f"{len(valid_entries) - len(retry_ids)} new)"
    )
    print(
        f"Workers: {MAX_WORKERS} | Initial timeout: {TIMEOUT_INITIAL}s | "
        f"Retry timeout: {TIMEOUT_RETRY}s"
    )
    print()

    # Track which were retried vs first attempt
    is_retry = { e["cve_id"]: e["cve_id"] in retry_ids for e in valid_entries }

    interrupted = False

    def sig_handler(sig, frame):
        nonlocal interrupted
        interrupted = True
        print("\n\nInterrupt! Saving progress...")

    signal.signal(signal.SIGINT, sig_handler)

    start_time = time.time()
    processed = 0
    success = 0
    empty = 0
    timeout_count = 0
    error_count = 0
    skipped_count = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = { }
        for entry in valid_entries:
            if interrupted:
                break
            future = executor.submit(process_one, entry, first_attempt=not is_retry[entry["cve_id"]])
            future_map[future] = entry

        for future in as_completed(future_map):
            if interrupted:
                for f in future_map:
                    f.cancel()
                break

            entry = future_map[future]
            cve_id = entry["cve_id"]
            first = not is_retry.get(cve_id, True)

            try:
                cve_id, result = future.result()
            except Exception as e:
                result = { "cve_id": entry["cve_id"], "status": "error", "error": str(e) }

            status = result["status"]
            processed += 1
            elapsed_total = time.time() - start_time
            pct = 100 * processed / len(valid_entries)
            tag = "[RETRY]" if not first else ""

            if status == "success":
                success += 1
                print(
                    f"[{processed}/{len(valid_entries)} {pct:.0f}% {elapsed_total / 60:.1f}m] "
                    f"{tag} {cve_id} ({entry['language']}): "
                    f"CPG={result.get('cpg_method_count', '?')}m/"
                    f"ICFG={result.get('icfg_edges', '?')}e "
                    f"({result.get('elapsed_s', 0):.0f}s)"
                )
                if cve_id not in progress["completed"]:
                    progress["completed"].append(cve_id)
            elif status == "timeout":
                timeout_count += 1
                print(
                    f"[{processed}/{len(valid_entries)} {pct:.0f}% {elapsed_total / 60:.1f}m] "
                    f"{tag} {cve_id} ({entry['language']}): TIMEOUT "
                    f"({result.get('elapsed_s', 0):.0f}s)"
                )
                if not first:
                    # Already retried — give up
                    if cve_id not in progress["failed"]:
                        progress["failed"].append(cve_id)
                else:
                    # Schedule retry with longer timeout
                    timeout_count -= 1  # Don't count as final
                    print(f"  -> Scheduling retry with {TIMEOUT_RETRY}s timeout")
                    is_retry[cve_id] = True
                    future2 = executor.submit(process_one, entry, first_attempt=False)
                    future_map[future2] = entry
            elif status == "empty":
                empty += 1
                print(
                    f"[{processed}/{len(valid_entries)} {pct:.0f}% {elapsed_total / 60:.1f}m] "
                    f"{tag} {cve_id} ({entry['language']}): EMPTY "
                    f"({result.get('error', 'no ICFG edges')[:60]})"
                )
                if cve_id not in progress["completed"]:
                    progress["completed"].append(cve_id)
            elif status == "skipped":
                skipped_count += 1
                print(
                    f"[{processed}/{len(valid_entries)} {pct:.0f}% {elapsed_total / 60:.1f}m] "
                    f"{tag} {cve_id} ({entry['language']}): SKIP "
                    f"({result.get('error', '')[:60]})"
                )
                if cve_id not in progress["skipped"]:
                    progress["skipped"].append(cve_id)
            else:
                error_count += 1
                err = result.get("error", "unknown")[:80]
                print(
                    f"[{processed}/{len(valid_entries)} {pct:.0f}% {elapsed_total / 60:.1f}m] "
                    f"{tag} {cve_id} ({entry['language']}): ERROR ({err})"
                )
                if cve_id not in progress["failed"]:
                    progress["failed"].append(cve_id)

            save_json(PROGRESS_PATH, progress)

    elapsed = time.time() - start_time
    print(f"\n{'=' * 60}")
    print(f"Batch done! Total: {elapsed / 60:.1f} min")
    print(
        f"  Success: {success}  Empty: {empty}  Timeout: {timeout_count}  "
        f"Error: {error_count}  Skipped: {skipped_count}"
    )
    print(f"  Completed: {len(progress['completed'])}")
    print(f"  Failed: {len(progress['failed'])}")
    print(f"  Skipped: {len(progress['skipped'])}")


if __name__ == "__main__":
    main()
