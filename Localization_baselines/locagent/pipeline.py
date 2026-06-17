"""
LocAgent baseline pipeline — run LocAgent agent on the VulnLocalization dataset.

Loads dataset, sets up ICFG graph + BM25 per CVE, runs multi-turn agent,
merges multi-sample results, and outputs result.json per CVE.
"""

import json
import logging
import os
import sys
import time
import traceback
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

# Add project root for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from shared.config import (
    DATASET_PATH, REPO_BASE, SCUBA_RESULTS_DIR, PROJECT_ROOT,
)

from .graph_adapter import GraphAdapter
from .bm25_retriever import BM25Retriever
from .tools import init_tools

logger = logging.getLogger(__name__)

# Output dir
OUTPUT_BASE = os.path.join(PROJECT_ROOT, "Results", "Localization", "LocAgent")
BM25_CACHE_DIR = os.path.join(PROJECT_ROOT, "Localization", "locagent", "bm25_cache")

# ICFG source priority
ICFG_SOURCES = [
    ("scubatrace", lambda cve: os.path.join(SCUBA_RESULTS_DIR, cve, "icfg_scubatrace.csv")),
    ("codeql", lambda cve: os.path.join(os.path.dirname(SCUBA_RESULTS_DIR), "CodeQL", cve, "icfg_icfg_db.csv")),
    ("codeql2", lambda cve: os.path.join(os.path.dirname(SCUBA_RESULTS_DIR), "CodeQL", cve, "icfg_icfg.csv")),
]


def load_dataset(dataset_path: str = DATASET_PATH) -> List[dict]:
    with open(dataset_path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_issue_info(cve_entry: dict) -> Tuple[str, str, str]:
    """Extract title, body, and repo name from a CVE entry."""
    cve_id = cve_entry["cve_id"]
    issues = cve_entry.get("issue_list", [])
    if issues:
        title = issues[0].get("title", "")
        body = issues[0].get("body", "")
        repo = issues[0].get("repo", "")
    else:
        title = cve_id
        body = cve_id
        repo = ""
    return title, body, repo


def find_repo_path(cve_id: str, repo: str) -> Optional[str]:
    """Find the repo directory for a CVE."""
    # Path: REPO_BASE/{CVE-ID}/{Owner}/{Project}
    if repo and "/" in repo:
        owner, project = repo.split("/", 1)
        candidate = os.path.join(REPO_BASE, cve_id, owner, project)
        if os.path.isdir(candidate):
            return candidate

    # Try scanning REPO_BASE/{CVE-ID} for any subdirectory
    cve_dir = os.path.join(REPO_BASE, cve_id)
    if os.path.isdir(cve_dir):
        for item in os.listdir(cve_dir):
            item_path = os.path.join(cve_dir, item)
            if os.path.isdir(item_path):
                # Check if it contains another level
                sub_items = os.listdir(item_path)
                for sub_item in sub_items:
                    sub_path = os.path.join(item_path, sub_item)
                    if os.path.isdir(sub_path) and _has_source_files(sub_path):
                        return sub_path
                if _has_source_files(item_path):
                    return item_path
    return None


def _has_source_files(path: str) -> bool:
    """Check if a directory contains source code files."""
    code_exts = {".py", ".c", ".cpp", ".java", ".go", ".rs", ".js", ".ts", ".rb", ".php", ".h"}
    try:
        for root, _, files in os.walk(path):
            for f in files[:50]:  # check first 50 files
                if os.path.splitext(f)[1].lower() in code_exts:
                    return True
            break
    except Exception:
        pass
    return False


def find_icfg_path(cve_id: str) -> Optional[str]:
    """Find ICFG CSV for a CVE, trying multiple sources."""
    for source_name, path_fn in ICFG_SOURCES:
        path = path_fn(cve_id)
        if os.path.exists(path):
            return path
    return None


def merge_samples(all_files: List[List[str]], all_modules: List[List[str]],
                  all_functions: List[List[str]], method: str = "mrr") -> Tuple[List[str], List[str], List[str]]:
    """Merge results from multiple samples using MRR weighting."""

    def rank_locs(found_locs: List[List[str]]) -> List[str]:
        weights = Counter()
        if method == "mrr":
            for sample_locs in found_locs:
                for rank, loc in enumerate(sample_locs, start=1):
                    weights[loc] += 1.0 / rank
        else:  # majority
            for sample_locs in found_locs:
                for loc in sample_locs:
                    weights[loc] += 1
        ranked = sorted(weights.items(), key=lambda x: x[1], reverse=True)
        return [loc for loc, _ in ranked]

    return (
        rank_locs(all_files),
        rank_locs(all_modules),
        rank_locs(all_functions),
    )


def process_cve(cve_entry: dict, num_samples: int = 2,
                max_iterations: int = 30) -> Optional[dict]:
    """Process a single CVE: set up graph, run agent, return result."""
    cve_id = cve_entry["cve_id"]
    title, body, repo_name = get_issue_info(cve_entry)

    # Find repo
    repo_path = find_repo_path(cve_id, repo_name)
    if not repo_path:
        logger.warning(f"[{cve_id}] Repo not found, skipping")
        return None

    # Find ICFG
    icfg_path = find_icfg_path(cve_id)
    if not icfg_path:
        logger.warning(f"[{cve_id}] No ICFG found, skipping")
        return None

    logger.info(f"[{cve_id}] Repo: {repo_path}")
    logger.info(f"[{cve_id}] ICFG: {icfg_path}")

    # Build graph adapter
    graph = GraphAdapter(icfg_path, repo_path)

    # Build BM25 index (with caching)
    bm25_cache_path = os.path.join(BM25_CACHE_DIR, f"{cve_id}.json")
    bm25 = BM25Retriever()
    if os.path.exists(bm25_cache_path):
        try:
            bm25 = BM25Retriever.load(bm25_cache_path)
            logger.debug(f"[{cve_id}] Loaded cached BM25")
        except Exception as e:
            logger.warning(f"[{cve_id}] BM25 cache load failed: {e}, re-indexing")
    if not bm25._built:
        try:
            bm25.index_repo(repo_path)
            bm25.save(bm25_cache_path)
        except Exception as e:
            logger.warning(f"[{cve_id}] BM25 index failed: {e}, using empty index")

    # Initialize tools
    init_tools(graph, bm25, repo_path)

    # Run agent (multiple samples)
    from .agent import run_agent

    all_found_files = []
    all_found_modules = []
    all_found_functions = []
    total_tokens = {"prompt": 0, "completion": 0}

    for sample_idx in range(num_samples):
        logger.info(f"[{cve_id}] Sample {sample_idx + 1}/{num_samples}")
        try:
            files, modules, funcs, meta = run_agent(
                issue_title=title,
                issue_body=body,
                repo_path=repo_path,
                max_iterations=max_iterations,
                temperature=0.7 + sample_idx * 0.1,  # slight variation between samples
            )
            all_found_files.append(files)
            all_found_modules.append(modules)
            all_found_functions.append(funcs)
            logger.info(f"[{cve_id}] Files found: {files}")
            logger.info(f"[{cve_id}] Functions found: {funcs[:5]}")
            if meta.get("final_output_snippet"):
                logger.info(f"[{cve_id}] Final output snippet: {meta['final_output_snippet'][:300]}")
            total_tokens["prompt"] += meta.get("prompt_tokens", 0)
            total_tokens["completion"] += meta.get("completion_tokens", 0)
            logger.info(f"[{cve_id}] Sample {sample_idx + 1}: "
                        f"{len(files)} files, {len(funcs)} functions")
        except Exception as e:
            logger.error(f"[{cve_id}] Sample {sample_idx + 1} failed: {e}")
            traceback.print_exc()
            all_found_files.append([])
            all_found_modules.append([])
            all_found_functions.append([])

    # Merge samples
    if any(any(s) for s in all_found_files):
        ranked_files, ranked_modules, ranked_funcs = merge_samples(
            all_found_files, all_found_modules, all_found_functions)
    else:
        ranked_files, ranked_modules, ranked_funcs = [], [], []

    # Build result.json in project format
    result = {
        "cve_id": cve_id,
        "vulnerable_files": [
            {"file": f, "score": round(1.0 / (i + 1), 4)}
            for i, f in enumerate(ranked_files)
        ],
        "vulnerable_functions": [
            {
                "function": func.split(":")[-1] if ":" in func else func,
                "file": func.split(":")[0] if ":" in func else "",
                "score": round(1.0 / (i + 1), 4),
            }
            for i, func in enumerate(ranked_funcs)
        ],
        "vulnerable_modules": ranked_modules,
        "raw_outputs": {
            "files_per_sample": all_found_files,
            "modules_per_sample": all_found_modules,
            "functions_per_sample": all_found_functions,
        },
        "metadata": {
            "repo": repo_name,
            "repo_path": repo_path,
            "icfg_path": icfg_path,
            "num_samples": num_samples,
            "total_prompt_tokens": total_tokens["prompt"],
            "total_completion_tokens": total_tokens["completion"],
        },
    }

    return result


def run_pipeline(
    dataset_path: str = DATASET_PATH,
    output_base: str = OUTPUT_BASE,
    num_samples: int = 2,
    max_iterations: int = 30,
    num_workers: int = 1,
    limit: int = 0,
    skip: int = 0,
    cves: Optional[List[str]] = None,
):
    """Run LocAgent pipeline on the dataset.

    Args:
        dataset_path: path to the dataset JSON.
        output_base: directory to save results.
        num_samples: number of agent samples per CVE (merged via MRR).
        max_iterations: max turns per agent run.
        num_workers: parallel workers (1 = sequential).
        limit: max number of CVEs to process (0 = all).
        skip: skip first N CVEs.
        cves: specific CVE IDs to process.
    """
    dataset = load_dataset(dataset_path)

    # Filter
    if cves:
        cve_set = set(cves)
        dataset = [d for d in dataset if d["cve_id"] in cve_set]
    if skip:
        dataset = dataset[skip:]
    if limit:
        dataset = dataset[:limit]

    total = len(dataset)
    logger.info(f"Processing {total} CVEs with {num_workers} workers")

    os.makedirs(output_base, exist_ok=True)

    # Track processed
    processed = set()
    for cve_entry in dataset:
        cve_id = cve_entry["cve_id"]
        out_dir = os.path.join(output_base, cve_id)
        if os.path.exists(os.path.join(out_dir, "result.json")):
            processed.add(cve_id)

    pending = [d for d in dataset if d["cve_id"] not in processed]
    logger.info(f"Already processed: {len(processed)}, pending: {len(pending)}")

    if not pending:
        logger.info("All CVEs already processed")
        return

    if num_workers <= 1:
        # Sequential
        for i, cve_entry in enumerate(pending):
            cve_id = cve_entry["cve_id"]
            logger.info(f"[{i + 1}/{len(pending)}] Processing {cve_id}")
            try:
                result = process_cve(cve_entry, num_samples, max_iterations)
                if result:
                    save_result(result, output_base)
                    logger.info(f"[{cve_id}] Saved result with "
                                f"{len(result['vulnerable_files'])} files, "
                                f"{len(result['vulnerable_functions'])} functions")
            except Exception as e:
                logger.error(f"[{cve_id}] Failed: {e}")
                traceback.print_exc()
    else:
        # Parallel
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = {}
            for cve_entry in pending:
                future = executor.submit(_process_worker, cve_entry, num_samples, max_iterations)
                futures[future] = cve_entry["cve_id"]

            completed = 0
            for future in as_completed(futures):
                cve_id = futures[future]
                completed += 1
                try:
                    result = future.result(timeout=600)
                    if result:
                        save_result(result, output_base)
                        logger.info(f"[{completed}/{len(pending)}] {cve_id}: "
                                    f"{len(result['vulnerable_files'])} files, "
                                    f"{len(result['vulnerable_functions'])} functions")
                    else:
                        logger.warning(f"[{completed}/{len(pending)}] {cve_id}: skipped")
                except Exception as e:
                    logger.error(f"[{completed}/{len(pending)}] {cve_id}: failed - {e}")

    logger.info("Pipeline complete")


def _process_worker(cve_entry: dict, num_samples: int, max_iterations: int) -> Optional[dict]:
    """Worker function for multiprocessing (module-level for pickling)."""
    logging.basicConfig(level=logging.WARNING)
    return process_cve(cve_entry, num_samples, max_iterations)


def save_result(result: dict, output_base: str):
    """Save a single CVE result to output directory."""
    cve_id = result["cve_id"]
    out_dir = os.path.join(output_base, cve_id)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "result.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="LocAgent baseline pipeline")
    parser.add_argument("--dataset", default=DATASET_PATH)
    parser.add_argument("--output", default=OUTPUT_BASE)
    parser.add_argument("--num-samples", type=int, default=2)
    parser.add_argument("--max-iterations", type=int, default=30)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--skip", type=int, default=0)
    parser.add_argument("--cves", type=str, default="")
    parser.add_argument("--log-level", type=str, default="INFO")

    args = parser.parse_args()

    cves = [c.strip() for c in args.cves.split(",") if c.strip()] if args.cves else None
    os.makedirs(args.output, exist_ok=True)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.FileHandler(os.path.join(args.output, "pipeline.log")),
            logging.StreamHandler(),
        ],
    )

    start = time.time()
    run_pipeline(
        dataset_path=args.dataset,
        output_base=args.output,
        num_samples=args.num_samples,
        max_iterations=args.max_iterations,
        num_workers=args.workers,
        limit=args.limit,
        skip=args.skip,
        cves=cves,
    )
    elapsed = time.time() - start
    logger.info(f"Total time: {elapsed / 60:.1f} min")
