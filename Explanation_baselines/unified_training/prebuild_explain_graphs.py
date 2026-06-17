"""Pre-build and cache PyG graphs for all CVE functions in localization dataset.

Output: EXPLAIN_CACHE/{cve_id}/{func_name}.pt  (PyG Data with .y=0, .gt_lines, .func_range)
"""
import os, sys, json, subprocess
import torch

sys.path.insert(0, os.path.dirname(__file__))
from config import REPO_BASE

GRAPH_CACHE_DIR = os.path.join(os.path.dirname(__file__), "explain_cache")
GT_DIR = "/mnt/d/Desktop/VulnLocalization/Dataset/GT"
MANIFEST_PATH = "/mnt/d/Desktop/VulnLocalization/Dataset/dataset_with_changed_files_filter.json"


def load_gt(cve_id):
    gt_path = os.path.join(GT_DIR, f"{cve_id}.json")
    if not os.path.exists(gt_path):
        return None
    with open(gt_path) as f:
        return json.load(f)


def get_source(repo_base, cve_id, owner, project, file_path, commit_sha=None):
    repo_dir = os.path.join(repo_base, cve_id, owner, project)
    if not os.path.isdir(repo_dir):
        repo_dir = os.path.join(repo_base, f"{owner}_{project}")
    if not os.path.isdir(repo_dir):
        return None

    file_full = os.path.join(repo_dir, file_path)
    if os.path.exists(file_full):
        try:
            with open(file_full, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception:
            pass

    try:
        ref = commit_sha if commit_sha else "HEAD"
        result = subprocess.run(
            ["git", "show", f"{ref}:{file_path}"],
            cwd=repo_dir, capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return result.stdout
    except Exception:
        pass
    return None


def extract_function_source(file_content, func_name, func_ranges):
    if not file_content:
        return None
    lines = file_content.split('\n')

    if func_ranges and func_name in func_ranges:
        rng = func_ranges[func_name]
        start, end = rng[0], rng[1]
        if start > 0 and end >= start:
            return '\n'.join(lines[start-1:end])

    import re
    escaped = re.escape(func_name)
    for i, line in enumerate(lines):
        if re.search(rf'\b{escaped}\b', line):
            brace_count = 0
            started = False
            func_lines = []
            for j in range(i, min(i+500, len(lines))):
                func_lines.append(lines[j])
                brace_count += lines[j].count('{') - lines[j].count('}')
                if '{' in lines[j]:
                    started = True
                if started and brace_count == 0:
                    return '\n'.join(func_lines)
            if func_lines:
                return '\n'.join(func_lines)
    return None


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--workers", type=int, default=1, help="Sequential only (tree-sitter not fork-safe)")
    args = parser.parse_args()

    os.makedirs(GRAPH_CACHE_DIR, exist_ok=True)
    print(f"Cache dir: {GRAPH_CACHE_DIR}")

    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)

    if args.limit > 0:
        manifest = manifest[:args.limit]

    total_funcs = 0
    cached = 0
    skipped_no_source = 0
    skipped_no_func = 0

    for idx, entry in enumerate(manifest):
        cve_id = entry["cve_id"]
        repo_full = entry.get("issue_list", [{}])[0].get("repo", "")
        if "/" in repo_full:
            owner, project = repo_full.split("/", 1)
        else:
            owner, project = "", ""

        fixing_commit = ""
        for c in entry.get("commit_list", []):
            cid = c.get("commit_id", c.get("sha", ""))
            if cid:
                fixing_commit = cid
                break

        gt = load_gt(cve_id)
        if not gt:
            continue

        func_names = gt.get("changed_functions", [])
        if not func_names:
            skipped_no_func += 1
            continue

        func_ranges = gt.get("func_ranges", {})
        changed_lines = gt.get("changed_lines", {})

        cve_cache_dir = os.path.join(GRAPH_CACHE_DIR, cve_id)
        os.makedirs(cve_cache_dir, exist_ok=True)

        for fname in func_names:
            total_funcs += 1
            cache_path = os.path.join(cve_cache_dir, f"{fname}.pt")

            if os.path.exists(cache_path):
                cached += 1
                continue

            file_path = None
            func_range = None

            for fpath, fns in func_ranges.items():
                if fname in fns:
                    file_path = fpath
                    func_range = fns[fname]
                    break

            if not file_path:
                for fpath in changed_lines:
                    file_path = fpath
                    break

            if not file_path:
                continue

            gt_lines = changed_lines.get(file_path, [])
            if not gt_lines:
                continue

            source = get_source(REPO_BASE, cve_id, owner, project, file_path, fixing_commit)
            if not source:
                skipped_no_source += 1
                continue

            func_ranges_flat = {fname: func_range} if func_range else {}
            func_source = extract_function_source(source, fname, func_ranges_flat)
            if not func_source or len(func_source.strip()) < 10:
                continue

            from graph_builder import build_pyg_graph
            graph = build_pyg_graph(f"{cve_id}_{fname}", func_source)
            if graph is None or graph.x.shape[0] < 2:
                continue

            # Attach metadata
            graph.gt_lines = torch.tensor(gt_lines, dtype=torch.long)
            graph.func_offset = func_range[0] - 1 if func_range else 0

            torch.save(graph, cache_path)

        if (idx + 1) % 10 == 0:
            print(f"  [{idx+1:3d}/{len(manifest)}] {cve_id}: total_funcs={total_funcs} "
                  f"cached={cached} skipped_source={skipped_no_source}", flush=True)

    print(f"\n{'='*50}")
    print(f"  Total functions: {total_funcs}")
    print(f"  Already cached:  {cached}")
    print(f"  Newly cached:    {total_funcs - cached - skipped_no_source}")
    print(f"  Skipped (no source): {skipped_no_source}")
    print(f"  Skipped (no func):   {skipped_no_func}")
    print(f"  Cache dir: {GRAPH_CACHE_DIR}")


if __name__ == "__main__":
    main()
