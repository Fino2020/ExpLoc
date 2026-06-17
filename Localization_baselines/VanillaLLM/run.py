"""
VanillaLLM — Pure LLM baseline for vulnerability localization.

No agent. No tools. No KG. No retrieval.
Reads the CVE issue report + repository source code, sends everything
in a single LLM call, and asks the LLM to predict vulnerable files/functions.

Compares against:
  - Step1 (full KG + multi-turn agent)
  - NoKG (no KG, but still has agent with tools)
  - RepoMem (commits-only KG, single-pass LLM)
"""

import io
import json
import os
import sys
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from typing import List, Optional, Tuple

import httpx
from openai import OpenAI

# Reuse shared config for LLM backends
_LOCALIZATION_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Localization")
if _LOCALIZATION_DIR not in sys.path:
    sys.path.insert(0, _LOCALIZATION_DIR)

from shared.config import (
    OPENAI_DS_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL,
    DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL,
)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH = os.path.join(BASE_DIR, "Dataset", "dataset_with_changed_files_filter.json")
REPO_BASE = os.getenv("REPO_BASE", "/mnt/e/Desktop/Localization_Repo/Localization_Repo")
DEFAULT_OUTPUT_DIR = os.path.join(BASE_DIR, "Results", "VanillaLLM")


# ---------------------------------------------------------------------------
# LLM backend
# ---------------------------------------------------------------------------

def _get_all_backends() -> List[Tuple[OpenAI, str]]:
    backends = []
    if OPENAI_DS_API_KEY and OPENAI_BASE_URL:
        backends.append((
            OpenAI(api_key=OPENAI_DS_API_KEY, base_url=OPENAI_BASE_URL, max_retries=2,
                   timeout=httpx.Timeout(300.0, connect=30.0, read=300.0)),
            OPENAI_MODEL,
        ))
    if DEEPSEEK_API_KEY:
        backends.append((
            OpenAI(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL, max_retries=2,
                   timeout=httpx.Timeout(300.0, connect=30.0, read=300.0)),
            DEEPSEEK_MODEL,
        ))
    if not backends:
        raise RuntimeError("No LLM API key configured. Check .env file.")
    return backends


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a vulnerability localization expert. You receive a CVE report and the source code of the affected repository. Your task is to identify which files and functions are most likely related to the vulnerability.

Follow these rules:
1. Focus on the ROOT CAUSE, not symptoms. Prefer input parsers, validators, deserializers, and entry points mentioned or implied by the CVE description.
2. For each suspicious file, assign a score from 0.10 to 1.00. Use the full range — top predictions should have scores >= 0.70.
3. For each suspicious function, indicate which file it belongs to and estimate start_line/end_line based on the provided source code.
4. Only predict functions you can SEE in the provided source code. Do not invent function names.
5. Provide a brief reason for each prediction.
6. Output ONLY valid JSON, no markdown or commentary."""


def build_issue_description(entry: dict) -> Tuple[str, str, str]:
    """Extract (title, body, combined) from a manifest entry."""
    title = ""
    body = ""
    for issue in entry.get("issue_list", []):
        if not title:
            title = issue.get("title", "")
        if not body:
            body = issue.get("body", "") or ""
        for event in issue.get("events", []):
            event_body = event.get("body", "")
            if event_body and len(body) < 3000:
                body += f"\n[Comment]: {event_body[:500]}"
    combined = f"Title: {title}\n\nDescription:\n{body}"
    return title, body, combined


# ---------------------------------------------------------------------------
# Repository analysis (no KG, no tree-sitter, just file system)
# ---------------------------------------------------------------------------

SOURCE_EXTS = {
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx",
    ".py", ".java", ".js", ".ts", ".jsx", ".tsx",
    ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".scala",
    ".cs", ".m", ".mm", ".r",
}
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", "vendor",
    "target", "build", "dist", ".svn", ".hg", ".deps",
    "test", "tests", "spec", "examples", "demo", "docs",
}
PRIORITY_DIRS = {
    "src", "lib", "app", "main", "source", "core", "modules", "include",
    "pkg", "cmd", "internal",
}


def get_directory_section(repo_path: str, depth: int = 3) -> str:
    """Build directory tree view of the repository."""
    if not os.path.isdir(repo_path):
        return "DIRECTORY STRUCTURE: Not available"

    lines = ["## Directory Structure", ""]
    repo_name = os.path.basename(repo_path.rstrip("/"))

    for root, dirs, files in os.walk(repo_path):
        rel = os.path.relpath(root, repo_path)
        if rel == ".":
            rel = ""

        current_depth = len(rel.split(os.sep)) if rel else 0
        if current_depth >= depth:
            dirs.clear()
            continue

        dirs[:] = sorted(d for d in dirs
                        if not d.startswith(".") and d not in SKIP_DIRS)

        indent = "  " * current_depth
        dir_name = os.path.basename(root) if rel else repo_name
        lines.append(f"{indent}{dir_name}/")

        for f in sorted(files)[:30]:
            if f.startswith("."):
                continue
            lines.append(f"{indent}  {f}")

    return "\n".join(lines[:200])


def collect_source_files(repo_path: str, max_files: int = 20) -> List[Tuple[str, str, int]]:
    """Collect source files from repo, ranked by priority + size.

    Returns list of (rel_path, ext, size_bytes), sorted best-first.
    """
    candidates = []
    for root, dirs, files in os.walk(repo_path):
        rel = os.path.relpath(root, repo_path)
        depth = 0 if rel == "." else len(rel.split(os.sep))
        if depth > 4:
            dirs.clear()
            continue

        dirs[:] = sorted(d for d in dirs
                        if not d.startswith(".") and d not in SKIP_DIRS)

        for f in sorted(files):
            if f.startswith("."):
                continue
            ext = os.path.splitext(f)[1].lower()
            if ext not in SOURCE_EXTS:
                continue

            fpath = os.path.join(root, f)
            rel_path = os.path.relpath(fpath, repo_path)

            # Score: priority dir match + file size
            in_priority = 1 if set(rel_path.split(os.sep)) & PRIORITY_DIRS else 0
            try:
                size = os.path.getsize(fpath)
            except OSError:
                size = 0

            # Prefer medium-large files (not tiny, not massive)
            # 2KB-200KB is sweet spot
            size_score = min(size, 200_000) / 200_000 if size > 2000 else 0.0

            candidates.append((rel_path, ext, size, in_priority, size_score))

    # Sort: priority first, then size score
    candidates.sort(key=lambda x: (x[3], x[4]), reverse=True)
    return [(c[0], c[1], c[2]) for c in candidates[:max_files]]


def read_source_files(repo_path: str, files: List[Tuple[str, str, int]],
                      max_per_file: int = 6000) -> str:
    """Read source file contents and format them for the prompt.

    Args:
        repo_path: absolute path to repo
        files: list of (rel_path, ext, size)
        max_per_file: max characters per file

    Returns formatted string with file contents.
    """
    lines = ["## Key Source Files", ""]
    total_chars = 0
    max_total = 80_000

    for i, (rel_path, ext, size) in enumerate(files):
        fpath = os.path.join(repo_path, rel_path)
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(max_per_file)
        except Exception:
            content = "[Could not read file]"

        kb = size / 1024
        lang = ext.lstrip(".")
        header = f"### [{i+1}] {rel_path} ({lang}, {kb:.0f} KB)"

        if total_chars + len(header) + len(content) > max_total:
            remaining = max_total - total_chars - len(header) - 100
            if remaining > 500:
                content = content[:remaining] + "\n... [truncated]"
            else:
                break

        lines.append(header)
        lines.append("")
        lines.append(content)
        lines.append("")

        total_chars += len(header) + len(content) + 3

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Localizer
# ---------------------------------------------------------------------------

class VanillaLLMLocalizer:
    """Pure LLM vulnerability localizer — one call, no tools."""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self._backends = _get_all_backends()

    def localize(
        self,
        cve_id: str,
        issue_title: str,
        issue_body: str,
    ) -> dict:
        """Run single-pass LLM localization.

        Returns result dict with vulnerable_files, vulnerable_functions, etc.
        """
        t0 = time.time()

        # 1. Build directory section
        dir_section = get_directory_section(self.repo_path)

        # 2. Collect and read key source files
        source_files = collect_source_files(self.repo_path, max_files=20)
        source_section = read_source_files(self.repo_path, source_files) if source_files else "## Key Source Files\n\nNo source files found."

        # 3. Build prompt
        user_prompt = f"""## Vulnerability Report

CVE: {cve_id}
{issue_title and f"Title: {issue_title}"}

{issue_body and f"Description:\n{issue_body}"}

{dir_section}

{source_section}

## Task

Based on the CVE report and source code above, identify the files and functions most likely related to this vulnerability.

Output a JSON object with these fields:
- "vulnerable_files": array of {{"file": "path/to/file", "score": 0.0-1.0, "reason": "..."}}
- "vulnerable_functions": array of {{"function": "name", "file": "path/to/file", "score": 0.0-1.0, "start_line": N, "end_line": N, "reason": "..."}}
- "confidence": "high" or "medium" or "low"
- "analysis_summary": brief explanation of your reasoning (2-4 sentences)

IMPORTANT:
- Rank files/functions by likelihood of being the vulnerability location
- Use the FULL 0.10-1.00 score range. Top-3 files should have scores >= 0.70.
- Only predict functions you can SEE in the provided source code. Do not invent function names.
- Estimate start_line/end_line from the source code shown above.
- Output ONLY valid JSON, no markdown fences, no extra text."""

        # 4. Call LLM with fallback
        response_text = None
        last_error = None

        for client, model in self._backends:
            try:
                resp = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=0.01,
                    max_tokens=4096,
                )
                response_text = resp.choices[0].message.content
                if response_text:
                    break
            except Exception as e:
                last_error = e
                continue

        if response_text is None:
            raise RuntimeError(f"All LLM backends failed. Last error: {last_error}")

        # 5. Parse JSON response
        result = self._parse_response(response_text)
        result["cve_id"] = cve_id
        result["elapsed_seconds"] = round(time.time() - t0, 1)
        result["mode"] = "vanilla_llm_single_pass"
        result["source_files_read"] = len(source_files)

        return result

    @staticmethod
    def _parse_response(text: str) -> dict:
        """Parse LLM JSON response, with cleanup for common formatting issues."""
        # Remove markdown fences
        text = text.strip()
        if text.startswith("```"):
            # Find the first newline after opening fence
            idx = text.find("\n")
            if idx > 0:
                text = text[idx + 1:]
            if text.endswith("```"):
                text = text[:-3]

        # Find first '{' and last '}'
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            text = text[start:end + 1]

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Fallback: try to extract structured data with regex
            data = _emergency_parse(text)

        return data

    def close(self):
        pass


def _emergency_parse(text: str) -> dict:
    """Emergency parser when JSON is malformed. Extracts file/function names via regex."""
    import re

    result = {
        "vulnerable_files": [],
        "vulnerable_functions": [],
        "confidence": "low",
        "analysis_summary": f"JSON parse failed. Raw: {text[:500]}",
        "parse_error": True,
    }

    # Try to extract file paths
    file_pattern = re.findall(
        r'"file"\s*:\s*"([^"]+)"', text
    )
    for f in file_pattern:
        if f not in [x["file"] for x in result["vulnerable_files"]]:
            result["vulnerable_files"].append({
                "file": f, "score": 0.5, "reason": "Extracted from malformed JSON"
            })

    # Try to extract function names
    func_pattern = re.findall(
        r'"function"\s*:\s*"([^"]+)"', text
    )
    for fn in func_pattern:
        if fn not in [x["function"] for x in result["vulnerable_functions"]]:
            result["vulnerable_functions"].append({
                "function": fn, "file": "", "score": 0.5,
                "start_line": 0, "end_line": 0,
                "reason": "Extracted from malformed JSON"
            })

    return result


# ---------------------------------------------------------------------------
# Manifest helpers
# ---------------------------------------------------------------------------

def load_manifest(path: str = MANIFEST_PATH) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


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
    if not entry.get("repo_path"):
        owner = entry.get("owner", "")
        project = entry.get("project", "")
        if owner and project:
            # Try CVE-ID based path
            cve_path = os.path.join(REPO_BASE, entry["cve_id"], owner, project)
            if os.path.isdir(os.path.join(cve_path, ".git")):
                entry["repo_path"] = cve_path
            else:
                # Fallback
                entry["repo_path"] = os.path.join(REPO_BASE, f"{owner}_{project}")
    return entry


# ---------------------------------------------------------------------------
# Worker function (module-level for ProcessPoolExecutor pickling)
# ---------------------------------------------------------------------------

def _process_single_cve(args: Tuple[dict, str]) -> dict:
    """Process a single CVE — entrypoint for ProcessPoolExecutor.

    Args:
        args: (entry, output_dir) tuple

    Returns: dict with cve_id, success, elapsed, n_files, n_funcs, error, log
    """
    entry, output_dir = args
    entry = _normalize_entry(entry)
    cve_id = entry["cve_id"]
    owner = entry.get("owner", "?")
    project = entry.get("project", "?")
    repo_path = entry.get("repo_path", "")

    log_buf = io.StringIO()

    def _log(msg: str):
        log_buf.write(msg + "\n")

    t0 = time.time()

    try:
        # Pre-checks
        if not repo_path or not os.path.isdir(os.path.join(repo_path, ".git")):
            _log(f"SKIP: repo not found at {repo_path}")
            cve_dir = os.path.join(output_dir, cve_id)
            os.makedirs(cve_dir, exist_ok=True)
            with open(os.path.join(cve_dir, "result.json"), "w", encoding="utf-8") as f:
                json.dump({
                    "cve_id": cve_id, "error": "repo_not_found",
                    "vulnerable_files": [], "vulnerable_functions": [],
                }, f)
            return {
                "cve_id": cve_id, "success": True, "skipped": True,
                "elapsed": time.time() - t0, "n_files": 0, "n_funcs": 0,
                "skip_reason": "repo_not_found", "log": log_buf.getvalue(),
            }

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

        # Run localization
        localizer = VanillaLLMLocalizer(repo_path=repo_path)
        try:
            result = localizer.localize(
                cve_id=cve_id,
                issue_title=title,
                issue_body=body,
            )
            elapsed = time.time() - t0

            result["owner"] = owner
            result["project"] = project
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
                f"Mode: vanilla_llm  |  Files read: {result.get('source_files_read', 0)}",
                f"Confidence: {result.get('confidence', 'N/A')}",
                "",
                f"--- Vulnerable Files ({len(result.get('vulnerable_files', []))}) ---",
            ]
            for vf in result.get("vulnerable_files", [])[:15]:
                report_lines.append(
                    f"  [{vf.get('score', 0):.2f}] {vf.get('file', '?')}"
                )
            report_lines.append("")
            report_lines.append(
                f"--- Vulnerable Functions ({len(result.get('vulnerable_functions', []))}) ---"
            )
            for vf in result.get("vulnerable_functions", [])[:15]:
                report_lines.append(
                    f"  [{vf.get('score', 0):.2f}] {vf.get('function', '?')}"
                    f" @ {vf.get('file', '?')}"
                )
            report_lines.append("")
            report_lines.append("--- Analysis Summary ---")
            report_lines.append(result.get("analysis_summary", "N/A"))
            with open(os.path.join(cve_dir, "report.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(report_lines))

            n_files = len(result.get("vulnerable_files", []))
            n_funcs = len(result.get("vulnerable_functions", []))
            _log(f"OK {elapsed:.1f}s: {n_files}f/{n_funcs}fn "
                 f"confidence={result.get('confidence', '?')}")

            return {
                "cve_id": cve_id, "success": True,
                "elapsed": elapsed, "n_files": n_files, "n_funcs": n_funcs,
                "confidence": result.get("confidence", ""),
                "log": log_buf.getvalue(),
            }
        finally:
            localizer.close()

    except Exception as e:
        elapsed = time.time() - t0
        _log(f"FAIL: {e}")
        _log(traceback.format_exc())
        cve_dir = os.path.join(output_dir, cve_id)
        os.makedirs(cve_dir, exist_ok=True)
        with open(os.path.join(cve_dir, "result.json"), "w", encoding="utf-8") as f:
            json.dump({
                "cve_id": cve_id, "error": str(e),
                "vulnerable_files": [], "vulnerable_functions": [],
            }, f)
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
    workers: int = 1,
) -> str:
    """Run VanillaLLM on a batch of CVEs.

    Args:
        workers: number of parallel worker processes (default 1 = sequential)

    Returns output_dir path.
    """
    manifest = load_manifest(manifest_path)
    print(f"Loaded {len(manifest)} CVEs from manifest")

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
        # Sequential mode — real-time output
        for i, entry in enumerate(manifest):
            cve_id = entry["cve_id"]
            owner = entry.get("owner", "?")
            project = entry.get("project", "?")

            print(f"\n{'='*60}")
            print(f"[{i+1}/{len(manifest)}] {cve_id} ({owner}/{project})")
            print(f"{'='*60}")

            result = _process_single_cve((entry, output_dir))
            if result["success"]:
                if result.get("skipped"):
                    print(f"  SKIP: {result.get('skip_reason', '?')}")
                    skip_count += 1
                else:
                    print(f"  Done in {result['elapsed']:.1f}s: "
                          f"{result['n_files']} files, {result['n_funcs']} functions")
                    success_count += 1
            else:
                print(f"  FAILED in {result['elapsed']:.1f}s: {result.get('error', 'unknown')}")
                print(result.get("log", "")[-1000:])
                fail_count += 1
    else:
        # Parallel mode — ProcessPoolExecutor
        task_args = [(entry, output_dir) for entry in manifest]
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
        "method": "VanillaLLM",
        "total_cves": len(manifest),
        "success": success_count,
        "failed": fail_count,
        "skipped": skip_count,
        "total_elapsed_seconds": round(total_elapsed, 1),
        "avg_seconds_per_cve": round(total_elapsed / max(success_count, 1), 1),
        "workers": workers,
        "timestamp": datetime.now().isoformat(),
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
        description="VanillaLLM — Pure LLM baseline (no agent, no tools, no KG)"
    )
    parser.add_argument("--limit", type=int, default=10,
                        help="Max CVEs to process (0=all, default: 10)")
    parser.add_argument("--skip", type=int, default=0,
                        help="Skip first N CVEs")
    parser.add_argument("--cves", type=str, default="",
                        help="Comma-separated CVE IDs")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT_DIR,
                        help="Output directory")
    parser.add_argument("--workers", type=int, default=1,
                        help="Parallel worker processes (default: 1 = sequential)")

    args = parser.parse_args()

    cve_list = None
    if args.cves:
        cve_list = [c.strip() for c in args.cves.split(",") if c.strip()]

    run_batch(
        manifest_path=MANIFEST_PATH,
        output_dir=args.output,
        limit=args.limit,
        skip=args.skip,
        cve_list=cve_list,
        workers=args.workers,
    )
