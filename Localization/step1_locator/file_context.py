"""
File Context — tree-sitter file signature extraction for prompt assembly.

Produces lightweight context for Step 1 prompt injection:
  - Function signatures (name, params, start_line) — no bodies
  - Class/struct declarations
  - Import/include directives (first 80 lines)
  - File line count and detected language

Uses tree_sitter_utils for AST parsing. Reuses parsers from the
Explainable_Localization tree_sitter_gt.py via shared/tree_sitter_utils.py.
"""

import os
from typing import Dict, List, Optional, Set

from shared.tree_sitter_utils import (
    detect_lang,
    extract_file_signature,
    extract_signatures_batch,
)


def collect_file_context(
    repo_path: str,
    candidate_files: List[str],
    top_k: int = 20,
) -> List[dict]:
    """Extract lightweight file signatures for top candidate files.

    Args:
        repo_path: path to the git repository root
        candidate_files: list of file paths (relative to repo) to consider
        top_k: maximum number of files to return

    Returns:
        List of FileSignature dicts sorted by priority (matches first).
    """
    results: List[dict] = []

    # Resolve full paths
    resolved = []
    for fp in candidate_files[:top_k * 2]:
        full = os.path.join(repo_path, fp)
        if os.path.isfile(full):
            resolved.append(full)
        else:
            # Try to find via partial match
            for root, dirs, files in os.walk(repo_path):
                # Limit depth
                rel = os.path.relpath(root, repo_path)
                if len(rel.split(os.sep)) > 4:
                    dirs.clear()
                    continue
                if os.path.basename(fp) in files:
                    resolved.append(os.path.join(root, os.path.basename(fp)))
                    break

    resolved = list(dict.fromkeys(resolved))  # dedup preserving order

    sigs = extract_signatures_batch(resolved, max_files=top_k)
    return [s.to_dict() for s in sigs]


def get_context_section(
    repo_path: str,
    files_from_commits: List[str],
    hotspot_files: List[dict],
    top_k: int = 20,
) -> str:
    """Build the 'File Context' section for the Step 1 prompt.

    Combines tree-sitter signatures with hotspot edit counts.

    Returns formatted string ready for prompt injection.
    """
    # Merge and dedup
    all_files: List[str] = list(dict.fromkeys(
        files_from_commits + [h.get("file_path", "") for h in hotspot_files]
    ))

    sigs = collect_file_context(repo_path, all_files, top_k=top_k)

    if not sigs:
        return "FILE CONTEXT: No source files available for analysis."

    lines = ["FILE CONTEXT (tree-sitter signatures, top relevant files):", ""]
    for i, sig in enumerate(sigs):
        lang = sig.get("language", "?")
        filepath = sig.get("file", "?")
        line_count = sig.get("lines", 0)
        funcs = sig.get("functions", [])
        classes = sig.get("classes", [])
        imports = sig.get("imports", [])

        lines.append(f"  [{i+1}] {filepath} ({lang}, {line_count} lines)")

        if classes:
            lines.append(f"      Classes: {', '.join(classes[:10])}")
        if imports:
            lines.append(f"      Imports: {', '.join(imports[:5])}")
        if funcs:
            for fn in funcs[:10]:
                name = fn.get("name", "?")
                params = fn.get("params", "...")
                start = fn.get("start_line", 0)
                lines.append(f"      - {name}{params}  # L{start}")

        lines.append("")

    return "\n".join(lines)


def get_repo_scan_context_section(repo_path: str, top_k: int = 20) -> str:
    """Build file context section by scanning repo source dirs (no KG guidance).

    Walks source directories, finds source files by language extension,
    extracts tree-sitter signatures. No dependency on hotspots or commits.
    """
    if not os.path.isdir(repo_path):
        return "SOURCE FILE OVERVIEW: Not available"

    source_exts = {
        ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp",
        ".py", ".java", ".js", ".ts", ".go", ".rs",
        ".rb", ".php", ".swift", ".kt", ".scala",
        ".cs", ".m", ".mm",
    }
    skip_dirs = {".git", "node_modules", "__pycache__", "vendor",
                 "target", "build", "dist", ".svn", ".hg",
                 "test", "tests", "spec", "examples", "demo"}

    candidate_files = []
    for root, dirs, files in os.walk(repo_path):
        rel = os.path.relpath(root, repo_path)
        depth = len(rel.split(os.sep)) if rel != "." else 0
        if depth > 5:
            dirs.clear()
            continue
        dirs[:] = sorted(d for d in dirs
                         if not d.startswith(".") and d not in skip_dirs)
        for f in sorted(files):
            if f.startswith("."):
                continue
            ext = os.path.splitext(f)[1].lower()
            if ext in source_exts:
                candidate_files.append(os.path.join(root, f))
                if len(candidate_files) >= 200:
                    break
        if len(candidate_files) >= 200:
            break

    if not candidate_files:
        return "SOURCE FILE OVERVIEW: No source files found for analysis."

    # Prefer files in src/, lib/, app/, main dirs; sort by size desc for importance
    priority_dirs = {"src", "lib", "app", "main", "source", "core", "modules", "include"}
    def _file_priority(fp):
        parts = set(os.path.relpath(fp, repo_path).split(os.sep))
        priority = 1 if parts & priority_dirs else 0
        try:
            size = os.path.getsize(fp)
        except OSError:
            size = 0
        return (priority, size)

    candidate_files.sort(key=_file_priority, reverse=True)
    selected = candidate_files[:top_k]

    from shared.tree_sitter_utils import extract_signatures_batch
    sigs = extract_signatures_batch(selected, max_files=top_k)

    if not sigs:
        return "SOURCE FILE OVERVIEW: Could not extract signatures."

    lines = ["SOURCE FILE OVERVIEW (tree-sitter signatures from key source files):", ""]
    for i, sig in enumerate(sigs):
        if hasattr(sig, 'to_dict'):
            d = sig.to_dict()
        elif isinstance(sig, dict):
            d = sig
        else:
            continue

        filepath = d.get("file", "?")
        lang = d.get("language", "?")
        line_count = d.get("lines", 0)
        funcs = d.get("functions", [])
        classes = d.get("classes", [])
        imports = d.get("imports", [])

        lines.append(f"  [{i+1}] {filepath} ({lang}, {line_count} lines)")
        if classes:
            lines.append(f"      Classes: {', '.join(classes[:10])}")
        if imports:
            lines.append(f"      Imports: {', '.join(imports[:5])}")
        for fn in funcs[:10]:
            name = fn.get("name", "?")
            params = fn.get("params", "...")
            start = fn.get("start_line", 0)
            lines.append(f"      - {name}{params}  # L{start}")
        lines.append("")

    return "\n".join(lines)


def get_fast_file_list_section(repo_path: str, top_k: int = 20) -> str:
    """Build file list section WITHOUT tree-sitter parsing (fast path for no-KG mode).

    Walks repo up to depth=3, collects source files in priority dirs,
    returns a simple list with path and extension — no AST parsing.
    """
    if not os.path.isdir(repo_path):
        return "SOURCE FILE LIST: Not available"

    source_exts = {
        ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp",
        ".py", ".java", ".js", ".ts", ".go", ".rs",
        ".rb", ".php", ".swift", ".kt", ".scala",
        ".cs", ".m", ".mm",
    }
    skip_dirs = {".git", "node_modules", "__pycache__", "vendor",
                 "target", "build", "dist", ".svn", ".hg",
                 "test", "tests", "spec", "examples", "demo"}
    priority_dirs = {"src", "lib", "app", "main", "source", "core", "modules", "include"}

    candidates = []
    for root, dirs, files in os.walk(repo_path):
        rel = os.path.relpath(root, repo_path)
        depth = 0 if rel == "." else len(rel.split(os.sep))
        if depth > 3:
            dirs.clear()
            continue
        dirs[:] = sorted(d for d in dirs
                         if not d.startswith(".") and d not in skip_dirs)
        for f in sorted(files):
            if f.startswith("."):
                continue
            ext = os.path.splitext(f)[1].lower()
            if ext in source_exts:
                fpath = os.path.join(root, f)
                rel_path = os.path.relpath(fpath, repo_path)
                in_priority = 1 if set(rel_path.split(os.sep)) & priority_dirs else 0
                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    size = 0
                candidates.append((rel_path, ext, in_priority, size))

    candidates.sort(key=lambda x: (x[2], x[3]), reverse=True)
    selected = candidates[:top_k]

    if not selected:
        return "SOURCE FILE LIST: No source files found."

    lang_map = {".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
                ".hpp": "cpp", ".py": "python", ".java": "java", ".js": "javascript",
                ".ts": "typescript", ".go": "go", ".rs": "rust", ".rb": "ruby",
                ".php": "php", ".swift": "swift", ".kt": "kotlin", ".scala": "scala",
                ".cs": "csharp", ".m": "objc", ".mm": "objcpp"}

    lines = ["SOURCE FILE LIST (key source files, no AST parsing):", ""]
    for i, (rel_path, ext, _, size) in enumerate(selected):
        lang = lang_map.get(ext, ext.lstrip("."))
        kb = size / 1024
        lines.append(f"  [{i+1}] {rel_path} ({lang}, {kb:.0f} KB)")

    return "\n".join(lines)


def get_directory_section(repo_path: str, depth: int = 3) -> str:
    """Build the 'Directory Structure' section for the Step 1 prompt.

    Returns a tree-like view of the repository structure (no file contents).
    """
    if not os.path.isdir(repo_path):
        return "DIRECTORY STRUCTURE: Not available"

    lines = ["DIRECTORY STRUCTURE:", ""]

    skip_dirs = {".git", "node_modules", "__pycache__", "vendor",
                 "target", "build", "dist", ".svn", ".hg"}

    for root, dirs, files in os.walk(repo_path):
        rel = os.path.relpath(root, repo_path)
        if rel == ".":
            rel = ""

        current_depth = len(rel.split(os.sep)) if rel else 0
        if current_depth >= depth:
            dirs.clear()
            continue

        dirs[:] = sorted(d for d in dirs
                         if not d.startswith(".") and d not in skip_dirs)

        indent = "  " * current_depth
        dir_name = os.path.basename(root) if rel else os.path.basename(repo_path.rstrip("/"))
        lines.append(f"{indent}{dir_name}/")

        for f in sorted(files)[:30]:
            if f.startswith("."):
                continue
            lines.append(f"{indent}  {f}")

    return "\n".join(lines[:200])
