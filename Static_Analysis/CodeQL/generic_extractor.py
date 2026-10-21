#!/usr/bin/env python3
"""
Generic Function-Call-Graph Extractor for languages without CodeQL support.

Uses regex-based parsing to extract function definitions and call edges.
Outputs the same CSV format as the CodeQL ICFG queries so the downstream
pipeline (edge_predictor → MCTS) works unchanged.

Supported languages: PHP, Perl, and other C-like-syntax languages.

CSV output: file,function,srcLine,dstLine,callee_target
  - dstLine is always 0 (function-level call graph, not line-level).
  - callee_target is the name of the called function.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
from collections import defaultdict
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple


# ---------------------------------------------------------------------------
# Per-language regex patterns
# ---------------------------------------------------------------------------

# Each language defines:
#   extensions     - file extensions to scan
#   func_def       - regex to find function/method definitions (group 1 = name)
#   func_call      - regex to find function/method calls (group 1 = callee name)
#   exclude_dirs   - directory names to skip
#   exclude_names  - function names to filter out (keywords, builtins)

LANG_PATTERNS: Dict[str, dict] = {
    "php": {
        "extensions": {".php", ".phtml", ".php3", ".php4", ".php5", ".inc"},
        "func_def": re.compile(
            r'(?:^|\n)\s*(?:(?:public|protected|private|static|abstract|final)\s+)*'
            r'function\s+(\w+)\s*\(',
            re.MULTILINE | re.IGNORECASE,
        ),
        "func_call": re.compile(
            # Match function calls: name(
            # But NOT after: function, class, if, for, while, switch, return, etc.
            r'(?<!\bfunction\s)(?<!\bclass\s)(?<!\bif\s)(?<!\belse\s)'
            r'(?<!\bfor\s)(?<!\bwhile\s)(?<!\bswitch\s)(?<!\breturn\s)'
            r'(?<!\bforeach\s)(?<!\bdeclare\s)(?<!\bnamespace\s)'
            r'(?<!\buse\s)(?<!\brequire\s)(?<!\binclude\s)'
            r'(?<!\bdefined\s)(?<!\bisset\s)(?<!\bempty\s)'
            r'(?<!\becho\s)(?<!\bprint\s)(?<!\bexit\s)(?<!\bdie\s)'
            r'(?<!\bnew\s)(?<!\bthrow\s)(?<!\bcatch\s)'
            r'\b(\w+)\s*\(',
            re.MULTILINE,
        ),
        "exclude_dirs": {
            "vendor", "node_modules", ".git", "cache", "tmp", "temp",
            "tests", "test", "Tests", "Test", "spec", "Spec",
        },
        "exclude_names": {
            # PHP builtins and common keywords that look like function calls
            "if", "while", "for", "foreach", "switch", "case", "return",
            "echo", "print", "exit", "die", "isset", "empty", "defined",
            "list", "array", "unset", "eval", "require", "include",
            "require_once", "include_once", "new", "clone", "throw",
            "function", "class", "interface", "trait", "namespace", "use",
            "public", "private", "protected", "static", "abstract", "final",
            "global", "const", "var", "declare", "enddeclare", "endif",
            "endfor", "endforeach", "endwhile", "endswitch",
            "define", "sprintf", "printf", "var_dump", "print_r",
            "__construct", "__destruct", "__call", "__get", "__set",
            "__isset", "__unset", "__sleep", "__wakeup", "__toString",
            "__invoke", "__set_state", "__clone", "__debugInfo",
        },
    },

    "perl": {
        "extensions": {".pl", ".pm", ".t", ".cgi"},
        "func_def": re.compile(
            r'(?:^|\n)\s*sub\s+(\w+)\s*\{',
            re.MULTILINE,
        ),
        "func_call": re.compile(
            r'(?<!\bsub\s)(?<!\bif\s)(?<!\belse\s)(?<!\belsif\s)'
            r'(?<!\bwhile\s)(?<!\bfor\s)(?<!\bforeach\s)'
            r'(?<!\breturn\s)(?<!\bmy\s)(?<!\bour\s)'
            r'\b(\w+(?:::\w+)*)\s*\(',
            re.MULTILINE,
        ),
        "exclude_dirs": {"blib", "_build", ".git", "t", "inc"},
        "exclude_names": {
            "if", "else", "elsif", "while", "for", "foreach", "return",
            "my", "our", "local", "print", "say", "die", "warn", "exit",
            "open", "close", "push", "pop", "shift", "unshift", "splice",
            "defined", "undef", "exists", "delete", "keys", "values",
            "sort", "grep", "map", "split", "join", "substr", "index",
            "length", "chomp", "chop", "pack", "unpack", "bless", "ref",
            "new", "use", "require", "package", "no", "do", "eval",
        },
    },
}


def _should_skip_dir(dirname: str, exclude_dirs: Set[str]) -> bool:
    return dirname.startswith(".") or dirname in exclude_dirs


def extract_file(filepath: Path, patterns: dict) -> List[Tuple[str, str, int, str]]:
    """Extract function definitions and calls from a single source file.

    Returns list of (function_name, callee, src_line, action_type) tuples.
    action_type is 'def' for function definition, 'call' for function call.
    """
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    results: List[Tuple[str, str, int, str]] = []
    exclude_names = patterns.get("exclude_names", set())
    func_def = patterns["func_def"]
    func_call = patterns["func_call"]

    # Build line-number lookup
    line_offsets = [0]
    for ch in text:
        if ch == "\n":
            line_offsets.append(len(line_offsets))

    def _offset_to_line(pos: int) -> int:
        """Binary search to find line number from character offset."""
        lo, hi = 0, len(line_offsets) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if line_offsets[mid] <= pos:
                lo = mid + 1
            else:
                hi = mid - 1
        return hi + 1  # 1-based line number

    # First pass: find function definitions and record which functions exist
    defined_funcs: Dict[str, int] = {}  # func_name -> line
    for match in func_def.finditer(text):
        name = match.group(1)
        if name in exclude_names:
            continue
        line = _offset_to_line(match.start())
        defined_funcs[name] = line

    # Second pass: find function calls
    for match in func_call.finditer(text):
        callee = match.group(1)
        if callee in exclude_names:
            continue
        line = _offset_to_line(match.start())

        # Determine which function contains this call
        containing_func = "(global)"
        for func_name, func_line in sorted(defined_funcs.items(),
                                           key=lambda x: x[1], reverse=True):
            if func_line <= line:
                containing_func = func_name
                break

        results.append((containing_func, callee, line, "call"))

    return results


def extract_project(project_root: Path, language: str,
                    output_csv: Path) -> int:
    """Extract full ICFG (cfg + call edges) for an entire project.

    Produces 6-column CodeQL-compatible CSV:
      file, function, srcLine, dstLine, edge_type, target_function

    Returns the number of edges written to the CSV.
    """
    patterns = LANG_PATTERNS.get(language)
    if patterns is None:
        print(f"  [WARN] No patterns for language '{language}'")
        return 0

    extensions = patterns["extensions"]
    exclude_dirs = patterns.get("exclude_dirs", set())

    # Per-function call sites: (file, func_name) → list of (src_line, callee)
    func_call_sites: Dict[Tuple[str, str], List[Tuple[int, str]]] = defaultdict(list)
    files_scanned = 0

    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if not _should_skip_dir(d, exclude_dirs)]
        for fname in sorted(files):
            ext = os.path.splitext(fname)[1].lower()
            if ext not in extensions:
                continue
            filepath = Path(root) / fname
            rel_path = str(filepath.relative_to(project_root))
            edges = extract_file(filepath, patterns)
            for caller_func, callee, src_line, _ in edges:
                if caller_func == "(global)":
                    # Assign global-scope calls to a synthetic file-level function
                    caller_func = "_" + os.path.splitext(os.path.basename(rel_path))[0]
                func_call_sites[(rel_path, caller_func)].append((src_line, callee))
            files_scanned += 1

    # Build 6-column ICFG rows with sequential cfg edges
    HEADER = ["file", "function", "srcLine", "dstLine",
              "edge_type", "target_function"]
    all_rows: List[Tuple[str, str, str, str, str, str]] = []

    for (file_path, func_name), calls in sorted(func_call_sites.items()):
        calls.sort()
        # Deduplicate calls at same line
        deduped: List[Tuple[int, str]] = []
        seen_lines = set()
        for line_no, callee in calls:
            if line_no not in seen_lines:
                seen_lines.add(line_no)
                deduped.append((line_no, callee))

        if len(deduped) == 1:
            line_no, callee = deduped[0]
            all_rows.append((file_path, func_name, str(line_no), str(line_no),
                           "cfg", ""))
            all_rows.append((file_path, func_name, str(line_no), str(line_no),
                           "call", callee))
        else:
            for i in range(len(deduped)):
                cur_line, callee = deduped[i]
                nxt_line = deduped[i + 1][0] if i + 1 < len(deduped) else cur_line
                all_rows.append((file_path, func_name, str(cur_line), str(nxt_line),
                               "cfg", ""))
                all_rows.append((file_path, func_name, str(cur_line), str(cur_line),
                               "call", callee))

    # Deduplicate and write CSV
    seen: Set[Tuple[str, str, str, str, str, str]] = set()
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    with open(output_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        row_count = 0
        for row in all_rows:
            key = (row[0].strip('"'), row[1].strip('"'), row[2], row[3],
                   row[4], row[5].strip('"'))
            if key not in seen:
                seen.add(key)
                writer.writerow(row)
                row_count += 1

    func_count = len(func_call_sites)
    print(f"  Generic extractor [{language}]: {files_scanned} files, "
          f"{func_count} functions, {row_count} ICFG edges → {output_csv}")
    return row_count


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generic function-call-graph extractor for unsupported languages"
    )
    parser.add_argument("project_root", help="Path to project root")
    parser.add_argument("output_csv", help="Path to output CSV file")
    parser.add_argument("--language", required=True,
                        choices=list(LANG_PATTERNS.keys()),
                        help="Target language")
    args = parser.parse_args()

    project_root = Path(args.project_root).resolve()
    output_csv = Path(args.output_csv).resolve()

    if not project_root.is_dir():
        print(f"[ERR] Not a directory: {project_root}")
        return 1

    count = extract_project(project_root, args.language, output_csv)
    if count == 0:
        print("[WARN] No call edges extracted — project may not contain "
              "recognizable source files.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
