#!/usr/bin/python3
"""
Extract ICFG-equivalent data from ScubaTrace built-in parser.

Outputs a CSV with the same 6-column format as CodeQL ICFG:
  file, function, srcLine, dstLine, edge_type, target_function

Edge types:
  - cfg: intra-procedural CFG edge (entry -> exit, statement sequence)
  - call: function call edge (call site -> callee entry)
  - return: return edge (callee exit -> call site continuation)
"""

import csv
import os
import sys
import time
import traceback
from collections import defaultdict
from typing import Optional

# ── Monkey-patch chardet to suppress false utf-7 detections ──
import chardet as _chardet
_original_detect = _chardet.detect

BLACKLIST_ENCODINGS = {"utf-7", "utf7", "UTF-7", "UTF7", "iso-2022-jp",
                        "hz-gb-2312", "x-mac-cyrillic"}

def _safe_detect(byte_str):
    result = _original_detect(byte_str)
    enc = result.get("encoding", "")
    if enc and enc.lower() in BLACKLIST_ENCODINGS:
        result["encoding"] = "utf-8"
        result["confidence"] = 0.0
    return result

_chardet.detect = _safe_detect

# Also patch scubatrace File.text to add fallback on decode error
import scubatrace as _scubatrace

_original_text = _scubatrace.File.text

def _safe_text(self):
    if self._content is not None:
        return self._content
    with open(self._path, "rb") as f:
        data = f.read()
        encoding = _original_detect(data)["encoding"]
        if encoding is None:
            encoding = "utf-8"
    for enc in [encoding, "utf-8", "latin-1"]:
        try:
            with open(self._path, "r", encoding=enc) as f:
                self._content = f.read()
                return self._content
        except (UnicodeDecodeError, LookupError):
            continue
    # Last resort: replace errors
    with open(self._path, "r", encoding="utf-8", errors="replace") as f:
        self._content = f.read()
        return self._content

_scubatrace.File.text = property(_safe_text)

import scubatrace

LANG_MAP = {
    "c": scubatrace.language.C,
    "cpp": scubatrace.language.C,
    "java": scubatrace.language.JAVA,
    "python": scubatrace.language.PYTHON,
    "javascript": scubatrace.language.JAVASCRIPT,
}


def detect_language_from_files(repo_path: str) -> Optional[str]:
    """Detect the dominant language by file extension count."""
    ext_map = {
        ".c": "c", ".h": "c",
        ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hxx": "cpp",
        ".java": "java",
        ".py": "python",
        ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
        ".ts": "javascript", ".tsx": "javascript",
    }
    counts = defaultdict(int)
    for root, dirs, files in os.walk(repo_path):
        # Skip hidden and build dirs
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in
                   ("node_modules", "build", "dist", "target", "__pycache__",
                    "vendor", "third_party", "thirdparty", ".git")]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in ext_map:
                counts[ext_map[ext]] += 1
        if sum(counts.values()) > 5000:
            break

    if not counts:
        return None
    return max(counts, key=counts.get)


def extract_call_line(func) -> Optional[int]:
    """Extract the line number of a call expression from a function's calls."""
    try:
        calls = func.calls
        if calls and len(calls) > 0:
            return calls[0].start_line
    except Exception:
        pass
    return None


def extract_icfg(repo_path: str, language: str, output_csv: str,
                 timeout: int = 600) -> dict:
    """
    Extract ICFG from a repo using ScubaTrace.

    Returns stats dict with keys: files, functions, edges, call_edges,
    cfg_edges, return_edges, error
    """
    result = {
        "files": 0,
        "functions": 0,
        "edges": 0,
        "call_edges": 0,
        "cfg_edges": 0,
        "return_edges": 0,
        "elapsed_s": 0,
        "error": None,
    }

    st_lang = LANG_MAP.get(language)
    if st_lang is None:
        result["error"] = f"Unsupported language: {language}"
        return result

    start = time.time()
    try:
        project = scubatrace.Project.create(repo_path, language=st_lang)
    except Exception as e:
        result["error"] = f"Project.create failed: {e}"
        result["elapsed_s"] = time.time() - start
        return result

    create_time = time.time() - start

    try:
        all_files = list(project.files)
        all_functions = list(project.functions)
    except Exception as e:
        result["error"] = f"Enumeration failed: {e}"
        result["elapsed_s"] = time.time() - start
        return result

    result["files"] = len(all_files)
    result["functions"] = len(all_functions)

    if not all_functions:
        result["error"] = "No functions found"
        result["elapsed_s"] = time.time() - start
        return result

    # Build function index for fast lookup
    func_index: dict[str, list] = defaultdict(list)  # name -> [funcs]
    for f in all_functions:
        func_index[f.name].append(f)

    def find_callee_by_name(name: str):
        """Find a function by name, preferring same-project functions."""
        candidates = func_index.get(name, [])
        if candidates:
            return candidates[0]
        # Try partial match
        for fname, funcs in func_index.items():
            if name in fname or fname in name:
                return funcs[0]
        return None

    rows = []
    seen_edges = set()

    for func in all_functions:
        if not func.file:
            continue

        filepath = func.file.relpath
        func_name = func.name
        start_line = func.start_line or 0
        end_line = func.end_line or start_line

        # Entry CFG edge: entry (line 0) -> first statement
        cfg_key = (filepath, func_name, 0, start_line, "cfg", "")
        if cfg_key not in seen_edges:
            seen_edges.add(cfg_key)
            rows.append([filepath, func_name, 0, start_line, "cfg", ""])

        # Exit CFG edge: last statement -> exit (line end_line+1)
        if end_line > start_line:
            cfg_key2 = (filepath, func_name, end_line, end_line + 1, "cfg", "")
            if cfg_key2 not in seen_edges:
                seen_edges.add(cfg_key2)
                rows.append([filepath, func_name, end_line, end_line + 1, "cfg", ""])

        # Statement-to-statement CFG edges (sequential within function)
        try:
            stmts = func.statements
            prev_line = start_line
            for stmt in stmts:
                sl = stmt.start_line
                if sl and sl > prev_line:
                    cfg_key3 = (filepath, func_name, prev_line, sl, "cfg", "")
                    if cfg_key3 not in seen_edges:
                        seen_edges.add(cfg_key3)
                        rows.append([filepath, func_name, prev_line, sl, "cfg", ""])
                    prev_line = sl
        except Exception:
            pass

        # Call edges
        try:
            callees = list(func.callees)
        except Exception:
            callees = []

        call_lines = {}  # callee_name -> [line_numbers]
        try:
            for call_node in func.calls:
                line = call_node.start_line
                if not line:
                    continue
                # Try to extract callee name from call node
                callee_name = None
                try:
                    # Check identifiers in the call expression
                    for ident in call_node.identifiers:
                        if ident.name and ident.name != func_name:
                            callee_name = ident.name
                            break
                except Exception:
                    pass

                if callee_name:
                    call_lines.setdefault(callee_name, []).append(line)
        except Exception:
            pass

        # Match callees to call lines and create call/return edges
        for callee in callees:
            callee_name = callee.name

            # Skip FunctionDeclaration (external / no location info)
            callee_file = ""
            callee_start = 0
            callee_end = 0
            if hasattr(callee, 'file') and callee.file:
                callee_file = callee.file.relpath
            if hasattr(callee, 'start_line'):
                callee_start = callee.start_line or 0
            if hasattr(callee, 'end_line'):
                callee_end = callee.end_line or callee_start
            if hasattr(callee, 'body_start_line') and callee_start == 0:
                callee_start = callee.body_start_line or 0
            if hasattr(callee, 'body_end_line') and callee_end == 0:
                callee_end = callee.body_end_line or callee_start

            # Try to find matching call line
            lines = call_lines.get(callee_name, [])
            if not lines:
                for key in call_lines:
                    if callee_name in key or key in callee_name:
                        lines = call_lines[key]
                        break

            call_line = lines[0] if lines else start_line

            # Call edge: call site -> callee entry
            call_key = (filepath, func_name, call_line, 0, "call", callee_name)
            if call_key not in seen_edges:
                seen_edges.add(call_key)
                rows.append([filepath, func_name, call_line, 0, "call", callee_name])

            # Return edge: only for non-external functions with file + line info
            if callee_file and callee_end > 0:
                ret_key = (callee_file, callee_name, callee_end, call_line + 1,
                           "return", func_name)
                if ret_key not in seen_edges:
                    seen_edges.add(ret_key)
                    rows.append([callee_file, callee_name, callee_end,
                                call_line + 1, "return", func_name])

    result["call_edges"] = sum(1 for r in rows if r[4] == "call")
    result["cfg_edges"] = sum(1 for r in rows if r[4] == "cfg")
    result["return_edges"] = sum(1 for r in rows if r[4] == "return")
    result["edges"] = len(rows)

    # Write CSV
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "function", "srcLine", "dstLine",
                         "edge_type", "target_function"])
        writer.writerows(rows)

    result["elapsed_s"] = time.time() - start
    return result


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: extract_icfg.py <repo_path> <language> <output_csv>")
        sys.exit(1)

    repo_path = sys.argv[1]
    language = sys.argv[2]
    output_csv = sys.argv[3]

    print(f"Extracting ICFG from: {repo_path}")
    print(f"Language: {language}")
    result = extract_icfg(repo_path, language, output_csv)
    for k, v in result.items():
        print(f"  {k}: {v}")
