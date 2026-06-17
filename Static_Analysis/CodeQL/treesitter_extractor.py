"""
Tree-sitter based ICFG Extractor — replaces generic regex-based extractor
for languages without CodeQL support (PHP, Perl).

Provides proper function name resolution, class/method awareness, and
call graph extraction using tree-sitter AST parsing.

Usage:
  from treesitter_extractor import extract_project
  count = extract_project(project_root, language, output_csv)
"""

from __future__ import annotations

import csv
import os
from collections import defaultdict
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import tree_sitter
from tree_sitter import Language, Parser, Node

# ---------------------------------------------------------------------------
# Language grammar setup (bundled tree-sitter grammars)
# ---------------------------------------------------------------------------

_GRAMMAR_MAP = {
    "php":        "tree_sitter_php",
    "python":     "tree_sitter_python",
    "javascript": "tree_sitter_javascript",
    "go":         "tree_sitter_go",
    "ruby":       "tree_sitter_ruby",
    "rust":       "tree_sitter_rust",
    "java":       "tree_sitter_java",
    "cpp":        "tree_sitter_cpp",
}

_parsers: Dict[str, Parser] = {}


def _get_parser(language: str) -> Optional[Parser]:
    """Get or create a tree-sitter parser for the given language."""
    if language not in _GRAMMAR_MAP:
        return None

    if language in _parsers:
        return _parsers[language]

    try:
        mod = __import__(_GRAMMAR_MAP[language], fromlist=["language"])
        # tree-sitter v0.24+ API: language_<name>() returns a PyCapsule
        # which must be wrapped in tree_sitter.Language
        if hasattr(mod, f"language_{language}"):
            lang_capsule = getattr(mod, f"language_{language}")()
            parser = Parser(Language(lang_capsule))
        elif hasattr(mod, "language"):
            lang = mod.language()
            parser = Parser(Language(lang))
        else:
            raise AttributeError(f"no language() or language_{language}() in {_GRAMMAR_MAP[language]}")
        _parsers[language] = parser
        return parser
    except (ImportError, AttributeError, Exception) as e:
        print(f"  [WARN] tree-sitter grammar for '{language}' not available: {e}")
        return None


# ---------------------------------------------------------------------------
# Per-language extraction config
# ---------------------------------------------------------------------------

LANG_CONFIG = {
    "php": {
        "extensions": {".php", ".phtml", ".php3", ".php4", ".php5", ".inc"},
        "exclude_dirs": {"vendor", "node_modules", ".git", "cache", "tmp", "temp",
                         "tests", "test", "Tests", "Test", "spec", "Spec"},
    },
    "perl": {
        "extensions": {".pl", ".pm", ".t", ".cgi"},
        "exclude_dirs": {"blib", "_build", ".git", "t", "inc"},
    },
}


def _should_skip_dir(dirname: str, exclude_dirs: Set[str]) -> bool:
    return dirname.startswith(".") or dirname in exclude_dirs


# ---------------------------------------------------------------------------
# Tree traversal helpers
# ---------------------------------------------------------------------------

def _find_nodes_by_type(node: Node, node_type: str, max_depth: int = 10) -> List[Node]:
    """Recursively find all descendant nodes of a given type."""
    results = []
    if node.type == node_type:
        results.append(node)
    if max_depth <= 0:
        return results
    for child in node.children:
        results.extend(_find_nodes_by_type(child, node_type, max_depth - 1))
    return results


def _find_ancestor_of_type(node: Node, node_types: set, max_depth: int = 20) -> Optional[Node]:
    """Find the nearest ancestor of the given type(s)."""
    current = node.parent
    depth = 0
    while current is not None and depth < max_depth:
        if current.type in node_types:
            return current
        current = current.parent
        depth += 1
    return None


def _node_text(node: Node, source: bytes) -> str:
    """Get the source text for a node."""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _get_function_name(node: Node, source: bytes) -> Optional[str]:
    """Extract function/method name from a function_declaration or method_declaration node."""
    # PHP: function_declaration / method_declaration
    # name is in a 'name' child node (identifier)
    for child in node.children:
        if child.type in ("name", "function_name", "method_name"):
            return _node_text(child, source)
    return None


def _get_class_name(node: Node, source: bytes) -> Optional[str]:
    """Extract class name from a class_declaration node."""
    for child in node.children:
        if child.type in ("name", "class_name"):
            return _node_text(child, source)
    return None


# ---------------------------------------------------------------------------
# Per-file extraction
# ---------------------------------------------------------------------------

def extract_file_treesitter(filepath: Path, language: str,
                            parser: Parser) -> List[Tuple[str, str, int, str]]:
    """Extract function definitions and call edges from a source file using tree-sitter.

    Returns list of (caller_func, callee_func, src_line, edge_type) tuples.
    """
    try:
        source_bytes = filepath.read_bytes()
        if not source_bytes.strip():
            return []
    except Exception:
        return []

    # Try UTF-8 first, then latin-1 (never fails), then binary fallback
    tree = None
    for encoding in ["utf-8", "latin-1", None]:
        try:
            if encoding is None:
                tree = parser.parse(source_bytes)
            else:
                text = source_bytes.decode(encoding)
                tree = parser.parse(text.encode("utf-8"))
            break
        except (UnicodeDecodeError, Exception):
            continue

    if tree is None:
        return []

    root = tree.root_node
    source = source_bytes

    # ----- Find all function/method definitions -----
    # PHP: function_definition, method_declaration
    # The node types vary slightly by language
    func_def_types = {"function_definition", "method_declaration",
                      "function_declaration", "arrow_function"}
    class_def_types = {"class_declaration"}

    all_func_nodes = _find_nodes_by_type(root, "function_definition", max_depth=20)
    all_func_nodes.extend(_find_nodes_by_type(root, "method_declaration", max_depth=20))
    all_func_nodes.extend(_find_nodes_by_type(root, "function_declaration", max_depth=20))

    # Build function name -> node mapping
    func_map: Dict[str, Node] = {}
    func_lines: Dict[str, int] = {}
    for node in all_func_nodes:
        name = _get_function_name(node, source)
        if name:
            # Check if this function is inside a class
            class_ancestor = _find_ancestor_of_type(node, class_def_types)
            if class_ancestor:
                class_name = _get_class_name(class_ancestor, source)
                if class_name:
                    name = f"{class_name}::{name}"
            func_map[name] = node
            func_lines[name] = node.start_point[0] + 1  # 1-based line

    # ----- Find all function calls -----
    # PHP: function_call_expression -> name is the function name
    call_exprs = _find_nodes_by_type(root, "function_call_expression", max_depth=20)
    call_exprs.extend(_find_nodes_by_type(root, "call_expression", max_depth=20))
    call_exprs.extend(_find_nodes_by_type(root, "member_call_expression", max_depth=20))

    results: List[Tuple[str, str, int, str]] = []

    # Keywords to skip as "function names"
    skip_names = {"if", "for", "while", "foreach", "switch", "return",
                  "echo", "print", "isset", "empty", "unset", "list",
                  "array", "define", "defined", "die", "exit", "require",
                  "include", "require_once", "include_once", "eval",
                  "new", "throw", "clone", "function", "class", "__construct",
                  "__destruct", "__get", "__set", "__call", "__toString"}

    for call_node in call_exprs:
        # Get function name from the call
        func_name_node = None
        for child in call_node.children:
            if child.type in ("name", "function_name", "function"):
                func_name_node = child
                break

        if func_name_node is None:
            # Sometimes the name is in a 'function' child
            for child in call_node.named_children:
                if child.type in ("name",):
                    func_name_node = child
                    break

        if func_name_node is None:
            continue

        callee = _node_text(func_name_node, source).strip()
        if not callee or callee.lower() in skip_names:
            continue
        if len(callee) < 2:
            continue

        call_line = call_node.start_point[0] + 1

        # Determine containing function
        containing = "(global)"
        # Find the nearest function ancestor
        func_ancestor = _find_ancestor_of_type(call_node, func_def_types)
        if func_ancestor:
            fname = _get_function_name(func_ancestor, source)
            if fname:
                class_anc = _find_ancestor_of_type(func_ancestor, class_def_types)
                if class_anc:
                    cname = _get_class_name(class_anc, source)
                    if cname:
                        fname = f"{cname}::{fname}"
                containing = fname

        results.append((containing, callee, call_line, "call"))

    return results


# ---------------------------------------------------------------------------
# Project-level extraction
# ---------------------------------------------------------------------------

def extract_project(project_root: Path, language: str,
                    output_csv: Path) -> int:
    """Extract full ICFG (cfg + call edges) for an entire project using tree-sitter.

    Produces 6-column CodeQL-compatible CSV:
      file, function, srcLine, dstLine, edge_type, target_function

    For each function, generates:
      - Sequential cfg edges connecting call sites (entry → stmt1 → stmt2 → exit)
      - Call edges at each call site pointing to the callee

    Falls back to generic_extractor if tree-sitter grammar is unavailable.
    """
    config = LANG_CONFIG.get(language, {})

    if not config:
        from generic_extractor import extract_project as generic_extract
        return generic_extract(project_root, language, output_csv)

    parser = _get_parser(language)
    if parser is None:
        print(f"  [INFO] tree-sitter not available for '{language}', "
              f"using generic extractor")
        from generic_extractor import extract_project as generic_extract
        return generic_extract(project_root, language, output_csv)

    extensions = config["extensions"]
    exclude_dirs = config.get("exclude_dirs", set())

    # Per-function call sites: (file, func_name) → list of (src_line, callee)
    func_call_sites: Dict[Tuple[str, str], List[Tuple[int, str]]] = defaultdict(list)
    files_scanned = 0
    files_skipped = 0
    skipped_reasons: Dict[str, int] = defaultdict(int)

    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if not _should_skip_dir(d, exclude_dirs)]
        for fname in sorted(files):
            ext = os.path.splitext(fname)[1].lower()
            if ext not in extensions:
                continue
            filepath = Path(root) / fname
            rel_path = str(filepath.relative_to(project_root))
            try:
                edges = extract_file_treesitter(filepath, language, parser)
            except Exception as e:
                edges = []
                skipped_reasons[str(type(e).__name__)] += 1
                files_skipped += 1
                continue

            if not edges:
                files_scanned += 1
                continue

            # Sort call sites by line number, collect per function
            file_calls: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
            for caller, callee, src_line, _ in edges:
                file_calls[caller].append((src_line, callee))

            for func_name, calls in file_calls.items():
                calls.sort()
                func_call_sites[(rel_path, func_name)].extend(calls)
            files_scanned += 1

    if files_skipped > 0:
        print(f"  [WARN] Tree-sitter [{language}]: {files_skipped} files skipped due to parse errors")
        for reason, count in sorted(skipped_reasons.items()):
            print(f"    {reason}: {count} files")

    # Build 6-column ICFG rows
    UNIFIED_HEADER = ["file", "function", "srcLine", "dstLine",
                      "edge_type", "target_function"]
    all_rows: List[Tuple[str, str, str, str, str, str]] = []

    for (file_path, func_name), calls in sorted(func_call_sites.items()):
        if not calls:
            continue

        # Deduplicate calls at same line (keep first callee)
        deduped: List[Tuple[int, str]] = []
        seen_lines = set()
        for line_no, callee in calls:
            if line_no not in seen_lines:
                seen_lines.add(line_no)
                deduped.append((line_no, callee))

        if len(deduped) == 1:
            line_no, callee = deduped[0]
            # Single call site: cfg self-loop + call edge
            all_rows.append((file_path, func_name, str(line_no), str(line_no),
                           "cfg", ""))
            all_rows.append((file_path, func_name, str(line_no), str(line_no),
                           "call", callee))
        else:
            # Multiple call sites: sequential cfg chain + call at each site
            for i in range(len(deduped)):
                cur_line, callee = deduped[i]
                nxt_line = deduped[i + 1][0] if i + 1 < len(deduped) else cur_line
                # cfg: current → next (or self-loop at last)
                all_rows.append((file_path, func_name, str(cur_line), str(nxt_line),
                               "cfg", ""))
                # call: current → callee
                all_rows.append((file_path, func_name, str(cur_line), str(cur_line),
                               "call", callee))

    # Deduplicate and write CSV
    seen: Set[Tuple[str, str, str, str, str, str]] = set()
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    with open(output_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(UNIFIED_HEADER)
        row_count = 0
        for row in all_rows:
            key = (row[0].strip('"'), row[1].strip('"'), row[2], row[3],
                   row[4], row[5].strip('"'))
            if key not in seen:
                seen.add(key)
                writer.writerow(row)
                row_count += 1

    print(f"  Tree-sitter [{language}]: {files_scanned} files, "
          f"{len(func_call_sites)} functions, {row_count} ICFG edges → {output_csv}")
    return row_count


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Tree-sitter based function call graph extractor"
    )
    parser.add_argument("project_root", help="Path to project root")
    parser.add_argument("output_csv", help="Path to output CSV file")
    parser.add_argument("--language", required=True,
                        choices=list(LANG_CONFIG.keys()),
                        help="Target language")
    args = parser.parse_args()

    project_root = Path(args.project_root).resolve()
    output_csv = Path(args.output_csv).resolve()

    count = extract_project(project_root, args.language, output_csv)
    if count == 0:
        print("[WARN] No call edges extracted.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
