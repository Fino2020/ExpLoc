"""
Code Extractor — tree-sitter code snippet extraction for path nodes.

For each node on a traced path:
  - Read source file
  - Tree-sitter extract function body or surrounding context (±10 lines)
  - Annotate role: source (entry), transform (intermediate), sink (termination)
"""

import os
from typing import Dict, List, Optional

from shared.tree_sitter_utils import detect_lang, _get_parser, _node_lines, _node_text


def extract_code_snippets(
    repo_path: str,
    path_chain: List[dict],
    nodes: List[str],
    entry_function: str,
    sink_function: str = "",
    context_lines: int = 10,
) -> List[dict]:
    """Extract code snippets for each node on a traced path.

    Args:
        repo_path: path to the git repository
        path_chain: list of {"from", "to", "edge_type", "prob"} dicts
        nodes: list of ICFG node IDs ("file:func:line")
        entry_function: the entry function name
        sink_function: the sink function name (if sink reached)
        context_lines: number of surrounding lines to extract

    Returns:
        List of {"node", "role", "lines", "file", "function", "start_line", "end_line"}
    """
    snippets = []

    for i, node_id in enumerate(nodes):
        parts = node_id.split(":")
        if len(parts) < 2:
            continue

        file_path = parts[0]
        func_name = parts[1]
        line_num = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 0

        # Determine role
        if i == 0:
            role = "source"
        elif sink_function and (func_name == sink_function or
                                f":{sink_function}:" in node_id or
                                f":{sink_function}" == f":{parts[1]}"):
            role = "sink"
        else:
            role = "transform"

        # Read source file and extract context
        full_path = os.path.join(repo_path, file_path)
        if not os.path.isfile(full_path):
            snippets.append({
                "node": node_id,
                "role": role,
                "lines": f"[File not found: {file_path}]",
                "file": file_path,
                "function": func_name,
                "start_line": line_num,
                "end_line": line_num,
            })
            continue

        extracted = _extract_function_or_context(
            full_path, func_name, line_num, context_lines
        )

        snippets.append({
            "node": node_id,
            "role": role,
            "lines": extracted,
            "file": file_path,
            "function": func_name,
            "start_line": line_num,
            "end_line": line_num,
        })

    return snippets


def _extract_function_or_context(
    file_path: str, func_name: str, line_num: int, context: int
) -> str:
    """Extract function body or line±context from a source file.

    Uses tree-sitter to find the function's exact line range,
    falling back to simple line-range extraction.
    """
    lang = detect_lang(file_path)
    if lang == "unknown":
        return _extract_context_fallback(file_path, line_num, context)

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except Exception:
        return f"[Cannot read: {file_path}]"

    if not source.strip():
        return "[Empty file]"

    # Try tree-sitter to find function range
    parser = _get_parser(lang)
    if parser is not None:
        try:
            tree = parser.parse(bytes(source, "utf-8"))
            func_range = _find_function_range(tree.root_node, func_name, lang, source)
            if func_range:
                start, end = func_range
                lines = source.split("\n")
                snippet_lines = lines[start-1:end]
                return _format_snippet(snippet_lines, start, end)
        except Exception:
            pass

    # Fallback: line±context
    return _extract_context_fallback(file_path, line_num, context)


def _find_function_range(node, func_name: str, lang: str, source: str):
    """Walk AST to find a function definition's line range."""
    from shared.tree_sitter_utils import _get_func_signature, _CLASS_TYPES

    # Try top-level functions first
    node_type = node.type
    func_info = _get_func_signature(node, lang, source)
    if func_info and func_info["name"] == func_name:
        return (func_info["start_line"], node.end_point[0] + 1)

    # Recurse into children
    for child in node.children:
        result = _find_function_range(child, func_name, lang, source)
        if result:
            return result

    return None


def _extract_context_fallback(file_path: str, line_num: int, context: int) -> str:
    """Simple line-range extraction around a target line."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
    except Exception:
        return f"[Cannot read: {file_path}]"

    if not all_lines:
        return "[Empty file]"

    start = max(0, line_num - context - 1)
    end = min(len(all_lines), line_num + context)
    snippet_lines = [l.rstrip("\n") for l in all_lines[start:end]]
    return _format_snippet(snippet_lines, start + 1, end)


def _format_snippet(lines: List[str], start_line: int, end_line: int) -> str:
    """Format code snippet with line numbers."""
    if not lines:
        return "[No code]"
    formatted = []
    for i, line in enumerate(lines):
        ln = start_line + i
        formatted.append(f"{ln:5d}| {line}")
    return "\n".join(formatted)
