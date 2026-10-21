#!/usr/bin/python3
"""
Extract standard 6-column ICFG CSV from a Joern CPG binary.

Output format (compatible with ICFGGraph.load_from_csv):
  file, function, srcLine, dstLine, edge_type, target_function

Edge types:
  - cfg: intra-procedural control flow edges
  - call: function call edges (call site -> callee entry)
  - return: return edges (callee exit -> caller continuation)
"""

import csv
import os
import sys
import time
from collections import defaultdict


def _build_method_index(cpg) -> dict:
    """
    Build lookup: METHOD node_id -> method_info dict.

    Returns dict mapping (label, seq) -> {
        name, full_name, filename, start_line, end_line, is_external
    }
    """
    index = {}
    for node in cpg.nodes_by_label("METHOD"):
        props = node.properties
        filename = props.get("FILENAME", "")
        is_ext = props.get("IS_EXTERNAL", False)
        # External methods have no source location
        if is_ext or not filename:
            index[node.id] = None
            continue
        index[node.id] = {
            "name": props.get("NAME", ""),
            "full_name": props.get("FULL_NAME", ""),
            "filename": filename,
            "start_line": props.get("LINE_NUMBER") or 0,
            "end_line": (props.get("LINE_NUMBER_END")
                         or props.get("LINE_NUMBER") or 0),
            "is_external": False,
        }
    return index


def _extract_cfg_edges(cpg, method_index: dict) -> list:
    """
    Extract intra-procedural CFG edges from CPG.

    For each CFG edge, finds the enclosing method of src and dst.
    If both are in the same non-external method, emits a 'cfg' edge
    using statement-level line granularity.
    """
    rows = []
    seen = set()
    # Build node -> enclosing method cache
    method_cache = {}

    def get_method(node_id):
        if node_id not in method_cache:
            m = cpg.enclosing_method(cpg.node(node_id))
            method_cache[node_id] = m
        return method_cache[node_id]

    for edge in cpg.edges:
        if edge.label != "CFG":
            continue
        src_method = get_method(edge.src)
        dst_method = get_method(edge.dst)
        if src_method is None or dst_method is None:
            continue
        if src_method.id != dst_method.id:
            continue  # skip inter-procedural CFG (can happen with inline calls)
        mi = method_index.get(src_method.id)
        if mi is None:
            continue  # external or no file

        src_node = cpg.node(edge.src)
        dst_node = cpg.node(edge.dst)
        src_line = src_node.location.line_number or 0
        dst_line = dst_node.location.line_number or 0

        if src_line <= 0 or dst_line <= 0:
            continue
        if src_line == dst_line:
            continue  # same-line edges not useful for ICFG

        key = (mi["filename"], mi["name"], src_line, dst_line, "cfg", "")
        if key not in seen:
            seen.add(key)
            rows.append([mi["filename"], mi["name"], src_line, dst_line, "cfg", ""])

    return rows


def _extract_entry_exit_edges(method_index: dict, seen_edges: set) -> list:
    """Add synthetic entry (0 -> start) and exit (end -> end+1) edges per method."""
    rows = []
    for node_id, mi in method_index.items():
        if mi is None:
            continue
        start = mi["start_line"]
        end = mi["end_line"]
        if start <= 0:
            continue

        # Entry edge
        entry_key = (mi["filename"], mi["name"], 0, start, "cfg", "")
        if entry_key not in seen_edges:
            rows.append([mi["filename"], mi["name"], 0, start, "cfg", ""])

        # Exit edge
        if end > start:
            exit_key = (mi["filename"], mi["name"], end, end + 1, "cfg", "")
            if exit_key not in seen_edges:
                rows.append([mi["filename"], mi["name"], end, end + 1, "cfg", ""])
    return rows


def _extract_call_return_edges(cpg, method_index: dict) -> list:
    """
    Extract CALL and RETURN edges from CPG.

    For each CALL node:
      1. Find enclosing method (caller)
      2. Follow CALL edge to find callee METHOD(s)
      3. Emit call edge: [caller_file, caller_func, call_line, 0, "call", callee_name]
      4. Emit return edge: [callee_file, callee_name, callee_end, call_line+1, "return", caller_func]
    """
    rows = []
    seen = set()

    for node in cpg.nodes_by_label("CALL"):
        caller_method = cpg.enclosing_method(node)
        if caller_method is None:
            continue
        caller_mi = method_index.get(caller_method.id)
        if caller_mi is None:
            continue

        call_line = node.location.line_number or 0
        if call_line <= 0:
            # Try to get line from properties
            call_line = node.properties.get("LINE_NUMBER", 0)

        # Resolve callees
        callees = cpg.call_targets(node)
        if not callees:
            # Unresolved call — still emit call edge with empty target
            name = node.properties.get("NAME", "")
            if not name:
                continue
            key = (caller_mi["filename"], caller_mi["name"], call_line, 0,
                   "call", name)
            if key not in seen:
                seen.add(key)
                rows.append([caller_mi["filename"], caller_mi["name"],
                            call_line, 0, "call", name])
            continue

        for callee in callees:
            callee_mi = method_index.get(callee.id)
            if callee_mi is None:
                # External callee — emit call edge only
                callee_name = callee.properties.get("NAME", "")
                if not callee_name:
                    continue
                key = (caller_mi["filename"], caller_mi["name"], call_line, 0,
                       "call", callee_name)
                if key not in seen:
                    seen.add(key)
                    rows.append([caller_mi["filename"], caller_mi["name"],
                                call_line, 0, "call", callee_name])
                continue

            callee_name = callee_mi["name"]

            # Call edge: caller callsite -> callee
            call_key = (caller_mi["filename"], caller_mi["name"], call_line, 0,
                        "call", callee_name)
            if call_key not in seen:
                seen.add(call_key)
                rows.append([caller_mi["filename"], caller_mi["name"],
                            call_line, 0, "call", callee_name])

            # Return edge: callee exit -> caller continuation (if callee has end_line)
            if callee_mi["end_line"] > 0:
                ret_key = (callee_mi["filename"], callee_name,
                          callee_mi["end_line"], call_line + 1,
                          "return", caller_mi["name"])
                if ret_key not in seen:
                    seen.add(ret_key)
                    rows.append([callee_mi["filename"], callee_name,
                                callee_mi["end_line"], call_line + 1,
                                "return", caller_mi["name"]])

    return rows


def cpg_to_icfg(cpg_path: str, output_csv: str) -> dict:
    """
    Extract ICFG from a CPG binary and write to CSV.

    Args:
        cpg_path: Path to the cpg.bin file.
        output_csv: Path for the output CSV file.

    Returns:
        Dict with: edges, cfg_edges, call_edges, return_edges,
                   methods, files, elapsed_s, error
    """
    import scubatrace.cpg as cpg_mod

    start = time.time()

    if not os.path.exists(cpg_path):
        return {"edges": 0, "cfg_edges": 0, "call_edges": 0, "return_edges": 0,
                "methods": 0, "files": 0,
                "elapsed_s": time.time() - start,
                "error": f"CPG file not found: {cpg_path}"}

    try:
        cpg = cpg_mod.load(cpg_path)
    except Exception as e:
        return {"edges": 0, "cfg_edges": 0, "call_edges": 0, "return_edges": 0,
                "methods": 0, "files": 0,
                "elapsed_s": time.time() - start,
                "error": f"CPG load failed: {e}"}

    # Build method index
    method_index = _build_method_index(cpg)
    valid_methods = sum(1 for v in method_index.values() if v is not None)
    if valid_methods == 0:
        return {"edges": 0, "cfg_edges": 0, "call_edges": 0, "return_edges": 0,
                "methods": 0, "files": 0,
                "elapsed_s": time.time() - start,
                "error": "No valid (non-external) methods in CPG"}

    # Extract edges
    cfg_rows = _extract_cfg_edges(cpg, method_index)

    # Add entry/exit edges
    seen = set((r[0], r[1], r[2], r[3], r[4], r[5]) for r in cfg_rows)
    entry_exit_rows = _extract_entry_exit_edges(method_index, seen)

    # Call and return edges
    cr_rows = _extract_call_return_edges(cpg, method_index)

    all_rows = cfg_rows + entry_exit_rows + cr_rows

    # Count by type
    cfg_count = sum(1 for r in all_rows if r[4] == "cfg")
    call_count = sum(1 for r in all_rows if r[4] == "call")
    return_count = sum(1 for r in all_rows if r[4] == "return")

    # Extract unique files
    files_set = set()
    for mi in method_index.values():
        if mi and mi["filename"]:
            files_set.add(mi["filename"])

    # Write CSV
    os.makedirs(os.path.dirname(output_csv) if os.path.dirname(output_csv) else ".", exist_ok=True)
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "function", "srcLine", "dstLine",
                         "edge_type", "target_function"])
        writer.writerows(all_rows)

    elapsed = time.time() - start
    return {
        "edges": len(all_rows),
        "cfg_edges": cfg_count,
        "call_edges": call_count,
        "return_edges": return_count,
        "methods": valid_methods,
        "files": len(files_set),
        "elapsed_s": elapsed,
        "error": None,
    }


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: cpg_to_icfg.py <cpg_path> <output_csv>")
        sys.exit(1)

    cpg_path = sys.argv[1]
    output_csv = sys.argv[2]

    print(f"Extracting ICFG from CPG: {cpg_path}")
    result = cpg_to_icfg(cpg_path, output_csv)
    for k, v in result.items():
        print(f"  {k}: {v}")
