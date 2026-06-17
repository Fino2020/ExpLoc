"""
Tree-sitter call site finder — finds function call sites via source parsing.

Returns call site info that the search engine uses for entry_to_call jump edges.
Does NOT modify the ICFG graph directly (avoids frontier explosion).

Usage:
    from ts_call_builder import find_call_sites
    sites = find_call_sites(repo_path, language, icfg)
    # sites = {func_name: [(call_site_node_id, edge_data), ...]}
"""

import os
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from shared.tree_sitter_utils import _get_parser, EXT_TO_LANG

# ---------------------------------------------------------------------------
# Function definition node types per language
# ---------------------------------------------------------------------------

_FUNC_DEF_TYPES = {
    "c":    {"function_definition"},
    "cpp":  {"function_definition"},
    "python": {"function_definition", "async_function_definition"},
    "javascript": {"function_declaration", "function_expression", "arrow_function",
                   "generator_function_declaration", "method_definition"},
    "java": {"method_declaration", "constructor_declaration"},
    "go":   {"function_declaration", "method_declaration"},
    "ruby": {"method", "singleton_method"},
    "rust": {"function_item", "function_signature_item"},
    "php":  {"function_definition", "method_declaration"},
}

# Call expression node types
_CALL_TYPES = {
    "c":    {"call_expression"},
    "cpp":  {"call_expression"},
    "python": {"call"},
    "javascript": {"call_expression"},
    "java": {"method_invocation"},
    "go":   {"call_expression"},
    "ruby": {"call", "method_call", "function_call"},
    "rust": {"call_expression"},
    "php":  {"function_call_expression", "method_declaration"},
}


def find_call_sites(repo_path: str, language: str, icfg=None) -> Dict[str, List[Tuple[str, dict]]]:
    """Find function call sites via tree-sitter.

    Returns {func_name: [(call_site_node_id, {"target_function": callee, "edge_type": "ts_call"}), ...]}
    where call_site_node_id is an ICFG node ID matching the call site location.
    """
    lang_key = _resolve_lang(language)
    if not lang_key or not os.path.isdir(repo_path):
        return {}

    source_files = _find_source_files(repo_path, lang_key)
    if not source_files:
        return {}

    # Build function def index
    func_defs = _build_func_def_index(source_files, lang_key)

    # Build callee name → (file_path, start_line) map
    name_to_def: Dict[str, Tuple[str, int]] = {}
    for (fp, fn_name), (s_line, e_line) in func_defs.items():
        if fn_name not in name_to_def:
            name_to_def[fn_name] = (fp, s_line)

    # Build ICFG node index: (file, function, line) → node_id
    icfg_nodes = _index_icfg_nodes(icfg)

    # For each file, find calls and map to ICFG nodes
    result: Dict[str, List[Tuple[str, dict]]] = defaultdict(list)
    seen_edges: Set[Tuple[str, str]] = set()  # (caller_func, callee) dedup

    for fp in source_files:
        _extract_calls(fp, lang_key, func_defs, name_to_def, icfg, icfg_nodes, repo_path, result, seen_edges)

    return dict(result)


def _resolve_lang(language: str) -> Optional[str]:
    mapping = {
        "c": "c", "c++": "cpp", "cpp": "cpp",
        "python": "python", "py": "python",
        "javascript": "javascript", "js": "javascript", "typescript": "javascript",
        "java": "java", "go": "go", "golang": "go",
        "ruby": "ruby", "rb": "ruby",
        "rust": "rust", "rs": "rust",
        "php": "php",
    }
    return mapping.get(language.lower().strip())


def _find_source_files(repo_path: str, lang_key: str) -> List[str]:
    ext_map = {ext: l for ext, l in EXT_TO_LANG.items() if l == lang_key}
    exts = set(ext_map.keys())
    if not exts:
        return []
    files = []
    for root, dirs, _fnames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in (
            "node_modules", "build", "dist", ".git", "__pycache__",
            "vendor", "third_party", "third-party", "3rdparty",
        )]
        for fname in _fnames:
            if os.path.splitext(fname)[1].lower() in exts:
                files.append(os.path.join(root, fname))
    return files


def _build_func_def_index(source_files: List[str], lang_key: str) -> Dict[Tuple[str, str], Tuple[int, int]]:
    def_types = _FUNC_DEF_TYPES.get(lang_key, set())
    if not def_types:
        return {}
    parser = _get_parser(lang_key)
    if parser is None:
        return {}
    func_defs: Dict[Tuple[str, str], Tuple[int, int]] = {}
    for fp in source_files:
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            continue
        if not source.strip():
            continue
        tree = parser.parse(bytes(source, "utf-8"))
        _walk_defs(tree.root_node, fp, source, func_defs, def_types)
    return func_defs


def _walk_defs(node, file_path: str, source: str, func_defs: Dict[Tuple[str, str], Tuple[int, int]], def_types: set):
    if node.type in def_types:
        name = _extract_func_name(node)
        if name:
            key = (file_path, name)
            if key not in func_defs:
                func_defs[key] = (node.start_point[0] + 1, node.end_point[0] + 1)
    for child in node.children:
        _walk_defs(child, file_path, source, func_defs, def_types)


def _extract_func_name(node) -> Optional[str]:
    name_node = node.child_by_field_name("name")
    if name_node:
        try:
            return name_node.text.decode()
        except Exception:
            pass
    declarator = node.child_by_field_name("declarator")
    if declarator:
        return _find_declarator_name(declarator)
    return None


def _find_declarator_name(node) -> Optional[str]:
    if node.type == "identifier":
        try:
            return node.text.decode()
        except Exception:
            return None
    for child in node.children:
        if child.type in ("identifier", "field_identifier"):
            try:
                return child.text.decode()
            except Exception:
                return None
        result = _find_declarator_name(child)
        if result:
            return result
    return None


def _index_icfg_nodes(icfg) -> Dict[Tuple[str, str, int], str]:
    """Build (file, function, line) → node_id index."""
    if not icfg or not hasattr(icfg, "graph"):
        return {}
    idx = {}
    for node_id, data in icfg.graph.nodes(data=True):
        f = data.get("file", "")
        fn = data.get("function", "")
        line = data.get("line", 0)
        if f and fn:
            idx[(f, fn, line)] = node_id
    return idx


def _extract_calls(
    fp: str, lang_key: str,
    func_defs: Dict[Tuple[str, str], Tuple[int, int]],
    name_to_def: Dict[str, Tuple[str, int]],
    icfg, icfg_nodes: Dict, repo_path: str,
    result: Dict[str, List[Tuple[str, dict]]],
    seen_edges: Set[Tuple[str, str]],
):
    parser = _get_parser(lang_key)
    if parser is None:
        return
    try:
        with open(fp, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except Exception:
        return
    if not source.strip():
        return
    tree = parser.parse(bytes(source, "utf-8"))
    call_types = _CALL_TYPES.get(lang_key, set())
    if not call_types:
        return

    rel_path = _rel_path(fp, repo_path)

    # Scan for calls and add to result
    _scan_calls(tree.root_node, source, call_types, func_defs, name_to_def,
                icfg, icfg_nodes, rel_path, fp, result, seen_edges, set())


def _scan_calls(
    node, source: str, call_types: set,
    func_defs: Dict[Tuple[str, str], Tuple[int, int]],
    name_to_def: Dict[str, Tuple[str, int]],
    icfg, icfg_nodes: Dict, rel_path: str, fp: str,
    result: Dict[str, List[Tuple[str, dict]]],
    seen_edges: Set[Tuple[str, str]],
    visited_callees: set,
):
    if node.type in call_types:
        callee = _extract_callee_name(node, source)
        if callee and callee not in visited_callees and callee in name_to_def:
            visited_callees.add(callee)
            caller_func = _find_enclosing_func(node)
            if not caller_func or (caller_func, callee) in seen_edges:
                return
            seen_edges.add((caller_func, callee))

            call_line = node.start_point[0] + 1

            # Find ICFG node matching this call site
            call_node_id = icfg_nodes.get((rel_path, caller_func, call_line))
            if not call_node_id:
                # Try nearby lines
                for delta in range(-2, 3):
                    if delta == 0:
                        continue
                    call_node_id = icfg_nodes.get((rel_path, caller_func, call_line + delta))
                    if call_node_id:
                        break

            if call_node_id:
                edge_data = {
                    "target_function": callee,
                    "edge_type": "ts_call",
                    "source_function": caller_func,
                }
                result[caller_func].append((call_node_id, edge_data))

    if node.child_count < 500:
        for child in node.children:
            _scan_calls(child, source, call_types, func_defs, name_to_def,
                       icfg, icfg_nodes, rel_path, fp, result, seen_edges, visited_callees)


def _extract_callee_name(node, source: str) -> Optional[str]:
    try:
        # Python/JS/C/etc: "function" field
        func_node = node.child_by_field_name("function")
        if not func_node:
            # Java: "name" field (method_invocation)
            func_node = node.child_by_field_name("name")
        if func_node:
            text = func_node.text.decode().strip()
            if "." in text:
                text = text.split(".")[-1]
            text = text.split("(")[0].strip()
            if text and not text[0].isdigit() and text not in ("if", "while", "for", "switch", "catch"):
                return text
        # Java: sometimes the method name is a direct child identifier
        for child in node.children:
            if child.type == "identifier":
                return child.text.decode().strip()
    except Exception:
        pass
    return None


def _find_enclosing_func(node) -> Optional[str]:
    parent = node.parent
    depth = 0
    while parent and depth < 20:
        name = _extract_func_name(parent)
        if name:
            return name
        parent = parent.parent
        depth += 1
    return None


def _rel_path(abs_path: str, repo_path: str) -> str:
    try:
        return os.path.relpath(abs_path, repo_path)
    except ValueError:
        return abs_path


# ---------------------------------------------------------------------------
# Lightweight call graph (no ICFG dependency)
# ---------------------------------------------------------------------------

class CallGraph:
    """Minimal call graph built from tree-sitter, replacing ICFG for mock search.

    Nodes: file:func:line format
    Edges: entry_to_call (entry → call site), call (call site → callee entry)
    No cfg edges — much smaller than ICFG.
    """

    def __init__(self):
        self.graph = None  # NetworkX DiGraph, built lazily
        self.function_entries: Dict[str, str] = {}  # func_name → node_id
        self.function_exits: Dict[str, List[str]] = {}  # func_name → [exit_node_id]

    @property
    def stats(self):
        if self.graph is None:
            return {"nodes": 0, "edges": 0}
        return {"nodes": self.graph.number_of_nodes(), "edges": self.graph.number_of_edges()}

    def get_node_data(self, node_id: str) -> dict:
        if self.graph is None:
            return {}
        return self.graph.nodes.get(node_id, {})

    def get_neighbors(self, node_id: str):
        if self.graph is None:
            return []
        return [(dst, data) for _, dst, data in self.graph.out_edges(node_id, data=True)]

    def get_entry_node(self, func_name: str) -> Optional[str]:
        return self.function_entries.get(func_name)


def build_call_graph(
    repo_path: str,
    language: str,
    target_files: Optional[List[str]] = None,
    target_functions: Optional[set] = None,
    max_depth: int = 3,
    max_files: int = 500,
    timeout_seconds: float = 60.0,
) -> CallGraph:
    """Build a focused call graph covering step1-suspicious files/functions.

    1. Parse target_files with tree-sitter → find function defs and call sites.
    2. Iteratively expand to callees not yet in the graph (up to max_depth).
    3. Return CallGraph with entry_to_call and call edges.

    Memory-efficient: only processes files that contribute to the subgraph.
    max_files: max source files to scan (prevents hang on huge repos).
    timeout_seconds: per-file timeout; if exceeded, returns partial CallGraph.
    """
    import networkx as nx, time as _time
    _t_start = _time.time()

    lang_key = _resolve_lang(language)
    if not lang_key or not os.path.isdir(repo_path):
        return CallGraph()

    # Resolve which files to start from
    if target_files:
        seed_files = [f for f in target_files if os.path.isfile(f)]
        if not seed_files:
            seed_files = _find_source_files(repo_path, lang_key)
    else:
        seed_files = _find_source_files(repo_path, lang_key)

    if not seed_files:
        return CallGraph()

    parser = _get_parser(lang_key)
    if parser is None:
        return CallGraph()

    def_types = _FUNC_DEF_TYPES.get(lang_key, set())
    call_types = _CALL_TYPES.get(lang_key, set())
    if not def_types or not call_types:
        return CallGraph()

    # Phase 1: index function definitions and calls in all source files
    all_func_defs: Dict[Tuple[str, str], Tuple[int, int]] = {}    # (file, name) → (start, end)
    all_func_calls: Dict[Tuple[str, str], List[Tuple[str, int]]] = defaultdict(list)  # (file, func) → [(callee, line)]

    files_to_scan = set(seed_files)
    scanned = set()

    def _extract_from_file(fp, source):
        """Extract function defs and calls from a single file's source (with per-file timeout)."""
        import threading
        result = [None]
        exc = [None]
        def _do():
            try:
                tree = parser.parse(bytes(source, "utf-8"))
                _walk_extract(tree.root_node, fp, source, all_func_defs, all_func_calls, def_types, call_types)
            except Exception as e:
                exc[0] = e
        t = threading.Thread(target=_do, daemon=True)
        t.start()
        t.join(timeout=30.0)  # per-file hard timeout
        if t.is_alive():
            return  # skip this file, tree-sitter hung
        if exc[0]:
            raise exc[0]

    # Scan seed files (with max_files and timeout)
    _files_scanned = 0
    for fp in seed_files:
        if _files_scanned >= max_files:
            break
        if _time.time() - _t_start > timeout_seconds:
            break
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            continue
        if not source.strip():
            continue
        _extract_from_file(fp, source)
        scanned.add(fp)
        _files_scanned += 1

    # Phase 2: iterative expansion — follow callees
    round_num = 1
    while round_num < max_depth:
        new_files = set()
        for (fp, func_name), calls in all_func_calls.items():
            for callee_name, _line in calls:
                for (def_fp, def_name), (_s, _e) in all_func_defs.items():
                    if def_name == callee_name and def_fp not in scanned:
                        new_files.add(def_fp)
                        break
        if not new_files:
            break
        for fp in new_files:
            if fp in scanned:
                continue
            if _files_scanned >= max_files:
                break
            if _time.time() - _t_start > timeout_seconds:
                break
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    source = f.read()
            except Exception:
                continue
            if not source.strip():
                continue
            _extract_from_file(fp, source)
            scanned.add(fp)
            _files_scanned += 1
        round_num += 1

    # Phase 3: build NetworkX graph
    graph = nx.DiGraph()
    cg = CallGraph()
    cg.graph = graph

    # Add entry nodes for all user-defined functions
    for (fp, func_name), (s_line, _e_line) in all_func_defs.items():
        rel = os.path.relpath(fp, repo_path)
        entry_id = f"{rel}:{func_name}:0"
        graph.add_node(entry_id, file=rel, function=func_name, line=0, node_type="entry")
        cg.function_entries[func_name] = entry_id
        cg.function_exits[func_name] = []

    # Pre-compute non-leaf function names
    non_leaf_funcs: Set[str] = {k[1] for k, v in all_func_calls.items() if v}

    # Add call site nodes and edges — include library calls as stubs
    for (fp, func_name), calls in all_func_calls.items():
        rel = os.path.relpath(fp, repo_path)
        caller_entry = cg.function_entries.get(func_name)
        if not caller_entry:
            continue

        # Include ALL callees (user-defined + library stubs), sort: step1 first, then by line
        valid_calls = []
        for callee_name, call_line in calls:
            callee_entry = cg.function_entries.get(callee_name)
            if callee_entry is None:
                # Library stub: create fake entry node
                stub_id = f"__lib__:{callee_name}:0"
                if stub_id not in graph:
                    graph.add_node(stub_id, file="__lib__", function=callee_name,
                                   line=0, node_type="library_stub")
                    cg.function_entries[callee_name] = stub_id
                callee_entry = stub_id
            valid_calls.append((call_line, callee_name, callee_entry))

        if not valid_calls:
            continue
        valid_calls.sort(key=lambda x: (0 if target_functions and x[1].lower() in target_functions else 1, x[0]))

        call_site_ids = []
        for call_line, callee_name, callee_entry in valid_calls:

            # Call site node
            call_site_id = f"{rel}:{func_name}:{call_line}"
            if call_site_id not in graph:
                graph.add_node(call_site_id, file=rel, function=func_name,
                               line=call_line, node_type="call_site")
            call_site_ids.append((call_site_id, callee_name, callee_entry))

        # Chain: entry → first call_site (via entry_to_call),
        #        call_site_i → call_site_{i+1} (via entry_to_call, fills next slot)
        for i, (cs_id, callee_name, callee_entry) in enumerate(call_site_ids):
            # entry_to_call from previous node to this call site
            if i == 0:
                prev_node = caller_entry
            else:
                prev_node = call_site_ids[i-1][0]

            if not graph.has_edge(prev_node, cs_id):
                graph.add_edge(prev_node, cs_id,
                               edge_type="entry_to_call",
                               target_function=callee_name)

            # inter_call to callee entry only for non-leaf callees
            if callee_name in non_leaf_funcs:
                if not graph.has_edge(cs_id, callee_entry):
                    graph.add_edge(cs_id, callee_entry,
                                   edge_type="inter_call",
                                   target_function=callee_name)

    return cg


def _walk_extract(node, file_path, source, func_defs, func_calls, def_types, call_types):
    """Walk tree-sitter AST, collecting function defs and calls."""
    if node.type in def_types:
        name = _extract_func_name(node)
        if name:
            key = (file_path, name)
            if key not in func_defs:
                func_defs[key] = (node.start_point[0] + 1, node.end_point[0] + 1)

    if node.type in call_types:
        callee = _extract_callee_name(node, source)
        if callee:
            enclosing = _find_enclosing_func(node)
            if enclosing:
                key = (file_path, enclosing)
                func_calls[key].append((callee, node.start_point[0] + 1))

    if node.child_count < 500:
        for child in node.children:
            _walk_extract(child, file_path, source, func_defs, func_calls, def_types, call_types)
