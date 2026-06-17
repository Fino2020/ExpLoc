"""
Graph adapter — wraps ICFG (CodeQL/ScubaTrace CSV) as a LocAgent-compatible graph.

Provides entity search (by name/type) and dependency traversal (call edges).
Unlike the original LocAgent dependency graph (with directory/file/class/function
nodes and contains/imports/invokes/inherits edges), this adapter works with the
simpler ICFG structure: file + function nodes, cfg + call edges.

Node IDs are formatted as "file_path:function_name" (matching LocAgent convention).
Code content is fetched from actual files on disk via tree-sitter.
"""

import csv
import os
import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

# Node types we expose (subset of LocAgent's VALID_NODE_TYPES)
NODE_TYPE_FILE = "file"
NODE_TYPE_FUNCTION = "function"
NODE_TYPE_CLASS = "class"

VALID_NODE_TYPES = [NODE_TYPE_FILE, NODE_TYPE_FUNCTION, NODE_TYPE_CLASS]

# Edge types
EDGE_TYPE_CALL = "invokes"       # map ICFG "call" to LocAgent "invokes"
EDGE_TYPE_CFG = "cfg"
EDGE_TYPE_CONTAINS = "contains"

VALID_EDGE_TYPES = [EDGE_TYPE_CONTAINS, EDGE_TYPE_CALL, EDGE_TYPE_CFG]


def _is_test_file(nid: str) -> bool:
    file_path = nid.split(":")[0].lower()
    parts = re.split(r"[ /_\-]", file_path)
    return any(p.startswith("test") or p.endswith("test") for p in parts if p)


def wrap_code_snippet(code: str, start_line: int, end_line: int) -> str:
    lines = code.split("\n")
    number_width = max(len(str(end_line)), 3)
    snippet_lines = lines[start_line - 1:end_line]
    return "```\n" + "\n".join(
        f"{str(i + start_line).rjust(number_width)} | {line}"
        for i, line in enumerate(snippet_lines)
    ) + "\n```"


class GraphAdapter:
    """Wraps an ICFG CSV + repo path into a LocAgent-style graph."""

    def __init__(self, icfg_csv_path: str, repo_path: str):
        self.repo_path = repo_path
        self.G = nx.MultiDiGraph()
        self._global_name_dict = None
        self._global_name_dict_lower = None
        self._file_cache: Dict[str, str] = {}

        self._load_icfg(icfg_csv_path)
        self._add_file_nodes()

    # --- ICFG loading ---

    def _load_icfg(self, csv_path: str):
        """Parse ICFG CSV — two-pass for performance.

        Pass 1: collect all (file, function) pairs → build nodes + lookup dict.
        Pass 2: add call edges using the lookup dict.
        CFG edges are skipped (intra-procedural, not needed for traversal).
        """
        if not os.path.exists(csv_path):
            return

        # --- Pass 1: collect data ---
        call_edges = []  # (src_file, src_func, target_func)
        files = set()
        funcs = set()    # (file, function) pairs

        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            headers = [h.strip().lower() for h in next(reader)]

            has_edge_type = "edge_type" in headers
            has_target_func = "target_function" in headers
            file_idx = headers.index("file")
            func_idx = headers.index("function")

            if has_edge_type:
                et_idx = headers.index("edge_type")
            if has_target_func:
                tf_idx = headers.index("target_function")

            for row in reader:
                file_ = row[file_idx]
                func = row[func_idx]
                files.add(file_)
                funcs.add((file_, func))

                if has_edge_type:
                    edge_type = row[et_idx].strip().lower()
                    if edge_type == "call" and has_target_func:
                        target_func = row[tf_idx].strip()
                        if target_func:
                            call_edges.append((file_, func, target_func))

        # --- Build nodes ---
        for file_ in files:
            self.G.add_node(file_, type=NODE_TYPE_FILE)

        # Function name → list of nid for cross-file resolution
        func_name_index = {}
        for file_, func in funcs:
            func_nid = f"{file_}:{func}"
            self.G.add_node(func_nid, type=NODE_TYPE_FUNCTION,
                            file=file_, function=func)
            self.G.add_edge(file_, func_nid, type=EDGE_TYPE_CONTAINS)
            # Index by function name (for cross-file edge resolution)
            if func not in func_name_index:
                func_name_index[func] = []
            func_name_index[func].append(func_nid)

        # --- Pass 2: add call edges ---
        for src_file, src_func, target_func in call_edges:
            src_nid = f"{src_file}:{src_func}"
            # Find target: prefer same-file, then any-file
            candidates = func_name_index.get(target_func, [])
            same_file = [n for n in candidates if n.startswith(f"{src_file}:")]
            if same_file:
                target_nid = same_file[0]
            elif candidates:
                target_nid = candidates[0]
            else:
                # Create placeholder in a shared synthetic file
                target_nid = f"{src_file}:{target_func}"
                if target_nid not in self.G:
                    self.G.add_node(target_nid, type=NODE_TYPE_FUNCTION,
                                    file=src_file, function=target_func)
            self.G.add_edge(src_nid, target_nid, type=EDGE_TYPE_CALL)

    def _add_file_nodes(self):
        """Add file-level nodes for all files in the repo that aren't in ICFG."""
        if not self.repo_path or not os.path.isdir(self.repo_path):
            return
        for root, _, files in os.walk(self.repo_path):
            for fname in files:
                fpath = os.path.relpath(os.path.join(root, fname), self.repo_path)
                fpath = fpath.replace("\\", "/")
                if fpath in self.G:
                    continue
                # Only add source files
                ext = os.path.splitext(fname)[1].lower()
                if ext in _SOURCE_EXTS:
                    self.G.add_node(fpath, type=NODE_TYPE_FILE)

    # --- Name indices (like LocAgent's RepoEntitySearcher) ---

    @property
    def global_name_dict(self) -> Dict[str, List[str]]:
        if self._global_name_dict is None:
            d = defaultdict(list)
            for nid in self.G.nodes():
                if _is_test_file(nid):
                    continue
                if nid.endswith(tuple(_SOURCE_EXTS)):
                    fname = os.path.basename(nid)
                    d[fname].append(nid)
                    name = os.path.splitext(fname)[0]
                    d[name].append(nid)
                elif ":" in nid and ":" not in nid.split(":", 1)[1]:
                    # file:function format (no line number)
                    name = nid.split(":")[-1].split(".")[-1]
                    d[name].append(nid)
            self._global_name_dict = dict(d)
        return self._global_name_dict

    @property
    def global_name_dict_lowercase(self) -> Dict[str, List[str]]:
        if self._global_name_dict_lower is None:
            d = defaultdict(list)
            for name, nids in self.global_name_dict.items():
                d[name.lower()].extend(nids)
            self._global_name_dict_lower = dict(d)
        return self._global_name_dict_lower

    # --- Node operations ---

    def has_node(self, nid: str, include_test: bool = False) -> bool:
        if not include_test and _is_test_file(nid):
            return False
        return nid in self.G

    def get_node_data(self, nids: List[str], return_code_content: bool = False,
                      wrap_with_ln: bool = True) -> List[dict]:
        results = []
        for nid in nids:
            if nid not in self.G:
                continue
            node = self.G.nodes[nid]
            data = {
                "node_id": nid,
                "type": node.get("type", NODE_TYPE_FUNCTION),
            }
            if return_code_content:
                code = self._get_code_for_node(nid, node)
                if code:
                    sl = node.get("start_line", 1)
                    el = node.get("end_line", len(code.split("\n")))
                    data["start_line"] = sl
                    data["end_line"] = el
                    if wrap_with_ln:
                        data["code_content"] = wrap_code_snippet(code, sl, el)
                    else:
                        data["code_content"] = code
            else:
                sl = node.get("start_line", None)
                if sl is not None:
                    data["start_line"] = sl
                el = node.get("end_line", None)
                if el is not None:
                    data["end_line"] = el
            results.append(data)
        return results

    def _get_code_for_node(self, nid: str, node: dict) -> str:
        """Fetch actual code content for a node from the source file."""
        file_path = node.get("file", nid.split(":")[0])
        full_path = os.path.join(self.repo_path, file_path)

        if file_path not in self._file_cache:
            if os.path.isfile(full_path):
                try:
                    with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                        self._file_cache[file_path] = f.read()
                except Exception:
                    self._file_cache[file_path] = ""
            else:
                self._file_cache[file_path] = ""

        return self._file_cache.get(file_path, "")

    def get_all_nodes_by_type(self, ntype: str) -> List[dict]:
        nodes = []
        for nid in self.G.nodes():
            if _is_test_file(nid):
                continue
            node = self.G.nodes[nid]
            if node.get("type") != ntype:
                continue
            if ntype == NODE_TYPE_FILE:
                nodes.append({"name": nid, "type": ntype})
            elif ntype == NODE_TYPE_FUNCTION:
                file_ = node.get("file", nid.split(":")[0])
                name = nid.split(":")[-1]
                nodes.append({
                    "name": name,
                    "file": file_,
                    "type": ntype,
                    "start_line": node.get("start_line", 0),
                    "end_line": node.get("end_line", 0),
                })
        return nodes

    # --- Dependency search ---

    def get_neighbors(self, nid: str, direction: str = "forward",
                      ntype_filter: Optional[List[str]] = None,
                      etype_filter: Optional[List[str]] = None,
                      ignore_test_file: bool = True) -> Tuple[List[str], List[tuple]]:
        nodes, edges = [], []
        if direction == "forward":
            for sn in self.G.successors(nid):
                if ignore_test_file and _is_test_file(sn):
                    continue
                if ntype_filter and self.G.nodes[sn].get("type") not in ntype_filter:
                    continue
                for key, edge_data in self.G.get_edge_data(nid, sn).items():
                    etype = edge_data.get("type", "")
                    if etype_filter and etype not in etype_filter:
                        continue
                    edges.append((nid, sn, 0, {"type": etype}))
                    nodes.append(sn)
        elif direction == "backward":
            for pn in self.G.predecessors(nid):
                if ignore_test_file and _is_test_file(pn):
                    continue
                if ntype_filter and self.G.nodes[pn].get("type") not in ntype_filter:
                    continue
                for key, edge_data in self.G.get_edge_data(pn, nid).items():
                    etype = edge_data.get("type", "")
                    if etype_filter and etype not in etype_filter:
                        continue
                    edges.append((pn, nid, 0, {"type": etype}))
                    nodes.append(pn)
        return nodes, edges


# Source file extensions to consider
_SOURCE_EXTS = {
    ".py", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh",
    ".java", ".kt", ".kts", ".scala",
    ".js", ".ts", ".jsx", ".tsx", ".mjs",
    ".go", ".rs", ".rb", ".php", ".swift",
    ".cs", ".vb", ".pl", ".pm", ".sh", ".bash",
}
