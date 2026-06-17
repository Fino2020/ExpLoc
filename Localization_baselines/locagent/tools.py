"""
LocAgent tools adapted to ICFG graph + filesystem code access.

Three tools matching the original LocAgent interface:
- search_code_snippets: search entities by name + BM25 keyword + line-based retrieval
- explore_tree_structure: tree-format dependency traversal
- explore_graph_structure: DOT/pydot-format graph traversal
"""

import fnmatch
import json
import os
import re
from collections import defaultdict
from copy import deepcopy
from typing import Dict, List, Optional, Tuple

import networkx as nx

from .graph_adapter import (
    GraphAdapter,
    NODE_TYPE_FILE,
    NODE_TYPE_FUNCTION,
    NODE_TYPE_CLASS,
    EDGE_TYPE_CALL,
    EDGE_TYPE_CONTAINS,
    EDGE_TYPE_CFG,
    VALID_NODE_TYPES,
    VALID_EDGE_TYPES,
    _is_test_file,
    wrap_code_snippet,
)
from .bm25_retriever import BM25Retriever

# ---------------------------------------------------------------------------
# Global state (set per CVE)
# ---------------------------------------------------------------------------

_graph: Optional[GraphAdapter] = None
_bm25: Optional[BM25Retriever] = None
_repo_path: str = ""


def init_tools(graph_adapter: GraphAdapter, bm25: BM25Retriever, repo_path: str):
    global _graph, _bm25, _repo_path
    _graph = graph_adapter
    _bm25 = bm25
    _repo_path = repo_path


# ---------------------------------------------------------------------------
# Helper: entity search
# ---------------------------------------------------------------------------

def _search_entity_in_graph(term: str, include_files: Optional[List[str]] = None,
                            prefix_term: Optional[str] = None) -> Optional[Dict[str, List[str]]]:
    """Search for an entity by name in the graph's global name dict."""
    graph = _graph
    if term.startswith(("class ", "Class ")):
        term = term[len("class "):].strip()
    elif term.startswith(("function ", "Function ", "def ")):
        term = term.split(" ", 1)[-1].strip()
    elif term.startswith(("method ", "Method ")):
        term = term[len("method "):].strip()

    gdict = None
    if term in graph.global_name_dict:
        gdict = graph.global_name_dict
        nids = gdict[term]
    elif term.lower() in graph.global_name_dict_lowercase:
        gdict = graph.global_name_dict_lowercase
        nids = gdict[term.lower()]
    else:
        return None

    found = defaultdict(list)
    for ndata in graph.get_node_data(nids):
        nfile = ndata["node_id"].split(":")[0]
        if include_files and nfile not in include_files:
            continue
        prefix_terms = []
        if prefix_term:
            prefix_terms = prefix_term.lower().split(".")
        candidate_prefixes = re.split(r"[./:]", ndata["node_id"].lower().replace(".py", ""))[:-1]
        if not prefix_term or all(p in candidate_prefixes for p in prefix_terms):
            found[ndata["type"]].append(ndata["node_id"])

    return dict(found) if found else None


def _search_entity(term: str, include_files: Optional[List[str]] = None) -> Tuple[List[dict], bool]:
    """Multi-level entity search: exact → global dict → BM25 → fuzzy."""
    graph = _graph
    results = []
    continue_search = True

    # Level 1: exact match in graph
    if graph.has_node(term):
        results.append(_make_result(term, "complete",
                                    f"Exact match found for entity `{term}`."))
        return results, False

    # Level 2: search global name dict
    found = _search_entity_in_graph(term, include_files)
    if not found:
        found = _search_entity_in_graph(term)

    used_term = term
    if not found and "." in term:
        parts = term.rsplit(".", 1)
        prefix_term = parts[0].split()[-1]
        split_term = parts[-1].strip()
        used_term = split_term
        found = _search_entity_in_graph(split_term, include_files, prefix_term)
        if not found:
            found = _search_entity_in_graph(split_term, prefix_term=prefix_term)

    if found:
        for ntype, nids in found.items():
            if not nids:
                continue
            node_datas = graph.get_node_data(nids, return_code_content=(len(nids) <= 3))
            for ndata in node_datas:
                if len(nids) <= 3:
                    results.append(_make_result(
                        ndata["node_id"], "preview",
                        f"Match found for `{used_term}`.",
                        ntype=ndata["type"],
                        start_line=ndata.get("start_line"),
                        end_line=ndata.get("end_line"),
                    ))
                else:
                    results.append(_make_result(
                        ndata["node_id"], "fold",
                        f"Match found for `{used_term}`.",
                        ntype=ndata["type"],
                    ))
        continue_search = False

    # Level 3: BM25
    if continue_search and _bm25:
        bm25_results = _bm25.retrieve(term, similarity_top_k=10, include_files=include_files)
        if not bm25_results:
            bm25_results = _bm25.retrieve(term, similarity_top_k=10)

        for br in bm25_results[:5]:
            fpath = br["file"]
            # Check for matching entities in the chunk's line range
            nids_in_range = _find_entities_in_range(fpath, br["start_line"], br["end_line"])
            if nids_in_range:
                for nid in nids_in_range[:3]:
                    ndata = graph.get_node_data([nid], return_code_content=True)
                    if ndata:
                        results.append(_make_result(
                            nid, "preview",
                            f"Retrieved using keyword search (BM25).",
                            ntype=ndata[0]["type"],
                            start_line=ndata[0].get("start_line"),
                            end_line=ndata[0].get("end_line"),
                        ))
            else:
                results.append(_make_result(
                    fpath, "code_snippet",
                    f"Retrieved code content using BM25.",
                    file_path=fpath,
                    start_line=br["start_line"],
                    end_line=br["end_line"],
                ))

    return results, continue_search


def _find_entities_in_range(file_path: str, start: int, end: int) -> List[str]:
    """Find function/class nodes in a file within a line range."""
    graph = _graph
    found = []
    for nid in graph.G.nodes():
        if not nid.startswith(file_path + ":"):
            continue
        node = graph.G.nodes[nid]
        sl = node.get("start_line", 0)
        el = node.get("end_line", 0)
        if sl and el and max(sl, start) <= min(el, end):
            found.append(nid)
    return found


def _make_result(nid: str, fmt: str, retrieve_src: str,
                 ntype: Optional[str] = None, file_path: Optional[str] = None,
                 start_line: Optional[int] = None, end_line: Optional[int] = None) -> dict:
    return {
        "nid": nid,
        "format": fmt,
        "retrieve_src": retrieve_src,
        "ntype": ntype,
        "file_path": file_path or (nid.split(":")[0] if ":" in nid else nid),
        "start_line": start_line,
        "end_line": end_line,
    }


# ---------------------------------------------------------------------------
# Tool 1: search_code_snippets
# ---------------------------------------------------------------------------

def search_code_snippets(
    search_terms: Optional[List[str]] = None,
    line_nums: Optional[List[int]] = None,
    file_path_or_pattern: Optional[str] = "**/*"
) -> str:
    """Searches the codebase to retrieve relevant code snippets.

    Args:
        search_terms: names, keywords, or code snippets to search for.
            Format: 'file_path:QualifiedName' for specific entity,
            or 'file_path' for full file content.
        line_nums: specific line numbers within file_path_or_pattern.
        file_path_or_pattern: glob pattern or file path to filter results.

    Returns:
        Formatted search results with code snippets and entity matches.
    """
    graph = _graph
    all_files = [f["name"] for f in graph.get_all_nodes_by_type(NODE_TYPE_FILE)]

    # Resolve file filter
    if file_path_or_pattern and file_path_or_pattern != "**/*":
        include_files = _match_files_from_list(all_files, file_path_or_pattern)
        if not include_files:
            include_files = all_files
    else:
        include_files = all_files

    result_parts = []
    all_query_results = []

    if search_terms:
        filter_terms = [t for t in search_terms if not _is_test_file(t)]
        for term in filter_terms:
            term = term.strip().strip(".")
            if not term:
                continue

            # Try exact entity match first
            query_results, continue_search = _search_entity(term, include_files)
            all_query_results.extend(query_results)

            # Fall back to BM25 content search
            if continue_search and _bm25:
                bm25_results = _bm25.retrieve(term, similarity_top_k=10,
                                             include_files=include_files)
                for br in bm25_results[:5]:
                    all_query_results.append(_make_result(
                        br["file"], "code_snippet",
                        f"Retrieved code content using BM25.",
                        file_path=br["file"],
                        start_line=br["start_line"],
                        end_line=br["end_line"]))

    # Line-based retrieval
    if line_nums and file_path_or_pattern in all_files:
        if isinstance(line_nums, int):
            line_nums = [line_nums]
        code = _read_file(file_path_or_pattern)
        if code:
            lines = code.split("\n")
            for ln in line_nums:
                start = max(1, ln - 10)
                end = min(len(lines), ln + 10)
                snippet = wrap_code_snippet(code, start, end)
                result_parts.append(
                    f"## Code at {file_path_or_pattern}:{ln}\n"
                    f"### Result:\n{snippet}\n"
                )

    # Format entity/BM25 results
    merged = _merge_query_results(all_query_results)
    for group in merged:
        result_parts.append(_format_result_group(group, graph))
        result_parts.append("")

    return "\n".join(result_parts).strip() or "No locations found."


def _match_files_from_list(file_list: List[str], pattern: str) -> List[str]:
    if "*" in pattern or "?" in pattern or "[" in pattern:
        return fnmatch.filter(file_list, pattern)
    return [f for f in file_list if pattern in f]


def _read_file(rel_path: str) -> Optional[str]:
    full = os.path.join(_repo_path, rel_path)
    if os.path.isfile(full):
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception:
            return None
    return None


def _merge_query_results(results: List[dict]) -> List[List[dict]]:
    """Group results by query uniqueness, dedup by nid."""
    seen = {}
    for r in results:
        nid = r.get("nid", "")
        if nid and nid in seen:
            if _fmt_priority(r["format"]) < _fmt_priority(seen[nid]["format"]):
                seen[nid] = r
        elif nid:
            seen[nid] = r

    # Group by file
    by_file = defaultdict(list)
    for r in seen.values():
        f = r.get("file_path", "")
        by_file[f].append(r)

    # Flatten: each file's results as a group
    groups = []
    for f, items in by_file.items():
        groups.append(items)
    return groups


def _fmt_priority(fmt: str) -> int:
    return {"complete": 0, "code_snippet": 1, "preview": 2, "fold": 3}.get(fmt, 4)


def _format_result_group(items: List[dict], graph: GraphAdapter) -> str:
    lines = []
    for item in items:
        nid = item["nid"]
        fmt = item["format"]
        src = item.get("retrieve_src", "")
        ntype = item.get("ntype", "")

        if fmt == "complete":
            ndata = graph.get_node_data([nid], return_code_content=True)
            if ndata:
                lines.append(f"Found {ndata[0]['type']} `{nid}`.")
                lines.append(f"Source: {src}")
                if "code_content" in ndata[0]:
                    lines.append(ndata[0]["code_content"])

        elif fmt == "preview":
            ndata = graph.get_node_data([nid], return_code_content=True)
            if ndata:
                lines.append(f"Found {ndata[0]['type']} `{nid}`.")
                lines.append(f"Source: {src}")
                if ndata[0].get("code_content"):
                    content = ndata[0]["code_content"]
                    # Truncate if too long (>100 lines)
                    if ndata[0].get("end_line", 0) - ndata[0].get("start_line", 0) > 100:
                        lines.append(f"(Large {ndata[0]['type']} — showing structure)")
                        lines.append(content[:2000] + "\n...")
                        lines.append(f"Hint: Search `{nid}` for full content.")
                    else:
                        lines.append(content)

        elif fmt == "code_snippet":
            fpath = item.get("file_path", "")
            code = _read_file(fpath)
            if code:
                sl = item.get("start_line", 1)
                el = item.get("end_line", sl + 20)
                snippet = wrap_code_snippet(code, sl, el)
                lines.append(f"Found code in `{fpath}` lines {sl}-{el}:")
                lines.append(f"Source: {src}")
                lines.append(snippet)

        elif fmt == "fold":
            lines.append(f"Found {ntype} `{nid}`.")
            lines.append(f"Source: {src}")
            lines.append(f"Hint: Search `{nid}` for full content.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool 2 & 3: Graph traversal
# ---------------------------------------------------------------------------

def _traverse_graph(start_entities: List[str], direction: str = "downstream",
                    hops: int = 2, node_type_filter: Optional[List[str]] = None,
                    edge_type_filter: Optional[List[str]] = None) -> Tuple[nx.MultiDiGraph, str]:
    """BFS traversal of the ICFG graph. Returns subgraph + hints."""
    graph = _graph
    G = graph.G
    valid_entities, hints = _validate_entities(start_entities, graph)

    subG = nx.MultiDiGraph()
    for e in valid_entities:
        subG.add_node(e)

    frontiers = [(nid, 0) for nid in valid_entities]
    visited = []

    while frontiers:
        nid, level = frontiers.pop()
        if nid in visited or abs(level) >= hops:
            continue
        visited.append(nid)

        if level > 0 or (level == 0 and direction in ("downstream", "both")):
            nodes, edges = graph.get_neighbors(
                nid, "forward", ntype_filter=node_type_filter,
                etype_filter=edge_type_filter)
            frontiers.extend((n, level + 1) for n in nodes)
            subG.add_edges_from(edges)

        if level < 0 or (level == 0 and direction in ("upstream", "both")):
            nodes, edges = graph.get_neighbors(
                nid, "backward", ntype_filter=node_type_filter,
                etype_filter=edge_type_filter)
            frontiers.extend((n, level - 1) for n in nodes)
            subG.add_edges_from(edges)

    return subG, hints


def _validate_entities(entities: List[str], graph: GraphAdapter) -> Tuple[List[str], str]:
    hints = ""
    valid = []
    for root in entities:
        root = root.strip("/")
        if root.endswith(".__init__"):
            root = root[:-len(".__init__")]
        if root not in graph.G:
            # Try BM25 suggestion
            if _bm25:
                results = _bm25.retrieve(root, similarity_top_k=3)
                if results:
                    hints += f"Entity `{root}` not found. Similar entities:\n"
                    for r in results:
                        # Find closest function node
                        nearby = _find_entities_in_range(r["file"], r["start_line"], r["end_line"])
                        for n in nearby[:2]:
                            hints += f"  {graph.G.nodes[n].get('type', '?')}: `{n}`\n"
                    hints += "\n"
                else:
                    hints += f"Entity `{root}` not found in graph.\n\n"
            else:
                hints += f"Entity `{root}` not found in graph.\n\n"
        elif _is_test_file(root):
            hints += f"Skipping test entity: `{root}`.\n\n"
        else:
            valid.append(root)
    return valid, hints


def _to_tree_str(G: nx.MultiDiGraph, root: str, direction: str = "downstream",
                 hops: int = 2, node_type_filter: Optional[List[str]] = None,
                 edge_type_filter: Optional[List[str]] = None) -> str:
    """Format subgraph as ASCII tree (like LocAgent's traverse_tree_structure)."""
    lines = []
    traversed = set()

    def traverse(node, prefix, is_last, level, edge_type, edir):
        if level > hops:
            return
        if node == root and level == 0:
            lines.append(str(node))
            new_prefix = ""
            edir = direction
        else:
            connector = "└── " if is_last else "├── "
            connector += f"{edge_type} ── "
            lines.append(f"{prefix}{connector}{node}")
            new_prefix = prefix + (" " if is_last else "│") + " " * (len(connector) - 1)

        if node in traversed:
            return
        traversed.add(node)

        neighs = []
        if "downstream" == edir or (node == root and direction == "both"):
            for _, sn, data in G.edges(node, data=True):
                etype = data.get("type", "")
                if edge_type_filter and etype not in edge_type_filter:
                    continue
                ntype = G.nodes[sn].get("type", "")
                if node_type_filter and ntype not in node_type_filter:
                    continue
                if not _is_test_file(sn):
                    neighs.append((sn, etype, "downstream"))

        if "upstream" == edir or (node == root and direction == "both"):
            for pn, _, data in G.in_edges(node, data=True):
                etype = data.get("type", "")
                if edge_type_filter and etype not in edge_type_filter:
                    continue
                ntype = G.nodes[pn].get("type", "")
                if node_type_filter and ntype not in node_type_filter:
                    continue
                if not _is_test_file(pn):
                    neighs.append((pn, etype + "-by", "upstream"))

        for i, (neigh_id, etype, edir) in enumerate(neighs):
            is_last_child = (i == len(neighs) - 1)
            traverse(neigh_id, new_prefix, is_last_child, level + 1, etype, edir)

    traverse(root, "", False, 0, None, None)
    return "\n".join(lines)


def explore_tree_structure(
    start_entities: List[str],
    direction: str = "downstream",
    traversal_depth: int = 2,
    entity_type_filter: Optional[List[str]] = None,
    dependency_type_filter: Optional[List[str]] = None,
) -> str:
    """Explore the dependency structure around entities as a tree.

    Args:
        start_entities: entities to start from (e.g., 'file.py:ClassName.method').
        direction: 'upstream' (dependencies), 'downstream' (dependents), or 'both'.
        traversal_depth: max hops (-1 = unlimited, up to 20).
        entity_type_filter: e.g., ['function', 'file'].
        dependency_type_filter: e.g., ['invokes', 'contains'].

    Returns:
        Tree-formatted traversal result.
    """
    if traversal_depth == -1:
        traversal_depth = 20

    subG, hints = _traverse_graph(
        start_entities, direction, traversal_depth,
        entity_type_filter, dependency_type_filter)

    if subG.number_of_nodes() == 0:
        return hints or "No results found."

    parts = []
    for root in start_entities:
        if root in subG:
            tree = _to_tree_str(subG, root, direction, traversal_depth,
                               entity_type_filter, dependency_type_filter)
            if tree.strip():
                parts.append(tree)

    result = "\n\n".join(parts)
    if hints:
        result += "\n\n" + hints
    return result.strip()


def explore_graph_structure(
    start_entities: List[str],
    direction: str = "downstream",
    traversal_depth: int = 1,
    entity_type_filter: Optional[List[str]] = None,
    dependency_type_filter: Optional[List[str]] = None,
) -> str:
    """Explore the dependency structure around entities as a DOT graph.

    Same args as explore_tree_structure. Returns DOT-format graph string.
    """
    if traversal_depth == -1:
        traversal_depth = 20

    subG, hints = _traverse_graph(
        start_entities, direction, traversal_depth,
        entity_type_filter, dependency_type_filter)

    if subG.number_of_nodes() == 0:
        return hints or "No results found."

    # Build DOT string manually
    lines = ["digraph {"]
    for node in subG.nodes():
        ntype = subG.nodes[node].get("type", "?")
        label = os.path.basename(node) if len(node) > 60 else node
        lines.append(f'  "{node}" [label="{label}" shape={"box" if ntype=="file" else "ellipse"}];')

    for u, v, data in subG.edges(data=True):
        etype = data.get("type", "")
        lines.append(f'  "{u}" -> "{v}" [label="{etype}"];')

    lines.append("}")

    result = "\n".join(lines)
    if hints:
        result += "\n\n" + hints
    return result


# ---------------------------------------------------------------------------
# Tool list
# ---------------------------------------------------------------------------

TOOL_DESCRIPTIONS = """
Available tools:

1. search_code_snippets(search_terms, line_nums, file_path_or_pattern)
   Search for code entities by name/keyword, or retrieve code at specific lines.
   - search_terms: list of entity names or keywords (e.g., ['MyClass.calculate', 'handle_error'])
   - line_nums: (optional) list of line numbers to retrieve
   - file_path_or_pattern: filter to specific files (default '**/*')

2. explore_tree_structure(start_entities, direction, traversal_depth, entity_type_filter, dependency_type_filter)
   Visualize dependency structure as an ASCII tree.
   - start_entities: list of entity IDs (e.g., ['src/main.py:process_request'])
   - direction: 'upstream' (who calls this), 'downstream' (what this calls), 'both'
   - traversal_depth: number of hops (default 2)
   - entity_type_filter: e.g., ['function', 'file']
   - dependency_type_filter: e.g., ['invokes', 'contains']

3. explore_graph_structure(start_entities, direction, traversal_depth, entity_type_filter, dependency_type_filter)
   Same as explore_tree_structure but returns DOT graph format.
"""
