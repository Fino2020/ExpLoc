"""
Path Tracer — ICFG forward trace from entry function to sink.

Algorithm:
  Start: function entry node
  While not terminated:
    1. Check if current node is sink → terminate with sink_match=true
    2. Get outgoing edges from ICFG
    3. If dead-end, jump to function exit node, retry
    4. Select edge with highest edge_prob:
       - inter_call edges: prob = max(prob, 0.25)
       - call edges: prob = max(prob, 0.20)
    5. Adaptive termination: if running_mean established AND
       best_prob < tau * running_mean → break (signal decay)
    6. Move to next node, update running_mean
  Max depth: 15 nodes

Parameters: tau=0.3, alpha=0.85 (for PPR mode), max_depth=15.

Adapted from Explainable_Localization/graph_explainer.py._trace_forward.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from shared.icfg_loader import ICFGGraph
from shared.sink_db import detect_vuln_types, get_sinks_for_vuln_types


@dataclass
class PathStep:
    """A single step in a traced path."""
    from_node: str
    to_node: str
    edge_type: str
    prob: float
    from_func: str = ""
    to_func: str = ""
    from_file: str = ""
    to_file: str = ""
    from_line: int = 0
    to_line: int = 0


@dataclass
class TraceResult:
    """Result of a forward trace from a single entry function."""
    entry_function: str
    entry_file: str
    entry_line: int
    sink: str = ""
    terminated_at_sink: bool = False
    terminated_by_decay: bool = False
    path_chain: List[dict] = field(default_factory=list)
    nodes: List[str] = field(default_factory=list)
    cumulative_score: float = 0.0


class PathTracer:
    """Forward trace along highest-probability ICFG edges."""

    def __init__(
        self,
        icfg: ICFGGraph,
        edge_probs: Optional[Dict[Tuple[str, str], float]] = None,
        tau: float = 0.3,
        max_depth: int = 15,
        inter_call_boost: float = 0.25,
        call_boost: float = 0.20,
        cfg_baseline: float = 0.01,
    ):
        self.icfg = icfg
        self.edge_probs = edge_probs or {}
        self.tau = tau
        self.max_depth = max_depth
        self.inter_call_boost = inter_call_boost
        self.call_boost = call_boost
        self.cfg_baseline = cfg_baseline

    def trace(
        self,
        entry_func: str,
        vuln_types: List[str],
        language: str,
    ) -> Optional[TraceResult]:
        """Forward trace from an entry function toward a sink.

        Args:
            entry_func: function name to start tracing from
            vuln_types: detected vulnerability types (for sink lookup)
            language: programming language (for sink lookup)

        Returns:
            TraceResult if entry node found, None otherwise.
        """
        # Find entry node
        entry_node = self.icfg.get_entry_node(entry_func)
        if entry_node is None:
            entry_node = self._fuzzy_find_entry(entry_func)
        if entry_node is None:
            return None

        entry_data = self.icfg.get_node_data(entry_node)
        entry_file = entry_data.get("file", "") if entry_data else ""
        entry_line = entry_data.get("line", 0) if entry_data else 0

        # Get sinks
        sinks = get_sinks_for_vuln_types(vuln_types, language)

        result = TraceResult(
            entry_function=entry_func,
            entry_file=entry_file,
            entry_line=entry_line,
        )

        # If entry node has no outgoing edges, find actual start node in same function
        neighbors = self.icfg.get_neighbors(entry_node)
        if not neighbors:
            actual_start = self._find_actual_start(entry_func, entry_file)
            if actual_start:
                entry_node = actual_start
                entry_data = self.icfg.get_node_data(entry_node)
                entry_line = entry_data.get("line", 0) if entry_data else 0
                result.entry_line = entry_line

        nodes = [entry_node]
        chain: List[dict] = []
        current = entry_node
        visited = {entry_node}
        hit_sink = self._is_sink_node(entry_node, sinks)
        prob_sum = 0.0
        prob_count = 0

        while not hit_sink and len(nodes) < self.max_depth:
            if self._is_sink_node(current, sinks):
                hit_sink = True
                break

            # Get outgoing neighbors + inter-procedural edges (resolved on-the-fly)
            neighbors = self.icfg.get_neighbors(current)
            inter_call_neighbors = self._resolve_interproc_edges(current, visited)

            if not neighbors and not inter_call_neighbors:
                # Dead end: try jumping to function exit
                jumped = self._jump_to_exit(current, visited)
                if jumped:
                    visited.add(jumped)
                    current = jumped
                    neighbors = self.icfg.get_neighbors(current)
                    inter_call_neighbors = self._resolve_interproc_edges(current, visited)
                if not neighbors and not inter_call_neighbors:
                    break

            # Find best outgoing edge
            best_prob = 0.0
            best_dst = None
            best_etype = ""

            for dst, edata in neighbors:
                if dst in visited:
                    continue
                ep = self.edge_probs.get((current, dst), 0.0)
                et = edata.get("edge_type", "cfg")

                if et == "inter_call":
                    ep = max(ep, self.inter_call_boost)
                elif et in ("call", "ts_call"):
                    ep = max(ep, self.call_boost)
                else:
                    ep = max(ep, self.cfg_baseline)

                if ep > best_prob:
                    best_prob = ep
                    best_dst = dst
                    best_etype = et

            # Also consider resolved inter-procedural edges
            for dst, target_func in inter_call_neighbors:
                ep = self.inter_call_boost
                if ep > best_prob:
                    best_prob = ep
                    best_dst = dst
                    best_etype = "inter_call"

            if best_dst is None:
                break

            # Adaptive termination: signal decay
            if prob_count > 0:
                running_mean = prob_sum / prob_count
                if best_prob < self.tau * running_mean:
                    result.terminated_by_decay = True
                    break

            prob_sum += best_prob
            prob_count += 1

            # Record path step
            src_data = self.icfg.get_node_data(current)
            dst_data = self.icfg.get_node_data(best_dst)

            chain.append({
                "from": src_data.get("function", "?") if src_data else "?",
                "to": dst_data.get("function", "?") if dst_data else "?",
                "edge_type": best_etype,
                "prob": round(best_prob, 4),
            })

            nodes.append(best_dst)
            visited.add(best_dst)
            current = best_dst

        # Check final node for sink
        if not hit_sink:
            hit_sink = self._is_sink_node(current, sinks)

        result.terminated_at_sink = hit_sink
        result.path_chain = chain
        result.nodes = nodes

        # Identify the sink function if we hit one
        if hit_sink:
            result.sink = self._find_sink_name(current, sinks)

        # Compute cumulative score (decayed sum)
        result.cumulative_score = sum(
            (0.95 ** i) for i in range(len(chain))
        ) / max(len(chain), 1)

        return result

    def trace_top_functions(
        self,
        functions: List[dict],
        issue_description: str,
        language: str,
        top_k: int = 5,
    ) -> List[TraceResult]:
        """Trace from multiple top-ranked functions.

        Args:
            functions: list of {"function": str, "file": str, "score": float, ...}
            issue_description: CVE issue description (for vuln type detection)
            language: programming language
            top_k: max number of functions to trace

        Returns:
            List of TraceResult, one per successfully traced function.
        """
        vuln_types = detect_vuln_types(issue_description)
        results = []

        for i, func_info in enumerate(functions[:top_k]):
            func_name = func_info.get("function", "")
            if not func_name:
                continue

            result = self.trace(func_name, vuln_types, language)
            if result:
                result.entry_function = func_name
                result.entry_file = func_info.get("file", result.entry_file)
                results.append(result)

        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_sink_node(self, node_id: str, sinks: Set[str]) -> bool:
        """Check if a node matches any sink pattern."""
        data = self.icfg.get_node_data(node_id)
        if data is None:
            return False
        func = data.get("function", "").lower()
        if not func:
            return False
        for sink in sinks:
            if sink in func:
                return True
        # Check outgoing call targets
        for dst, edata in self.icfg.get_neighbors(node_id):
            target = edata.get("target_function", "").lower()
            if target:
                for sink in sinks:
                    if sink in target:
                        return True
        return False

    def _find_sink_name(self, node_id: str, sinks: Set[str]) -> str:
        """Find which sink function was hit."""
        data = self.icfg.get_node_data(node_id)
        if data:
            func = data.get("function", "")
            for sink in sinks:
                if sink in func.lower():
                    return func
        for dst, edata in self.icfg.get_neighbors(node_id):
            target = edata.get("target_function", "")
            for sink in sinks:
                if sink in target.lower():
                    return target
        return ""

    def _fuzzy_find_entry(self, func_name: str) -> Optional[str]:
        """Fuzzy match a function name to an ICFG entry node."""
        func_lower = func_name.lower()
        for fname, entry_id in self.icfg.function_entries.items():
            if func_lower in fname.lower() or fname.lower() in func_lower:
                return entry_id
        return None

    def _find_actual_start(self, func_name: str, file_name: str) -> Optional[str]:
        """Find a node in the function that has outgoing cfg edges (actual start)."""
        best_node = None
        best_line = float("inf")

        # Support FastICFG (has .nodes dict) or NetworkX graph
        nodes_iter = getattr(self.icfg, "nodes", None)
        if nodes_iter and isinstance(nodes_iter, dict):
            for nid, ndata in nodes_iter.items():
                if ndata.get("function") != func_name:
                    continue
                if file_name and ndata.get("file") != file_name:
                    continue
                line = ndata.get("line", 0)
                out_edges = self.icfg.get_neighbors(nid)
                has_cfg = any(e[1].get("edge_type") == "cfg" for e in out_edges)
                if has_cfg and line < best_line:
                    best_line = line
                    best_node = nid
        else:
            graph = getattr(self.icfg, "graph", None)
            if graph is not None:
                for nid, ndata in graph.nodes(data=True):
                    if ndata.get("function") != func_name:
                        continue
                    if file_name and ndata.get("file") != file_name:
                        continue
                    line = ndata.get("line", 0)
                    out_edges = list(graph.out_edges(nid, data=True))
                    has_cfg = any(e[2].get("edge_type") == "cfg" for e in out_edges)
                    if has_cfg and line < best_line:
                        best_line = line
                        best_node = nid
        return best_node

    def _jump_to_exit(self, node_id: str, visited: set) -> Optional[str]:
        """Jump to the exit node of the current function (dead-end escape)."""
        data = self.icfg.get_node_data(node_id)
        if data is None:
            return None
        cur_func = data.get("function", "")
        cur_file = data.get("file", "")

        # Support both NetworkX graph and FastICFG
        exits = getattr(self.icfg, "function_exits", {}).get(cur_func, [])
        if exits:
            for exit_id in exits:
                if exit_id not in visited:
                    edata = self.icfg.get_node_data(exit_id)
                    if edata and edata.get("file") == cur_file:
                        return exit_id

        # Fallback: iterate all nodes (NetworkX path)
        graph = getattr(self.icfg, "graph", None)
        if graph is not None:
            for nid, ndata in graph.nodes(data=True):
                if (ndata.get("function") == cur_func and
                    ndata.get("file") == cur_file and
                    ndata.get("node_type") == "exit" and
                    nid not in visited):
                    return nid
        return None

    def _resolve_interproc_edges(self, node_id: str, visited: set) -> List[tuple]:
        """Resolve call/return edges to inter-procedural jumps on-the-fly.

        Without pre-built inter_call/inter_return edges, this looks at
        call/return edges from the current node and resolves them to
        the callee's entry (for calls) or the continuation point (for returns).

        Returns [(dst_node_id, target_function), ...]
        """
        results = []
        for dst, edata in self.icfg.get_neighbors(node_id):
            et = edata.get("edge_type", "")
            target = edata.get("target_function", "").strip()
            if not target:
                continue

            if et == "call":
                # Call edge: jump to callee's entry
                callee_entry = self.icfg.get_entry_node(target)
                if callee_entry is None:
                    # Fuzzy match
                    target_lower = target.lower()
                    for fname, entry_id in self.icfg.function_entries.items():
                        if target_lower in fname.lower() or fname.lower() in target_lower:
                            callee_entry = entry_id
                            break
                if callee_entry and callee_entry not in visited:
                    results.append((callee_entry, target))

            elif et == "return":
                # Return edge: from callee exit back to caller's continuation
                exits = self.icfg.function_exits.get(target)
                if exits is None:
                    target_lower = target.lower()
                    for fname, exit_ids in self.icfg.function_exits.items():
                        if target_lower in fname.lower() or fname.lower() in target_lower:
                            exits = exit_ids
                            break
                if exits:
                    for exit_id in exits:
                        if exit_id not in visited:
                            results.append((exit_id, target))

        return results
