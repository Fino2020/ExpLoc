"""
Dual-Path Tracer — simultaneous forward trace on two ICFG graphs.

Loads CodeQL + ScubaTrace ICFGs as separate FastICFG instances. At each
trace step, collects candidate edges from BOTH graphs, picks the globally
best edge, and syncs both graph cursors to the target function.

This avoids the merge step and exploits complementary edge coverage: if
one graph has an edge the other misses, the dual search still finds it.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Set

from shared.sink_db import get_sinks_for_vuln_types


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


class DualPathTracer:
    """Forward trace on TWO ICFG graphs simultaneously.

    At each step:
      1. Collect outgoing edges from current_a (in icfg_a) and current_b (in icfg_b)
      2. Resolve inter-procedural edges on-the-fly from both graphs
      3. Pick the edge with highest probability
      4. Follow it: for call/inter_call, jump both cursors to target function entry;
         for cfg, advance only the source graph's cursor.
      5. Adaptive termination when best_prob < tau * running_mean.
    """

    def __init__(
        self,
        icfg_a,          # FastICFG (e.g. CodeQL)
        icfg_b,          # FastICFG (e.g. ScubaTrace)
        tau: float = 0.3,
        max_depth: int = 15,
        inter_call_boost: float = 0.25,
        call_boost: float = 0.20,
        cfg_baseline: float = 0.01,
    ):
        self.icfg_a = icfg_a
        self.icfg_b = icfg_b
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
        """Forward trace from entry_func toward sinks, searching both ICFGs.

        Returns TraceResult with the best path found across both graphs.
        """
        # Find entry nodes in both graphs
        entry_a = self._find_entry(self.icfg_a, entry_func)
        entry_b = self._find_entry(self.icfg_b, entry_func)

        if entry_a is None and entry_b is None:
            return None

        # Determine entry file / line from whichever graph has the entry
        entry_data = None
        if entry_a:
            entry_data = self.icfg_a.get_node_data(entry_a)
        if entry_data is None and entry_b:
            entry_data = self.icfg_b.get_node_data(entry_b)
        entry_file = entry_data.get("file", "") if entry_data else ""
        entry_line = entry_data.get("line", 0) if entry_data else 0

        # Handle entry nodes with no outgoing edges: find actual start in same function
        if entry_a:
            neighbors_a = self.icfg_a.get_neighbors(entry_a)
            if not neighbors_a:
                actual = self._find_actual_start(self.icfg_a, entry_func, entry_file)
                if actual:
                    entry_a = actual
                    ed = self.icfg_a.get_node_data(entry_a)
                    if ed:
                        entry_line = ed.get("line", entry_line)
        if entry_b:
            neighbors_b = self.icfg_b.get_neighbors(entry_b)
            if not neighbors_b:
                actual = self._find_actual_start(self.icfg_b, entry_func, entry_file)
                if actual:
                    entry_b = actual

        sinks = get_sinks_for_vuln_types(vuln_types, language)

        result = TraceResult(
            entry_function=entry_func,
            entry_file=entry_file,
            entry_line=entry_line,
        )

        current_a = entry_a
        current_b = entry_b
        chain: List[dict] = []
        nodes: List[str] = [entry_a or entry_b or f"{entry_file}:{entry_func}:0"]
        visited_funcs: Set[str] = {entry_func.lower()}
        visited_nodes: Set[str] = set()
        if entry_a:
            visited_nodes.add(entry_a)
        if entry_b:
            visited_nodes.add(entry_b)

        hit_sink = False
        prob_sum = 0.0
        prob_count = 0

        while not hit_sink and len(nodes) < self.max_depth:
            # Check sink at current positions
            cur_func = self._current_function(current_a, current_b)
            if cur_func and self._is_sink_func(cur_func, sinks):
                hit_sink = True
                result.sink = cur_func
                break

            # Collect candidates from both graphs
            candidates: List[_EdgeCandidate] = []

            if current_a:
                self._collect_edges(
                    self.icfg_a, current_a, visited_nodes, candidates, "a")

            if current_b:
                self._collect_edges(
                    self.icfg_b, current_b, visited_nodes, candidates, "b")

            if not candidates:
                # Dead end: try jumping to function exit in both graphs
                jumped_a = self._jump_to_exit(self.icfg_a, current_a, visited_nodes) if current_a else None
                jumped_b = self._jump_to_exit(self.icfg_b, current_b, visited_nodes) if current_b else None
                if jumped_a:
                    current_a = jumped_a
                    visited_nodes.add(jumped_a)
                    continue
                if jumped_b:
                    current_b = jumped_b
                    visited_nodes.add(jumped_b)
                    continue
                break

            # Pick best edge by probability
            best = max(candidates, key=lambda c: c.prob)

            # Adaptive termination
            if prob_count > 0:
                running_mean = prob_sum / prob_count
                if best.prob < self.tau * running_mean:
                    result.terminated_by_decay = True
                    break

            prob_sum += best.prob
            prob_count += 1

            # Record path step
            src_func = self._current_function(current_a, current_b) or "?"
            dst_func = best.target_func or self._resolve_dst_function(best.dst_id)

            chain.append({
                "from": src_func,
                "to": dst_func,
                "edge_type": best.edge_type,
                "prob": round(best.prob, 4),
            })

            nodes.append(best.dst_id)
            visited_nodes.add(best.dst_id)

            # --- Advance cursors ---
            target_func = best.target_func

            if best.edge_type in ("call", "inter_call") and target_func:
                # Cross-function jump: sync BOTH graphs to target function entry
                tgt_lower = target_func.lower()
                if tgt_lower not in visited_funcs:
                    visited_funcs.add(tgt_lower)
                    current_a = self._find_entry(self.icfg_a, target_func)
                    current_b = self._find_entry(self.icfg_b, target_func)
                else:
                    # Already visited this function — dead end to prevent loops
                    break
            else:
                # cfg edge (intra-procedural): advance only the source graph
                if best.source_graph == "a":
                    current_a = best.dst_id
                    # Try to sync graph B to a nearby node in the same function
                    if current_b is None and dst_func:
                        current_b = self._find_entry(self.icfg_b, dst_func)
                else:
                    current_b = best.dst_id
                    if current_a is None and dst_func:
                        current_a = self._find_entry(self.icfg_a, dst_func)

        # Final sink check
        if not hit_sink:
            cur_func = self._current_function(current_a, current_b)
            if cur_func and self._is_sink_func(cur_func, sinks):
                hit_sink = True
                result.sink = cur_func

        result.terminated_at_sink = hit_sink
        result.path_chain = chain
        result.nodes = nodes

        result.cumulative_score = sum(
            (0.95 ** i) for i in range(len(chain))
        ) / max(len(chain), 1)

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _collect_edges(self, icfg, node_id: str, visited: set,
                       candidates: list, source_tag: str):
        """Collect outgoing edges from one graph into the candidates list."""
        # Direct neighbors
        for dst, edata in icfg.get_neighbors(node_id):
            if dst in visited:
                continue
            ep = 0.0
            et = edata.get("edge_type", "cfg")
            target = edata.get("target_function", "")

            if et == "inter_call":
                ep = self.inter_call_boost
            elif et == "call":
                ep = self.call_boost
            else:
                ep = self.cfg_baseline

            candidates.append(_EdgeCandidate(
                prob=ep, dst_id=dst, edge_type=et,
                source_graph=source_tag, target_func=target))

        # Resolved inter-procedural edges
        for dst, target_func in self._resolve_interproc_edges(icfg, node_id, visited):
            candidates.append(_EdgeCandidate(
                prob=self.inter_call_boost, dst_id=dst, edge_type="inter_call",
                source_graph=source_tag, target_func=target_func))

    def _current_function(self, node_a: Optional[str],
                          node_b: Optional[str]) -> Optional[str]:
        """Get the current function name from whichever graph has a cursor."""
        if node_a:
            d = self.icfg_a.get_node_data(node_a)
            if d:
                return d.get("function", "")
        if node_b:
            d = self.icfg_b.get_node_data(node_b)
            if d:
                return d.get("function", "")
        return None

    def _resolve_dst_function(self, node_id: str) -> str:
        """Get the function name for a destination node (try both graphs)."""
        for icfg in (self.icfg_a, self.icfg_b):
            d = icfg.get_node_data(node_id)
            if d:
                return d.get("function", "?")
        return "?"

    def _find_entry(self, icfg, func_name: str) -> Optional[str]:
        """Find function entry node in one ICFG (exact, then fuzzy)."""
        entry = icfg.get_entry_node(func_name)
        if entry is not None:
            return entry
        func_lower = func_name.lower()
        for fname, eid in icfg.function_entries.items():
            if func_lower in fname.lower() or fname.lower() in func_lower:
                return eid
        return None

    def _is_sink_func(self, func_name: str, sinks: Set[str]) -> bool:
        """Check if a function name matches any sink pattern."""
        func_lower = func_name.lower()
        for sink in sinks:
            if sink in func_lower:
                return True
        return False

    def _find_actual_start(self, icfg, func_name: str, file_name: str) -> Optional[str]:
        """Find first node in function that has outgoing cfg edges."""
        best_node = None
        best_line = float("inf")
        nodes_iter = getattr(icfg, "nodes", None)
        if nodes_iter is None or not isinstance(nodes_iter, dict):
            return None
        for nid, ndata in nodes_iter.items():
            if ndata.get("function") != func_name:
                continue
            if file_name and ndata.get("file") != file_name:
                continue
            line = ndata.get("line", 0)
            out_edges = icfg.get_neighbors(nid)
            has_cfg = any(e[1].get("edge_type") == "cfg" for e in out_edges)
            if has_cfg and line < best_line:
                best_line = line
                best_node = nid
        return best_node

    def _jump_to_exit(self, icfg, node_id: str, visited: set) -> Optional[str]:
        """Jump to exit node of the current function (dead-end escape)."""
        data = icfg.get_node_data(node_id)
        if data is None:
            return None
        cur_func = data.get("function", "")
        cur_file = data.get("file", "")
        exits = getattr(icfg, "function_exits", {}).get(cur_func, [])
        for exit_id in exits:
            if exit_id not in visited:
                edata = icfg.get_node_data(exit_id)
                if edata and edata.get("file") == cur_file:
                    return exit_id
        return None

    def _resolve_interproc_edges(self, icfg, node_id: str,
                                 visited: set) -> List[tuple]:
        """Resolve call/return edges to inter-procedural jumps on-the-fly.

        Returns [(dst_node_id, target_function), ...]
        """
        results = []
        for dst, edata in icfg.get_neighbors(node_id):
            et = edata.get("edge_type", "")
            target = edata.get("target_function", "").strip()
            if not target:
                continue

            if et == "call":
                callee_entry = self._find_entry(icfg, target)
                if callee_entry and callee_entry not in visited:
                    results.append((callee_entry, target))

            elif et == "return":
                exits = icfg.function_exits.get(target)
                if exits is None:
                    target_lower = target.lower()
                    for fname, exit_ids in icfg.function_exits.items():
                        if target_lower in fname.lower() or fname.lower() in target_lower:
                            exits = exit_ids
                            break
                if exits:
                    for exit_id in exits:
                        if exit_id not in visited:
                            results.append((exit_id, target))
        return results


class _EdgeCandidate:
    """Lightweight candidate edge from one graph."""
    __slots__ = ("prob", "dst_id", "edge_type", "source_graph", "target_func")

    def __init__(self, prob: float, dst_id: str, edge_type: str,
                 source_graph: str, target_func: str):
        self.prob = prob
        self.dst_id = dst_id
        self.edge_type = edge_type
        self.source_graph = source_graph
        self.target_func = target_func
