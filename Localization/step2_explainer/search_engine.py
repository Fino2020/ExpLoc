"""
Archetype-Guided ICFG Search Engine.

Unified priority-queue best-first search algorithm:
  - Start from entry functions (Step 1 localization results)
  - At each node: classify outgoing callees into archetype slots
  - Select top-k edges by slot_priority × cwe_weight × feasibility
  - Terminate when all required archetype slots are filled
  - Stagnation detection with backtracking support

The same mechanism (slot filling) drives both edge selection AND termination.
"""

import heapq
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .cwe_archetypes.archetype_library import Archetype, get_archetype
from .cwe_archetypes.cwe_mapper import CWEMapper, infer_archetype_from_issue
from .slot_classifier import SlotClassifier
from .edge_selector import EdgeSelector, ScoredEdge
from .termination import TerminationController, TerminationDecision, TerminationReason


# ---------------------------------------------------------------------------
# SearchPath — a candidate path through the ICFG
# ---------------------------------------------------------------------------

@dataclass
class SearchPath:
    """A candidate explanation path through the ICFG.

    Tracks: nodes visited, edges traversed, slots filled,
    slot history (for stagnation detection), and cumulative score.
    """
    nodes: List[str] = field(default_factory=list)
    edges: List[dict] = field(default_factory=list)
    filled_slots: Dict[str, str] = field(default_factory=dict)  # slot_name → node
    slot_history: List[bool] = field(default_factory=list)      # per-step new-slot-filled
    cumulative_score: float = 0.0
    depth: int = 0

    # Entry metadata
    entry_function: str = ""
    entry_file: str = ""
    entry_line: int = 0

    # Result metadata
    termination_reason: str = ""
    confidence: float = 0.0

    def __lt__(self, other: "SearchPath") -> bool:
        # Higher cumulative_score = higher priority (max-heap via negative)
        return self.cumulative_score > other.cumulative_score

    @property
    def current_node(self) -> str:
        return self.nodes[-1] if self.nodes else ""

    def clone(self) -> "SearchPath":
        return SearchPath(
            nodes=list(self.nodes),
            edges=list(self.edges),
            filled_slots=dict(self.filled_slots),
            slot_history=list(self.slot_history),
            cumulative_score=self.cumulative_score,
            depth=self.depth,
            entry_function=self.entry_function,
            entry_file=self.entry_file,
            entry_line=self.entry_line,
        )

    def add_step(
        self,
        node: str,
        edge: dict,
        new_slot: Optional[str] = None,
        edge_score: float = 0.0,
    ) -> "SearchPath":
        """Create a new path extended by one step."""
        cloned = self.clone()
        cloned.nodes.append(node)
        cloned.edges.append(edge)
        cloned.depth += 1

        if new_slot and new_slot not in cloned.filled_slots:
            cloned.filled_slots[new_slot] = node
            cloned.slot_history.append(True)
        else:
            cloned.slot_history.append(False)

        # Running average of edge scores
        n = cloned.depth
        cloned.cumulative_score = (self.cumulative_score * (n - 1) + edge_score) / max(n, 1)

        return cloned


# ---------------------------------------------------------------------------
# ArchetypeSearchEngine
# ---------------------------------------------------------------------------

class ArchetypeSearchEngine:
    """Priority-queue best-first ICFG search guided by CWE archetype.

    Usage:
        engine = ArchetypeSearchEngine(icfg, slot_classifier, edge_selector, termination)
        results = engine.search(entry_functions, issue_report, cve_id)
    """

    def __init__(
        self,
        icfg,                              # ICFGGraph
        slot_classifier: SlotClassifier,
        edge_selector: EdgeSelector,
        termination: TerminationController,
        cwe_mapper: Optional[CWEMapper] = None,
        llm = None,                        # ModelClient for LLM-based archetype inference
        max_frontier_size: int = 500,
        max_results: int = 5,
    ):
        self.icfg = icfg
        self.slot_classifier = slot_classifier
        self.edge_selector = edge_selector
        self.termination = termination
        self.cwe_mapper = cwe_mapper
        self.llm = llm
        self.max_frontier_size = max_frontier_size
        self.max_results = max_results
        self.max_call_sites_per_function: int = 100

        # Step1 function names for prioritizing call sites
        self._step1_func_set: set = set()

        # Cache: function_name → [(call_site_node, edge_data), ...]
        self._func_call_sites: Dict[str, List[tuple]] = {}
        # Tree-sitter call sites (merged into _func_call_sites on first access)
        self._ts_call_sites: Dict[str, List[tuple]] = {}

    # ------------------------------------------------------------------
    # Public API for call site population
    # ------------------------------------------------------------------

    def add_ts_call_sites(self, ts_sites: Dict[str, List[tuple]]):
        """Add tree-sitter call sites to the engine's call site cache.

        Merged with ICFG inter_call edges on first access via _get_function_call_sites().
        """
        self._ts_call_sites.update(ts_sites)

    def set_step1_functions(self, step1_funcs: list):
        """Set step1 function names for prioritizing entry_to_call edges."""
        self._step1_func_set = {f.lower() for f in step1_funcs if f}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def search(
        self,
        entry_functions: List[dict],
        issue_report: str,
        cve_id: str,
        language: str = "",
    ) -> List[SearchPath]:
        """Run archetype-guided search from each entry function.

        Args:
            entry_functions: list of {"function": str, "file": str, "score": float, ...}
                             from Step 1 localization results.
            issue_report: CVE issue description text.
            cve_id: CVE identifier (e.g., "CVE-2015-1862").
            language: programming language hint (optional).

        Returns:
            List of SearchPath results, one per entry function that produced a path.
            Sorted by confidence descending.
        """
        # Resolve archetype
        archetype = self._resolve_archetype(cve_id, issue_report)

        results: List[SearchPath] = []

        for entry_info in entry_functions[:self.max_results * 3]:  # search more than we need
            func_name = entry_info.get("function", "")
            if not func_name:
                continue

            result = self._search_single(
                entry_info, archetype, issue_report,
            )
            if result:
                results.append(result)

            if len(results) >= self.max_results:
                break

        # Sort by confidence descending
        results.sort(key=lambda p: -p.confidence)
        return results[:self.max_results]

    def search_single(
        self,
        entry_function: str,
        entry_file: str = "",
        issue_report: str = "",
        cve_id: str = "",
        archetype: Optional[Archetype] = None,
    ) -> Optional[SearchPath]:
        """Search from a single entry function.

        Convenience wrapper for single-entry search.
        """
        if archetype is None:
            archetype = self._resolve_archetype(cve_id, issue_report)

        entry_info = {
            "function": entry_function,
            "file": entry_file,
            "score": 1.0,
        }
        return self._search_single(entry_info, archetype, issue_report)

    # ------------------------------------------------------------------
    # Core search algorithm
    # ------------------------------------------------------------------

    def _search_single(
        self,
        entry_info: dict,
        archetype: Archetype,
        issue_report: str,
    ) -> Optional[SearchPath]:
        """Priority-queue best-first search from one entry function.

        Algorithm:
          1. Find entry node in ICFG
          2. Classify entry node into archetype slot
          3. Initialize frontier with entry path
          4. While frontier not empty:
             a. Pop highest-priority path
             b. Check termination → SUCCESS / STUCK / TRUNCATED
             c. Get outgoing edges from current node
             d. Classify callees, compute edge scores
             e. Push new paths to frontier
          5. Return best found path (or None)
        """
        func_name = entry_info.get("function", "")
        entry_file = entry_info.get("file", "")

        # Find entry node in ICFG
        entry_node = self._find_entry_node(func_name)
        if entry_node is None:
            return None

        # Get entry metadata
        entry_data = self.icfg.get_node_data(entry_node) if hasattr(self.icfg, "get_node_data") else {}
        entry_file = entry_info.get("file", "") or entry_data.get("file", "") if entry_data else ""
        entry_line = entry_data.get("line", 0) if entry_data else 0

        # Get entry function code for classification
        entry_code = entry_data.get("code", "") if entry_data else ""

        # Classify entry node
        entry_slot, entry_just, entry_conf = self.slot_classifier.classify(
            entry_code, func_name, issue_report, archetype,
        )

        # Initialize search path
        init_path = SearchPath(
            nodes=[entry_node],
            filled_slots={entry_slot: entry_node} if entry_slot else {},
            slot_history=[True] if entry_slot else [False],
            cumulative_score=1.0,
            depth=1,
            entry_function=func_name,
            entry_file=entry_file,
            entry_line=entry_line,
        )

        # Frontier: priority queue (max-heap via negative score)
        frontier: List[Tuple[float, int, SearchPath]] = []
        counter = 0  # tiebreaker for heap ordering
        heapq.heappush(frontier, (-init_path.cumulative_score, counter, init_path))
        counter += 1

        # Visited tracking: (current_node, frozen_slot_set) → best_score
        visited: Dict[Tuple[str, frozenset], float] = {}

        best_partial: Optional[SearchPath] = None
        best_partial_required = 0

        while frontier:
            neg_score, _, path = heapq.heappop(frontier)

            # Check termination
            has_outgoing = self._has_outgoing_edges(path.current_node)
            decision = self.termination.check(
                path.nodes,
                {k for k in path.filled_slots
                 if archetype.get_slot_by_name(k) and archetype.get_slot_by_name(k).required},
                {k for k in path.filled_slots
                 if archetype.get_slot_by_name(k) and not archetype.get_slot_by_name(k).required},
                archetype,
                path.slot_history,
                has_outgoing,
            )

            if decision.reason == TerminationReason.SUCCESS:
                path.termination_reason = "archetype_complete"
                path.confidence = self._compute_confidence(path, archetype, decision)
                return path

            if decision.reason == TerminationReason.TRUNCATED:
                path.termination_reason = "truncated"
                path.confidence = self._compute_confidence(path, archetype, decision)
                # Track best partial result
                req_filled = len({k for k in path.filled_slots
                                  if archetype.get_slot_by_name(k) and archetype.get_slot_by_name(k).required})
                if best_partial is None or req_filled > best_partial_required:
                    best_partial = path
                    best_partial_required = req_filled
                continue

            if self.termination.should_prune(decision):
                continue

            # Get outgoing edges
            outgoing = self._get_outgoing_edges(path.current_node)

            if not outgoing:
                # Dead end — try jumping to function exit
                jumped = self._jump_to_exit(path.current_node, set(path.nodes))
                if jumped:
                    outgoing = self._get_outgoing_edges(jumped)
                    if not outgoing:
                        continue
                else:
                    continue

            # Select top-k edges by archetype-guided scoring
            scored_edges = self.edge_selector.select_edges(
                path.current_node, outgoing, path.filled_slots,
                archetype, issue_report, self.icfg,
            )

            # Expand frontier
            for se in scored_edges:
                if se.score < self.edge_selector.prune_threshold:
                    continue

                # Avoid cycles: skip already-visited nodes (unless it's a REQUIRED slot filler)
                if se.to_node in path.nodes and se.target_slot not in archetype.required_slot_names:
                    continue

                # Build edge dict for path recording
                edge_dict = {
                    "from": path.current_node,
                    "to": se.to_node,
                    "from_func": path.entry_function if path.depth == 1 else "",
                    "to_func": se.target_function,
                    "edge_type": se.edge_type,
                    "score": round(se.score, 4),
                    "slot": se.target_slot,
                    "slot_justification": se.slot_justification,
                }

                new_path = path.add_step(
                    node=se.to_node,
                    edge=edge_dict,
                    new_slot=se.target_slot if se.target_slot else None,
                    edge_score=se.score,
                )

                # Deduplication: same node + same filled slots → keep best
                frozen = frozenset(new_path.filled_slots.keys())
                vkey = (se.to_node, frozen)
                if vkey in visited and visited[vkey] >= new_path.cumulative_score:
                    continue
                visited[vkey] = new_path.cumulative_score

                # Enforce frontier size limit
                if len(frontier) >= self.max_frontier_size:
                    continue

                heapq.heappush(frontier, (-new_path.cumulative_score, counter, new_path))
                counter += 1

        # Return best partial result if no complete path found
        if best_partial:
            return best_partial
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_archetype(self, cve_id: str, issue_report: str) -> Archetype:
        """Resolve CWE archetype: LLM inference from issue text first, then keyword fallback."""
        # Primary: LLM-based inference from issue report
        if self.llm:
            archetype, _desc, confidence = infer_archetype_from_issue(self.llm, issue_report)
            if archetype and archetype.family != "Generic" and confidence >= 0.5:
                return archetype

        # Fallback: classify CWE from issue report text (fast keyword heuristic)
        if self.cwe_mapper:
            candidates = self.cwe_mapper.classify_cwe_from_issue(issue_report)
            if candidates and candidates[0][1] > 0.7:  # high confidence keyword match
                return get_archetype(candidates[0][0])

        # Ultimate fallback: generic archetype
        return get_archetype("")

    def _find_entry_node(self, func_name: str) -> Optional[str]:
        """Find ICFG entry node for a function name.

        Progressive matching strategies (tried in order):
          1. Exact lookup via get_entry_node
          2. Substring: func_name in ICFG name or vice versa
          3. Token overlap: split on '_' and case boundaries, require ≥2 common tokens
          4. Prefix-stripped match: remove common prefixes and compare
        """
        if not func_name:
            return None

        # 1. Direct lookup
        if hasattr(self.icfg, "get_entry_node"):
            node = self.icfg.get_entry_node(func_name)
            if node:
                return node

        if not hasattr(self.icfg, "function_entries"):
            return None

        fe = self.icfg.function_entries
        fl = func_name.lower()

        # 2. Substring match
        for fname, entry_id in fe.items():
            icfg_lower = fname.lower()
            if fl in icfg_lower or icfg_lower in fl:
                return entry_id

        # 3. Token overlap (split on '_' and case changes)
        step1_tokens = {t for t in re.split(r'[_]+', fl) if len(t) > 2}
        # Also split on camelCase boundaries
        camel_tokens = set()
        for t in step1_tokens.copy():
            parts = re.split(r'(?<=[a-z])(?=[A-Z])', t)
            if len(parts) > 1:
                camel_tokens.update(p.lower() for p in parts if len(p) > 2)
        step1_tokens.update(camel_tokens)

        if step1_tokens:
            best_count = 0
            best_id = None
            for fname, entry_id in fe.items():
                icfg_tokens = {t for t in re.split(r'[_]+', fname.lower()) if len(t) > 2}
                overlap = len(step1_tokens & icfg_tokens)
                if overlap > best_count:
                    best_count = overlap
                    best_id = entry_id
            # Require at least 2 common tokens or majority of smaller set
            if best_count >= max(2, min(len(step1_tokens), 3)):
                return best_id

        # 4. Prefix-stripped match (common project prefixes)
        prefixes = ["ssl_", "_ssl", "opj_", "PHP_", "ZEND_", "zim_", "t1_", "tls_",
                     "ngx_", "http_", "h2_", "spdy_", "sv_", "evp_", "bio_", "x509_"]
        for fname, entry_id in fe.items():
            icfg_lower = fname.lower()
            fl_stripped = fl
            for p in prefixes:
                if fl.startswith(p):
                    fl_stripped = fl[len(p):]
                    break
            icfg_stripped = icfg_lower
            for p in prefixes:
                if icfg_lower.startswith(p):
                    icfg_stripped = icfg_lower[len(p):]
                    break
            if fl_stripped == icfg_stripped:
                return entry_id

        return None

    def _has_outgoing_edges(self, node_id: str) -> bool:
        """Check if a node has outgoing edges."""
        if hasattr(self.icfg, "get_neighbors"):
            neighbors = self.icfg.get_neighbors(node_id)
            return len(neighbors) > 0
        return False

    def _get_outgoing_edges(self, node_id: str) -> List[tuple]:
        """Get outgoing edges: (dst_node, edge_data) tuples.

        entry_to_call edges only from entry nodes, limited to max_call_sites_per_function.
        Step1-prioritized: matching step1 functions come first.
        """
        if not hasattr(self.icfg, "get_neighbors"):
            return []
        outgoing = list(self.icfg.get_neighbors(node_id))

        node_data = self.icfg.get_node_data(node_id) if hasattr(self.icfg, "get_node_data") else {}
        is_entry = (node_data or {}).get("node_type", "") == "entry" if node_data else False

        if is_entry:
            func_name = node_data.get("function", "") if node_data else ""
            if func_name:
                call_sites = self._get_function_call_sites(func_name)
                seen_targets = set()
                for _dst2, e_data2 in outgoing:
                    if isinstance(e_data2, dict):
                        t = e_data2.get("target_function", "")
                        if t:
                            seen_targets.add(t)

                # Sort: step1 functions first, then rest
                step1_sites = []
                other_sites = []
                for cs_node, cs_data in call_sites:
                    if cs_data.get("target_function", "") not in seen_targets:
                        target = cs_data.get("target_function", "").lower()
                        if target in self._step1_func_set:
                            step1_sites.append((cs_node, cs_data))
                        else:
                            other_sites.append((cs_node, cs_data))

                # Add step1-prioritized call sites, up to limit
                limit = self.max_call_sites_per_function
                added = 0
                for cs_node, cs_data in step1_sites + other_sites:
                    target = cs_data.get("target_function", "")
                    if target not in seen_targets:
                        outgoing.append((cs_node, cs_data))
                        seen_targets.add(target)
                        added += 1
                        if added >= limit:
                            break
        return outgoing

    def _jump_to_exit(self, node_id: str, visited: set) -> Optional[str]:
        """Jump to function exit node (dead-end escape)."""
        if not hasattr(self.icfg, "get_node_data"):
            return None

        data = self.icfg.get_node_data(node_id)
        if not data:
            return None
        cur_func = data.get("function", "")

        # Try function_exits map
        if hasattr(self.icfg, "function_exits"):
            exits = self.icfg.function_exits.get(cur_func, [])
            if exits:
                for exit_id in exits:
                    if exit_id not in visited:
                        return exit_id

        return None

    def _get_function_call_sites(self, func_name: str) -> List[tuple]:
        """Get all call sites within a function (lazily cached, merged sources).

        Sources (lower index = higher priority):
          1. ICFG inter_call edges (pre-built index, built once)
          2. Tree-sitter call sites (ts_call_builder)

        Returns list of (call_site_node, edge_data) tuples.
        """
        if func_name in self._func_call_sites:
            return self._func_call_sites[func_name]

        sites = []
        seen_callees = set()

        # Source 1: ICFG inter_call edges (use pre-built index if available)
        if not hasattr(self, "_icfg_call_index"):
            self._icfg_call_index = self._build_icfg_call_index()

        for callee, node_id, edge_data in self._icfg_call_index.get(func_name, []):
            if callee not in seen_callees:
                sites.append((node_id, edge_data))
                seen_callees.add(callee)

        # Source 2: Tree-sitter call sites (additional coverage)
        if func_name in self._ts_call_sites:
            for node_id, edata in self._ts_call_sites[func_name]:
                callee = edata.get("target_function", "")
                if callee not in seen_callees:
                    sites.append((node_id, edata))
                    seen_callees.add(callee)

        self._func_call_sites[func_name] = sites
        return sites

    def _build_icfg_call_index(self) -> Dict[str, List[Tuple[str, str, dict]]]:
        """Build func_name → [(callee, node_id, edge_data), ...] index once.

        Iterates ICFG inter_call edges once, groups by source function.
        """
        idx: Dict[str, List[Tuple[str, str, dict]]] = {}
        if not hasattr(self.icfg, "graph"):
            return idx

        for u, v, data in self.icfg.graph.edges(data=True):
            if data.get("edge_type") == "inter_call":
                node_data = self.icfg.graph.nodes.get(u, {})
                func_name = node_data.get("function", "")
                if not func_name:
                    continue
                callee = data.get("target_function", "")
                if not callee:
                    continue
                edge_copy = dict(data)
                edge_copy["edge_type"] = "entry_to_call"
                if func_name not in idx:
                    idx[func_name] = []
                idx[func_name].append((callee, u, edge_copy))

        return idx

    def _compute_confidence(
        self,
        path: SearchPath,
        archetype: Archetype,
        decision: TerminationDecision,
    ) -> float:
        """Compute confidence score for the search result."""
        # Slot completion ratio
        req_total = max(len(archetype.required_slot_names), 1)
        req_filled = len({k for k in path.filled_slots
                          if archetype.get_slot_by_name(k) and archetype.get_slot_by_name(k).required})
        slot_score = req_filled / req_total

        # Path score
        path_score = min(path.cumulative_score, 1.0)

        # Termination quality
        term_modifiers = {
            TerminationReason.SUCCESS: 1.0,
            TerminationReason.TRUNCATED: 0.6,
            TerminationReason.DEAD_END: 0.4,
        }
        term_mod = term_modifiers.get(decision.reason, 0.5)
        term_mod *= decision.confidence_modifier

        return round(0.4 * slot_score + 0.3 * path_score + 0.3 * term_mod, 3)

    # ------------------------------------------------------------------
    # Batch search (multiple entry points)
    # ------------------------------------------------------------------

    def search_all_entries(
        self,
        entry_functions: List[dict],
        issue_report: str,
        cve_id: str,
        language: str = "",
    ) -> List[SearchPath]:
        """Alias for search() — batch search from multiple entry functions."""
        return self.search(entry_functions, issue_report, cve_id, language)
