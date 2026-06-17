"""
Edge Selector — scores and selects outgoing ICFG edges during search.

Scoring formula:
  score(e) = slot_priority × cwe_type_weight × feasibility

Where:
  - slot_priority: based on whether callee fills a missing slot (3.0/2.0/1.0/0.3)
  - cwe_type_weight: per-edge-type multiplier from archetype profile
  - feasibility: LLM check — can this function execute under the trigger?

Selects top-k edges above threshold. Prunes infeasible edges.
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .cwe_archetypes.archetype_library import Archetype
from .slot_classifier import SlotClassifier


@dataclass
class ScoredEdge:
    """An ICFG edge with its computed score and slot classification."""
    from_node: str
    to_node: str
    edge_type: str
    edge_data: dict = field(default_factory=dict)

    # Scoring components
    slot_priority: float = 0.0
    cwe_weight: float = 1.0
    feasibility: float = 1.0
    score: float = 0.0

    # Slot classification result
    target_slot: str = ""               # slot name or "" for NONE
    target_slot_required: bool = False
    slot_justification: str = ""

    # Target function info
    target_function: str = ""
    target_file: str = ""
    target_line: int = 0


# ---------------------------------------------------------------------------
# EdgeSelector
# ---------------------------------------------------------------------------

class EdgeSelector:
    """Score and select outgoing ICFG edges using archetype-guided criteria.

    Usage:
        selector = EdgeSelector(slot_classifier)
        scored = selector.select_edges(current_node, outgoing_edges, ...)
    """

    # Default slot priority values
    PRIORITY_MISSING_REQUIRED = 3.0
    PRIORITY_MISSING_OPTIONAL = 2.0
    PRIORITY_ALREADY_FILLED = 1.0    # secondary evidence
    PRIORITY_NONE = 0.5              # explore unknown callees (higher so call edges aren't starved)

    def __init__(
        self,
        slot_classifier: SlotClassifier,
        top_k: int = 5,
        prune_threshold: float = 0.3,
        enable_feasibility_check: bool = True,
        feasibility_sample_rate: float = 0.3,  # only check feasibility on subset
    ):
        self.classifier = slot_classifier
        self.top_k = top_k
        self.prune_threshold = prune_threshold
        self.enable_feasibility_check = enable_feasibility_check
        self.feasibility_sample_rate = feasibility_sample_rate

        # Cache: (function_name, slot) → score  (avoids re-classifying same function)
        self._slot_cache: Dict[str, Tuple[str, str, float]] = {}

        # Slot name normalizer: for slot de-duplication
        self._slot_name_cache: Dict[str, str] = {}

        # Step1 function set for boosting (set by caller)
        self._step1_func_set: set = set()

    def set_step1_functions(self, step1_funcs: list):
        """Set step1 function names for score boosting."""
        self._step1_func_set = {f.lower() for f in step1_funcs if f}

    def select_edges(
        self,
        current_node: str,
        outgoing_edges: List[tuple],     # [(dst_node, edge_data), ...]
        filled_slots: Dict[str, str],    # slot_name → node_that_filled_it
        archetype: Archetype,
        issue_report: str,
        icfg=None,                       # ICFG for node data lookups
    ) -> List[ScoredEdge]:
        """Score all outgoing edges, return top-k above threshold.

        Args:
            current_node: current ICFG node ID
            outgoing_edges: list of (dst_node_id, edge_data_dict) tuples
            filled_slots: dict mapping slot_name → node that filled it
            archetype: CWE archetype with slot definitions
            issue_report: CVE issue description text
            icfg: optional ICFGGraph for node metadata lookups

        Returns:
            List of ScoredEdge, sorted by score descending, limited to top_k.
        """
        if not outgoing_edges:
            return []

        # 1. Batch-classify all target functions
        target_funcs = []
        edge_map: Dict[str, List[int]] = {}  # func_key → [edge_index, ...]

        for i, (dst, edata) in enumerate(outgoing_edges):
            target_func = edata.get("target_function", "") or edata.get("function", "")
            if not target_func:
                dst_data = icfg.get_node_data(dst) if icfg else {}
                target_func = dst_data.get("function", "") if dst_data else ""

            func_key = self._normalize_func_name(target_func)
            if func_key not in edge_map:
                edge_map[func_key] = []
                target_funcs.append({
                    "name": target_func,
                    "key": func_key,
                })
            edge_map[func_key].append(i)

        # Batch classify (use func names only — code snippets added when available)
        batch_results = self._batch_classify_targets(
            target_funcs, outgoing_edges, issue_report, archetype, icfg,
        )

        # Build results index: func_key → slot
        slot_results: Dict[str, Tuple[str, str, float]] = {}
        for i, func_info in enumerate(target_funcs):
            if i < len(batch_results):
                slot_results[func_info["key"]] = batch_results[i]

        # 2. Score each edge
        scored: List[ScoredEdge] = []
        missing_required = archetype.required_slot_names - set(filled_slots.keys())
        missing_optional = {s.name for s in archetype.slots if not s.required} - set(filled_slots.keys())

        for i, (dst, edata) in enumerate(outgoing_edges):
            target_func = edata.get("target_function", "") or edata.get("function", "")
            if not target_func:
                dst_data = icfg.get_node_data(dst) if icfg else {}
                target_func = dst_data.get("function", "") if dst_data else ""
            func_key = self._normalize_func_name(target_func)

            slot_name, justification, slot_conf = slot_results.get(
                func_key, ("", "", 0.0),
            )

            # Compute slot priority
            slot_priority = self._compute_slot_priority(
                slot_name, filled_slots, missing_required, missing_optional,
            )

            # Get CWE-type edge weight
            edge_type = edata.get("edge_type", "cfg")
            cwe_weight = self._get_cwe_weight(edge_type, target_func, archetype)

            # Feasibility (sampled)
            feasibility = 1.0
            if self.enable_feasibility_check and slot_priority > self.PRIORITY_NONE:
                # Only check feasibility for high-priority edges
                if self._should_check_feasibility(slot_name, slot_priority):
                    feasibility = self._estimate_feasibility(
                        dst, edata, issue_report, icfg,
                    )

            # Step1 boost: multiply score for functions in step1 results
            step1_boost = 5.0 if target_func.lower() in self._step1_func_set else 1.0

            # Final score
            score = slot_priority * cwe_weight * feasibility * step1_boost

            # Build result
            is_required = False
            if slot_name:
                slot_def = archetype.get_slot_by_name(slot_name)
                is_required = slot_def.required if slot_def else False

            se = ScoredEdge(
                from_node=current_node,
                to_node=dst,
                edge_type=edge_type,
                edge_data=edata,
                slot_priority=slot_priority,
                cwe_weight=cwe_weight,
                feasibility=feasibility,
                score=score,
                target_slot=slot_name,
                target_slot_required=is_required,
                slot_justification=justification,
                target_function=target_func,
                target_file=edata.get("file", ""),
                target_line=edata.get("line", 0),
            )
            scored.append(se)

        # 3. Sort by score, filter, limit
        scored.sort(key=lambda e: -e.score)
        filtered = [e for e in scored if e.score >= self.prune_threshold]
        return filtered[:self.top_k]

    # ------------------------------------------------------------------
    # Internal: slot priority
    # ------------------------------------------------------------------

    def _compute_slot_priority(
        self,
        slot_name: str,
        filled_slots: Dict[str, str],
        missing_required: Set[str],
        missing_optional: Set[str],
    ) -> float:
        """Compute slot priority for edge scoring."""
        if not slot_name:
            return self.PRIORITY_NONE
        if slot_name in missing_required:
            return self.PRIORITY_MISSING_REQUIRED
        if slot_name in missing_optional:
            return self.PRIORITY_MISSING_OPTIONAL
        if slot_name in filled_slots:
            return self.PRIORITY_ALREADY_FILLED
        return self.PRIORITY_NONE

    # ------------------------------------------------------------------
    # Internal: CWE-type edge weight
    # ------------------------------------------------------------------

    def _get_cwe_weight(
        self,
        edge_type: str,
        target_function: str,
        archetype: Archetype,
    ) -> float:
        """Get CWE-type-specific edge weight from archetype profile.

        Also checks for special function-category weights
        (e.g., call_to_mem matches malloc/free/memcpy).
        """
        profile = archetype.edge_weight_profile

        base = profile.get(edge_type, 1.0)

        # CodeQL call edges are high quality — weight like inter_call
        if edge_type == "codeql_call":
            base = max(base, profile.get("inter_call", profile.get("call", 4.0)))

        # Intra-procedural edges are infrastructure — heavily discounted
        # so real call edges (even to unknown targets) are explored first.
        if edge_type in ("intra_jump", "intra_seq"):
            base *= 0.30  # jump edges skip CFG chains — boosted above cfg
        elif edge_type == "cfg":
            base *= 0.15
        elif edge_type == "synth_return":
            base *= 0.10  # synthetic return from library call — lowest weight

        # Function-category weights only apply to call-type edges
        # (not cfg/intra_jump, which are intra-procedural infrastructure)
        is_call_edge = edge_type in ("call", "inter_call", "codeql_call", "entry_to_call")
        if is_call_edge:
            fl = target_function.lower()
            # Memory functions
            if any(kw in fl for kw in ("memcpy", "memmove", "memset", "memcmp",
                                         "malloc", "calloc", "realloc", "free",
                                         "new", "delete", "alloc", "dealloc")):
                base = max(base, profile.get("call_to_mem", 1.0))
            # String functions
            if any(kw in fl for kw in ("strcpy", "strncpy", "strcat", "strncat",
                                         "sprintf", "snprintf", "gets", "scanf",
                                         "strlen", "strdup")):
                base = max(base, profile.get("call_to_str", 1.0))
            # Exec functions
            if any(kw in fl for kw in ("system", "exec", "popen", "eval",
                                         "spawn", "shell_exec", "passthru")):
                base = max(base, profile.get("call_to_exec", 1.0))
            # Query functions
            if any(kw in fl for kw in ("mysql_query", "mysqli_query", "sqlite",
                                         "execute", "query", "prepare")):
                base = max(base, profile.get("call_to_query", 1.0))
            # Auth functions
            if any(kw in fl for kw in ("auth", "login", "authenticate", "verify",
                                         "permission", "check_access", "authorize")):
                base = max(base, profile.get("call_to_auth_check", 1.0))
            # Admin functions
            if "admin" in fl:
                base = max(base, profile.get("call_to_admin", 1.0))
            # Web functions — HTTP handlers, redirect, fetch, file upload
            if any(kw in fl for kw in ("request", "response", "redirect", "header",
                                         "upload", "download", "fetch", "curl",
                                         "wget", "http", "url", "uri", "get_file",
                                         "file_get_contents", "readfile", "sendfile",
                                         "forward", "proxy", "dispatch", "route")):
                base = max(base, profile.get("call_to_web", 1.0))
            # Log functions (down-weighted — rarely vulnerability-relevant)
            if any(kw in fl for kw in ("log", "debug", "print", "trace", "info")):
                log_w = profile.get("call_to_log", 0.2)
                base = min(base, log_w) if base > 1.0 else log_w

        return max(base, 0.1)

    # ------------------------------------------------------------------
    # Internal: batch classification of targets
    # ------------------------------------------------------------------

    def _batch_classify_targets(
        self,
        target_funcs: List[dict],
        outgoing_edges: List[tuple],
        issue_report: str,
        archetype: Archetype,
        icfg=None,
    ) -> List[Tuple[str, str, float]]:
        """Batch classify all target functions by slot.

        Uses cache to avoid re-classifying same function.
        Uses simplified (name-only) classification when code unavailable.
        """
        results = []
        uncached: List[dict] = []
        uncached_indices: List[int] = []

        for i, func_info in enumerate(target_funcs):
            key = func_info["key"]
            if key in self._slot_cache:
                results.append((i, self._slot_cache[key]))
            else:
                uncached.append(func_info)
                uncached_indices.append(i)

        if not uncached:
            # All cached — reorder by original index
            return [r[1] for r in sorted(results, key=lambda x: x[0])]

        # Build function list for LLM with code snippets where available
        funcs_for_llm = []
        for func_info in uncached:
            func_name = func_info["name"]
            code = self._get_func_code(func_name, icfg, outgoing_edges)
            funcs_for_llm.append({"name": func_name, "code": code})

        # Classify via LLM
        classifications = self.classifier.classify_batch(
            funcs_for_llm, issue_report, archetype,
        )

        # Update cache
        for i, (slot, just, conf) in enumerate(classifications):
            if i < len(uncached):
                key = uncached[i]["key"]
                self._slot_cache[key] = (slot, just, conf)
                results.append((uncached_indices[i], (slot, just, conf)))

        # Merge cached + newly classified
        all_results = [(idx, res) for idx, res in results]
        all_results.sort(key=lambda x: x[0])
        return [r[1] for r in all_results]

    # ------------------------------------------------------------------
    # Internal: feasibility
    # ------------------------------------------------------------------

    def _should_check_feasibility(self, slot_name: str, slot_priority: float) -> bool:
        """Decide whether to run LLM feasibility check.

        Only for high-priority edges (missing required slots) and sampled.
        """
        if slot_priority < self.PRIORITY_MISSING_REQUIRED:
            return False
        # Sample: only check subset to save LLM cost
        import random
        return random.random() < self.feasibility_sample_rate

    def _estimate_feasibility(
        self,
        dst_node: str,
        edge_data: dict,
        issue_report: str,
        icfg=None,
    ) -> float:
        """Estimate feasibility of callee execution under trigger.

        Returns 1.0 (no check), 0.5 (uncertain), or 0.0 (infeasible).

        Note: Full LLM feasibility check is expensive. Default returns 1.0.
        The sampled LLM check is done via SlotClassifier.check_feasibility().
        """
        # For now, return 1.0 — feasibility checks are optional and expensive.
        # Can be enabled by setting enable_feasibility_check=True and
        # feasibility_sample_rate higher.
        return 1.0

    def run_feasibility_check(
        self,
        scored_edges: List[ScoredEdge],
        issue_report: str,
    ) -> None:
        """Run LLM feasibility checks on selected edges (post-selection).

        Modifies scored_edges in-place, updating feasibility and score.
        """
        for edge in scored_edges:
            if edge.target_slot and edge.slot_priority >= self.PRIORITY_MISSING_REQUIRED:
                # Build minimal code context from edge data
                code = edge.edge_data.get("code", "") or ""
                func_name = edge.target_function

                decision, conf = self.classifier.check_feasibility(
                    issue_report, func_name, code,
                )
                if decision == "YES":
                    edge.feasibility = 1.0
                elif decision == "NO":
                    edge.feasibility = 0.0
                else:
                    edge.feasibility = 0.5

                edge.score = edge.slot_priority * edge.cwe_weight * edge.feasibility

    # ------------------------------------------------------------------
    # Internal: helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_func_name(name: str) -> str:
        """Normalize function name for cache key."""
        if not name:
            return "__unknown__"
        return name.strip().lower().split("(")[0].split("<")[0].strip()

    @staticmethod
    def _get_func_code(
        func_name: str,
        icfg=None,
        outgoing_edges: List[tuple] = None,
    ) -> str:
        """Get function code from ICFG if available. Returns empty string if not.

        The slot classifier works with function name + issue report alone
        when code is unavailable (lower accuracy but functional).
        """
        if icfg is None:
            return ""
        # Try to find the function's entry node and extract code
        entry = icfg.get_entry_node(func_name) if hasattr(icfg, "get_entry_node") else None
        if entry:
            data = icfg.get_node_data(entry) if hasattr(icfg, "get_node_data") else {}
            return data.get("code", "") if data else ""
        # Fallback: look in edge data
        if outgoing_edges:
            for _, edata in outgoing_edges:
                if edata.get("target_function", "") == func_name:
                    return edata.get("code", "") or edata.get("target_code", "")
        return ""
