"""
Termination Controller — decides when search should stop.

Four rules:
  1. Archetype Complete  → SUCCESS (all required slots filled)
  2. Stagnation Detection → STUCK (no new slots in window)
  3. Safety Cutoff        → TRUNCATED (depth exceeded)
  4. Slot Revisit         → CONTINUE but deprioritize (handled by edge_selector)
"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Optional, Set

from .cwe_archetypes.archetype_library import Archetype


class TerminationReason(Enum):
    CONTINUE = auto()          # Keep searching
    SUCCESS = auto()           # All required slots filled — return path
    STUCK = auto()             # No progress in recent steps — prune branch
    TRUNCATED = auto()         # Max depth exceeded — return partial result
    DEAD_END = auto()          # No outgoing edges — cannot continue


@dataclass
class TerminationDecision:
    reason: TerminationReason
    confidence_modifier: float = 1.0     # Multiplier for result confidence
    message: str = ""


class TerminationController:
    """Determines whether search should terminate at current path state.

    Usage:
        ctrl = TerminationController(max_depth=15, stagnation_window=5)
        decision = ctrl.check(path, filled_slots, archetype, slot_history)
    """

    def __init__(
        self,
        max_depth: int = 15,
        stagnation_window: int = 5,
        min_required_ratio: float = 0.5,
    ):
        self.max_depth = max_depth
        self.stagnation_window = stagnation_window
        self.min_required_ratio = min_required_ratio  # for stagnation: if below, prune

    def check(
        self,
        path_nodes: List[str],
        filled_required_slots: Set[str],
        filled_optional_slots: Set[str],
        archetype: Archetype,
        slot_history: List[bool],     # True if step i filled a NEW slot
        has_outgoing_edges: bool = True,
    ) -> TerminationDecision:
        """Check all termination rules. First match wins.

        Args:
            path_nodes: ordered node IDs on current path
            filled_required_slots: names of filled REQUIRED slots
            filled_optional_slots: names of filled OPTIONAL slots
            archetype: the CWE archetype being searched
            slot_history: list of bool, True if step i filled a new slot
            has_outgoing_edges: whether current node has successors in ICFG

        Returns:
            TerminationDecision with reason and confidence modifier
        """

        # Rule 1: Archetype Complete
        required = archetype.required_slot_names
        if required and required.issubset(filled_required_slots):
            all_filled = len(filled_required_slots | filled_optional_slots)
            total = len(archetype.slots)
            conf = 1.0 if all_filled == total else 0.85
            return TerminationDecision(
                reason=TerminationReason.SUCCESS,
                confidence_modifier=conf,
                message=f"All {len(required)} required slots filled "
                        f"(+ {len(filled_optional_slots)} optional)",
            )

        # Rule 2: Dead end (no outgoing edges)
        if not has_outgoing_edges:
            filled_count = len(filled_required_slots)
            total_required = len(required)
            return TerminationDecision(
                reason=TerminationReason.DEAD_END,
                confidence_modifier=filled_count / max(total_required, 1),
                message=f"No outgoing edges. Filled {filled_count}/{total_required} required slots.",
            )

        # Rule 3: Stagnation Detection
        # Stagnation = no new slots filled AND nodes are cycling (not making CFG progress).
        # CFG traversal visits new nodes without filling slots — that's normal, don't prune.
        if len(slot_history) >= self.stagnation_window:
            recent = slot_history[-self.stagnation_window:]
            new_slots_in_window = sum(1 for filled in recent if filled)

            if new_slots_in_window == 0:
                # Check if we're cycling (revisiting nodes) vs traversing CFG (new nodes)
                recent_nodes = path_nodes[-self.stagnation_window:]
                unique_nodes = len(set(recent_nodes))
                cycling = unique_nodes < len(recent_nodes) * 0.5  # >50% repeats

                if cycling:
                    filled_count = len(filled_required_slots)
                    total_required = max(len(required), 1)
                    ratio = filled_count / total_required

                    if ratio < self.min_required_ratio:
                        return TerminationDecision(
                            reason=TerminationReason.STUCK,
                            confidence_modifier=ratio,
                            message=f"Stagnation: cycling + 0/{self.stagnation_window} new slots, "
                                    f"filled {filled_count}/{total_required} required (< {self.min_required_ratio})",
                        )
                    else:
                        return TerminationDecision(
                            reason=TerminationReason.CONTINUE,
                            confidence_modifier=0.5,
                            message=f"Cycling but {filled_count}/{total_required} required slots filled — deprioritizing",
                        )

        # Rule 4: Safety Cutoff (max depth)
        if len(path_nodes) >= self.max_depth:
            filled_count = len(filled_required_slots)
            total_required = max(len(required), 1)
            if required.issubset(filled_required_slots):
                return TerminationDecision(
                    reason=TerminationReason.SUCCESS,
                    confidence_modifier=0.85,
                    message=f"Complete at max depth {self.max_depth}",
                )
            return TerminationDecision(
                reason=TerminationReason.TRUNCATED,
                confidence_modifier=filled_count / total_required * 0.7,
                message=f"Max depth {self.max_depth} reached. "
                        f"Filled {filled_count}/{total_required} required slots.",
            )

        # Default: continue
        return TerminationDecision(reason=TerminationReason.CONTINUE)

    def should_prune(self, decision: TerminationDecision) -> bool:
        """Whether this path should be pruned (not added to frontier)."""
        return decision.reason in (
            TerminationReason.STUCK,
            TerminationReason.DEAD_END,
        )

    def is_terminal(self, decision: TerminationDecision) -> bool:
        """Whether this path has reached a terminal state (success or failure)."""
        return decision.reason in (
            TerminationReason.SUCCESS,
            TerminationReason.STUCK,
            TerminationReason.TRUNCATED,
            TerminationReason.DEAD_END,
        )
