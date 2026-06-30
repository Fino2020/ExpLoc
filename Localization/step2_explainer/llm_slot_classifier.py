"""
Phase 2: LLM-Driven Slot Classifier.

Replaces heuristic keyword matching with LLM reasoning.
For each function and its callees, LLM reads code, analyzes data flow,
and assigns each callee to the appropriate archetype slot.

Preserves: archetype slot system, SearchEngine traversal, termination logic.
"""

import json
import re
import sys
import os
from typing import Dict, List, Optional, Tuple

_LOC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _LOC_DIR not in sys.path:
    sys.path.insert(0, _LOC_DIR)

from acr_baseline.model import ModelClient
from step2_explainer.slot_classifier import SlotClassifier as HeuristicClassifier


SYSTEM_PROMPT = """You are a vulnerability analysis expert specializing in slot-based exploit chain reconstruction.

You receive:
1. A CVE vulnerability report
2. An archetype with slots (Source, Sink, Propagation, etc.)
3. A current function and its callees (with source code)

Your task: classify each callee into archetype slots, with confidence scores.

CLASSIFICATION GUIDELINES:
- Source: Where tainted/untrusted data enters the code path (user input, network recv, file read, env vars)
- Sink: Where the vulnerability manifests (buffer overflow, command exec, SQL injection, path traversal)
- MissingBoundsCheck: Where bounds/validation is absent (memcpy, strcpy, array access without size check)
- Allocation: Memory allocation that could fail or overflow
- Free: Resource deallocation (use-after-free, double-free)
- Execute: Command/code execution (system, exec, eval)
- Deserialize: Parsing untrusted data (JSON, XML, binary deserialization)
- PathResolution: File path operations susceptible to traversal
- MissingEncoding: Output encoding missing (XSS)

OUTPUT — JSON inside ```json``` fences:
```json
{
  "classifications": [
    {
      "callee": "function_name",
      "file": "path/to/file.c",
      "slot": "Source",
      "confidence": 0.85,
      "justification": "Reads user-controlled data from network socket without validation..."
    }
  ],
  "analysis_summary": "Brief analysis of how data flows through these functions..."
}
```

Score confidence 0.0-1.0. Use the full range. Only classify functions clearly related to the vulnerability."""


class LLMSlotClassifier:
    """LLM-based slot classifier with SearchBackend access for code verification."""

    def __init__(self):
        self._llm = ModelClient()
        self._cache: Dict[str, Tuple[str, str, float]] = {}

    def classify(
        self,
        function_code: str,
        function_name: str,
        issue_report: str,
        archetype,
    ) -> Tuple[str, str, float]:
        """Classify a single function into an archetype slot.

        Returns: (slot_name, justification, confidence)
        """
        cache_key = function_name
        if cache_key in self._cache:
            return self._cache[cache_key]

        result = self._classify_batch(
            [{"name": function_name, "code": function_code[:2000]}],
            issue_report, archetype,
        )
        if result and result[0]:
            self._cache[cache_key] = result[0]
            return result[0]

        # Fallback to heuristic
        fallback = HeuristicClassifier()
        return fallback.classify(function_code, function_name, issue_report, archetype)

    def classify_batch(
        self,
        functions: List[dict],
        issue_report: str,
        archetype,
    ) -> List[Tuple[str, str, float]]:
        """Classify multiple functions into archetype slots."""
        return self._classify_batch(functions, issue_report, archetype)

    def _classify_batch(
        self,
        functions: List[dict],
        issue_report: str,
        archetype,
    ) -> List[Tuple[str, str, float]]:
        """Internal batch classification via LLM."""
        if not functions:
            return []

        # Describe slots to LLM
        slot_descs = []
        for s in archetype.slots:
            req = "REQUIRED" if s.name in archetype.required_slot_names else "optional"
            slot_descs.append(f"  - {s.name} ({req}): {s.description[:150]}")
        slot_text = "\n".join(slot_descs)

        # Describe functions
        func_descs = []
        for i, fn in enumerate(functions[:50]):
            name = fn.get('name', '?')
            code = fn.get('code', '')[:300]
            func_descs.append(f"  [{i+1}] {name}:\n    {code}")

        prompt = f"""CVE VULNERABILITY REPORT:
{issue_report[:2000]}

ARCHETYPE: {archetype.family} — {archetype.display_name}
SLOTS:
{slot_text}

CANDIDATE FUNCTIONS (callees of a vulnerable function):
{chr(10).join(func_descs)[:8000]}

Classify each candidate function into the most appropriate slot. Output as JSON inside ```json``` fences:
```json
{{
  "classifications": [
    {{"callee": "func_name", "slot": "Source", "confidence": 0.85, "justification": "..."}},
    ...
  ]
}}
```"""

        try:
            response = self._llm.call(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
            )

            # Parse JSON
            m = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', response)
            if not m:
                # Try bare JSON
                m = re.search(r'\{\s*"classifications"\s*:\s*\[[\s\S]*?\]\s*\}', response)
            if m:
                data = json.loads(m.group(1) if 'classifications' in m.group(1) else m.group(0))
                classifications = data.get('classifications', [])

                # Map back to function names
                result = []
                for fn in functions[:len(classifications)]:
                    name = fn.get('name', '')
                    # Find matching classification
                    slot = ""
                    conf = 0.5
                    just = ""
                    for c in classifications:
                        if c.get('callee', '') == name:
                            slot = c.get('slot', '')
                            conf = float(c.get('confidence', 0.5))
                            just = c.get('justification', '')
                            break
                    if not slot:
                        # No classification — fallback to heuristic
                        h = HeuristicClassifier()
                        slot, just, conf = h.classify("", name, issue_report, archetype)
                    result.append((slot, just, min(1.0, max(0.0, conf))))
                return result
        except Exception:
            pass

        # Full fallback: heuristic for all
        h = HeuristicClassifier()
        return [h.classify("", fn.get('name', ''), issue_report, archetype) for fn in functions]
