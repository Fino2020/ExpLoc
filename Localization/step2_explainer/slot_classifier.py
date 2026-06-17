"""
Slot Classifier — LLM classifies function code into archetype slot.

No pattern matching (per user preference). Pure LLM classification.
Given function code + CVE issue report + archetype slot list, LLM
outputs exactly one slot name (or empty for NONE) + justification.

Batch mode: classifies multiple functions in one LLM call for efficiency.
"""

import json
import re
import time
from typing import Dict, List, Optional, Tuple

import httpx
from openai import OpenAI

from .cwe_archetypes.archetype_library import Archetype, Slot

# Reuse LLM config from shared
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from shared.config import (
    OPENAI_DS_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL,
    DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL,
)


# ---------------------------------------------------------------------------
# LLM client factory (same fallback as nl_explainer.py)
# ---------------------------------------------------------------------------

def _get_llm() -> Tuple[OpenAI, str]:
    # Try primary API with short connect timeout (falls through fast if unreachable)
    if OPENAI_DS_API_KEY and OPENAI_BASE_URL:
        return (
            OpenAI(api_key=OPENAI_DS_API_KEY, base_url=OPENAI_BASE_URL, max_retries=1,
                   timeout=httpx.Timeout(120.0, connect=5.0, read=120.0)),
            OPENAI_MODEL,
        )
    if DEEPSEEK_API_KEY:
        return (
            OpenAI(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL, max_retries=2,
                   timeout=httpx.Timeout(120.0, connect=30.0, read=120.0)),
            DEEPSEEK_MODEL,
        )
    raise RuntimeError("No LLM API key configured for SlotClassifier.")


def _try_fallback(error_msg: str) -> Tuple[OpenAI, str]:
    """Try fallback LLM when primary fails (connection errors only)."""
    if DEEPSEEK_API_KEY:
        low = error_msg.lower()
        if "connect" in low or "timeout" in low or "handshake" in low or "eof" in low:
            return (
                OpenAI(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL, max_retries=2,
                       timeout=httpx.Timeout(120.0, connect=30.0, read=120.0)),
                DEEPSEEK_MODEL,
            )
    raise RuntimeError(f"LLM call failed and no fallback: {error_msg}")


# ---------------------------------------------------------------------------
# Slot classification prompt
# ---------------------------------------------------------------------------

SLOT_CLASSIFY_SYSTEM = """You are a vulnerability analysis expert specializing in classifying code functions into vulnerability mechanism stages.

Given:
1. A CVE issue report describing a vulnerability
2. A list of mechanism stages (slots) that constitute the vulnerability archetype
3. Source code for one or more functions (MAY BE UNAVAILABLE — use function name semantics)

For each function, classify it into EXACTLY ONE slot from the provided list, or NONE if it does not participate in any stage of this vulnerability mechanism.

A function fills a slot if:
- For "Source": it reads/acquires untrusted or external input
- For "Missing*" slots: it represents a code path where a required check IS ABSENT
- For "Sink/Impact" slots: it performs the dangerous operation or causes the consequence
- For "NONE": it is a utility function, logging, or unrelated processing with no role in the vulnerability

When source code is unavailable, classify based on function name semantics:
- Names containing "read", "recv", "get", "input", "parse", "request", "extract" → likely Source
- Names containing "alloc", "malloc", "new", "create", "init", "buffer" → likely BufferAllocation/Allocation
- Names containing "copy", "memcpy", "strcpy", "write", "send", "exec", "system" → likely Sink/DangerousUse
- Names containing "free", "delete", "release", "destroy", "close" → likely Free/Release
- Names containing "check", "validate", "verify", "auth", "sanitize" → likely Validate/Sanitize
- Names containing "overflow", "crash", "corrupt", "error", "fail" → likely Corruption/Sink
- Names containing "url", "path", "file", "dir" → analyze in context of issue report (could be Source or BuildPath)
- Names containing "decode", "encode", "parse", "convert", "transform" → likely Manipulation/Processing
If no clear signal from function name, classify as NONE.

Output ONLY valid JSON. No explanation outside the JSON block."""


SLOT_CLASSIFY_USER = """CVE Issue Report:
{issue_report}

Vulnerability Archetype: {archetype_name}
Mechanism Stages (slots):
{slots_text}

Functions to classify:
{functions_text}

For each function, output:
```json
{{
  "classifications": [
    {{
      "function": "function_name",
      "slot": "slot_name_or_empty_for_NONE",
      "justification": "one-line semantic justification"
    }}
  ]
}}
```"""


# ---------------------------------------------------------------------------
# SlotClassifier
# ---------------------------------------------------------------------------

class SlotClassifier:
    """LLM-based slot classification for ICFG nodes.

    Usage:
        classifier = SlotClassifier()
        slot, justification, confidence = classifier.classify(
            func_code, func_name, issue_report, archetype
        )
    """

    def __init__(self, client: Optional[OpenAI] = None, model: Optional[str] = None):
        if client and model:
            self.client = client
            self.model = model
        else:
            self.client, self.model = _get_llm()

    # ------------------------------------------------------------------
    # Single-function classification
    # ------------------------------------------------------------------

    def classify(
        self,
        function_code: str,
        function_name: str,
        issue_report: str,
        archetype: Archetype,
    ) -> Tuple[str, str, float]:
        """Classify a single function into an archetype slot.

        Args:
            function_code: source code of the function body
            function_name: function name (for identification in prompt)
            issue_report: CVE issue description text
            archetype: Archetype with slot definitions

        Returns:
            (slot_name, justification, confidence)
            slot_name is "" for NONE classification.
        """
        results = self.classify_batch(
            [{"name": function_name, "code": function_code}],
            issue_report, archetype,
        )
        if results:
            return results[0]
        return ("", "classification failed", 0.0)

    # ------------------------------------------------------------------
    # Batch classification (primary interface — more efficient)
    # ------------------------------------------------------------------

    def classify_batch(
        self,
        functions: List[dict],
        issue_report: str,
        archetype: Archetype,
    ) -> List[Tuple[str, str, float]]:
        """Classify multiple functions in a single LLM call.

        Args:
            functions: list of {"name": str, "code": str} dicts
            issue_report: CVE issue description text
            archetype: Archetype with slot definitions

        Returns:
            List of (slot_name, justification, confidence) matching input order.
            slot_name is "" for NONE classification.
        """
        if not functions:
            return []

        # Truncate issue report if very long
        truncated_issue = issue_report[:3000] if len(issue_report) > 3000 else issue_report

        # Build slots text
        slots_text = archetype.get_slot_prompt()

        # Build functions text (limit code length per function to ~100 lines / 3000 chars)
        func_parts = []
        for i, func in enumerate(functions):
            code = func.get("code", "")
            if code:
                if len(code) > 3000:
                    code = code[:1500] + "\n... [truncated] ...\n" + code[-1500:]
                code_block = f"```\n{code}\n```"
            else:
                code_block = "```\n[source code not available — classify based on function name semantics]\n```"
            func_parts.append(
                f"### Function {i+1}: {func.get('name', 'unknown')}\n"
                f"{code_block}"
            )
        functions_text = "\n\n".join(func_parts)

        prompt = SLOT_CLASSIFY_USER.format(
            issue_report=truncated_issue,
            archetype_name=archetype.display_name,
            slots_text=slots_text,
            functions_text=functions_text,
        )

        for attempt in range(3):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SLOT_CLASSIFY_SYSTEM},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.1,
                    max_tokens=2048,
                )
                content = response.choices[0].message.content or ""
                return self._parse_batch_response(content, functions, archetype)
            except Exception as exc:
                if attempt == 2:
                    # Connection error fallback: try DeepSeek
                    try:
                        self.client, self.model = _try_fallback(str(exc))
                        return self.classify_batch(functions, issue_report, archetype)
                    except RuntimeError:
                        return [("", f"LLM error: {exc}", 0.0) for _ in functions]
                time.sleep(2)

        return [("", "classification failed", 0.0) for _ in functions]

    # ------------------------------------------------------------------
    # Prompt building helpers (public — usable by other components)
    # ------------------------------------------------------------------

    def build_feasibility_prompt(
        self,
        issue_report: str,
        callee_name: str,
        callee_code: str,
    ) -> str:
        """Build prompt for feasibility check (can this function execute under trigger?).

        Used by EdgeSelector for issue-report feasibility filtering.
        """
        return (
            f"Issue report: {issue_report[:2000]}\n\n"
            f"Function: {callee_name}\n"
            f"```\n{callee_code[:2000]}\n```\n\n"
            f"Can this function execute under the vulnerability trigger condition "
            f"described in the issue report?\n"
            f"Answer: YES / NO / UNCERTAIN"
        )

    def check_feasibility(
        self,
        issue_report: str,
        callee_name: str,
        callee_code: str,
    ) -> Tuple[str, float]:
        """Check whether a callee can execute under the reported trigger.

        Returns: (decision, confidence)
        decision ∈ {"YES", "NO", "UNCERTAIN"}
        confidence: 0.0 to 1.0
        """
        prompt = self.build_feasibility_prompt(issue_report, callee_name, callee_code)

        for attempt in range(2):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "Answer only YES, NO, or UNCERTAIN. No other text."},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.0,
                    max_tokens=32,
                )
                content = response.choices[0].message.content.strip().upper() if response.choices[0].message.content else ""
                if content.startswith("YES"):
                    return ("YES", 0.9)
                elif content.startswith("NO"):
                    return ("NO", 0.9)
                else:
                    return ("UNCERTAIN", 0.5)
            except Exception:
                if attempt == 1:
                    return ("UNCERTAIN", 0.3)
                time.sleep(1)

        return ("UNCERTAIN", 0.3)

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_batch_response(
        self,
        content: str,
        functions: List[dict],
        archetype: Archetype,
    ) -> List[Tuple[str, str, float]]:
        """Parse LLM JSON response for batch classification."""
        valid_slots = {s.name for s in archetype.slots}
        valid_slots.add("")  # NONE

        # Extract JSON block
        json_str = ""
        m = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', content, re.DOTALL)
        if m:
            json_str = m.group(1)
        else:
            # Try raw JSON
            start = content.find("{")
            end = content.rfind("}")
            if start >= 0 and end > start:
                json_str = content[start:end + 1]

        try:
            data = json.loads(json_str)
            classifications = data.get("classifications", [])
        except json.JSONDecodeError:
            # Try to recover: extract individual slot names
            return self._fallback_parse(content, functions, archetype)

        results = []
        for i, func in enumerate(functions):
            if i < len(classifications):
                entry = classifications[i]
                slot = entry.get("slot", "").strip()
                justification = entry.get("justification", "").strip()

                # Validate slot name
                if slot not in valid_slots:
                    slot = ""
                    # Try fuzzy match
                    for vs in valid_slots:
                        if vs and vs.lower() in slot.lower():
                            slot = vs
                            break

                results.append((slot, justification, 0.8 if slot else 0.5))
            else:
                results.append(("", "missing in response", 0.0))

        return results

    def _fallback_parse(
        self,
        content: str,
        functions: List[dict],
        archetype: Archetype,
    ) -> List[Tuple[str, str, float]]:
        """Fallback: extract slot assignments from unstructured LLM output."""
        results = []
        for func in functions:
            func_name = func.get("name", "")
            slot_found = ""
            justification = "fallback parse"

            # Look for patterns like "function_name → slot_name" or "slot_name: function_name"
            for slot in archetype.slots:
                pattern = rf'{re.escape(slot.name)}.*?{re.escape(func_name)}|{re.escape(func_name)}.*?{re.escape(slot.name)}'
                if re.search(pattern, content, re.IGNORECASE):
                    slot_found = slot.name
                    justification = f"fallback: matched '{slot.name}' near '{func_name}'"
                    break

            if not slot_found:
                # Check for "NONE" near function name
                if re.search(rf'{re.escape(func_name)}.*?\bNONE\b|\bNONE\b.*?{re.escape(func_name)}',
                            content, re.IGNORECASE):
                    slot_found = ""
                    justification = "fallback: classified as NONE"

            results.append((slot_found, justification, 0.4 if slot_found else 0.3))

        return results
