# Localization/step1_v2/func_pinpointer.py
"""
Stage 2 — Function Pinpointer: single-pass agent for function-level localization
within already-identified vulnerable files.

Receives top-10 files from Stage 1, extracts full function bodies via tree-sitter,
annotates with static analysis alerts, and calls LLM (single-pass) to identify
specific vulnerable functions.
"""

import json
import os
import re
import sys
from typing import Dict, List

_LOC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _LOC_DIR not in sys.path:
    sys.path.insert(0, _LOC_DIR)

from shared.tree_sitter_utils import extract_all_functions_with_bodies


SYSTEM_PROMPT = """You are a vulnerability localization expert specializing in FUNCTION-LEVEL pinpointing.

You receive:
1. A vulnerability report (CVE title + description)
2. A list of candidate files (pre-ranked by a file-level agent)
3. Full function signatures and body snippets extracted from those files
4. Static analysis annotations (CodeQL alerts mapped to specific files)

Your task: identify the SPECIFIC vulnerable functions within the provided files.

CRITICAL CONSTRAINTS:
- Every function name MUST be copied EXACTLY from the FUNCTION CONTEXT section.
  Do not invent, paraphrase, or guess function names.
- The "file" field for each function MUST match the file path shown in FUNCTION CONTEXT.
- Do not predict functions from files NOT listed in FUNCTION CONTEXT.

RANKING RULES:
- Functions with static analysis alerts + matching vulnerability type → highest (0.80-1.00)
- Functions in commit patches with relevant logic → medium-high (0.55-0.79)
- Functions that appear structurally related (helper/callback) → medium (0.30-0.54)
- Use the FULL 0.10-1.00 score range
- Predict 10-20 functions

OUTPUT — single JSON block inside ```json``` fences:
```json
{
  "vulnerable_functions": [
    {
      "function": "exact_name_from_context",
      "file": "path/to/file.c",
      "score": 0.85,
      "reason": "Brief explanation of why this function is vulnerable",
      "evidence": {
        "static_alert": "CodeQL command_injection @ L142",
        "code_analysis": "Unsanitized user input flows to system() call"
      }
    }
  ],
  "confidence": "high",
  "analysis_summary": "Brief analysis of function-level vulnerability localizations"
}
```

Confidence: "high", "medium", or "low"."""


class FuncPinpointer:
    """Stage 2 agent: single-pass function localization within candidate files."""

    def __init__(self, repo_path: str = ""):
        self.repo_path = repo_path
        from acr_baseline.model import ModelClient
        self._llm = ModelClient()

    def pinpoint(
        self,
        cve_id: str,
        issue_title: str,
        issue_body: str,
        language: str,
        top_files: List[dict],
    ) -> dict:
        """Run Stage 2 function pinpointing.

        Args:
            cve_id: CVE identifier
            issue_title: CVE title
            issue_body: CVE description
            language: primary language of the repo
            top_files: list of {'file': str, 'score': float, 'reason': str, ...}
                       from Stage 1 FileHunter output

        Returns dict with vulnerable_functions[], confidence, analysis_summary.
        """
        issue_description = f"Title: {issue_title}\n\nDescription:\n{issue_body}"

        # Extract function bodies for top files (capped at 10 files)
        file_func_map = self._extract_functions(top_files[:10])

        # Build prompt
        file_list_section = self._format_file_list(top_files[:10])
        func_context_section = self._format_function_context(
            file_func_map, cve_id
        )

        prompt = f"""VULNERABILITY REPORT:
{issue_description[:2000]}

LANGUAGE: {language or 'unknown'}

STAGE 1 RESULTS — Top Candidate Files:
{file_list_section}

FUNCTION CONTEXT (tree-sitter extracted, with static analysis annotations):
{func_context_section[:6000] or 'No function bodies could be extracted.'}

Based on the vulnerability report and the function context above, identify
the specific vulnerable functions. Every function name MUST match exactly
the signatures listed in FUNCTION CONTEXT above. Do not invent names."""

        # Call LLM with fallback through backends
        result = self._call_llm(prompt)

        result["_stage2_mode"] = "single_pass"
        return result

    # ------------------------------------------------------------------
    # Function extraction
    # ------------------------------------------------------------------

    def _extract_functions(
        self, top_files: List[dict], max_files: int = 10
    ) -> Dict[str, List[dict]]:
        """Extract full function bodies for top candidate files.

        Returns {file_path: [func_dict, ...]} where func_dict has:
            name, start_line, end_line, body_snippet, params
        """
        result: Dict[str, List[dict]] = {}
        for vf in top_files[:max_files]:
            fpath = vf.get("file", "")
            if not fpath:
                continue
            full_path = os.path.join(self.repo_path, fpath)
            if not os.path.isfile(full_path):
                continue

            try:
                funcs = extract_all_functions_with_bodies(
                    full_path, body_snippet_lines=25
                )
                if funcs:
                    # Cap at 50 functions per file
                    result[fpath] = funcs[:50]
            except Exception:
                continue

        return result

    # ------------------------------------------------------------------
    # Prompt assembly
    # ------------------------------------------------------------------

    def _format_file_list(self, top_files: List[dict]) -> str:
        lines = []
        for i, vf in enumerate(top_files, 1):
            fpath = vf.get("file", "?")
            score = vf.get("score", 0)
            reason = vf.get("reason", "")[:100]
            lines.append(f"  {i}. [{score:.2f}] {fpath} — {reason}")
        return "\n".join(lines)

    def _format_function_context(
        self, file_func_map: Dict[str, List[dict]], cve_id: str
    ) -> str:
        """Format extracted function bodies with static analysis annotations."""
        if not file_func_map:
            return "No function bodies available."

        # Gather static alerts for annotation
        alerts: Dict[str, Dict[int, List[str]]] = {}
        try:
            from step1_v2.static_evidence import _find_codeql_csv, _extract_alert_summary

            codeql_path = _find_codeql_csv(cve_id)
            if codeql_path:
                candidate_set = set(file_func_map.keys())
                raw_alerts = _extract_alert_summary(codeql_path, candidate_set)
                # Parse alerts to map line numbers for annotation
                for fpath, alert_list in raw_alerts.items():
                    line_alerts: Dict[int, List[str]] = {}
                    for alert_str in alert_list:
                        # Parse "alert_type @ L{line}"
                        m = re.match(r"(.+)\s*@\s*L(\d+)", alert_str)
                        if m:
                            alert_type = m.group(1).strip()
                            line_num = int(m.group(2))
                            line_alerts.setdefault(line_num, []).append(alert_type)
                    if line_alerts:
                        alerts[fpath] = line_alerts
        except Exception:
            pass

        sections = []
        for fpath, funcs in file_func_map.items():
            sections.append(f"\n{'='*60}")
            sections.append(f"FILE: {fpath}")
            file_alerts = alerts.get(fpath, {})

            # Show file-level alert summary
            if file_alerts:
                total = sum(len(v) for v in file_alerts.values())
                sections.append(f"  Static Alerts: {total} alerts in this file")

            sections.append(f"  Functions ({len(funcs)}):")
            for func in funcs:
                name = func.get("name", "?")
                start = func.get("start_line", "?")
                end = func.get("end_line", "?")
                params = func.get("params", "")
                body = func.get("body_snippet", "")

                # Annotate with alerts at this function's line range
                func_alerts = []
                if file_alerts:
                    for line_num, alert_types in file_alerts.items():
                        if isinstance(start, int) and isinstance(end, int):
                            if start <= line_num <= end:
                                func_alerts.extend(alert_types)

                alert_tag = ""
                if func_alerts:
                    alert_tag = f" [ALERTS: {', '.join(func_alerts[:3])}]"

                sections.append(f"\n  --- {name}({params}) @ L{start}-{end}{alert_tag} ---")
                if body:
                    sections.append(body[:600])  # cap per function body

        return "\n".join(sections)

    # ------------------------------------------------------------------
    # LLM call
    # ------------------------------------------------------------------

    def _call_llm(self, prompt: str) -> dict:
        """Call LLM via ModelClient (DS proxy with rate-limit retry, DeepSeek fallback)."""
        try:
            content = self._llm.call(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=4096,
            )
            return self._parse_output(content)
        except Exception as e:
            print(f"  [FUNC_PINPOINTER] All backends exhausted: {str(e)[:100]}")
            return {
                "vulnerable_functions": [],
                "confidence": "low",
                "analysis_summary": f"LLM call failed: {str(e)[:200]}",
            }

    def _parse_output(self, content: str) -> dict:
        """Parse JSON from LLM output."""
        json_match = re.search(r"```json\s*(.*?)\s*```", content, re.DOTALL)
        if not json_match:
            json_match = re.search(
                r"\{[\s\S]*\"vulnerable_functions\"[\s\S]*\}", content
            )
            if json_match:
                json_str = json_match.group(0)
            else:
                return {
                    "vulnerable_functions": [],
                    "confidence": "low",
                    "analysis_summary": "Failed to parse output",
                }
        else:
            json_str = json_match.group(1)

        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            return {
                "vulnerable_functions": [],
                "confidence": "low",
                "analysis_summary": "JSON parse error",
            }

    def close(self):
        pass
