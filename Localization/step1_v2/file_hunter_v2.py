# Localization/step1_v2/file_hunter_v2.py
"""
Iterative File Hunter — multi-round LLM agent for file-level vulnerability localization.

Uses ACR's SearchBackend (class/function/text index) for O(1) code search.
Replaces single-pass FileHunter with iterative tool-calling pattern.
"""

import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

_LOC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _LOC_DIR not in sys.path:
    sys.path.insert(0, _LOC_DIR)

from acr_baseline.search_backend import SearchBackend
from acr_baseline.model import ModelClient
from acr_baseline.data_structures import BugLocation, MessageThread
from acr_baseline.search_manage import parse_function_invocation


# ---------------------------------------------------------------------------
# Prompts (optimized for comprehensive file discovery)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a security researcher analyzing a vulnerability report for a software project.
The vulnerability report is marked between <issue> and </issue>.
Your task is to invoke search API calls to locate ALL source FILES and FUNCTIONS likely relevant to the vulnerability.

CRITICAL: Your goal is COMPREHENSIVE coverage. Find ALL potentially related files AND their vulnerable functions.
Use search_method() and search_code() to identify specific vulnerable functions within discovered files.
"""

SELECT_PROMPT = """Based on the vulnerability report, use the following search APIs to explore the codebase:

- search_class(class_name: str): Search for a class in the entire codebase.
- search_class_in_file(class_name: str, file_name: str): Search for a class in a specific file.
- search_method_in_file(method_name: str, file_path: str): Search for a method/function in a specific file.
- search_method_in_class(method_name: str, class_name: str): Search for a method within a specific class.
- search_method(method_name: str): Search for a method/function in the entire codebase.
- search_code(code_str: str): Search for a code string in the entire codebase.
- search_code_in_file(code_str: str, file_path: str): Search for a code string in a specific file.
- get_code_around_line(file_path: str, line_number: int, window_size: int): Get code around a line number.

SEARCH STRATEGY (follow this order):
1. EXTRACT: Identify 3-5 key terms from the vulnerability report (function names, API calls, error messages, variable names, module names).
2. BROAD SEARCH: Use search_code() with distinctive code patterns or error strings from the report.
3. TARGETED SEARCH: Use search_method() for specific function names mentioned or implied by the report.
4. CLASS SEARCH: Use search_class() for class/module names related to the vulnerability.
5. DEEP DIVE: Use search_method() and search_code() to find specific vulnerable functions. Use get_code_around_line() to read their code.
6. EXPAND: If you find one relevant file, search for related files (same directory, similar names, imports/includes).

Use MULTIPLE APIs per round (3-5 calls). Each API call must have concrete arguments from the report.
Do NOT guess API names — use only the 8 APIs listed above.

Output format:
```json
{"API_calls": ["search_code('buffer_overflow')", "search_method('authenticate')"], "bug_locations": []}
```"""

ANALYZE_AND_SELECT_PROMPT = """Based on your analysis of the search results above, answer in this EXACT JSON format:

```json
{
  "API_calls": ["search_code('some_code')"],
  "bug_locations": [
    {
      "file": "src/module/file.ext",
      "class": "ClassName",
      "method": "vulnerableFunction",
      "intended_behavior": "This file handles user input without proper bounds checking..."
    }
  ],
  "coverage_assessment": "partial"
}
```

Rules:
- If you need more context: fill API_calls, leave bug_locations EMPTY [].
- If you found vulnerability locations: leave API_calls EMPTY [], fill bug_locations.
- Identify 5-10 files AND their most likely vulnerable methods/functions.
- Each bug location MUST have: file, method (can be empty "" if unsure), class (can be ""), intended_behavior.
- For method: use EXACT function names from search_method() results. Do NOT invent names.
- File paths MUST be EXACT paths from search results.
- "coverage_assessment": "comprehensive" or "partial".
- Also search for specific vulnerable functions using search_method() or search_code().

BEFORE FINALIZING, ask yourself:
- Have I searched for ALL key terms from the vulnerability report?
- Have I used search_method() to find specific vulnerable functions?
- Are there configuration files, header files, or related modules I should check?
- Would searching with alternative keywords reveal more files? Only finalize after at least 3 rounds of exploration."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_issue_text(cve_id: str, title: str, body: str, severity: str = "",
                     cvss: str = "", cwe_ids: list = None) -> str:
    """Build rich issue report text matching ACR's format for better LLM context."""
    parts = []
    parts.append(f"# Vulnerability Report: {cve_id}")
    if severity or cvss:
        parts.append(f"Severity: {severity or 'N/A'} (CVSS: {cvss or 'N/A'})")
    if cwe_ids:
        parts.append(f"CWE: {', '.join(cwe_ids)}")
    parts.append("")
    parts.append("## Description")
    if title:
        parts.append(f"Title: {title}")
    parts.append(body or "No description available.")
    return "\n".join(parts)


def _prepare_issue_prompt(title: str, body: str, cve_id: str = "",
                          severity: str = "", cvss: str = "", cwe_ids: list = None) -> str:
    """Sanitize and tag the issue statement."""
    text = _build_issue_text(cve_id, title, body, severity, cvss, cwe_ids)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    lines = [x.strip() for x in text.split("\n")]
    lines = [x for x in lines if x]
    return "<issue>\n" + "\n".join(lines) + "\n</issue>"


def _extract_json(text: str) -> Optional[dict]:
    """Extract JSON object from LLM response text."""
    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    for match in re.finditer(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text, re.DOTALL):
        try:
            result = json.loads(match.group())
            if "API_calls" in result or "bug_locations" in result:
                return result
        except json.JSONDecodeError:
            continue
    return None


class IterativeFileHunter:
    """Multi-round file-level search agent using SearchBackend + LLM tool calling."""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.backend = SearchBackend(repo_path)
        self.client = ModelClient()
        self._rounds = 0

    def hunt(
        self,
        cve_id: str = "",
        issue_title: str = "",
        issue_body: str = "",
        language: str = "",
        before_date: str = "",
        max_rounds: int = 5,
        severity: str = "",
        cvss: str = "",
        cwe_ids: list = None,
    ) -> dict:
        """Run iterative file-level search.

        Returns dict with vulnerable_files[], confidence, analysis_summary, _rounds.
        Compatible with existing step1_v2/pipeline.py consumer.
        """
        t_start = time.time()
        issue_text = _prepare_issue_prompt(
            issue_title, issue_body, cve_id=cve_id,
            severity=severity, cvss=cvss, cwe_ids=cwe_ids or [],
        )

        msg_thread = MessageThread()
        msg_thread.add_system(SYSTEM_PROMPT)
        msg_thread.add_user(issue_text)
        msg_thread.add_user(SELECT_PROMPT)

        bug_locations: list = []
        search_result_msg = ""
        round_no = 0
        all_files_seen: set = set()
        coverage = "partial"

        for round_no in range(max_rounds):
            self._rounds = round_no + 1

            # --- LLM call: select APIs (round 0) or analyze + decide (rounds 1+) ---
            if round_no == 0:
                response = self.client.call(msg_thread.to_msg(), temperature=0.0, max_tokens=4096)
                msg_thread.add_model(response)
                parsed = _extract_json(response)
            else:
                # Add progress nudges if coverage is shallow
                progress_note = ""
                if all_files_seen:
                    progress_note = f"\n\nFiles identified so far: {len(all_files_seen)}. "
                    if len(all_files_seen) < 3:
                        progress_note += "Try different search terms to find more related files."
                    elif len(all_files_seen) < 5:
                        progress_note += "Consider searching for additional related files."

                msg_thread.add_user(search_result_msg + progress_note)

                # At round 4 (second-to-last), force bug_locations output
                if round_no >= max_rounds - 2 and len(all_files_seen) == 0:
                    force_prompt = (
                        "FINAL IDENTIFICATION ROUND. Do NOT search for more code.\n\n"
                        "Based on ALL the search results and context collected so far, "
                        "you MUST identify the most likely vulnerable files.\n\n"
                        "Output ONLY bug_locations with the file paths you've seen. "
                        "Leave API_calls EMPTY. Provide 3-10 file paths.\n\n"
                        + ANALYZE_AND_SELECT_PROMPT
                    )
                    msg_thread.add_user(force_prompt)
                else:
                    combined_prompt = (
                        "Analyze the search results:\n"
                        "1. What does this code do?\n"
                        "2. How does it relate to the vulnerability?\n"
                        "3. What other files might be related?\n\n"
                        + ANALYZE_AND_SELECT_PROMPT
                    )
                    msg_thread.add_user(combined_prompt)

                response = self.client.call(msg_thread.to_msg(), temperature=0.0, max_tokens=4096)
                msg_thread.add_model(response)
                parsed = _extract_json(response)

            if parsed is None:
                continue

            api_calls = parsed.get("API_calls", [])
            bug_locs_raw = parsed.get("bug_locations", [])
            new_coverage = parsed.get("coverage_assessment", "partial")

            # --- Resolve any bug locations ---
            if bug_locs_raw:
                resolved = self._resolve_bug_locations(bug_locs_raw)
                if resolved:
                    for loc in resolved:
                        if loc.rel_file_path and loc.rel_file_path not in all_files_seen:
                            all_files_seen.add(loc.rel_file_path)
                            bug_locations.append(loc)
                    coverage = new_coverage

                if not api_calls:
                    # Agent wants to stop with bug_locations
                    if len(all_files_seen) >= 2 or round_no == max_rounds - 1:
                        break
                    search_result_msg = (
                        f"Only {len(all_files_seen)} files identified. "
                        "Explore a bit more — search for related files in the same directories."
                    )
                    continue
                # Agent has both bug_locations AND api_calls — execute both
                search_result_msg = self._execute_api_calls(api_calls)
                continue

            # --- No bug_locations yet: execute API calls or nudge ---
            if api_calls:
                search_result_msg = self._execute_api_calls(api_calls)

            # After round 3, force transition from search to identification
            if len(all_files_seen) == 0 and round_no >= 3:
                search_result_msg += (
                    "\n\nCRITICAL: You have been searching for multiple rounds without "
                    "identifying any files. Based on ALL search results above, you MUST "
                    "now identify the most likely vulnerable files. Output bug_locations "
                    "with file paths from the search results. Leave API_calls EMPTY. "
                    "Provide 3-5 file paths even if you are not 100% certain."
                )
            elif len(all_files_seen) < 3 and round_no >= 2:
                search_result_msg += (
                    f"\n\nYou have identified {len(all_files_seen)} files so far. "
                    "Search for a few more related files (helpers, callers, config)."
                )
            elif not api_calls and len(all_files_seen) == 0:
                search_result_msg = (
                    "Please provide either API_calls to search for more context, "
                    "or bug_locations to identify vulnerable files."
                )

        # --- Format result ---
        elapsed = time.time() - t_start
        return self._format_result(bug_locations, round_no + 1, elapsed)

    def _execute_api_calls(self, api_calls: List[str]) -> str:
        """Execute a list of API call strings, return collated results text."""
        collated = ""
        for api_call in api_calls:
            try:
                func_name, func_args = parse_function_invocation(api_call)
            except ValueError as e:
                collated += f"Error parsing API call '{api_call}': {e}\n\n"
                continue

            if not hasattr(self.backend, func_name):
                collated += f"Unknown API: {func_name}\n\n"
                continue

            func = getattr(self.backend, func_name)
            try:
                result_str, _, call_ok = func(*func_args)
            except Exception as e:
                result_str = f"Error calling {api_call}: {e}"
                call_ok = False

            status = "OK" if call_ok else "FAILED"
            collated += f"Result of {api_call} [{status}]:\n{result_str}\n\n"

        return collated

    def _resolve_bug_locations(self, raw_locs: List[dict]) -> list:
        """Resolve raw agent bug_locations into concrete BugLocation objects."""
        all_locs = []
        for loc_dict in raw_locs:
            resolved = self.backend.get_bug_loc_snippets_new(loc_dict)
            all_locs.extend(resolved)

        unique = []
        seen = set()
        for loc in all_locs:
            key = (loc.rel_file_path, loc.start, loc.end)
            if key not in seen:
                seen.add(key)
                unique.append(loc)
        return unique

    def _format_result(self, bug_locations: list, rounds: int, elapsed: float) -> dict:
        """Format bug locations into pipeline-compatible result dict."""
        vulnerable_files = []
        vulnerable_functions = []
        seen_files = set()
        seen_funcs = set()

        for i, loc in enumerate(bug_locations):
            fpath = loc.rel_file_path
            if fpath and fpath not in seen_files:
                seen_files.add(fpath)
                score = 1.0 - (i * 0.03)
                vulnerable_files.append({
                    "file": fpath,
                    "score": max(0.1, round(score, 4)),
                    "reason": loc.intended_behavior or "",
                    "evidence": {
                        "class": loc.class_name or "",
                        "line_range": f"L{loc.start}-L{loc.end}" if loc.start and loc.end else "",
                    },
                })

            # Extract function predictions from bug_locations
            method_name = getattr(loc, 'method_name', '') or ''
            if method_name and fpath and (fpath, method_name) not in seen_funcs:
                seen_funcs.add((fpath, method_name))
                vulnerable_functions.append({
                    "function": method_name,
                    "file": fpath,
                    "score": max(0.1, round(1.0 - (i * 0.03), 4)),
                    "reason": loc.intended_behavior or "",
                })

        if not vulnerable_files:
            return {
                "vulnerable_files": [],
                "vulnerable_functions": [],
                "confidence": "low",
                "analysis_summary": f"No vulnerable files identified after {rounds} rounds ({elapsed:.1f}s)",
                "_rounds": rounds,
            }

        n = len(vulnerable_files)
        confidence = "high" if n >= 5 else "medium" if n >= 2 else "low"
        return {
            "vulnerable_files": vulnerable_files,
            "vulnerable_functions": vulnerable_functions,
            "confidence": confidence,
            "analysis_summary": f"Identified {n} files, {len(vulnerable_functions)} functions across {rounds} rounds ({elapsed:.1f}s)",
            "_rounds": rounds,
        }

    def close(self):
        pass
