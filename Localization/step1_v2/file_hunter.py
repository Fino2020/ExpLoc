"""
Stage 1 — File Hunter: single-pass agent for file-level vulnerability localization.

Uses expanded evidence prompt (issue + static analysis + directory + commits +
resolved issues) in a single LLM call. No tool calling — DeepSeek tool-calling
mode is unreliable for final JSON output.

Backend fallback: DS proxy → DeepSeek direct.
"""

import json
import os
import re
import sys
import time
from typing import Dict, List

import httpx
from openai import OpenAI

_LOC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _LOC_DIR not in sys.path:
    sys.path.insert(0, _LOC_DIR)

from shared.config import (
    OPENAI_DS_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL,
    DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL,
)


# Additional model configs for backend fallback
_EXTRA_MODELS = [
    ("CLAUDE_SONNET_4_6", "claude-sonnet-4-6"),
    ("GPT_5_MINI", "gpt-5-mini"),
    ("GEMINI_3_FLASH_PREVIEW", "gemini-3-flash-preview"),
    ("GROK_4_3", "grok-4.3"),
]
from shared.sink_db import detect_vuln_types


SYSTEM_PROMPT = """You are a vulnerability localization expert.

You receive:
1. A vulnerability report (CVE title + description)
2. Detected vulnerability types
3. Static analysis findings (CodeQL/ICFG function coverage)
4. Directory structure of the repository
5. Resolved issues with linked commits and changed files
6. Commit history (BM25-ranked) with patches
7. Function context — tree-sitter function signatures from candidate files

Your task: identify the most likely vulnerable files AND functions.

CRITICAL — FUNCTION NAMES:
- Every predicted function MUST be selected FROM the "FUNCTION CONTEXT" section (Section 7).
  Section 7 lists function signatures extracted from the actual source code via tree-sitter.
- You MUST copy the exact function name as it appears in Section 7. Do not invent,
  paraphrase, or guess function names.
- For each vulnerable_function, the "file" field MUST match the file path shown in
  Section 7 for that function.

RANKING RULES:
- Files/functions appearing in MULTIPLE evidence sources → highest (0.80-1.00)
- Files in high-scoring commits + static analysis → medium-high (0.55-0.79)
- Files whose names/directories match the vulnerability type → medium (0.30-0.54)
- Use the FULL 0.10-1.00 score range with clear differentiation
- TOP-3 file predictions MUST have scores >= 0.70
- Prefer root-cause locations (input parsers, validators) over symptom locations
- Each prediction MUST include an "evidence" object

OUTPUT — single JSON block inside ```json``` fences:
```json
{
  "vulnerable_files": [
    {
      "file": "path/to/file.c",
      "score": 0.85,
      "reason": "Brief explanation",
      "evidence": {
        "matching_commits": ["abc1234"],
        "matching_issues": [571],
        "static_alerts": ["command_injection"],
        "code_analysis": "Handles unsanitized user input"
      }
    }
  ],
  "vulnerable_functions": [
    {
      "function": "exact_name_from_context",
      "file": "path/to/file.c",
      "score": 0.80,
      "reason": "Brief explanation",
      "evidence": {
        "matching_commits": ["abc1234"],
        "code_analysis": "Unsanitized user input flows to system() call"
      }
    }
  ],
  "confidence": "high",
  "analysis_summary": "Brief analysis of how evidence supports the localization"
}
```
Predict 10-20 files and 10-20 functions. Confidence: "high", "medium", or "low"."""


def _get_all_backends():
    """Build available LLM backends for single-pass calls.

    Priority: DS proxy only.
    """
    backends = []
    if OPENAI_DS_API_KEY and OPENAI_BASE_URL:
        backends.append((
            OpenAI(api_key=OPENAI_DS_API_KEY, base_url=OPENAI_BASE_URL, max_retries=3,
                   timeout=httpx.Timeout(90.0, connect=15.0, read=90.0)),
            OPENAI_MODEL,
        ))
    if not backends:
        raise RuntimeError("No LLM API key configured. Check .env file.")
    return backends


class FileHunter:
    """Stage 1 agent: single-pass file-level localization with expanded evidence."""

    def __init__(self, retriever, repo_path: str = ""):
        self.retriever = retriever
        self.repo_path = repo_path or retriever.repo_path
        self._backends = _get_all_backends()
        self.client, self.model = self._backends[0]

    def hunt(
        self,
        cve_id: str,
        issue_title: str,
        issue_body: str,
        language: str = "",
        before_date: str = "",
    ) -> dict:
        """Run Stage 1 file hunting — single-pass LLM with expanded evidence.

        Returns dict with vulnerable_files[], confidence, analysis_summary.
        """
        issue_description = f"Title: {issue_title}\n\nDescription:\n{issue_body}"

        from step1_locator.file_context import get_directory_section

        directory_section = get_directory_section(self.repo_path, depth=3)

        # Resolved issues
        resolved = self.retriever.search_issues(issue_description, top_k=5)
        resolved_section = _format_issues(resolved)

        # Commit history
        commit_hits = self.retriever.search_commit(
            issue_description, top_k=10, before_date=before_date
        )
        examined = []
        all_files: set = set()
        for hit in commit_hits[:5]:
            detail = self.retriever.examine_commit(hit["sha"])
            if detail:
                examined.append(detail)
                for f in detail.get("modified_files", []):
                    all_files.add(f)
        commit_section = _format_commits(examined)

        # Static analysis evidence
        vuln_types = detect_vuln_types(issue_description)
        from step1_v2.static_evidence import load_static_evidence
        static_section = load_static_evidence(
            cve_id, self.repo_path, list(all_files), vuln_types
        )

        # Function context — use proven get_context_section from file_context
        from step1_locator.file_context import get_context_section
        hotspot_files = self.retriever.get_hotspots(top_k=30)
        func_context = get_context_section(
            self.repo_path,
            list(all_files),
            hotspot_files,
            top_k=20,
        )

        # Fallback: if repo doesn't exist (func_context empty), use ICFG data
        if not func_context or "No source files available" in func_context:
            from step1_v2.static_evidence import _parse_icfg_csv, _find_codeql_csv, _find_scubatrace_csv
            all_funcs = {}
            for icfg_finder in [_find_codeql_csv, _find_scubatrace_csv]:
                icfg_path = icfg_finder(cve_id)
                if icfg_path:
                    data = _parse_icfg_csv(icfg_path)
                    for fpath, funcs in data.items():
                        all_funcs.setdefault(fpath, set()).update(funcs)
            if all_funcs:
                lines = ["ICFG FUNCTION CONTEXT (from static analysis graph):", ""]
                for fpath in sorted(all_funcs)[:20]:
                    func_str = ", ".join(sorted(all_funcs[fpath])[:8])
                    lines.append(f"  {fpath}: {func_str}")
                func_context = "\n".join(lines)

        # Build prompt
        user_message = f"""VULNERABILITY REPORT:
{issue_description[:2500]}

LANGUAGE: {language or 'unknown'}
DETECTED VULN TYPES: {', '.join(vuln_types) if vuln_types else 'none detected'}

STATIC ANALYSIS FINDINGS:
{static_section[:1500] or 'No static analysis data available for this CVE.'}

DIRECTORY STRUCTURE:
{directory_section[:2000]}

INITIAL EVIDENCE:
Resolved Issues:
{resolved_section[:1500] or 'No resolved issues found.'}

Commit History (BM25-ranked):
{commit_section[:1500] or 'No matching commits found.'}

FUNCTION CONTEXT (tree-sitter signatures from candidate files):
{func_context[:4000] or 'No function context available.'}

Based on ALL evidence above, identify the most likely vulnerable files AND functions.
Output JSON with both vulnerable_files[] and vulnerable_functions[].
Every function name MUST come from the FUNCTION CONTEXT section above."""

        # Single-pass call with backend fallback
        return self._call_single_pass(user_message)

    def _call_single_pass(self, user_message: str) -> dict:
        """Call LLM single-pass with backend fallback chain."""
        backends = list(self._backends)

        for attempt in range(2):
            for bi, (client, model_name) in enumerate(backends):
                try:
                    response = client.chat.completions.create(
                        model=model_name,
                        messages=[
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": user_message},
                        ],
                        temperature=0.2,
                    )

                    if bi > 0:
                        self.client = client
                        self.model = model_name
                        print(f"  [FILE_HUNTER] Switched to backend #{bi+1}")

                    content = response.choices[0].message.content or ""
                    return _parse_output(content)

                except Exception as e:
                    err_str = str(e)
                    print(f"  [FILE_HUNTER] Backend #{bi+1} error: {err_str[:100]}")
                    continue  # try next backend immediately

            # All backends tried — retry outer loop
            wait = [5, 15][attempt]
            print(f"  [FILE_HUNTER] All backends failed (attempt {attempt+1}/2, waiting {wait}s)")
            if attempt < 2:
                time.sleep(wait)

        return {
            "vulnerable_files": [],
            "confidence": "low",
            "analysis_summary": "LLM call failed after 3 attempts",
        }

    def _debug_call_and_parse(self, messages, label: str = "") -> dict:
        """Temporary debug: call LLM and show raw response."""
        for bi, (client, model_name) in enumerate(self._backends[:]):
            try:
                response = client.chat.completions.create(
                    model=model_name,
                    messages=messages,
                    temperature=0.2,
                    max_tokens=4096,
                )
                content = response.choices[0].message.content or ""
                result = _parse_output(content)
                if not result.get("vulnerable_files"):
                    print(f"  [FH DEBUG {label}] backend={bi}, content[:500]: {content[:500]}")
                return result
            except Exception as e:
                print(f"  [FH DEBUG {label}] backend={bi} error: {e}")
                continue
        return {"vulnerable_files": [], "confidence": "low"}

    def close(self):
        pass


# ---------------------------------------------------------------------------
# Helpers (module-level for reuse)
# ---------------------------------------------------------------------------

def _parse_output(content: str) -> dict:
    """Parse JSON from LLM output."""
    json_match = re.search(r"```json\s*(.*?)\s*```", content, re.DOTALL)
    if not json_match:
        json_match = re.search(r"\{[\s\S]*\"vulnerable_files\"[\s\S]*\}", content)
        if json_match:
            json_str = json_match.group(0)
        else:
            return {
                "vulnerable_files": [],
                "confidence": "low",
                "analysis_summary": f"Failed to parse output",
            }
    else:
        json_str = json_match.group(1)

    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        return {
            "vulnerable_files": [],
            "confidence": "low",
            "analysis_summary": f"JSON parse error",
        }


def _format_issues(issues: List[dict]) -> str:
    if not issues:
        return ""
    lines = []
    for issue in issues[:5]:
        lines.append(f"#{issue.get('issue_number', '?')}: {issue.get('title', '')[:120]}")
        lines.append(f"  State: {issue.get('state', '?')}")
        commit = issue.get("commit_sha", "")
        if commit:
            lines.append(f"  Commit: {commit}")
        files = issue.get("changed_files", "")
        if isinstance(files, str):
            files = files.split(",") if files else []
        if files:
            lines.append(f"  Files: {', '.join(files[:10])}")
        lines.append("")
    return "\n".join(lines)


def _format_commits(examined: List[dict]) -> str:
    if not examined:
        return ""
    lines = []
    for detail in examined[:5]:
        lines.append(f"Commit {detail['sha'][:8]}: {detail['message'][:150]}")
        lines.append(f"  Author: {detail['author']}, Date: {detail['date']}")
        mf = detail.get("modified_files", [])
        if mf:
            lines.append(f"  Files: {', '.join(mf[:15])}")
        lines.append("")
    return "\n".join(lines)


def _get_function_context(
    repo_path: str,
    commit_files: List[str],
    hotspot_files: List[dict],
    max_files: int = 20,
) -> str:
    """Extract tree-sitter function signatures for candidate files.

    Priority: commit files first, then hotspot files.
    Cap at max_files. Returns formatted string for prompt injection.
    """
    from shared.tree_sitter_utils import extract_file_signature, EXT_TO_LANG

    # Merge and deduplicate candidate files
    candidate = list(dict.fromkeys(commit_files))
    for h in hotspot_files:
        fp = h.get("file_path", "") if isinstance(h, dict) else str(h)
        if fp and fp not in candidate:
            candidate.append(fp)

    if not candidate:
        return ""

    lines = []
    extracted = 0
    for fp in candidate:
        if extracted >= max_files:
            break
        full = os.path.join(repo_path, fp)
        if not os.path.isfile(full):
            continue
        sig = extract_file_signature(full)
        if not sig or not sig.functions:
            continue
        lines.append(f"\n--- {fp} ({sig.language}, {sig.line_count} lines, {len(sig.functions)} funcs) ---")
        for func in sig.functions[:30]:  # cap per file
            name = func.get("name", "?")
            params = func.get("params", "")
            start = func.get("start_line", "?")
            lines.append(f"  {name}({params}) @ L{start}")
        extracted += 1

    return "\n".join(lines) if lines else ""
