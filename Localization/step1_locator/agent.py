"""
Hybrid Agent — LLM-based vulnerability localization with fallback.

Single-pass mode (default):
  One LLM call with a 5-section prompt (Vulnerability Report, Directory
  Structure, Resolved Issues, Commit History, File Context).

Multi-turn fallback (triggered on low confidence or too few predictions):
  Up to 3 turns with 5 tools (view_code, search_code, examine_commit,
  search_issues, get_directory).

Output: JSON with vulnerable_files[], vulnerable_functions[],
        confidence, mode, analysis_summary, evidence fields.
"""

import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx
from openai import OpenAI

from step1_locator.retriever import Retriever
from shared.sink_db import detect_vuln_types
from shared.config import (
    OPENAI_DS_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL,
    DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL,
)


# ---------------------------------------------------------------------------
# LLM client
# ---------------------------------------------------------------------------

def _get_all_backends() -> List[Tuple[OpenAI, str]]:
    """Build all available LLM backends for runtime fallback.

    Priority: DEEPSEEK → DS_KEY.
    DeepSeek first because DS proxy may be rate-limited.
    Returns list of (client, model) tuples.
    """
    backends = []
    if DEEPSEEK_API_KEY:
        backends.append((
            OpenAI(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL, max_retries=2,
                   timeout=httpx.Timeout(300.0, connect=30.0, read=300.0)),
            DEEPSEEK_MODEL,
        ))
    if OPENAI_DS_API_KEY and OPENAI_BASE_URL:
        backends.append((
            OpenAI(api_key=OPENAI_DS_API_KEY, base_url=OPENAI_BASE_URL, max_retries=2,
                   timeout=httpx.Timeout(300.0, connect=30.0, read=300.0)),
            OPENAI_MODEL,
        ))
    if not backends:
        raise RuntimeError("No LLM API key configured. Check .env file.")
    return backends


def _get_llm() -> Tuple[OpenAI, str]:
    """Return first available backend (DS_KEY priority, for backward compat)."""
    return _get_all_backends()[0]


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a vulnerability localization expert. You receive:

1. A vulnerability report (CVE title + description)
2. Directory structure of the repository
3. Resolved issues from the project history with linked commits and changed files
4. Matching commit history (BM25 search over commit messages) with patches
5. File context — function signatures extracted via tree-sitter (no bodies)

Your task: identify the most likely vulnerable files and functions.

CRITICAL CONSTRAINT — FUNCTION NAMES:
- Every predicted function MUST be selected FROM the "FILE CONTEXT" section (Section 5).
  Section 5 lists function signatures extracted from the actual source code via tree-sitter.
- You MUST copy the exact function name as it appears in Section 5. Do not invent,
  paraphrase, or guess function names. If a name appears in commit patches or issue
  descriptions but NOT in Section 5, it may be outdated — prefer the Section 5 form.
- For each vulnerable_function, the "file" field MUST match the file path shown in
  Section 5 for that function.
- If Section 5 is empty or sparse, you may use function names from the "EXAMINED COMMIT
  PATCHES" section (Section 4), but mark confidence="low" for those predictions.

RANKING RULES:
- Files/functions appearing in MULTIPLE matching commit patches → highest (0.80-1.00)
- Files/functions in a single high-scoring commit patch → medium-high (0.55-0.79)
- Files whose function signatures match the vulnerability type → medium (0.30-0.54)
- Use the FULL 0.10-1.00 score range with clear differentiation
- TOP-3 predictions MUST have scores >= 0.70
- Prefer root-cause locations (input parsers, validators, deserializers) over symptom locations
- Each prediction MUST include an "evidence" object with matching_issues and/or matching_commits

OUTPUT — single JSON block inside ```json``` fences:
```json
{
  "vulnerable_files": [
    {"file": "path/to/file.c", "score": 0.85, "reason": "...",
     "evidence": {"matching_issues": [571], "matching_commits": ["abc1234"]}}
  ],
  "vulnerable_functions": [
    {"function": "func_name", "file": "path/to/file.c", "score": 0.80,
     "start_line": 42, "end_line": 95, "reason": "...",
     "evidence": {"matching_issues": [571]}}
  ],
  "confidence": "high",
  "analysis_summary": "Brief analysis of how evidence supports the localization"
}
```
Predict 10-20 files and 10-20 functions. Confidence: "high", "medium", or "low"."""


# ---------------------------------------------------------------------------
# Tool definitions (for multi-turn mode)
# ---------------------------------------------------------------------------

NO_KG_TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "view_code",
            "description": "Read source code lines from a file. Use to inspect specific functions or code sections.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file": {"type": "string", "description": "File path relative to repo root"},
                    "start": {"type": "integer", "description": "Start line number (1-based)"},
                    "end": {"type": "integer", "description": "End line number (1-based)"},
                },
                "required": ["file", "start", "end"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "Grep the repository for a pattern. Returns matching lines with file:line info.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regex or literal pattern to search for"},
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_directory",
            "description": "List files and subdirectories under a given path in the repository.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path relative to repo root (empty for root)"},
                },
                "required": ["path"],
            },
        },
    },
]

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "view_code",
            "description": "Read source code lines from a file. Use to inspect specific functions or code sections.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file": {"type": "string", "description": "File path relative to repo root"},
                    "start": {"type": "integer", "description": "Start line number (1-based)"},
                    "end": {"type": "integer", "description": "End line number (1-based)"},
                },
                "required": ["file", "start", "end"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "Grep the repository for a pattern. Returns matching lines with file:line info.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regex or literal pattern to search for"},
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "examine_commit",
            "description": "Get full patch and changed files for a specific commit SHA.",
            "parameters": {
                "type": "object",
                "properties": {
                    "sha": {"type": "string", "description": "Commit SHA (full or short)"},
                },
                "required": ["sha"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_issues",
            "description": "Search resolved issues by keyword. Returns matched issues with resolution commits and changed files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query (keywords)"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_directory",
            "description": "List files and subdirectories under a given path in the repository.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path relative to repo root (empty for root)"},
                },
                "required": ["path"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------

def build_no_kg_prompt(
    issue_description: str,
    language: str,
    directory_section: str,
    file_context: str,
) -> str:
    """Assemble prompt for no-KG ablation mode (3 sections, no issue/commit history)."""
    lang_line = f"Language: {language}" if language else ""
    vuln_types = detect_vuln_types(issue_description)
    vuln_line = f"Detected vulnerability types: {', '.join(vuln_types)}"

    return f"""Analyze this vulnerability report and identify the most likely vulnerable files and functions.

{lang_line}
{vuln_line}

---
SECTION 1: VULNERABILITY REPORT
---
{issue_description[:3000]}

---
SECTION 2: DIRECTORY STRUCTURE
---
{directory_section[:3000]}

---
SECTION 3: SOURCE FILE LIST (key files by relevance, no AST content)
---
{file_context[:4000] or "No file context available."}

---
Based on the vulnerability report, directory structure, and source file list, output your localization result as a JSON block inside ```json``` fences. Each prediction must include an "evidence" object (can note "code_analysis" for reasoning based on source inspection)."""


def build_single_pass_prompt(
    issue_description: str,
    language: str,
    directory_section: str,
    resolved_issues: str,
    commit_history: str,
    file_context: str,
    static_evidence: str = "",
) -> str:
    """Assemble the 6-section prompt for single-pass mode."""
    lang_line = f"Language: {language}" if language else ""
    vuln_types = detect_vuln_types(issue_description)
    vuln_line = f"Detected vulnerability types: {', '.join(vuln_types)}"

    static_block = ""
    if static_evidence:
        static_block = f"""
---
SECTION 6: STATIC ANALYSIS FINDINGS (CodeQL/ICFG)
---
{static_evidence[:1500]}
"""

    return f"""Analyze this vulnerability report and identify the most likely vulnerable files and functions.

{lang_line}
{vuln_line}

---
SECTION 1: VULNERABILITY REPORT
---
{issue_description[:3000]}

---
SECTION 2: DIRECTORY STRUCTURE
---
{directory_section[:3000]}

---
SECTION 3: RESOLVED ISSUES (issue → commit → changed files)
---
{resolved_issues[:3000] or "No resolved issues found."}

---
SECTION 4: COMMIT HISTORY (BM25 search over commit messages)
---
{commit_history[:4000] or "No matching commits found."}

---
SECTION 5: FILE CONTEXT (tree-sitter signatures)
---
{file_context[:4000] or "No file context available."}
{static_block}
---
Based on ALL sections above, output your localization result as a JSON block inside ```json``` fences.

REMEMBER: Every function name in vulnerable_functions MUST come from Section 5 (FILE CONTEXT). Copy the exact function name and file path shown there. Do not invent names."""


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class HybridAgent:
    """Hybrid LLM agent: single-pass + optional multi-turn fallback."""

    def __init__(self, retriever, repo_path: str = "", no_kg: bool = False):
        self.retriever = retriever
        self.repo_path = repo_path or retriever.repo_path
        self.no_kg = no_kg
        self._backends = _get_all_backends()
        self.client, self.model = self._backends[0]
        self.exploration_log: List[dict] = []
        self.max_multi_turns = 1  # reduced from 3 for batch speed

        # DEEPSEEK backend for multi-turn tool calling (DS proxy doesn't support tools)
        if DEEPSEEK_API_KEY:
            self.tool_client = OpenAI(
                api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL, max_retries=2,
                timeout=httpx.Timeout(300.0, connect=30.0, read=300.0))
            self.tool_model = DEEPSEEK_MODEL
        else:
            self.tool_client = self.client
            self.tool_model = self.model

    def localize(
        self,
        cve_id: str,
        issue_title: str,
        issue_body: str,
        language: str = "",
        before_date: str = "",
    ) -> dict:
        """Run localization: single-pass first, multi-turn fallback if needed.

        Returns result dict with vulnerable_files, vulnerable_functions, etc.
        """
        issue_description = f"Title: {issue_title}\n\nDescription:\n{issue_body}"

        # Assemble prompt sections
        from step1_locator.file_context import (
            get_context_section,
            get_directory_section,
            get_fast_file_list_section,
        )

        # Section 2: Directory structure (shared)
        directory_section = get_directory_section(self.repo_path, depth=3)

        if self.no_kg:
            # No-KG mode: fast file list (no tree-sitter), skip issues/commits/hotspots
            file_context = get_fast_file_list_section(self.repo_path, top_k=20)
            prompt = build_no_kg_prompt(
                issue_description, language,
                directory_section, file_context,
            )
            commit_hits = []
            examined_commits = []
            hotspot_files = []
            resolved = []
        else:
            # Section 3: Resolved issues
            resolved = self.retriever.search_issues(issue_description, top_k=5)
            resolved_section = self._format_issues_section(resolved)

            # Section 4: Commit history (BM25 + examine top patches)
            commit_hits = self.retriever.search_commit(
                issue_description, top_k=10, before_date=before_date
            )
            examined_commits = []
            all_mod_files: set = set()
            for hit in commit_hits[:5]:
                detail = self.retriever.examine_commit(hit["sha"])
                if detail:
                    examined_commits.append(detail)
                    for f in detail.get("modified_files", []):
                        all_mod_files.add(f)
            commit_section = self._format_commit_section(commit_hits, examined_commits)

            # Section 5: File context
            hotspot_files = self.retriever.get_hotspots(top_k=30)
            file_context = get_context_section(
                self.repo_path,
                list(all_mod_files),
                hotspot_files,
                top_k=20,
            )

            # Section 6: Static analysis evidence (CodeQL/ICFG)
            static_section = ""
            try:
                from step1_v2.static_evidence import load_static_evidence
                static_section = load_static_evidence(
                    cve_id, self.repo_path,
                    list(all_mod_files),
                    detect_vuln_types(issue_description),
                )
            except Exception:
                pass

            prompt = build_single_pass_prompt(
                issue_description, language,
                directory_section, resolved_section, commit_section, file_context,
                static_evidence=static_section,
            )

        result = self._call_llm(prompt)

        self.exploration_log.append({
            "mode": "single_pass",
            "commit_hits": len(commit_hits),
            "examined_commits": len(examined_commits),
            "hotspot_files": len(hotspot_files),
            "resolved_issues": len(resolved),
        })

        # Check if fallback needed
        if self._needs_fallback(result):
            result = self._multi_turn_fallback(
                issue_description, language, before_date, result
            )

        result["cve_id"] = cve_id
        return result

    # ------------------------------------------------------------------
    # Single-pass LLM call
    # ------------------------------------------------------------------

    def _call_llm(self, prompt: str, tools: Optional[List[dict]] = None) -> dict:
        """Call LLM with optional tools, return parsed JSON result.

        On auth/connection errors, tries next backend in fallback chain.
        """
        backends = list(self._backends)  # copy to rotate through
        for attempt in range(3):
            last_error = None
            for bi, (client, model_name) in enumerate(backends):
                try:
                    kwargs = dict(
                        model=model_name,
                        messages=[
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                        temperature=0.2,
                        max_tokens=4096,
                    )
                    if tools:
                        kwargs["tools"] = tools
                        kwargs["tool_choice"] = "auto"

                    response = client.chat.completions.create(**kwargs)

                    # Switch to this working backend for future calls
                    if bi > 0:
                        self.client = client
                        self.model = model_name
                        print(f"  [AGENT] Switched to backend #{bi+1}")

                    # Handle tool calls in response
                    msg = response.choices[0].message
                    if msg.tool_calls:
                        return {
                            "_tool_calls": [
                                {"id": tc.id, "name": tc.function.name,
                                 "arguments": json.loads(tc.function.arguments)}
                                for tc in msg.tool_calls
                            ],
                            "_content": msg.content or "",
                        }

                    content = msg.content or ""
                    if not content and attempt < 2:
                        kwargs["messages"][1]["content"] = kwargs["messages"][1]["content"][:6000]
                        continue
                    return self._parse_output(content)

                except Exception as e:
                    last_error = e
                    err_str = str(e)
                    # On auth/subscription errors, try next backend immediately
                    if "403" in err_str or "401" in err_str or "subscription" in err_str.lower():
                        print(f"  [AGENT] Backend #{bi+1} auth error, trying next ...")
                        continue
                    break  # Non-auth error, go to outer retry loop

            wait = [5, 15, 45][attempt]
            print(f"  [AGENT] LLM call failed (attempt {attempt+1}/3, waiting {wait}s): {last_error}")
            if attempt == 2:
                return {
                    "vulnerable_files": [], "vulnerable_functions": [],
                    "confidence": "low",
                    "analysis_summary": f"LLM call failed: {last_error}",
                }
            time.sleep(wait)

        return {"vulnerable_files": [], "vulnerable_functions": [], "confidence": "low"}

    # ------------------------------------------------------------------
    # Multi-turn fallback
    # ------------------------------------------------------------------

    def _needs_fallback(self, result: dict) -> bool:
        """Check if multi-turn fallback should be triggered."""
        if not isinstance(result, dict):
            return True
        files = result.get("vulnerable_files", [])
        confidence = result.get("confidence", "")

        if confidence == "low" and len(files) < 3:
            return True
        if len(files) < 2:
            return True
        if len(files) >= 3 and all(isinstance(f, dict) for f in files[:3]):
            top3_scores = [f.get("score", 0) for f in files[:3]]
            if len(top3_scores) >= 3:
                mean = sum(top3_scores) / 3
                variance = sum((s - mean) ** 2 for s in top3_scores) / 3
                if variance ** 0.5 < 0.15:
                    return True
        return False

    def _multi_turn_fallback(
        self, issue_description: str, language: str, before_date: str,
        initial_result: dict,
    ) -> dict:
        """Run multi-turn tool-calling loop (max 3 turns)."""
        print("  [AGENT] Triggering multi-turn fallback ...")

        tools = NO_KG_TOOL_DEFINITIONS if self.no_kg else TOOL_DEFINITIONS

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"VULNERABILITY REPORT:\n{issue_description[:3000]}\n\nLanguage: {language}\n\nLocate the vulnerable files and functions. Use the provided tools to explore the repository."},
        ]

        for turn in range(self.max_multi_turns):
            try:
                response = self.tool_client.chat.completions.create(
                    model=self.tool_model,
                    messages=messages,
                    tools=tools,
                    tool_choice="auto",
                    temperature=0.2,
                    max_tokens=4096,
                )
            except Exception as e:
                print(f"  [AGENT] Multi-turn call failed: {e}")
                break

            msg = response.choices[0].message

            if not msg.tool_calls:
                # No more tools — parse final output
                content = msg.content or ""
                if content.strip():
                    result = self._parse_output(content)
                    result["mode"] = f"multi_turn_{turn+1}"
                    self.exploration_log.append({"mode": result["mode"]})
                    return result
                # Empty response — skip this turn
                continue

            # Execute tool calls (max 2 per turn)
            tool_results = []
            if not msg.tool_calls:
                continue
            for tc in msg.tool_calls[:2]:
                result_str = self._execute_tool(
                    tc.function.name,
                    json.loads(tc.function.arguments),
                )
                tool_results.append({
                    "tool_call_id": tc.id,
                    "role": "tool",
                    "content": result_str[:2000],
                })

            messages.append(msg)
            messages.extend(tool_results)

        # Fallback: use initial single-pass result if it has predictions
        if isinstance(initial_result, dict) and (
            initial_result.get("vulnerable_files") or initial_result.get("vulnerable_functions")
        ):
            initial_result["mode"] = f"multi_turn_{self.max_multi_turns}_fallback_kept_initial"
            return initial_result
        initial_result["mode"] = f"multi_turn_{self.max_multi_turns}_fallback"
        return initial_result

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    def _execute_tool(self, name: str, args: dict) -> str:
        """Execute a tool and return result string."""
        if name == "view_code":
            return self._tool_view_code(
                args.get("file", ""), args.get("start", 0), args.get("end", 0))
        elif name == "search_code":
            return self._tool_search_code(args.get("pattern", ""))
        elif name == "examine_commit":
            if self.no_kg:
                return "Not available in no-KG mode"
            return self._tool_examine_commit(args.get("sha", ""))
        elif name == "search_issues":
            if self.no_kg:
                return "Not available in no-KG mode"
            return self._tool_search_issues(args.get("query", ""))
        elif name == "get_directory":
            return self._tool_get_directory(args.get("path", ""))
        else:
            return f"Unknown tool: {name}"

    def _tool_view_code(self, file: str, start: int, end: int) -> str:
        if not os.path.isdir(self.repo_path):
            return "Repository not available"
        full = os.path.join(self.repo_path, file)
        if not os.path.isfile(full):
            return f"File not found: {file}"
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            start = max(1, start)
            end = min(len(lines), end) if end > 0 else min(start + 50, len(lines))
            snippet = "".join(lines[start-1:end])
            return f"```{file} L{start}-L{end}\n{snippet[:3000]}\n```"
        except Exception as e:
            return f"Error reading {file}: {e}"

    def _tool_search_code(self, pattern: str) -> str:
        if not pattern:
            return "No pattern provided"
        try:
            import subprocess
            result = subprocess.run(
                ["grep", "-rn", "--include=*.c", "--include=*.cpp", "--include=*.h",
                 "--include=*.py", "--include=*.js", "--include=*.java", "--include=*.go",
                 "-m", "20", pattern, self.repo_path],
                capture_output=True, text=True, timeout=30,
            )
            output = result.stdout.strip()[:3000]
            return output if output else f"No matches for '{pattern}'"
        except Exception as e:
            return f"Search error: {e}"

    def _tool_examine_commit(self, sha: str) -> str:
        detail = self.retriever.examine_commit(sha) if sha else None
        if not detail:
            return f"Commit not found: {sha}"
        patch = detail.get("patch", "")
        if len(patch) > 3000:
            patch = patch[:3000] + "\n... [truncated]"
        return (
            f"Commit {detail['sha'][:8]} | {detail['date']} | {detail['message'][:120]}\n"
            f"Modified: {', '.join(detail.get('modified_files', [])[:20])}\n\n"
            f"Patch:\n{patch}"
        )

    def _tool_search_issues(self, query: str) -> str:
        issues = self.retriever.search_issues(query, top_k=5)
        if not issues:
            return "No matching issues found"
        lines = []
        for i, iss in enumerate(issues):
            lines.append(
                f"#{iss['issue_number']}: {iss.get('title', '')}"
                f" | commit={iss.get('commit_sha', '')[:8]}"
                f" | changed_files={iss.get('changed_files', '')[:200]}"
            )
        return "\n".join(lines)

    def _tool_get_directory(self, path: str) -> str:
        return self.retriever.list_directory(path, depth=2)

    # ------------------------------------------------------------------
    # Formatting helpers
    # ------------------------------------------------------------------

    def _format_issues_section(self, resolved: List[dict]) -> str:
        if not resolved:
            return "No resolved issues found."
        lines = []
        for iss in resolved:
            lines.append(
                f"  #{iss['issue_number']}: {iss.get('title', '')[:120]}\n"
                f"    State: {iss.get('state', '?')} | "
                f"Commit: {iss.get('commit_sha', '')[:8]}\n"
                f"    Changed files: {iss.get('changed_files', '')[:300]}\n"
                f"    Changed functions: {iss.get('changed_functions', '')[:200]}"
            )
        return "RESOLVED ISSUES (issue → commit → changed files):\n" + "\n".join(lines)

    def _format_commit_section(
        self, hits: List[dict], examined: List[dict]
    ) -> str:
        lines = []

        # BM25 search results
        lines.append("BM25 SEARCH RESULTS:")
        for i, hit in enumerate(hits[:10], 1):
            lines.append(
                f"  {i}. [{hit['score']:.4f}] {hit['sha'][:8]} | {hit['date']} | "
                f"{hit['message'][:120]}"
            )
            if hit.get("linked_issues"):
                lines.append(f"     Linked: {hit['linked_issues']}")

        # Examined patches
        lines.append("\nEXAMINED COMMIT PATCHES (top-3):")
        for ec in examined[:3]:
            patch = ec.get("patch", "")
            if len(patch) > 3000:
                patch = patch[:3000] + "\n... [truncated]"
            lines.append(
                f"\n  Commit {ec['sha'][:8]} | {ec['date']} | {ec['message'][:100]}\n"
                f"  Modified: {', '.join(ec.get('modified_files', [])[:15])}\n"
                f"  Patch:\n{patch}"
            )

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def _parse_output(self, content: str) -> dict:
        """Extract JSON from LLM output with json_repair fallback."""
        from json_repair import repair_json

        candidates = []
        m = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', content, re.DOTALL)
        if m:
            candidates.append(m.group(1))
        start = content.find('{')
        end = content.rfind('}')
        if start >= 0 and end > start:
            candidates.append(content[start:end + 1])

        for text in candidates:
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return parsed
                # LLM returned a JSON array instead of object; treat as unparseable
            except json.JSONDecodeError:
                try:
                    repaired = repair_json(text)
                    parsed = json.loads(repaired)
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    pass

        print(f"  [AGENT] Could not parse JSON ({len(content)} chars)")
        return {
            "vulnerable_files": [],
            "vulnerable_functions": [],
            "confidence": "low",
            "analysis_summary": "Failed to parse agent output",
        }

    def close(self):
        self.exploration_log.clear()
