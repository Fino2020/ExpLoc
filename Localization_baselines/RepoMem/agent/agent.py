"""
LLM Agent for RepoMem — Memory-Augmented Vulnerability Localization.

Implements the RepoMem paper (ICLR 2026) approach:
  - Agent uses 3 memory tools: SearchCommit, ExamineCommit, ViewSummary
  - Pre-retrieval from per-project RMS (commit history)
  - LLM synthesizes evidence into ranked file/function predictions

Uses pre-retrieval + prompt injection for compatibility with models that
do not support function calling.
"""

import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx
from openai import OpenAI

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mem_retrieval.rms_retriever import RMSRetriever


# ---------------------------------------------------------------------------
# LLM client
# ---------------------------------------------------------------------------

def _get_llm_client_and_model() -> Tuple[OpenAI, str]:
    """Build LLM client using the fallback chain."""
    from dotenv import load_dotenv

    env_dir = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        candidate = os.path.join(env_dir, ".env")
        if os.path.exists(candidate):
            load_dotenv(candidate)
            break
        env_dir = os.path.dirname(env_dir)

    # Agent needs tool-calling support — use DEEPSEEK_API_KEY (direct API) first.
    # OPENAI_DS_API_KEY proxy may not support function calling.

    ds_api_key = os.getenv("DEEPSEEK_API_KEY", "")
    if ds_api_key:
        return (
            OpenAI(api_key=ds_api_key,
                   base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
                   max_retries=2,
                   timeout=httpx.Timeout(300.0, connect=30.0, read=300.0)),
            os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash"),
        )

    base_url = os.getenv("OPENAI_BASE_URL", "")
    model = os.getenv("OPENAI_MODEL", "deepseek-v4-flash")
    ds_key = os.getenv("OPENAI_DS_API_KEY", "") or os.getenv("OPENAI_DEFAULT_KEY", "")
    if ds_key and base_url:
        return (
            OpenAI(api_key=ds_key, base_url=base_url, max_retries=2,
                   timeout=httpx.Timeout(300.0, connect=30.0, read=300.0)),
            model,
        )

    first_url = os.getenv("USE_FIRST_URL", "")
    first_key = os.getenv("USE_FIRST_KEY", "")
    if first_key and first_url:
        return (
            OpenAI(api_key=first_key, base_url=first_url, max_retries=2,
                   timeout=httpx.Timeout(300.0, connect=30.0, read=300.0)),
            model,
        )

    raise RuntimeError("No LLM API key configured. Check .env file.")


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a vulnerability localization expert using the RepoMem memory-augmented approach. You receive:

1. A vulnerability report (CVE title + description)
2. Repository Memory Context extracted from the project's commit history:
   - Matching commits (BM25 search over commit messages) with their patches
   - Hotspot files with LLM-generated functionality summaries
   - File edit frequency statistics

Your task: Identify the most likely vulnerable files and functions based on the commit history evidence and the vulnerability description.

RANKING RULES:
- Files/functions that appear in MULTIPLE matching commit patches → highest scores (0.80-1.00)
- Files/functions mentioned in a single high-scoring commit patch → medium-high (0.55-0.79)
- Hotspot files whose functionality summary matches the vulnerability type → medium (0.30-0.54)
- Use the FULL 0.10-1.00 score range with clear differentiation
- The TOP-3 predictions MUST have scores >= 0.70
- Prefer root-cause locations (input parsers, validators, deserializers) over symptom locations

OUTPUT — single JSON block inside ```json``` fences:
```json
{
  "vulnerable_files": [
    {"file": "path/to/file.c", "score": 0.85, "reason": "specific reason referencing commit evidence"}
  ],
  "vulnerable_functions": [
    {"function": "func_name", "file": "path/to/file.c", "score": 0.80, "reason": "specific reason referencing commit evidence"}
  ],
  "analysis_summary": "Brief analysis of the vulnerability and how commit history evidence supports the localization"
}
```
Predict 10-20 files and 10-20 functions. Each reason must reference specific commit SHA or file history evidence."""


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class RepoMemAgent:
    """Memory-augmented LLM Agent using per-project commit history.

    Uses pre-retrieval + prompt injection (not iterative tool calling)
    to be compatible with models that don't support function calling.
    """

    def __init__(self, rms: RMSRetriever):
        self.rms = rms
        self.client, self.model = _get_llm_client_and_model()
        self.exploration_log: List[dict] = []

    def analyze(
        self,
        issue_description: str,
        language: str = "",
        before_date: str = "",
    ) -> dict:
        """Run pre-retrieval + LLM analysis for a vulnerability.

        Args:
            issue_description: CVE title + body text
            language: programming language hint
            before_date: ISO date; only use commits before this date
                         (contamination filter per paper §3.1)

        Returns:
            dict with vulnerable_files, vulnerable_functions, analysis_summary
        """
        # Phase 1: Pre-retrieve memory context (simulates tool calls)
        memory_context = self._retrieve_memory_context(
            issue_description, language, before_date
        )

        self.exploration_log.append({
            "phase": "pre_retrieval",
            "search_hits": memory_context["search_hits"],
            "examined_commits": len(memory_context.get("examined_commits", [])),
            "hotspot_files": len(memory_context.get("hotspot_files", [])),
            "file_summaries": len(memory_context.get("file_summaries", {})),
        })

        # Phase 2: Build prompt with injected memory context
        prompt = self._build_augmented_prompt(
            issue_description, language, memory_context
        )

        # Phase 3: Call LLM (with retries)
        content = ""
        for attempt in range(3):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.2,
                    max_tokens=4096,
                )
                content = response.choices[0].message.content or ""
                break
            except Exception as e:
                print(f"  [AGENT] LLM call failed (attempt {attempt+1}/3): {e}")
                if attempt == 2:
                    self.exploration_log.append({"error": str(e)})
                    return {
                        "vulnerable_files": [],
                        "vulnerable_functions": [],
                        "analysis_summary": f"LLM call failed: {e}",
                    }
                time.sleep(2)

        self.exploration_log.append({
            "phase": "llm_response",
            "content_length": len(content),
        })

        if not content.strip():
            return {
                "vulnerable_files": [],
                "vulnerable_functions": [],
                "analysis_summary": "Empty LLM response",
            }

        return self._parse_output(content)

    # ------------------------------------------------------------------
    # Memory retrieval (simulates SearchCommit → ExamineCommit → ViewSummary)
    # ------------------------------------------------------------------

    def _retrieve_memory_context(
        self, issue_description: str, language: str, before_date: str
    ) -> dict:
        """Pre-retrieve all memory context.

        Simulates: SearchCommit → ExamineCommit (top-k) → ViewSummary (hotspots).
        """
        # Step 1: SearchCommit — BM25 over commit messages
        search_hits = self.rms.search_commit(
            issue_description, top_k=10, before_date=before_date
        )

        # Step 2: ExamineCommit — get full patches for top hits
        examined_commits = []
        all_mod_files: set = set()
        for hit in search_hits[:5]:
            detail = self.rms.examine_commit(hit["sha"])
            if detail:
                examined_commits.append(detail)
                for f in detail.get("modified_files", []):
                    all_mod_files.add(f)

        # Step 3: ViewSummary — get cached summaries for hotspot files
        # and for files that appeared in matching commits
        hotspot_files = self.rms.get_hotspots(top_k=30)
        all_summaries = self.rms.get_all_summaries()

        # Also try to get summaries for files from matching commits
        for fpath in list(all_mod_files)[:20]:
            if fpath not in all_summaries:
                summary = self.rms.view_summary(fpath)
                if summary:
                    all_summaries[fpath] = summary

        return {
            "search_hits": len(search_hits),
            "search_results": search_hits[:10],
            "examined_commits": examined_commits,
            "all_mod_files": sorted(all_mod_files)[:30],
            "hotspot_files": hotspot_files,
            "file_summaries": all_summaries,
        }

    # ------------------------------------------------------------------
    # Prompt building
    # ------------------------------------------------------------------

    def _build_augmented_prompt(
        self, issue_description: str, language: str, ctx: dict
    ) -> str:
        """Build the augmented prompt with injected commit history context."""

        # Section 1: Matching commits (SearchCommit results)
        search_lines = []
        for i, hit in enumerate(ctx.get("search_results", [])[:10], 1):
            search_lines.append(
                f"  {i}. [{hit['score']:.4f}] {hit['sha'][:8]} | {hit['date']} | "
                f"{hit['message'][:120]}"
            )
            if hit.get("linked_issues"):
                search_lines.append(f"     Linked: {hit['linked_issues']}")

        search_section = (
            "MATCHING COMMITS (BM25 search):\n" + "\n".join(search_lines)
            if search_lines
            else "MATCHING COMMITS: None found"
        )

        # Section 2: Examined commit patches (top-3, truncated)
        examined_lines = []
        for ec in ctx.get("examined_commits", [])[:3]:
            patch = ec.get("patch", "")
            if len(patch) > 3000:
                patch = patch[:3000] + "\n... [truncated]"
            examined_lines.append(
                f"  Commit {ec['sha'][:8]} | {ec['date']} | {ec['message'][:100]}\n"
                f"  Modified files: {', '.join(ec.get('modified_files', [])[:15])}\n"
                f"  Patch:\n{patch}\n"
            )

        examined_section = (
            "EXAMINED COMMIT PATCHES:\n" + "\n---\n".join(examined_lines)
            if examined_lines
            else "EXAMINED COMMIT PATCHES: None"
        )

        # Section 3: Hotspot files with summaries
        hotspot_lines = []
        for h in ctx.get("hotspot_files", [])[:15]:
            fpath = h.get("file_path", "")
            summary = ctx.get("file_summaries", {}).get(fpath, "")
            summary_str = f" — {summary[:120]}" if summary else ""
            hotspot_lines.append(
                f"  {fpath} (edits={h.get('edit_count', 0)}){summary_str}"
            )

        hotspot_section = (
            "HOTSPOT FILES (most edited in history):\n" + "\n".join(hotspot_lines)
            if hotspot_lines
            else "HOTSPOT FILES: None"
        )

        # Section 4: Files from matching commits with summaries
        mod_files_with_summaries = []
        for fpath in ctx.get("all_mod_files", [])[:15]:
            summary = ctx.get("file_summaries", {}).get(fpath, "")
            if summary:
                mod_files_with_summaries.append(f"  {fpath}: {summary[:150]}")

        mod_section = ""
        if mod_files_with_summaries:
            mod_section = (
                "FILES FROM MATCHING COMMITS (with summaries):\n"
                + "\n".join(mod_files_with_summaries)
            )

        lang_line = f"Language: {language}" if language else ""

        return f"""Analyze this vulnerability report and identify the most likely vulnerable files and functions.

{lang_line}

VULNERABILITY REPORT:
{issue_description[:3000]}

---
REPOSITORY MEMORY CONTEXT (from commit history):
---

{search_section}

{examined_section}

{hotspot_section}

{mod_section}

---
Based on the vulnerability report AND the commit history evidence above, output your localization result as a JSON block inside ```json``` fences. Reference specific commit SHAs or file history patterns in your reasons."""

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def _parse_output(self, content: str) -> dict:
        """Extract JSON from LLM output."""
        # Try ```json ... ``` block
        m = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', content, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass

        # Try raw JSON object
        try:
            start = content.find('{')
            end = content.rfind('}')
            if start >= 0 and end > start:
                return json.loads(content[start:end + 1])
        except json.JSONDecodeError:
            pass

        print(f"  [AGENT] Could not parse JSON ({len(content)} chars)")
        print(f"  [AGENT] First 200 chars: {content[:200]}")
        return {
            "vulnerable_files": [],
            "vulnerable_functions": [],
            "analysis_summary": "Failed to parse agent output",
        }
