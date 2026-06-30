"""
Phase 1: LLM Entry Discovery.

Expands step1 entry functions by searching the codebase for CVE-report keywords.
Uses SearchBackend tools — the LLM reads the report, extracts keywords, searches,
and identifies additional entry points that step1 may have missed.
"""

import json
import os
import re
import sys
from typing import Dict, List, Optional

_LOC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _LOC_DIR not in sys.path:
    sys.path.insert(0, _LOC_DIR)

from acr_baseline.model import ModelClient


SYSTEM_PROMPT = """You are a vulnerability localization expert. Given a CVE report and access to code search tools, identify entry-point functions where the exploit chain begins.

AVAILABLE TOOLS:
- search_code(query): Search for code patterns in the codebase
- search_method(name): Find a function by name
- read_file(path): Read file content

STRATEGY:
1. Extract key terms from the CVE report: function names, API calls, file paths, error strings
2. Search for each term using search_code() and search_method()
3. Read discovered files with read_file()
4. Identify the specific entry-point functions where attacker input enters the system

OUTPUT — JSON inside ```json``` fences:
```json
{
  "entry_functions": [
    {"function": "exact_name", "file": "path/to/file.c", "reason": "Receives network input on port 8080..."}
  ],
  "keywords_used": ["keyword1", "keyword2"]
}
```

Discover 3-8 entry functions. Function names MUST be exact from search results."""


def _execute_tool(backend, func_name, arg):
    """Execute a single tool call."""
    try:
        if func_name == 'search_code':
            r, _, ok = backend.search_code(arg)
        elif func_name == 'search_method':
            r, _, ok = backend.search_method(arg)
        elif func_name == 'read_file':
            r, _, ok = backend.get_file_content(arg)
        else:
            return "", False
        return r[:1500] if ok else f"Not found: {arg}", ok
    except Exception as e:
        return f"Error: {e}", False


def discover_entries(
    cve_id: str,
    issue_description: str,
    step1_functions: List[dict],
    repo_path: str,
    max_rounds: int = 3,
) -> List[dict]:
    """Discover entry functions via LLM + SearchBackend.

    Args:
        cve_id: CVE identifier
        issue_description: Full CVE report
        step1_functions: [{'function': str, 'file': str, 'score': float}, ...]
        repo_path: Repository path
        max_rounds: Max exploration rounds

    Returns:
        Expanded list of entry functions (step1 ∪ discovered).
        Each entry: {'function': str, 'file': str, 'score': float, 'reason': str}
    """
    from acr_baseline.search_backend import SearchBackend

    backend = SearchBackend(repo_path)
    if not backend.parsed_files:
        return step1_functions

    llm = ModelClient()

    # Build step1 context
    step1_lines = []
    for i, f in enumerate(step1_functions[:10]):
        step1_lines.append(
            f"  {i+1}. [{f.get('score', 0):.2f}] {f.get('function', '?')} @ {f.get('file', '?')}"
        )
    step1_text = "\n".join(step1_lines) if step1_lines else "None"

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"""VULNERABILITY REPORT:
{issue_description[:2500]}

STEP1 LOCALIZATION RESULTS (pre-identified functions):
{step1_text}

Based on the vulnerability report, search the codebase to find ALL entry-point functions where the exploit chain could begin. Consider functions mentioned in the report (API endpoints, network handlers, input parsers) that step1 may have missed.

Start by extracting keywords from the report and searching for them."""},
    ]

    discovered = []

    for _ in range(max_rounds):
        response = llm.call(messages, temperature=0.0)
        messages.append({"role": "assistant", "content": response})

        # Check for final JSON
        json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', response)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                entries = data.get('entry_functions', [])
                if entries:
                    discovered = entries
                    break
            except json.JSONDecodeError:
                pass

        # Parse and execute tool calls
        tool_pattern = r'<(search_code|search_method|read_file)[^>]*>([^<]+)</\1>'
        xml_calls = re.findall(tool_pattern, response)

        func_pattern = r'(search_code|search_method|read_file)\s*\(\s*["\']([^"\']+)["\']\s*\)'
        func_calls = re.findall(func_pattern, response)

        all_calls = list(set(xml_calls + func_calls))

        if not all_calls:
            messages.append({"role": "user", "content": "Please use the available tools to search the codebase. Output entry functions as JSON inside ```json``` fences."})
            continue

        tool_results = []
        for func_name, arg in all_calls[:5]:
            result_str, ok = _execute_tool(backend, func_name, arg)
            tag = "OK" if ok else "NF"
            tool_results.append(f"[{tag}] {func_name}('{arg}'):\n{result_str}")

        messages.append({"role": "user", "content": "Tool results:\n\n" + "\n\n".join(tool_results) + "\n\nContinue exploring or output the entry functions as JSON."})

    # Merge: step1 functions first, then discovered (deduplicated)
    seen = set()
    merged = []
    for f in step1_functions:
        key = (f.get('file', ''), f.get('function', ''))
        if key not in seen:
            seen.add(key)
            merged.append(f)

    for d in discovered:
        key = (d.get('file', ''), d.get('function', ''))
        if key not in seen:
            seen.add(key)
            merged.append({
                'function': d.get('function', ''),
                'file': d.get('file', ''),
                'score': 0.7,
                'reason': d.get('reason', 'LLM-discovered entry point'),
            })

    return merged[:15] if merged else step1_functions
