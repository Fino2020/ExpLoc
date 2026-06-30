"""
LLM+Tool Exploit Tracer — multi-round LLM agent for exploit chain generation.

Replaces archetype-based slot search with LLM-driven code exploration.
Uses SearchBackend tools to freely search, read, and trace code.

Does NOT modify existing step2_explainer modules — standalone addition.
"""

import json
import os
import re
import sys
import time
from typing import Dict, List, Optional

_LOC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _LOC_DIR not in sys.path:
    sys.path.insert(0, _LOC_DIR)

from acr_baseline.search_backend import SearchBackend
from acr_baseline.model import ModelClient
from step2_explainer.code_extractor import extract_code_snippets

SYSTEM_PROMPT = """You are a vulnerability exploitation expert. Given a CVE report and access to repository search tools, trace the complete exploit chain from entry point to sink.

AVAILABLE TOOLS:
- search_code(query: str): Search for code patterns in the entire codebase
- search_method(name: str): Find a function/method by name
- search_class(name: str): Find a class by name
- read_file(path: str): Read first 100 lines of a file
- get_code_around(path: str, line: int): Get code context around a line

EXPLOIT CHAIN FORMAT (output inside ```json``` fences when done):
```json
{
  "exploit_chains": [
    {
      "entry": {"function": "main", "file": "src/main.c"},
      "sink": {"function": "strcpy", "file": "src/util.c", "vuln_type": "buffer-overflow"},
      "function_path": {
        "entry_function": "main",
        "entry_file": "src/main.c",
        "edges": [
          {"from_func": "main", "to_func": "parse_input", "edge_type": "call", "slot": "Source"},
          {"from_func": "parse_input", "to_func": "copy_data", "edge_type": "call", "slot": "Propagation"},
          {"from_func": "copy_data", "to_func": "strcpy", "edge_type": "call", "slot": "Sink"}
        ]
      },
      "vulnerability_type": "buffer-overflow",
      "nl_summary": "User input enters through main, flows to parse_input without validation, reaches strcpy in copy_data causing buffer overflow."
    }
  ]
}
```

STRATEGY:
1. Extract key terms from the CVE report (function names, API calls, file paths, error messages)
2. Search for those terms using search_code() and search_method()
3. Read candidate files with read_file()
4. Get context around discovered functions with get_code_around()
5. Follow the data flow from entry → intermediate calls → sink
6. Identify WHERE validation is missing and HOW the vulnerability triggers
7. Output the complete exploit chain as JSON
"""

SELECT_PROMPT = """Based on the vulnerability report and the list of candidate vulnerable functions below, explore the codebase to trace the exploit path.

Start by searching for the candidate functions, reading their code, and identifying what they call.
Output your tool calls (one per line) or your final exploit chain JSON.

SEARCH STRATEGY:
1. First: read_file() on files containing candidate vulnerable functions
2. Then: search_code() for key terms from the vulnerability report
3. Then: search_method() for specific callee functions you discover
4. Finally: get_code_around() to verify line numbers"""


def _parse_tool_call(text: str) -> List[tuple]:
    """Parse tool calls from LLM response — both function-style and XML-style."""
    calls = []
    # Format 1: search_code("query"), read_file("path")
    pattern1 = r'(search_code|search_method|search_class|read_file|get_code_around)\s*\(\s*["\']([^"\']+)["\'](?:\s*,\s*(\d+))?\s*\)'
    calls.extend(re.findall(pattern1, text))
    # Format 2: <search_code>query</search_code>, <read_file path="...">, <get_code_around line="N">path</get_code_around>
    xml_patterns = [
        (r'<search_code>([^<]+)</search_code>', 'search_code'),
        (r'<search_code\s+query\s*=\s*["\']([^"\']+)["\']\s*/?>', 'search_code'),
        (r'<search_method>([^<]+)</search_method>', 'search_method'),
        (r'<search_method\s+name\s*=\s*["\']([^"\']+)["\']\s*/?>', 'search_method'),
        (r'<search_class>([^<]+)</search_class>', 'search_class'),
        (r'<read_file\s+path\s*=\s*["\']([^"\']+)["\']\s*/?>', 'read_file'),
        (r'<read_file>([^<]+)</read_file>', 'read_file'),
        (r'<get_code_around\s+path\s*=\s*["\']([^"\']+)["\']\s+line\s*=\s*["\']?(\d+)["\']?\s*/?>', 'get_code_around'),
        (r'<get_code_around\s+line\s*=\s*["\']?(\d+)["\']?\s+path\s*=\s*["\']([^"\']+)["\']\s*/?>', 'get_code_around'),
    ]
    for pattern, func_name in xml_patterns:
        for m in re.finditer(pattern, text):
            groups = m.groups()
            args = [func_name, groups[0]]
            if len(groups) >= 2 and groups[1] and groups[1].isdigit():
                args.append(groups[1])
            elif func_name == 'get_code_around' and len(groups) >= 2:
                # For get_code_around(line=N, path=...), arg order is (path, line)
                if 'line' in pattern and groups[0].isdigit():
                    args = [func_name, groups[1], groups[0]]
            calls.append(tuple(args))
    # Deduplicate
    seen = set()
    unique = []
    for c in calls:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def _execute_tools(backend: SearchBackend, calls: List[tuple]) -> str:
    """Execute tool calls and return formatted results."""
    results = []
    for func_name, arg1, arg2 in calls[:5]:
        try:
            if func_name == 'search_code':
                r, _, ok = backend.search_code(arg1)
            elif func_name == 'search_method':
                r, _, ok = backend.search_method(arg1)
            elif func_name == 'search_class':
                r, _, ok = backend.search_class(arg1)
            elif func_name == 'read_file':
                r, _, ok = backend.get_file_content(arg1)
            elif func_name == 'get_code_around':
                line = int(arg2) if arg2 else 1
                r, _, ok = backend.get_code_around_line(arg1, line)
            else:
                continue
            status = "OK" if ok else "NOT FOUND"
            results.append(f"[{status}] {func_name}('{arg1}'{', ' + arg2 if arg2 else ''}):\n{r[:1500]}")
        except Exception as e:
            results.append(f"[ERROR] {func_name}('{arg1}'): {e}")
    return "\n\n".join(results)


def trace_exploit_chain(
    cve_id: str,
    issue_description: str,
    language: str,
    top_functions: List[dict],
    repo_path: str,
    max_rounds: int = 5,
) -> Optional[dict]:
    """Generate exploit chain via LLM + SearchBackend exploration.

    Args:
        cve_id: CVE identifier
        issue_description: Full CVE report text
        language: Programming language
        top_functions: [{'function': str, 'file': str, 'score': float}, ...] from step1
        repo_path: Path to repository root
        max_rounds: Maximum exploration rounds

    Returns:
        dict with explanations[] compatible with step2 output format,
        or None on failure.
    """
    t_start = time.time()

    backend = SearchBackend(repo_path)
    if not backend.parsed_files:
        return None

    llm = ModelClient()

    # Build function list for prompt
    func_lines = []
    for i, f in enumerate(top_functions[:5]):
        fn = f.get('function', '?')
        fp = f.get('file', '?')
        sc = f.get('score', 0)
        func_lines.append(f"  {i+1}. [{sc:.2f}] {fn} @ {fp}")
    func_list = "\n".join(func_lines)

    # Round 0: Initial exploration prompt
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"""VULNERABILITY REPORT:
{issue_description[:2500]}

CANDIDATE VULNERABLE FUNCTIONS (from step1 localization):
{func_list}

{SELECT_PROMPT}"""},
    ]

    exploit_chains = []
    all_tool_results = ""

    for round_no in range(max_rounds):
        response = llm.call(messages, temperature=0.0)
        messages.append({"role": "assistant", "content": response})

        # Check for final JSON output
        json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', response)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                chains = data.get('exploit_chains', [])
                if chains:
                    exploit_chains = chains
                    break
            except json.JSONDecodeError:
                pass

        # Parse and execute tool calls
        calls = _parse_tool_call(response)
        if not calls:
            # No tools and no JSON — prompt for action
            messages.append({"role": "user", "content": "Please use the available tools to explore the codebase (search_code, search_method, read_file, get_code_around). Then output the exploit chain as JSON inside ```json``` fences."})
            continue

        tool_results = _execute_tools(backend, calls)
        all_tool_results += tool_results + "\n\n"
        messages.append({"role": "user", "content": f"Tool Results:\n\n{tool_results}\n\nContinue exploring or output the final exploit chain."})

    # Force final JSON if needed
    if not exploit_chains:
        messages.append({"role": "user", "content": "Based on all your exploration above, output the complete exploit chain as JSON inside ```json``` fences. Include entry, sink, and function_path with edges."})
        final = llm.call(messages, temperature=0.0)
        json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', final)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                exploit_chains = data.get('exploit_chains', [])
            except json.JSONDecodeError:
                pass

    elapsed = time.time() - t_start

    if not exploit_chains:
        return None

    # Format as step2-compatible output
    explanations = []
    for i, chain in enumerate(exploit_chains):
        entry = chain.get('entry', {})
        sink = chain.get('sink', {})
        fp = chain.get('function_path', {})

        # Build path_chain from function_path edges
        path_chain = []
        for edge in fp.get('edges', []):
            path_chain.append({
                "from": edge.get('from_func', ''),
                "to": edge.get('to_func', ''),
                "edge_type": edge.get('edge_type', 'call'),
                "prob": 1.0,
                "slot": edge.get('slot', ''),
            })

        # Build nodes for code snippet extraction
        nodes = []
        entry_fn = fp.get('entry_function', entry.get('function', ''))
        entry_file = fp.get('entry_file', entry.get('file', ''))
        if entry_file and entry_fn:
            nodes.append(f"{entry_file}:func:0")
        for edge in path_chain:
            to_fn = edge.get('to', '')
            nodes.append(f"{entry_file}:func:0")

        # Extract code snippets
        snippets = {}
        try:
            snippets = extract_code_snippets(
                repo_path=repo_path,
                path_chain=path_chain,
                nodes=nodes,
                entry_function=entry_fn,
                sink_function=sink.get('function', ''),
            )
        except Exception:
            pass

        explanations.append({
            "function_rank": i + 1,
            "entry_function": entry_fn,
            "entry_file": entry_file,
            "entry_line": entry.get('line', 0),
            "archetype": "LLMTrace",
            "archetype_display": "LLM+Tool Trace",
            "filled_slots": {},
            "slot_count": len(fp.get('edges', [])),
            "required_slots": [],
            "sink": sink.get('function', ''),
            "terminated_at_sink": bool(sink.get('function')),
            "termination_reason": "llm_trace_complete",
            "confidence": 0.85,
            "path_chain": path_chain,
            "nodes": nodes,
            "code_snippets": snippets,
            "cumulative_score": len(fp.get('edges', [])),
            "nl_summary": chain.get('nl_summary', ''),
        })

    return {
        "cve_id": cve_id,
        "step2_mode": "llm_trace",
        "archetype": "LLMTrace",
        "icfg_source": "llm_trace",
        "icfg_path": "",
        "icfg_stats": {"nodes": len(backend.parsed_files), "edges": 0},
        "explanations": explanations,
        "trace_statistics": {
            "num_traced": len(explanations),
            "num_archetype_complete": sum(1 for e in explanations if e.get('terminated_at_sink')),
        },
        "selection_reason": "llm_trace",
    }
