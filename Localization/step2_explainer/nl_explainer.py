"""
NL Explainer — LLM natural language explanation generation.

Given a traced path with code snippets, generates:
  - One-sentence summary
  - Paragraph explaining data flow from entry to sink
  - References to specific code lines and vulnerability mechanism

Uses the same LLM backend as the Step 1 agent.
"""

import json
import re
import time
from typing import List, Tuple

import httpx
from openai import OpenAI

from shared.config import (
    OPENAI_DS_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL,
    DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL,
)


def _get_llm() -> Tuple[OpenAI, str]:
    """Build LLM client — fallback: DS_KEY → DEEPSEEK."""
    if OPENAI_DS_API_KEY and OPENAI_BASE_URL:
        return (
            OpenAI(api_key=OPENAI_DS_API_KEY, base_url=OPENAI_BASE_URL, max_retries=2,
                   timeout=httpx.Timeout(120.0, connect=30.0, read=120.0)),
            OPENAI_MODEL,
        )
    if DEEPSEEK_API_KEY:
        return (
            OpenAI(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL, max_retries=2,
                   timeout=httpx.Timeout(120.0, connect=30.0, read=120.0)),
            DEEPSEEK_MODEL,
        )
    raise RuntimeError("No LLM API key configured.")


EXPLAIN_PROMPT = """You are a vulnerability analysis expert. Explain how data flows from a vulnerability entry point to a dangerous sink function.

Given:
1. A traced path through the program's control flow graph
2. Code snippets for each node on the path
3. The vulnerability type
4. Evidence from the localization step (matching issues/commits)

Output a JSON block:
```json
{
  "summary": "One-sentence summary of the vulnerability flow",
  "explanation": "Detailed paragraph explaining how data flows from entry to sink, referencing specific code lines and the vulnerability mechanism. Include the CWE/mitigation if relevant.",
  "entry_description": "What the entry function does and how it receives untrusted data",
  "sink_description": "What the sink function does and why it's dangerous",
  "key_lines": ["file:line — brief note about critical operations"]
}
```"""


def generate_explanation(
    path_chain: List[dict],
    code_snippets: List[dict],
    vuln_type: str,
    evidence: List[str],
    entry_function: str = "",
    sink_function: str = "",
    terminated_at_sink: bool = False,
) -> dict:
    """Generate a natural language explanation for a traced path.

    Args:
        path_chain: list of {"from", "to", "edge_type", "prob"} dicts
        code_snippets: list of {"node", "role", "lines", "file", "function", ...}
        vuln_type: vulnerability type name (e.g., "command_injection")
        evidence: list of evidence strings from Step 1
        entry_function: name of the entry function
        sink_function: name of the sink function
        terminated_at_sink: whether the trace actually reached a sink

    Returns:
        dict with summary, explanation, entry_description, sink_description, key_lines
    """
    if not path_chain or not code_snippets:
        return {
            "summary": "Insufficient path data for explanation",
            "explanation": "",
            "entry_description": "",
            "sink_description": "",
            "key_lines": [],
        }

    # Build prompt context
    path_desc = _format_path_for_prompt(path_chain)
    code_desc = _format_snippets_for_prompt(code_snippets)
    evidence_str = "\n".join(f"- {e}" for e in evidence[:5]) if evidence else "None"

    prompt = f"""Vulnerability Type: {vuln_type}
Entry Function: {entry_function}
Sink Function: {sink_function or 'Not reached'}
Trace Terminated at Sink: {terminated_at_sink}

TRACED PATH:
{path_desc}

CODE SNIPPETS:
{code_desc}

EVIDENCE FROM LOCALIZATION:
{evidence_str}

Based on this information, explain the vulnerability flow from entry to sink."""

    client, model = _get_llm()

    for attempt in range(3):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": EXPLAIN_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=2048,
            )
            content = response.choices[0].message.content or ""
            return _parse_explanation(content)
        except Exception as e:
            print(f"  [NL] LLM call failed (attempt {attempt+1}/3): {e}")
            if attempt == 2:
                return {
                    "summary": f"LLM explanation failed: {e}",
                    "explanation": "",
                    "entry_description": "",
                    "sink_description": "",
                    "key_lines": [],
                }
            time.sleep(2)

    return {"summary": "Failed to generate explanation", "explanation": ""}


def generate_batch(
    trace_results: List[dict],
    issue_description: str,
    vuln_types: List[str],
    evidence: List[str],
) -> List[dict]:
    """Generate explanations for multiple traced paths.

    Args:
        trace_results: list of TraceResult dicts from path_tracer
        issue_description: CVE description
        vuln_types: detected vulnerability types
        evidence: evidence strings from Step 1

    Returns:
        List of explanation dicts, one per trace result.
    """
    vuln_type = vuln_types[0] if vuln_types else "unknown"
    explanations = []

    for i, trace in enumerate(trace_results):
        path_chain = trace.get("path_chain", [])
        code_snippets = trace.get("code_snippets", [])
        entry = trace.get("entry_function", "")
        sink = trace.get("sink", "")
        hit_sink = trace.get("terminated_at_sink", False)

        if not path_chain:
            explanations.append({
                "function_rank": i + 1,
                "entry_function": entry,
                "summary": "No path found — function has no outgoing edges in ICFG",
            })
            continue

        exp = generate_explanation(
            path_chain=path_chain,
            code_snippets=code_snippets,
            vuln_type=vuln_type,
            evidence=evidence,
            entry_function=entry,
            sink_function=sink,
            terminated_at_sink=hit_sink,
        )
        exp["function_rank"] = i + 1
        exp["entry_function"] = entry
        exp["sink"] = sink
        exp["terminated_at_sink"] = hit_sink
        explanations.append(exp)

    return explanations


def _format_path_for_prompt(path_chain: List[dict]) -> str:
    """Format path chain for LLM prompt."""
    lines = []
    for i, step in enumerate(path_chain):
        lines.append(
            f"  {i+1}. {step['from']} → {step['to']} "
            f"({step.get('edge_type', '?')}, prob={step.get('prob', 0):.3f})"
        )
    return "\n".join(lines) if lines else "No path steps"


def _format_snippets_for_prompt(code_snippets: List[dict]) -> str:
    """Format code snippets for LLM prompt."""
    lines = []
    for snip in code_snippets:
        role_tag = snip.get("role", "?").upper()
        lines.append(
            f"--- {role_tag}: {snip.get('function', '?')} "
            f"@ {snip.get('file', '?')} ---"
        )
        lines.append(snip.get("lines", "[No code]"))
        lines.append("")
    return "\n".join(lines) if lines else "No code snippets"


def _parse_explanation(content: str) -> dict:
    """Parse LLM JSON output."""
    m = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', content, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    try:
        start = content.find('{')
        end = content.rfind('}')
        if start >= 0 and end > start:
            return json.loads(content[start:end + 1])
    except json.JSONDecodeError:
        pass
    return {
        "summary": content[:200],
        "explanation": content,
        "entry_description": "",
        "sink_description": "",
        "key_lines": [],
    }
