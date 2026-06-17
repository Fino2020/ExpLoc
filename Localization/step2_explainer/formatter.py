"""
Formatter — three-layer explanation assembly.

Assembles output from path_tracer, code_extractor, and nl_explainer
into the Step 2 output format specified in the design doc.
"""

from typing import Dict, List


def format_explanation(
    trace_result: dict,
    nl_explanation: dict,
    evidence_from_step1: List[str],
    function_rank: int = 1,
) -> dict:
    """Format a single explanation into the spec output format.

    Args:
        trace_result: dict from PathTracer.trace() serialized
        nl_explanation: dict from nl_explainer.generate_explanation()
        evidence_from_step1: evidence strings from Step 1 localization
        function_rank: rank of this function among all traced functions

    Returns:
        Formatted explanation dict per the spec:
        {
          function_rank, entry_function, sink, terminated_at_sink,
          path_chain, code_snippets, nl_explanation, evidence_from_step1
        }
    """
    return {
        "function_rank": function_rank,
        "entry_function": trace_result.get("entry_function", ""),
        "sink": trace_result.get("sink", ""),
        "terminated_at_sink": trace_result.get("terminated_at_sink", False),
        "path_chain": trace_result.get("path_chain", []),
        "code_snippets": trace_result.get("code_snippets", []),
        "nl_explanation": nl_explanation.get("explanation", ""),
        "nl_summary": nl_explanation.get("summary", ""),
        "entry_description": nl_explanation.get("entry_description", ""),
        "sink_description": nl_explanation.get("sink_description", ""),
        "key_lines": nl_explanation.get("key_lines", []),
        "evidence_from_step1": evidence_from_step1[:10],
    }


def assemble_explanations(
    trace_results: List[dict],
    nl_explanations: List[dict],
    evidence_from_step1: List[str],
) -> List[dict]:
    """Assemble multiple explanations from parallel lists.

    Args:
        trace_results: list of serialized TraceResult dicts
        nl_explanations: list of NL explanation dicts
        evidence_from_step1: evidence strings from Step 1

    Returns:
        List of formatted explanation dicts.
    """
    explanations = []
    for i, (trace, nl) in enumerate(zip(trace_results, nl_explanations)):
        exp = format_explanation(
            trace_result=trace,
            nl_explanation=nl,
            evidence_from_step1=evidence_from_step1,
            function_rank=i + 1,
        )
        explanations.append(exp)
    return explanations


def format_step2_output(
    cve_id: str,
    explanations: List[dict],
    step1_evidence: List[str],
    trace_stats: dict,
) -> dict:
    """Produce the final Step 2 output JSON.

    Args:
        cve_id: CVE identifier
        explanations: list of formatted explanation dicts
        step1_evidence: evidence strings from Step 1
        trace_stats: dict with trace statistics (num_traced, num_sink_hit, etc.)

    Returns:
        Complete Step 2 result dict.
    """
    return {
        "cve_id": cve_id,
        "explanations": explanations,
        "evidence_from_step1": step1_evidence[:10],
        "trace_statistics": trace_stats,
    }
