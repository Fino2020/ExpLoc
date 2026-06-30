# Localization/step1_v2/pipeline.py
"""
Two-stage Step1 orchestrator: File Hunter → Function Pinpointer.

Connects Stage 1 (DeepSeek tool-calling file discovery) and Stage 2
(single-pass function localization) with error recovery at each stage.

Produces result.json in backward-compatible format (vulnerable_files[],
vulnerable_functions[] at top level).
"""

import json
import os
import sys
import time
from typing import Dict, List

_LOC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _LOC_DIR not in sys.path:
    sys.path.insert(0, _LOC_DIR)

from shared.config import OUTPUT_DIR


def run_step1_v2(
    cve_entry: dict,
    retriever,
    repo_path: str = "",
    two_stage: bool = False,
    use_iterative: bool = False,
) -> dict:
    """Run two-stage Step1 localization for a single CVE.

    Args:
        cve_entry: dict with cve_id, issue_title, issue_body, language,
                   issue_list (for before_date extraction)
        retriever: step1_locator.retriever.Retriever instance
        repo_path: path to repository root
        two_stage: if True, run FileHunter (files) + FuncPinpointer (functions).
                   Default False = unified single-pass.
        use_iterative: if True, use IterativeFileHunter instead of FileHunter.

    Returns:
        dict with vulnerable_files[], vulnerable_functions[], confidence,
        analysis_summary, mode="two_stage"/"unified_single_pass", stage1/stage2 metadata.
        Compatible with existing evaluate.py.
    """
    cve_id = cve_entry["cve_id"]
    issue_title = cve_entry.get("issue_title", "")
    issue_body = cve_entry.get("issue_body", "")
    language = cve_entry.get("language", "unknown")

    # Compute before_date from earliest issue
    before_date = _get_earliest_date(cve_entry)

    t_start = time.time()

    # ─── Iterative path: replace single-pass FileHunter ─────────────
    if use_iterative:
        print(f"  [V2] Stage 1: Iterative File Hunter ({cve_id}) ...")
        from step1_v2.file_hunter_v2 import IterativeFileHunter

        hunter = IterativeFileHunter(repo_path=repo_path)
        try:
            stage1_result = hunter.hunt(
                cve_id=cve_id,
                issue_title=issue_title,
                issue_body=issue_body,
                language=language,
                before_date=before_date,
                max_rounds=5,
                severity=cve_entry.get("severity", ""),
                cvss=str(cve_entry.get("baseScore", "")),
                cwe_ids=cve_entry.get("cwe_id", []),
            )
        finally:
            hunter.close()

        stage1_files = stage1_result.get("vulnerable_files", [])
        stage1_confidence = stage1_result.get("confidence", "low")
        stage1_turns = stage1_result.get("_rounds", 0)
        stage1_summary = stage1_result.get("analysis_summary", "")
        stage1_funcs = stage1_result.get("vulnerable_functions", [])

        # Skip the existing FileHunter block entirely — jump to ranking
        from step1_locator.ranker import rank_results

        ranked = rank_results(files=stage1_files, functions=stage1_funcs)
        ranked_files = ranked["vulnerable_files"]
        ranked_funcs = ranked["vulnerable_functions"]

        n_files = len(ranked_files)
        n_funcs = len(ranked_funcs)
        overall_confidence = stage1_confidence
        mode = "iterative_search"

        # Hybrid fallback: if iterative found 0 files, retry with unified FileHunter
        if n_files == 0:
            print(f"  [V2] Iterative found 0 files, falling back to unified FileHunter ...")
            mode = "iterative_fallback_unified"

            from step1_v2.file_hunter import FileHunter
            hunter2 = FileHunter(retriever, repo_path=repo_path)
            try:
                stage1_result = hunter2.hunt(
                    cve_id=cve_id,
                    issue_title=issue_title,
                    issue_body=issue_body,
                    language=language,
                    before_date=before_date,
                )
            finally:
                hunter2.close()

            fallback_files = stage1_result.get("vulnerable_files", [])
            fallback_funcs = stage1_result.get("vulnerable_functions", [])

            from step1_locator.ranker import rank_results
            ranked = rank_results(files=fallback_files, functions=fallback_funcs)
            ranked_files = ranked["vulnerable_files"]
            ranked_funcs = ranked["vulnerable_functions"]
            n_files = len(ranked_files)
            n_funcs = len(ranked_funcs)
            overall_confidence = stage1_result.get("confidence", "low")
            stage1_turns = stage1_result.get("_turns", 0)

        print(f"  [V2] Stage 1 done ({mode}): {n_files} files (confidence={overall_confidence})")
    else:
        # ─── Stage 1: File Hunter ───────────────────────────────────────
        print(f"  [V2] Stage 1: File Hunter ({cve_id}) ...")

        from step1_v2.file_hunter import FileHunter

        hunter = FileHunter(retriever, repo_path=repo_path)
        try:
            stage1_result = hunter.hunt(
                cve_id=cve_id,
                issue_title=issue_title,
                issue_body=issue_body,
                language=language,
                before_date=before_date,
            )
        finally:
            hunter.close()

        stage1_files = stage1_result.get("vulnerable_files", [])
        stage1_confidence = stage1_result.get("confidence", "low")
        stage1_turns = stage1_result.get("_turns", 0)
        stage1_summary = stage1_result.get("analysis_summary", "")

        # Fallback: if Stage 1 returns too few files, retry without static evidence
        if len(stage1_files) < 3:
            print(f"  [V2] Stage 1 returned only {len(stage1_files)} files, retrying without static evidence ...")
            # Retry with empty static evidence (force wider search)
            # Monkey-patch the static evidence call to return empty
            from step1_v2.static_evidence import load_static_evidence as _orig_load
            import step1_v2.static_evidence as se
            se.load_static_evidence = lambda *a, **kw: ""

            hunter2 = FileHunter(retriever, repo_path=repo_path)
            try:
                stage1_result = hunter2.hunt(
                    cve_id=cve_id,
                    issue_title=issue_title,
                    issue_body=issue_body,
                    language=language,
                    before_date=before_date,
                )
            finally:
                hunter2.close()

            # Restore original
            se.load_static_evidence = _orig_load

            stage1_files = stage1_result.get("vulnerable_files", [])
            stage1_confidence = stage1_result.get("confidence", "low")
            stage1_turns = stage1_result.get("_turns", 0)
            stage1_summary = stage1_result.get("analysis_summary", "")

        # Normalize and rank Stage 1 files + functions (unified prompt)
        from step1_locator.ranker import rank_results

        stage1_funcs = stage1_result.get("vulnerable_functions", [])

        ranked = rank_results(files=stage1_files, functions=stage1_funcs)
        ranked_files = ranked["vulnerable_files"]
        ranked_funcs = ranked["vulnerable_functions"]

        n_files = len(ranked_files)
        n_funcs = len(ranked_funcs)
        overall_confidence = stage1_confidence
        mode = "unified_single_pass"
        print(f"  [V2] Stage 1 done: {n_files} files, {n_funcs} functions (confidence={stage1_confidence}, turns={stage1_turns})")

    # ─── Stage 2: Function Pinpointer (optional) ───────────────────────
    stage2_funcs = None
    stage2_turns = 0
    stage2_summary = ""
    if two_stage and ranked_files:
        print(f"  [V2] Stage 2: Function Pinpointer ({cve_id}) ...")
        from step1_v2.func_pinpointer import FuncPinpointer

        pinpointer = FuncPinpointer(repo_path=repo_path)
        try:
            stage2_result = pinpointer.pinpoint(
                cve_id=cve_id,
                issue_title=issue_title,
                issue_body=issue_body,
                language=language,
                top_files=ranked_files,
            )
        finally:
            pinpointer.close()

        stage2_funcs = stage2_result.get("vulnerable_functions", [])
        stage2_summary = stage2_result.get("analysis_summary", "")
        s2_conf = stage2_result.get("confidence", "low")

        # Fallback: if Stage 2 produces too few functions, keep Stage 1 functions
        if len(stage2_funcs) < 3 and stage1_funcs:
            print(f"  [V2] Stage 2 returned only {len(stage2_funcs)} functions, falling back to Stage 1 functions")
            ranked = rank_results(files=stage1_files, functions=stage1_funcs)
            ranked_funcs = ranked["vulnerable_functions"]
            mode = "two_stage_fallback"
        else:
            # Merge: Stage 1 files + Stage 2 functions
            ranked = rank_results(files=stage1_files, functions=stage2_funcs)
            ranked_funcs = ranked["vulnerable_functions"]
            mode = "two_stage"
        n_funcs = len(ranked_funcs)
        overall_confidence = stage1_confidence if stage1_confidence == "high" else s2_conf
        print(f"  [V2] Stage 2 done: {n_funcs} functions (confidence={s2_conf})")

    # ─── Assemble final result ───────────────────────────────────────
    t_elapsed = time.time() - t_start

    if not two_stage:
        overall_confidence = stage1_confidence

    combined_summary = (stage2_summary or stage1_summary)[:300]
    result = {
        "vulnerable_files": ranked_files,
        "vulnerable_functions": ranked_funcs,
        "confidence": overall_confidence,
        "analysis_summary": combined_summary,
        "mode": mode,
        "stage1": {
            "files": [
                {"file": f.get("file", ""), "score": f.get("score", 0)}
                for f in ranked_files[:10]
            ],
            "turns": stage1_turns,
            "confidence": stage1_confidence,
            "summary": stage1_summary[:200],
        },
        "cve_id": cve_id,
        "exploration_log": [
            {"stage": "stage1", "turns": stage1_turns,
             "files_found": n_files, "functions_found": n_funcs},
        ],
        "step1_elapsed": round(t_elapsed, 1),
        "step1_v2": True,
    }
    if two_stage:
        result["stage2"] = {
            "functions": [
                {"function": f.get("function", ""), "file": f.get("file", ""), "score": f.get("score", 0)}
                for f in ranked_funcs[:10]
            ],
            "turns": stage2_turns,
            "summary": stage2_summary[:200],
        }
        result["exploration_log"].append(
            {"stage": "stage2", "funcs_found": n_funcs},
        )

    return result


def _get_earliest_date(cve_entry: dict) -> str:
    """Extract earliest issue date from CVE entry for before_date filter."""
    earliest = ""
    for issue in cve_entry.get("issue_list", []):
        date = issue.get("created_at", "")
        if date and (not earliest or date < earliest):
            earliest = date
    return earliest
