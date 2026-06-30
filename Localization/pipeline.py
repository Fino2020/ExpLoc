"""
Pipeline Orchestrator — integrated two-stage vulnerability localization + exploit chain tracing.

Flow per CVE:
  1. Stage 1a: IterativeFileHunter — multi-round LLM agent discovers vulnerable files
  2. Stage 1b: FuncPinpointer — single-pass LLM refines functions within discovered files
  3. Step 2: Exploit Chain Tracing — two-phase agent traces Source→Sink exploit chains

Usage:
  python3 pipeline.py --cves CVE-2013-7449
  python3 pipeline.py --limit 10
  python3 pipeline.py --limit 0 --workers 8
  python3 pipeline.py --skip 50 --limit 0 --resume
"""

import fcntl
import io
import json
import os
import re
import sys
import time
import traceback
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from typing import Dict, List, Optional, Tuple

_LOC_DIR = os.path.dirname(os.path.abspath(__file__))
if _LOC_DIR not in sys.path:
    sys.path.insert(0, _LOC_DIR)

from shared.config import (
    PROJECT_ROOT, DATASET_PATH, MANIFEST_PATH, OUTPUT_DIR,
    REPO_BASE, RMS_DB_DIR,
)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _get_earliest_issue_date(entry: dict) -> str:
    issues = entry.get("issue_list", [])
    if not issues:
        return ""
    dates = [i.get("created_at", "") for i in issues if i.get("created_at")]
    return min(dates) if dates else ""


def _build_issue_description(entry: dict) -> Tuple[str, str, str]:
    title = entry.get("issue_title", "") or entry.get("cve_id", "")
    body = ""
    for src in ("issue_body", "description", "cve_description"):
        val = entry.get(src, "")
        if val:
            body = val
            break
    language = entry.get("language", "") or "unknown"
    return title, body, language


def _resolve_repo_path(entry: dict) -> str:
    cve_id = entry["cve_id"]
    owner = entry.get("owner", "")
    project = entry.get("project", "")
    if owner and project:
        path_cve = os.path.join(REPO_BASE, cve_id, owner, project)
        path_flat = os.path.join(REPO_BASE, f"{owner}_{project}")
        if os.path.isdir(path_cve):
            return path_cve
        if os.path.isdir(path_flat):
            return path_flat
        return path_cve
    return os.path.join(REPO_BASE, cve_id, "unknown")


# ---------------------------------------------------------------------------
# Stage 1: IterativeFileHunter + FuncPinpointer
# ---------------------------------------------------------------------------

def run_step1(
    cve_id: str,
    issue_title: str,
    issue_body: str,
    language: str,
    before_date: str,
    owner: str,
    project: str,
    retriever,
    repo_path: str,
    no_agent: bool = False,
    no_refine: bool = False,
    no_kg: bool = False,
    use_v2: bool = True,
    two_stage: bool = True,
    iterative: bool = True,
    severity: str = "",
    base_score: str = "",
    cwe_ids: Optional[List[str]] = None,
) -> dict:
    """Run Stage 1: IterativeFileHunter + FuncPinpointer (or fallback HybridAgent)."""
    if use_v2:
        from step1_v2.pipeline import run_step1_v2

        cve_entry = {
            "cve_id": cve_id,
            "issue_title": issue_title,
            "issue_body": issue_body,
            "language": language,
            "owner": owner,
            "project": project,
            "issue_list": [{"created_at": before_date}] if before_date else [],
            "severity": severity or "",
            "baseScore": base_score or "",
            "cwe_id": cwe_ids or [],
        }
        return run_step1_v2(cve_entry, retriever, repo_path,
                            two_stage=two_stage, use_iterative=iterative)

    # Legacy fallback: HybridAgent
    from step1_locator.ranker import rank_results

    if no_agent:
        return _run_step1_heuristic(cve_id, issue_title, issue_body,
                                     language, before_date, retriever)

    from step1_locator.agent import HybridAgent
    agent = HybridAgent(retriever, repo_path=repo_path, no_kg=no_kg)
    try:
        result = agent.localize(
            cve_id=cve_id,
            issue_title=issue_title,
            issue_body=issue_body,
            language=language,
            before_date=before_date,
        )
        ranked = rank_results(
            files=result.get("vulnerable_files", []),
            functions=result.get("vulnerable_functions", []),
        )
        result["vulnerable_files"] = ranked["vulnerable_files"]
        result["vulnerable_functions"] = ranked["vulnerable_functions"]

        if not no_refine and ranked["vulnerable_files"]:
            result["vulnerable_functions"] = _run_func_refiner(
                issue_title, issue_body, language,
                ranked["vulnerable_files"],
                ranked["vulnerable_functions"],
                repo_path, agent,
            )
        result["exploration_log"] = agent.exploration_log
        result["memory_stats"] = retriever.stats()
        return result
    finally:
        agent.close()


def _run_func_refiner(issue_title, issue_body, language,
                       top_files, top_functions, repo_path, agent) -> list:
    from step1_locator.func_refiner import refine_functions
    try:
        issue_desc = f"Title: {issue_title}\n\nDescription:\n{issue_body}"
        file_paths = [f.get("file", f) if isinstance(f, dict) else f for f in top_files[:10]]
        refined, _ = refine_functions(
            issue_description=issue_desc,
            language=language,
            top_files=file_paths,
            repo_path=repo_path,
            llm_client=agent.client,
            llm_model=agent.model,
            original_functions=top_functions,
        )
        if refined:
            return refined
    except Exception as e:
        print(f"  [REFINER] Failed: {e}")
    return top_functions


def _run_step1_heuristic(cve_id, issue_title, issue_body, language,
                          before_date, retriever) -> dict:
    from step1_locator.ranker import rank_results
    keywords = set(re.findall(r'[a-zA-Z_]\w{3,}', f"{issue_title} {issue_body}"))
    stopwords = {'the', 'and', 'for', 'that', 'this', 'with', 'from', 'have',
                 'when', 'which', 'what', 'does', 'into', 'over', 'after',
                 'cve', 'vulnerability', 'attack', 'exploit', 'issue'}
    keywords -= stopwords

    files = retriever.search_files(keywords, top_k=15)
    ranked = rank_results(files=[], functions=[])
    result = {
        "cve_id": cve_id,
        "vulnerable_files": [{"file": f, "score": s, "reason": "keyword match"}
                              for f, s in files[:15]],
        "vulnerable_functions": [],
        "confidence": "low",
        "analysis_summary": "Heuristic keyword-based search",
        "mode": "heuristic",
    }
    return result


# ---------------------------------------------------------------------------
# Step 2: Exploit Chain Tracing
# ---------------------------------------------------------------------------

def run_step2(
    cve_id: str,
    issue_description: str,
    language: str,
    step1_result: dict,
    repo_path: str,
    step2_mode: str = "call_site_windows",
) -> Optional[dict]:
    """Run Step 2: exploit chain tracing from top functions."""
    top_funcs = step1_result.get("vulnerable_functions", [])[:5]
    if not top_funcs:
        return {"cve_id": cve_id, "error": "no_functions", "explanations": []}

    if step2_mode == "call_site_windows":
        return _run_step2_call_site_windows(cve_id, issue_description, top_funcs, repo_path)

    elif step2_mode == "greedy":
        return _run_step2_greedy(cve_id, issue_description, language, step1_result, repo_path)

    elif step2_mode == "archetype":
        return _run_step2_archetype(cve_id, issue_description, language, step1_result, repo_path)

    elif step2_mode == "llm_guided":
        return _run_step2_llm_guided(cve_id, issue_description, language, step1_result, repo_path)

    elif step2_mode == "pure_llm":
        return _run_step2_pure_llm(cve_id, issue_description, language, step1_result, repo_path)

    elif step2_mode == "llm_cwe":
        return _run_step2_llm_cwe(cve_id, issue_description, language, step1_result, repo_path)

    else:
        return {"cve_id": cve_id, "error": f"unknown_step2_mode: {step2_mode}", "explanations": []}


def _run_step2_call_site_windows(
    cve_id: str,
    issue_description: str,
    top_funcs: List[dict],
    repo_path: str,
) -> Optional[dict]:
    """Exploit chain tracing via ICFG call-site context windows + LLM classification."""
    from step2_explainer.agent_explainer import generate_exploit_chain_simple

    result = generate_exploit_chain_simple(
        cve_id=cve_id,
        issue_description=issue_description,
        step1_functions=top_funcs,
        repo_path=repo_path,
    )
    if result is None:
        return {"cve_id": cve_id, "error": "call_site_windows_failed", "explanations": []}
    return result


def _run_step2_greedy(
    cve_id: str, issue_description: str, language: str,
    step1_result: dict, repo_path: str,
) -> Optional[dict]:
    """Greedy PathTracer with ICFG forward trace."""
    from shared.icfg_loader import load_icfg_if_exists
    from shared.static_selector import select_best_icfg
    from step2_explainer.path_tracer import PathTracer
    from step2_explainer.code_extractor import extract_code_snippets
    from step2_explainer.nl_explainer import generate_explanation as gen_nl
    from step2_explainer.formatter import format_explanation

    selection = select_best_icfg(cve_id, language=language, strategy="scubatrace_first")
    if not selection.selected_path:
        return {"cve_id": cve_id, "error": "no_icfg", "explanations": []}

    icfg = load_icfg_if_exists(selection.selected_path)
    if icfg is None:
        return {"cve_id": cve_id, "error": "icfg_load_failed", "explanations": []}

    top_funcs = step1_result.get("vulnerable_functions", [])[:2]
    if not top_funcs:
        return {"cve_id": cve_id, "error": "no_functions", "explanations": []}

    evidence = []
    for vf in step1_result.get("vulnerable_files", [])[:5]:
        ev = vf.get("evidence", {})
        if ev.get("matching_issues"):
            evidence.append(f"Issue(s): {ev['matching_issues']}")
        if ev.get("matching_commits"):
            evidence.append(f"Commit(s): {ev['matching_commits']}")
    evidence.append(step1_result.get("analysis_summary", ""))

    vuln_types = _detect_vuln_types(issue_description)
    tracer = PathTracer(icfg, tau=0.3, max_depth=15)
    explanations = []

    for i, func_info in enumerate(top_funcs):
        func_name = func_info.get("function", "")
        if not func_name:
            continue
        trace_result = tracer.trace(func_name, vuln_types, language)
        if trace_result is None:
            explanations.append({"function_rank": i + 1, "entry_function": func_name,
                                 "error": "entry_node_not_found"})
            continue
        snippets = extract_code_snippets(
            repo_path=repo_path, path_chain=trace_result.path_chain,
            nodes=trace_result.nodes, entry_function=func_name,
            sink_function=trace_result.sink,
        )
        nl = gen_nl(
            path_chain=trace_result.path_chain,
            code_snippets=snippets,
            vuln_type=vuln_types[0] if vuln_types else "unknown",
            evidence=evidence,
            entry_function=func_name,
            sink_function=trace_result.sink,
            terminated_at_sink=trace_result.terminated_at_sink,
        )
        exp = format_explanation(
            trace_result={
                "entry_function": trace_result.entry_function if hasattr(trace_result, 'entry_function') else func_name,
                "entry_file": trace_result.entry_file if hasattr(trace_result, 'entry_file') else func_info.get("file", ""),
                "entry_line": trace_result.entry_line if hasattr(trace_result, 'entry_line') else 0,
                "sink": trace_result.sink,
                "terminated_at_sink": trace_result.terminated_at_sink,
                "path_chain": trace_result.path_chain,
                "nodes": trace_result.nodes,
                "code_snippets": snippets,
                "cumulative_score": trace_result.cumulative_score if hasattr(trace_result, 'cumulative_score') else 0,
            },
            nl_explanation=nl,
            evidence_from_step1=evidence,
            function_rank=i + 1,
        )
        explanations.append(exp)

    num_sink_hit = sum(1 for e in explanations if e.get("terminated_at_sink"))

    return {
        "cve_id": cve_id, "step2_mode": "greedy",
        "icfg_source": selection.selected_path,
        "icfg_path": selection.selected_path,
        "icfg_stats": {"nodes": icfg.number_of_nodes(), "edges": icfg.number_of_edges()},
        "explanations": explanations,
        "trace_statistics": {
            "num_traced": len(explanations),
            "num_sink_hit": num_sink_hit,
            "sink_match_rate": num_sink_hit / max(len(explanations), 1),
        },
        "selection_reason": selection.selection_reason,
    }


# (archetype, llm_guided, pure_llm, llm_cwe stubs kept for API compatibility)
# These are imported lazily when requested — see legacy functions below.


def _run_step2_archetype(cve_id, issue_description, language, step1_result, repo_path):
    from pipeline_legacy import run_step2_archetype as _fn
    return _fn(cve_id, issue_description, language, step1_result, repo_path)


def _run_step2_llm_guided(cve_id, issue_description, language, step1_result, repo_path):
    from pipeline_legacy import run_step2_llm_guided as _fn
    return _fn(cve_id, issue_description, language, step1_result, repo_path)


def _run_step2_pure_llm(cve_id, issue_description, language, step1_result, repo_path):
    from pipeline_legacy import run_step2_pure_llm as _fn
    return _fn(cve_id, issue_description, language, step1_result, repo_path)


def _run_step2_llm_cwe(cve_id, issue_description, language, step1_result, repo_path):
    from pipeline_legacy import run_step2_llm_cwe as _fn
    return _fn(cve_id, issue_description, language, step1_result, repo_path)


def _detect_vuln_types(text: str) -> list:
    """Lightweight CWE keyword detection from issue text."""
    patterns = {
        "buffer-overflow": r"buffer.overflow|stack.based|heap.based",
        "command-injection": r"command.injection|os.command",
        "sql-injection": r"sql.injection",
        "xss": r"cross.site.script|xss",
        "path-traversal": r"path.traversal|directory.traversal",
        "use-after-free": r"use.after.free|uaf",
        "null-pointer": r"null.pointer.dereference",
        "integer-overflow": r"integer.overflow",
        "out-of-bounds": r"out.of.bounds|oob.",
        "memory-corruption": r"memory.corruption",
        "format-string": r"format.string",
        "race-condition": r"race.condition|toctou",
        "deserialization": r"deseriali[sz]ation|insecure.deseriali",
        "authentication": r"authentication.bypass|auth.bypass",
        "information-leak": r"information.leak|info.leak|sensitive.data",
    }
    found = []
    t = text.lower()
    for vtype, pattern in patterns.items():
        if re.search(pattern, t):
            found.append(vtype)
    return found or ["memory-corruption"]


# ---------------------------------------------------------------------------
# Single CVE runner
# ---------------------------------------------------------------------------

def run_single_cve(
    entry: dict,
    output_dir: str = "",
    skip_step2: bool = False,
    no_agent: bool = False,
    no_refine: bool = False,
    no_kg: bool = False,
    step2_mode: str = "call_site_windows",
    mock_nl: bool = False,
    uniform_edges: bool = False,
    no_slot_termination: bool = False,
    use_v2: bool = True,
    two_stage: bool = True,
    iterative: bool = True,
) -> dict:
    """Run full pipeline for a single CVE."""
    cve_id = entry["cve_id"]
    title, body, language = _build_issue_description(entry)
    before_date = _get_earliest_issue_date(entry)
    owner = entry.get("owner", "")
    project = entry.get("project", "")
    repo_path = _resolve_repo_path(entry)
    issue_description = f"Title: {title}\n\nDescription:\n{body}"

    print(f"\n{'='*60}")
    print(f"  {cve_id}  |  {language}  |  {owner}/{project}")
    print(f"{'='*60}")

    # --- Setup retriever ---
    if no_kg or iterative:
        from step1_locator.retriever import NoKGRetriever
        retriever = NoKGRetriever(repo_path=repo_path)
        print(f"  RMS: No-KG mode (iterative search uses SearchBackend)")
    else:
        db_path = os.path.join(RMS_DB_DIR, f"{owner}_{project}.db")
        from step1_locator.retriever import Retriever
        if not os.path.exists(db_path):
            print(f"  ERROR: RMS DB not found at {db_path}")
            return {"cve_id": cve_id, "error": "no_rms_db",
                    "vulnerable_files": [], "vulnerable_functions": []}
        retriever = Retriever(db_path, repo_path=repo_path)
        stats = retriever.stats()
        print(f"  RMS: {stats['commits']} commits, {stats['hotspots']} hotspots")

    # --- Stage 1 ---
    print(f"  Stage 1: IterativeFileHunter + FuncPinpointer ...")
    t1 = time.time()
    try:
        result = run_step1(
            cve_id=cve_id,
            issue_title=title, issue_body=body, language=language,
            before_date=before_date, owner=owner, project=project,
            retriever=retriever, repo_path=repo_path,
            no_agent=no_agent, no_refine=no_refine, no_kg=no_kg,
            use_v2=use_v2, two_stage=two_stage, iterative=iterative,
            severity=entry.get("severity", ""),
            base_score=str(entry.get("baseScore", "")),
            cwe_ids=entry.get("cwe_id", []),
        )
    except Exception as e:
        traceback.print_exc()
        retriever.close()
        return {"cve_id": cve_id, "error": f"step1_failed: {e}"}

    result["step1_elapsed"] = round(time.time() - t1, 1)
    n_files = len(result.get("vulnerable_files", []))
    n_funcs = len(result.get("vulnerable_functions", []))
    print(f"  Stage 1 done: {n_files} files, {n_funcs} functions "
          f"({result.get('step1_elapsed', 0)}s)")

    # --- Step 2 ---
    if not skip_step2:
        print(f"  Step 2: Exploit Chain Tracing (call_site_windows) ...")
        t2 = time.time()
        try:
            step2_result = run_step2(
                cve_id=cve_id, issue_description=issue_description,
                language=language, step1_result=result, repo_path=repo_path,
                step2_mode=step2_mode,
            )
            if step2_result:
                result["step2"] = step2_result
                result["step2_elapsed"] = round(time.time() - t2, 1)
                n_exp = len(step2_result.get("explanations", []))
                print(f"  Step 2 done: {n_exp} chains ({result.get('step2_elapsed', 0)}s)")
        except Exception as e:
            traceback.print_exc()
            result["step2_error"] = str(e)

    retriever.close()
    return result


# ---------------------------------------------------------------------------
# Batch runner
# ---------------------------------------------------------------------------

def run_batch(
    manifest_path: str = MANIFEST_PATH,
    output_dir: str = OUTPUT_DIR,
    limit: int = 10,
    skip: int = 0,
    cve_list: Optional[List[str]] = None,
    skip_step2: bool = False,
    no_agent: bool = False,
    no_refine: bool = False,
    no_kg: bool = False,
    workers: int = 1,
    resume: bool = False,
    step2_mode: str = "call_site_windows",
    mock_nl: bool = False,
    uniform_edges: bool = False,
    no_slot_termination: bool = False,
    use_v2: bool = True,
    two_stage: bool = True,
    iterative: bool = True,
):
    """Run pipeline over multiple CVEs, optionally in parallel."""
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    if cve_list:
        cve_set = set(cve_list)
        entries = [e for e in manifest if e["cve_id"] in cve_set]
    else:
        entries = manifest[skip:]
        if limit > 0:
            entries = entries[:limit]

    print(f"Pipeline: {len(entries)} CVEs | workers={workers} | "
          f"step2_mode={step2_mode} | use_v2={use_v2} two_stage={two_stage} iterative={iterative}")

    os.makedirs(output_dir, exist_ok=True)

    if workers > 1:
        from concurrent.futures import ProcessPoolExecutor, as_completed
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = []
            for entry in entries:
                cve_id = entry["cve_id"]
                cve_dir = os.path.join(output_dir, cve_id)
                if resume and os.path.exists(os.path.join(cve_dir, "result.json")):
                    print(f"  SKIP {cve_id} (already exists)")
                    continue
                futures.append(executor.submit(
                    _process_single_cve,
                    (entry, output_dir, skip_step2, no_agent, no_refine, no_kg,
                     False, step2_mode, mock_nl, uniform_edges, no_slot_termination,
                     use_v2, two_stage, iterative),
                ))
            for future in as_completed(futures):
                r = future.result()
                _print_result(r)
    else:
        for entry in entries:
            cve_id = entry["cve_id"]
            cve_dir = os.path.join(output_dir, cve_id)
            if resume and os.path.exists(os.path.join(cve_dir, "result.json")):
                print(f"  SKIP {cve_id} (already exists)")
                continue
            result = run_single_cve(
                entry, output_dir=output_dir,
                skip_step2=skip_step2, no_agent=no_agent,
                no_refine=no_refine, no_kg=no_kg,
                step2_mode=step2_mode, mock_nl=mock_nl,
                uniform_edges=uniform_edges,
                no_slot_termination=no_slot_termination,
                use_v2=use_v2, two_stage=two_stage, iterative=iterative,
            )
            _save_and_print(result, output_dir)


def _process_single_cve(args_tuple: tuple) -> dict:
    entry, output_dir, skip_step2, no_agent, no_refine, no_kg, capture_log, \
        step2_mode, mock_nl, uniform_edges, no_slot_termination, \
        use_v2, two_stage, iterative = args_tuple

    cve_id = entry["cve_id"]
    t0 = time.time()

    def _run():
        return run_single_cve(
            entry, output_dir=output_dir, skip_step2=skip_step2,
            no_agent=no_agent, no_refine=no_refine, no_kg=no_kg,
            step2_mode=step2_mode, mock_nl=mock_nl,
            uniform_edges=uniform_edges, no_slot_termination=no_slot_termination,
            use_v2=use_v2, two_stage=two_stage, iterative=iterative,
        )

    log_buf = io.StringIO() if capture_log else None
    _ctx = (redirect_stdout(log_buf), redirect_stderr(log_buf)) if capture_log else None

    if _ctx:
        _ctx[0].__enter__()
        _ctx[1].__enter__()
    try:
        result = _run()
        elapsed = time.time() - t0
        result["elapsed_seconds"] = round(elapsed, 1)
        result["timestamp"] = datetime.now().isoformat()
        result["owner"] = entry.get("owner", "?")
        result["project"] = entry.get("project", "?")
        result["language"] = entry.get("language", "unknown")

        cve_dir = os.path.join(output_dir, cve_id)
        os.makedirs(cve_dir, exist_ok=True)
        with open(os.path.join(cve_dir, "result.json"), "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        return {"cve_id": cve_id, "result": result, "elapsed": elapsed, "error": None}
    except Exception as e:
        traceback.print_exc()
        elapsed = time.time() - t0
        return {"cve_id": cve_id, "result": None, "elapsed": elapsed, "error": str(e)}
    finally:
        if _ctx:
            _ctx[1].__exit__(None, None, None)
            _ctx[0].__exit__(None, None, None)


def _save_and_print(result: dict, output_dir: str):
    cve_id = result.get("cve_id", "?")
    cve_dir = os.path.join(output_dir, cve_id)
    os.makedirs(cve_dir, exist_ok=True)
    with open(os.path.join(cve_dir, "result.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    _print_result({"cve_id": cve_id, "result": result, "elapsed": result.get("elapsed_seconds", 0),
                   "error": result.get("error")})


def _print_result(r: dict):
    cve_id = r["cve_id"]
    err = r.get("error")
    if err:
        print(f"  [{cve_id}] ERROR: {err}")
        return
    res = r.get("result", {})
    nf = len(res.get("vulnerable_files", []))
    nfn = len(res.get("vulnerable_functions", []))
    nchains = len(res.get("step2", {}).get("explanations", [])) if res.get("step2") else 0
    t = r.get("elapsed", 0)
    print(f"  [{cve_id}] files={nf} funcs={nfn} chains={nchains} ({t:.0f}s)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="ExpLoc — Two-Stage Vulnerability Localization + Exploit Chain Tracing"
    )
    parser.add_argument("--limit", type=int, default=10,
                        help="Max CVEs (0=all, default: 10)")
    parser.add_argument("--skip", type=int, default=0,
                        help="Skip first N CVEs")
    parser.add_argument("--cves", type=str, default="",
                        help="Comma-separated CVE IDs")
    parser.add_argument("--output", type=str, default=None,
                        help="Output directory (default: Results/Localization/Localization)")
    parser.add_argument("--manifest", type=str, default=None,
                        help="Manifest path (default: Dataset/dataset_with_changed_files_filter.json)")
    parser.add_argument("--workers", type=int, default=1,
                        help="Parallel workers (default: 1)")
    parser.add_argument("--resume", action="store_true",
                        help="Skip CVEs with existing result.json")

    # Step 1 controls
    parser.add_argument("--no-step1-v2", action="store_true",
                        help="Use legacy HybridAgent instead of iterative two-stage")
    parser.add_argument("--no-two-stage", action="store_true",
                        help="Disable Stage 1b FuncPinpointer")
    parser.add_argument("--no-iterative", action="store_true",
                        help="Use single-pass FileHunter instead of IterativeFileHunter")
    parser.add_argument("--no-kg", action="store_true",
                        help="No-KG ablation: skip RMS DB, BM25, issue links")

    # Step 2 controls
    parser.add_argument("--no-step2", action="store_true",
                        help="Skip exploit chain tracing (Stage 1 only)")
    parser.add_argument("--step2-mode", type=str, default="call_site_windows",
                        choices=["call_site_windows", "greedy", "archetype",
                                 "llm_guided", "pure_llm", "llm_cwe"],
                        help="Step 2 mode (default: call_site_windows)")

    args = parser.parse_args()

    cve_list = None
    if args.cves:
        cve_list = [c.strip() for c in args.cves.split(",") if c.strip()]

    manifest_path = args.manifest or MANIFEST_PATH

    if args.output:
        output_dir = args.output
    elif args.no_kg:
        output_dir = os.path.join(os.path.dirname(OUTPUT_DIR), "Localization_NoKG")
    else:
        output_dir = OUTPUT_DIR

    run_batch(
        manifest_path=manifest_path,
        output_dir=output_dir,
        limit=args.limit,
        skip=args.skip,
        cve_list=cve_list,
        skip_step2=args.no_step2 or args.no_kg,
        no_agent=False,
        no_refine=args.no_kg,
        no_kg=args.no_kg,
        workers=args.workers,
        resume=args.resume,
        step2_mode=args.step2_mode,
        use_v2=not args.no_step1_v2,
        two_stage=not args.no_two_stage,
        iterative=not args.no_iterative,
    )
