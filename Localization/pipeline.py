"""
Pipeline Orchestrator — chains Step 1 (localization) and Step 2 (explanation).

Flow per CVE:
  1. Load/build per-project RMS DB
  2. Run issue_linker to populate issue→commit mappings
  3. Step 1: HybridAgent → ranked files + functions
  4. Step 2: Select ICFG → PathTracer on top-5 functions
     → code_extractor → nl_explainer
  5. Serialize results to OUTPUT_DIR/{CVE-ID}/

Usage:
  python3 pipeline.py --limit 10
  python3 pipeline.py --cves CVE-2024-XXXX
  python3 pipeline.py --skip 5 --limit 0  # all from skip
"""

import fcntl
import io
import json
import os
import sys
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from tqdm import tqdm

_LOC_DIR = os.path.dirname(os.path.abspath(__file__))
if _LOC_DIR not in sys.path:
    sys.path.insert(0, _LOC_DIR)

from shared.config import (
    MANIFEST_PATH, DATASET_PATH, OUTPUT_DIR, REPO_BASE,
    RMS_DB_DIR, HISTORY_DIR, ICFG_DIR, SCUBA_RESULTS_DIR,
)
from shared.sink_db import detect_vuln_types


# ---------------------------------------------------------------------------
# CVE loading
# ---------------------------------------------------------------------------

def load_manifest(path: str = MANIFEST_PATH) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _get_language(entry: dict) -> str:
    return entry.get("language", "unknown")


def _normalize_entry(entry: dict) -> dict:
    """Fill missing owner/project/language from issue_list repo field."""
    if not entry.get("owner") or not entry.get("project"):
        for issue in entry.get("issue_list", []):
            repo = issue.get("repo", "")
            if "/" in repo:
                parts = repo.split("/")
                entry["owner"] = parts[0]
                entry["project"] = parts[1]
                break
    if not entry.get("repo_path") and entry.get("owner") and entry.get("project"):
        # Try CVE-ID based path first: REPO_BASE/{cve_id}/{owner}/{project}/
        cve_path = os.path.join(REPO_BASE, entry["cve_id"], entry["owner"], entry["project"])
        if os.path.isdir(os.path.join(cve_path, ".git")):
            entry["repo_path"] = cve_path
        else:
            # Fallback: REPO_BASE/{owner}_{project}/
            entry["repo_path"] = os.path.join(REPO_BASE, f"{entry['owner']}_{entry['project']}")
    if not entry.get("language") or entry.get("language") == "unknown":
        # Try to detect from repo_path
        rp = entry.get("repo_path", "")
        if rp and os.path.isdir(rp):
            entry["language"] = _detect_language_from_repo(rp)
    return entry


def _detect_language_from_repo(repo_path: str) -> str:
    """Detect primary language from repo file extensions."""
    ext_counts = {}
    exts = {".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".py": "python",
            ".java": "java", ".js": "javascript", ".ts": "javascript",
            ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
            ".swift": "swift", ".kt": "kotlin"}
    try:
        for root, dirs, files in os.walk(repo_path):
            rel = os.path.relpath(root, repo_path)
            if len(rel.split(os.sep)) > 4:
                dirs.clear()
                continue
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in exts:
                    lang = exts[ext]
                    ext_counts[lang] = ext_counts.get(lang, 0) + 1
            if len(ext_counts) > 10000:
                break
    except Exception:
        pass
    if ext_counts:
        return max(ext_counts, key=ext_counts.get)
    return "unknown"


def _get_earliest_issue_date(entry: dict) -> str:
    earliest = ""
    for issue in entry.get("issue_list", []):
        date = issue.get("created_at", "")
        if date and (not earliest or date < earliest):
            earliest = date
    return earliest


def _build_issue_description(entry: dict) -> Tuple[str, str, str]:
    title = ""
    body = ""
    for issue in entry.get("issue_list", []):
        if not title:
            title = issue.get("title", "")
        if not body:
            body = issue.get("body", "") or ""
        for event in issue.get("events", []):
            event_body = event.get("body", "")
            if event_body and len(body) < 2000:
                body += f"\n[Comment]: {event_body[:500]}"
    return title, body, f"Title: {title}\n\nDescription:\n{body}"


# ---------------------------------------------------------------------------
# Step 1: Localization
# ---------------------------------------------------------------------------

def _run_func_refiner(
    issue_title: str,
    issue_body: str,
    language: str,
    ranked_files: List[dict],
    ranked_functions: List[dict],
    repo_path: str,
    agent,
) -> List[dict]:
    """Second-pass function refinement on top predicted files.

    Extracts ALL functions from top-N files via tree-sitter and has the LLM
    re-score them for vulnerability relevance.
    """
    from step1_locator.func_refiner import refine_functions

    top_files = [f.get("file", "") for f in ranked_files[:20] if f.get("file")]
    if not top_files:
        return ranked_functions

    issue_description = f"Title: {issue_title}\n\nDescription:\n{issue_body}"

    try:
        refined, summary = refine_functions(
            issue_description=issue_description,
            language=language,
            top_files=top_files,
            repo_path=repo_path,
            llm_client=agent.client,
            llm_model=agent.model,
            original_functions=ranked_functions,
        )
        if refined:
            return refined
    except Exception as e:
        print(f"  [REFINER] Failed: {e}")

    return ranked_functions


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
) -> dict:
    """Run Step 1: hybrid agent localization (or heuristic-only if no_agent)."""
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

        # Second-pass function refinement on top predicted files
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


def _run_step1_heuristic(
    cve_id: str,
    issue_title: str,
    issue_body: str,
    language: str,
    before_date: str,
    retriever,
) -> dict:
    """Heuristic-only localization: BM25 commit search + hotspot files (no LLM)."""
    from step1_locator.ranker import rank_results

    query = f"{issue_title} {issue_body}"[:2000]
    commits = retriever.search_commit(query, top_k=20, before_date=before_date)

    file_scores = {}
    for c in commits:
        files = retriever.get_files_from_commits([c["sha"]])
        score = c.get("score", 0)
        for f in files:
            file_scores[f] = max(file_scores.get(f, 0), score)

    hotspots = retriever.get_hotspots(top_k=10)
    for h in hotspots:
        fp = h.get("file_path", "")
        score = h.get("edit_count", 0) / 100.0
        file_scores[fp] = max(file_scores.get(fp, 0), score)

    sorted_files = sorted(file_scores.items(), key=lambda x: -x[1])[:20]
    file_list = [{"file": f, "score": s, "source": "heuristic"} for f, s in sorted_files]

    ranked = rank_results(files=file_list, functions=[])

    return {
        "cve_id": cve_id,
        "vulnerable_files": ranked["vulnerable_files"],
        "vulnerable_functions": [],
        "confidence": "low",
        "analysis_summary": f"Heuristic-only: {len(file_list)} files from BM25 + hotspots",
        "mode": "heuristic",
    }


def _mock_generate_explanation(**kwargs) -> dict:
    """Placeholder NL — skip LLM, return tracing data only."""
    return {
        "summary": "NL explanation disabled (mock mode)",
        "explanation": "",
        "entry_description": "",
        "sink_description": "",
        "key_lines": [],
    }


def _patch_nl():
    """Monkey-patch NL explainer to skip LLM calls."""
    import step2_explainer.nl_explainer
    step2_explainer.nl_explainer.generate_explanation = _mock_generate_explanation


# ---------------------------------------------------------------------------
# Step 2: Archetype mode (CWE prototype / slot-based search)
# ---------------------------------------------------------------------------

def run_step2_archetype(
    cve_id: str,
    issue_description: str,
    language: str,
    step1_result: dict,
    repo_path: str,
    mock_nl: bool = True,
    uniform_edges: bool = False,
    no_slot_termination: bool = False,
) -> Optional[dict]:
    """Run Step 2: archetype-guided ICFG search.

    Uses CWE prototype / slot system instead of greedy PathTracer.

    Ablation flags:
      uniform_edges: if True, all CWE edge weights = 1.0 (ablate edge selection)
      no_slot_termination: if True, disable slot-based SUCCESS, only depth+stagnation
    """
    from shared.icfg_loader import load_icfg_if_exists
    from shared.static_selector import select_best_icfg
    from shared.sink_db import detect_vuln_types
    from step2_explainer.cwe_archetypes.archetype_library import get_archetype
    from step2_explainer.cwe_archetypes.cwe_mapper import CWEMapper
    from step2_explainer.search_engine import ArchetypeSearchEngine
    from step2_explainer.edge_selector import EdgeSelector
    from step2_explainer.termination import TerminationController, TerminationReason, TerminationDecision
    from step2_explainer.code_extractor import extract_code_snippets

    # Build step1 function name set for boosting
    _step1_func_names = {f.get("function", "").lower() for f in step1_result.get("vulnerable_functions", [])[:30]}

    # Keyword → slot mappings (used by heuristic/fallback classifier)
    _KEYWORD_SLOTS = [
        (["alloc", "malloc", "calloc", "realloc", "new_obj", "create_obj", "make_obj"], "Allocation"),
        (["free", "delete", "destroy", "release", "cleanup", "close_handle", "remove_obj"], "Free"),
        (["memcpy", "memmove", "memset", "strcpy", "strncpy", "sprintf", "snprintf", "strcat", "memcmp",
          "bcopy", "copy_mem", "write_buf", "read_buf", "out_of_bound", "overflow"], "OutOfBoundsAccess"),
        (["read", "recv", "fread", "fgets", "fgetc", "getc", "input", "load_file", "load_data",
          "open_file", "receive", "fetch", "download", "get_data", "read_data"], "Source"),
        (["write", "send", "fwrite", "fputs", "fputc", "putc", "output", "save", "store",
          "write_data", "send_data", "put_data", "print", "fprintf", "emit"], "Sink"),
        (["exec", "execute", "system", "popen", "eval", "spawn", "run_cmd", "shell",
          "do_exec", "call_prog", "invoke", "launch", "start_proc", "execv", "execl"], "Execute"),
        (["parse", "decode", "deserialize", "unmarshal", "unpack", "xml_parse",
          "json_parse", "yaml_parse", "parse_data", "read_xml"], "Deserialize"),
        (["build", "construct", "format", "sprintf", "compose", "assemble",
          "make_str", "build_query", "build_cmd", "build_path", "create_sql", "snprintf"], "BuildQuery"),
        (["auth", "login", "authenticate", "verify_pwd", "check_pass", "validate_user",
          "check_perm", "authorize", "check_access", "permission", "allow_access"], "AuthCheck"),
        (["check", "validate", "verify", "test_input", "assert", "sanitize",
          "escape", "filter_input", "check_bounds", "is_valid", "ensure",
          "access", "stat", "fstat", "exists", "check_path", "check_file"], "MissingBoundsCheck"),
        (["init", "setup", "configure", "initialize", "startup", "bootstrap",
          "prepare", "create_ctx", "new_ctx", "setup_env", "main"], "Entry"),
        (["encode", "htmlencode", "urlencode", "escape_html", "escape_js",
          "sanitize_html", "xss_filter", "strip_tags"], "MissingEncoding"),
        (["lock", "unlock", "mutex", "acquire", "release_lock", "sem_wait",
          "sem_post", "critical_section", "atomic_op"], "TimeWindow"),
        (["get", "lookup", "find", "search", "query", "select", "retrieve",
          "get_value", "get_field", "get_prop", "getenv", "getcwd"], "RequestEntry"),
        (["set", "put", "update", "modify", "change", "assign", "store_val",
          "set_field", "set_prop", "set_value", "write_var", "putenv", "setenv",
          "set_dir", "own_dir", "set_path", "chdir"], "ExternalPath"),
        (["open", "fopen", "create_file", "mkfile", "new_file", "open_fd",
          "socket", "connect", "bind", "listen", "accept", "path", "dir",
          "filename", "filepath", "dll_path", "lib_path"], "ExternalPath"),
        (["load", "dlopen", "dlsym", "require", "import", "include",
          "load_lib", "load_module", "load_plugin", "loadlibrary", "getproc"], "LoadUntrusted"),
        (["render", "display", "show", "present", "draw", "paint",
          "to_html", "to_string", "serialize", "marshal"], "Render"),
        (["crypto", "encrypt", "decrypt", "hash", "sign", "verify_sig",
          "cipher", "digest", "random", "rng", "pbkdf", "hmac"], "CryptoOperation"),
        (["resolve", "realpath", "canonical", "normalize_path", "abspath",
          "dirname", "basename", "clean_path", "real_path", "resolve_path"], "PathResolution"),
        (["log", "debug", "trace", "info_msg", "warn", "error_msg",
          "print_err", "log_msg", "logging"], "Log"),
        # Memory safety slots (dominant in full dataset)
        (["deref", "dereference", "ptr", "pointer", "ref", "get_ptr", "get_ref",
          "follow_ptr", "resolve_ptr", "indirect", "get_addr", "addressof",
          "to_ptr", "as_ptr", "take_ptr", "unwrap_ptr"], "Dereference"),
        (["null", "nil", "none", "empty", "is_null", "check_null", "null_check",
          "null_ptr", "nil_ptr", "is_nil", "is_empty", "not_null", "assert_ptr",
          "ptr_valid", "validate_ptr", "ensure_ptr", "guard_ptr"], "MissingNullCheck"),
        (["corrupt", "corruption", "trash", "garbage", "memory_error",
          "heap_error", "stack_smash", "buffer_overrun", "mem_corrupt",
          "heap_corruption", "stack_corrupt", "mem_error"], "Corruption"),
        (["crash", "abort", "terminate", "segfault", "sigsegv", "fatal",
          "panic", "die", "exit_err", "exit_fail", "unhandled", "assert_fail",
          "trap", "exception", "signal_handler", "fatal_err"], "Crash"),
        (["leak", "memory_leak", "fd_leak", "handle_leak", "resource_leak",
          "forget_free", "miss_free", "no_free", "unreleased",
          "not_freed", "orphan", "lost_ref", "ref_leak", "alloc_no_free"], "Leak"),
        (["use_after_free", "uaf", "dangling", "stale_ptr", "free_then_use",
          "reuse_freed", "after_free", "dangling_ref", "freed_access",
          "post_free", "use_free", "zombie"], "UseAfterFree"),
        (["double_free", "dup_free", "free_twice", "refree", "re_free",
          "already_freed", "multi_free", "repeat_free"], "SecondFree"),
        # Integer/arithmetic
        (["add", "sub", "mul", "div", "mod", "inc", "dec", "increment",
          "decrement", "multiply", "divide", "subtract", "compute",
          "calculate", "calc", "arithmetic", "int_op", "math_op", "numeric_op",
          "size_calc", "len_calc", "offset_calc", "count_calc"], "ArithmeticOperation"),
        (["size", "len", "length", "count", "num", "capacity", "max_size",
          "buf_size", "alloc_size", "data_size", "total_len", "byte_count",
          "element_count", "remaining", "avail", "left", "limit"], "MissingBoundsCheck"),
        # IO / Transmission
        (["transmit", "transfer", "send_over", "put_over", "push_data",
          "forward", "relay", "proxy", "pass_through", "tunnel",
          "route", "deliver", "dispatch_to", "forward_to"], "Transmit"),
        # Config / environment
        (["config", "conf", "setting", "option", "pref", "property",
          "env", "environment", "ctx", "context", "state", "global_var",
          "static_var", "module_var", "class_var", "member_var"], "Source"),
        (["protect", "guard", "safe", "safe_call", "checked", "bounded",
          "safe_copy", "bounds_check", "range_check", "limit_check",
          "size_check", "cap_check", "overflow_check", "underflow_check"], "ProtectedAccess"),
        (["weak", "insecure", "broken", "flawed", "vulnerable", "deprecated",
          "legacy", "old_api", "unsafe_api", "obsolete", "weak_algo",
          "weak_cipher", "md4", "md5", "sha1", "rc4", "des_ecb"], "WeakVerification"),
        # Transformation
        (["convert", "transform", "convert_to", "change_type", "cast",
          "reinterpret", "type_cast", "coerce", "to_int", "to_str",
          "to_bytes", "from_bytes", "to_char", "wide_to_narrow",
          "narrow_to_wide", "encoding_convert", "charset_convert"], "Transform"),
        # OS interaction
        (["access", "stat", "fstat", "lstat", "exists", "file_exists",
          "dir_exists", "path_exists", "check_path", "realpath",
          "canonicalize", "normalize", "resolve_symlink", "follow_link"], "PathResolution"),
        (["close", "fclose", "shutdown", "disconnect", "close_fd",
          "close_handle", "close_sock", "hangup", "close_conn",
          "end_session", "teardown", "cleanup_conn"], "Free"),
    ]

    def _heuristic_slot(func_name: str, archetype) -> str:
        """Assign archetype slot based on function name keywords."""
        fl = func_name.lower().replace("-", "_").replace(" ", "_")
        slot_names = {s.name for s in archetype.slots}
        required = list(archetype.required_slot_names)

        matched = []
        for keywords, slot in _KEYWORD_SLOTS:
            if slot in slot_names:
                if any(kw in fl for kw in keywords):
                    matched.append((slot, keywords))

        if matched:
            for slot, kws in matched:
                if slot in required:
                    return slot
            return matched[0][0]

        if required:
            idx = hash(fl) % len(required)
            return required[idx]
        return list(slot_names)[0] if slot_names else ""

    if mock_nl:
        import step2_explainer.slot_classifier

        def _mock_classify(self, code, name, report, archetype):
            slot = _heuristic_slot(name, archetype)
            conf = 0.95 if name.lower() in _step1_func_names else 0.6
            return (slot, f"heuristic: {name} -> {slot}", conf)

        def _mock_classify_batch(self, funcs, report, archetype):
            results = []
            for f in funcs:
                name = f.get("name", "")
                slot = _heuristic_slot(name, archetype)
                conf = 0.95 if name.lower() in _step1_func_names else 0.6
                results.append((slot, f"heuristic: {name} -> {slot}", conf))
            return results

        step2_explainer.slot_classifier.SlotClassifier.classify = _mock_classify
        step2_explainer.slot_classifier.SlotClassifier.classify_batch = _mock_classify_batch
        from step2_explainer.slot_classifier import SlotClassifier
        slot_classifier = SlotClassifier()
    else:
        from step2_explainer.slot_classifier import SlotClassifier
        slot_classifier = SlotClassifier()
    # slot_classifier is ready; pre-classification hook set below after call graph built

    top_funcs = step1_result.get("vulnerable_functions", [])[:5]
    if not top_funcs:
        return {"cve_id": cve_id, "error": "no_functions", "explanations": []}

    vuln_types = detect_vuln_types(issue_description)
    cwe_ids = step1_result.get("cwe_ids", [])
    cwe_mapper_obj = None
    archetype = None
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    nvd_dir = os.path.join(project_root, "Dataset", "DataFeed")
    cwe_csv = os.path.join(nvd_dir, "1000.csv")
    if os.path.isfile(cwe_csv):
        try:
            cwe_mapper_obj = CWEMapper(nvd_dir=nvd_dir, cwe_csv_path=cwe_csv)
            archetype = cwe_mapper_obj.get_archetype_for_cve(cve_id)
        except Exception:
            pass
    if cwe_mapper_obj is None or archetype is None or archetype.family == "Generic":
        archetype = get_archetype(cwe_ids[0]) if cwe_ids else get_archetype("")

    # Extract step1 function names early (used by edge_selector and engine)
    step1_func_names = [f.get("function", "") for f in step1_result.get("vulnerable_functions", [])[:30]]
    step1_target_funcs = {f.lower() for f in step1_func_names[:20]}

    # Build focused call graph from tree-sitter (replaces full ICFG for speed)
    from step2_explainer.ts_call_builder import build_call_graph

    target_files = [os.path.join(repo_path, f.get("file", ""))
                    for f in step1_result.get("vulnerable_files", [])[:50]
                    if f.get("file")]
    t0_cg = time.time()
    cg = build_call_graph(repo_path, language, target_files=target_files,
                          target_functions=step1_target_funcs, max_depth=5,
                          max_files=500, timeout_seconds=120.0)
    icfg = cg  # CallGraph duck-types ICFG interface
    print(f"    Call graph: {cg.stats['nodes']} nodes, {cg.stats['edges']} edges "
          f"({time.time()-t0_cg:.1f}s)", flush=True)

    # Pre-classify all unique functions via LLM once, then use cached results
    if not mock_nl and archetype:
        all_func_names = set()
        for _, _, data in cg.graph.edges(data=True):
            t = data.get("target_function", "")
            if t:
                all_func_names.add(t)
        for fn in cg.function_entries:
            all_func_names.add(fn)

        if all_func_names:
            unique = sorted(all_func_names)
            _slot_cache: Dict[str, Tuple[str, str, float]] = {}
            print(f"    Pre-classifying {len(unique)} functions via LLM...", flush=True)
            t0_llm = time.time()
            for i in range(0, len(unique), 50):
                chunk = unique[i:i + 50]
                funcs = [{"name": n, "code": ""} for n in chunk]
                try:
                    results = slot_classifier.classify_batch(funcs, issue_description, archetype)
                    for j, (slot, just, conf) in enumerate(results):
                        nm = chunk[j] if j < len(chunk) else ""
                        _slot_cache[nm] = (slot, just, conf) if slot else (_heuristic_slot(nm, archetype), f"fallback: {nm}", 0.4)
                except Exception as ex:
                    print(f"    LLM batch failed: {ex}", flush=True)
                    for nm in chunk:
                        _slot_cache[nm] = (_heuristic_slot(nm, archetype), f"error: {nm}", 0.3)
            print(f"    Done ({time.time()-t0_llm:.1f}s)", flush=True)

            # Wrap classifier with O(1) cache
            _orig_clf = slot_classifier
            _orig_clf._cache = _slot_cache
            _orig_clf._orig_classify = _orig_clf.classify
            _orig_clf._orig_classify_batch = _orig_clf.classify_batch

            def _cached_classify_batch(self, funcs, report, arch):
                return [_cached_classify(self, "", f.get("name", ""), report, arch) for f in funcs]

            def _cached_classify(self, code, name, report, arch):
                cache = getattr(self, '_cache', {})
                if name in cache:
                    return cache[name]
                return (_heuristic_slot(name, arch), f"cache-miss: {name}", 0.4)

            import types
            _orig_clf.classify_batch = types.MethodType(_cached_classify_batch, _orig_clf)
            _orig_clf.classify = types.MethodType(_cached_classify, _orig_clf)

    icfg_source = "call_graph"
    icfg_path = ""

    # ── Ablation A: uniform edge weights ──
    if uniform_edges and archetype:
        archetype.edge_weight_profile = {k: 1.0 for k in archetype.edge_weight_profile}
        archetype.edge_weight_profile["call_to_log"] = 1.0

    edge_selector = EdgeSelector(slot_classifier, prune_threshold=0.01, top_k=10)
    edge_selector.set_step1_functions(step1_func_names)

    # ── Ablation B: no slot termination, only depth + stagnation ──
    if no_slot_termination:
        class DepthOnlyTermination(TerminationController):
            def check(self, path_nodes, filled_required_slots, filled_optional_slots,
                      archetype, slot_history, has_outgoing_edges=True):
                depth = len(path_nodes)
                if depth > self.max_depth:
                    return TerminationDecision(reason=TerminationReason.TRUNCATED, message=f"Depth {depth}>{self.max_depth}")
                recent = slot_history[-self.stagnation_window:] if len(slot_history) >= self.stagnation_window else []
                if recent and not any(recent):
                    return TerminationDecision(reason=TerminationReason.STUCK, message="No slot progress")
                return TerminationDecision(reason=TerminationReason.CONTINUE)
        termination = DepthOnlyTermination(max_depth=12, stagnation_window=3)
    else:
        termination = TerminationController(max_depth=12, stagnation_window=3)
    engine = ArchetypeSearchEngine(
        icfg=icfg, slot_classifier=slot_classifier, edge_selector=edge_selector,
        termination=termination, cwe_mapper=cwe_mapper_obj,
        max_frontier_size=400, max_results=5,
    )

    # Pass step1 function names for call site prioritization
    engine.set_step1_functions(step1_func_names)

    search_results = engine.search(top_funcs, issue_description, cve_id, language)

    explanations = []
    for i, path in enumerate(search_results):
        edges = getattr(path, 'edges', [])
        nodes = getattr(path, 'nodes', [])
        filled_slots = getattr(path, 'filled_slots', {})

        path_chain = []
        for e in edges:
            path_chain.append({
                "from": e.get("from_func", e.get("from", "")),
                "to": e.get("to_func", e.get("to", "")),
                "edge_type": e.get("edge_type", ""),
                "prob": e.get("score", e.get("prob", 0)),
                "slot": e.get("slot", ""),
            })

        snippets = extract_code_snippets(
            repo_path=repo_path, path_chain=path_chain, nodes=nodes,
            entry_function=path.entry_function, sink_function="",
        )

        explanations.append({
            "function_rank": i + 1,
            "entry_function": path.entry_function,
            "entry_file": path.entry_file,
            "entry_line": path.entry_line,
            "archetype": archetype.family,
            "archetype_display": archetype.display_name,
            "filled_slots": filled_slots,
            "slot_count": len(filled_slots),
            "required_slots": list(archetype.required_slot_names),
            "sink": filled_slots.get("Sink", filled_slots.get("Execute", "")),
            "terminated_at_sink": path.termination_reason == "archetype_complete",
            "termination_reason": path.termination_reason,
            "confidence": getattr(path, 'confidence', 0),
            "path_chain": path_chain,
            "nodes": nodes,
            "code_snippets": snippets,
            "cumulative_score": getattr(path, 'cumulative_score', 0),
            "nl_summary": f"Archetype: {archetype.display_name}, slots: {len(filled_slots)}/{len(archetype.slots)}",
        })

    # ── Supplementary entries: include high-score step1 functions ──
    # Strategy: s1_th=0.5_minK=2 — pred = {step1 funcs with score >= 0.5}, min 2
    traced_funcs = {e.get("entry_function", "").lower() for e in explanations}
    for func_info in step1_result.get("vulnerable_functions", []):
        fn = func_info.get("function", "")
        score = func_info.get("score", 0)
        if not fn or fn.lower() in traced_funcs:
            continue
        if score < 0.5:
            continue
        ffile = func_info.get("file", "")
        line = func_info.get("start_line", 0)
        explanations.append({
            "function_rank": len(explanations) + 1,
            "entry_function": fn,
            "entry_file": ffile,
            "entry_line": line,
            "archetype": archetype.family,
            "archetype_display": archetype.display_name,
            "filled_slots": {},
            "slot_count": 0,
            "required_slots": [],
            "sink": "",
            "terminated_at_sink": False,
            "termination_reason": "step1_supplementary",
            "confidence": score,
            "path_chain": [],
            "nodes": [],
            "code_snippets": {},
            "cumulative_score": score,
            "nl_summary": f"Supplementary: step1 prediction (score={score:.3f})",
        })
        traced_funcs.add(fn.lower())

    # Min-k=2 fallback: ensure at least 2 predicted functions per CVE
    if len(explanations) < 2:
        for func_info in step1_result.get("vulnerable_functions", []):
            fn = func_info.get("function", "")
            if not fn or fn.lower() in traced_funcs:
                continue
            ffile = func_info.get("file", "")
            score = func_info.get("score", 0)
            line = func_info.get("start_line", 0)
            explanations.append({
                "function_rank": len(explanations) + 1,
                "entry_function": fn,
                "entry_file": ffile,
                "entry_line": line,
                "archetype": archetype.family,
                "archetype_display": archetype.display_name,
                "filled_slots": {},
                "slot_count": 0,
                "required_slots": [],
                "sink": "",
                "terminated_at_sink": False,
                "termination_reason": "step1_min_k_fallback",
                "confidence": score,
                "path_chain": [],
                "nodes": [],
                "code_snippets": {},
                "cumulative_score": score,
                "nl_summary": f"Fallback: min-k=2 (score={score:.3f})",
            })
            traced_funcs.add(fn.lower())
            if len(explanations) >= 2:
                break

    num_complete = sum(1 for e in explanations if e.get("terminated_at_sink"))
    avg_slots = sum(e.get("slot_count", 0) for e in explanations) / max(len(explanations), 1)
    avg_conf = sum(e.get("confidence", 0) for e in explanations) / max(len(explanations), 1)

    icfg_stats = icfg.stats if isinstance(icfg.stats, dict) else icfg.stats()
    return {
        "cve_id": cve_id, "step2_mode": "archetype", "archetype": archetype.family,
        "icfg_source": icfg_source, "icfg_path": icfg_path,
        "icfg_stats": icfg_stats, "explanations": explanations,
        "trace_statistics": {
            "num_traced": len(explanations), "num_archetype_complete": num_complete,
            "avg_slots_filled": round(avg_slots, 1), "avg_confidence": round(avg_conf, 3),
        },
        "selection_reason": "call_graph",
    }


# ---------------------------------------------------------------------------
# Step 2 Ablation: Variant 1 — LLM-guided graph search (no CWE prototype)
# ---------------------------------------------------------------------------

def _llm_call_fallback(prompt: str, max_tokens: int = 500, temperature: float = 0.1) -> str:
    """Call LLM with fallback: OPENAI_DS → DEEPSEEK. Returns response text or raises."""
    import httpx
    from openai import OpenAI
    from shared.config import (OPENAI_DS_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL,
                                DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL)
    backends = []
    if OPENAI_DS_API_KEY and OPENAI_BASE_URL:
        backends.append((OpenAI(api_key=OPENAI_DS_API_KEY, base_url=OPENAI_BASE_URL,
                                max_retries=1, timeout=httpx.Timeout(60.0)), OPENAI_MODEL))
    if DEEPSEEK_API_KEY:
        backends.append((OpenAI(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL,
                                max_retries=1, timeout=httpx.Timeout(60.0)), "deepseek-chat"))
    if not backends:
        raise RuntimeError("No LLM backend available")

    last_error = None
    for client, model in backends:
        try:
            resp = client.chat.completions.create(
                model=model, messages=[{"role": "user", "content": prompt}],
                temperature=temperature, max_tokens=max_tokens,
            )
            return resp.choices[0].message.content or ""
        except Exception as e:
            last_error = e
    raise last_error or RuntimeError("All LLM backends failed")


def run_step2_llm_guided(
    cve_id: str, issue_description: str, language: str,
    step1_result: dict, repo_path: str,
) -> Optional[dict]:
    """Ablation: LLM decides edge selection and termination (no CWE prototype).

    Replaces EdgeSelector + TerminationController with LLM calls.
    Still traverses tree-sitter call graph.
    """
    from step2_explainer.ts_call_builder import build_call_graph
    from step2_explainer.code_extractor import extract_code_snippets

    top_funcs = step1_result.get("vulnerable_functions", [])[:5]
    if not top_funcs:
        return None

    step1_func_names = [f.get("function", "") for f in top_funcs]
    step1_target_funcs = {f.lower() for f in step1_func_names[:20]}

    target_files = [os.path.join(repo_path, f.get("file", ""))
                    for f in step1_result.get("vulnerable_files", [])[:30] if f.get("file")]
    cg = build_call_graph(repo_path, language, target_files=target_files,
                          target_functions=step1_target_funcs, max_depth=5, max_files=300,
                          timeout_seconds=60.0)

    explanations = []
    for i, func_info in enumerate(top_funcs):
        entry_name = func_info.get("function", "")
        entry_file = func_info.get("file", "")
        if not entry_name:
            continue

        entry_node = cg.get_entry_node(entry_name) if hasattr(cg, 'get_entry_node') else None
        if entry_node is None or cg.graph is None or entry_node not in cg.graph:
            continue
        edges = []
        for succ in cg.graph.successors(entry_node):
            data = cg.get_node_data(succ) if hasattr(cg, 'get_node_data') else {}
            edges.append({
                "to_func": data.get("name", succ.split(":")[1] if ":" in succ else succ),
                "to_file": data.get("file", succ.split(":")[0] if ":" in succ else ""),
                "to_line": data.get("line", 0),
                "edge_type": "call",
            })
        if not edges:
            continue

        edge_list = "\n".join(
            f"{j+1}. {e.get('to_func','?')} [{e.get('edge_type','?')}] (file: {e.get('to_file','?')})"
            for j, e in enumerate(edges[:15])
        )
        prompt = f"""Vulnerability Report: {issue_description[:2000]}
Entry Function: {entry_name} (file: {entry_file})

Candidate callees (possible next steps in exploit chain):
{edge_list}

Select up to 5 most relevant callees. Assign roles: InputSource, Transform, Sanitizer, CryptoOperation, MemoryOperation, Execute, Exposure.
Output JSON: {{"selected": [{{"idx": <number>, "role": "<role>", "reason": "<brief>"}}], "should_continue": true/false, "termination_reason": "<brief>"}}
"""
        try:
            raw = _llm_call_fallback(prompt, max_tokens=500, temperature=0.1)
            raw = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            llm_out = json.loads(raw)
        except Exception as e:
            print(f"    LLM edge selection failed for {entry_name}: {e}", flush=True)
            continue

        selected = llm_out.get("selected", [])
        roles = {s["idx"]: s["role"] for s in selected if "idx" in s}

        # Build path chain from LLM selections
        path_chain = []
        nodes = [f"{entry_file}:func:{0}"]
        for sel in selected[:5]:
            idx = sel.get("idx", 1) - 1
            if 0 <= idx < len(edges):
                e = edges[idx]
                path_chain.append({
                    "from": entry_name, "to": e.get("to_func", ""),
                    "edge_type": e.get("edge_type", ""), "prob": 1.0,
                    "slot": sel.get("role", ""),
                })
                to_file = e.get("to_file", "")
                to_line = e.get("to_line", 0)
                nodes.append(f"{to_file}:func:{to_line}" if to_line else f"{to_file}:func:0")

        snippets = extract_code_snippets(repo_path=repo_path, path_chain=path_chain, nodes=nodes,
                                         entry_function=entry_name, sink_function="")

        explanations.append({
            "function_rank": i+1, "entry_function": entry_name,
            "entry_file": entry_file, "entry_line": 0,
            "archetype": "LLMGuided", "archetype_display": "LLM-Guided Search",
            "filled_slots": {s["role"]: nodes[min(s["idx"], len(nodes)-1)] for s in selected},
            "slot_count": len(selected), "required_slots": [],
            "sink": "", "terminated_at_sink": not llm_out.get("should_continue", True),
            "termination_reason": llm_out.get("termination_reason", "llm_stop"),
            "confidence": 0.7, "path_chain": path_chain, "nodes": nodes,
            "code_snippets": snippets, "cumulative_score": len(selected),
            "nl_summary": f"LLM-guided: {len(selected)} functions, reason={llm_out.get('termination_reason','?')}",
        })

    return {
        "cve_id": cve_id, "step2_mode": "llm_guided",
        "icfg_source": "call_graph", "icfg_path": "",
        "icfg_stats": cg.stats if hasattr(cg, 'stats') and isinstance(cg.stats, dict) else cg.stats() if hasattr(cg, 'stats') else {},
        "explanations": explanations,
        "trace_statistics": {"num_traced": len(explanations), "num_archetype_complete": 0,
                             "avg_slots_filled": 0, "avg_confidence": 0.7},
        "selection_reason": "llm_guided",
    }


# ---------------------------------------------------------------------------
# Step 2 Ablation: Variant 2 — Pure LLM (no graph search)
# ---------------------------------------------------------------------------

def run_step2_pure_llm(
    cve_id: str, issue_description: str, language: str,
    step1_result: dict, repo_path: str,
) -> Optional[dict]:
    """Ablation: LLM directly outputs explanation from issue report + source code.

    No graph traversal, no static analysis. Pure prompt engineering.
    """
    from step2_explainer.code_extractor import extract_code_snippets

    top_funcs = step1_result.get("vulnerable_functions", [])[:5]
    if not top_funcs:
        return None

    # Extract source code for top functions
    func_sources = []
    for fi in top_funcs:
        fname = fi.get("function", "")
        ffile = fi.get("file", "")
        if not fname or not ffile:
            continue
        full_path = os.path.join(repo_path, ffile)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            content = ""
        if content:
            # Find function in file
            lines = content.split("\n")
            import re
            escaped = re.escape(fname)
            found_lines = []
            for li, line in enumerate(lines):
                if re.search(rf'\b{escaped}\b', line):
                    start = max(0, li-5)
                    end = min(len(lines), li+60)
                    found_lines = [f"{j+1}| {lines[j]}" for j in range(start, end)]
                    break
            func_sources.append({
                "function": fname, "file": ffile,
                "code": "\n".join(found_lines) if found_lines else content[:3000],
            })

    if not func_sources:
        return None

    # Build prompt
    func_desc = "\n\n".join(
        f"### {fs['function']} ({fs['file']})\n```\n{fs['code'][:2000]}\n```"
        for fs in func_sources[:3]
    )

    prompt = f"""You are a vulnerability explanation expert. Given a CVE report and source code of suspicious functions, produce an exploit chain explanation.

CVE: {cve_id}
Vulnerability Report:
{issue_description[:2000]}

Suspicious Functions (from vulnerability localization):
{func_desc}

Output a JSON object with:
- "exploit_chain": array of steps, each with: "function" (name), "file" (path), "role" (InputSource/Transform/Sanitizer/Execute/MemoryOperation/Exposure), "line_numbers" (relevant line numbers), "description" (1 sentence why relevant)
- "entry_point": {{"function": "...", "file": "..."}}
- "sink": {{"function": "...", "file": "..."}}
- "summary": 1-2 sentence summary of the vulnerability trigger path

Output ONLY valid JSON, no markdown fences.
"""
    try:
        raw = _llm_call_fallback(prompt, max_tokens=1000, temperature=0.1)
        raw = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        llm_out = json.loads(raw)
    except Exception as e:
        print(f"    Pure LLM failed for {cve_id}: {e}", flush=True)
        return None

    chain = llm_out.get("exploit_chain", [])
    path_chain = []
    nodes = []
    for step in chain:
        fn = step.get("function", "")
        ff = step.get("file", "")
        role = step.get("role", "")
        path_chain.append({"from": "", "to": fn, "edge_type": "llm", "prob": 1.0, "slot": role})
        nodes.append(f"{ff}:func:0")

    snippets = extract_code_snippets(repo_path=repo_path, path_chain=path_chain, nodes=nodes,
                                     entry_function=llm_out.get("entry_point", {}).get("function", ""),
                                     sink_function=llm_out.get("sink", {}).get("function", ""))

    explanations = [{
        "function_rank": 1, "entry_function": llm_out.get("entry_point", {}).get("function", ""),
        "entry_file": llm_out.get("entry_point", {}).get("file", ""), "entry_line": 0,
        "archetype": "PureLLM", "archetype_display": "Pure LLM (no graph)",
        "filled_slots": {s.get("role", ""): f"{s.get('file','')}:func:0" for s in chain},
        "slot_count": len(chain), "required_slots": [],
        "sink": llm_out.get("sink", {}).get("function", ""),
        "terminated_at_sink": bool(llm_out.get("sink", {}).get("function")),
        "termination_reason": "llm_complete",
        "confidence": 0.7, "path_chain": path_chain, "nodes": nodes,
        "code_snippets": snippets, "cumulative_score": len(chain),
        "nl_summary": llm_out.get("summary", ""),
    }]

    return {
        "cve_id": cve_id, "step2_mode": "pure_llm",
        "icfg_source": "none", "icfg_path": "",
        "icfg_stats": {}, "explanations": explanations,
        "trace_statistics": {"num_traced": 1, "num_archetype_complete": 0,
                             "avg_slots_filled": len(chain), "avg_confidence": 0.7},
        "selection_reason": "pure_llm",
    }


# ---------------------------------------------------------------------------
# Step 2 Ablation: Variant 2 — Pure LLM + CWE prototype + slot guidance
# ---------------------------------------------------------------------------

def run_step2_llm_cwe(
    cve_id: str, issue_description: str, language: str,
    step1_result: dict, repo_path: str,
) -> Optional[dict]:
    """Ablation: Pure LLM with CWE prototype knowledge and slot structure.

    No graph traversal — but LLM receives archetype slots and CWE context
    to guide its explanation output.
    """
    from step2_explainer.code_extractor import extract_code_snippets
    from step2_explainer.cwe_archetypes.archetype_library import get_archetype
    from step2_explainer.cwe_archetypes.cwe_mapper import CWEMapper

    top_funcs = step1_result.get("vulnerable_functions", [])[:5]
    if not top_funcs:
        return None

    # Get archetype/prototype
    cwe_ids = step1_result.get("cwe_ids", [])
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    nvd_dir = os.path.join(project_root, "Dataset", "DataFeed")
    cwe_csv = os.path.join(nvd_dir, "1000.csv")
    archetype = None
    if os.path.isfile(cwe_csv):
        try:
            cwe_mapper_obj = CWEMapper(nvd_dir=nvd_dir, cwe_csv_path=cwe_csv)
            archetype = cwe_mapper_obj.get_archetype_for_cve(cve_id)
        except Exception:
            pass
    if archetype is None or archetype.family == "Generic":
        archetype = get_archetype(cwe_ids[0]) if cwe_ids else get_archetype("")

    # Describe slots to LLM
    slot_desc = []
    for s in archetype.slots:
        req = "REQUIRED" if s.name in archetype.required_slot_names else "optional"
        slot_desc.append(f"  - {s.name} ({req}): {s.description[:200]}")
    slot_text = "\n".join(slot_desc)
    edge_profile = {k: v for k, v in archetype.edge_weight_profile.items() if v > 1.0}

    # Extract source code for top functions
    func_sources = []
    for fi in top_funcs:
        fname = fi.get("function", "")
        ffile = fi.get("file", "")
        if not fname or not ffile:
            continue
        full_path = os.path.join(repo_path, ffile)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            content = ""
        if content:
            lines = content.split("\n")
            import re
            escaped = re.escape(fname)
            found_lines = []
            for li, line in enumerate(lines):
                if re.search(rf'\b{escaped}\b', line):
                    start = max(0, li-5)
                    end = min(len(lines), li+60)
                    found_lines = [f"{j+1}| {lines[j]}" for j in range(start, end)]
                    break
            func_sources.append({
                "function": fname, "file": ffile,
                "code": "\n".join(found_lines) if found_lines else content[:3000],
            })

    if not func_sources:
        return None

    func_desc = "\n\n".join(
        f"### {fs['function']} ({fs['file']})\n```\n{fs['code'][:2000]}\n```"
        for fs in func_sources[:3]
    )

    prompt = f"""You are a vulnerability explanation expert using a CWE prototype framework.

CVE: {cve_id}
CWE Archetype: {archetype.family} — {archetype.display_name}
Vulnerability Report: {issue_description[:2000]}

PROTOTYPE SLOTS (fill as many as possible in order):
{slot_text}

Edge priority hints (edges to these roles preferred): {json.dumps(edge_profile)}

Suspicious Functions:
{func_desc}

Output a JSON object with:
- "entry_point": {{"function": "...", "file": "..."}}
- "sink": {{"function": "...", "file": "..."}}
- "filled_slots": {{"SlotName": "FunctionName"}} (map each matched slot to a function from the code)
- "exploit_chain": array of steps, each: {{"function", "file", "role" (slot name), "line_numbers", "description"}}
- "termination_reason": "archetype_complete" if all REQUIRED slots filled, else "partial"
- "summary": 1-2 sentence summary

Output ONLY valid JSON, no markdown.
"""
    try:
        raw = _llm_call_fallback(prompt, max_tokens=1200, temperature=0.1)
        raw = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        llm_out = json.loads(raw)
    except Exception as e:
        print(f"    LLM+CWE failed for {cve_id}: {e}", flush=True)
        return None

    chain = llm_out.get("exploit_chain", [])
    filled = llm_out.get("filled_slots", {})
    path_chain = []
    nodes = []
    for step in chain:
        fn = step.get("function", "")
        ff = step.get("file", "")
        role = step.get("role", "")
        path_chain.append({"from": "", "to": fn, "edge_type": "llm_cwe", "prob": 1.0, "slot": role})
        nodes.append(f"{ff}:func:0")

    snippets = extract_code_snippets(repo_path=repo_path, path_chain=path_chain, nodes=nodes,
                                     entry_function=llm_out.get("entry_point", {}).get("function", ""),
                                     sink_function=llm_out.get("sink", {}).get("function", ""))

    explanations = [{
        "function_rank": 1, "entry_function": llm_out.get("entry_point", {}).get("function", ""),
        "entry_file": llm_out.get("entry_point", {}).get("file", ""), "entry_line": 0,
        "archetype": archetype.family, "archetype_display": f"LLM+CWE: {archetype.display_name}",
        "filled_slots": {k: ":func:0" for k in filled},
        "slot_count": len(filled), "required_slots": list(archetype.required_slot_names),
        "sink": llm_out.get("sink", {}).get("function", ""),
        "terminated_at_sink": llm_out.get("termination_reason") == "archetype_complete",
        "termination_reason": llm_out.get("termination_reason", "llm_cwe"),
        "confidence": 0.7, "path_chain": path_chain, "nodes": nodes,
        "code_snippets": snippets, "cumulative_score": len(chain),
        "nl_summary": llm_out.get("summary", ""),
    }]

    return {
        "cve_id": cve_id, "step2_mode": "llm_cwe",
        "icfg_source": "none", "icfg_path": "",
        "icfg_stats": {}, "explanations": explanations,
        "trace_statistics": {"num_traced": 1, "num_archetype_complete": 0,
                             "avg_slots_filled": len(filled), "avg_confidence": 0.7},
        "selection_reason": "llm_cwe",
    }


# ---------------------------------------------------------------------------
# Step 2: Explanation (greedy PathTracer)
# ---------------------------------------------------------------------------

def run_step2(
    cve_id: str,
    issue_description: str,
    language: str,
    step1_result: dict,
    repo_path: str,
) -> Optional[dict]:
    """Run Step 2: ICFG-based explanation for top-5 functions."""
    from shared.icfg_loader import load_icfg_if_exists
    from shared.static_selector import select_best_icfg
    from step2_explainer.path_tracer import PathTracer
    from step2_explainer.code_extractor import extract_code_snippets
    from step2_explainer.nl_explainer import generate_explanation
    from step2_explainer.formatter import format_explanation

    # Select ICFG
    selection = select_best_icfg(cve_id, language=language, strategy="merge")
    if not selection.selected_path:
        return {
            "cve_id": cve_id,
            "error": "no_icfg",
            "selection_reason": selection.selection_reason,
            "explanations": [],
        }

    icfg = load_icfg_if_exists(selection.selected_path)
    if icfg is None:
        return {
            "cve_id": cve_id,
            "error": "icfg_load_failed",
            "icfg_path": selection.selected_path,
            "explanations": [],
        }

    # Get top functions from Step 1
    top_funcs = step1_result.get("vulnerable_functions", [])[:5]
    if not top_funcs:
        return {"cve_id": cve_id, "error": "no_functions", "explanations": []}

    # Collect evidence from Step 1 results
    evidence = []
    for vf in step1_result.get("vulnerable_files", [])[:5]:
        ev = vf.get("evidence", {})
        if ev.get("matching_issues"):
            evidence.append(f"Issue(s): {ev['matching_issues']}")
        if ev.get("matching_commits"):
            evidence.append(f"Commit(s): {ev['matching_commits']}")
    evidence.append(step1_result.get("analysis_summary", ""))

    vuln_types = detect_vuln_types(issue_description)

    # Trace each function
    tracer = PathTracer(icfg, tau=0.3, max_depth=15)
    explanations = []

    for i, func_info in enumerate(top_funcs):
        func_name = func_info.get("function", "")
        if not func_name:
            continue

        trace_result = tracer.trace(func_name, vuln_types, language)
        if trace_result is None:
            explanations.append({
                "function_rank": i + 1,
                "entry_function": func_name,
                "error": "entry_node_not_found",
            })
            continue

        # Extract code snippets for path nodes
        snippets = extract_code_snippets(
            repo_path=repo_path,
            path_chain=trace_result.path_chain,
            nodes=trace_result.nodes,
            entry_function=func_name,
            sink_function=trace_result.sink,
        )

        # Generate NL explanation
        nl = generate_explanation(
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
                "entry_function": trace_result.entry_function,
                "entry_file": trace_result.entry_file,
                "entry_line": trace_result.entry_line,
                "sink": trace_result.sink,
                "terminated_at_sink": trace_result.terminated_at_sink,
                "path_chain": trace_result.path_chain,
                "nodes": trace_result.nodes,
                "code_snippets": snippets,
                "cumulative_score": trace_result.cumulative_score,
            },
            nl_explanation=nl,
            evidence_from_step1=evidence,
            function_rank=i + 1,
        )
        explanations.append(exp)

    # Trace statistics
    num_sink_hit = sum(1 for e in explanations if e.get("terminated_at_sink"))

    return {
        "cve_id": cve_id,
        "icfg_source": selection.source_type,
        "icfg_path": selection.selected_path,
        "icfg_stats": icfg.stats(),
        "explanations": explanations,
        "trace_statistics": {
            "num_traced": len(explanations),
            "num_sink_hit": num_sink_hit,
            "sink_match_rate": num_sink_hit / max(len(explanations), 1),
        },
        "selection_reason": selection.selection_reason,
    }


# ---------------------------------------------------------------------------
# Per-CVE pipeline
# ---------------------------------------------------------------------------

def run_single_cve(
    entry: dict,
    output_dir: str = OUTPUT_DIR,
    skip_step2: bool = False,
    no_agent: bool = False,
    no_refine: bool = False,
    no_kg: bool = False,
    step2_mode: str = "greedy",
    mock_nl: bool = False,
    uniform_edges: bool = False,
    no_slot_termination: bool = False,
) -> dict:
    """Run full pipeline for a single CVE.

    Returns the combined result dict.
    """
    cve_id = entry["cve_id"]
    owner = entry.get("owner", "")
    project = entry.get("project", "")
    language = _get_language(entry)
    title, body, issue_description = _build_issue_description(entry)
    before_date = _get_earliest_issue_date(entry)

    if not title and not body:
        return {
            "cve_id": cve_id,
            "error": "empty_issue",
            "vulnerable_files": [],
            "vulnerable_functions": [],
        }

    # Find repo
    repo_path = entry.get("repo_path") or os.path.join(REPO_BASE, f"{owner}_{project}")
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return {
            "cve_id": cve_id,
            "error": "no_repo",
            "vulnerable_files": [],
            "vulnerable_functions": [],
        }

    if no_kg:
        # No-KG mode: skip RMS DB, use NoKGRetriever
        from step1_locator.retriever import NoKGRetriever
        retriever = NoKGRetriever(repo_path=repo_path)
        print(f"  RMS: No-KG mode (no BM25, no issues, no hotspots)")
    else:
        # Load per-CVE RMS (must be pre-built by build_all_rms.py)
        db_path = _get_db_path(owner, project, cve_id)
        from step1_locator.retriever import Retriever

        if not os.path.exists(db_path):
            print(f"  ERROR: RMS DB not found at {db_path}")
            print(f"  Run: python3 build_all_rms.py --cves {cve_id}")
            return {
                "cve_id": cve_id,
                "error": "no_rms_db",
                "vulnerable_files": [],
                "vulnerable_functions": [],
            }

        retriever = Retriever(db_path, repo_path=repo_path)
        stats = retriever.stats()
        print(f"  RMS: {stats['commits']} commits, {stats['hotspots']} hotspots, "
              f"{stats['linked_issues']} linked issues")

    # Checkout repo to fix-commit parent (last vulnerable state)
    import subprocess
    fix_parent = _find_fix_parent(repo_path, entry, retriever)
    if fix_parent:
        subprocess.run(
            ["git", "-C", repo_path, "checkout", "-q", fix_parent],
            capture_output=True, timeout=30,
        )
        print(f"  Checked out to {fix_parent[:8]} (fix parent)")

    # Step 1
    print(f"  Step 1: Localizing ...")
    t1 = time.time()
    try:
        result = run_step1(
            cve_id=cve_id,
            issue_title=title,
            issue_body=body,
            language=language,
            before_date=before_date,
            owner=owner,
            project=project,
            retriever=retriever,
            repo_path=repo_path,
            no_agent=no_agent,
            no_refine=no_refine,
            no_kg=no_kg,
        )
    except Exception as e:
        traceback.print_exc()
        retriever.close()
        return {"cve_id": cve_id, "error": f"step1_failed: {e}"}

    step1_elapsed = time.time() - t1
    result["step1_elapsed"] = round(step1_elapsed, 1)

    # Step 2 (optional)
    if not skip_step2:
        mode_names = {"archetype": "Archetype", "greedy": "Greedy PathTracer",
                      "llm_guided": "LLM-Guided", "pure_llm": "Pure LLM", "llm_cwe": "LLM+CWE"}
        mode_name = mode_names.get(step2_mode, step2_mode)
        print(f"  Step 2 ({mode_name}): top-{min(5, len(result.get('vulnerable_functions', [])))} functions ...")
        t2 = time.time()
        try:
            if step2_mode == "archetype":
                if mock_nl:
                    _patch_nl()
                step2_result = run_step2_archetype(
                    cve_id=cve_id, issue_description=issue_description,
                    language=language, step1_result=result, repo_path=repo_path,
                    mock_nl=mock_nl,
                    uniform_edges=uniform_edges, no_slot_termination=no_slot_termination,
                )
            elif step2_mode == "llm_guided":
                step2_result = run_step2_llm_guided(
                    cve_id=cve_id, issue_description=issue_description,
                    language=language, step1_result=result, repo_path=repo_path,
                )
            elif step2_mode == "pure_llm":
                step2_result = run_step2_pure_llm(
                    cve_id=cve_id, issue_description=issue_description,
                    language=language, step1_result=result, repo_path=repo_path,
                )
            elif step2_mode == "llm_cwe":
                step2_result = run_step2_llm_cwe(
                    cve_id=cve_id, issue_description=issue_description,
                    language=language, step1_result=result, repo_path=repo_path,
                )
            else:
                if mock_nl:
                    _patch_nl()
                step2_result = run_step2(
                    cve_id=cve_id, issue_description=issue_description,
                    language=language, step1_result=result, repo_path=repo_path,
                )
            if step2_result:
                result["step2"] = step2_result
                result["step2_elapsed"] = round(time.time() - t2, 1)
        except Exception as e:
            traceback.print_exc()
            result["step2_error"] = str(e)

    retriever.close()
    return result


# ---------------------------------------------------------------------------
# Batch runner
# ---------------------------------------------------------------------------

def _repo_lock_path(repo_path: str) -> str:
    """Get lock file path for a git repo to prevent concurrent checkouts."""
    return os.path.join(os.path.dirname(repo_path.rstrip("/")),
                        f".pipeline_lock_{os.path.basename(repo_path.rstrip('/'))}")


def _process_single_cve(args_tuple: tuple) -> dict:
    """Process a single CVE (entrypoint for ProcessPoolExecutor).

    Args:
        args_tuple: (entry, output_dir, skip_step2, no_agent, no_refine, no_kg, capture_log, step2_mode, mock_nl, uniform_edges, no_slot_termination)

    Returns: dict with cve_id, result, elapsed, error (if any)
    """
    entry, output_dir, skip_step2, no_agent, no_refine, no_kg, capture_log, step2_mode, mock_nl, uniform_edges, no_slot_termination = args_tuple
    cve_id = entry["cve_id"]
    t0 = time.time()

    def _run():
        return run_single_cve(
            entry, output_dir=output_dir, skip_step2=skip_step2,
            no_agent=no_agent, no_refine=no_refine, no_kg=no_kg,
            step2_mode=step2_mode, mock_nl=mock_nl,
            uniform_edges=uniform_edges, no_slot_termination=no_slot_termination,
        )

    log_buf = io.StringIO() if capture_log else None
    _ctx = (redirect_stdout(log_buf), redirect_stderr(log_buf)) if capture_log else None

    def _enter():
        if _ctx:
            _ctx[0].__enter__()
            _ctx[1].__enter__()

    def _exit():
        if _ctx:
            _ctx[1].__exit__(None, None, None)
            _ctx[0].__exit__(None, None, None)

    _enter()
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
        _write_report(cve_dir, result, entry.get("language", "unknown"))

        n_files = len(result.get("vulnerable_files", []))
        n_funcs = len(result.get("vulnerable_functions", []))
        step2_info = ""
        if not skip_step2 and "step2" in result:
            n_exp = len(result["step2"].get("explanations", []))
            n_sink = result["step2"].get("trace_statistics", {}).get("num_sink_hit", 0)
            step2_info = f" | {n_exp} explanations, {n_sink} sink-hits"

        return {
            "cve_id": cve_id,
            "success": True,
            "elapsed": elapsed,
            "n_files": n_files,
            "n_funcs": n_funcs,
            "step2_info": step2_info,
            "log": log_buf.getvalue() if log_buf else "",
        }
    except Exception as e:
        elapsed = time.time() - t0
        traceback.print_exc(file=log_buf if log_buf else sys.stderr)
        _exit()
        cve_dir = os.path.join(output_dir, cve_id)
        os.makedirs(cve_dir, exist_ok=True)
        with open(os.path.join(cve_dir, "result.json"), "w", encoding="utf-8") as f:
            json.dump({"cve_id": cve_id, "error": str(e)}, f)
        return {
            "cve_id": cve_id,
            "success": False,
            "elapsed": elapsed,
            "error": str(e),
            "log": log_buf.getvalue() if log_buf else "",
        }
    finally:
        _exit()


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
    step2_mode: str = "greedy",
    mock_nl: bool = False,
    uniform_edges: bool = False,
    no_slot_termination: bool = False,
) -> str:
    """Run pipeline on a batch of CVEs.

    Args:
        workers: number of parallel worker processes (default 1 = sequential)
        resume: skip CVEs whose result.json already exists in output_dir

    Returns output_dir path.
    """
    manifest = load_manifest(manifest_path)
    print(f"Loaded {len(manifest)} CVEs from manifest")

    if cve_list:
        cve_set = set(cve_list)
        manifest = [e for e in manifest if e["cve_id"] in cve_set]
        print(f"Filtered to {len(manifest)} specified CVEs")
    elif limit > 0:
        manifest = manifest[skip:skip + limit]
        print(f"Processing {len(manifest)} CVEs (skip={skip}, limit={limit})")
    else:
        manifest = manifest[skip:]
        print(f"Processing all {len(manifest)} CVEs (skip={skip})")

    if not manifest:
        print("No CVEs to process")
        return output_dir

    os.makedirs(output_dir, exist_ok=True)

    # Normalize all entries first (before forking for multiprocessing)
    print(f"Normalizing {len(manifest)} entries ...")
    for i, entry in enumerate(manifest):
        if (i + 1) % 200 == 0:
            print(f"  Normalized {i + 1}/{len(manifest)} ...")
        manifest[i] = _normalize_entry(entry)

    # Resume: skip CVEs with existing results
    if resume:
        print(f"Checking resume state ({len(manifest)} CVEs) ...")
        skipped = []
        remaining = []
        for i, entry in enumerate(manifest):
            cve_dir = os.path.join(output_dir, entry["cve_id"])
            if os.path.isfile(os.path.join(cve_dir, "result.json")):
                skipped.append(entry["cve_id"])
            else:
                remaining.append(entry)
            if (i + 1) % 200 == 0:
                print(f"  Checked {i + 1}/{len(manifest)} ...")
        if skipped:
            print(f"Resume: skipping {len(skipped)} already-completed CVEs")
        manifest = remaining
        if not manifest:
            print("All CVEs already completed. Nothing to do.")
            return output_dir

    success = 0
    fail = 0
    total_start = time.time()

    if workers <= 1:
        # Sequential mode — real-time output, no capture
        task_args = [
            (entry, output_dir, skip_step2, no_agent, no_refine, no_kg, False, step2_mode, mock_nl, uniform_edges, no_slot_termination)
            for entry in manifest
        ]
        pbar = tqdm(task_args, desc="Pipeline", unit="cve")
        for i, args_tuple in enumerate(pbar):
            entry = manifest[i]
            cve_id = entry["cve_id"]
            result = _process_single_cve(args_tuple)
            if result["success"]:
                pbar.set_postfix_str(f"{cve_id} {result['elapsed']:.0f}s {result['n_files']}f/{result['n_funcs']}fn")
                success += 1
            else:
                pbar.set_postfix_str(f"{cve_id} FAIL {result.get('error', 'unknown')[:30]}")
                fail += 1
        pbar.close()
    else:
        # Parallel mode — capture child output, use tqdm.write for failures
        task_args = [
            (entry, output_dir, skip_step2, no_agent, no_refine, no_kg, True, step2_mode, mock_nl, uniform_edges, no_slot_termination)
            for entry in manifest
        ]
        print(f"Running {len(manifest)} CVEs with {workers} workers ...")
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(_process_single_cve, a): a[0]["cve_id"] for a in task_args}
            pbar = tqdm(total=len(manifest), desc="Pipeline", unit="cve")
            for future in as_completed(futures):
                cve_id = futures[future]
                try:
                    result = future.result()
                    if result["success"]:
                        pbar.set_postfix_str(f"{cve_id} OK {result['elapsed']:.0f}s {result['n_files']}f/{result['n_funcs']}fn")
                        success += 1
                    else:
                        pbar.set_postfix_str(f"{cve_id} FAIL {result.get('error', 'unknown')[:30]}")
                        fail += 1
                        log = result.get("log", "")
                        if log:
                            tqdm.write(f"\n--- {cve_id} log ---\n{log.strip()[-2000:]}\n---")
                except Exception as e:
                    pbar.set_postfix_str(f"{cve_id} CRASH")
                    tqdm.write(f"\n--- {cve_id} crash ---\n{e}\n---")
                    fail += 1
                pbar.update(1)
            pbar.close()

    total_elapsed = time.time() - total_start

    # Summary
    summary = {
        "total_cves": len(manifest),
        "success": success,
        "failed": fail,
        "total_elapsed_seconds": round(total_elapsed, 1),
        "avg_seconds_per_cve": round(total_elapsed / max(success, 1), 1),
        "timestamp": datetime.now().isoformat(),
        "workers": workers,
        "resume": resume,
    }
    with open(os.path.join(output_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"DONE: {success} success, {fail} failed")
    print(f"Total time: {total_elapsed:.1f}s ({total_elapsed/60:.1f}m)")
    print(f"Results saved to: {output_dir}")
    print(f"{'='*60}")

    return output_dir


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_db_path(owner: str, project: str, cve_id: str) -> str:
    safe_name = f"{owner}___{project}___{cve_id}"
    return os.path.join(RMS_DB_DIR, f"{safe_name}.db")


def _find_fix_parent(repo_path: str, entry: dict, retriever) -> str:
    """Find the parent of the fix commit for a CVE using issue_links.

    Returns the SHA of the fix commit's parent (last vulnerable state),
    or empty string if no fix commit found.
    """
    import subprocess

    for issue in entry.get("issue_list", []):
        num = issue.get("id") or issue.get("number")
        if not num:
            continue
        row = retriever.get_issue_by_number(num)
        if row and row.get("commit_sha"):
            fix_sha = row["commit_sha"]
            # Get parent commit
            out = subprocess.run(
                ["git", "-C", repo_path, "rev-list", "-1", "--parents", fix_sha],
                capture_output=True, text=True, timeout=30,
            )
            parts = out.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1]  # second field = first parent
            elif len(parts) == 1 and parts[0]:
                return parts[0]  # root commit, no parent
    return ""


def _write_report(cve_dir: str, result: dict, language: str):
    lines = [
        f"CVE: {result.get('cve_id', '?')}",
        f"Time: {result.get('timestamp', '?')}",
        f"Language: {language}",
        f"Step 1 time: {result.get('step1_elapsed', '?')}s",
        "",
        f"--- Vulnerable Files ({len(result.get('vulnerable_files', []))}) ---",
    ]
    for vf in result.get("vulnerable_files", [])[:15]:
        lines.append(
            f"  [{vf.get('score', 0):.2f}] {vf.get('file', '?')}"
            f"  — {vf.get('reason', '')[:100]}"
        )
    lines.append("")
    lines.append(f"--- Vulnerable Functions ({len(result.get('vulnerable_functions', []))}) ---")
    for vf in result.get("vulnerable_functions", [])[:15]:
        lines.append(
            f"  [{vf.get('score', 0):.2f}] {vf.get('function', '?')}"
            f" @ {vf.get('file', '?')}"
            f"  — {vf.get('reason', '')[:100]}"
        )
    lines.append("")
    lines.append("--- Analysis Summary ---")
    lines.append(result.get("analysis_summary", "N/A")[:500])

    if "step2" in result:
        lines.append("")
        lines.append("--- Step 2 Explanations ---")
        for exp in result["step2"].get("explanations", [])[:5]:
            lines.append(f"  [{exp.get('function_rank', '?')}] {exp.get('entry_function', '?')}")
            lines.append(f"    Sink: {exp.get('sink', '?')} | Hit: {exp.get('terminated_at_sink', False)}")
            lines.append(f"    Summary: {exp.get('nl_summary', '')[:200]}")

    with open(os.path.join(cve_dir, "report.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Localization Pipeline — Step 1 + Step 2"
    )
    parser.add_argument("--limit", type=int, default=10,
                        help="Max CVEs (0=all, default: 10)")
    parser.add_argument("--skip", type=int, default=0,
                        help="Skip first N CVEs")
    parser.add_argument("--cves", type=str, default="",
                        help="Comma-separated CVE IDs")
    parser.add_argument("--output", type=str, default=None,
                        help="Output directory (default: Results/Localization or Results/Localization_NoKG)")
    parser.add_argument("--no-step2", action="store_true",
                        help="Skip Step 2 (explanation generation)")
    parser.add_argument("--no-agent", action="store_true",
                        help="Use heuristic-only mode (skip LLM agent)")
    parser.add_argument("--no-refine", action="store_true",
                        help="Skip second-pass function refinement")
    parser.add_argument("--manifest", type=str, default=None,
                        help="Manifest file path (default: Dataset/dataset_with_changed_files_filter.json for --no-kg, else full_manifest.json)")
    parser.add_argument("--no-kg", action="store_true",
                        help="No-KG ablation: skip RMS DB, BM25, issue links, hotspots")
    parser.add_argument("--workers", type=int, default=1,
                        help="Number of parallel worker processes (default: 1 = sequential)")
    parser.add_argument("--resume", action="store_true",
                        help="Skip CVEs whose result.json already exists in output dir")
    parser.add_argument("--step2-mode", type=str, default="greedy", choices=["greedy", "archetype", "llm_guided", "pure_llm", "llm_cwe"],
                        help="Step 2 mode: greedy PathTracer or CWE archetype guided search (default: greedy)")
    parser.add_argument("--mock-nl", action="store_true", default=False,
                        help="Skip LLM NL explanation, keep tracing only")
    parser.add_argument("--uniform-edges", action="store_true", default=False,
                        help="Ablation: all CWE edge weights = 1.0 (no edge selection)")
    parser.add_argument("--no-slot-termination", action="store_true", default=False,
                        help="Ablation: disable slot-based termination, use depth+stagnation only")

    args = parser.parse_args()

    cve_list = None
    if args.cves:
        cve_list = [c.strip() for c in args.cves.split(",") if c.strip()]

    if args.manifest:
        manifest_path = args.manifest
    elif args.no_kg:
        manifest_path = DATASET_PATH  # dataset_with_changed_files_filter.json
    else:
        manifest_path = MANIFEST_PATH

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
        no_agent=getattr(args, 'no_agent', False),
        no_refine=args.no_refine or args.no_kg,
        no_kg=args.no_kg,
        workers=args.workers,
        resume=args.resume,
        step2_mode=args.step2_mode,
        mock_nl=args.mock_nl,
        uniform_edges=args.uniform_edges,
        no_slot_termination=args.no_slot_termination,
    )
