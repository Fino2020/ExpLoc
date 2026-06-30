"""
Legacy Step 2 modes extracted from the original pipeline.py.

These are kept for backward compatibility and ablation experiments.
Active development uses call_site_windows (default in pipeline.py).
"""

import json
import os
import time
from typing import Dict, List, Optional, Tuple


def _llm_call_fallback(prompt: str, max_tokens: int = 500, temperature: float = 0.1) -> str:
    """Call LLM with fallback: OPENAI_DS -> DEEPSEEK. Returns response text or raises."""
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


# ---------------------------------------------------------------------------
# Step 2: Archetype-guided ICFG search
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

    # Keyword -> slot mappings (used by heuristic/fallback classifier)
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
        (["add", "sub", "mul", "div", "mod", "inc", "dec", "increment",
          "decrement", "multiply", "divide", "subtract", "compute",
          "calculate", "calc", "arithmetic", "int_op", "math_op", "numeric_op",
          "size_calc", "len_calc", "offset_calc", "count_calc"], "ArithmeticOperation"),
        (["size", "len", "length", "count", "num", "capacity", "max_size",
          "buf_size", "alloc_size", "data_size", "total_len", "byte_count",
          "element_count", "remaining", "avail", "left", "limit"], "MissingBoundsCheck"),
        (["transmit", "transfer", "send_over", "put_over", "push_data",
          "forward", "relay", "proxy", "pass_through", "tunnel",
          "route", "deliver", "dispatch_to", "forward_to"], "Transmit"),
        (["config", "conf", "setting", "option", "pref", "property",
          "env", "environment", "ctx", "context", "state", "global_var",
          "static_var", "module_var", "class_var", "member_var"], "Source"),
        (["protect", "guard", "safe", "safe_call", "checked", "bounded",
          "safe_copy", "bounds_check", "range_check", "limit_check",
          "size_check", "cap_check", "overflow_check", "underflow_check"], "ProtectedAccess"),
        (["weak", "insecure", "broken", "flawed", "vulnerable", "deprecated",
          "legacy", "old_api", "unsafe_api", "obsolete", "weak_algo",
          "weak_cipher", "md4", "md5", "sha1", "rc4", "des_ecb"], "WeakVerification"),
        (["convert", "transform", "convert_to", "change_type", "cast",
          "reinterpret", "type_cast", "coerce", "to_int", "to_str",
          "to_bytes", "from_bytes", "to_char", "wide_to_narrow",
          "narrow_to_wide", "encoding_convert", "charset_convert"], "Transform"),
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

    top_funcs = step1_result.get("vulnerable_functions", [])[:2]
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

    step1_func_names = [f.get("function", "") for f in step1_result.get("vulnerable_functions", [])[:30]]
    step1_target_funcs = {f.lower() for f in step1_func_names[:20]}

    from step2_explainer.ts_call_builder import build_call_graph

    target_files = [os.path.join(repo_path, f.get("file", ""))
                    for f in step1_result.get("vulnerable_files", [])[:50]
                    if f.get("file")]
    t0_cg = time.time()
    cg = build_call_graph(repo_path, language, target_files=target_files,
                          target_functions=step1_target_funcs, max_depth=5,
                          max_files=500, timeout_seconds=120.0)
    icfg = cg
    print(f"    Call graph: {cg.stats['nodes']} nodes, {cg.stats['edges']} edges "
          f"({time.time()-t0_cg:.1f}s)", flush=True)

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

    if uniform_edges and archetype:
        archetype.edge_weight_profile = {k: 1.0 for k in archetype.edge_weight_profile}
        archetype.edge_weight_profile["call_to_log"] = 1.0

    edge_selector = EdgeSelector(slot_classifier, prune_threshold=0.01, top_k=10)
    edge_selector.set_step1_functions(step1_func_names)

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
# Step 2 Ablation: LLM-guided graph search (no CWE prototype)
# ---------------------------------------------------------------------------

def run_step2_llm_guided(
    cve_id: str, issue_description: str, language: str,
    step1_result: dict, repo_path: str,
) -> Optional[dict]:
    """Ablation: LLM decides edge selection and termination (no CWE prototype)."""
    from step2_explainer.ts_call_builder import build_call_graph
    from step2_explainer.code_extractor import extract_code_snippets

    top_funcs = step1_result.get("vulnerable_functions", [])[:2]
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

        path_chain = []
        nodes = [f"{entry_file}:func:0"]
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
        "icfg_stats": cg.stats if isinstance(cg.stats, dict) else cg.stats(),
        "explanations": explanations,
        "trace_statistics": {"num_traced": len(explanations), "num_archetype_complete": 0,
                             "avg_slots_filled": 0, "avg_confidence": 0.7},
        "selection_reason": "llm_guided",
    }


# ---------------------------------------------------------------------------
# Step 2 Ablation: Pure LLM (no graph search)
# ---------------------------------------------------------------------------

def run_step2_pure_llm(
    cve_id: str, issue_description: str, language: str,
    step1_result: dict, repo_path: str,
) -> Optional[dict]:
    """Ablation: LLM directly outputs explanation from issue report + source code."""
    from step2_explainer.code_extractor import extract_code_snippets

    top_funcs = step1_result.get("vulnerable_functions", [])[:2]
    if not top_funcs:
        return None

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
# Step 2 Ablation: Pure LLM + CWE prototype + slot guidance
# ---------------------------------------------------------------------------

def run_step2_llm_cwe(
    cve_id: str, issue_description: str, language: str,
    step1_result: dict, repo_path: str,
) -> Optional[dict]:
    """Ablation: Pure LLM with CWE prototype knowledge and slot structure."""
    from step2_explainer.code_extractor import extract_code_snippets
    from step2_explainer.cwe_archetypes.archetype_library import get_archetype
    from step2_explainer.cwe_archetypes.cwe_mapper import CWEMapper

    top_funcs = step1_result.get("vulnerable_functions", [])[:2]
    if not top_funcs:
        return None

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

    slot_desc = []
    for s in archetype.slots:
        req = "REQUIRED" if s.name in archetype.required_slot_names else "optional"
        slot_desc.append(f"  - {s.name} ({req}): {s.description[:200]}")
    slot_text = "\n".join(slot_desc)
    edge_profile = {k: v for k, v in archetype.edge_weight_profile.items() if v > 1.0}

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
