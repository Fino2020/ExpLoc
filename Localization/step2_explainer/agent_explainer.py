"""
Two-Phase Agent for Exploit Chain Generation.

Phase 1: Keyword extraction from CVE report (1 LLM call, no tools)
Phase 2: Exploit chain tracing (3 rounds, SearchBackend + ICFG tools)

Key principle: SearchBackend for DISCOVERY, ICFG for VERIFICATION.
"""

import json
import os
import re
import subprocess
import sys
import time
from typing import Dict, List, Optional

_LOC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _LOC_DIR not in sys.path:
    sys.path.insert(0, _LOC_DIR)

from acr_baseline.model import ModelClient
from acr_baseline.search_backend import SearchBackend
from step2_explainer.icfg_tools import get_icfg_tools
from step2_explainer.code_extractor import extract_code_snippets


def verify_code_in_repo(repo_path: str, file_path: str, line: int) -> Optional[str]:
    """Read actual source code at (file, line) from repo. Returns None if not found."""
    if not repo_path or not file_path or line <= 0:
        return None
    full = os.path.join(repo_path, file_path) if not os.path.isabs(file_path) else file_path
    if not os.path.isfile(full):
        return None
    try:
        with open(full, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].rstrip()
    except Exception:
        pass
    return None


# ── Phase 1: Keyword Extraction ──────────────────────────────────────

PHASE1_PROMPT = """Extract key information from this CVE report for code search.

Output ONLY a JSON object inside ```json``` fences:
```json
{
  "suspicious_functions": ["func1", "func2"],
  "suspicious_files": ["path/to/file.c"],
  "search_terms": ["buffer overflow", "SSL verify", "strcpy"],
  "vulnerability_type": "buffer-overflow",
  "cwe_keywords": ["CWE-119", "input validation"]
}
```

RULES:
- suspicious_functions: function names EXACTLY as mentioned in the report
- suspicious_files: file paths mentioned (partial paths OK)
- search_terms: 3-6 distinctive code patterns, API calls, error messages from the report
- vulnerability_type: brief classification
- cwe_keywords: CWE-related terms from the report
"""

def _run_phase1(llm, desc: str) -> dict:
    """Extract keywords from CVE report via LLM (1 call, cached by caller)."""
    try:
        resp = llm.call(
            [{'role': 'user', 'content': f"{PHASE1_PROMPT}\n\nCVE REPORT:\n{desc[:3000]}"}],
            temperature=0.0, max_tokens=1024,
        )
    except Exception:
        return {}
    m = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', resp)
    if not m:
        return {}
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return {}


def _code_search_boost(repo_path: str, phase1: dict) -> set:
    """Use SearchBackend to find files/functions matching phase1 search_terms.
    Returns a set of (relative_file_path) strings to boost in call-site scoring.
    """
    if not repo_path or not phase1.get('search_terms'):
        return set()
    try:
        from acr_baseline.search_backend import SearchBackend
        backend = SearchBackend(repo_path)
    except Exception:
        return set()
    boosted = set()
    for term in phase1.get('search_terms', [])[:5]:
        try:
            _, results, ok = backend.search_code(term)
        except Exception:
            continue
        if not ok:
            continue
        for r in results[:10]:
            rel = os.path.relpath(r.file_path, repo_path) if os.path.isabs(r.file_path) else r.file_path
            boosted.add(rel)
            if r.func_name:
                boosted.add(f"func:{r.func_name.lower()}")
    return boosted


def _score_call_site(fp, fn, tgt, window, target_names, step1_files, phase1, search_boost=None) -> float:
    """Score a call site by step1 match + issue keyword relevance + code search boost."""
    score = 0.0
    fn_l = fn.lower(); tgt_l = tgt.lower(); fp_l = fp.lower(); w_l = window.lower()
    # Step1 exact function name match (highest weight)
    if fn in target_names: score += 100.0
    if tgt in target_names: score += 80.0
    # Step1 file boost: call sites in step1 top files get priority
    fp_basename = os.path.basename(fp)
    for sf in step1_files:
        if os.path.basename(sf) == fp_basename:
            score += 50.0
            break
    # Phase1 suspicious functions
    for sf in phase1.get('suspicious_functions', []):
        sf_l = sf.lower()
        if sf_l in fn_l: score += 20.0
        if sf_l in tgt_l: score += 16.0
    # Phase1 suspicious files
    for sf in phase1.get('suspicious_files', []):
        if os.path.basename(sf).lower() in fp_l or sf.lower() in fp_l:
            score += 8.0
    # Phase1 search terms in code window or names
    for st in phase1.get('search_terms', []):
        st_l = st.lower()
        if st_l in w_l: score += 4.0
        if st_l in fn_l: score += 3.0
        if st_l in tgt_l: score += 2.0
    # SearchBackend boost: files/functions found by code search
    if search_boost:
        if fp in search_boost:
            score += 30.0
        if f"func:{fn_l}" in search_boost:
            score += 25.0
        if f"func:{tgt_l}" in search_boost:
            score += 20.0
    return score


# ── Phase 2: Exploit Chain Tracing ───────────────────────────────────

PHASE2_SYSTEM = """You trace exploit chains from vulnerability reports using code search and call graph tools.

AVAILABLE TOOLS:
CODE SEARCH: search_code, search_method, search_class, read_file, get_code_around
CALL GRAPH: get_callees, get_callers, find_path
LINE PINPOINT: pinpoint_line(file, line_number) — verify a specific code line exists and get its content

RULES:
1. EVERY edge MUST have from_line > 0, to_line > 0, from_file, and to_file.
2. Use pinpoint_line(file, line) to verify each code line. Call it for EVERY line you output.
3. If pinpoint_line returns an error, find the correct line and re-verify.
4. from_code and to_code MUST be the actual code returned by pinpoint_line, not your guess.
5. Do NOT use line 0. Search for the actual line with search_code or read_file.

STRATEGY:
1. Extract specific API calls, function names, and file paths from the CVE report
2. Search for these using search_code/search_method
3. Read discovered files with read_file to understand the code
4. Use get_callees to find what vulnerable functions call (downstream sinks)
5. Use get_callers to trace where tainted data comes from (upstream sources)
6. Use find_path to connect source to sink through the call graph
7. For each function in the chain, read its code, then use pinpoint_line to verify vulnerable lines
8. Build the complete chain with verified file paths and line numbers for each edge

ARCHETYPE SLOTS:
- Source: where tainted data enters (user input, network recv)
- Propagation: functions that pass tainted data through
- MissingValidation: where a safety check is missing
- Sink: where the vulnerability manifests (overflow, exec, injection)

OUTPUT — JSON inside ```json``` fences. ALL edges MUST have line numbers verified by pinpoint_line:
```json
{
  "exploit_chains": [
    {
      "entry": {"function": "main", "file": "src/main.c", "line": 100, "code": "char *input = argv[1];"},
      "sink": {"function": "strcpy", "file": "src/util.c", "line": 150, "code": "strcpy(buf, input);", "vuln_type": "buffer-overflow"},
      "function_path": {
        "entry_function": "main",
        "entry_file": "src/main.c",
        "edges": [
          {"from_func": "main", "from_file": "src/main.c", "to_func": "parse_input", "to_file": "src/parse.c", "from_line": 100, "to_line": 120, "from_code": "char *input = argv[1];", "to_code": "void parse_input(char *s)", "edge_type": "call", "slot": "Source"},
          {"from_func": "parse_input", "from_file": "src/parse.c", "to_func": "strcpy", "to_file": "src/util.c", "from_line": 140, "to_line": 150, "from_code": "process_data(buf, input);", "to_code": "strcpy(buf, input);", "edge_type": "call", "slot": "Sink"}
        ]
      },
      "filled_slots": {"Source": "parse_input", "Sink": "strcpy"},
      "nl_summary": "Input from main → parse_input without validation → strcpy overflow"
    }
  ]
}
```

Output your best chain with line numbers verified by pinpoint_line. Partial chains OK — mark unverified lines as 0."""


TOOL_NAMES = r'(search_code|search_method|search_class|read_file|get_code_around|get_callees|get_callers|find_path|pinpoint_line)'

def _parse_tool_calls(text: str) -> List[tuple]:
    """Parse tool calls from LLM response (function-call, XML, function+parameters)."""
    calls = []
    # Format 1: function-call style: search_code("query", 42)
    pattern = TOOL_NAMES + r'\s*\(\s*["\']([^"\']+)["\'](?:\s*,\s*(\d+))?\s*\)'
    calls.extend(re.findall(pattern, text))
    # Format 1b: pinpoint_line with int arg: pinpoint_line("file.c", 42)
    ppattern = r'pinpoint_line\s*\(\s*["\']([^"\']+)["\']\s*,\s*(\d+)\s*\)'
    for m in re.finditer(ppattern, text):
        calls.append(("pinpoint_line", m.group(1), m.group(2)))
    # Format 2: Simple XML: <search_code>query</search_code>
    for pat, fn in [
        (r'<search_code>([^<]+)</search_code>', 'search_code'),
        (r'<search_method>([^<]+)</search_method>', 'search_method'),
        (r'<read_file[^>]*>([^<]+)</read_file>', 'read_file'),
        (r'<get_callees[^>]*>([^<]+)</get_callees>', 'get_callees'),
        (r'<get_callers[^>]*>([^<]+)</get_callers>', 'get_callers'),
        (r'<pinpoint_line[^>]*>\s*([^<]+?)\s*,\s*(\d+)\s*</pinpoint_line>', 'pinpoint_line'),
    ]:
        for m in re.finditer(pat, text):
            calls.append((fn, m.group(1).strip(), m.group(2).strip() if m.lastindex and m.lastindex >= 2 else ""))
    # Format 3: DeepSeek function XML: <function>tool_name</function><parameters>{"key":"val"}</parameters>
    fcall_pat = r'<function>\s*' + TOOL_NAMES + r'\s*</function>\s*<parameters>\s*(\{[^}]+\})\s*</parameters>'
    for m in re.finditer(fcall_pat, text):
        fn = m.group(1)
        try: params = json.loads(m.group(2))
        except json.JSONDecodeError: continue
        if not isinstance(params, dict):
            continue
        # Map JSON param keys to arg1, arg2
        arg1 = params.get("query", params.get("name", params.get("file_path",
                params.get("function", params.get("from_func", "")))))
        arg2 = str(params.get("line", params.get("line_number", "")))
        calls.append((fn, str(arg1), arg2))
    return list(dict.fromkeys(calls))[:15]


def _execute(backend, icfg, func_name, arg1, arg2, step1_names, repo_path=""):
    """Execute a tool call, return (result_str, ok, verified_line_or_none)."""
    try:
        if func_name == 'search_code':
            r, _, ok = backend.search_code(arg1)
            return (r[:1500] if ok else f"Not found: {arg1}", ok, None)
        elif func_name == 'search_method':
            r, _, ok = backend.search_method(arg1)
            return (r[:1500] if ok else f"Not found: {arg1}", ok, None)
        elif func_name == 'search_class':
            r, _, ok = backend.search_class(arg1)
            return (r[:1500] if ok else f"Not found: {arg1}", ok, None)
        elif func_name == 'read_file':
            r, _, ok = backend.get_file_content(arg1)
            return (r[:1500] if ok else f"Not found: {arg1}", ok, None)
        elif func_name == 'get_code_around':
            line = int(arg2) if arg2.isdigit() else 1
            r, _, ok = backend.get_code_around_line(arg1, line)
            return (r[:1500] if ok else f"Not found: {arg1}", ok, None)
        elif func_name == 'get_callees' and icfg:
            callees = icfg.get_callees(arg1, arg2 if arg2 else "")
            if not callees:
                callees = backend_search_fallback(icfg, arg1, backend)
            names = []
            for c in callees[:25]:
                marker = " ★" if c.get('function','') in step1_names else ""
                names.append(f"{c['function']} ({c.get('edge_type','?')}){marker}")
            return (f"Callees of {arg1}:\n  " + "\n  ".join(names) if names else f"No callees for {arg1}", bool(names), None)
        elif func_name == 'get_callers' and icfg:
            callers = icfg.get_callers(arg1, arg2 if arg2 else "")
            names = []
            for c in callers[:25]:
                marker = " ★" if c.get('function','') in step1_names else ""
                names.append(f"{c['function']} ({c.get('edge_type','?')}){marker}")
            return (f"Callers of {arg1}:\n  " + "\n  ".join(names) if names else f"No callers for {arg1}", bool(names), None)
        elif func_name == 'find_path' and icfg:
            path = icfg.find_path(arg1, arg2)
            return (f"Path: {' → '.join(path)}" if path else f"No path: {arg1} → {arg2}", bool(path), None)
        elif func_name == 'pinpoint_line':
            if not repo_path:
                return ("Error: No repo path for file access", False, None)
            file_path = arg1 if os.path.isabs(arg1) else os.path.join(repo_path, arg1)
            try:
                line_no = int(arg2)
            except ValueError:
                return (f"Invalid line number: {arg2}", False, None)
            if not os.path.isfile(file_path):
                return (f"File not found: {arg1}", False, None)
            try:
                with open(file_path, encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                if line_no < 1 or line_no > len(lines):
                    return (f"❌ Line {line_no} out of range (file has {len(lines)} lines)", False, None)
                code_line = lines[line_no - 1].rstrip()
                verified = {"file": arg1, "line": line_no, "code": code_line}
                return (f"✓ Line {line_no}: {code_line[:200]}", True, verified)
            except Exception as e:
                return (f"Error reading {arg1}: {e}", False, None)
    except Exception as e:
        return (f"Error: {e}", False, None)
    return ("Unknown tool", False, None)


def backend_search_fallback(icfg, func_name, backend):
    """Fallback: fuzzy ICFG search, then backend search."""
    results = []
    for (fp, fn), edges in icfg._callees.items():
        if func_name.lower() in fn.lower():
            for _, target, etype in edges:
                results.append({"function": target, "edge_type": etype})
            if len(results) >= 20:
                break
    if results:
        return results
    r, _, ok = backend.search_code(func_name)
    return [{"function": f"backend:{func_name}", "edge_type": "search"}] if ok else []


def _build_statements(chains: List[dict], verified_lines: List[dict], repo_path: str) -> List[dict]:
    """Build deduplicated, verified statement list from exploit chains."""
    from gt_chain_agent import is_source_file

    seen: set = set()
    statements: List[dict] = []

    def _add(fp: str, ln: int, func: str, slot: str):
        if not fp or ln <= 0:
            return
        if not is_source_file(fp):
            return
        key = (os.path.basename(fp), ln)
        if key in seen:
            return
        if slot == "MissingValidation":
            return
        code = verify_code_in_repo(repo_path, fp, ln)
        if not code:
            return
        seen.add(key)
        statements.append({
            "step": len(statements) + 1,
            "function": func,
            "file": fp,
            "line": ln,
            "code": code,
            "role": slot or "Propagation",
        })

    # Priority 1: pinpoint_line verified lines
    for vl in verified_lines:
        _add(vl["file"], vl["line"], "", vl.get("slot", ""))

    # Priority 2: edges from chains
    for chain in chains:
        fp = chain.get("function_path", {})
        entry = chain.get("entry", {})
        sink = chain.get("sink", {})

        # Entry statement
        ef = entry.get("function", "") or fp.get("entry_function", "")
        if ef:
            _add(entry.get("file", ""), entry.get("line", 0), ef, "Source")

        # Edge endpoint statements
        for edge in fp.get("edges", []):
            slot = edge.get("slot", "Propagation")
            _add(edge.get("from_file", ""), edge.get("from_line", 0),
                 edge.get("from_func", ""), slot)
            _add(edge.get("to_file", ""), edge.get("to_line", 0),
                 edge.get("to_func", ""), slot)

        # Sink statement
        sf = sink.get("function", "")
        if sf:
            _add(sink.get("file", ""), sink.get("line", 0), sf, "Sink")

    return statements


# ── Call-Site Context Windows ─────────────────────────────────────────

def _extract_func_code(repo_path: str, file_path: str, func_name: str) -> str:
    """Extract full function body with line numbers using tree-sitter."""
    from shared.tree_sitter_utils import _get_parser, EXT_TO_LANG
    ext = os.path.splitext(file_path)[1].lower()
    lang = EXT_TO_LANG.get(ext, 'c')
    parser = _get_parser(lang)
    if not parser:
        return ''
    full = os.path.join(repo_path, file_path) if not os.path.isabs(file_path) else file_path
    if not os.path.isfile(full):
        return ''
    try:
        with open(full, encoding='utf-8', errors='replace') as f:
            source = f.read()
    except Exception:
        return ''
    tree = parser.parse(bytes(source, 'utf-8'))
    # Function definition node types per language
    func_def_types = {
        'c': 'function_definition', 'cpp': 'function_definition',
        'python': 'function_definition', 'java': 'method_declaration',
        'go': 'function_declaration', 'rust': 'function_item',
        'javascript': 'function_declaration', 'ruby': 'method',
        'php': 'function_definition',
    }
    target_type = func_def_types.get(lang, 'function_definition')
    lines = source.split('\n')

    def _find(node):
        if node.type in (target_type, 'ERROR'):
            # Try to get function name from declarator child
            for child in node.children:
                if child.type in ('function_declarator', 'identifier', 'declarator',
                                  'method_declaration', 'variable_declarator'):
                    name = source[child.start_byte:child.end_byte].split('(')[0].strip()
                    if name == func_name:
                        sl = node.start_point[0] + 1
                        el = node.end_point[0] + 1
                        result = ''
                        for i in range(sl - 1, min(el, len(lines))):
                            result += f'{i+1:5d}| {lines[i]}\n'
                        return result
            # Also check for named children that match
            name_node = node.child_by_field_name('name')
            if name_node:
                name = source[name_node.start_byte:name_node.end_byte]
                if name == func_name:
                    sl = node.start_point[0] + 1
                    el = node.end_point[0] + 1
                    result = ''
                    for i in range(sl - 1, min(el, len(lines))):
                        result += f'{i+1:5d}| {lines[i]}\n'
                    return result
        for child in node.children:
            r = _find(child)
            if r:
                return r
        return ''

    return _find(tree.root_node) or ''


CS_PROMPT = """You trace exploit chains in source code. Pick the ROOT CAUSE lines where the vulnerability BEGINS, not where it ends.

CRITICAL RULE — pick EARLIEST lines:
- Source: The FIRST line where untrusted data is DECLARED, RECEIVED, or IMPORTED — not where it's later used.
- Propagation: The FIRST line where a MISSING CHECK should have been — not where the unchecked data crashes.
- Sink: The line where the vulnerable state is SET UP (bad config, missing init, wrong assignment) — not the crash site.

Think like a code reviewer finding the BUG ROOT CAUSE, not a debugger tracing the crash.

ARCHETYPE SLOTS:
{archetype_slots}

OUTPUT inside ```json``` fences:
```json
{{"statements":[{{"function":"parse","file":"src/a.c","line":42,"code":"buf=read_input(fd);","role":"Source"}}]}}
```"""


def generate_exploit_chain_simple(
    cve_id: str,
    issue_description: str,
    step1_functions: List[dict],
    repo_path: str,
    archetype=None,
) -> Optional[dict]:
    """ICFG call-site context windows + LLM classification."""
    if not repo_path:
        return None

    from acr_baseline.model import ModelClient
    from gt_chain_agent import is_source_file
    import csv
    from shared.config import ICFG_DIR, SCUBA_RESULTS_DIR

    llm = ModelClient()
    target_names = {f.get('function', '') for f in (step1_functions or []) if f.get('function')}
    call_sites = []

    for csv_path in [
        os.path.join(ICFG_DIR, cve_id, 'icfg_icfg_db.csv'),
        os.path.join(ICFG_DIR, cve_id, 'icfg_codeql.csv'),
        os.path.join(SCUBA_RESULTS_DIR, cve_id, 'icfg_joern.csv'),
        os.path.join(SCUBA_RESULTS_DIR, cve_id, 'icfg_scubatrace.csv'),
    ]:
        if not os.path.isfile(csv_path):
            continue
        try:
            import pickle as pkl
            pkl_path = csv_path + '.call_sites.pkl'
            if os.path.isfile(pkl_path) and os.path.getmtime(pkl_path) >= os.path.getmtime(csv_path):
                # Load cached filtered call sites
                call_sites.extend(pkl.load(open(pkl_path, 'rb')))
                continue
            # Parse CSV, filter call-type edges, build cache
            cached = []
            with open(csv_path, encoding='utf-8', errors='replace') as f:
                reader = csv.reader(f)
                h = [x.strip().lower().strip('"') for x in next(reader)]
                col = {n: i for i, n in enumerate(h)}
                fc = col.get('file', col.get('filename', 0))
                fnc = col.get('function', col.get('func', col.get('name', 1)))
                sc = col.get('srcline', col.get('src_line', 2))
                tc = col.get('target_function', col.get('target', 5))
                ec = col.get('edge_type', 4)
                for row in reader:
                    try:
                        if len(row) <= max(fc, fnc, tc):
                            continue
                        fp = row[fc].strip().strip('"')
                        fn = row[fnc].strip().strip('"')
                        tgt = row[tc].strip().strip('"')
                        try:
                            et = row[ec].strip().strip('"').lower()
                        except Exception:
                            et = 'call'
                        if et not in ('call', 'inter_call', 'ts_call', 'calltype'):
                            continue
                        try:
                            ln = int(row[sc].strip().strip('"'))
                        except Exception:
                            continue
                        if ln <= 0 or not is_source_file(fp):
                            continue
                        cached.append((fp, ln, fn, tgt, ""))
                    except Exception:
                        continue
            # Dedup before saving
            seen_keys = set()
            deduped = []
            for cs in cached:
                key = (cs[0], cs[1])
                if key not in seen_keys:
                    seen_keys.add(key)
                    deduped.append(cs)
            try:
                pkl.dump(deduped, open(pkl_path, 'wb'))
            except Exception:
                pass
            call_sites.extend(deduped)
            continue
        except Exception:
            continue

    if not call_sites:
        return None

    # Phase 1: extract issue keywords for call-site scoring
    phase1 = _run_phase1(llm, issue_description)
    search_boost = _code_search_boost(repo_path, phase1)

    step1_files = [f.get('file', '') for f in (step1_functions or []) if f.get('file')]

    call_sites.sort(key=lambda x: -_score_call_site(x[0], x[2], x[3], x[4], target_names, step1_files, phase1, search_boost))
    call_sites = call_sites[:80]

    af = archetype.family if archetype else 'Generic'
    ad = archetype.display_name if archetype else 'Generic'
    slot_descs = []
    if archetype:
        for s in archetype.slots:
            req = 'REQUIRED' if hasattr(s, 'required') and s.required else 'optional'
            slot_descs.append(f'  {s.name} ({req}): {s.description[:80]}')
    archetype_text = '\n'.join(slot_descs) if slot_descs else 'Source, Propagation, Sink'

    # Build full function code with step1 evidence annotation
    seen_funcs = set()
    func_blocks = []; total_lines = 0
    # Priority 1: step1 top 5 functions with score + reason annotation
    for rank, f in enumerate((step1_functions or [])[:5]):
        fn = f.get('function', ''); fp = f.get('file', '')
        if not fn or not fp: continue
        key = (fp, fn)
        if key in seen_funcs: continue
        seen_funcs.add(key)
        code = _extract_func_code(repo_path, fp, fn)
        if not code: continue
        sc = f.get('score', 0); reason = f.get('reason', '')[:120]
        header = f'### [{rank+1}] {fn} @ {os.path.basename(fp)}  [step1_score={sc:.2f}]'
        if reason:
            header += f'\n    reason: {reason}'
        func_blocks.append(f'{header}\n```c\n{code}```\n')
        total_lines += code.count('\n')
        if total_lines > 200:
            break
    # Priority 2: ICFG call-site functions (supplement if room)
    for fp, ln, fn, tgt, _ in call_sites[:30]:
        key = (fp, fn)
        if key in seen_funcs: continue
        seen_funcs.add(key)
        code = _extract_func_code(repo_path, fp, fn)
        if not code: continue
        func_blocks.append(f'### [ICFG] {fn} @ {os.path.basename(fp)}\n```c\n{code}```\n')
        total_lines += code.count('\n')
        if total_lines > 200:
            break

    func_text = '\n'.join(func_blocks) if func_blocks else 'No function code available.'

    prompt = f"""CVE REPORT:
{issue_description[:2000]}

ARCHETYPE: {af} -- {ad}

FUNCTION CODE (ranked by step1 vulnerability score, with evidence):
{func_text[:12000]}

TASK: Fill the exploit chain slots IN ORDER. Pick EXACT line numbers from the code above.

Source (required): Where untrusted/attacker-controlled data ENTERS.
Propagation: Where data passes without validation.
Sink (required): Where the vulnerability MANIFESTS (crash, overflow, injection, etc).

Output only 1 line per slot. Prefer lines from higher-ranked [1] functions."""

    system = CS_PROMPT.replace('{archetype_slots}', archetype_text)

    statements = []
    for _ in range(2):
        try:
            resp = llm.call(
                [{'role': 'system', 'content': system}, {'role': 'user', 'content': prompt}],
                temperature=0.0, max_tokens=4096,
            )
        except Exception:
            continue
        m = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', resp)
        if not m:
            m = re.search(r'(\{[^{]*"statements"[\s\S]*\})', resp)
        if not m:
            continue
        try:
            data = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        statements = data.get('statements', [])
        if statements:
            break
    # ── Quality check: if first-pass output looks weak, retry per-function ──
    def _quality_ok(stmts, func_blocks_text):
        """Check if LLM output is credible: has real lines, files match step1."""
        if not stmts:
            return False
        # Filter out obvious garbage: all lines = 1 or all code = first-line boilerplate
        lines = [int(s.get('line', 0)) for s in stmts if s.get('line')]
        if len(lines) >= 2 and all(l <= 5 for l in lines):
            return False  # LLM guessed first 5 lines
        # At least one statement should reference a real function from func_blocks
        funcs_in_prompt = set()
        for fb in func_blocks:
            for m in re.finditer(r'###\s+.*?(\w[\w.]*)\s*@', fb):
                funcs_in_prompt.add(m.group(1).strip())
        stmt_funcs = {s.get('function', '') for s in stmts}
        if funcs_in_prompt and not (stmt_funcs & funcs_in_prompt):
            return False  # LLM invented function names not in prompt
        return True

    # ── File-overlap check: if pred files don't overlap with Step1 files, retry ──
    _stmt_files = set(os.path.basename(s.get('file', '')) for s in statements if s.get('file'))
    _step1_basenames = set(os.path.basename(f) for f in step1_files if f)
    if _step1_basenames and _stmt_files and not (_stmt_files & _step1_basenames):
        # Retry: Step2 traced wrong files. Re-run with only Step1-file functions.
        _retry_blocks = []
        _retry_seen = set()
        for rank, f in enumerate((step1_functions or [])[:5]):
            fn = f.get('function', ''); fp = f.get('file', '')
            if not fn or not fp: continue
            key = (fp, fn)
            if key in _retry_seen: continue
            _retry_seen.add(key)
            code = _extract_func_code(repo_path, fp, fn)
            if not code: continue
            sc = f.get('score', 0)
            _retry_blocks.append('### [%d] %s @ %s  [step1_score=%.2f]\n```c\n%s\n```\n' % (rank+1, fn, os.path.basename(fp), sc, code[:3000]))
            if len(_retry_blocks) >= 3: break
        if _retry_blocks:
            _retry_prompt = """CVE REPORT:
%s

FUNCTION CODE (corrected — only Step1 vulnerable functions):
%s

TASK: Find vulnerability-triggering statements. Pick EXACT line numbers from the code above.
Output JSON:
```json
{"statements":[{"step":1,"function":"...","file":"...","line":<int>,"code":"<code>","role":"Source|Propagation|Sink"}]}
```""" % (issue_description[:2000], '\n'.join(_retry_blocks)[:8000])
            for _ in range(2):
                try:
                    resp = llm.call(
                        [{'role': 'system', 'content': system}, {'role': 'user', 'content': _retry_prompt}],
                        temperature=0.0, max_tokens=4096)
                except Exception:
                    continue
                m2 = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', resp)
                if not m2: m2 = re.search(r'(\{[^{]*"statements"[\s\S]*\})', resp)
                if not m2: continue
                try: data2 = json.loads(m2.group(1))
                except: continue
                stmts2 = data2.get('statements', [])
                if stmts2:
                    seen_keys = set((s.get('file',''), s.get('line',0)) for s in statements)
                    for s in stmts2:
                        key = (s.get('file',''), s.get('line',0))
                        if key not in seen_keys:
                            seen_keys.add(key)
                            statements.append(s)
                    break

    # ── Call-site based second pass (always run, supplements first pass) ──
    # Build file->line lookup from ICFG call_sites
    cs_by_file = {}  # file -> {line: (func, target)}
    for cs in call_sites:
        fp_cs, ln_cs, fn_cs, tgt_cs, _ = cs
        if fp_cs not in cs_by_file:
            cs_by_file[fp_cs] = {}
        cs_by_file[fp_cs][ln_cs] = (fn_cs, tgt_cs)

    cs_stmts = []
    for rank, f in enumerate((step1_functions or [])[:3]):
        fn = f.get('function', ''); fp = f.get('file', '')
        if not fn or not fp: continue
        sc = f.get('score', 0)
        reason = f.get('reason', '')[:120]

        fp_cs = cs_by_file.get(fp, {})
        if not fp_cs: continue

        cs_lines = sorted(fp_cs.items())
        if len(cs_lines) > 50:
            cs_lines = cs_lines[:50]

        cs_table = ''
        for i, (ln, (cs_fn, cs_tgt)) in enumerate(cs_lines):
            cs_table += '%3d. line %5d | %s -> %s\n' % (i+1, ln, cs_fn, cs_tgt)

        cs_prompt = """CVE REPORT:
%s

FUNCTION [%d]: %s @ %s (step1_score=%.2f)
%s

CALL-SITES (potential exploit locations from ICFG static analysis):
%s

TASK: Which call-site lines are involved in the vulnerability? Select 1-3.
Output JSON (use the EXACT line numbers from the table):
```json
{"statements":[{"step":1,"function":"%s","file":"%s","line":<int>,"role":"Source|Propagation|Sink"}]}
```""" % (
            issue_description[:2000], rank+1, fn, os.path.basename(fp), sc,
            ('reason: ' + reason) if reason else '',
            cs_table[:5000], fn, fp)

        for _ in range(2):
            try:
                resp = llm.call(
                    [{'role': 'system', 'content': system}, {'role': 'user', 'content': cs_prompt}],
                    temperature=0.0, max_tokens=4096)
            except Exception:
                continue
            m2 = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', resp)
            if not m2:
                m2 = re.search(r'(\{[^{]*"statements"[\s\S]*\})', resp)
            if not m2: continue
            try:
                data2 = json.loads(m2.group(1))
            except json.JSONDecodeError:
                continue
            stmts2 = data2.get('statements', [])
            if stmts2:
                # Verify: only keep statements whose line is in our call-site table
                for s in stmts2:
                    s_ln = s.get('line', 0)
                    if s_ln in fp_cs:
                        cs_stmts.append(s)
                break

    if cs_stmts:
        # Merge call-site results with first-pass results, deduplicate
        seen_keys = set()
        merged = []
        for s in cs_stmts + statements:
            key = (s.get('file', ''), s.get('line', 0))
            if key not in seen_keys and s.get('line', 0) > 0:
                seen_keys.add(key)
                merged.append(s)
        statements = merged

    if not _quality_ok(statements, func_blocks):
        # Final fallback: if merged result still looks bad, use only call-site results
        if cs_stmts:
            statements = cs_stmts

    if not statements:
        return None

    edges = []
    for s in statements:
        fn = s.get('function', ''); fp = s.get('file', ''); ln = s.get('line', 0)
        try:
            ln = int(ln)
        except Exception:
            ln = 0
        tgt = ''
        for cs in call_sites:
            if cs[0] == fp and cs[1] == ln:
                tgt = cs[3]; break
        edges.append({
            'from_func': fn, 'from_file': fp, 'from_line': ln,
            'to_func': tgt or fn, 'to_file': fp,
            'slot': s.get('role', 'Propagation'), 'from_code': s.get('code', ''),
        })

    path_chain = []
    for e in edges:
        pe = dict(e, **{'to_line': 0, 'from_code': e.get('from_code', ''), 'to_code': '',
                         'edge_type': 'call', 'prob': 1.0})
        for pfx in ('from', 'to'):
            fpath = pe.get(f'{pfx}_file', ''); ln = pe.get(f'{pfx}_line', 0)
            try:
                ln = int(ln)
            except Exception:
                ln = 0
            if fpath and ln > 0:
                c = verify_code_in_repo(repo_path, fpath, ln)
                if c:
                    pe[f'{pfx}_code'] = c
        path_chain.append(pe)

    stmts = []; seen = set()
    for s in statements:
        fn = s.get('file', ''); ln = s.get('line', 0)
        try:
            ln = int(ln)
        except Exception:
            ln = 0
        code = s.get('code', '')
        if fn and ln > 0 and code:
            if not is_source_file(fn):
                continue
            cv = verify_code_in_repo(repo_path, fn, ln)
            if cv:
                code = cv
            key = (os.path.basename(fn), ln)
            if key in seen:
                continue
            seen.add(key)
            stmts.append({
                'step': len(stmts) + 1, 'function': s.get('function', ''),
                'file': fn, 'line': ln, 'code': code, 'role': s.get('role', 'Propagation'),
            })

    entry = statements[0] if statements else {}
    return {
        'cve_id': cve_id, 'step2_mode': 'call_site_windows', 'archetype': af,
        'icfg_source': 'codeql+scubatrace', 'icfg_stats': {'call_sites': len(call_sites)},
        'explanations': [{
            'function_rank': 1, 'entry_function': entry.get('function', ''),
            'entry_file': entry.get('file', ''), 'entry_line': entry.get('line', 0),
            'archetype': af, 'archetype_display': ad, 'filled_slots': {}, 'slot_count': 0,
            'required_slots': [], 'sink': '', 'terminated_at_sink': False,
            'termination_reason': 'call_site_windows', 'confidence': 0.8,
            'path_chain': path_chain,
            'nodes': [f'{s["file"]}:{s["function"]}:{s["line"]}' for s in stmts],
            'code_snippets': [], 'statements': stmts, 'cumulative_score': len(edges),
            'nl_summary': '',
        }],
        'trace_statistics': {'num_traced': 1, 'num_archetype_complete': 0},
        'selection_reason': 'call_site_windows_v15',
    }
