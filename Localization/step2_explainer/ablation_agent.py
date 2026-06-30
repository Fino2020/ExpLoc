"""
Ablation Agent — 3 variants for RQ3b.

Modes:
  V1: w/o pattern (ICFG tools + Repo tools, no archetype slots)
  V2: w/o graph   (Repo tools + archetype pattern, no ICFG)
  V3: w/o both    (Repo tools only, no ICFG, no archetype)
"""
import json, os, re, sys, time, subprocess

_LOC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _LOC_DIR not in sys.path:
    sys.path.insert(0, _LOC_DIR)

from gt_chain_agent import is_source_file
from acr_baseline.model import ModelClient
from step2_explainer.icfg_tools import get_icfg_tools

# ── Tool Definitions ──
REPO_TOOLS = [
    {"type": "function", "function": {"name": "search_code",
        "description": "Search code patterns in the repository (git grep)",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string", "description": "Code string, pattern, or keyword"}
        }, "required": ["query"]}}},
    {"type": "function", "function": {"name": "read_file",
        "description": "Read a source file with line numbers (first 200 lines)",
        "parameters": {"type": "object", "properties": {
            "file_path": {"type": "string", "description": "File path relative to repo root"}
        }, "required": ["file_path"]}}},
    {"type": "function", "function": {"name": "get_code_around",
        "description": "Get +/- N lines around a specific line with context markers",
        "parameters": {"type": "object", "properties": {
            "file_path": {"type": "string"}, "line": {"type": "integer"},
            "context": {"type": "integer", "description": "Lines before/after (default 10)"}
        }, "required": ["file_path", "line"]}}},
    {"type": "function", "function": {"name": "pinpoint_line",
        "description": "Verify exact code at a specific file:line",
        "parameters": {"type": "object", "properties": {
            "file_path": {"type": "string"}, "line": {"type": "integer"}
        }, "required": ["file_path", "line"]}}},
]

ICFG_TOOLS = [
    {"type": "function", "function": {"name": "get_callees",
        "description": "Get functions called BY a given function (ICFG forward trace)",
        "parameters": {"type": "object", "properties": {
            "function": {"type": "string", "description": "Function name"}
        }, "required": ["function"]}}},
    {"type": "function", "function": {"name": "get_callers",
        "description": "Get functions that CALL a given function (ICFG backward trace)",
        "parameters": {"type": "object", "properties": {
            "function": {"type": "string", "description": "Function name"}
        }, "required": ["function"]}}},
    {"type": "function", "function": {"name": "find_path",
        "description": "Find shortest call path between two functions in ICFG",
        "parameters": {"type": "object", "properties": {
            "from_func": {"type": "string"}, "to_func": {"type": "string"}
        }, "required": ["from_func", "to_func"]}}},
]

SYSTEM_PROMPTS = {
    "V1": """You are a vulnerability localization agent. Given a CVE issue report, Step1 function candidates, and ICFG call graph tools, find the exploit chain.

Use tools to explore:
- search_code/read_file/get_code_around/pinpoint_line: explore repository code
- get_callees/get_callers/find_path: trace ICFG call graph to find the path from entry to vulnerability point

MANDATORY:
1. Start from Step1 candidate functions using search_code/read_file
2. Use get_callees to trace FORWARD from entry functions
3. Use get_callers to trace BACKWARD from suspicious callees
4. Use find_path to verify connectivity between functions
5. pinpoint_line to verify each statement's code

Output statements forming a coherent exploit chain.
```json
{"entry_function":"...","entry_file":"...","statements":[
  {"step":1,"function":"...","file":"...","line":<int>,"code":"<actual code>","role":"step description"}
]}
```""",

    "V2": """You are a vulnerability localization agent. Given a CVE issue report, Step1 function candidates, and vulnerability pattern hints, find the exploit chain.

VULNERABILITY PATTERN:
- Source: Where untrusted data enters the system
- Propagation: Where data passes without validation
- Sink: Where the vulnerability manifests (crash, overflow, injection)

Use tools: search_code, read_file, get_code_around, pinpoint_line.

MANDATORY:
1. search_code for function names/files from the issue report
2. read_file on relevant files to understand the code
3. get_code_around on suspicious areas
4. pinpoint_line to verify each statement

Output statements with roles: Source, Propagation, Sink.
```json
{"entry_function":"...","entry_file":"...","statements":[
  {"step":1,"function":"...","file":"...","line":<int>,"code":"<actual code>","role":"Source"},
  {"step":2,"function":"...","file":"...","line":<int>,"code":"<actual code>","role":"Propagation"},
  {"step":3,"function":"...","file":"...","line":<int>,"code":"<actual code>","role":"Sink"}
]}
```""",

    "V3": """You are a vulnerability localization agent. Given only a CVE issue report and repository access, find the vulnerable statements.

Use tools: search_code, read_file, get_code_around, pinpoint_line.

MANDATORY:
1. search_code for function names, file names, or keywords from the issue report
2. read_file on the most relevant files
3. get_code_around on suspicious areas
4. pinpoint_line to verify each statement

Output statements. Every line MUST be verified with pinpoint_line.
```json
{"entry_function":"...","entry_file":"...","statements":[
  {"step":1,"function":"...","file":"...","line":<int>,"code":"<actual code>","role":"Source"},
  ...
]}
```""",
}


def execute_tool(tool_name, args, repo, icfg=None):
    try:
        if tool_name == 'search_code':
            query = args.get('query', '')
            if not query: return "Error: empty query"
            r = subprocess.run(['git', 'grep', '-n', '-i', query], cwd=repo,
                             capture_output=True, text=True, timeout=15)
            lines = [l.strip() for l in r.stdout.split('\n') if l.strip() and is_source_file(l.split(':')[0])]
            return '\n'.join(lines[:80]) if lines else f"No results for '{query}'"

        elif tool_name == 'read_file':
            fp = args.get('file_path', '')
            if not is_source_file(fp): return f"REJECTED: not a source file"
            full = os.path.join(repo, fp) if not os.path.isabs(fp) else fp
            if not os.path.isfile(full): return f"File not found: {fp}"
            with open(full, encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
            result = ''
            for i in range(min(200, len(lines))):
                result += f'{i+1:5d}| {lines[i].rstrip()}\n'
            return result[:10000] if result else 'Empty'

        elif tool_name == 'get_code_around':
            fp = args.get('file_path', ''); ln = int(args.get('line', 0) or 0)
            ctx = int(args.get('context', 10) or 10)
            if not is_source_file(fp): return f"REJECTED: not a source file"
            full = os.path.join(repo, fp) if not os.path.isabs(fp) else fp
            if not os.path.isfile(full): return f"File not found: {fp}"
            with open(full, encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
            start = max(ln - ctx - 1, 0); stop = min(ln + ctx, len(lines))
            result = ''
            for i in range(start, stop):
                marker = '>>>' if i == ln - 1 else '   '
                result += f'{marker} {i+1:5d}| {lines[i].rstrip()}\n'
            return result[:6000]

        elif tool_name == 'pinpoint_line':
            fp = args.get('file_path', '')
            ln = int(args.get('line', 0) or 0)
            full = os.path.join(repo, fp) if not os.path.isabs(fp) else fp
            if not os.path.isfile(full): return f"File not found: {fp}"
            with open(full, encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
            if ln < 1 or ln > len(lines):
                return f"Line {ln} out of range (file has {len(lines)} lines)"
            return f"Line {ln}: {lines[ln-1].rstrip()[:300]}"

        elif tool_name in ('get_callees', 'get_callers') and icfg:
            fn = args.get('function', '')
            if tool_name == 'get_callees':
                callees = icfg.get_callees(fn)
                names = [f"{c['function']} ({c.get('edge_type','?')})" for c in callees[:25]]
                return "Callees:\n  " + "\n  ".join(names) if names else "No callees"
            else:
                callers = icfg.get_callers(fn)
                names = [f"{c['function']} ({c.get('edge_type','?')})" for c in callers[:25]]
                return "Callers:\n  " + "\n  ".join(names) if names else "No callers"

        elif tool_name == 'find_path' and icfg:
            path = icfg.find_path(args.get('from_func', ''), args.get('to_func', ''))
            return "Path: " + " -> ".join(path) if path else "No path found"

        return f"Unknown tool: {tool_name}"
    except Exception as e:
        return f"Error: {str(e)[:200]}"


def run_ablation(cve_id, issue_text, repo_path, step1_funcs=None, mode="V3"):
    """Run ablation agent for one CVE. Returns V16-compatible step2 dict or None."""
    if not repo_path: return None

    tools = REPO_TOOLS + (ICFG_TOOLS if mode == "V1" else [])
    system_prompt = SYSTEM_PROMPTS[mode]
    llm = ModelClient()

    # Build user prompt with mode-specific context
    extra = ""
    if step1_funcs and mode in ("V1", "V2"):
        func_list = "\n".join(f"  [{i+1}] {f.get('function','')} @ {os.path.basename(f.get('file',''))} (score={f.get('score',0):.2f})"
                              for i, f in enumerate((step1_funcs or [])[:5]))
        extra = f"\nSTEP1 FUNCTION CANDIDATES (start from these):\n{func_list}\n"

    user_prompt = f"""CVE: {cve_id}

ISSUE REPORT:
{issue_text[:3000]}
{extra}
REPOSITORY: {repo_path}

Find the vulnerability-triggering statements. Use tools to explore the code.
Verify every line with pinpoint_line before outputting."""

    messages = [
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': user_prompt},
    ]

    # Lazy-load ICFG for V1
    icfg = None
    if mode == "V1":
        try: icfg = get_icfg_tools(cve_id)
        except: pass

    max_rounds = 8
    for round_no in range(max_rounds):
        try:
            resp = llm.call_with_tools(messages=messages, tools=tools,
                                       temperature=0.0, max_tokens=4096)
        except Exception as e:
            if round_no < 2:
                time.sleep(2 ** round_no)
                continue
            return None

        content = resp.get('content', '')
        tool_calls = resp.get('tool_calls', [])
        messages.append({'role': 'assistant', 'content': content[:2000]})

        if content:
            m = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', content)
            if not m:
                m = re.search(r'(\{"entry_function"[\s\S]*\})', content)
            if not m:
                m = re.search(r'(\{[^{]*"statements"[\s\S]*\})', content)
            if m:
                try:
                    data = json.loads(m.group(1))
                    if data.get('statements'):
                        return _format_step2(cve_id, data, repo_path, mode)
                except json.JSONDecodeError: pass

        if not tool_calls:
            if round_no >= 4:
                messages.append({'role': 'user', 'content': 'Stop using tools. Output JSON with statements NOW inside ```json``` fences.'})
            continue

        for tc in tool_calls:
            try: args = json.loads(tc['function']['arguments'])
            except: args = {}
            result = execute_tool(tc['function']['name'], args, repo_path, icfg)
            messages.append({'role': 'tool', 'tool_call_id': tc['id'], 'content': result[:3000]})

        if round_no >= 6:
            messages.append({'role': 'user', 'content': 'That is enough. Output the JSON with statements NOW. Do NOT call any more tools.'})

    # Force final
    try:
        content = llm.call(messages + [{'role': 'user', 'content': 'Output ONLY the JSON now.'}],
                          temperature=0.0, max_tokens=2048)
        m = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', content)
        if not m: m = re.search(r'(\{[^{]*"statements"[\s\S]*\})', content)
        if m:
            data = json.loads(m.group(1))
            if data.get('statements'):
                return _format_step2(cve_id, data, repo_path, mode)
    except: pass
    return None


def _format_step2(cve_id, data, repo_path, mode):
    statements = data.get('statements', [])
    entry_func = data.get('entry_function', statements[0].get('function', '') if statements else '')
    entry_file = data.get('entry_file', statements[0].get('file', '') if statements else '')

    for s in statements:
        fp = s.get('file', ''); ln = s.get('line', 0)
        try: ln = int(ln)
        except: continue
        full = os.path.join(repo_path, fp) if not os.path.isabs(fp) else fp
        if os.path.isfile(full):
            try:
                with open(full, encoding='utf-8', errors='replace') as f:
                    lines = f.readlines()
                if ln <= len(lines): s['code'] = lines[ln - 1].rstrip()
            except: pass
        if 'step' not in s: s['step'] = len(statements)

    path_chain = []
    for i in range(len(statements) - 1):
        s1, s2 = statements[i], statements[i+1]
        path_chain.append({
            'from_func': s1.get('function', ''), 'from_file': s1.get('file', ''),
            'from_line': s1.get('line', 0),
            'to_func': s2.get('function', ''), 'to_file': s2.get('file', ''),
            'to_line': s2.get('line', 0),
            'edge_type': 'call', 'slot': s1.get('role', 'Propagation'),
        })

    mode_names = {"V1": "ablation_no_pattern", "V2": "ablation_no_graph", "V3": "ablation_no_both"}
    return {
        'cve_id': cve_id, 'step2_mode': mode_names.get(mode, mode),
        'archetype': 'Generic', 'icfg_source': 'icfg' if mode == 'V1' else 'none',
        'icfg_path': '', 'icfg_stats': {'nodes': 0, 'edges': 0},
        'explanations': [{
            'function_rank': 1, 'entry_function': entry_func,
            'entry_file': entry_file, 'entry_line': 0,
            'filled_slots': {},
            'path_chain': path_chain,
            'statements': statements,
            'nodes': [], 'code_snippets': [],
            'slot_count': len(statements), 'required_slots': [],
            'archetype': 'Generic', 'archetype_display': 'Generic',
            'sink': '', 'terminated_at_sink': False,
            'termination_reason': mode_names.get(mode, mode),
            'confidence': 0.5,
            'nl_summary': f'{mode_names.get(mode, mode)}: {len(statements)} statements',
        }],
        'trace_statistics': {'num_traced': 1, 'num_archetype_complete': 1},
        'selection_reason': mode_names.get(mode, mode),
    }
