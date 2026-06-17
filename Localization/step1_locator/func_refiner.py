"""
Second-pass function refinement — re-scores functions within top predicted files.

After the LLM agent predicts files + functions, this module:
1. Extracts ALL functions from the top-N predicted files via tree-sitter
2. Builds a focused LLM prompt: CVE + complete function list + body snippets
3. Has the LLM score each function for vulnerability relevance
4. Merges refined scores with original predictions via RRF

Rationale: 90.1% of "file correct, function wrong" cases have functions in the
correct file but with the wrong name. A second pass with complete candidate
coverage and focused comparison fixes this.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from openai import OpenAI

from shared.tree_sitter_utils import extract_all_functions_with_bodies


# Maximum candidates to send to LLM (to keep prompt size manageable)
MAX_FILES = 10
MAX_FUNCS_PER_FILE = 30
MAX_BODY_SNIPPET_LINES = 20

SYSTEM_REFINE = """You are a vulnerability localization expert performing a SECOND-PASS function refinement.

You receive:
1. A vulnerability report (CVE title + description)
2. A list of candidate FILES already identified as likely vulnerable
3. ALL functions inside those files — with signatures and body snippets

Your task: score EACH function for vulnerability relevance (0.0 to 1.0).

SCORING GUIDELINES:
- 0.90-1.00: Directly handles the vulnerable input/code path. The function body clearly processes the type of data mentioned in the CVE.
- 0.70-0.89: Indirectly involved — called by the vulnerable path, or wraps/manages the vulnerable component.
- 0.40-0.69: Tangentially related — utility/helper in the same file that touches similar data.
- 0.10-0.39: Unlikely related — general-purpose function in the same file.
- 0.00-0.09: Clearly unrelated — init, cleanup, logging, configuration.

SCORE ALL functions in the list. Do not skip any. Use the FULL 0.0-1.0 range.

OUTPUT — single JSON block inside ```json``` fences:
```json
{
  "functions": [
    {"function": "func_name", "file": "path/to/file.c", "score": 0.85, "reason": "..."},
    ...
  ],
  "analysis_summary": "Brief summary of which functions are most likely vulnerable and why"
}
```"""


def refine_functions(
    issue_description: str,
    language: str,
    top_files: List[str],
    repo_path: str,
    llm_client: OpenAI,
    llm_model: str,
    original_functions: Optional[List[dict]] = None,
) -> Tuple[List[dict], str]:
    """Second-pass function refinement on top predicted files.

    Args:
        issue_description: CVE title + body
        language: programming language
        top_files: top-N predicted file paths (relative to repo)
        repo_path: path to the git repository root
        llm_client: OpenAI client
        llm_model: model name
        original_functions: original function predictions from agent (for merge)

    Returns:
        (refined_functions, analysis_summary)
        refined_functions: list of {function, file, score, reason} sorted by score desc
    """
    # Step 1: Extract ALL functions from top files
    candidates = _extract_candidates(repo_path, top_files[:MAX_FILES])

    if not candidates:
        if original_functions:
            return sorted(original_functions, key=lambda x: -x.get("score", 0)), ""
        return [], "No candidate functions extracted from top files."

    # Step 2: Build focused prompt
    prompt = _build_refine_prompt(issue_description, language, candidates)

    # Step 3: Call LLM
    try:
        response = llm_client.chat.completions.create(
            model=llm_model,
            messages=[
                {"role": "system", "content": SYSTEM_REFINE},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=4096,
        )
        content = response.choices[0].message.content or ""
    except Exception as e:
        print(f"  [REFINER] LLM call failed: {e}")
        if original_functions:
            return sorted(original_functions, key=lambda x: -x.get("score", 0)), ""
        return [], str(e)

    # Step 4: Parse output
    refined_funcs, summary = _parse_refiner_output(content)

    if not refined_funcs:
        if original_functions:
            return sorted(original_functions, key=lambda x: -x.get("score", 0)), summary
        return [], summary

    # Step 5: Merge with original predictions
    merged = _merge_function_scores(original_functions or [], refined_funcs)

    return sorted(merged, key=lambda x: -x.get("score", 0)), summary


# ---------------------------------------------------------------------------
# Candidate extraction
# ---------------------------------------------------------------------------

def _extract_candidates(repo_path: str, file_paths: List[str]) -> List[dict]:
    """Extract ALL functions from each file via tree-sitter.

    Returns flat list of {function, file, score_base, body_snippet, start_line, end_line}
    """
    import os

    all_funcs = []
    seen = set()

    for fpath in file_paths:
        if not fpath:
            continue
        full = os.path.join(repo_path, fpath)
        if not os.path.isfile(full):
            continue

        funcs = extract_all_functions_with_bodies(full, MAX_BODY_SNIPPET_LINES)
        if not funcs:
            continue

        for fn in funcs[:MAX_FUNCS_PER_FILE]:
            key = (fpath, fn["name"])
            if key in seen:
                continue
            seen.add(key)

            body = fn.get("body_snippet", "")
            if len(body) > 2000:
                body = body[:2000] + "\n... [truncated]"

            all_funcs.append({
                "function": fn["name"],
                "file": fpath,
                "score_base": 0.1,  # small base score from file prediction
                "start_line": fn.get("start_line", 0),
                "end_line": fn.get("end_line", 0),
                "body_snippet": body,
                "params": fn.get("params", "..."),
            })

    return all_funcs


# ---------------------------------------------------------------------------
# Prompt building
# ---------------------------------------------------------------------------

def _build_refine_prompt(
    issue_description: str,
    language: str,
    candidates: List[dict],
) -> str:
    """Build the second-pass refinement prompt."""
    lang_line = f"Language: {language}" if language else ""

    # Group candidates by file
    by_file: Dict[str, List[dict]] = {}
    for c in candidates:
        by_file.setdefault(c["file"], []).append(c)

    sections = []
    for i, (fpath, funcs) in enumerate(by_file.items()):
        parts = [f"[{i+1}] File: {fpath} ({len(funcs)} functions)"]
        for fn in funcs:
            body = fn.get("body_snippet", "")
            indent_body = "\n".join(f"        {line}" for line in body.split("\n")[:15])
            parts.append(
                f"  - {fn['function']}{fn.get('params', '()')}  "
                f"L{fn.get('start_line', '?')}-L{fn.get('end_line', '?')}\n"
                f"    body:\n{indent_body}"
            )
        sections.append("\n".join(parts))

    candidate_text = "\n\n".join(sections)

    return f"""Refine function-level vulnerability localization for this CVE.

{lang_line}

---
VULNERABILITY REPORT:
---
{issue_description[:3000]}

---
CANDIDATE FUNCTIONS (extracted via tree-sitter from top predicted files):
---
{candidate_text[:8000]}

---
Based on the vulnerability report and function bodies above, score EVERY function for vulnerability relevance (0.0-1.0). Output as JSON inside ```json``` fences."""


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------

def _parse_refiner_output(text: str) -> Tuple[List[dict], str]:
    """Parse LLM JSON output with robust error handling."""
    if not text:
        return [], ""

    # Extract JSON block from code fences
    m = re.search(r'```(?:json)?\s*([\s\S]*?)```', text)
    if m:
        json_str = m.group(1).strip()
    else:
        # Try to find raw JSON object
        m = re.search(r'\{[\s\S]*"functions"[\s\S]*\}', text)
        if m:
            json_str = m.group(0)
        else:
            json_str = text.strip()

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        # Try to fix common JSON issues
        fixed = _fix_json(json_str)
        try:
            data = json.loads(fixed)
        except json.JSONDecodeError:
            return [], ""

    summary = data.get("analysis_summary", "") if isinstance(data, dict) else ""
    raw_funcs = data.get("functions", []) if isinstance(data, dict) else []

    if not isinstance(raw_funcs, list):
        return [], summary

    funcs = []
    for item in raw_funcs:
        item = _normalize_refiner_item(item)
        if item and item.get("function") and item.get("file"):
            funcs.append(item)

    return funcs, summary


def _normalize_refiner_item(item) -> Optional[dict]:
    """Coerce a refiner output item into {function, file, score, reason}."""
    if isinstance(item, str):
        return {"function": item, "file": "", "score": 0.5, "reason": ""}
    if not isinstance(item, dict):
        return None
    name = item.get("function", item.get("name", ""))
    if isinstance(name, dict):
        name = name.get("name", name.get("function", ""))
    name = str(name).strip()
    fpath = item.get("file", item.get("path", ""))
    if isinstance(fpath, dict):
        fpath = fpath.get("file", fpath.get("path", ""))
    fpath = str(fpath).strip()
    try:
        score = float(item.get("score", 0.5))
    except (TypeError, ValueError):
        score = 0.5
    reason = str(item.get("reason", ""))[:200]
    return {"function": name, "file": fpath, "score": min(1.0, max(0.0, score)),
            "reason": reason}


def _fix_json(json_str: str) -> str:
    """Attempt to fix common JSON syntax errors from LLM output."""
    # Remove trailing commas
    json_str = re.sub(r',\s*([}\]])', r'\1', json_str)
    # Fix unescaped newlines in strings (within double-quoted values)
    # Try to balance braces
    open_braces = json_str.count('{') - json_str.count('}')
    if open_braces > 0:
        json_str += '}' * open_braces
    return json_str


# ---------------------------------------------------------------------------
# Score merging with original predictions
# ---------------------------------------------------------------------------

def _merge_function_scores(
    original: List[dict],
    refined: List[dict],
    refinement_weight: float = 0.7,
) -> List[dict]:
    """Merge original function predictions with refined scores.

    Uses weighted combination:
      combined = (1 - w) * original_score + w * refined_score

    Functions only in refined list get a low original_score (0.1).
    Functions only in original list keep their score.
    """
    # Build lookup maps
    orig_by_key: Dict[Tuple[str, str], dict] = {}
    for f in original:
        name = _normalize_refiner_item(f)
        if not name:
            continue
        key = (name["file"], name["function"])
        orig_by_key[key] = {"item": f, "score": name["score"]}

    refined_by_key: Dict[Tuple[str, str], dict] = {}
    for r in refined:
        key = (r["file"], r["function"])
        refined_by_key[key] = r

    all_keys = set(orig_by_key.keys()) | set(refined_by_key.keys())

    merged = []
    w = refinement_weight

    for key in all_keys:
        orig = orig_by_key.get(key)
        ref = refined_by_key.get(key)

        if orig and ref:
            # Both: weighted combination
            combined = (1 - w) * orig["score"] + w * ref["score"]
            item = dict(orig["item"])
            item["score"] = round(combined, 4)
            item["reason"] = ref.get("reason", item.get("reason", ""))
            item["source"] = "refined"
            merged.append(item)
        elif ref:
            # Only in refined: new function extracted by tree-sitter
            merged.append({
                "function": ref["function"],
                "file": ref["file"],
                "score": round(w * ref["score"], 4),
                "reason": ref.get("reason", ""),
                "start_line": ref.get("start_line", 0),
                "end_line": ref.get("end_line", 0),
                "source": "refiner_only",
            })
        elif orig:
            # Only in original: keep as-is (might be from a file outside top-N)
            item = dict(orig["item"])
            item["source"] = "original"
            merged.append(item)

    return merged
