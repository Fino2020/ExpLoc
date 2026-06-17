"""
LocAgent LLM agent — multi-turn code localization using ICFG graph tools.

Adapted from LocAgent's auto_search_main.py auto_search_process.
Uses the project's LLM API fallback chain (DS_KEY → DEFAULT_KEY → DEEPSEEK).
"""

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx
from openai import OpenAI

from shared.config import (
    USE_FIRST_KEY, USE_FIRST_URL,
    OPENAI_DS_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL,
    DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL,
)

from .tools import (
    search_code_snippets,
    explore_tree_structure,
    explore_graph_structure,
    TOOL_DESCRIPTIONS,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LLM backend fallback chain
# ---------------------------------------------------------------------------

def _get_all_backends() -> List[Tuple[OpenAI, str]]:
    backends = []
    if USE_FIRST_KEY and USE_FIRST_URL:
        backends.append((
            OpenAI(api_key=USE_FIRST_KEY, base_url=USE_FIRST_URL, max_retries=2,
                   timeout=httpx.Timeout(300.0, connect=30.0, read=300.0)),
            OPENAI_MODEL,
        ))
    if OPENAI_DS_API_KEY and OPENAI_BASE_URL:
        backends.append((
            OpenAI(api_key=OPENAI_DS_API_KEY, base_url=OPENAI_BASE_URL, max_retries=2,
                   timeout=httpx.Timeout(300.0, connect=30.0, read=300.0)),
            OPENAI_MODEL,
        ))
    if DEEPSEEK_API_KEY:
        backends.append((
            OpenAI(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL, max_retries=2,
                   timeout=httpx.Timeout(300.0, connect=30.0, read=300.0)),
            DEEPSEEK_MODEL,
        ))
    return backends


# ---------------------------------------------------------------------------
# Prompts (adapted from LocAgent)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an experienced software security analyst and static analysis expert.
Given a vulnerability report, perform thorough static analysis to localize the vulnerable code using the available tools.

Focus on:
- Tracing the flow of execution through critical paths, conditions, loops, and function calls.
- Identifying deviations, potential errors, or unexpected behavior that could contribute to the vulnerability.
- Considering how dynamic binding, late resolution, or other runtime behavior may influence the code's behavior.
- Highlighting possible root causes or key areas for further inspection.
"""

TASK_INSTRUCTION = """
Given the following vulnerability report, your objective is to localize the specific files, functions, and lines of code that are related to the vulnerability.

Follow these steps to localize the issue:

## Step 1: Categorize and Extract Key Problem Information
- Classify the problem statement into: Problem description, error trace, code to reproduce, and additional context.
- Identify modules mentioned in each category.
- Use extracted keywords and line numbers to search for relevant code references.

## Step 2: Locate Referenced Modules
- Accurately determine specific modules by exploring the repository structure.
- Analyze the described execution flow to identify specific modules or components being referenced.
- Pay attention to distinguishing between modules with similar names.
- Output format for collected modules: 'file_path:QualifiedName'

## Step 3: Analyze and Reproduce the Problem
- Clarify the purpose of the issue.
- If addressing unexpected behavior: Focus on localizing modules containing potential bugs.
- Reconstruct the execution flow: Identify main entry points, trace function calls, class interactions.
- Identify potential breakpoints causing the issue.

## Step 4: Locate Areas for Modification
- Locate specific files, functions, or lines of code requiring changes.
- Consider upstream and downstream dependencies that may affect or be affected.
- If applicable, identify where to introduce new fields, functions, or variables.
- Think thoroughly: List multiple potential solutions and consider edge cases.

## Output Format for Final Results:
Your final answer should list the locations, wrapped with triple backticks.
Each location should include file path, function name, and line numbers, ordered by importance.

### Example Output:
```
path/to/file1.py
function: calculate_sum
line: 45

path/to/file2.py
class: RequestHandler
function: process_request
line: 120
line: 156
```

## Important Notes:
- Use the available tools to search for code and explore dependencies.
- When calling a tool, use EXACTLY this format:
  ```tool
  function_name(arg1=value1, arg2=value2)
  ```
- You can use: search_code_snippets, explore_tree_structure, explore_graph_structure.
- After each tool call, you will receive the result in the next turn.
- When you have found all relevant locations, output your final answer in the format above.
- Think thoroughly — it's fine if your analysis is long.
"""

FAKE_USER_MSG = (
    "Verify if the found locations contain ALL necessary information to address the vulnerability. "
    "Check for any relevant references in other parts of the codebase that may not have appeared in search results. "
    "If you think you have solved the task, please output your final answer with the file/function listings "
    "wrapped in triple backticks. IMPORTANT: YOU SHOULD NEVER ASK FOR HUMAN HELP.\n"
)


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

def _call_llm(messages: List[dict], backends: List[Tuple[OpenAI, str]],
              temperature: float = 0.7, max_tokens: int = 4096) -> Tuple[str, int, int]:
    """Call LLM with fallback across backends. Returns (content, prompt_tokens, completion_tokens)."""
    last_error = None
    for client, model in backends:
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            content = resp.choices[0].message.content or ""
            return content, resp.usage.prompt_tokens, resp.usage.completion_tokens
        except Exception as e:
            last_error = e
            logger.warning(f"LLM backend {model} failed: {e}")
            continue
    raise RuntimeError(f"All LLM backends failed. Last error: {last_error}")


def _parse_tool_call(content: str) -> Optional[Tuple[str, dict]]:
    """Detect tool call in LLM response. Returns (func_name, kwargs) or None."""
    # Look for ```tool ... ``` blocks
    pattern = r"```tool\s*\n(.*?)\n```"
    matches = re.findall(pattern, content, re.DOTALL)
    if matches:
        for match in matches:
            func_name, kwargs = _parse_call_str(match.strip())
            if func_name:
                return func_name, kwargs

    # Look for print(func_name(...)) patterns
    print_pattern = r"print\s*\(\s*(search_code_snippets|explore_tree_structure|explore_graph_structure)\s*\((.*?)\)\s*\)"
    matches = re.findall(print_pattern, content, re.DOTALL)
    if matches:
        func_name, args_str = matches[0]
        kwargs = _parse_kwargs(args_str)
        return func_name, kwargs

    return None


def _parse_call_str(call_str: str) -> Tuple[Optional[str], dict]:
    """Parse 'func_name(key=value, ...)' into (name, kwargs)."""
    match = re.match(r"(search_code_snippets|explore_tree_structure|explore_graph_structure)\s*\((.*)\)", call_str, re.DOTALL)
    if not match:
        return None, {}
    func_name = match.group(1)
    args_str = match.group(2)
    return func_name, _parse_kwargs(args_str)


def _parse_kwargs(args_str: str) -> dict:
    """Best-effort parse Python kwargs string into dict."""
    kwargs = {}
    # Match key=value pairs where value can be list, string, int, etc.
    pairs = re.findall(r"(\w+)\s*=\s*(\[.*?\]|'.*?'|\".*?\"|\d+|True|False|None)", args_str, re.DOTALL)
    for key, val in pairs:
        try:
            kwargs[key] = eval(val)
        except Exception:
            kwargs[key] = val.strip("'\"")
    return kwargs


def _execute_tool(func_name: str, kwargs: dict) -> str:
    """Execute a tool call and return the result string."""
    try:
        if func_name == "search_code_snippets":
            return search_code_snippets(**kwargs)
        elif func_name == "explore_tree_structure":
            return explore_tree_structure(**kwargs)
        elif func_name == "explore_graph_structure":
            return explore_graph_structure(**kwargs)
        else:
            return f"Unknown tool: {func_name}"
    except Exception as e:
        return f"Tool execution error: {e}"


def _parse_final_output(content: str, repo_path: str) -> Tuple[List[str], List[str], List[str]]:
    """Extract file, module (class), and function lists from final LLM output."""
    found_files = []
    found_modules = []
    found_functions = []

    # Look for code blocks containing file listings, OR scan the full content
    code_blocks = re.findall(r"```(.*?)```", content, re.DOTALL)
    if code_blocks:
        text = "\n".join(code_blocks)
    else:
        text = content

    current_file = None
    current_class = None

    for line in text.split("\n"):
        line = line.strip().strip(":").strip()
        if not line:
            continue

        # File path detection — must end with a recognized code extension
        fp = _extract_file_path(line, repo_path)
        if fp:
            current_file = fp
            current_class = None
            if current_file not in found_files:
                found_files.append(current_file)
            continue

        # Class detection
        if re.match(r"^class\s*:", line, re.IGNORECASE):
            cls_name = re.split(r"[: ]", line, maxsplit=1)[-1].strip().split()[0]
            if re.match(r"^[A-Za-z_]\w*$", cls_name):
                current_class = cls_name
                if current_file:
                    module_id = f"{current_file}:{cls_name}"
                    if module_id not in found_modules:
                        found_modules.append(module_id)
            continue

        # Function/method detection
        if re.match(r"^(function|method|def)\s*:", line, re.IGNORECASE):
            func_name = re.split(r"[: ]", line, maxsplit=1)[-1].strip().split()[0]
            func_name = func_name.strip("(){};")
            if re.match(r"^[A-Za-z_]\w*$", func_name) and len(func_name) > 2:
                if current_file:
                    if current_class and "." not in func_name:
                        func_id = f"{current_file}:{current_class}.{func_name}"
                    else:
                        func_id = f"{current_file}:{func_name}"
                    if func_id not in found_functions:
                        found_functions.append(func_id)
            continue

        # Line detection
        if re.match(r"^lines?\s*:", line, re.IGNORECASE):
            continue

        # Explicit file:function format (most reliable)
        if ":" in line and current_file is None:
            parts = line.split()
            for part in parts:
                part = part.strip("`'\"()[]{};,")
                if re.match(r"^[\w\.\-/]+\.\w{1,5}:[\w.]+$", part):
                    file_part, func_part = part.rsplit(":", 1)
                    fp = _extract_file_path(file_part, repo_path)
                    if fp and re.match(r"^[A-Za-z_]\w*$", func_part) and len(func_part) > 2:
                        if fp not in found_files:
                            found_files.append(fp)
                            current_file = fp
                        func_id = f"{fp}:{func_part}"
                        if func_id not in found_functions:
                            found_functions.append(func_id)

    return found_files, found_modules, found_functions


def _extract_file_path(line: str, repo_path: str) -> Optional[str]:
    """Extract a valid file path from a text line — must end with code extension."""
    # Remove markdown formatting
    clean = line.strip("`*[](){}\"'")
    # Find a path ending with a known code extension
    match = re.search(
        r"[\w\.\-/]+\.(" + "|".join(e.lstrip(".") for e in _CODE_EXTS) + r")\b",
        clean, re.IGNORECASE)
    if match:
        return match.group(0)
    # Try exact file check
    candidate = clean.split()[0].strip("`'\"")
    full = os.path.join(repo_path, candidate)
    if os.path.isfile(full):
        return candidate
    return None


_CODE_EXTS = {".py", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp",
              ".java", ".kt", ".js", ".ts", ".go", ".rs", ".rb", ".php",
              ".swift", ".cs", ".pl", ".pm"}


def run_agent(
    issue_title: str,
    issue_body: str,
    repo_path: str,
    max_iterations: int = 30,
    temperature: float = 0.7,
) -> Tuple[List[str], List[str], List[str], dict]:
    """Run LocAgent for a single CVE.

    Returns:
        (found_files, found_modules, found_functions, metadata)
    """
    backends = _get_all_backends()
    if not backends:
        raise RuntimeError("No LLM backends configured")

    # Build initial messages
    problem_statement = f"--- BEGIN PROBLEM STATEMENT ---\nTitle: {issue_title}\n\n{issue_body}\n--- END PROBLEM STATEMENT ---\n"

    instruction = TASK_INSTRUCTION + "\n" + TOOL_DESCRIPTIONS

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": instruction},
        {"role": "user", "content": problem_statement},
    ]

    total_prompt_tokens = 0
    total_completion_tokens = 0
    final_output = ""

    logger.info(f"Starting LocAgent for repo: {repo_path}")

    for iteration in range(max_iterations):
        logger.debug(f"=== Iteration {iteration + 1}/{max_iterations} ===")

        try:
            content, pt, ct = _call_llm(messages, backends, temperature=temperature)
            total_prompt_tokens += pt
            total_completion_tokens += ct
        except RuntimeError as e:
            logger.error(f"LLM call failed: {e}")
            break

        messages.append({"role": "assistant", "content": content})

        # Check if this is a final answer (has code block with file paths)
        if _has_final_output(content):
            final_output = content
            logger.info("Agent produced final output")
            break

        # Check for tool calls
        tool_result = _parse_tool_call(content)
        if tool_result:
            func_name, kwargs = tool_result
            logger.info(f"Executing tool: {func_name}({kwargs})")
            start_time = time.time()
            result = _execute_tool(func_name, kwargs)
            elapsed = time.time() - start_time
            logger.info(f"Tool {func_name} completed in {elapsed:.1f}s (result length: {len(result)})")

            # Truncate very long tool results
            if len(result) > 8000:
                result = result[:8000] + "\n... (truncated)"

            messages.append({
                "role": "user",
                "content": f"OBSERVATION:\n{result}\n\n{FAKE_USER_MSG}",
            })
        else:
            # No tool call found — prompt to continue
            messages.append({
                "role": "user",
                "content": FAKE_USER_MSG,
            })

    # Parse final output
    if final_output:
        logger.debug(f"Final output:\n{final_output[:2000]}")
        found_files, found_modules, found_functions = _parse_final_output(
            final_output, repo_path)
    else:
        # Try to extract from last response
        last_content = messages[-1].get("content", "") if messages else ""
        logger.debug(f"Last message (no final):\n{last_content[:2000]}")
        found_files, found_modules, found_functions = _parse_final_output(
            last_content, repo_path)

    metadata = {
        "prompt_tokens": total_prompt_tokens,
        "completion_tokens": total_completion_tokens,
        "iterations": iteration + 1,
        "final_output_snippet": final_output[:500] if final_output else "",
    }

    return found_files, found_modules, found_functions, metadata


def _has_final_output(content: str) -> bool:
    """Check if the LLM response contains a final answer with file listings."""
    # Must have a code block with structured file/function listings
    code_blocks = re.findall(r"```(.*?)```", content, re.DOTALL)
    for block in code_blocks:
        block_stripped = block.strip()
        # Count lines that look like actual file paths (with code extensions)
        file_lines = re.findall(
            r"[\w\.\-/]+\.(py|c|cpp|cc|cxx|h|hpp|hh|java|kt|js|ts|jsx|tsx|go|rs|rb|php|swift|cs|pl|pm)\b",
            block_stripped, re.IGNORECASE)
        func_lines = re.findall(r"(function|method|def)\s*:", block_stripped, re.IGNORECASE)
        class_lines = re.findall(r"class\s*:", block_stripped, re.IGNORECASE)
        line_refs = re.findall(r"lines?\s*:", block_stripped, re.IGNORECASE)

        # Need at least 1 file path AND some function/class/line detail
        if len(file_lines) >= 1 and (len(func_lines) + len(class_lines) + len(line_refs)) >= 1:
            return True
        # Or: explicit Final Answer / ## Final / "here is my final" marker
        if re.search(r"(final answer|## Final|here is my final)", block_stripped, re.IGNORECASE):
            if len(file_lines) >= 1:
                return True
    return False
