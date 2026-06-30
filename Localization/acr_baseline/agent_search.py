"""
LLM agent prompts for vulnerability localization search.
Adapted from auto-code-rover for vulnerability detection (not patch generation).

The agent iteratively selects search API calls, analyzes results,
and identifies vulnerability-relevant files, classes, functions.
"""

import json
import re
from typing import Optional

from acr_baseline.data_structures import MessageThread
from acr_baseline.model import ModelClient

SYSTEM_PROMPT = """You are a security researcher analyzing a vulnerability report for a software project.
The vulnerability report is marked between <issue> and </issue>.
Your task is to invoke search API calls to locate the code that is likely relevant to the vulnerability.
The collected code locations will be used to identify vulnerable files and functions.
Focus on finding source code that implements the functionality described in the vulnerability report.
"""

SELECT_PROMPT = """Based on the vulnerability report, use the following search APIs to explore the codebase:

- search_class(class_name: str): Search for a class in the entire codebase.
- search_class_in_file(class_name: str, file_name: str): Search for a class in a specific file.
- search_method_in_file(method_name: str, file_path: str): Search for a method/function in a specific file.
- search_method_in_class(method_name: str, class_name: str): Search for a method within a specific class.
- search_method(method_name: str): Search for a method/function in the entire codebase.
- search_code(code_str: str): Search for a code string in the entire codebase.
- search_code_in_file(code_str: str, file_path: str): Search for a code string in a specific file.
- get_code_around_line(file_path: str, line_number: int, window_size: int): Get code around a line number.

You can use multiple search APIs in one round. Each API call must have concrete arguments.

Now analyze the vulnerability report and select necessary APIs to locate the vulnerable code.
Output your API calls in this format:
```json
{"API_calls": ["search_method('authenticate')", "search_code('buffer_overflow')"], "bug_locations": []}
```"""

ANALYZE_PROMPT = """Let's analyze the collected context:
1. What does this code do?
2. How does it relate to the vulnerability described in the report?
3. Is this code likely to be the vulnerable location, or do we need more context?"""

ANALYZE_AND_SELECT_PROMPT = """Based on your analysis, answer in this EXACT JSON format:

```json
{
  "API_calls": ["search_method('someFunc')"],
  "bug_locations": [
    {
      "file": "src/module/file.ext",
      "class": "ClassName",
      "method": "methodName",
      "intended_behavior": "This code handles user input without proper bounds checking, causing buffer overflow..."
    }
  ]
}
```

Rules:
- If you need more context: fill API_calls, leave bug_locations EMPTY [].
- If you found vulnerability locations: leave API_calls EMPTY [], fill bug_locations.
- Each bug location MUST have: file, class (can be empty string), method (can be empty string), intended_behavior.
- Only include locations clearly related to the vulnerability.
- File paths should be relative to the project root.
"""


def prepare_issue_prompt(problem_stmt: str) -> str:
    """Sanitize and tag the issue statement."""
    problem_wo_comments = re.sub(r"<!--.*?-->", "", problem_stmt, flags=re.DOTALL)
    lines = problem_wo_comments.split("\n")
    lines = [x.strip() for x in lines]
    lines = [x for x in lines if x]
    return "<issue>\n" + "\n".join(lines) + "\n</issue>"


def init_search_thread(issue_stmt: str, sbfl_result: str = "") -> MessageThread:
    """Initialize the message thread for search."""
    msg_thread = MessageThread()
    msg_thread.add_system(SYSTEM_PROMPT)
    msg_thread.add_user(prepare_issue_prompt(issue_stmt))
    if sbfl_result:
        msg_thread.add_user(
            "External analysis tool results (use if helpful):\n" + sbfl_result)
    msg_thread.add_user(SELECT_PROMPT)
    return msg_thread


def select_apis(client: ModelClient, msg_thread: MessageThread) -> tuple[str, Optional[dict]]:
    """LLM call to select search APIs. Returns (response_text, parsed_json_or_None)."""
    response = client.call(msg_thread.to_msg(), temperature=0.0, max_tokens=4096)
    msg_thread.add_model(response)
    parsed = _extract_json(response)
    return response, parsed


def analyze_results(
    client: ModelClient,
    msg_thread: MessageThread,
    search_results: str,
) -> tuple[str, Optional[dict]]:
    """LLM call to analyze search results and decide next step.
    Returns (response_text, parsed_json_or_None).
    """
    msg_thread.add_user(search_results)
    msg_thread.add_user(ANALYZE_PROMPT)

    # First call: analysis
    response1 = client.call(msg_thread.to_msg(), temperature=0.0, max_tokens=4096)
    msg_thread.add_model(response1)

    # Second call: decide (more search or identify locations)
    msg_thread.add_user(ANALYZE_AND_SELECT_PROMPT)
    response2 = client.call(msg_thread.to_msg(), temperature=0.0, max_tokens=4096)
    msg_thread.add_model(response2)

    parsed = _extract_json(response2)
    return response2, parsed


def _extract_json(text: str) -> Optional[dict]:
    """Extract JSON object from LLM response text."""
    # Try ```json ... ``` block
    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try bare JSON object
    for match in re.finditer(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text, re.DOTALL):
        try:
            result = json.loads(match.group())
            if "API_calls" in result or "bug_locations" in result:
                return result
        except json.JSONDecodeError:
            continue

    return None
