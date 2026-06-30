"""
Search manager — orchestrates the iterative search loop.
Adapted from auto-code-rover search_manage.py.

Flow:
  1. Initialize MessageThread with issue report
  2. LLM selects search APIs → backend executes → results returned
  3. LLM analyzes results → either identifies bug_locations OR requests more APIs
  4. Loop continues until bug_locations found or max rounds reached
  5. Return ranked BugLocations
"""

import inspect
import json
import os
from pathlib import Path
from typing import Optional

from acr_baseline.agent_search import (
    init_search_thread, select_apis, analyze_results,
)
from acr_baseline.data_structures import BugLocation, MessageThread
from acr_baseline.model import ModelClient
from acr_baseline.search_backend import SearchBackend


def parse_function_invocation(api_call: str) -> tuple[str, list]:
    """Parse a function call string like 'func_name(arg1, arg2)' -> (func_name, [arg1, arg2])."""
    import re
    match = re.match(r'(\w+)\((.*)\)', api_call.strip())
    if not match:
        raise ValueError(f"Cannot parse API call: {api_call}")
    func_name = match.group(1)
    args_str = match.group(2)

    # Parse args - handle quoted strings
    args = []
    for arg_match in re.finditer(r"""'([^']*)'|"([^"]*)"|(\d+)""", args_str):
        if arg_match.group(1) is not None:
            args.append(arg_match.group(1))
        elif arg_match.group(2) is not None:
            args.append(arg_match.group(2))
        elif arg_match.group(3) is not None:
            args.append(int(arg_match.group(3)))

    return func_name, args


class SearchManager:
    """Orchestrates iterative search for vulnerability location."""

    def __init__(self, project_path: str, output_dir: str):
        self.output_dir = os.path.join(output_dir, "search")
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        self.backend = SearchBackend(project_path)
        self.tool_call_layers: list[list[dict]] = []

    def search_iterative(
        self,
        issue_stmt: str,
        max_rounds: int = 10,
    ) -> tuple[list[BugLocation], MessageThread, list[str]]:
        """Main search loop. Returns (bug_locations, message_thread, ranked_files).

        Args:
            issue_stmt: The vulnerability report text.
            max_rounds: Maximum number of search rounds.

        Returns:
            bug_locations: List of identified vulnerable locations.
            message_thread: Full conversation history.
            ranked_files: List of (file_path, score) tuples for file-level ranking.
        """
        client = ModelClient()
        msg_thread = init_search_thread(issue_stmt)

        round_no = 0
        bug_locations: list[BugLocation] = []
        search_result_msg = ""

        for round_no in range(max_rounds):
            self.start_new_tool_call_layer()

            if round_no == 0:
                # Round 0: select APIs
                response, parsed = select_apis(client, msg_thread)
            else:
                # Subsequent rounds: analyze results, then decide
                response, parsed = analyze_results(client, msg_thread, search_result_msg)

            # Save round state
            conv_file = Path(self.output_dir, f"search_round_{round_no}.json")
            msg_thread.save_to_file(str(conv_file))

            if parsed is None:
                continue

            api_calls = parsed.get("API_calls", [])
            bug_locs_raw = parsed.get("bug_locations", [])

            # Check if agent identified bug locations
            if bug_locs_raw and (not api_calls):
                bug_locs = self._resolve_bug_locations(bug_locs_raw)
                if bug_locs:
                    self.dump_tool_call_layers_to_file()
                    # Extract ranked files
                    ranked_files = self._extract_ranked_files(bug_locations)
                    return bug_locs, msg_thread, ranked_files

                # Locations couldn't be resolved - ask agent to try again
                search_result_msg = (
                    "Some bug locations could not be resolved in the codebase. "
                    "Please use more specific search API calls first, "
                    "or provide more precise file/class/method names."
                )
                continue

            # Execute API calls
            if not api_calls:
                search_result_msg = (
                    "Please provide either API_calls to search for more context, "
                    "or bug_locations if you have identified the vulnerability."
                )
                continue

            collated = ""
            for api_call in api_calls:
                try:
                    func_name, func_args = parse_function_invocation(api_call)
                except ValueError as e:
                    collated += f"Error parsing API call '{api_call}': {e}\n\n"
                    continue

                # Execute the backend function
                if not hasattr(self.backend, func_name):
                    collated += f"Unknown API: {func_name}\n\n"
                    continue

                func = getattr(self.backend, func_name)
                try:
                    result_str, _, call_ok = func(*func_args)
                except Exception as e:
                    result_str = f"Error calling {api_call}: {e}"
                    call_ok = False

                collated += f"Result of {api_call}:\n{result_str}\n\n"
                self.add_tool_call_to_curr_layer(
                    func_name, dict(zip(self._get_arg_names(func_name), func_args)),
                    call_ok,
                )

            search_result_msg = collated

        # Max rounds reached
        self.dump_tool_call_layers_to_file()
        ranked_files = self._extract_ranked_files(bug_locations)
        return bug_locations, msg_thread, ranked_files

    def _resolve_bug_locations(self, raw_locs: list[dict]) -> list[BugLocation]:
        """Resolve raw agent bug locations into concrete BugLocation objects."""
        all_locs: list[BugLocation] = []
        for loc_dict in raw_locs:
            resolved = self.backend.get_bug_loc_snippets_new(loc_dict)
            all_locs.extend(resolved)

        # Deduplicate
        unique: list[BugLocation] = []
        seen = set()
        for loc in all_locs:
            key = (loc.rel_file_path, loc.start, loc.end)
            if key not in seen:
                seen.add(key)
                unique.append(loc)

        # Save
        out_file = Path(self.output_dir, "bug_locations.json")
        out_file.write_text(json.dumps([loc.to_dict() for loc in unique], indent=4))

        return unique

    def _extract_ranked_files(self, bug_locations: list[BugLocation]) -> list[str]:
        """Extract ranked file list from bug locations (preserving order)."""
        seen = set()
        files = []
        for loc in bug_locations:
            if loc.rel_file_path not in seen:
                seen.add(loc.rel_file_path)
                files.append(loc.rel_file_path)
        return files

    def _get_arg_names(self, func_name: str) -> list[str]:
        """Get argument names of a backend method."""
        func = getattr(self.backend, func_name)
        while hasattr(func, "__wrapped__"):
            func = func.__wrapped__
        spec = inspect.getfullargspec(func)
        return spec.args[1:]  # skip 'self'

    def start_new_tool_call_layer(self):
        self.tool_call_layers.append([])

    def add_tool_call_to_curr_layer(self, func_name: str, args: dict, result: bool):
        self.tool_call_layers[-1].append({
            "func_name": func_name,
            "arguments": args,
            "call_ok": result,
        })

    def dump_tool_call_layers_to_file(self):
        out = Path(self.output_dir, "tool_call_layers.json")
        out.write_text(json.dumps(self.tool_call_layers, indent=4))
