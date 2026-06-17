"""
Agent tool definitions for RepoMem vulnerability localization.

Tools match the RepoMem paper (ICLR 2026):
  1. search_commit  — BM25 keyword search over commit messages
  2. examine_commit — full commit details + patch + linked issues
  3. view_summary   — cached LLM file functionality summary
"""

import json
from typing import Dict, List, Optional

from mem_retrieval.rms_retriever import RMSRetriever


TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "search_commit",
            "description": (
                "Search the repository's commit history for commits relevant "
                "to the vulnerability. Uses BM25 keyword matching against "
                "commit messages. Returns matching commits with scores, "
                "dates, and linked issues. Use this to find past fixes for "
                "similar vulnerabilities."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Free-text query describing the vulnerability pattern",
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "Number of commits to return (default: 10)",
                        "default": 10,
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "examine_commit",
            "description": (
                "Get full details for a specific commit: full diff/patch, "
                "list of modified files, linked issues. Use this to understand "
                "exactly what code was changed and how a past vulnerability "
                "was fixed."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "sha": {
                        "type": "string",
                        "description": "Commit SHA hash",
                    },
                },
                "required": ["sha"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "view_summary",
            "description": (
                "Get the cached LLM-generated functionality summary for a "
                "file. Provides a high-level description of what the file "
                "does. Use this to understand whether a frequently-modified "
                "file is relevant to the vulnerability being analyzed."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_name": {
                        "type": "string",
                        "description": "File path or basename to look up",
                    },
                },
                "required": ["file_name"],
            },
        },
    },
]


class ToolExecutor:
    """Executes RepoMem tool calls against the RMS retriever."""

    def __init__(self, rms: RMSRetriever):
        self.rms = rms
        self.call_log: List[dict] = []

    def execute(self, tool_name: str, arguments: dict) -> str:
        """Execute a tool call and return JSON result."""
        self.call_log.append({"tool": tool_name, "args": arguments})

        if tool_name == "search_commit":
            query = arguments.get("query", "")
            top_k = int(arguments.get("top_k", 10))
            before_date = arguments.get("before_date", "")
            results = self.rms.search_commit(query, top_k=top_k, before_date=before_date)
            return json.dumps({
                "count": len(results),
                "results": results,
            }, ensure_ascii=False)

        elif tool_name == "examine_commit":
            sha = arguments.get("sha", "")
            result = self.rms.examine_commit(sha)
            if result is None:
                return json.dumps({"error": f"Commit not found: {sha}"})
            # Truncate patch to avoid exceeding context
            if len(result.get("patch", "")) > 8000:
                result["patch"] = result["patch"][:8000] + "\n... [truncated]"
            return json.dumps(result, ensure_ascii=False)

        elif tool_name == "view_summary":
            file_name = arguments.get("file_name", "")
            summary = self.rms.view_summary(file_name)
            if summary is None:
                return json.dumps({
                    "file_name": file_name,
                    "summary": None,
                    "note": "No cached summary for this file",
                })
            return json.dumps({
                "file_name": file_name,
                "summary": summary,
            }, ensure_ascii=False)

        else:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})
