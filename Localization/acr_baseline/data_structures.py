"""
Data structures for ACR baseline — adapted from auto-code-rover.
Simplified: no patch-related structures, just localization.
"""

import json
from dataclasses import dataclass
from pathlib import Path


class MessageThread:
    """Conversation thread with LLM. Serializable to JSON."""

    def __init__(self, messages=None):
        self.messages: list[dict] = messages or []

    def add(self, role: str, message: str):
        self.messages.append({"role": role, "content": message})

    def add_system(self, message: str):
        self.add("system", message)

    def add_user(self, message: str):
        self.add("user", message)

    def add_model(self, message: str):
        self.messages.append({"role": "assistant", "content": message})

    def to_msg(self) -> list[dict]:
        return self.messages

    def save_to_file(self, file_path: str):
        Path(file_path).write_text(json.dumps(self.messages, indent=4))

    @classmethod
    def load_from_file(cls, file_path: str) -> "MessageThread":
        with open(file_path) as f:
            messages = json.load(f)
        return cls(messages)


@dataclass
class SearchResult:
    """A code fragment found by search APIs."""

    file_path: str       # absolute path
    start: int | None    # 1-based line
    end: int | None      # 1-based line
    class_name: str | None
    func_name: str | None
    code: str

    def to_tagged_str(self, project_root: str) -> str:
        rel_path = self.file_path
        if project_root and self.file_path.startswith(project_root):
            rel_path = self.file_path[len(project_root):].lstrip("/\\")
        result = f"<file>{rel_path}</file>"
        if self.class_name:
            result += f"\n<class>{self.class_name}</class>"
        if self.func_name:
            result += f"\n<func>{self.func_name}</func>"
        result += f"\n<code>\n{self.code}\n</code>"
        return result


class BugLocation:
    """Confirmed vulnerable location."""

    rel_file_path: str
    abs_file_path: str
    start: int | None
    end: int | None
    class_name: str | None
    method_name: str | None
    code: str
    intended_behavior: str  # renamed from "intended behavior" — adapted for vuln: describes the vulnerability

    def __init__(self, search_res: SearchResult, project_path: str, intended_behavior: str):
        self.abs_file_path = search_res.file_path
        if project_path and search_res.file_path.startswith(project_path):
            rel = search_res.file_path[len(project_path):].lstrip("/\\")
        else:
            rel = search_res.file_path
        self.rel_file_path = rel

        self.start = search_res.start
        self.end = search_res.end
        self.class_name = search_res.class_name
        self.method_name = search_res.func_name
        self.intended_behavior = intended_behavior
        self.code = search_res.code

    def to_dict(self) -> dict:
        return {
            "rel_file_path": self.rel_file_path,
            "abs_file_path": self.abs_file_path,
            "start": self.start,
            "end": self.end,
            "class_name": self.class_name,
            "method_name": self.method_name,
            "code": self.code,
            "intended_behavior": self.intended_behavior,
        }

    def __eq__(self, other):
        if not isinstance(other, BugLocation):
            return False
        return self.rel_file_path == other.rel_file_path and self.start == other.start and self.end == other.end

    def __hash__(self):
        return hash((self.rel_file_path, self.start, self.end))

    def __str__(self):
        return (
            f"<file>{self.rel_file_path}</file>\n"
            f"<class>{self.class_name}</class>\n"
            f"<method>{self.method_name}</method>\n"
            f"<code>\n{self.code}\n</code>"
        )

    def __repr__(self):
        return self.__str__()
