"""
Multi-language search backend using tree-sitter.
Builds class/function index for all source files in a repo.
Replaces ast-based Python-only search from original auto-code-rover.

Supported languages: C, C++, Python, JavaScript, Java, Go, Ruby, Rust, PHP.
"""

import glob
import os
import re
from collections import defaultdict, namedtuple
from pathlib import Path
from typing import Optional

from acr_baseline.data_structures import BugLocation, SearchResult

# Reuse tree-sitter utils from shared/
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.tree_sitter_utils import (
    _get_parser, detect_lang, _node_lines, _node_text,
    _get_func_signature, _get_class_name, _CLASS_TYPES,
    EXT_TO_LANG, LANG_PARSER_MODULES, extract_all_functions_with_bodies,
)

LineRange = namedtuple("LineRange", ["start", "end"])

RESULT_SHOW_LIMIT = 5

# File extensions per language for source file discovery
SOURCE_EXTENSIONS = {
    "python": {".py"},
    "c": {".c", ".h"},
    "cpp": {".cpp", ".cc", ".cxx", ".hpp", ".hh", ".h", ".c"},
    "java": {".java"},
    "javascript": {".js", ".mjs", ".jsx", ".ts", ".tsx"},
    "go": {".go"},
    "ruby": {".rb"},
    "rust": {".rs"},
    "php": {".php", ".phtml"},
}

# Directories to skip when scanning for source files
SKIP_DIRS = {
    "test", "tests", "__pycache__", "node_modules", "vendor",
    ".git", "build", "dist", "target", "cmake-build-debug",
    "venv", ".venv", "env", ".env", ".tox", ".eggs",
    "third_party", "thirdparty", "external", "doc", "docs",
    "examples", "example", "benchmarks", "benchmark",
}

# Non-source files to always skip
SKIP_FILES = {
    "setup.py", "conftest.py", "__init__.py",
    "package.json", "package-lock.json",
    "Makefile", "CMakeLists.txt",
}


def _is_test_file(file_path: str) -> bool:
    """Check if a file is a test file."""
    parts = Path(file_path).parts
    for part in parts:
        if part in ("test", "tests", "testing", "__pycache__", "node_modules"):
            return True
    name = Path(file_path).name.lower()
    if name.startswith("test_") or name.endswith("_test.py") or name.endswith("_test.go"):
        return True
    if name.startswith("test") and name.endswith(".py"):
        return True
    if "spec." in name and (name.endswith(".js") or name.endswith(".ts")):
        return True
    if name in SKIP_FILES:
        return True
    return False


def find_source_files(dir_path: str) -> list[str]:
    """Find all source files in a directory, skipping tests and build artifacts."""
    source_files = []
    for root, dirs, files in os.walk(dir_path):
        # Skip unwanted directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]

        for f in files:
            ext = os.path.splitext(f)[1].lower()
            file_path = os.path.join(root, f)
            if _is_test_file(file_path):
                continue
            # Check if extension belongs to any supported language
            if ext in EXT_TO_LANG or ext in {".h", ".hpp", ".hh"}:
                source_files.append(file_path)

    return source_files


def get_code_snippets(file_path: str, start: int, end: int) -> str:
    """Get code lines from start to end (1-based, inclusive)."""
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if start < 1:
            start = 1
        if end > len(lines):
            end = len(lines)
        return "".join(lines[start - 1:end])
    except Exception:
        return ""


def get_code_region_around_line(file_path: str, line_no: int, window_size: int = 10) -> Optional[str]:
    """Get code around a specific line number."""
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if line_no < 1 or line_no > len(lines):
            return None
        start = max(1, line_no - window_size)
        end = min(len(lines) + 1, line_no + window_size)
        result = ""
        for i in range(start, end):
            result += f"{i} {lines[i - 1]}"
        return result
    except Exception:
        return None


class SearchBackend:
    """Multi-language search index built with tree-sitter."""

    def __init__(self, project_path: str):
        self.project_path = os.path.abspath(project_path)
        self.parsed_files: list[str] = []

        # class_name -> [(file_path, LineRange)]
        self.class_index: dict[str, list[tuple[str, LineRange]]] = defaultdict(list)

        # class_name -> {func_name -> [(file_path, LineRange)]}
        self.class_func_index: dict[str, dict[str, list[tuple[str, LineRange]]]] = defaultdict(
            lambda: defaultdict(list))

        # func_name -> [(file_path, LineRange)]
        self.function_index: dict[str, list[tuple[str, LineRange]]] = defaultdict(list)

        # file_path -> (file_content, line list) cache for text search
        self._file_cache: dict[str, list[str]] = {}

        self._build_index()

    # ------------------------------------------------------------------
    # Index building
    # ------------------------------------------------------------------

    def _build_index(self):
        """Build class/function indexes from all source files."""
        source_files = find_source_files(self.project_path)
        for file_path in source_files:
            self._index_file(file_path)

    def _index_file(self, file_path: str):
        """Parse a single file with tree-sitter and update indexes."""
        lang = detect_lang(file_path)
        if lang == "unknown":
            return

        parser = _get_parser(lang)
        if parser is None:
            return

        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            return

        if not source.strip():
            return

        try:
            tree = parser.parse(bytes(source, "utf-8"))
        except Exception:
            return

        root = tree.root_node

        # Walk all nodes
        self._walk_nodes(root, file_path, lang, source)

        self.parsed_files.append(file_path)

        # Cache file lines for text search
        self._file_cache[file_path] = source.split("\n")

    def _walk_nodes(self, node, file_path: str, lang: str, source: str):
        """Recursively walk AST nodes and build indexes."""
        cls_types = _CLASS_TYPES.get(lang, set())

        for child in node.children:
            node_type = child.type

            # Check if this node is a class/struct
            cls_name = _get_class_name(child, lang)
            if cls_name:
                start, end = _node_lines(child)
                self.class_index[cls_name].append((file_path, LineRange(start, end)))

                # Walk class members for methods
                body = (child.child_by_field_name("body") or
                        child.child_by_field_name("class_body") or
                        child.child_by_field_name("declaration_list"))
                if body:
                    self._walk_class_members(body, file_path, lang, source, cls_name)
                else:
                    # Some languages don't have explicit body field
                    self._walk_class_members(child, file_path, lang, source, cls_name)

                continue

            # Check if this is a top-level function
            func_info = _get_func_signature(child, lang, source)
            if func_info:
                fname = func_info["name"]
                start = func_info["start_line"]
                end_line, _ = _node_lines(child)
                # Determine end line
                end = end_line[1] if isinstance(end_line, tuple) else end_line
                self.function_index[fname].append((file_path, LineRange(start, end)))
                continue

            # Recurse into containers
            container_types = {
                "declaration_list", "class_body", "block",
                "source_file", "program", "module", "translation_unit",
                "expression_statement", "object",
                "namespace_definition",
            }
            if node_type in container_types or node_type in cls_types:
                self._walk_nodes(child, file_path, lang, source)

    def _walk_class_members(self, node, file_path: str, lang: str, source: str, cls_name: str):
        """Walk members of a class to find methods."""
        container_types = {"declaration_list", "class_body", "block", "object", "program"}

        for child in node.children:
            node_type = child.type

            # Try function signature extraction
            func_info = _get_func_signature(child, lang, source)
            if func_info:
                fname = func_info["name"]
                start = func_info["start_line"]
                end_line, _ = _node_lines(child)
                end_val = end_line[1] if isinstance(end_line, tuple) else end_line
                if not isinstance(end_val, int):
                    end_val = start
                self.class_func_index[cls_name][fname].append(
                    (file_path, LineRange(start, end_val)))
                continue

            # Nested class
            cls_name2 = _get_class_name(child, lang)
            if cls_name2:
                start, end = _node_lines(child)
                self.class_index[cls_name2].append((file_path, LineRange(start, end)))
                body = (child.child_by_field_name("body") or
                        child.child_by_field_name("class_body") or
                        child.child_by_field_name("declaration_list"))
                if body:
                    self._walk_class_members(body, file_path, lang, source, cls_name2)
                continue

            # Recurse
            if node_type in container_types:
                self._walk_class_members(child, file_path, lang, source, cls_name)

    # ------------------------------------------------------------------
    # Search utilities
    # ------------------------------------------------------------------

    def _file_line_to_class_and_func(self, file_path: str, line_no: int) -> tuple:
        """Given file + line, find containing class and function."""
        for cls_name, funcs in self.class_func_index.items():
            for func_name, entries in funcs.items():
                for fname, (start, end) in entries:
                    if fname == file_path and start <= line_no <= end:
                        return cls_name, func_name
        for func_name, entries in self.function_index.items():
            for fname, (start, end) in entries:
                if fname == file_path and start <= line_no <= end:
                    return None, func_name
        return None, None

    def _search_code_text(self, code_str: str, file_path: str | None = None) -> list[SearchResult]:
        """Text-based code search. If file_path given, search only that file."""
        files = [file_path] if file_path else list(self._file_cache.keys())

        results: list[SearchResult] = []
        for fpath in files:
            if fpath not in self._file_cache:
                continue
            lines = self._file_cache[fpath]
            try:
                source = "\n".join(lines)
            except Exception:
                continue

            # Search for the code string
            pattern = re.compile(re.escape(code_str), re.IGNORECASE)
            for match in pattern.finditer(source):
                # Find line number of match
                matched_pos = match.start()
                line_no = source.count("\n", 0, matched_pos) + 1

                # Get context
                context_start = max(0, line_no - 5 - 1)
                context_end = min(len(lines), line_no + 5)
                snippet = "\n".join(
                    f"{i + 1} {lines[i]}" for i in range(context_start, context_end))

                class_name, func_name = self._file_line_to_class_and_func(fpath, line_no)
                results.append(SearchResult(
                    file_path=fpath, start=line_no, end=line_no,
                    class_name=class_name, func_name=func_name, code=snippet))

        return results

    def _get_matching_files(self, target_name: str) -> list[str]:
        """Find files whose path/name matches the target."""
        candidates = []
        target_lower = target_name.lower()
        for f in self.parsed_files:
            rel = f
            if f.startswith(self.project_path):
                rel = f[len(self.project_path):].lstrip("/\\")
            if target_lower in rel.lower():
                candidates.append(f)
        if not candidates:
            # Fallback: try matching just the file name
            for f in self.parsed_files:
                if target_lower in os.path.basename(f).lower():
                    candidates.append(f)
        return candidates

    def _relativize(self, abs_path: str) -> str:
        if self.project_path and abs_path.startswith(self.project_path):
            return abs_path[len(self.project_path):].lstrip("/\\")
        return abs_path

    # ------------------------------------------------------------------
    # Public search APIs (matching original ACR interface)
    # Each returns: (tool_result_str, list[SearchResult], bool_success)
    # ------------------------------------------------------------------

    def search_class(self, class_name: str) -> tuple[str, list[SearchResult], bool]:
        """Search for a class across the entire codebase."""
        search_res: list[SearchResult] = []
        if class_name not in self.class_index:
            return f"Could not find class '{class_name}' in the codebase.", [], False

        entries = self.class_index[class_name]
        for fname, (start, end) in entries:
            code = get_code_snippets(fname, start, min(start + 10, end))
            search_res.append(SearchResult(
                file_path=fname, start=start, end=end,
                class_name=class_name, func_name=None, code=code))

        if not search_res:
            return f"Could not find class '{class_name}' in the codebase.", [], False

        if len(search_res) > RESULT_SHOW_LIMIT:
            result = f"Found {len(search_res)} classes named '{class_name}'. Showing first {RESULT_SHOW_LIMIT}:\n\n"
        else:
            result = f"Found {len(search_res)} class(es) named '{class_name}':\n\n"

        for idx, res in enumerate(search_res[:RESULT_SHOW_LIMIT]):
            result += f"Result {idx + 1}:\n{res.to_tagged_str(self.project_path)}\n\n"

        return result, search_res[:RESULT_SHOW_LIMIT], True

    def search_class_in_file(self, class_name: str, file_name: str) -> tuple[str, list[SearchResult], bool]:
        """Search for a class in a specific file."""
        search_res: list[SearchResult] = []
        if class_name not in self.class_index:
            return f"Could not find class '{class_name}' in file '{file_name}'.", [], False

        matching_files = self._get_matching_files(file_name)
        if not matching_files:
            return f"Could not find file matching '{file_name}'.", [], False

        for fname, (start, end) in self.class_index[class_name]:
            if fname in matching_files:
                code = get_code_snippets(fname, start, min(start + 15, end))
                search_res.append(SearchResult(
                    file_path=fname, start=start, end=end,
                    class_name=class_name, func_name=None, code=code))

        if not search_res:
            return f"Class '{class_name}' not found in file '{file_name}'.", [], False

        result = f"Found class '{class_name}' in file:\n"
        for idx, res in enumerate(search_res):
            result += f"\n{res.to_tagged_str(self.project_path)}\n"

        return result, search_res, True

    def search_method_in_file(self, method_name: str, file_path: str) -> tuple[str, list[SearchResult], bool]:
        """Search for a method/function in a specific file."""
        search_res: list[SearchResult] = []
        matching_files = self._get_matching_files(file_path)
        if not matching_files:
            return f"Could not find file matching '{file_path}'.", [], False

        # Check class methods
        for cls_name, funcs in self.class_func_index.items():
            if method_name in funcs:
                for fname, (start, end) in funcs[method_name]:
                    if fname in matching_files:
                        code = get_code_snippets(fname, start, end)
                        search_res.append(SearchResult(
                            file_path=fname, start=start, end=end,
                            class_name=cls_name, func_name=method_name, code=code))

        # Check top-level functions
        if method_name in self.function_index:
            for fname, (start, end) in self.function_index[method_name]:
                if fname in matching_files:
                    code = get_code_snippets(fname, start, end)
                    search_res.append(SearchResult(
                        file_path=fname, start=start, end=end,
                        class_name=None, func_name=method_name, code=code))

        if not search_res:
            return f"Method '{method_name}' not found in file '{file_path}'.", [], False

        result = f"Found method '{method_name}' in file:\n"
        for idx, res in enumerate(search_res):
            result += f"\n{res.to_tagged_str(self.project_path)}\n"

        return result, search_res, True

    def search_method_in_class(self, method_name: str, class_name: str) -> tuple[str, list[SearchResult], bool]:
        """Search for a method within a specific class."""
        search_res: list[SearchResult] = []
        if class_name not in self.class_func_index:
            return f"Could not find class '{class_name}'.", [], False
        if method_name not in self.class_func_index[class_name]:
            return f"Method '{method_name}' not found in class '{class_name}'.", [], False

        for fname, (start, end) in self.class_func_index[class_name][method_name]:
            code = get_code_snippets(fname, start, end)
            search_res.append(SearchResult(
                file_path=fname, start=start, end=end,
                class_name=class_name, func_name=method_name, code=code))

        if not search_res:
            return f"Method '{method_name}' not found in class '{class_name}'.", [], False

        result = f"Found method '{method_name}' in class '{class_name}':\n"
        for idx, res in enumerate(search_res):
            result += f"\n{res.to_tagged_str(self.project_path)}\n"

        return result, search_res, True

    def search_method(self, method_name: str) -> tuple[str, list[SearchResult], bool]:
        """Search for a method/function across the entire codebase."""
        search_res: list[SearchResult] = []

        # Check class methods first
        for cls_name, funcs in self.class_func_index.items():
            if method_name in funcs:
                for fname, (start, end) in funcs[method_name]:
                    code = get_code_snippets(fname, start, min(start + 20, end))
                    search_res.append(SearchResult(
                        file_path=fname, start=start, end=end,
                        class_name=cls_name, func_name=method_name, code=code))

        # Check top-level functions
        if method_name in self.function_index:
            for fname, (start, end) in self.function_index[method_name]:
                code = get_code_snippets(fname, start, min(start + 20, end))
                search_res.append(SearchResult(
                    file_path=fname, start=start, end=end,
                    class_name=None, func_name=method_name, code=code))

        if not search_res:
            return f"Could not find method/function '{method_name}' in the codebase.", [], False

        if len(search_res) > RESULT_SHOW_LIMIT:
            result = f"Found {len(search_res)} results for '{method_name}'. Showing first {RESULT_SHOW_LIMIT}:\n\n"
        else:
            result = f"Found {len(search_res)} result(s) for '{method_name}':\n\n"

        for idx, res in enumerate(search_res[:RESULT_SHOW_LIMIT]):
            result += f"Result {idx + 1}:\n{res.to_tagged_str(self.project_path)}\n\n"

        return result, search_res[:RESULT_SHOW_LIMIT], True

    def search_code(self, code_str: str) -> tuple[str, list[SearchResult], bool]:
        """Full-text search for a code string across the codebase."""
        results = self._search_code_text(code_str)

        if not results:
            return f"Could not find code matching '{code_str[:100]}...'.", [], False

        if len(results) > RESULT_SHOW_LIMIT:
            out = f"Found {len(results)} matches for the code. Showing first {RESULT_SHOW_LIMIT}:\n\n"
        else:
            out = f"Found {len(results)} match(es):\n\n"

        for idx, res in enumerate(results[:RESULT_SHOW_LIMIT]):
            out += f"Match {idx + 1}:\n{res.to_tagged_str(self.project_path)}\n\n"

        return out, results[:RESULT_SHOW_LIMIT], True

    def search_code_in_file(self, code_str: str, file_path: str) -> tuple[str, list[SearchResult], bool]:
        """Full-text search for code in a specific file."""
        matching_files = self._get_matching_files(file_path)

        all_results: list[SearchResult] = []
        for f in matching_files:
            results = self._search_code_text(code_str, f)
            all_results.extend(results)

        if not all_results:
            return f"Could not find code matching '{code_str[:100]}...' in file '{file_path}'.", [], False

        if len(all_results) > RESULT_SHOW_LIMIT:
            out = f"Found {len(all_results)} matches. Showing first {RESULT_SHOW_LIMIT}:\n\n"
        else:
            out = f"Found {len(all_results)} match(es):\n\n"

        for idx, res in enumerate(all_results[:RESULT_SHOW_LIMIT]):
            out += f"Match {idx + 1}:\n{res.to_tagged_str(self.project_path)}\n\n"

        return out, all_results[:RESULT_SHOW_LIMIT], True

    def get_code_around_line(self, file_path: str, line_number: int, window_size: int = 10) -> tuple[str, list[SearchResult], bool]:
        """Get code around a specific line in a file."""
        matching_files = self._get_matching_files(file_path)
        if not matching_files:
            return f"Could not find file matching '{file_path}'.", [], False

        f = matching_files[0]
        snippet = get_code_region_around_line(f, line_number, window_size)
        if snippet is None:
            return f"Invalid line number {line_number} for file '{file_path}'.", [], False

        class_name, func_name = self._file_line_to_class_and_func(f, line_number)
        res = SearchResult(
            file_path=f, start=line_number, end=line_number,
            class_name=class_name, func_name=func_name, code=snippet)

        return f"Code around line {line_number} in '{self._relativize(f)}':\n```\n{snippet}\n```", [res], True

    def get_file_content(self, file_path: str) -> tuple[str, list[SearchResult], bool]:
        """Get content of a file (first 100 lines)."""
        matching_files = self._get_matching_files(file_path)
        if not matching_files:
            return f"Could not find file matching '{file_path}'.", [], False

        f = matching_files[0]
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except Exception:
            return f"Could not read file '{file_path}'.", [], False

        # Return first 100 lines
        snippet = "".join(lines[:100])
        total = len(lines)
        prefix = f"File '{self._relativize(f)}' ({total} lines total, showing first 100):\n```\n"

        res = SearchResult(
            file_path=f, start=1, end=min(100, total),
            class_name=None, func_name=None, code=snippet)

        return prefix + snippet + "\n```", [res], True

    # ------------------------------------------------------------------
    # Bug location resolution
    # ------------------------------------------------------------------

    def get_bug_loc_snippets_new(self, bug_location_dict: dict) -> list[BugLocation]:
        """Resolve a bug location from agent output.

        Follows original ACR logic: try method+class → method+file →
        class+file → class → method → file.
        """
        tmp_file = bug_location_dict.get("file", "")
        tmp_method = bug_location_dict.get("method", "")
        tmp_class = bug_location_dict.get("class", "")
        intended_behavior = bug_location_dict.get("intended_behavior", "")

        # Handle Class.method format
        if not tmp_class and tmp_method and "." in tmp_method:
            parts = tmp_method.split(".")
            if len(parts) == 2:
                tmp_class, tmp_method = parts

        if not (tmp_method or tmp_class or tmp_file):
            return []

        call_ok = False
        search_res: list[SearchResult] = []

        # Try: method in class
        if tmp_method and tmp_class:
            _, curr_res, call_ok = self.search_method_in_class(tmp_method, tmp_class)
            search_res.extend(curr_res)

        # Try: method in file
        if (not call_ok) and tmp_method and tmp_file:
            _, curr_res, call_ok = self.search_method_in_file(tmp_method, tmp_file)
            search_res.extend(curr_res)

        # Try: class in file
        if (not call_ok) and tmp_class and tmp_file:
            _, curr_res, call_ok = self.search_class_in_file(tmp_class, tmp_file)
            search_res.extend(curr_res)

        # Try: class only
        if (not call_ok) and tmp_class:
            _, curr_res, call_ok = self.search_class(tmp_class)
            search_res.extend(curr_res)

        # Try: method only
        if (not call_ok) and tmp_method:
            _, curr_res, call_ok = self.search_method(tmp_method)
            search_res.extend(curr_res)

        # Try: file only
        if (not call_ok) and tmp_file:
            _, curr_res, call_ok = self.get_file_content(tmp_file)
            search_res.extend(curr_res)

        if not call_ok:
            return []

        final_locs: list[BugLocation] = []
        for res in search_res:
            if res.start is None or res.end is None:
                continue
            bug_loc = BugLocation(res, self.project_path, intended_behavior)
            final_locs.append(bug_loc)

        return final_locs
