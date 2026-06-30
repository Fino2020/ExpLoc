"""
Tree-sitter parser management and lightweight code extraction.

Reuses parser patterns from Explainable_Localization/tree_sitter_gt.py.
Focus: function signatures (name, params, line range) and file-level
structure (imports, class declarations) — NOT full function bodies.

Used by step1_locator/file_context.py for prompt assembly.
"""

import os
import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

import tree_sitter

# ---------------------------------------------------------------------------
# Language → parser mapping (lazy init)
# ---------------------------------------------------------------------------

_PARSERS: Dict[str, tree_sitter.Parser] = {}

LANG_PARSER_MODULES = {
    "c":           "tree_sitter_c",
    "cpp":         "tree_sitter_cpp",
    "python":      "tree_sitter_python",
    "javascript":  "tree_sitter_javascript",
    "java":        "tree_sitter_java",
    "go":          "tree_sitter_go",
    "ruby":        "tree_sitter_ruby",
    "rust":        "tree_sitter_rust",
    "php":         "tree_sitter_php",
}

EXT_TO_LANG = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".py": "python", ".pyx": "python",
    ".js": "javascript", ".mjs": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".rs": "rust",
    ".php": "php", ".phtml": "php",
}


def _get_parser(lang: str) -> Optional[tree_sitter.Parser]:
    """Get or create a tree-sitter parser for the given language."""
    if lang not in LANG_PARSER_MODULES:
        return None
    if lang not in _PARSERS:
        try:
            mod = __import__(LANG_PARSER_MODULES[lang], fromlist=["language"])
            if hasattr(mod, "language"):
                lang_obj = mod.language()
            elif hasattr(mod, "language_php"):
                lang_obj = mod.language_php()
            elif hasattr(mod, "language_php_only"):
                lang_obj = mod.language_php_only()
            else:
                candidates = [x for x in dir(mod)
                              if x.startswith("language") and callable(getattr(mod, x))]
                if candidates:
                    lang_obj = getattr(mod, candidates[0])()
                else:
                    return None
            parser = tree_sitter.Parser(tree_sitter.Language(lang_obj))
            _PARSERS[lang] = parser
        except Exception:
            return None
    return _PARSERS[lang]


def detect_lang(file_path: str) -> str:
    """Detect language key from file extension."""
    ext = os.path.splitext(file_path)[1].lower()
    return EXT_TO_LANG.get(ext, "unknown")


# ---------------------------------------------------------------------------
# Lightweight file structure extraction (for Step 1 prompt context)
# ---------------------------------------------------------------------------

class FileSignature:
    def __init__(self, file_path: str, language: str, line_count: int):
        self.file_path = file_path
        self.language = language
        self.line_count = line_count
        self.functions: List[dict] = []
        self.classes: List[str] = []
        self.imports: List[str] = []

    def to_dict(self) -> dict:
        return {
            "file": self.file_path,
            "language": self.language,
            "lines": self.line_count,
            "functions": self.functions,
            "classes": self.classes,
            "imports": self.imports,
        }


def extract_file_signature(file_path: str, source: Optional[str] = None) -> Optional[FileSignature]:
    """Extract lightweight file structure: function signatures, classes, imports.

    Reads only the structural elements, never function bodies.
    """
    lang = detect_lang(file_path)
    if lang == "unknown":
        return None

    if source is None:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            return None

    if not source.strip():
        return None

    sig = FileSignature(file_path, lang, source.count("\n") + 1)

    parser = _get_parser(lang)
    if parser is None:
        return sig

    tree = parser.parse(bytes(source, "utf-8"))
    root = tree.root_node

    # Extract imports from first 80 lines
    sig.imports = _extract_imports(root, lang, source)

    # Walk top-level nodes for functions and classes
    _walk_top_level(root, lang, source, sig)

    return sig


def extract_signatures_batch(file_paths: List[str], max_files: int = 20) -> List[FileSignature]:
    """Extract signatures for multiple files, returning up to max_files results."""
    results = []
    for fp in file_paths[:max_files]:
        if not os.path.isfile(fp):
            continue
        sig = extract_file_signature(fp)
        if sig:
            results.append(sig)
    return results


# ---------------------------------------------------------------------------
# Full function extraction with body snippets (for second-pass refinement)
# ---------------------------------------------------------------------------
#
# Unlike extract_file_signature which just gets signatures for prompt context,
# these functions extract ALL functions from a file WITH body snippets, so
# the LLM can discriminate which specific function is vulnerable within an
# already-identified file.

def extract_all_functions_with_bodies(
    file_path: str,
    body_snippet_lines: int = 25,
    source: Optional[str] = None,
) -> Optional[List[dict]]:
    """Extract ALL functions from a file with name, params, line range, body snippet.

    Walks top-level AND class-member functions recursively. Returns None if
    the file cannot be parsed.

    If source is provided, use it directly instead of reading the file.
    """
    lang = detect_lang(file_path)
    if lang == "unknown":
        return None

    if source is None:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            return None

    if not source.strip():
        return None

    parser = _get_parser(lang)
    if parser is None:
        return None

    tree = parser.parse(bytes(source, "utf-8"))
    root = tree.root_node
    source_lines = source.split("\n")

    funcs = []

    def _collect_functions(node, enclosing_class: str = "", depth: int = 0):
        # Container node types to recurse into
        _container_types = {
            "declaration_list", "class_body", "block",
            "source_file", "program", "module", "translation_unit",
            "expression_statement", "object",
            "assignment_expression", "variable_declaration",
            "lexical_declaration", "variable_declarator",
            # C/C++ preprocessor nodes (files wrapped in #ifdef etc.)
            "preproc_ifdef", "preproc_if", "preproc_else", "preproc_elif",
            # C/C++ linkage blocks (extern "C" { ... } wraps all funcs)
            "linkage_specification",
            # Function bodies — recurse into nested/inner functions
            "function_definition", "async_function_definition",
            "method_definition", "method_declaration",
            "function_declaration", "function_item",
            "decorated_definition",  # Python decorator wrappers
        }

        for child in node.children:
            node_type = child.type

            # JavaScript: function expressions in object literals (pairs)
            js_func_info = _get_js_func_expr(child, lang, source, source_lines,
                                             body_snippet_lines, enclosing_class)
            if js_func_info:
                funcs.append(js_func_info)
            else:
                # Standard function/method definitions
                func_info = _get_func_with_body(child, lang, source, source_lines,
                                                body_snippet_lines, enclosing_class)
                if func_info:
                    funcs.append(func_info)

            # Recurse into class bodies
            cls_types = _CLASS_TYPES.get(lang, set())
            if node_type in cls_types:
                name_node = child.child_by_field_name("name")
                cls_name = name_node.text.decode() if name_node else ""
                body = child.child_by_field_name("body") or \
                    child.child_by_field_name("declaration_list") or \
                    child.child_by_field_name("class_body")
                if body:
                    _collect_functions(body, cls_name)
                else:
                    _collect_functions(child, cls_name)
            elif node_type in _container_types:
                _collect_functions(child, enclosing_class)

    _collect_functions(root)

    return funcs if funcs else []


def _get_func_with_body(node, lang: str, source: str, source_lines: List[str],
                         body_snippet_lines: int, enclosing_class: str = "",
                         force_name: str = "") -> Optional[dict]:
    """Extract function info with body snippet.

    Returns {name, params, start_line, end_line, body_snippet, file, language}
    or None if the node is not a function definition.
    """
    node_type = node.type

    name = None
    params = "..."

    if lang == "python" and node_type == "function_definition":
        name_node = node.child_by_field_name("name")
        params_node = node.child_by_field_name("parameters")
        if name_node:
            name = name_node.text.decode()
            params = _node_text(params_node, source) if params_node else "()"

    elif lang in ("c", "cpp") and node_type == "function_definition":
        declarator = node.child_by_field_name("declarator")
        if declarator:
            name = _find_declarator_name(declarator)

    elif lang == "javascript" and node_type in (
        "function_declaration", "generator_function_declaration",
        "method_definition",
    ):
        name_node = node.child_by_field_name("name")
        params_node = node.child_by_field_name("parameters")
        if name_node:
            name = name_node.text.decode()
            params = _node_text(params_node, source) if params_node else "()"
        if enclosing_class:
            name = f"{enclosing_class}.{name}"

    elif lang == "javascript" and node_type == "function_expression":
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = _node_text(params_node, source)
        if force_name:
            name = force_name
        else:
            name_node = node.child_by_field_name("name")
            if name_node:
                name = name_node.text.decode()

    elif lang == "javascript" and node_type == "arrow_function":
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = _node_text(params_node, source)
        if force_name:
            name = force_name

    elif lang == "java" and node_type in ("method_declaration", "constructor_declaration"):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = name_node.text.decode()
            cls = enclosing_class or _find_enclosing_class(node, lang)
            if cls:
                name = f"{cls}.{name}"

    elif lang == "go" and node_type in ("function_declaration", "method_declaration"):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = name_node.text.decode()
            receiver = node.child_by_field_name("receiver")
            if receiver:
                rec_text = _node_text(receiver, source)
                type_match = re.search(r'\*?(\w+)\s*$', rec_text.strip("() "))
                if type_match:
                    name = f"{type_match.group(1)}.{name}"

    elif lang == "ruby" and node_type == "method":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = name_node.text.decode()

    elif lang == "rust" and node_type == "function_item":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = name_node.text.decode()

    elif lang == "php" and node_type in ("function_definition", "method_declaration"):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = name_node.text.decode()
            cls = enclosing_class or _find_enclosing_class(node, lang)
            if cls:
                name = f"{cls}::{name}"

    if not name:
        return None

    start_line, end_line = _node_lines(node)

    # Extract body snippet (skip the signature/opening line)
    body_start = start_line + 1
    body_end = min(start_line + body_snippet_lines + 1, end_line, len(source_lines))
    if body_end <= body_start:
        body_end = min(body_start + 5, len(source_lines))
    body_snippet = "\n".join(source_lines[body_start - 1:body_end])

    return {
        "name": name,
        "params": params,
        "start_line": start_line,
        "end_line": end_line,
        "body_snippet": body_snippet,
        "language": lang,
    }


def _extract_js_member_name(node) -> str:
    """Extract full name from a JS member_expression chain.

    E.g. Template.prototype.compile → "Template.prototype.compile"
    """
    if node.type == "identifier":
        return node.text.decode()
    if node.type == "property_identifier":
        return node.text.decode()
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        obj_name = _extract_js_member_name(obj) if obj else ""
        prop_name = _extract_js_member_name(prop) if prop else ""
        if obj_name and prop_name:
            return f"{obj_name}.{prop_name}"
        return obj_name or prop_name
    return ""


def _get_js_func_expr(node, lang: str, source: str, source_lines: List[str],
                      body_snippet_lines: int, enclosing_class: str = "") -> Optional[dict]:
    """Extract JS function expressions: object literal methods, prototype
    assignments, and variable-assigned functions.

    Handles:
      - { methodName: function() {} }     (pair)
      - { methodName: () => {} }          (pair with arrow)
      - obj.method = function() {}        (assignment_expression)
      - obj.method = () => {}             (assignment_expression with arrow)
      - var/let/const name = function() {}  (variable_declarator)
      - var/let/const name = () => {}       (variable_declarator with arrow)
    """
    if lang != "javascript":
        return None

    node_type = node.type
    force_name = ""

    if node_type == "pair":
        key_node = node.child_by_field_name("key")
        value_node = node.child_by_field_name("value")
        if key_node and value_node and value_node.type in (
            "function_expression", "arrow_function"
        ):
            force_name = key_node.text.decode()
            if enclosing_class:
                force_name = f"{enclosing_class}.{force_name}"
            return _get_func_with_body(value_node, lang, source, source_lines,
                                       body_snippet_lines, enclosing_class,
                                       force_name=force_name)

    elif node_type == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left and right and right.type in ("function_expression", "arrow_function"):
            force_name = _extract_js_member_name(left)
            if force_name:
                return _get_func_with_body(right, lang, source, source_lines,
                                           body_snippet_lines, enclosing_class,
                                           force_name=force_name)

    elif node_type == "variable_declarator":
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node and value_node and value_node.type in (
            "function_expression", "arrow_function"
        ):
            force_name = name_node.text.decode()
            if enclosing_class:
                force_name = f"{enclosing_class}.{force_name}"
            return _get_func_with_body(value_node, lang, source, source_lines,
                                       body_snippet_lines, enclosing_class,
                                       force_name=force_name)

    return None


# ---------------------------------------------------------------------------
# Signature extraction (no bodies)
# ---------------------------------------------------------------------------

def _walk_top_level(node, lang: str, source: str, sig: FileSignature):
    """Walk only top-level nodes to find function/class declarations."""
    for child in node.children:
        node_type = child.type

        # Function signatures
        func_info = _get_func_signature(child, lang, source)
        if func_info:
            sig.functions.append(func_info)

        # Class/struct declarations
        cls_name = _get_class_name(child, lang)
        if cls_name:
            sig.classes.append(cls_name)

        # Recurse into class bodies for methods (but not deeper)
        if node_type in _CLASS_TYPES.get(lang, set()):
            for member in child.children:
                if member.type == "declaration_list" or member.type == "class_body":
                    for inner in member.children:
                        inner_func = _get_func_signature(inner, lang, source)
                        if inner_func:
                            sig.functions.append(inner_func)


_CLASS_TYPES = {
    "python": {"class_definition"},
    "java": {"class_declaration", "interface_declaration"},
    "javascript": {"class_declaration", "class"},
    "cpp": {"class_specifier", "struct_specifier"},
    "c": {"struct_specifier"},
    "go": {"type_declaration"},
    "ruby": {"class", "module"},
    "rust": {"struct_item", "enum_item"},
    "php": {"class_declaration", "interface_declaration"},
}


def _get_func_signature(node, lang: str, source: str) -> Optional[dict]:
    """Extract function name, params, and line range (no body)."""
    node_type = node.type

    if lang == "python" and node_type == "function_definition":
        name_node = node.child_by_field_name("name")
        params_node = node.child_by_field_name("parameters")
        if name_node:
            name = name_node.text.decode()
            params = _node_text(params_node, source) if params_node else "()"
            sl, _ = _node_lines(node)
            return {"name": name, "params": params, "start_line": sl}

    elif lang in ("c", "cpp") and node_type == "function_definition":
        declarator = node.child_by_field_name("declarator")
        if declarator:
            name = _find_declarator_name(declarator)
            if name:
                sl, _ = _node_lines(node)
                return {"name": name, "params": "...", "start_line": sl}

    elif lang == "javascript" and node_type in (
        "function_declaration", "generator_function_declaration",
        "method_definition",
    ):
        name_node = node.child_by_field_name("name")
        params_node = node.child_by_field_name("parameters")
        if name_node:
            name = name_node.text.decode()
            params = _node_text(params_node, source) if params_node else "()"
            sl, _ = _node_lines(node)
            return {"name": name, "params": params, "start_line": sl}

    elif lang == "java" and node_type in ("method_declaration", "constructor_declaration"):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = name_node.text.decode()
            cls = _find_enclosing_class(node, lang)
            if cls:
                name = f"{cls}.{name}"
            sl, _ = _node_lines(node)
            return {"name": name, "params": "...", "start_line": sl}

    elif lang == "go" and node_type in ("function_declaration", "method_declaration"):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = name_node.text.decode()
            receiver = node.child_by_field_name("receiver")
            if receiver:
                rec_text = _node_text(receiver, source)
                type_match = re.search(r'\*?(\w+)\s*$', rec_text.strip("() "))
                if type_match:
                    name = f"{type_match.group(1)}.{name}"
            sl, _ = _node_lines(node)
            return {"name": name, "params": "...", "start_line": sl}

    elif lang == "ruby" and node_type == "method":
        name_node = node.child_by_field_name("name")
        if name_node:
            sl, _ = _node_lines(node)
            return {"name": name_node.text.decode(), "params": "...", "start_line": sl}

    elif lang == "rust" and node_type == "function_item":
        name_node = node.child_by_field_name("name")
        if name_node:
            sl, _ = _node_lines(node)
            return {"name": name_node.text.decode(), "params": "...", "start_line": sl}

    elif lang == "php" and node_type in ("function_definition", "method_declaration"):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = name_node.text.decode()
            cls = _find_enclosing_class(node, lang)
            if cls:
                name = f"{cls}::{name}"
            sl, _ = _node_lines(node)
            return {"name": name, "params": "...", "start_line": sl}

    return None


def _get_class_name(node, lang: str) -> Optional[str]:
    """Extract class/struct/interface name from a node."""
    type_map = {
        "python": {"class_definition"},
        "java": {"class_declaration", "interface_declaration"},
        "javascript": {"class_declaration", "class"},
        "cpp": {"class_specifier", "struct_specifier"},
        "c": {"struct_specifier"},
        "ruby": {"class", "module"},
        "rust": {"struct_item", "enum_item", "trait_item"},
        "php": {"class_declaration", "interface_declaration", "trait_declaration"},
    }
    expected = type_map.get(lang, set())
    if node.type not in expected:
        return None
    name_node = node.child_by_field_name("name")
    if name_node:
        return name_node.text.decode()
    return None


def _find_enclosing_class(node, lang: str) -> Optional[str]:
    """Walk up to find enclosing class name."""
    p = node.parent
    class_types = _CLASS_TYPES.get(lang, set())
    while p is not None:
        if p.type in class_types:
            name_node = p.child_by_field_name("name")
            if name_node:
                return name_node.text.decode()
        p = p.parent
    return None


# ---------------------------------------------------------------------------
# Import/include extraction (first 80 lines only)
# ---------------------------------------------------------------------------

def _extract_imports(root, lang: str, source: str) -> List[str]:
    """Extract import/include directives from the first 80 lines of source."""
    lines = source.split("\n")[:80]
    imports = []

    if lang == "python":
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")):
                imports.append(stripped)
    elif lang in ("c", "cpp"):
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#include"):
                imports.append(stripped)
    elif lang == "javascript":
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(("import ", "require(", "const {", "export ")):
                imports.append(stripped)
    elif lang == "java":
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("import "):
                imports.append(stripped)
    elif lang == "go":
        in_import_block = False
        for line in lines:
            stripped = line.strip()
            if stripped == "import (":
                in_import_block = True
                continue
            if in_import_block:
                if stripped == ")":
                    in_import_block = False
                else:
                    imports.append(stripped)
            elif stripped.startswith("import "):
                imports.append(stripped)
    elif lang == "ruby":
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("require "):
                imports.append(stripped)
    elif lang == "rust":
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("use "):
                imports.append(stripped)
    elif lang == "php":
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(("use ", "require", "include")):
                imports.append(stripped)

    return imports


# ---------------------------------------------------------------------------
# Helpers (shared with tree_sitter_gt.py)
# ---------------------------------------------------------------------------

def _node_lines(node) -> Tuple[int, int]:
    """Get 1-based start and end line of a tree-sitter node."""
    return node.start_point[0] + 1, node.end_point[0] + 1


def _node_text(node, source: str) -> str:
    """Get the source text of a node."""
    return source[node.start_byte:node.end_byte]


def _find_declarator_name(node) -> Optional[str]:
    """Walk down a C/C++ declarator tree to find the function identifier."""
    if node.type == "identifier":
        return node.text.decode()
    if node.type == "qualified_identifier":
        parts = []
        for child in node.children:
            if child.type == "identifier":
                parts.append(child.text.decode())
            elif child.type == "qualified_identifier":
                inner = _find_declarator_name(child)
                if inner:
                    parts.append(inner)
        if parts:
            return "::".join(parts)
    if node.type in (
        "function_declarator", "pointer_declarator", "reference_declarator",
        "array_declarator", "field_identifier", "parenthesized_declarator",
        "qualified_identifier", "template_function",
    ):
        for child in node.children:
            name = _find_declarator_name(child)
            if name:
                return name
    return None
