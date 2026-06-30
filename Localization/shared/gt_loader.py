"""
Ground Truth loader — loads pre-computed GT from Dataset/GT/{CVE-ID}.json.

The GT files are produced by precompute_gt.py and consumed by evaluate.py.
This module provides read-only access for evaluation purposes only.
Must NOT be used during prediction (anti-leakage constraint).
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from shared.config import GT_DIR

# Files that should never be considered vulnerable code in GT.
# Evaluated case-insensitively against the basename or full relative path.
_EXCLUDE_BASENAME_PATTERNS = [
    # Autotools / Make
    "configure", "configure.ac", "configure.in",
    "makefile", "makefile.am", "makefile.in", "makefile.inc",
    "gnumakefile", "makefile.msc",
    # CMake
    "cmakelists.txt",
    # Python packaging
    "setup.py", "setup.cfg", "pyproject.toml", "manifest.in",
    # Node.js
    "package.json", "package-lock.json", "yarn.lock", "npm-shrinkwrap.json",
    # Rust
    "cargo.toml", "cargo.lock",
    # Java
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
    # CI/CD
    ".travis.yml", "appveyor.yml", ".appveyor.yml",
    "dockerfile", "docker-compose.yml", ".dockerignore",
    "jenkinsfile", ".gitlab-ci.yml", ".github",
    # Git
    ".gitignore", ".gitmodules", ".gitattributes",
    # PHP
    "composer.json", "composer.lock",
    # Version files
    "version", "version.txt", "version.py", "version.js",
    # Other packaging/manifest
    "manifest.json", "bower.json",
    # Auto-generated
    "configure.js", "configure.py",
    # IDE/config misc
    ".editorconfig", ".eslintrc", ".eslintrc.json", ".eslintrc.js",
    ".prettierrc", ".stylelintrc",
    ".babelrc", ".browserslistrc", ".npmrc",
    ".htaccess", ".npmignore",
    ".pre-commit-config.yaml", "vcs.xml",
]

_EXCLUDE_NAME_REGEX = re.compile(
    r"^(readme|changelog|changes|news|relnotes|releasenotes|authors|license|"
    r"copying|copyright|contributing|notice|acknowledgements|"
    r"thanks|history|release|whatsnew|todo|knownbugs|"
    r"install|installing|upgrading|migrating)",
    re.IGNORECASE,
)

_EXCLUDE_EXT_REGEX = re.compile(
    r"\.(md|rst|txt|adoc|markdown|pod|man|texi|tex|html|"
    r"gif|png|jpe?g|ico|svg|bmp|tiff?|"
    r"ttf|woff2?|eot|otf|"
    r"css|less|scss|sass|"
    r"spec|sql|pdf)$",
    re.IGNORECASE,
)

_TEST_FILE_REGEX = re.compile(
    r"(^|[/\\])(test[s]?[/\\]|test_|test(?=[A-Z])|_test\.|\.test\.|^test\.)",
)

_TEST_SUFFIX_REGEX = re.compile(
    r"(Test|Tests|TestCase|TestSuite)\.(py|c|cpp|java|go|ts|js|rb|php|rs)$",
)


# Path-level patterns to exclude (any file under these paths is non-code)
_EXCLUDE_PATH_PATTERNS = [
    "release-notes/",
    "releasenotes/",
    "release_notes/",
    "changelog/",
    "docs/",
    "documentation/",
    "examples/",
    "sample/",
    "samples/",
    "demo/",
    "vendor/",
    "node_modules/",
    "third_party/",
    "thirdparty/",
    ".idea/",
]


def _is_excluded_file(fpath: str) -> bool:
    """Check if a file path should be excluded from ground truth.

    Excludes: build/config files, documentation, test files.
    """
    fpath = fpath.replace("\\", "/")
    # Strip leading ./ or ../ components without stripping dotfile basenames
    while fpath.startswith("./") or fpath.startswith("../"):
        if fpath.startswith("./"):
            fpath = fpath[2:]
        else:
            fpath = fpath[3:]
    basename = os.path.basename(fpath).lower()
    name_no_ext = os.path.splitext(basename)[0].lower()

    # Known basenames
    if basename in _EXCLUDE_BASENAME_PATTERNS:
        return True

    # Doc-like names (README, CHANGES, RELNOTES, etc.)
    if _EXCLUDE_NAME_REGEX.match(name_no_ext):
        return True

    # Doc-like extensions (.md, .rst, .txt, etc.)
    if _EXCLUDE_EXT_REGEX.search(basename):
        return True

    # Path-level patterns (release-notes/, docs/, examples/, vendor/, etc.)
    fpath_lower = fpath.lower()
    for pat in _EXCLUDE_PATH_PATTERNS:
        if pat in fpath_lower:
            return True

    # Test files
    if _TEST_FILE_REGEX.search(fpath):
        return True
    if _TEST_SUFFIX_REGEX.search(basename):
        return True

    return False


def _remove_paired_headers(files: Set[str]) -> Set[str]:
    """Remove .h files that have a same-basename .c/.cpp/.cc file in the set.

    If both src/foo.h and src/foo.c are in GT, remove the .h file
    since the real vulnerability is in the implementation file.
    """
    c_exts = {".c", ".cpp", ".cc", ".cxx", ".c++"}
    h_exts = {".h", ".hpp", ".hh", ".hxx"}

    c_basenames: Set[str] = set()
    for f in files:
        base, ext = os.path.splitext(os.path.basename(f.lower()))
        if ext in c_exts:
            c_basenames.add(base)

    result = set()
    for f in files:
        base, ext = os.path.splitext(os.path.basename(f.lower()))
        if ext in h_exts and base in c_basenames:
            continue
        result.add(f)
    return result


# Keywords and common false positives that should never be GT function names.
# These come from regex mistakes in hunk-header and diff-body parsing.
_NOISE_FUNCTION_NAMES: Set[str] = {
    # C/C++ keywords
    "if", "else", "for", "while", "do", "switch", "case", "default",
    "return", "break", "continue", "goto",
    "void", "int", "char", "float", "double", "bool", "long", "short",
    "unsigned", "signed", "auto", "extern", "static", "const", "volatile",
    "register", "enum", "union", "typedef", "struct", "class",
    "sizeof", "throw", "try", "catch", "finally",
    "namespace", "using", "typename",
    # C++/Java access modifiers
    "public", "private", "protected", "virtual", "inline",
    "friend", "explicit", "override", "final", "abstract",
    # Memory
    "new", "delete", "malloc", "realloc", "free",
    "this", "self", "super", "nullptr", "null", "nil", "true", "false",
    # PHP
    "echo", "print", "die", "exit",
    "isset", "unset", "empty", "list", "array",
    "require", "require_once", "include", "include_once",
    "global", "function", "instanceof", "insteadof", "clone", "yield",
    "match", "fn",
    # JS/TS
    "var", "let", "const", "async", "await",
    "export", "import", "default", "from",
    # Python-specific (already handled by parser, but guard)
    "def",
    # Common false positives
    "set", "get", "on", "in", "as", "is", "or", "and", "not", "xor",
    # Node.js / CommonJS module patterns
    "exports", "module", "require", "describe", "it", "before", "after",
    "beforeeach", "aftereach", "setup", "teardown",
    "specify", "context", "suite", "test",
    # Synthetic names from extraction
    "__top_level__",
    # Generic property/option names
    "privacyoptions", "options", "config", "settings", "preferences",
    "verbose", "debug", "trace", "enabled", "disabled",
    "start", "stop", "init", "destroy", "reset", "restart", "clear",
    "open", "close", "read", "write", "send", "receive",
    # JS/TS specific false positives
    "isfloat", "isint", "isstring", "isbool", "isarray", "isobject",
    "isnull", "isundefined", "isnan", "isfinite",
    "tostring", "valueof", "hasownproperty", "isprototypeof",
    # Macro/constant-like patterns
    "api", "version", "major", "minor", "patch",
}

_NOISE_FUNCTION_PATTERN = re.compile(
    r"^UC_CPU_",  # Only match UC_CPU_* constants — generic uppercase patterns catch real macros
)


def _is_noise_function(func_name: str) -> bool:
    """Check if a function name is noise (keyword, type, or false positive)."""
    if not func_name or len(func_name) <= 1:
        return True
    low = func_name.lower().strip().rstrip(";{}()")
    if not low or len(low) <= 1:
        return True
    if low in _NOISE_FUNCTION_NAMES:
        return True
    if _NOISE_FUNCTION_PATTERN.match(func_name):
        return True
    # PHP/Perl/Shell variable references ($var)
    if func_name.startswith("$"):
        return True
    # All-numeric (version years, line numbers, etc.)
    if low.isdigit():
        return True
    # All-uppercase with underscores longer than 15 chars: likely macro/constant
    if func_name.isupper() and "_" in func_name and len(func_name) > 15:
        return True
    return False


def filter_gt(gt: "GroundTruth") -> "GroundTruth":
    """Filter ground truth to exclude non-code files.

    Removes config/build/doc/test files and paired .h files (when
    corresponding .c file is also in GT).
    """
    from dataclasses import replace

    filtered_files = {f for f in gt.changed_files if not _is_excluded_file(f)}
    filtered_files = _remove_paired_headers(filtered_files)

    filtered_funcs = {f for f in gt.changed_functions if not _is_noise_function(f)}
    filtered_lines = {
        f: v for f, v in gt.changed_lines.items()
        if f in filtered_files
    }
    filtered_ranges = {
        f: v for f, v in gt.func_ranges.items()
        if f in filtered_files
    }

    return replace(
        gt,
        changed_files=filtered_files,
        changed_functions=filtered_funcs,
        changed_lines=filtered_lines,
        func_ranges=filtered_ranges,
    )


@dataclass
class GroundTruth:
    cve_id: str
    changed_files: Set[str] = field(default_factory=set)
    changed_functions: Set[str] = field(default_factory=set)
    changed_lines: Dict[str, List[int]] = field(default_factory=dict)
    func_ranges: Dict[str, Dict[str, Tuple[int, int]]] = field(default_factory=dict)

    @property
    def file_count(self) -> int:
        return len(self.changed_files)

    @property
    def function_count(self) -> int:
        return len(self.changed_functions)


def _gt_from_dict(d: dict) -> GroundTruth:
    """Deserialize GroundTruth from cached dict."""
    func_ranges = {}
    for f, funcs in d.get("func_ranges", {}).items():
        func_ranges[f] = {fn: tuple(r) for fn, r in funcs.items()}
    return GroundTruth(
        cve_id=d["cve_id"],
        changed_files=set(d.get("changed_files", [])),
        changed_functions=set(d.get("changed_functions", [])),
        changed_lines={k: list(v) for k, v in d.get("changed_lines", {}).items()},
        func_ranges=func_ranges,
    )


def load_gt(cve_id: str, gt_dir: str = GT_DIR) -> Optional[GroundTruth]:
    """Load pre-computed ground truth for a CVE.

    Returns None if no GT file exists.
    """
    path = os.path.join(gt_dir, f"{cve_id}.json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return _gt_from_dict(json.load(f))


def load_gt_if_exists(cve_id: str, gt_dir: str = GT_DIR) -> Optional[GroundTruth]:
    """Alias for load_gt — returns None if no GT file exists."""
    return load_gt(cve_id, gt_dir)
