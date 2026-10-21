#!/usr/bin/env python3
"""
CodeQL Auto Analyzer — Multi-language automated CodeQL database creation
and ICFG (Inter-procedural Control Flow Graph) extraction.

Supports: C/C++, Java, Python, JavaScript/TypeScript, Go, Ruby, Rust

Usage:
    python codeql_auto_analyzer.py <project_root> <output_dir> [--language LANG]

The script auto-detects the project language, creates a CodeQL database,
and runs the ICFG query to extract the inter-procedural control flow graph.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

# ─────────────────────────── Language Detection ────────────────────────────

LANG_SIGNATURES = {
    "cpp":        {
        "files":       ["CMakeLists.txt", "Makefile", "configure", "configure.ac",
                        "Makefile.am", "meson.build", "BUILD", "WORKSPACE"],
        "extensions":  [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx", ".m", ".mm"],
        "description": "C/C++",
    },
    "java":       {
        "files":       ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"],
        "extensions":  [".java", ".kt", ".kts"],
        "description": "Java/Kotlin",
    },
    "python":     {
        "files":       ["setup.py", "setup.cfg", "pyproject.toml", "requirements.txt",
                        "Pipfile", "poetry.lock", "setup.py"],
        "extensions":  [".py", ".pyw"],
        "description": "Python",
    },
    "javascript": {
        "files":       ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        "extensions":  [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
        "description": "JavaScript/TypeScript",
    },
    "go":         {
        "files":       ["go.mod", "go.sum", "Gopkg.lock"],
        "extensions":  [".go"],
        "description": "Go",
    },
    "ruby":       {
        "files":       ["Gemfile", "Rakefile", ".ruby-version"],
        "extensions":  [".rb"],
        "description": "Ruby",
    },
    "perl":       {
        "files":       ["Makefile.PL", "cpanfile", "META.json", "META.yml"],
        "extensions":  [".pl", ".pm", ".t"],
        "description": "Perl",
    },
    "rust":       {
        "files":       ["Cargo.toml", "Cargo.lock"],
        "extensions":  [".rs"],
        "description": "Rust",
    },
    "php":        {
        "files":       ["composer.json", "composer.lock", "index.php"],
        "extensions":  [".php", ".phtml", ".php3", ".php4", ".php5", ".inc"],
        "description": "PHP",
    },
}


def detect_language(project_root: Path) -> Optional[str]:
    """Detect the primary language of a project by scanning root-level files."""
    scores: dict[str, int] = { }

    root_items = set()
    try:
        for item in project_root.iterdir():
            if item.is_file():
                root_items.add(item.name)
    except (PermissionError, OSError):
        pass

    for lang, sig in LANG_SIGNATURES.items():
        score = 0
        for fname in sig["files"]:
            if fname in root_items:
                score += 10
        scores[lang] = score

    # If any build file was matched, verify that source files in the
    # detected language actually exist.  Makefile in particular is a weak
    # signal — many non-C/C++ projects use one for build orchestration.
    #
    # Tiebreaker: PHP projects commonly include package.json for frontend
    # dependencies, but the primary language is PHP (composer.json is the
    # authoritative marker).  When both PHP and JS match, prefer PHP.
    if scores.get("php", 0) > 0 and scores.get("javascript", 0) > 0:
        # Both PHP and JavaScript build files exist — check which has more
        # source files to determine the dominant language
        php_count = 0
        js_count = 0
        try:
            for _root, dirs, files in os.walk(project_root):
                dirs[:] = [d for d in dirs if not d.startswith(".") and d not in
                           ("node_modules", "vendor", ".git", "cache")]
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in LANG_SIGNATURES["php"]["extensions"]:
                        php_count += 1
                    if ext in LANG_SIGNATURES["javascript"]["extensions"]:
                        js_count += 1
                if php_count + js_count > 300:
                    break
        except (PermissionError, OSError):
            pass
        # Prefer PHP if it has at least 20% as many files as JS
        # (PHP projects often have many JS files in vendor/node_modules)
        if php_count > 0 and (php_count >= js_count * 0.2):
            return "php"

    best = max(scores, key=scores.get)
    if scores[best] > 0:
        exts = LANG_SIGNATURES[best]["extensions"]
        try:
            for _root, dirs, files in os.walk(project_root):
                dirs[:] = [d for d in dirs if not d.startswith(".") and d not in
                           ("node_modules", "build", "target", "dist", "__pycache__",
                            "vendor", ".git", "venv", "env", ".venv")]
                for fname in files:
                    if os.path.splitext(fname)[1].lower() in exts:
                        return best
                if sum(1 for _ in files) > 500:
                    break
        except (PermissionError, OSError):
            pass
        # Build-file match was a false positive (e.g. Makefile in a JS
        # project) — fall through to extension-based detection below.

    # Fallback: scan file extensions
    ext_counts: dict[str, int] = {lang: 0 for lang in LANG_SIGNATURES}
    try:
        for root, dirs, files in os.walk(project_root):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in
                       ("node_modules", "build", "target", "dist", "__pycache__",
                        "vendor", ".git", "venv", "env", ".venv")]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                for lang, sig in LANG_SIGNATURES.items():
                    if ext in sig["extensions"]:
                        ext_counts[lang] += 1
            if sum(ext_counts.values()) > 200:
                break
    except (PermissionError, OSError):
        pass

    best = max(ext_counts, key=ext_counts.get)
    if ext_counts[best] > 0:
        return best

    return None


def detect_all_languages(project_root: Path, min_ratio: float = 0.05) -> list[str]:
    """Detect ALL languages with significant source files in the project.

    Returns a list of language codes sorted by file count (dominant first).
    Languages with fewer than `min_ratio` of total source files are excluded.

    This enables joint extraction for mixed-language projects like
    PHP+JavaScript (WordPress plugins, opencart) or C+++Python.
    """
    # Scan all source files and classify by extension
    lang_counts: dict[str, int] = {lang: 0 for lang in LANG_SIGNATURES}
    exclude_dirs = {"node_modules", "vendor", ".git", "build", "target",
                    "dist", "cache", "tmp", "temp", "__pycache__",
                    "venv", "env", ".venv", "tests", "test", "Tests", "Test"}

    try:
        for _root, dirs, files in os.walk(project_root):
            dirs[:] = [d for d in dirs
                       if not d.startswith(".") and d not in exclude_dirs]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                for lang, sig in LANG_SIGNATURES.items():
                    if ext in sig["extensions"]:
                        lang_counts[lang] += 1
            # Use a higher threshold to ensure deep subdirectories are sampled.
            # Mixed-language projects (e.g. PHP + JS in opencart) often have JS
            # files in view/javascript/ subdirectories that are visited later
            # than the PHP files in controller/model/ subdirectories.
            if sum(lang_counts.values()) > 2000:
                break
    except (PermissionError, OSError):
        pass

    total = sum(lang_counts.values())
    if total == 0:
        return []

    # Filter to languages with significant presence
    result = []
    for lang, count in sorted(lang_counts.items(), key=lambda x: -x[1]):
        if count >= total * min_ratio and count > 0:
            result.append(lang)

    return result


def merge_icfg_csvs(csv_paths: list[Path], output_path: Path) -> int:
    """Merge multiple ICFG CSV files into one, deduplicating rows.

    Normalizes two common formats to a unified 6-column schema:
      file, function, srcLine, dstLine, edge_type, target_function

    Generic extractor (5 cols): file, function, srcLine, dstLine, callee_target
      → callee_target becomes target_function, edge_type = "call"

    CodeQL ICFG (6 cols): file, function, srcLine, dstLine, edge_type, target_function
      → used as-is
    """
    import csv

    if not csv_paths:
        return 0

    if len(csv_paths) == 1:
        import shutil
        shutil.copy(str(csv_paths[0]), str(output_path))
        with open(output_path) as f:
            return sum(1 for _ in f) - 1

    UNIFIED_HEADER = ["file", "function", "srcLine", "dstLine",
                      "edge_type", "target_function"]
    all_rows: list[tuple] = []

    for p in csv_paths:
        if not p.exists():
            continue
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            raw_header = [h.strip().lower().strip('"') for h in next(reader, [])]
            if not raw_header:
                continue

            # Determine format
            has_edge_type = "edge_type" in raw_header

            for row in reader:
                if has_edge_type:
                    # 6-column CodeQL format (already unified)
                    all_rows.append(tuple(row[:6]))
                else:
                    # 5-column generic extractor format:
                    #   file, function, srcLine, dstLine, callee_target
                    # → file, function, srcLine, dstLine, "call", callee_target
                    normalized = (
                        row[0],                    # file
                        row[1],                    # function
                        row[2],                    # srcLine
                        row[3],                    # dstLine
                        "call",                    # edge_type
                        row[4] if len(row) > 4 else "",  # target_function
                    )
                    all_rows.append(normalized)

    if not all_rows:
        return 0

    # Deduplicate by (file, function, srcLine, target_function)
    seen = set()
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(UNIFIED_HEADER)
        count = 0
        for row in all_rows:
            key = (row[0].strip('"'), row[1].strip('"'), row[2], row[5].strip('"'))
            if key not in seen:
                seen.add(key)
                writer.writerow(row)
                count += 1

    return count


def analyze_multilang_project(
        project_root: Path, output_dir: Path,
        project_label: str = "",
        ) -> tuple[Optional[Path], Optional[str]]:
    """Joint multi-language ICFG extraction for a project.

    Detects all languages with significant source files, runs the
    appropriate extractor for each, and merges the results into a
    single ICFG CSV.

    Returns (merged_csv_path, error_message).
    """
    languages = detect_all_languages(project_root)
    if not languages:
        return None, "No recognizable source files found."

    lang_names = [LANG_SIGNATURES.get(l, {}).get("description", l) for l in languages]
    print(f"  Detected languages: {', '.join(lang_names)}")

    if len(languages) == 1:
        # Single language — use the standard single-language pipeline
        result, error = analyze_single_project(project_root, output_dir,
                                               language=languages[0],
                                               project_label=project_label)
        if result and result.exists():
            # Ensure _db suffix copy exists for batch_runner compatibility
            db_csv = output_dir / f"{project_label}_icfg_db.csv"
            if result != db_csv:
                import shutil
                shutil.copy(str(result), str(db_csv))
        return result, error

    # Multi-language: extract each separately, then merge
    csv_paths: list[Path] = []
    errors: list[str] = []

    for lang in languages:
        lang_csv = output_dir / f"{project_label}_{lang}_icfg.csv"
        lang_desc = LANG_SIGNATURES.get(lang, {}).get("description", lang)
        print(f"  [{lang_desc}] Extracting...")
        result, error = analyze_single_project(
            project_root, output_dir, language=lang,
            project_label=f"{project_label}_{lang}",
            output_csv=lang_csv,
        )
        if error:
            errors.append(f"[{lang}] {error}")
        elif result:
            csv_paths.append(result)
            print(f"  [{lang_desc}] {result}")
        else:
            errors.append(f"[{lang}] Unknown failure")

    if not csv_paths:
        return None, "; ".join(errors)

    # Merge all CSVs into the final output
    merged_csv = output_dir / f"{project_label}_icfg.csv"
    row_count = merge_icfg_csvs(csv_paths, merged_csv)

    if row_count == 0:
        return None, "Merge produced empty ICFG."

    # Clean up per-language intermediate CSVs
    for p in csv_paths:
        if p != merged_csv:
            p.unlink(missing_ok=True)

    print(f"  Merged ICFG: {merged_csv} ({row_count} rows, "
          f"{len(languages)} languages)")

    # Also apply C++ filtering if cpp was one of the languages
    if "cpp" in languages and row_count > 5000:
        filtered = _filter_cpp_icfg(merged_csv, project_root)
        if filtered > 0:
            print(f"  Filtered: {filtered} rows after C++ source-dir filter")

    # Copy merged CSV to _db suffix for pipeline compatibility
    db_csv = output_dir / f"{project_label}_icfg_db.csv"
    if merged_csv != db_csv:
        import shutil
        shutil.copy(str(merged_csv), str(db_csv))

    return merged_csv, None


# ───────────────────────── Database Creation ───────────────────────────────

# Suppress "installed in home directory" warning
os.environ.setdefault("CODEQL_ALLOW_INSTALLATION_ANYWHERE", "true")

# Auto-detect codeql binary — check common locations
def _find_codeql() -> str:
    """Find the codeql binary, checking PATH and common locations."""
    import shutil
    found = shutil.which("codeql")
    if found:
        return found
    for candidate in [
        os.getenv("CODEQL_BIN", "codeql"),
        "/usr/local/bin/codeql",
        "/opt/codeql/codeql",
    ]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return "codeql"  # fallback — will fail with clear error later

CODEQL_BIN = _find_codeql()


def check_codeql() -> bool:
    """Verify codeql CLI is available."""
    try:
        result = subprocess.run(
            [CODEQL_BIN, "version"], capture_output=True,
            text=True, timeout=30
            )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def create_stubs_for_cpp(project_root: Path) -> Path:
    """Create stub headers for C/C++ projects missing third-party includes."""
    stubs_dir = project_root / ".codeql-stubs"
    stubs_dir.mkdir(exist_ok=True)

    src_exts = { ".c", ".cpp", ".cc", ".cxx", ".m", ".mm" }
    missing_headers: set[str] = set()

    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != ".codeql-stubs"]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in src_exts:
                continue
            fpath = Path(root) / fname
            for _ in range(10):  # up to 10 rounds of stub creation per file
                try:
                    result = subprocess.run(
                        ["g++", "-std=c++17", f"-I{stubs_dir}", f"-I{project_root}",
                         "-E", str(fpath), "-o", "/dev/null"],
                        capture_output=True, text=True, timeout=30,
                    )
                    for line in result.stderr.splitlines():
                        if "fatal error:" in line and "No such file or directory" in line:
                            header = line.split("fatal error:")[1].strip()
                            header = header.split(":")[0].strip()
                            missing_headers.add(header)
                    break  # no more fatal errors for this file
                except subprocess.TimeoutExpired:
                    break
            else:
                break  # exceeded max iterations

    # Create stub files for all missing headers
    for header in missing_headers:
        stub_path = stubs_dir / header
        stub_path.parent.mkdir(parents=True, exist_ok=True)
        if not stub_path.exists():
            stub_path.touch()

    return stubs_dir


def create_db_cpp(project_root: Path, db_dir: Path) -> subprocess.CompletedProcess:
    """Create CodeQL database for C/C++ using --build-mode=none.

    Uses buildless extraction so that ALL source files are parsed even when
    system headers (openssl, pcap, wireless, etc.) are missing.  This trades
    some intra-procedural precision for complete file coverage — the ICFG
    will include every .c/.cpp file rather than only the compilable ones.
    """
    cmd = [
        CODEQL_BIN, "database", "create", str(db_dir),
        "--language=cpp",
        "--source-root", str(project_root),
        "--build-mode=none",
        "--overwrite",
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=1800)


def create_db_java(project_root: Path, db_dir: Path) -> subprocess.CompletedProcess:
    """Create CodeQL database for Java/Kotlin."""
    cmd = [
        CODEQL_BIN, "database", "create", str(db_dir),
        "--language=java",
        "--source-root", str(project_root),
        "--build-mode=none",
        "--overwrite",
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=1800)


def create_db_python(project_root: Path, db_dir: Path) -> subprocess.CompletedProcess:
    """Create CodeQL database for Python."""
    cmd = [
        CODEQL_BIN, "database", "create", str(db_dir),
        "--language=python",
        "--source-root", str(project_root),
        "--overwrite",
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=1800)


def create_db_javascript(project_root: Path, db_dir: Path) -> subprocess.CompletedProcess:
    """Create CodeQL database for JavaScript/TypeScript."""
    cmd = [
        CODEQL_BIN, "database", "create", str(db_dir),
        "--language=javascript",
        "--source-root", str(project_root),
        "--overwrite",
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=1800)


def _check_toolchain(executable: str) -> bool:
    """Check if a required compiler/tool is available in PATH."""
    try:
        result = subprocess.run(
            [executable, "version"], capture_output=True, text=True, timeout=15
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def create_db_go(project_root: Path, db_dir: Path) -> subprocess.CompletedProcess:
    """Create CodeQL database for Go. Requires go compiler in PATH."""
    if not _check_toolchain("go"):
        env = os.environ.get("GOROOT", "")
        detail = f"go not found in PATH"
        if env:
            detail += f"; GOROOT={env}"
        detail += ". Install Go or skip Go projects."
        raise RuntimeError(f"Go compiler not available: {detail}")

    cmd = [
        CODEQL_BIN, "database", "create", str(db_dir),
        "--language=go",
        "--source-root", str(project_root),
        "--build-mode=autobuild",
        "--overwrite",
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=1800)


def create_db_ruby(project_root: Path, db_dir: Path) -> subprocess.CompletedProcess:
    """Create CodeQL database for Ruby."""
    cmd = [
        CODEQL_BIN, "database", "create", str(db_dir),
        "--language=ruby",
        "--source-root", str(project_root),
        "--overwrite",
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=1800)


def create_db_perl(project_root: Path, db_dir: Path) -> subprocess.CompletedProcess:
    """Perl is not supported by CodeQL — always fails with a clear message."""
    raise RuntimeError("Perl is not supported by CodeQL (no Perl extractor available).")


def create_db_rust(project_root: Path, db_dir: Path) -> subprocess.CompletedProcess:
    """Create CodeQL database for Rust. Rust supports buildless analysis."""
    cmd = [
        CODEQL_BIN, "database", "create", str(db_dir),
        "--language=rust",
        "--source-root", str(project_root),
        "--build-mode=none",
        "--overwrite",
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=1800)


DB_CREATORS = {
    "cpp":        create_db_cpp,
    "java":       create_db_java,
    "python":     create_db_python,
    "javascript": create_db_javascript,
    "go":         create_db_go,
    "ruby":       create_db_ruby,
    "perl":       create_db_perl,
    "rust":       create_db_rust,
}

# Languages handled by the generic regex-based extractor (no CodeQL support)
GENERIC_LANGUAGES = {"php", "perl"}

# Directories to exclude from C/C++ ICFG (build helpers, docs, examples, tests)
CPP_SOURCE_DIRS = {"src", "lib", "include", "source", "modules", "core", "common", "main"}
CPP_EXCLUDE_DIRS = {"make", "docs", "doc", "tools", "tool", "contrib", "examples",
                    "sample", "samples", "test", "tests", "testing", "benchmarks",
                    "build", "cmake", "dist", "docker", "scripts", "ci"}

# ───────────────────────── ICFG Query Execution ────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
QUERIES_DIR = SCRIPT_DIR / "queries"


def run_icfg_query(language: str, db_dir: Path, output_csv: Path) -> bool:
    """Run the ICFG query against a CodeQL database."""
    icfg_ql = QUERIES_DIR / language / "icfg.ql"
    if not icfg_ql.exists():
        print(f"  [WARN] No ICFG query for language '{language}', skipping.")
        return False

    bqrs_file = output_csv.with_suffix(".bqrs")

    run_cmd = [
        CODEQL_BIN, "query", "run", str(icfg_ql),
        "--database", str(db_dir),
        "--output", str(bqrs_file),
    ]
    result = subprocess.run(run_cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        print(f"  [ERR] Query failed: {result.stderr[:500]}")
        return False

    decode_cmd = [
        CODEQL_BIN, "bqrs", "decode", str(bqrs_file),
        "--format=csv",
        "--output", str(output_csv),
    ]
    result = subprocess.run(decode_cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        print(f"  [ERR] Decode failed: {result.stderr[:500]}")
        return False

    bqrs_file.unlink(missing_ok=True)
    return True


# ───────────────────────── Main Entry Point ────────────────────────────────

_LANG_DB_MARKERS = {
    "cpp":        "db-cpp",
    "java":       "db-java",
    "python":     "db-python",
    "javascript": "db-javascript",
    "go":         "db-go",
    "ruby":       "db-ruby",
    "rust":       "db-rust",
}

# Languages that need an external compiler/toolchain to build
_TOOLCHAIN_REQUIREMENTS = {
    "go": "go",
}


def _filter_cpp_icfg(csv_path: Path, project_root: Path) -> int:
    """Filter C/C++ ICFG CSV: keep only rows from recognized source directories.

    For C/C++ projects, the ICFG often includes files from build helpers
    (make/, cmake/), documentation (docs/), examples, and test directories.
    This filter keeps only files under recognized source directories
    (src/, lib/, include/, modules/, core/, etc.).

    If the project has NO recognized source directories, the filter is
    skipped and the original ICFG is preserved.

    Returns the number of rows after filtering (0 = filter was skipped).
    """
    import csv
    import shutil

    # First pass: check if any source directories exist in the project
    has_source_dirs = False
    for src_dir in CPP_SOURCE_DIRS:
        if (project_root / src_dir).is_dir():
            has_source_dirs = True
            break

    if not has_source_dirs:
        # No recognized source dirs — skip filtering (project may use
        # a non-standard layout, e.g. everything at root level)
        return 0

    # Read, filter, write back
    temp_path = csv_path.with_suffix(".csv.tmp")
    keep_count = 0
    total_count = 0

    with open(csv_path, "r", encoding="utf-8", errors="replace") as fin, \
         open(temp_path, "w", encoding="utf-8", newline="") as fout:
        reader = csv.reader(fin)
        writer = csv.writer(fout)

        # Copy header
        header = next(reader)
        writer.writerow(header)

        file_col = 0  # first column is file path

        for row in reader:
            total_count += 1
            file_path = row[file_col].strip().strip('"')

            # Determine the top-level directory of this file
            parts = file_path.replace("\\", "/").split("/")
            if not parts:
                continue

            top_dir = parts[0]

            # Keep if top-level dir is a source dir
            if top_dir in CPP_SOURCE_DIRS:
                writer.writerow(row)
                keep_count += 1
                continue

            # Also keep if file is at root level (no subdirectory)
            if len(parts) == 1:
                writer.writerow(row)
                keep_count += 1
                continue

            # Skip files in excluded directories
            if top_dir in CPP_EXCLUDE_DIRS:
                continue

            # For unknown directories: keep if they look like source
            # (e.g., contain .cpp/.h files at second level)
            # Conservative: keep files in unrecognized dirs that have
            # source-like names
            if any(ext in file_path.lower() for ext in (".cpp", ".c", ".h", ".hpp")):
                writer.writerow(row)
                keep_count += 1
                continue

    if keep_count > 0 and keep_count < total_count:
        # Replace original with filtered version
        shutil.move(str(temp_path), str(csv_path))
        return keep_count
    else:
        # Filter would remove too much — keep original
        temp_path.unlink(missing_ok=True)
        return 0


def analyze_single_project(
        project_root: Path, output_dir: Path,
        language: Optional[str] = None,
        project_label: str = "",
        output_csv: Optional[Path] = None,
        ) -> tuple[Optional[Path], Optional[str]]:
    """
    Analyze a single project and return (csv_path, error_message).

    Returns:
        (csv_path, None) on success.
        (None, error_message) on failure.
        Error messages starting with "SKIP:" mean the project should be
        skipped rather than retried (toolchain missing, etc.).
    """
    if not check_codeql():
        return None, "codeql CLI not found on PATH."

    project_root = project_root.resolve()

    if language is None:
        language = detect_language(project_root)
        if language is None:
            return None, "Could not detect language."

    lang_desc = LANG_SIGNATURES.get(language, { }).get("description", language)
    print(f"  Language: {lang_desc} ({language})")

    # ── Generic extractor path (PHP, Perl, etc.) ──
    if language in GENERIC_LANGUAGES:
        # Try tree-sitter extractor first, fall back to generic regex
        try:
            from treesitter_extractor import extract_project as ts_extract
            if output_csv is None:
                output_csv = output_dir / f"{project_label}_icfg.csv"
            output_csv.parent.mkdir(parents=True, exist_ok=True)
            count = ts_extract(project_root, language, output_csv)
            if count > 0:
                print(f"  Tree-sitter ICFG: {output_csv} ({count} rows)")
                return output_csv, None
        except Exception as e:
            print(f"  [INFO] Tree-sitter extractor failed: {e}, "
                  f"falling back to generic extractor")

        from generic_extractor import extract_project
        if output_csv is None:
            output_csv = output_dir / f"{project_label}_icfg.csv"
        output_csv.parent.mkdir(parents=True, exist_ok=True)
        count = extract_project(project_root, language, output_csv)
        if count > 0:
            print(f"  Generic ICFG: {output_csv} ({count} rows)")
            return output_csv, None
        else:
            return None, f"SKIP:Generic extractor found no {lang_desc} source files."

    # Check toolchain requirements before attempting DB creation
    required_tool = _TOOLCHAIN_REQUIREMENTS.get(language)
    if required_tool and not _check_toolchain(required_tool):
        return None, (
            f"SKIP:{lang_desc} compiler ({required_tool}) not found in PATH. "
            f"Install {required_tool} or skip this language."
        )

    db_dir = output_dir / f"{project_label}_db"
    creator = DB_CREATORS.get(language)
    if creator is None:
        return None, f"Language '{language}' not supported (no DB creator)."

    # Clean up any leftover corrupted database from a previous interrupted run
    if db_dir.exists():
        import shutil
        shutil.rmtree(db_dir, ignore_errors=True)

    print(f"  Creating database at {db_dir} ...")
    try:
        result = creator(project_root, db_dir)
    except subprocess.TimeoutExpired:
        return None, "Database creation timed out (1800s)."
    except Exception as e:
        msg = str(e)
        if msg.startswith("SKIP:"):
            return None, msg  # preserve SKIP prefix for caller
        return None, f"Database creation error: {type(e).__name__}: {e}"

    if result.returncode != 0:
        stderr_tail = result.stderr[-800:] if result.stderr else "(no stderr output)"
        stdout_tail = result.stdout[-400:] if result.stdout else "(no stdout output)"
        return None, (
            f"Database creation failed (rc={result.returncode}).\n"
            f"    stderr: {stderr_tail}\n"
            f"    stdout: {stdout_tail}"
        )

    marker = _LANG_DB_MARKERS.get(language)
    if marker is None or not db_dir.exists() or not (db_dir / marker).exists():
        found = list(db_dir.iterdir()) if db_dir.exists() else []
        return None, f"Database not created — missing marker '{marker}'. Contents: {found}"

    print(f"  Database created successfully.")

    if output_csv is None:
        output_csv = output_dir / f"{project_label}_icfg.csv"
    print(f"  Running ICFG query ...")
    if run_icfg_query(language, db_dir, output_csv):
        row_count = 0
        try:
            with open(output_csv) as f:
                row_count = sum(1 for _ in f)
        except Exception:
            pass
        print(f"  ICFG: {output_csv} ({row_count} rows)")

        # Post-processing: filter non-source directories for C/C++ projects
        if language == "cpp" and row_count > 5000:
            filtered_count = _filter_cpp_icfg(output_csv, project_root)
            if filtered_count > 0:
                print(f"  Filtered ICFG: {output_csv} ({filtered_count} rows "
                      f"after removing non-source dirs)")
            else:
                print(f"  [WARN] ICFG empty after filtering — keeping original")

        return output_csv, None
    else:
        return None, "ICFG query execution failed (see above for details)."


def main():
    parser = argparse.ArgumentParser(
        description="CodeQL Auto Analyzer — Multi-language ICFG extraction"
    )
    parser.add_argument("project_root", help="Path to the project root directory")
    parser.add_argument("output_dir", help="Directory for output database and CSV files")
    parser.add_argument(
        "--language", help="Force a specific language (skip auto-detection)",
        choices=list(LANG_SIGNATURES.keys())
        )
    parser.add_argument("--label", help="Project label for output naming", default="")
    parser.add_argument("--multilang", action="store_true",
                        help="Enable multi-language joint extraction "
                             "(detect all languages and merge ICFGs)")
    args = parser.parse_args()

    project_root = Path(args.project_root)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    label = args.label or project_root.name

    if args.language is not None:
        # Explicit --language flag: single-language mode
        result, error = analyze_single_project(project_root, output_dir,
                                                args.language, label)
    else:
        # Default: multi-language joint extraction
        # This ensures PHP web projects (which have both composer.json AND
        # package.json) get BOTH PHP and JS ICFGs merged, fixing the 79.9%
        # file-level mismatch caused by single-language detection.
        result, error = analyze_multilang_project(project_root, output_dir, label)
    if error:
        print(f"[ERR] {error}")
    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
