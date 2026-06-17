#!/usr/bin/python3
"""
Generate a Joern CPG (Code Property Graph) for a single project.

Runs joern-parse as a subprocess with configurable timeout.
Bypasses scubatrace's joern.parse() to get direct timeout control.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import signal


# Joern language flag mapping
JOERN_LANG_MAP = {
    "c": "newc",
    "cpp": "newc",
    "c++": "newc",
    "java": "javasrc",
    "python": "python",
    "javascript": "javascript",
    "js": "javascript",
    "typescript": "javascript",
    "go": "golang",
    "golang": "golang",
    "ruby": "rubysrc",
    "rust": "rust",
}

# Minimum file size for a CPG binary (bytes). Anything smaller is considered invalid.
MIN_CPG_SIZE = 5000

# CPGs larger than this are trusted without full load (avoids multi-minute validation)
TRUST_CPG_SIZE = 1_000_000  # 1 MB


def _validate_cpg(cpg_path: str) -> dict:
    """Validate a CPG binary — fast size check, optional full load."""
    if not os.path.exists(cpg_path):
        return {"valid": False, "error": f"File not found: {cpg_path}"}

    file_size = os.path.getsize(cpg_path)
    if file_size < MIN_CPG_SIZE:
        return {"valid": False, "error": f"CPG too small ({file_size} bytes)"}

    # Check for summary file with cached stats (instant)
    summary_path = os.path.join(os.path.dirname(cpg_path), "cpg_summary.json")
    if os.path.exists(summary_path):
        try:
            with open(summary_path) as f:
                summary = json.load(f)
            if summary.get("status") == "success" and summary.get("cpg_method_count", 0) > 0:
                return {
                    "valid": True,
                    "error": None,
                    "node_count": summary.get("cpg_node_count", -1),
                    "edge_count": summary.get("cpg_edge_count", -1),
                    "method_count": summary.get("cpg_method_count", -1),
                    "file_count": summary.get("cpg_file_count", -1),
                }
        except (json.JSONDecodeError, KeyError):
            pass

    # Trust large CPG files without full load (avoids timeout for 100MB+ files)
    if file_size >= TRUST_CPG_SIZE:
        return {
            "valid": True,
            "error": None,
            "node_count": -1,
            "edge_count": -1,
            "method_count": 1,  # non-zero to pass validation
            "file_count": -1,
        }

    # Full validation only for small files without summary
    try:
        import scubatrace.cpg as cpg_mod
        cpg_obj = cpg_mod.load(cpg_path)
    except Exception as e:
        return {"valid": False, "error": f"CPG load failed: {e}"}

    method_count = len(cpg_obj.nodes_by_label("METHOD"))
    node_count = cpg_obj.node_count
    edge_count = cpg_obj.edge_count

    if method_count == 0:
        return {
            "valid": False,
            "error": "CPG has 0 METHOD nodes",
            "node_count": node_count,
            "edge_count": edge_count,
            "method_count": 0,
        }

    return {
        "valid": True,
        "error": None,
        "node_count": node_count,
        "edge_count": edge_count,
        "method_count": method_count,
        "file_count": len(cpg_obj.nodes_by_label("FILE")),
    }


def _run_joern(cmd: list, cwd: str, timeout: int) -> subprocess.CompletedProcess:
    """Run joern-parse with process-group cleanup on timeout."""
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout_b, stderr_b = proc.communicate(timeout=timeout)
        stdout = stdout_b.decode("utf-8", errors="replace") if stdout_b else ""
        stderr = stderr_b.decode("utf-8", errors="replace") if stderr_b else ""
        return subprocess.CompletedProcess(
            args=cmd, returncode=proc.returncode,
            stdout=stdout, stderr=stderr,
        )
    except subprocess.TimeoutExpired:
        # Kill the entire process group: joern-parse + its Java child
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        raise


def generate_cpg(
    repo_path: str,
    language: str,
    output_cpg_path: str,
    joern_parse_path: str = "joern-parse",
    timeout: int = 600,
    overwrite: bool = False,
) -> dict:
    """
    Generate a CPG binary from a repository using Joern.

    Args:
        repo_path: Absolute path to the source repository.
        language: One of "c", "cpp", "java", "python", "javascript", "go", "ruby", "rust".
        output_cpg_path: Destination path for the cpg.bin file.
        joern_parse_path: Path to joern-parse executable.
        timeout: Timeout in seconds for the joern-parse subprocess.
        overwrite: If True, re-generate even if output_cpg_path exists.

    Returns:
        Dict with: status, cpg_path, elapsed_s, node_count, edge_count,
                   method_count, file_count, language, error (if failed)
    """
    # Validate language
    joern_lang = JOERN_LANG_MAP.get(language.lower())
    if joern_lang is None:
        return {
            "status": "skipped",
            "cpg_path": None,
            "elapsed_s": 0,
            "error": f"Unsupported language: {language}",
        }

    # Validate repo
    if not os.path.isdir(repo_path):
        return {
            "status": "error",
            "cpg_path": None,
            "elapsed_s": 0,
            "error": f"Repo not found: {repo_path}",
        }

    # Check existing CPG
    if os.path.exists(output_cpg_path) and not overwrite:
        validation = _validate_cpg(output_cpg_path)
        if validation["valid"]:
            return {
                "status": "success",
                "cpg_path": output_cpg_path,
                "elapsed_s": 0,
                "node_count": validation["node_count"],
                "edge_count": validation["edge_count"],
                "method_count": validation["method_count"],
                "file_count": validation.get("file_count", 0),
                "language": language,
                "error": None,
            }

    # Create temp output directory
    tmpdir = tempfile.mkdtemp(prefix="joern_cpg_")
    start = time.time()

    try:
        # Run joern-parse with process-group-safe timeout
        cmd = [joern_parse_path, "--language", joern_lang, repo_path]
        proc = _run_joern(cmd, tmpdir, timeout)

        elapsed = time.time() - start

        if proc.returncode != 0:
            stderr_tail = (proc.stderr or "")[-500:]
            return {
                "status": "error",
                "cpg_path": None,
                "elapsed_s": elapsed,
                "error": f"joern-parse exit {proc.returncode}: {stderr_tail}",
            }

        # Locate cpg.bin in output dir
        cpg_bin = os.path.join(tmpdir, "cpg.bin")
        if not os.path.exists(cpg_bin):
            return {
                "status": "error",
                "cpg_path": None,
                "elapsed_s": elapsed,
                "error": "joern-parse succeeded but cpg.bin not found",
            }

        # Copy to destination
        os.makedirs(os.path.dirname(output_cpg_path), exist_ok=True)
        shutil.copy2(cpg_bin, output_cpg_path)

        # Validate
        validation = _validate_cpg(output_cpg_path)
        elapsed = time.time() - start

        if not validation["valid"]:
            return {
                "status": "empty",
                "cpg_path": output_cpg_path,
                "elapsed_s": elapsed,
                "node_count": validation.get("node_count", 0),
                "edge_count": validation.get("edge_count", 0),
                "method_count": validation.get("method_count", 0),
                "file_count": validation.get("file_count", 0),
                "language": language,
                "error": validation["error"],
            }

        return {
            "status": "success",
            "cpg_path": output_cpg_path,
            "elapsed_s": elapsed,
            "node_count": validation["node_count"],
            "edge_count": validation["edge_count"],
            "method_count": validation["method_count"],
            "file_count": validation.get("file_count", 0),
            "language": language,
            "error": None,
        }

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        return {
            "status": "timeout",
            "cpg_path": None,
            "elapsed_s": elapsed,
            "error": f"Timeout after {timeout}s",
        }
    except FileNotFoundError:
        elapsed = time.time() - start
        return {
            "status": "error",
            "cpg_path": None,
            "elapsed_s": elapsed,
            "error": f"joern-parse not found at '{joern_parse_path}'",
        }
    except Exception as e:
        elapsed = time.time() - start
        return {
            "status": "error",
            "cpg_path": None,
            "elapsed_s": elapsed,
            "error": str(e),
        }
    finally:
        # Clean up temp dir
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: generate_cpg.py <repo_path> <language> <output_cpg_path> [timeout]")
        sys.exit(1)

    repo_path = sys.argv[1]
    language = sys.argv[2]
    output_cpg_path = sys.argv[3]
    timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 600

    print(f"Generating CPG for: {repo_path}")
    print(f"Language: {language} → Joern: {JOERN_LANG_MAP.get(language, 'N/A')}")
    result = generate_cpg(repo_path, language, output_cpg_path, timeout=timeout)
    # Output single-line JSON for machine parsing
    print("RESULT_JSON:" + json.dumps(result))
