"""
CWE Mapper — CVE-ID → CWE-ID → family → archetype lookup.
Also provides LLM-based vulnerability type inference from issue reports.

Data sources (for NVD fallback only):
  - nvdcve-2.0-{year}.json: CVE-ID → CWE-ID(s)
  - 1000.csv: CWE-ID → Name, Description, Hierarchy
"""

import csv
import glob
import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .archetype_library import (Archetype, get_archetype, get_archetype_by_family,
                                list_families, ARCHETYPE_LIBRARY)


# ── LLM-based archetype inference prompt ────────────────────────────────

def _build_archetype_catalog() -> str:
    """Build a catalog of all archetype families for LLM selection."""
    lines = []
    for arch in ARCHETYPE_LIBRARY:
        if arch.family == "Generic":
            continue
        slots_str = " → ".join(s.name for s in arch.slots if s.required)
        lines.append(
            f"- {arch.family}: {arch.display_name}\n"
            f"  Required chain: {slots_str}"
        )
    lines.append("- Generic: (catch-all, use when no specific family matches)")
    return "\n".join(lines)


_ARCHETYPE_CATALOG = _build_archetype_catalog()

ARC_INFER_PROMPT = f"""You are a vulnerability analysis expert. Read the vulnerability issue report and identify which vulnerability mechanism family it belongs to.

AVAILABLE FAMILIES:
{_ARCHETYPE_CATALOG}

INSTRUCTIONS:
1. Read the issue report carefully to understand the vulnerability mechanism.
2. Select the SINGLE best-matching family from the list above.
3. If multiple families could apply, choose the most specific one.
4. If no family clearly matches, select "Generic".
5. Also provide a brief natural-language description of the vulnerability mechanism.

Output ONLY a JSON object inside ```json``` fences:
```json
{{
  "family": "Memory-Buffer-Overflow",
  "description": "The issue report describes a stack-based buffer overflow in the FTP command parser where user-supplied input is copied into a fixed-size buffer without length validation.",
  "confidence": 0.85
}}
```"""


def infer_archetype_from_issue(llm, issue_report: str) -> Tuple[Archetype, str, float]:
    """Use LLM to infer the vulnerability archetype from an issue report.

    Args:
        llm: ModelClient with a .call(messages, temperature, max_tokens) method.
        issue_report: The full text of the vulnerability issue report.

    Returns:
        (Archetype, natural_language_description, confidence)
    """
    try:
        resp = llm.call(
            [{"role": "user", "content": f"{ARC_INFER_PROMPT}\n\nISSUE REPORT:\n{issue_report[:4000]}"}],
            temperature=0.0, max_tokens=1024,
        )
    except Exception:
        return get_archetype(""), "LLM inference failed", 0.0

    m = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", resp)
    if not m:
        # Try without fences
        m = re.search(r'(\{"family"[\s\S]*\})', resp)
    if not m:
        return get_archetype(""), f"Could not parse LLM response: {resp[:200]}", 0.0

    try:
        data = json.loads(m.group(1))
    except json.JSONDecodeError:
        return get_archetype(""), f"JSON parse error: {resp[:200]}", 0.0

    family = data.get("family", "").strip()
    description = data.get("description", "").strip()
    confidence = float(data.get("confidence", 0.5))

    archetype = get_archetype_by_family(family)
    if archetype is None:
        archetype = get_archetype("")

    return archetype, description, confidence


@dataclass
class CWEInfo:
    """Metadata for a single CWE type."""
    cwe_id: str
    name: str
    description: str
    extended_description: str
    abstraction: str                      # Base, Class, Variant, etc.
    common_consequences: str
    parent_ids: List[str] = field(default_factory=list)   # CWE hierarchy parents
    child_ids: List[str] = field(default_factory=list)    # CWE hierarchy children


class CWEMapper:
    """CVE-ID → CWE-ID → CWE family → Archetype.

    Uses NVD JSON files for CVE→CWE mapping and 1000.csv for CWE metadata.
    Lazy-loads NVD data on first access; caches results in memory.

    Usage:
        mapper = CWEMapper(nvd_dir="Dataset/DataFeed", cwe_csv="Dataset/DataFeed/1000.csv")
        archetype = mapper.get_archetype_for_cve("CVE-2015-1862")
        cwe_info = mapper.get_cwe_info("787")
    """

    def __init__(self, nvd_dir: str, cwe_csv_path: str):
        self.nvd_dir = nvd_dir
        self.cwe_csv_path = cwe_csv_path

        # Lazy-loaded data
        self._cve_to_cwe: Optional[Dict[str, List[str]]] = None
        self._cwe_info: Optional[Dict[str, CWEInfo]] = None
        self._cwe_hierarchy: Optional[Dict[str, List[str]]] = None  # parent → children

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_archetype_for_cve(self, cve_id: str) -> Optional[Archetype]:
        """Get the archetype for a given CVE-ID.

        Returns None only if CVE is completely unknown (uses Generic archetype
        as fallback when CWEs are known but unclassified).
        """
        cwes = self.get_cwes_for_cve(cve_id)
        if not cwes:
            return get_archetype("")  # Generic fallback

        # Multiple CWEs per CVE possible (rare). Take first non-generic archetype.
        for cwe in cwes:
            arch = get_archetype(cwe)
            if arch.family != "Generic":
                return arch
        return get_archetype(cwes[0])  # All generic, use first

    def get_cwes_for_cve(self, cve_id: str) -> List[str]:
        """Get all CWE-IDs for a CVE (with 'CWE-' prefix stripped)."""
        if self._cve_to_cwe is None:
            self._load_nvd()
        cwes = self._cve_to_cwe.get(cve_id.upper(), [])
        return [c.replace("CWE-", "").replace("CWE", "").strip() for c in cwes]

    def get_cwe_info(self, cwe_id: str) -> Optional[CWEInfo]:
        """Get metadata for a CWE type from 1000.csv."""
        if self._cwe_info is None:
            self._load_cwe_csv()
        clean = str(cwe_id).strip()
        # Try direct lookup + zero-padded variants
        for key in (clean, clean.zfill(3), clean.zfill(4), clean.lstrip("0")):
            if key in self._cwe_info:
                return self._cwe_info[key]
        return None

    def get_cwe_hierarchy_chain(self, cwe_id: str, max_depth: int = 10) -> List[str]:
        """Get parent chain from cwe_id up to root (top of hierarchy)."""
        chain = []
        current = str(cwe_id).strip()
        for _ in range(max_depth):
            info = self.get_cwe_info(current)
            if not info or not info.parent_ids:
                break
            parent = info.parent_ids[0]
            if parent in chain:
                break  # cycle guard
            chain.append(parent)
            current = parent
        return chain

    def get_cwes_in_family(self, family: str) -> List[str]:
        """Get all CWE-IDs in a given archetype family."""
        arch = get_archetype(family)
        if arch is None:
            arch = get_archetype(family)
        return arch.cwe_types if arch else []

    def classify_cwe_from_issue(self, issue_report: str) -> List[Tuple[str, float]]:
        """Classify CWE type from issue report text using keyword heuristics.

        This is a fast, zero-cost pre-filter before LLM classification.
        Returns list of (cwe_id, confidence) sorted by confidence.

        LLM fallback should be used when top confidence < 0.5.
        """
        text_lower = issue_report.lower()
        scores: List[Tuple[str, float]] = []

        # Keyword → CWE mapping based on CWE vocabulary
        keyword_patterns = [
            # Memory safety
            (r"\b(use.after.free|uaf|dangling.pointer)\b", "416", 0.9),
            (r"\b(double.free)\b", "415", 0.9),
            (r"\b(null.pointer.deref|NULL.pointer|segfault|segmentation.fault)\b", "476", 0.85),
            (r"\b(buffer.overflow|buffer.overrun|stack.overflow|heap.overflow|out.of.bounds.write|OOB.write)\b", "787", 0.85),
            (r"\b(out.of.bounds.read|OOB.read|buffer.over.read|buffer.under.read)\b", "125", 0.85),
            (r"\b(memory.leak|resource.leak|memory.not.freed)\b", "401", 0.8),
            (r"\b(memory.corruption|heap.corruption|stack.corruption)\b", "119", 0.7),
            (r"\b(uninitialized|uninit|use.of.uninitialized)\b", "908", 0.8),

            # Integer
            (r"\b(integer.overflow|integer.wraparound|signed.overflow|arithmetic.overflow)\b", "190", 0.85),
            (r"\b(divide.by.zero|division.by.zero)\b", "369", 0.9),
            (r"\b(off.by.one|off-by-one)\b", "193", 0.85),
            (r"\b(integer.underflow)\b", "191", 0.8),

            # Injection
            (r"\b(SQL.injection|SQLi)\b", "89", 0.9),
            (r"\b(cross.site.scripting|XSS|stored.XSS|reflected.XSS)\b", "79", 0.9),
            (r"\b(command.injection|OS.command|shell.injection|arbitrary.command)\b", "78", 0.85),
            (r"\b(code.injection|eval.injection|arbitrary.code.execution|remote.code.execution|RCE)\b", "94", 0.8),
            (r"\b(deserialization|untrusted.deserializ|insecure.deserializ)\b", "502", 0.85),
            (r"\b(XXE|XML.external.entity|external.entity)\b", "611", 0.9),
            (r"\b(path.traversal|directory.traversal|file.traversal|dot.dot.slash|\.\.\/)\b", "22", 0.85),

            # Auth — match qualifier + "authorization" within ~5 words
            (r"(?i)\b(?:missing|no|without|lack|improper|bypass|insufficient|absent|unauthorized)\s+(?:\w+\s+){0,5}(?:authorization|auth\w*)\b", "862", 0.7),
            (r"(?i)\b(?:missing|no|broken|weak|flawed|bypass|insufficient|improper)\s+(?:\w+\s+){0,5}(?:authentication|auth\w*)\b", "287", 0.7),
            (r"(?i)\b(?:does\s+not.*?)\b(?:authoriz|auth\w*)\b", "862", 0.6),
            (r"(?i)\bauth(?:entication)?\s+bypass\b", "287", 0.8),
            (r"(?i)\bunauthorized\s+access\b", "862", 0.7),
            (r"\b(incorrect.permission|wrong.permission|overly.permissive|world.readable|world.writable)\b", "732", 0.8),

            # Resource
            (r"\b(denial.of.service|DoS|resource.exhaustion|infinite.loop)\b", "400", 0.6),
            (r"\b(infinite.loop|endless.loop)\b", "835", 0.85),
            (r"\b(uncontrolled.recursion)\b", "674", 0.85),

            # Info leak
            (r"\b(information.leak|information.disclosure|data.leak|sensitive.information.exposure|data.exposure)\b", "200", 0.7),
            (r"\b(race.condition|TOCTOU|TOCTTOU|time.of.check)\b", "362", 0.8),
        ]

        for pattern, cwe_id, confidence in keyword_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                scores.append((cwe_id, confidence))

        # Deduplicate: keep highest confidence per CWE
        seen: Set[str] = set()
        deduped = []
        for cwe_id, conf in sorted(scores, key=lambda x: -x[1]):
            if cwe_id not in seen:
                deduped.append((cwe_id, conf))
                seen.add(cwe_id)

        return deduped if deduped else [("", 0.0)]

    # ------------------------------------------------------------------
    # Internal: load NVD JSON (with disk cache for fast reload)
    # ------------------------------------------------------------------

    _CACHE_FILENAME = "cve_to_cwe_cache.json"

    def _load_nvd(self) -> None:
        """Load CVE→CWE mapping from NVD JSON files.

        Uses a disk cache (JSON) in nvd_dir. First run parses all NVD files
        (~1.5 GB) and writes the compact mapping (~15 MB). Subsequent runs
        load the cache directly in <1s.
        """
        self._cve_to_cwe = {}
        cache_path = os.path.join(self.nvd_dir, self._CACHE_FILENAME)

        # 1. Try disk cache first
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    self._cve_to_cwe = json.load(f)
                return
            except (json.JSONDecodeError, OSError) as exc:
                pass  # Corrupt cache, rebuild

        # 2. Build from scratch
        pattern = os.path.join(self.nvd_dir, "nvdcve-2.0-*.json")
        for fpath in sorted(glob.glob(pattern)):
            # Skip year 2026 (current year, incomplete)
            if "2026" in os.path.basename(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError) as exc:
                continue

            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cve", {}).get("id", "")
                if not cve_id:
                    continue
                weaknesses = vuln.get("cve", {}).get("weaknesses", [])
                cwe_list: List[str] = []
                for w in weaknesses:
                    for d in w.get("description", []):
                        val = d.get("value", "")
                        if val.startswith("CWE-"):
                            cwe_list.append(val)
                if cwe_list:
                    self._cve_to_cwe[cve_id] = cwe_list

        # 3. Write cache
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(self._cve_to_cwe, f, separators=(",", ":"))
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Internal: load 1000.csv CWE metadata
    # ------------------------------------------------------------------

    def _load_cwe_csv(self) -> None:
        """Load CWE metadata from 1000.csv."""
        self._cwe_info = {}
        self._cwe_hierarchy = defaultdict(list)

        with open(self.cwe_csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cwe_id = row.get("CWE-ID", "").strip()
                if not cwe_id:
                    continue

                # Parse parent IDs from Related Weaknesses
                parent_ids = self._parse_parents(row.get("Related Weaknesses", ""))

                info = CWEInfo(
                    cwe_id=cwe_id,
                    name=row.get("Name", "").strip(),
                    description=row.get("Description", "").strip(),
                    extended_description=row.get("Extended Description", "").strip(),
                    abstraction=row.get("Weakness Abstraction", "").strip(),
                    common_consequences=row.get("Common Consequences", "").strip(),
                    parent_ids=parent_ids,
                )
                self._cwe_info[cwe_id] = info

                for pid in parent_ids:
                    self._cwe_hierarchy[pid].append(cwe_id)

        # Second pass: fill child_ids from hierarchy
        for cwe_id, info in self._cwe_info.items():
            info.child_ids = self._cwe_hierarchy.get(cwe_id, [])

    @staticmethod
    def _parse_parents(related_weaknesses: str) -> List[str]:
        """Parse parent CWE IDs from the Related Weaknesses field.

        Format: ::NATURE:ChildOf:CWE ID:120:VIEW ID:1000:ORDINAL:Primary::
        """
        if not related_weaknesses:
            return []
        parents = []
        for segment in related_weaknesses.split("::"):
            if "ChildOf" in segment:
                parts = segment.split(":")
                for i, part in enumerate(parts):
                    if part.strip() == "CWE ID" and i + 1 < len(parts):
                        cwe_val = parts[i + 1].strip()
                        if cwe_val.isdigit():
                            parents.append(cwe_val)
        return parents
