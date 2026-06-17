"""
CWE Archetype Library — maps CVE-ID → CWE-ID → mechanism family → archetype slots.

Data sources:
  1000.csv — 944 CWE entries with descriptions, hierarchy, consequences
  nvdcve-2.0-{year}.json — CVE-ID → CWE-ID mapping (239K entries)
"""

from .archetype_library import Archetype, Slot, ARCHETYPE_LIBRARY, get_archetype, list_families
from .cwe_mapper import CWEMapper

__all__ = [
    "Archetype", "Slot", "ARCHETYPE_LIBRARY",
    "get_archetype", "list_families", "CWEMapper",
]
