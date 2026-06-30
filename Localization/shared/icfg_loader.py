"""
ICFG Loader — thin wrapper around Explainable_Localization/icfg_graph.py.

Reuses ICFGGraph for CSV→NetworkX parsing. Provides convenience
loaders for the three ICFG source formats (CodeQL, ScubaTrace, Joern).
"""

import os
import sys
from typing import Optional

# Import ICFGGraph from the existing EL module
_EL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                       "Explainable_Localization")
if _EL_DIR not in sys.path:
    sys.path.insert(0, _EL_DIR)

from icfg_graph import ICFGGraph  # noqa: E402

__all__ = ["ICFGGraph", "load_icfg", "load_icfg_if_exists"]


def load_icfg(csv_path: str) -> ICFGGraph:
    """Load an ICFG from a CSV file into an ICFGGraph instance."""
    return ICFGGraph().load_from_csv(csv_path)


def load_icfg_if_exists(csv_path: str) -> Optional[ICFGGraph]:
    """Load ICFG if the CSV file exists, return None otherwise."""
    if os.path.exists(csv_path):
        return ICFGGraph().load_from_csv(csv_path)
    return None
