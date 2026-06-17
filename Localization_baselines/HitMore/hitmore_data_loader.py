"""
Load HitMore's original training dataset from merge files + XML bug reports + GT.

Data sources (6 Java projects):
  - Merge files: merge_data_without_GT/{ds}.merge.txt
  - XML bug reports: bugLocator/{ds}/{ds}.xml (summary + description)
  - GT files: bugLocator/{ds}/{ds}_bugPredict.res

Produces a DataFrame with the same columns as dataset.build_dataset() output.
"""

import os
import re
import json
import random
import xml.etree.ElementTree as ET
import numpy as np
import pandas as pd

from HitMore.features_extract import extract_all_features
from HitMore.config import RANDOM_SEED

random.seed(RANDOM_SEED)

HITMORE_BASE = "/mnt/d/Desktop/HitMore-main/dataset"
MERGE_DIR = os.path.join(HITMORE_BASE, "merge_data_without_GT")
BUGLOCATOR_DIR = os.path.join(HITMORE_BASE, "bugLocator")

DATASETS = ["aspectj", "hibernate", "lucene", "openjpa", "tomcat", "zookeeper"]

# XML filename mapping (aspectj uses org.aspectj prefix)
XML_NAME_MAP = {
    "aspectj": "org.aspectj.xml",
    "hibernate": "hibernate-orm.xml",
    "lucene": "lucene-solr.xml",
    "openjpa": "openjpa.xml",
    "tomcat": "tomcat.xml",
    "zookeeper": "zookeeper.xml",
}


def parse_xml_bug_reports(dataset_name):
    """Parse XML bug reports for a dataset.

    Returns dict: bugId -> {summary, description, fixed_files}
    """
    xml_name = XML_NAME_MAP.get(dataset_name, f"{dataset_name}.xml")
    xml_path = os.path.join(BUGLOCATOR_DIR, dataset_name, xml_name)

    if not os.path.exists(xml_path):
        print(f"  WARNING: XML not found at {xml_path}")
        return {}

    tree = ET.parse(xml_path)
    root = tree.getroot()
    reports = {}

    for bug in root.findall("bug"):
        bug_id = bug.get("id")
        buginfo = bug.find("buginformation")
        if buginfo is None:
            continue

        summary_el = buginfo.find("summary")
        desc_el = buginfo.find("description")
        summary = summary_el.text if summary_el is not None and summary_el.text else ""
        description = desc_el.text if desc_el is not None and desc_el.text else ""

        fixed_files = []
        fixed_el = bug.find("fixedFiles")
        if fixed_el is not None:
            for f_el in fixed_el.findall("file"):
                if f_el.text:
                    fixed_files.append(f_el.text.strip())

        reports[bug_id] = {
            "summary": summary,
            "description": description,
            "fixed_files": fixed_files,
        }

    return reports


def parse_gt_res(dataset_name):
    """Parse GT res file for a dataset.

    Returns dict: bugId -> set of (fixed_file_path, ...)
    """
    gt_dir = os.path.join(BUGLOCATOR_DIR, dataset_name)
    res_files = [f for f in os.listdir(gt_dir) if f.endswith("_bugPredict.res")]

    if not res_files:
        print(f"  WARNING: No GT res file found in {gt_dir}")
        return {}

    gt_path = os.path.join(gt_dir, res_files[0])
    gt = {}

    with open(gt_path, "r") as f:
        header = f.readline()  # skip header
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) < 2:
                continue
            bug_id = parts[0].strip()
            file_path = parts[1].strip()
            if bug_id not in gt:
                gt[bug_id] = set()
            gt[bug_id].add(file_path)

    return gt


def _match_gt_path(merge_file_path, gt_file_set):
    """Fuzzy match a merge file path against GT file set.

    merge_file_path: path from merge file (could be short, qualified, or full)
    gt_file_set: set of qualified Java paths from GT

    Returns True if the merge file matches any GT file.
    """
    mf = merge_file_path.lower().rstrip(".")
    mf_basename = os.path.basename(mf)

    for gf in gt_file_set:
        gf_lower = gf.lower()

        # Exact match
        if mf == gf_lower:
            return True

        # Suffix match (one ends with the other)
        if mf.endswith(gf_lower) or gf_lower.endswith(mf):
            return True

        # Basename match
        gf_basename = os.path.basename(gf_lower)
        if mf_basename == gf_basename:
            return True

        # Path contains the other (for partial matches)
        if gf_lower in mf or mf in gf_lower:
            return True

    return False


def parse_merge_file(dataset_name):
    """Parse merge file for a dataset.

    Returns list of unique (bugId, file_path, source, rank, score) tuples.
    Deduplicates by (bugId, file_path), keeping the best (lowest) rank.
    """
    merge_path = os.path.join(MERGE_DIR, f"{dataset_name}.merge.txt")
    if not os.path.exists(merge_path):
        print(f"  WARNING: Merge file not found: {merge_path}")
        return []

    # Dict keyed by (bugId, file_path_lower) -> (bugId, file_path, source, rank, score)
    best = {}

    with open(merge_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")

            bug_id = parts[0].strip()

            # Amalgam: columns 1,2,3
            if len(parts) >= 4 and parts[3].strip():
                rank = int(parts[1]) if parts[1].strip() else 999
                score = float(parts[2]) if parts[2].strip() else 0.0
                file_path = parts[3].strip()
                key = (bug_id, file_path.lower())
                if key not in best or rank < best[key][3]:
                    best[key] = (bug_id, file_path, "amalgam", rank, score)

            # BugLocator: columns 5,6,7
            if len(parts) >= 8 and parts[6].strip():
                rank = int(parts[5]) if parts[5].strip() else 999
                file_path = parts[6].strip()
                score = float(parts[7]) if parts[7].strip() else 0.0
                key = (bug_id, file_path.lower())
                if key not in best or rank < best[key][3]:
                    best[key] = (bug_id, file_path, "buglocator", rank, score)

            # Blizzard: columns 9,10
            if len(parts) >= 11 and parts[10].strip():
                rank = int(parts[9]) if parts[9].strip() else 999
                file_path = parts[10].strip()
                score = 0.0  # Blizzard has no score column
                key = (bug_id, file_path.lower())
                if key not in best or rank < best[key][3]:
                    best[key] = (bug_id, file_path, "blizzard", rank, score)

    return list(best.values())


def get_vulnlocalization_test_files():
    """Collect all GT file paths from VulnLocalization test set for dedup.

    Returns set of (normalized) file paths that appear in VulnLocalization GT.
    """
    import json as _json
    test_files = set()
    gt_dir = os.path.join("/mnt/d/Desktop/VulnLocalization", "Dataset", "GT")
    if os.path.isdir(gt_dir):
        for fname in os.listdir(gt_dir):
            if fname.endswith(".json"):
                with open(os.path.join(gt_dir, fname), "r") as f:
                    gt = _json.load(f)
                    for cf in gt.get("changed_files", []):
                        test_files.add(cf.lower().rstrip("."))
    return test_files


def dedup_against_vulnlocalization(df, test_files):
    """Remove training rows whose file path overlaps with VulnLocalization test set.

    A training row is removed if its file_path matches any test GT file path
    via exact, suffix, or basename matching.
    """
    if df.empty or not test_files:
        return df

    def _is_overlap(fp):
        fp_lower = fp.lower().rstrip(".")
        fp_bn = os.path.basename(fp_lower)
        for tf in test_files:
            if fp_lower == tf:
                return True
            if fp_lower.endswith(tf) or tf.endswith(fp_lower):
                return True
            if os.path.basename(tf) == fp_bn:
                return True
        return False

    mask = df["file_path"].apply(_is_overlap)
    removed = mask.sum()
    if removed > 0:
        print(f"\n  DEDUP: Removing {removed} rows with file paths overlapping VulnLocalization test set")
        df = df[~mask].copy()
    else:
        print(f"\n  DEDUP: No overlap found between HitMore training and VulnLocalization test files")
    return df


def load_hitmore_training_data(max_neg_ratio=5, verbose=True,
                                dedup_test_files=True):
    """Build training DataFrame from HitMore's original 6 datasets.

    For each dataset:
      1. Parse merge file -> (bugId, file_path) pairs
      2. Parse GT -> label each pair (1=positive, 0=negative)
      3. Parse XML -> bug report text for features
      4. Extract features
      5. Remove any rows overlapping with VulnLocalization test set

    Args:
        max_neg_ratio: max negative samples per positive (controls imbalance)
        dedup_test_files: if True, remove rows whose file paths overlap with test set
    Returns:
        DataFrame with same schema as dataset.build_dataset() output
    """
    rows = []
    total_pos = 0
    total_neg = 0

    for ds_name in DATASETS:
        if verbose:
            print(f"\n{'='*50}")
            print(f"Loading dataset: {ds_name}")

        # Load all data sources
        xml_reports = parse_xml_bug_reports(ds_name)
        gt = parse_gt_res(ds_name)
        pairs = parse_merge_file(ds_name)

        if verbose:
            print(f"  XML reports: {len(xml_reports)}")
            print(f"  GT bugs: {len(gt)}")
            print(f"  Merge pairs: {len(pairs)}")

        # Group pairs by bugId
        pairs_by_bug = {}
        for bug_id, file_path, source, rank, score in pairs:
            if bug_id not in pairs_by_bug:
                pairs_by_bug[bug_id] = []
            pairs_by_bug[bug_id].append((file_path, source, rank, score))

        ds_pos = 0
        ds_neg = 0
        skipped_no_gt = 0

        for bug_id, bug_pairs in pairs_by_bug.items():
            gt_files = gt.get(bug_id, set())

            # Separate positives and negatives
            pos_pairs = []
            neg_pairs = []
            for file_path, source, rank, score in bug_pairs:
                if _match_gt_path(file_path, gt_files):
                    pos_pairs.append((file_path, source, rank, score))
                else:
                    neg_pairs.append((file_path, source, rank, score))

            if not pos_pairs:
                skipped_no_gt += 1
                continue

            # Sample negatives
            n_neg = min(len(neg_pairs), len(pos_pairs) * max_neg_ratio)
            sampled_neg = random.sample(neg_pairs, n_neg) if n_neg > 0 else []

            # Get bug report text
            report = xml_reports.get(bug_id, {})
            issue_title = report.get("summary", "")
            issue_body = report.get("description", "")

            # Build rows
            for file_path, source, rank, score in pos_pairs:
                feats = extract_all_features(issue_title, issue_body, file_path, "java")
                feats["cve_id"] = bug_id
                feats["file_path"] = file_path
                feats["label"] = 1
                feats["_gt_funcs"] = json.dumps([])  # No function-level GT in HitMore
                feats["_dataset"] = ds_name
                feats["_source"] = source
                rows.append(feats)
                ds_pos += 1

            for file_path, source, rank, score in sampled_neg:
                feats = extract_all_features(issue_title, issue_body, file_path, "java")
                feats["cve_id"] = bug_id
                feats["file_path"] = file_path
                feats["label"] = 0
                feats["_gt_funcs"] = json.dumps([])
                feats["_dataset"] = ds_name
                feats["_source"] = source
                rows.append(feats)
                ds_neg += 1

        total_pos += ds_pos
        total_neg += ds_neg

        if verbose:
            print(f"  Positives: {ds_pos}, Negatives: {ds_neg}, "
                  f"Bugs: {len(pairs_by_bug) - skipped_no_gt}, "
                  f"No-GT bugs: {skipped_no_gt}")

    if verbose:
        print(f"\n{'='*50}")
        print(f"TOTAL: {len(rows)} rows ({total_pos} pos, {total_neg} neg)")
        print(f"Class ratio: {total_pos / max(total_neg, 1):.4f}")

    df = pd.DataFrame(rows)

    # Deduplicate against VulnLocalization test set
    if dedup_test_files:
        test_files = get_vulnlocalization_test_files()
        df = dedup_against_vulnlocalization(df, test_files)

    return df


if __name__ == "__main__":
    print("Loading HitMore training data...")
    df = load_hitmore_training_data(max_neg_ratio=3, verbose=True)
    print(f"\nColumns: {list(df.columns)}")
    print(f"Label distribution:\n{df['label'].value_counts()}")
    print(f"\nDataset distribution:\n{df['_dataset'].value_counts()}")
    print(f"\nFirst 3 rows:")
    print(df.head(3).to_string())
