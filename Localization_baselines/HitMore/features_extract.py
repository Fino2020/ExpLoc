"""
Feature extraction adapted from HitMore-main for VulnLocalization data.

Original HitMore has 122 features in 3 categories:
  - Bug Report Features (28): stack traces, code, patch, screenshots, readability, reporter
  - Buggy File Features (77): readability, NDEV, DAF/MAF, scattering, complexity, CK metrics
  - Relation Features (18): similarity, collaborative filtering, overlap, topic

For VulnLocalization, we adapt to multi-language CVE data:
  - Bug Report Features: text-based features from issue title+body
  - File Features: path-based features (repo context, extension, depth)
  - Relation Features: TF-IDF similarity between issue text and file path/functions
"""

import re
import os
import math
import string
import json
from collections import Counter
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from nltk.stem import PorterStemmer
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

# ============================================================
# Text normalization (adapted from HitMore similarity.py)
# ============================================================

_stop_words = set(stopwords.words("english"))
_stemmer = PorterStemmer()


def normalize(text):
    """Normalize text: lowercase, remove punctuation, tokenize, stem, remove stopwords."""
    if not text:
        return []
    remove_punc_map = dict((ord(char), None) for char in string.punctuation)
    removed_punc = text.lower().translate(remove_punc_map)
    tokenized = word_tokenize(removed_punc)
    stemmed = [_stemmer.stem(item) for item in tokenized if item not in _stop_words]
    return stemmed


def preprocess(text):
    """Preprocess text: tokenize, camelCase split, lemmatize, remove stopwords."""
    from nltk.stem import WordNetLemmatizer
    lemmatizer = WordNetLemmatizer()
    if not text:
        return []
    words = word_tokenize(text)
    processed = []
    for word in words:
        if word.isalnum() and word.lower() not in _stop_words:
            split_words = re.sub(r"([a-z])([A-Z])", r"\1 \2", word).split()
            for sw in split_words:
                processed.append(lemmatizer.lemmatize(sw.lower()))
    return processed


# ============================================================
# Bug Report Features (adapted from HitMore BugReportFeatures.py)
# ============================================================

_STACK_PATTERNS = [
    re.compile(r"at\s(.*)\.java:\d"),
    re.compile(r"^[\s]*at[\s]+.*[\n]?\([\w]+\.java(:[\d]+)?\)", re.MULTILINE),
    re.compile(r"^[\s]*([\w]+\.)+[\w]+(Exception|Error)", re.MULTILINE),
    re.compile(r"Traceback\s*\(most recent call last\)"),
    re.compile(r"File\s+\".*\",\s*line\s*\d+"),
    re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+", re.MULTILINE),  # C/C++ backtrace
]

_CODE_PATTERNS = [
    re.compile(r"^[\s]*(public|private|protected).*class[\s]+[\w]+[\s]", re.MULTILINE),
    re.compile(r"^[\s]*(public|private|protected).*\(.*\)[\n]?", re.MULTILINE),
    re.compile(r"^[\s]*(if|for|while)[\s]*\(.*\)", re.MULTILINE),
    re.compile(r"\{(.*\n)*.*\}", re.MULTILINE),
    re.compile(r"import[\s]+.*;"),
    re.compile(r"def\s+\w+\s*\(.*\):", re.MULTILINE),  # Python
    re.compile(r"function\s+\w+\s*\(.*\)\s*\{", re.MULTILINE),  # JS
    re.compile(r"```"),  # Markdown code fence
]

_PATCH_PATTERNS = [
    re.compile(r"[-]{3}[\s].*\n[\+]{3}[\s].*\n[@]{2}"),
    re.compile(r"diff\s+--git"),
]

_SCREENSHOT_KEYWORDS = [
    "window", "view", "picture", "screenshot", "visible", "image",
    "png", "bmp", "jpg", "jpeg", "screen shot", "rectangle",
]

_CVE_SECURITY_KEYWORDS = [
    "overflow", "injection", "xss", "csrf", "bypass", "escalation",
    "denial", "dos", "rce", "execute", "leak", "disclosure", "traversal",
    "authenticate", "authorize", "encrypt", "decrypt", "ssl", "tls",
    "sanitize", "validate", "escape", "input", "output", "null",
    "dereference", "corrupt", "race", "deadlock", "double-free",
    "use-after-free", "uaf", "exploit", "attack", "malicious",
    "unauthorized", "privilege", "root", "admin",
]


def extract_bug_report_features(issue_text):
    """
    Extract features from CVE issue description.
    Returns dict of feature_name -> float/int.
    """
    if not issue_text:
        issue_text = ""

    features = {}

    # Text statistics
    features["br_text_len"] = len(issue_text)
    features["br_word_count"] = len(issue_text.split())
    features["br_sentence_count"] = max(issue_text.count(".") + issue_text.count("!")
                                         + issue_text.count("?"), 1)

    # Has stack traces
    features["br_has_stack_trace"] = 0
    for pat in _STACK_PATTERNS:
        if pat.search(issue_text):
            features["br_has_stack_trace"] = 1
            break

    # Has code snippets
    features["br_has_code"] = 0
    for pat in _CODE_PATTERNS:
        if pat.search(issue_text):
            features["br_has_code"] = 1
            break

    # Has patch/diff
    features["br_has_patch"] = 0
    if "patch" in issue_text.lower() or "fix" in issue_text.lower():
        features["br_has_patch"] = 1
    for pat in _PATCH_PATTERNS:
        if pat.search(issue_text):
            features["br_has_patch"] = 1
            break

    # Has screenshots
    features["br_has_screenshot"] = 0
    text_lower = issue_text.lower()
    for word in _SCREENSHOT_KEYWORDS:
        if word in text_lower:
            features["br_has_screenshot"] = 1
            break

    # Security keyword density
    security_count = sum(1 for kw in _CVE_SECURITY_KEYWORDS if kw in text_lower)
    features["br_security_keyword_count"] = security_count

    # Readability metrics (adapted from HitMore readability/)
    features["br_avg_word_len"] = _avg_word_length(issue_text)
    features["br_readability"] = _flesch_kincaid(issue_text)

    # Normalized tokens
    tokens = preprocess(issue_text)
    features["br_token_count"] = len(tokens)
    features["br_unique_token_count"] = len(set(tokens))
    features["br_unique_ratio"] = (len(set(tokens)) / max(len(tokens), 1))

    # URL / mention count
    features["br_url_count"] = len(re.findall(r"https?://[^\s]+", issue_text))
    features["br_mention_count"] = len(re.findall(r"@\w+", issue_text))

    # Issue body structure
    features["br_has_java_example"] = 1 if re.search(r"\.java\b|public\s+class|import\s+java", issue_text) else 0
    features["br_has_c_example"] = 1 if re.search(r"#include|malloc|free\(", issue_text) else 0
    features["br_has_python_example"] = 1 if re.search(r"def\s+\w+\s*\(|import\s+\w+\s*$", issue_text, re.MULTILINE) else 0

    return features


def _avg_word_length(text):
    words = text.split()
    if not words:
        return 0.0
    return sum(len(w) for w in words) / len(words)


def _flesch_kincaid(text):
    """Simplified Flesch Reading Ease. Higher = easier to read."""
    sentences = max(text.count(".") + text.count("!") + text.count("?"), 1)
    words = max(len(text.split()), 1)
    syllables = sum(_count_syllables(w) for w in text.split())
    if words == 0 or sentences == 0:
        return 50.0
    return 206.835 - 1.015 * (words / sentences) - 84.6 * (syllables / words)


def _count_syllables(word):
    word = word.lower()
    count = 0
    vowels = "aeiouy"
    if word and word[0] in vowels:
        count += 1
    for i in range(1, len(word)):
        if word[i] in vowels and word[i - 1] not in vowels:
            count += 1
    if word.endswith("e"):
        count -= 1
    if word.endswith("le") and len(word) > 2 and word[-3] not in vowels:
        count += 1
    return max(count, 1)


# ============================================================
# File Features (adapted from HitMore buggy file features)
# ============================================================

_IMPORTANT_DIRS = [
    "src", "lib", "core", "main", "include", "inc", "engine",
    "kernel", "net", "http", "ssl", "tls", "auth", "crypto",
    "parse", "serialize", "deserialize", "xml", "json", "sql",
    "exec", "shell", "os", "io", "fs", "mem", "buf",
]

_VULN_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp",
                    ".py", ".js", ".ts", ".java", ".php", ".rb",
                    ".go", ".rs", ".pl", ".sh", ".swift"}


def extract_file_features(file_path, language):
    """Extract features from a file path."""
    features = {}
    path_lower = file_path.lower()

    # Path components
    parts = file_path.replace("\\", "/").split("/")
    features["file_depth"] = len(parts)
    features["file_name"] = parts[-1] if parts else ""
    features["file_name_len"] = len(features["file_name"])

    # Extension
    _, ext = os.path.splitext(file_path)
    features["file_extension"] = ext.lower()
    features["file_has_src_ext"] = 1 if ext.lower() in _VULN_EXTENSIONS else 0

    # Important dirs in path
    features["file_in_important_dir"] = 0
    for part in parts[:-1]:
        if part.lower() in _IMPORTANT_DIRS:
            features["file_in_important_dir"] = 1
            break

    # Path contains security-related keywords
    sec_keywords = ["sec", "auth", "ssl", "tls", "crypto", "cipher", "hash",
                    "passwd", "token", "session", "cookie", "xss", "csrf",
                    "input", "sanitize", "escape", "validate", "filter"]
    features["file_path_security_score"] = sum(1 for kw in sec_keywords if kw in path_lower)

    # Test file heuristics
    features["file_is_test"] = 1 if ("test" in path_lower or "spec" in path_lower
                                      or path_lower.endswith("test.py")
                                      or path_lower.endswith("_test.c")) else 0

    # File type match with language
    lang_ext_map = {
        "c": [".c", ".h"],
        "cpp": [".cpp", ".cc", ".cxx", ".hpp", ".h"],
        "python": [".py"],
        "javascript": [".js", ".ts", ".jsx", ".tsx"],
        "java": [".java"],
        "php": [".php"],
        "go": [".go"],
        "ruby": [".rb"],
        "rust": [".rs"],
        "perl": [".pl", ".pm"],
    }
    expected_exts = lang_ext_map.get(language.lower(), [])
    features["file_matches_language"] = 1 if any(ext.lower() in expected_exts for ext in [ext.lower()]) else 0
    # Better check
    features["file_matches_language"] = 1 if ext.lower() in expected_exts else 0

    return features


# ============================================================
# Relation Features (adapted from HitMore similarity.py etc.)
# ============================================================

def extract_relation_features(issue_text, file_path, file_content=None):
    """
    Extract relation features between issue description and candidate file.
    """
    features = {}

    # Tokenize both
    issue_tokens = set(normalize(issue_text))
    file_tokens = set(normalize(file_path))
    # Also tokenize the file path parts (split by / and by camelCase)
    path_parts = file_path.replace("\\", "/").split("/")
    all_file_tokens = set()
    for part in path_parts:
        all_file_tokens.update(normalize(part))
    file_tokens.update(all_file_tokens)

    # Jaccard similarity (like HitMore's surface lexical similarity)
    if issue_tokens and file_tokens:
        features["rel_jaccard"] = len(issue_tokens & file_tokens) / max(len(issue_tokens | file_tokens), 1)
    else:
        features["rel_jaccard"] = 0.0

    # Keyword overlap count
    features["rel_token_overlap"] = len(issue_tokens & file_tokens)

    # File name appears in issue text
    file_name = os.path.basename(file_path)
    file_name_no_ext = os.path.splitext(file_name)[0]
    features["rel_filename_in_issue"] = 1 if file_name.lower() in issue_text.lower() else 0
    features["rel_filename_noext_in_issue"] = 1 if file_name_no_ext.lower() in issue_text.lower() else 0

    # Directory overlap
    issue_lower = issue_text.lower()
    dir_matches = sum(1 for p in path_parts[:-1] if p.lower() in issue_lower)
    features["rel_dir_overlap"] = dir_matches

    # Code content similarity (if available)
    if file_content:
        file_doc_tokens = set(normalize(file_content))
        if issue_tokens and file_doc_tokens:
            features["rel_content_jaccard"] = len(issue_tokens & file_doc_tokens) / max(len(issue_tokens | file_doc_tokens), 1)
        else:
            features["rel_content_jaccard"] = 0.0
    else:
        features["rel_content_jaccard"] = 0.0

    return features


# ============================================================
# Full feature extraction for a (CVE, file) pair
# ============================================================

def extract_all_features(issue_title, issue_body, file_path, language, cwe_id=None, cvss_score=None):
    """
    Extract the complete feature vector for a (CVE, file) pair.
    Returns flat dict of all features.
    """
    full_text = (issue_title or "") + " " + (issue_body or "")

    features = {}
    features.update(extract_bug_report_features(full_text))
    features.update(extract_file_features(file_path, language))
    features.update(extract_relation_features(full_text, file_path))

    # Additional metadata features
    features["meta_cwe_id"] = cwe_id or "UNKNOWN"
    features["meta_cvss_score"] = cvss_score or 0.0
    features["meta_language"] = language or "unknown"

    return features
