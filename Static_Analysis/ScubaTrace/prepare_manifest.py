"""
Generate ScubaTrace manifest from DataLeakageAssessment.json.
Populates repo_path and language for cloned repos.
"""
import json, os, sys

REPO_BASE = "/mnt/e/Desktop/Localization_Repo/Localization_Repo"
DATASET = "/mnt/d/Desktop/VulnLocalization/Dataset/DataLeakageAssessment.json"
OUTPUT = "/mnt/d/Desktop/VulnLocalization/Static_Analysis/ScubaTrace/manifest_scubatrace.json"

LANG_MAP = {".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
            ".py": "python", ".java": "java", ".js": "javascript", ".ts": "javascript",
            ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php"}


def detect_language(repo_path):
    """Quick language detection from file extensions."""
    if not os.path.isdir(repo_path):
        return "unknown"
    counts = {}
    try:
        for root, dirs, files in os.walk(repo_path):
            rel = os.path.relpath(root, repo_path)
            if len(rel.split(os.sep)) > 5:
                dirs.clear()
                continue
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in LANG_MAP:
                    lang = LANG_MAP[ext]
                    counts[lang] = counts.get(lang, 0) + 1
            if len(counts) > 5000:
                break
    except Exception:
        pass
    if counts:
        return max(counts, key=counts.get)
    return "unknown"


with open(DATASET) as f:
    dataset = json.load(f)

manifest = []
missing = 0
for item in dataset:
    cve_id = item["cve_id"]
    commits = item.get("commit_list", [])
    if not commits:
        continue
    repo = commits[0]["repo"]
    owner, project = repo.split("/", 1) if "/" in repo else ("", repo)
    repo_path = os.path.join(REPO_BASE, cve_id, owner, project)

    if not os.path.isdir(os.path.join(repo_path, ".git")):
        missing += 1
        continue

    lang = detect_language(repo_path)
    manifest.append({"cve_id": cve_id, "language": lang, "repo_path": repo_path})

with open(OUTPUT, "w") as f:
    json.dump(manifest, f, indent=2)

print(f"Generated {OUTPUT}: {len(manifest)} entries (skipped {missing} not cloned)")
print("Languages:", {e["language"] for e in manifest})
