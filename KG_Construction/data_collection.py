import json
import urllib.request
import re
import time
import os
import requests
from requests_oauth2 import OAuth2BearerToken
from unidiff import PatchSet
import math
import numpy as np
import copy
from datetime import datetime


GH_REST_URL = 'https://api.github.com/repos'
GH_GRAPHQL_URL = "https://api.github.com/graphql"

MAX_TRY_TIME = 1
GH_TOKEN = ['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']  # fill with your own GitHub Token
TOKEN_NUM = 3
LIMIT_PER_ACCOUNT_PER_HOUR = 4950

GLOBAL_REQUEST_COUNT = 0
GLOBAL_DOWNLOAD_COUNT = 0


def fix_time(t):
    t = t.strip()
    t = re.sub(r'\sUTC', 'Z', t)
    # t = t.strip()
    t = re.sub(r'\s', 'T', t)
    return t


def get_by_oauth2(url):
    t = 0
    while t < MAX_TRY_TIME:
        try:
            with requests.Session() as s:
                global GLOBAL_REQUEST_COUNT
                if (GLOBAL_REQUEST_COUNT % 1000) == 0:
                    time.sleep(1)
                s.auth = OAuth2BearerToken(GH_TOKEN[int(GLOBAL_REQUEST_COUNT / LIMIT_PER_ACCOUNT_PER_HOUR) % TOKEN_NUM])
                GLOBAL_REQUEST_COUNT += 1
                r = s.get(url)
                r.raise_for_status()
            
            return r.json()
        except Exception as e:
            print(e)
            time.sleep(1)
            t += 1
    
    return None


def post_by_oauth2(url, payload):
    t = 0
    while t < MAX_TRY_TIME:
        try:
            with requests.Session() as s:
                global GLOBAL_REQUEST_COUNT
                if (GLOBAL_REQUEST_COUNT % 1000) == 0:
                    time.sleep(1)
                s.auth = OAuth2BearerToken(GH_TOKEN[int(GLOBAL_REQUEST_COUNT / LIMIT_PER_ACCOUNT_PER_HOUR) % TOKEN_NUM])
                GLOBAL_REQUEST_COUNT += 1
                r = s.post(url, json=payload)
                r.raise_for_status()
            
            return r.json()
        except Exception as e:
            print(e)
            time.sleep(1)
            t += 1
    
    return None


def download_diff(url):
    t = 0
    while t < MAX_TRY_TIME:
        try:
            global GLOBAL_DOWNLOAD_COUNT
            if GLOBAL_DOWNLOAD_COUNT % 1000 == 0:
                time.sleep(1)
            GLOBAL_DOWNLOAD_COUNT += 1
            diff = urllib.request.urlopen(url)
            encoding = diff.headers.get_charsets()[0]
            diff = diff.read().decode(encoding)
            return diff
        except Exception as e:
            print(e)
            time.sleep(1)
            t += 1

    return None


def save_gh_artifact(gh_artifact, gh_url, attr="metadata"):
    gh_commit = GH_COMMIT.match(gh_url)
    gh_issue_pull = GH_ISSUE_PULL.match(gh_url)
    url_type = None
    if gh_issue_pull is not None:
        url_type = gh_issue_pull.group(3)
        if url_type == "pull":
            url_type = "pulls"
        repo = gh_issue_pull.group(2).lower()
        id_ = gh_issue_pull.group(4)
    elif gh_commit is not None:
        url_type = "commits"
        repo = gh_commit.group(2).lower()
        id_ = gh_commit.group(4)
    else:
        return None
    
    if attr in ["metadata", "timeline"] and url_type == "pulls":
        url_type = "issues"
    save_path = DATA_PATH + f"{url_type}_{attr}/" + f"{repo.replace('/', '.')}.{id_}.json"

    if not os.path.exists(save_path):
        with open(save_path, 'w') as f:
            json.dump(gh_artifact, f, indent=4)
    

def save_issue_metadata_from_event_cr(issue_from_cr):
    issue_metadata = {}
    for k, v in issue_from_cr.items():
        if k in ["draft", "repository"]:
            continue
        
        issue_metadata[k] = v
    
    save_gh_artifact(gh_artifact=issue_metadata, gh_url=issue_from_cr["html_url"], attr="metadata")


def save_commit_metadata_from_pull_commits(pull_commits):
    for commit in pull_commits:
        commit_metadata = {}
        for key in ["sha", "node_id", "url", "html_url", "parents"]:
            commit_metadata[key] = commit[key]
        for key in ["author", "committer", "tree", "message", "verification"]:
            commit_metadata[key] = commit["commit"][key]
        
        save_gh_artifact(gh_artifact=commit_metadata, gh_url=commit["html_url"], attr="metadata")


def update_commit_metadata():
    directory_path = DATA_PATH + "pulls_commits/"
    for f in os.listdir(directory_path):
        pull_commit = json.load(open(directory_path + f, 'r'))
        save_commit_metadata_from_pull_commits(pull_commits=pull_commit)


def extract_commit_url_from_event(commit_id, commit_url):
    if commit_id is None:
        print(f"reference without commit")
        return None
    
    gh_commit_api = GH_COMMIT_API.match(commit_url)
    user_repo = gh_commit_api.group(2)
    return f"https://github.com/{user_repo}/commit/{commit_id}"


def crawl_gh_artifact(gh_url, attr="metadata"):
    gh_issue_pull = GH_ISSUE_PULL.match(gh_url)
    gh_commit = GH_COMMIT.match(gh_url)
    
    gh_sec_adv = GH_SEC_ADVISORY.match(gh_url)
    ghsa_id = GHSA_ID.match(gh_url)
    cve_id = CVE_ID.match(gh_url)

    url_type = None
    if gh_issue_pull is not None:
        url_type = gh_issue_pull.group(3)
        if url_type == "pull":
            url_type = "pulls"
        repo = gh_issue_pull.group(2)
        id_ = gh_issue_pull.group(4)
    elif gh_commit is not None:
        url_type = "commits"
        repo = gh_commit.group(2)
        id_ = gh_commit.group(4)
        if len(id_) != 40:
            if id_ in MAPPINGS:
                id_ = MAPPINGS[id_]
                if id_ is None:
                    return None
            else:
                incomplete_url = f"https://github.com/{repo}/commit/{id_}"
                query = "query { resource(url: \"" + incomplete_url + "\") { url}}"
                result = post_by_oauth2(url=GH_GRAPHQL_URL, payload={"query": query})
                try:
                    updated_url = result["data"]["resource"]["url"]
                except Exception:
                    updated_url = None
                if updated_url is not None:
                    print("[MAPPING]", id_, GH_COMMIT.match(updated_url).group(4))
                    id_ = GH_COMMIT.match(updated_url).group(4)
                else:
                    print("[MAPPING]", id_, None)
                    return None
    
    elif any(_ is not None for _ in [gh_sec_adv, ghsa_id, cve_id]):
        url_type = "advisories"
        if gh_sec_adv is not None:
            id_ = gh_sec_adv.group(3)
        elif (ghsa_id is not None) or (cve_id is not None):
            id_ = gh_url
            if "CVE" in id_ and id_ in MAPPINGS:
                id_ = MAPPINGS[id_]
                if id_ is None:
                    return None
    else:
        return None
    
    if attr not in ["metadata", "timeline", "commits", "diff"]:
        raise ValueError("invalid attr")
    if attr == "commits" and url_type != "pulls":
        raise ValueError("only pulls have attr [commits]")
    if attr == "diff" and url_type != "commits":
        raise ValueError("only commits have attr [diff]")
    
    if attr in ["metadata", "timeline"] and url_type == "pulls":
        url_type = "issues"
        
    if url_type == "advisories":
        save_path = DATA_PATH + "advisories/" + f"{id_}.json"
    else:
        save_path = DATA_PATH + f"{url_type}_{attr}/" + f"{repo.lower().replace('/', '.')}.{id_}"
        save_path += ".patch" if attr == "diff" else ".json"

    if os.path.exists(save_path):
        if attr == "diff":
            artifact = 1
            # artifact = open(save_path, 'r').readlines()
            # artifact = PatchSet.from_filename(save_path, encoding="utf-8")
        else:
            artifact = json.load(open(save_path, 'r'))
    else:
        if url_type == "advisories":
            request_url = GH_GRAPHQL_URL
            if "GHSA" in id_:
                query = "query { securityAdvisory(ghsaId:\"" + id_ + "\") { ghsaId description references { url} vulnerabilities(first:1) { nodes { package { name}}}}}"
            elif "CVE" in id_:
                query = "query { securityAdvisories(identifier:{type:CVE, value:\"" + id_ + "\"}, first:1) { nodes { ghsaId references { url} identifiers {type value} vulnerabilities(first:1) { nodes { package { name}}}}}}"
        elif url_type == "commits":
            request_url = f"https://api.github.com/repos/{repo}/git/commits/{id_}"
        else:
            request_url = f"https://api.github.com/repos/{repo}/{url_type}/{id_}"
        
        if attr in ["timeline", "commits"]:
            request_url += f"/{attr}"
        elif attr == "diff":
            request_url = f"https://github.com/{repo}/commit/{id_}.patch"
        
        if request_url in INVALID_URL:
            return None
        
        if url_type == "advisories":
            artifact = post_by_oauth2(request_url, payload={"query": query})
            if artifact is not None:
                if "GHSA" in id_:
                    artifact = artifact["data"]["securityAdvisory"]
                elif "CVE" in id_:
                    artifact = artifact["data"]["securityAdvisories"]["nodes"]
                    artifact = None if len(artifact) == 0 else artifact[0]
                    if artifact is not None:
                        if id_ in [_["value"] for _ in artifact["identifiers"]]:
                            save_path = DATA_PATH + "advisories/" + f"{artifact['ghsaId']}.json"
                            print("[MAPPING]", id_, artifact['ghsaId'])
                        else:
                            print("[MAPPING]", id_, None)
                            return None
        
        elif attr == "diff":
            artifact = download_diff(request_url)
        
        else:
            artifact = get_by_oauth2(request_url)
        
        if artifact is not None:
            with open(save_path, 'w') as f:
                if attr == "diff":
                    f.writelines(artifact)
                else:
                    json.dump(artifact, f, indent=4)
                
            if url_type == "pull" and attr == "commits":
                save_commit_metadata_from_pull_commits(artifact)

    return artifact


def crawl_gh_repo_info(gh_repo):
    repo = gh_repo.lower()
    save_path = DATA_PATH + "repo_info/" + f"{repo.replace('/', '.')}.json"
    if os.path.exists(save_path):
        repo_info = json.load(open(save_path, 'r'))
        return repo_info

    request_url = f"https://api.github.com/repos/{repo}"
    repo_info = get_by_oauth2(request_url)
    if repo_info is not None:
        with open(save_path, 'w') as f:
            json.dump(repo_info, f, indent=4)
    return repo_info


def crawl_gh_repo_last_commit(gh_repo, default_branch="master"):
    repo = gh_repo.lower()
    save_path = DATA_PATH + "repo_last_commit/" + f"{repo.replace('/', '.')}.json"
    if os.path.exists(save_path):
        repo_last_commit = json.load(open(save_path, 'r'))
        return repo_last_commit
    
    request_url = f"https://api.github.com/repos/{repo}/branches/{default_branch}"
    repo_last_commit = get_by_oauth2(request_url)
    if repo_last_commit is not None:
        with open(save_path, 'w') as f:
            json.dump(repo_last_commit, f, indent=4)
    return repo_last_commit


def crawl_gh_pull_extra_info(repo, pull_id):
    save_path = DATA_PATH + "pulls_extra_info/" + f"{repo.lower().replace('/', '.')}.{pull_id}.json"
    if os.path.exists(save_path):
        pull_extra_info = json.load(open(save_path, 'r'))
        return pull_extra_info
    
    owner, name = repo.split('/')
    query = "query {repository(owner:\"" + owner + "\", name:\"" + name + "\") {pullRequest(number:" + str(pull_id) + ") { isCrossRepository}}}"
    pull_extra_info = post_by_oauth2(GH_GRAPHQL_URL, payload={"query": query})
    pull_extra_info = None if pull_extra_info is None else pull_extra_info["data"]["repository"]["pullRequest"]
    if pull_extra_info is not None:
        with open(save_path, 'w') as f:
            json.dump(pull_extra_info, f, indent=4)
    return pull_extra_info


def update_file_name(dir_path):
    files = os.listdir(dir_path)
    files.sort()
    for f in files:
        new_f = f"{'.'.join(f.split('.')[:-1])}.patch".lower()
        old_path = dir_path + f
        new_path = dir_path + new_f
        if not os.path.exists(new_path):
            os.rename(src=old_path, dst=new_path)
        else:
            os.remove(old_path)


def match_user_repo(user_repo, software, description):
    soft_ = [_.lower() for _ in software]
    descrip_ = description.lower()

    user, repo = user_repo.split('/')

    repo_split = re.sub(r'[^a-z]', ' ', repo, flags=re.I).split()
    user_split = re.sub(r'[^a-z]', ' ', user, flags=re.I).split()

    repo_split = [pp for p in repo_split for pp in re.sub(r'([A-Z][a-z]+)', r' \1', re.sub(r'([A-Z]+)', r' \1', p)).split()]
    user_split = [pp for p in user_split for pp in re.sub(r'([A-Z][a-z]+)', r' \1', re.sub(r'([A-Z]+)', r' \1', p)).split()]

    user, repo = user.lower(), repo.lower()
    user_split = [p.lower() for p in user_split]
    repo_split = [p.lower() for p in repo_split]

    if all([(len(r) < 3) for r in repo_split]):
        repo_split = []
    if all([(len(u) < 3) for u in user_split]):
        user_split = []

    if any((repo in c) for c in soft_) or any((user in c) for c in soft_):
        return 1

    score_repo_des = 0
    score_user_des = 0
    score_repo_soft = 0
    score_user_soft = 0

    if len(repo_split) > 0:
        len_repo = sum([len(r) for r in repo_split])
        if len(soft_) > 0:
            len_match_repo_soft = max([sum([len(r) for r in repo_split if r in s]) for s in soft_])
            score_repo_soft = len_match_repo_soft / len_repo

    if len(user_split) > 0:
        len_user = sum([len(u) for u in user_split])
        if len(soft_) > 0:
            len_match_user_soft = max([sum([len(u) for u in user_split if u in s]) for s in soft_])
            score_user_soft = len_match_user_soft / len_user

    return max(score_repo_des, score_user_des, score_repo_soft, score_user_soft)


def get_valid_gh_url(external_references, description, software, cve_id=None):
    gh_url = {"issue": [], "pull": [], "commit": [], "security_advisory": [], "release_tag": [], "change_log": [], "other": []}
    user_repo_count = {}

    for reference in external_references:
        if "url" not in reference:
            continue
        
        if "github.com" in reference["url"]:
            url = GH_URL.match(reference["url"])
            if url is not None:
                user_repo = url.group(2)
                if user_repo not in user_repo_count:
                    user_repo_count[user_repo] = 0

                gh_issue_pull = GH_ISSUE_PULL.match(reference["url"]) if (not any((_.lower() in reference["url"].lower()) for _ in BLACK_LIST)) else None
                gh_commit = GH_COMMIT.match(reference["url"])
                gh_security_advisory = True if GH_SEC_ADVISORY.match(reference["url"]) is not None and (not any((_.lower() in reference["url"].lower()) for _ in BLACK_LIST)) else False
                gh_release_tag = True if "/releases/tag/" in reference["url"] else False
                gh_change_log = True if "/change" in reference["url"].lower() else False

                # heuristics to further remove links from repositories other than the vulnerable one
                url_type = "other"
                if gh_issue_pull is not None:
                    if gh_issue_pull.group(3) == "issues":
                        url_type = "issue"
                        small_issue_id = True if int(gh_issue_pull.group(4)) < 10 else False
                        repo_with_keyword = True if INVALID_USER_REPO.search(user_repo) else False
                        if repo_with_keyword:
                            user_repo_count[user_repo] += 1
                        elif small_issue_id:
                            user_repo_count[user_repo] += 2
                        else:
                            user_repo_count[user_repo] += 3
                    else:
                        url_type = "pull"
                        if gh_commit is not None:
                            user_repo_count[user_repo] += 6
                            gh_url["commit"].append(f"https://github.com/{gh_commit.group(2)}/commit/{gh_commit.group(4)}")
                        else:
                            user_repo_count[user_repo] += 3
                
                elif gh_commit is not None:
                    url_type = "commit"
                    user_repo_count[user_repo] += 6
                    if "pull" in gh_commit.group(3):
                        url_type = "pull"
                        gh_url["commit"].append(f"https://github.com/{gh_commit.group(2)}/commit/{gh_commit.group(4)}")
                
                elif gh_security_advisory:
                    url_type = "security_advisory"
                    repo_with_keyword = True if INVALID_USER_REPO.search(user_repo) else False
                    if repo_with_keyword:
                        user_repo_count[user_repo] += 1
                    else:
                        user_repo_count[user_repo] += 3
                
                elif gh_release_tag:
                    url_type = "release_tag"
                    user_repo_count[user_repo] += 3
                
                elif gh_change_log:
                    url_type = "change_log"
                    user_repo_count[user_repo] += 3

                else:
                    url_type = "other"
                    repo_with_keyword = True if INVALID_USER_REPO.search(user_repo) else False
                    if repo_with_keyword:
                        user_repo_count[user_repo] += 1
                    else:
                        user_repo_count[user_repo] += 2
                
                gh_url[url_type].append(reference["url"])
    
    if not any([len(_) for _ in gh_url.values()]):
        return None

    thres = 2
    match_thres = 0.3
    correct_user_repo = []
    sorted_user_repo_count = sorted(user_repo_count.items(), key=lambda x:x[1], reverse=True)
    if len(user_repo_count) > 1:
        for ur in sorted_user_repo_count:
            if (ur[1] > thres) or (ur[1] > 1 and match_user_repo(user_repo=ur[0], software=software, description=description) > match_thres):
                correct_user_repo.append(ur[0])
        
        if len(correct_user_repo) == 0:
            if sorted_user_repo_count[0][1] != sorted_user_repo_count[1][1]:
                correct_user_repo.append(sorted_user_repo_count[0][0])

    else:
        ur = sorted_user_repo_count[0]
        if (ur[1] > 2) or (ur[1] > 1 and match_user_repo(user_repo=ur[0], software=software, description=description) > match_thres):
            correct_user_repo.append(ur[0])

    for url_type, urls in gh_url.items():
        valid_url = []
        for u in urls:
            user_repo = GH_URL.match(u).group(2)
            if user_repo in correct_user_repo or any((_.lower() in user_repo.lower()) for _ in WHITE_LIST):
                valid_url.append(u)
            else:
                pass
        gh_url[url_type] = valid_url

    del gh_url["other"]
    if not any([len(_) for _ in gh_url.values()]):
        return None
    
    return gh_url


def collect_nvd_gh_url(directory_path):
    cve_url = {}

    total_cve = 0
    cve_with_gh_url = 0
    cve_per_year = {}
    
    count_issue_pull_commit = 0
    count_security_advisory = 0
    count_release_tag_change_log = 0

    files = os.listdir(directory_path)
    files.sort()
    for f in files:
        file_path = directory_path + f
        data = json.load(open(file_path, 'r', encoding="utf-8"))
        for vuln in data["CVE_Items"]:
            total_cve += 1

            published_year = vuln["publishedDate"][0:4]
            if published_year not in cve_per_year:
                cve_per_year[published_year] = [0, 0]
            cve_per_year[published_year][0] += 1

            cve_id = vuln["cve"]["CVE_data_meta"]["ID"]
            description = vuln["cve"]["description"]["description_data"][0]["value"].lower()
            cpes = set(CPE.findall(str(vuln["configurations"]["nodes"]).lower()))

            gh_url = get_valid_gh_url(external_references=vuln["cve"]["references"]["reference_data"], description=description, software=cpes, cve_id=cve_id)
            if gh_url is None:
                continue
                
            cve_url[cve_id] = copy.deepcopy(gh_url)
            
            cve_with_gh_url += 1
            cve_per_year[published_year][1] += 1


            if len(gh_url["issue"]) + len(gh_url["pull"]) + len(gh_url["commit"]) > 0:
                count_issue_pull_commit += 1
            elif len(gh_url["security_advisory"]) > 0:
                count_security_advisory += 1
            elif len(gh_url["release_tag"]) + len(gh_url["change_log"]) > 0:
                count_release_tag_change_log += 1
    
    print("issue_pull_commit:", count_issue_pull_commit)
    print("security_advisory:", count_security_advisory)
    print("release_tag_change_log:", count_release_tag_change_log)
    
    with open("nvd_gh_url.json", "w") as f:
        json.dump(cve_url, f, indent=4)


def collect_osv_gh_url(directory_path):
    cve_url = {}
    noncve_url = {}

    total_cve = 0
    total_noncve = 0
    cve_with_gh_url = 0
    noncve_with_gh_url = 0

    sub_dirs = os.listdir(directory_path)
    for sub_dir in sub_dirs:
        path = directory_path + sub_dir + '/'
        for file in os.listdir(path):
            vuln = json.load(open(path + file, 'r'))
            
            cve_id = None
            if "CVE" in vuln["id"]:
                cve_id = vuln["id"]
            elif "aliases" in vuln:
                for alias in vuln["aliases"]:
                    if "CVE" in alias:
                        cve_id = alias
                        break
            
            if cve_id is not None:
                total_cve += 1
            else:
                total_noncve += 1
            
            description = ""
            if "summary" in vuln:
                description += (vuln["summary"] + " ")
            if "details" in vuln:
                description += (vuln["details"] + " ")

            package = set([_["package"]["name"] for _ in vuln["affected"]])

            if "references" not in vuln:
                continue
            gh_url = get_valid_gh_url(external_references=vuln["references"], description=description, software=package)

            if gh_url is None:
                continue

            if cve_id is not None:
                cve_url[cve_id] = copy.deepcopy(gh_url)
                cve_with_gh_url += 1
            else:
                noncve_url[vuln["id"]] = copy.deepcopy(gh_url)
                noncve_with_gh_url += 1
    
    print(f"total_cve: {total_cve}, cve_with_gh_url: {cve_with_gh_url}, ratio: {cve_with_gh_url / total_cve}")
    print(f"total_noncve: {total_noncve}, noncve_with_gh_url: {noncve_with_gh_url}, ratio: {noncve_with_gh_url} / {total_noncve}")

    with open("osv_gh_url_cve.json", 'w') as f:
        json.dump(cve_url, f, indent=4)
    with open("osv_gh_url_noncve.json", 'w') as f:
        json.dump(noncve_url, f, indent=4)


def merge_multisource_gh_url():
    nvd_gh_url = json.load(open("nvd_gh_url.json", 'r'))
    osv_gh_url_cve = json.load(open("osv_gh_url_cve.json", 'r'))

    artifacts = ["issue", "pull", "commit", "security_advisory", "release_tag", "change_log"]

    count_additional_url = 0
    count_additional_cve = 0

    merged_gh_url = {}
    for cve_id, gh_url in nvd_gh_url.items():
        if cve_id in osv_gh_url_cve:
            for a in artifacts:
                for url in osv_gh_url_cve[cve_id][a]:
                    if url not in gh_url[a]:
                        gh_url[a].append(url)
                        count_additional_url += 1
                        print(cve_id, a, url)
            del osv_gh_url_cve[cve_id]

        merged_gh_url[cve_id] = gh_url

    for cve_id, gh_url in osv_gh_url_cve.items():
        merged_gh_url[cve_id] = gh_url
        count_additional_cve += 1
        print(cve_id)

    print(count_additional_url, count_additional_cve)

    with open("merged_gh_url.json", 'w') as f:
        json.dump(merged_gh_url, f, indent=4)


def collect_cve_dict(directory_path):
    merged_data = dict()
    multi_cwe = []
    files = os.listdir(directory_path)
    files.sort()
    for f in files:
        file_path = directory_path + f
        data = json.load(open(file_path, 'r', encoding="utf-8"))
        for s in data["CVE_Items"]:
            cve_id = s["cve"]["CVE_data_meta"]["ID"]
            description, cwe_id, impact_v2, impact_v3 = [None]*4
            try:
                description = s["cve"]["description"]["description_data"][0]["value"]
                cwe_id = [_["value"] for _ in s["cve"]["problemtype"]["problemtype_data"][0]["description"]]
                if len(cwe_id) > 1:
                    multi_cwe.append(cve_id)
                
                impact_v2 = s["impact"]["baseMetricV2"]
                impact_v3 = s["impact"]["baseMetricV3"]
            except Exception:
                pass
            
            merged_data[cve_id] = {
                "cve_id": cve_id,
                "description": description,
                "cwe_id": cwe_id,
                "impact_cvssV2": impact_v2,
                "impact_cvssV3": impact_v3,
                "published_date": s["publishedDate"],
                "last_modified_date": s["lastModifiedDate"]
            }
            
    print(len(merged_data))
    print("multiple cwe:", len(multi_cwe))
    with open(DATA_PATH + "nvd_cve_data.json", 'w') as f:
        json.dump(merged_data, f, indent=4)
    

def collect_osv_dict(directory_path):
    cve_dict = {}
    noncve_dict = {}

    sub_dirs = os.listdir(directory_path)
    for sub_dir in sub_dirs:
        path = directory_path + sub_dir + '/'
        for file in os.listdir(path):
            vuln = json.load(open(path + file, 'r'))
            
            cve_id = None
            if "CVE" in vuln["id"]:
                cve_id = vuln["id"]
            elif "aliases" in vuln:
                for alias in vuln["aliases"]:
                    if "CVE" in alias:
                        cve_id = alias
                        break
            
            description, cwe_id, severity, impact_v3 = [None]*4
            
            description = ""
            if "summary" in vuln:
                description += (vuln["summary"] + " ")
            if "details" in vuln:
                description += (vuln["details"] + " ")
            
            if "database_specific" in vuln:
                if "cwe_ids" in vuln["database_specific"]:
                    cwe_id = vuln["database_specific"]["cwe_ids"]
                if "severity" in vuln["database_specific"]:
                    severity = vuln["database_specific"]["severity"]

            if "severity" in vuln:
                for s in vuln["severity"]:
                    if s["type"] == "CVSS_V3":
                        impact_v3 = s["score"]
            
            d = {
                "id": cve_id or vuln["id"],
                "description": description,
                "cwe_id": cwe_id,
                "severity": severity,
                "impact_cvssV3": impact_v3,
                "published_date": vuln["published"],
                "last_modified_date": vuln["modified"],
                "ecosystem": sub_dir,
            }
            
            if cve_id is not None:
                cve_dict[cve_id] = d
            else:
                noncve_dict[vuln["id"]] = d
    
    print("#OSV cve:", len(cve_dict))
    print("#OSV non-cve:", len(noncve_dict))

    with open(DATA_PATH + "osv_cve_data.json", 'w') as f:
        json.dump(cve_dict, f, indent=4)
    with open(DATA_PATH + "osv_noncve_data.json", 'w') as f:
        json.dump(noncve_dict, f, indent=4)


def merge_multisource_cve_dict():
    nvd_cve_dict = json.load(open(DATA_PATH + "nvd_cve_data.json", 'r'))
    osv_cve_dict = json.load(open(DATA_PATH + "osv_cve_data.json", 'r'))

    print("#OSV:", len(osv_cve_dict))

    count_nvd_osv = 0

    for cve_id in osv_cve_dict.keys():
        if cve_id in nvd_cve_dict:
            print(cve_id)
            count_nvd_osv += 1
            for attr in ["ecosystem", "published_date"]:
                nvd_cve_dict[cve_id][f"{attr}_osv"] = osv_cve_dict[cve_id][attr]
            
    print("#CVE is both NVD & OSV:", count_nvd_osv)

    with open(DATA_PATH + "merged_cve_data.json", 'w') as f:
        json.dump(nvd_cve_dict, f, indent=4)


def format_gh_url(gh_url, url_type="issue"):
    if url_type == "issue":
        gh_issue_pull = GH_ISSUE_PULL.match(gh_url)
        if gh_issue_pull is not None:
            user_repo = gh_issue_pull.group(2)
            id = gh_issue_pull.group(4)
            return f"https://github.com/{user_repo}/issues/{id}"
    elif url_type == "pull": 
        gh_issue_pull = GH_ISSUE_PULL.match(gh_url)
        if gh_issue_pull is not None:
            user_repo = gh_issue_pull.group(2)
            id = gh_issue_pull.group(4)
            return f"https://github.com/{user_repo}/pull/{id}"
    elif url_type == "commit":
        gh_commit = GH_COMMIT.match(gh_url)
        if gh_commit is not None:
            user_repo = gh_commit.group(2)
            id = gh_commit.group(4)
            return f"https://github.com/{user_repo}/commit/{id}"
    elif url_type == "security_advisory":
        gh_sec_adv = GH_SEC_ADVISORY.match(gh_url)
        ghsa_id = GHSA_ID.match(gh_url)
        cve_id = CVE_ID.match(gh_url)
        user_repo = None
        if gh_sec_adv is not None:
            if gh_sec_adv.group(2) is not None:
                user_repo = gh_sec_adv.group(2)[:-10]
            id = gh_sec_adv.group(3)
        elif (ghsa_id is not None) or (cve_id is not None):
            id = gh_url

        if user_repo is None:
            return id
        else:
            return f"https://github.com/{user_repo}/security/advisories/{id}"
    else:
        if gh_url[-1] in [',', '.']:
            gh_url = gh_url[:-1]
        return gh_url.split('#')[0]

    return None


def clean_update_gh_url(file_name):
    cleaned_cve_gh_url = {}

    cve_gh_url = json.load(open(f"{file_name}.json", 'r'))
    for cve_id, gh_url in cve_gh_url.items():
        print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), cve_id)
        cleaned_gh_url = {"issue": set(), "pull": set(), "commit": set(), "security_advisory": set(), "release_tag": set(), "change_log": set()} 
        for url_type, url_list in gh_url.items():
            for url in url_list:
                metadata = crawl_gh_artifact(url, "metadata")
                if metadata is not None:
                    if "html_url" in metadata and url != metadata["html_url"]:
                        print(url, metadata["html_url"])
                    
                    if url_type == "security_advisory":
                        ghsa_id = metadata["ghsaId"]
                        user_repo = None
                        gh_sec_adv = GH_SEC_ADVISORY.match(metadata["references"][0]["url"])
                        if gh_sec_adv is not None and gh_sec_adv.group(2) is not None:
                            user_repo = gh_sec_adv.group(2)[:-10]
                        if user_repo is None:
                            gh_sec_adv = GH_SEC_ADVISORY.match(url)
                            if gh_sec_adv is not None and gh_sec_adv.group(2) is not None:
                                user_repo = gh_sec_adv.group(2)[:-10]
                        
                        if user_repo is not None:
                            updated_url = f"https://github.com/{user_repo}/security/advisories/{ghsa_id}"
                            cleaned_gh_url["security_advisory"].add(updated_url)
                            if url != updated_url:
                                print(url, updated_url)
                        else:
                            cleaned_gh_url["security_advisory"].add(ghsa_id)
                            print(url, ghsa_id)
                    
                    elif url_type in ["issue", "pull"]:
                        url_type_tmp = "pull" if "pull_request" in metadata else "issue"
                        cleaned_gh_url[url_type_tmp].add(metadata["html_url"])
                    
                    else:
                        cleaned_gh_url[url_type].add(metadata["html_url"])
                else:
                    formatted_url = format_gh_url(gh_url=url, url_type=url_type)
                    if url != formatted_url:
                        print(url, formatted_url)
                    
                    if formatted_url is not None:
                        cleaned_gh_url[url_type].add(formatted_url)
        
        if any(len(_) for _ in cleaned_gh_url.values()):
            cleaned_cve_gh_url[cve_id] = {}
            for k, v in cleaned_gh_url.items(): 
                cleaned_cve_gh_url[cve_id][k] = list(v)

    with open(f"{file_name}_cleaned.json", 'w') as f:
        json.dump(cleaned_cve_gh_url, f, indent=4)


def extract_gh_url_from_text(text, software):
    candidate_url_list = []

    for match in MD_LINK.finditer(text):
        candidate_url_list.append({'url': match.group(2)})
    text = MD_LINK.sub(" ", text)

    for match in URL.finditer(text):
        candidate_url_list.append({'url': match.group(0)})
    text = URL.sub(" ", text)

    extracted_link = get_valid_gh_url(external_references=candidate_url_list, description="", software=software)

    extracted_id = {"issue_pull": [], "commit": [], "security_advisory": []}

    for match in CVE_ID.finditer(text):
        extracted_id["security_advisory"].append((None, match.group(0)))
    text = CVE_ID.sub(" ", text)
    for match in GHSA_ID.finditer(text):
        extracted_id["security_advisory"].append((None, match.group(0)))
    text = GHSA_ID.sub(" ", text)

    for match in ISSUE_ID.finditer(text):
        extracted_id["issue_pull"].append((match.group(1), match.group(2)))
    text = ISSUE_ID.sub(" ", text)
    
    for match in COMMIT_ID.finditer(text):
        user_repo = match.group(1)
        extracted_id["commit"].append((user_repo[:-1] if user_repo is not None else None, match.group(2)))

    return extracted_link, extracted_id


def check_extracted_id(user_repo, id, url_type, reference_date):
    if url_type == "issue_pull":
        gh_url = f"https://github.com/{user_repo}/issues/{id}"
    elif url_type == "commit":
        gh_url = f"https://github.com/{user_repo}/commit/{id}"
    elif url_type == "security_advisory":
        gh_url = id
    else:
        print("[ERROR: unsupported URL type in check_extracted_id]", url_type)
        return False, None

    metadata = crawl_gh_artifact(gh_url=gh_url, attr="metadata")
    if metadata is None:
        return False, None
    
    if url_type == "security_advisory":
        gh_sec_adv = GH_SEC_ADVISORY.match(metadata["references"][0]["url"])
        if gh_sec_adv is not None and gh_sec_adv.group(2) is not None:
            if gh_sec_adv.group(2)[:-10].lower() == user_repo.lower():
                return True, metadata["references"][0]["url"]
        return False, None

    try:
        created_at = metadata["created_at"] if url_type == "issue_pull" else metadata["committer"]["date"]
        created_at = fix_time(created_at)
    except Exception:
        return False, None

    if created_at <= reference_date:
        return True, metadata["html_url"]
    else:
        return False, None


def check_extracted_url(gh_url, url_type, reference_user_repo=None, force_same_repo=True, reference_date=None, force_before_time=False):
    reference_user_repo = reference_user_repo.lower()
    if url_type in ["issue_pull", "issue", "pull"]:
        gh_issue_pull = GH_ISSUE_PULL.match(gh_url)
        user_repo = gh_issue_pull.group(2)
    elif url_type == "commit":
        gh_commit = GH_COMMIT.match(gh_url)
        user_repo = gh_commit.group(2)
    elif url_type == "security_advisory":
        gh_sec_adv = GH_SEC_ADVISORY.match(gh_url)
        user_repo = gh_sec_adv.group(2)[:-10] if gh_sec_adv is not None else None
    else:
        print("[ERROR: unsupported URL type in check_extracted_url]", url_type, gh_url)
        return False
    
    if user_repo is not None and user_repo.lower() == reference_user_repo:
        return True
    else:
        return False


def complete_gh_url(file_name):
    cve_gh_url = json.load(open(f"{file_name}.json", 'r'))
    for cve_id, url_dict in cve_gh_url.items():
        print(f"========== {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {cve_id} ==========")

        if len(url_dict["issue"]) > 0:
            for gh_url in url_dict["issue"]:
                print(gh_url)
                reference_user_repo = GH_ISSUE_PULL.match(gh_url).group(2)
                
                artifact = crawl_gh_artifact(gh_url=gh_url, attr="timeline")

                if artifact is not None:
                    for event in artifact:
                        if event["event"] == "referenced":
                            if event["commit_id"] is not None:
                                commit_html_url = extract_commit_url_from_event(commit_id=event["commit_id"], commit_url=event["commit_url"])
                                if check_extracted_url(gh_url=commit_html_url, url_type="commit", reference_user_repo=reference_user_repo):
                                    if commit_html_url not in url_dict["commit"]:
                                        url_dict["commit"].append(commit_html_url)
                                        print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "[FIND]", cve_id, commit_html_url)
                            else:
                                print("[ERROR: reference not commit]", cve_id, gh_url)

                        elif event["event"] == "cross-referenced":
                            if event["source"]["type"] == "issue":
                                issue_html_url = event["source"]["issue"]["html_url"]
                                if check_extracted_url(gh_url=issue_html_url, url_type="issue_pull", reference_user_repo=reference_user_repo):
                                    save_issue_metadata_from_event_cr(event["source"]["issue"])
                                    url_type = "pull" if GH_ISSUE_PULL.match(issue_html_url).group(3) == "pull" else "issue"
                                    if issue_html_url not in url_dict[url_type]:
                                        url_dict[url_type].append(issue_html_url)
                                        print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "[FIND]", cve_id, issue_html_url)
                            else:
                                print("[ERROR: cross-reference not issue]", cve_id, gh_url)

                        elif event["event"] == "closed":
                            if event["commit_id"] is not None:
                                commit_html_url = extract_commit_url_from_event(commit_id=event["commit_id"], commit_url=event["commit_url"])
                                if check_extracted_url(gh_url=commit_html_url, url_type="commit", reference_user_repo=reference_user_repo):
                                    if commit_html_url not in url_dict["commit"]:
                                        url_dict["commit"].append(commit_html_url)
                                        print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "[FIND]", cve_id, commit_html_url)

                            break
        
        if len(url_dict["commit"]) > 0:
            for gh_url in url_dict["commit"]:
                print(gh_url)
                artifact= crawl_gh_artifact(gh_url=gh_url, attr="metadata")

                if artifact is not None:
                    user_repo = GH_URL.match(gh_url).group(2)
                    reference_date = fix_time(artifact["committer"]["date"])
                    extracted_link, extracted_id = extract_gh_url_from_text(text=artifact["message"], software=user_repo)
                    for url_type, id_list in extracted_id.items():
                        for ur_id in id_list:
                            if ur_id[0] is None:
                                flag, updated_url = check_extracted_id(user_repo=user_repo, id=ur_id[1], url_type=url_type, reference_date=reference_date)
                                if flag:
                                    url_type_tmp = url_type
                                    if url_type == "issue_pull":
                                        url_type_tmp = "pull" if GH_ISSUE_PULL.match(updated_url).group(3) == "pull" else "issue"
                                    if updated_url not in url_dict[url_type_tmp]:
                                        url_dict[url_type_tmp].append(updated_url)
                                        print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "[FIND]", cve_id, updated_url)
        
        if len(url_dict["pull"]) > 0:
            for gh_url in url_dict["pull"]:
                print(gh_url)
                artifact = crawl_gh_artifact(gh_url=gh_url, attr="metadata")
                commits = crawl_gh_artifact(gh_url=gh_url, attr="commits")

                if artifact is not None:
                    user_repo = GH_URL.match(gh_url).group(2)
                    reference_date = fix_time(artifact["created_at"])
                    text = (artifact["title"] or "") + " " + (artifact["body"] or "")
                    extracted_link, extracted_id = extract_gh_url_from_text(text=text, software=user_repo)
                    for url_type, id_list in extracted_id.items():
                        for ur_id in id_list:
                            if ur_id[0] is None:
                                flag, updated_url = check_extracted_id(user_repo=user_repo, id=ur_id[1], url_type=url_type, reference_date=reference_date)
                                if flag:
                                    url_type_tmp = url_type
                                    if url_type == "issue_pull":
                                        url_type_tmp = "pull" if GH_ISSUE_PULL.match(updated_url).group(3) == "pull" else "issue"
                                    if updated_url not in url_dict[url_type_tmp]:
                                        url_dict[url_type_tmp].append(updated_url)
                                        print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "[FIND]", cve_id, updated_url)

                if commits is not None:
                    for c in commits:
                        commit_html_url = c["html_url"]
                        if commit_html_url not in url_dict["commit"]:
                            url_dict["commit"].append(commit_html_url)
                            print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "[FIND]", cve_id, commit_html_url)
        
        if len(url_dict["security_advisory"]) > 0:
            for gh_url in url_dict["security_advisory"]:
                print(gh_url)
                user_repo = None
                gh_sec_adv = GH_SEC_ADVISORY.match(gh_url)
                if gh_sec_adv is not None and gh_sec_adv.group(2) is not None:
                        user_repo = gh_sec_adv.group(2)[:-10]

                artifact = crawl_gh_artifact(gh_url=gh_url, attr="metadata")
                package = None

                if artifact is not None:
                    if user_repo is None:
                        gh_sec_adv = GH_SEC_ADVISORY.match(artifact["references"][0]["url"])
                        if gh_sec_adv is not None and gh_sec_adv.group(2) is not None:
                            user_repo = gh_sec_adv.group(2)[:-10]

                    if user_repo is not None:
                        package = user_repo
                    else:
                        vuln_nodes = artifact["vulnerabilities"]["nodes"]

                        if len(vuln_nodes) > 0:
                            package = vuln_nodes[0]["package"]["name"]
                        if package is not None:
                            gh_package = GH_PACKAGE.match(package)
                            if gh_package is not None:
                                package = gh_package.group(2)
                                user_repo = package
   
                    extracted_gh_url = get_valid_gh_url(external_references=artifact["references"], software=package, description="")
                    if extracted_gh_url is not None:
                        selected_extracted_gh_url = {}
                        for url_type in ["issue", "pull", "commit", "security_advisory"]:
                            selected_extracted_gh_url[url_type] = extracted_gh_url[url_type]
                        if user_repo is not None:
                            for url_type, url_list in selected_extracted_gh_url.items():
                                for url in url_list:
                                    if check_extracted_url(gh_url=url, url_type=url_type, reference_user_repo=user_repo):
                                        if url not in url_dict[url_type]:
                                            url_dict[url_type].append(url)
                                            print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "[FIND]", cve_id, url)

    with open(f"{file_name}_completed.json", 'w') as f:
        json.dump(cve_gh_url, f, indent=4)


def prepare_artifact(file_name):
    cve_gh_url = json.load(open(f"{file_name}.json", 'r'))

    for cve_id, url_dict in cve_gh_url.items():
        print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), cve_id)
        for url_type, url_list in url_dict.items():
            if url_type in ["issue", "pull", "commit"]:
                for url in url_list:
                    gh_repo = GH_URL.match(url).group(2)
                    artifact = crawl_gh_repo_info(gh_repo=gh_repo)
                    if artifact is None:
                        print("[NONE]", "repo_info", cve_id, url)

                    artifact = crawl_gh_artifact(gh_url=url, attr="metadata")
                    if artifact is None:
                        print("[NONE]", "metadata", cve_id, url)
                    
                    if url_type in ["issue", "pull"]:
                        artifact = crawl_gh_artifact(gh_url=url, attr="timeline")
                        if artifact is None:
                            print("[NONE]", "timeline", cve_id, url)
                    elif url_type == "commit":
                        artifact = crawl_gh_artifact(gh_url=url, attr="diff")
                        if artifact is None:
                            print("[NONE]", "diff", cve_id, url)


def prepare_repo_last_commit(file_name):
    repo_info = json.load(open(DATA_PATH + f"{file_name}.json", 'r'))
    for k, v in repo_info.items():
        print(k)
        gh_repo = v["full_name"]
        save_path = DATA_PATH + "repo_info/" + f"{gh_repo.lower().replace('/', '.')}.json"
        if os.path.exists(save_path):
            repo_info = json.load(open(save_path, 'r'))
            artifact = crawl_gh_repo_last_commit(gh_repo=gh_repo, default_branch=repo_info["default_branch"])
            if artifact is None:
                print("[NONE]", "repo_last_commit", gh_repo)


def prepare_pull_extra_info(file_name):
    dataset = json.load(open(DATA_PATH + f"{file_name}.json", 'r'))
    for vuln in dataset:
        for pull in vuln["pull_list"]:
            pull_extra_info = crawl_gh_pull_extra_info(repo=pull["repo"], pull_id=pull["id"])
            
            if pull_extra_info is None:
                print("[NONE]", "pull_extra_info", pull["repo"], pull["id"])
            
            for attr in ["isCrossRepository"]:
                pull[attr] = pull_extra_info[attr] if pull_extra_info is not None else None
    
    return dataset


def generate_repo_info(directory, directory_last_commit=None):
    selected_attr = ["name", "full_name", "private", "description", "fork", "stargazers_count", "watchers_count", "language", "forks_count", "archived", "disabled", "open_issues_count", "topics", "network_count", "subscribers_count"]

    repo_info = {}

    for f in os.listdir(directory):
        info = json.load(open(directory + f))
        repo = info["full_name"].lower()
        repo_info[repo] = {}
        for attr in selected_attr:
            repo_info[repo][attr] = info[attr]
        
        if directory_last_commit is not None:
            if os.path.exists(directory_last_commit + f):
                last_commit = json.load(open(directory_last_commit + f))
                repo_info[repo]["last_commit"] = last_commit["commit"]["commit"]["committer"]["date"]
                
    with open(DATA_PATH + "repo_info.json", 'w') as f:
        json.dump(repo_info, f, indent=4)


def generate_dataset(file_name):
    cve_gh_url = json.load(open(f"{file_name}.json", 'r'))
    
    dataset = []

    for cve_id, url_dict in cve_gh_url.items():
        print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), cve_id)
        item = {"cve_id": cve_id}
        item["issue_list"] = []
        item["pull_list"] = []
        item["commit_list"] = []

        for url in url_dict['issue'] + url_dict["pull"]:
            gh_issue_pull = GH_ISSUE_PULL.match(url)
            repo = gh_issue_pull.group(2)
            issue_pull_id = gh_issue_pull.group(4)
            
            ir_metadata_path = DATA_PATH + "issues_metadata/" + f"{repo.lower().replace('/', '.')}.{issue_pull_id}.json"
            ir_timeline_path = DATA_PATH + "issues_timeline/" + f"{repo.lower().replace('/', '.')}.{issue_pull_id}.json"

            ir_metadata_exist = os.path.exists(ir_metadata_path)
            ir_timeline_exist = os.path.exists(ir_timeline_path)

            if (ir_metadata_exist + ir_timeline_exist) == 1:
                if not ir_metadata_exist:
                    print("[SINGLE]", "metadata", url)
                if not ir_timeline_exist:
                    print("[SINGLE]", "timeline", url)
                
            if (ir_metadata_exist + ir_timeline_exist) == 2:
                ir_metadata = json.load(open(ir_metadata_path, 'r'))
                ir_timeline = json.load(open(ir_timeline_path, 'r'))

                is_pull = True if "pull_request" in ir_metadata else False

                ir = {"repo": repo, "id": ir_metadata["number"]}

                selected_attr = ["created_at", "updated_at", "closed_at", "title", "body", "author_association", "comments", "state", "state_reason", "locked", "active_lock_reason"]
                for attr in selected_attr:
                    ir[attr] = ir_metadata[attr]
                
                user_attr = ["login", "id", "type"]
                for attr in user_attr:
                    ir[f"user_{attr}"] = ir_metadata["user"][attr]
                
                ir["milestoned"] = True if ir_metadata["milestone"] is not None else False
                
                ir["labels"] = [{"name": _["name"], "description": _["description"], "default": _["default"]} for _ in ir_metadata["labels"]]

                if is_pull:
                    ir["merged_at"] = ir_metadata["pull_request"]["merged_at"]
                    pull_commits_path = DATA_PATH + "pulls_commits/" + f"{repo.lower().replace('/', '.')}.{issue_pull_id}.json"
                    ir["pull_commits"] = []
                    if os.path.exists(pull_commits_path):
                        pull_commits = json.load(open(pull_commits_path, 'r'))
                        for c in pull_commits:
                            ir["pull_commits"].append({"sha": c["sha"], "committer_date": c["commit"]["committer"]["date"]})
                    else:
                        raise ValueError("pull_commits not exist")

                ir["events"] = []
                for event in ir_timeline:

                    e = {"event": event["event"]}
                    if "created_at" in event:
                        e["created_at"] = event["created_at"]
                    if "actor" in event and event["actor"] is not None:
                        for attr in ["login", "id", "type"]:
                            e[f"actor_{attr}"] = event["actor"][attr]

                    if event["event"] == "commented":
                        for attr in ["updated_at", "body", "author_association"]:
                            e[attr] = event[attr]
                    
                    elif event["event"] == "cross-referenced":
                        for attr in ["updated_at"]:
                            e[attr] = event[attr]
                        e["type"] = event["source"]["type"]
                        if e["type"] == "issue":
                            if "pull_request" in event["source"]["issue"]:
                                e["type"] == "pull"

                    elif event["event"] in ["labeled", "unlabeled", "assigned", "renamed", "locked", "closed", "reopened", "milestoned", "unmilestoned", "referenced", "mentioned", "subscribed", "unsubscribed", "merged", "reviewed"]:
                        for attr in ["commit_id"]:
                            e[attr] = event[attr]
                        
                        if event["event"] in ["labeled", "unlabeled"]:
                            e["label"] = event["label"]["name"]
                        elif event["event"] in ["closed", "reopened"]:
                            e["state_reason"] = event["state_reason"]
                        elif event["event"] in ["milestoned", "unmilestoned"]:
                            e["title"] = event["milestone"]["title"]
                        elif event["event"] == "assigned":
                            if event["assignee"] is not None:
                                for attr in ["login", "id", "type"]:
                                    e[f"assignee_{attr}"] = event["assignee"][attr]
                        elif event["event"] == "locked":
                            e["lock_reason"] = event["lock_reason"]
                        elif event["event"] == "renamed":
                            e["from"] = event["rename"]["from"]
                            e["to"] = event["rename"]["to"]
                        elif event["event"] == "reviewed":
                            e["user"] = event["user"]["login"] if event["user"] is not None else None
                            for attr in ["submitted_at", "author_association"]:
                                e[attr] = event[attr]
                    elif event["event"] == "committed":
                        for attr in ["sha", "message"]:
                            e[attr] = event[attr]
                        for attr in ["name", "date"]:
                            e[f"author_{attr}"] = event["author"][attr]
                            e[f"committer_{attr}"] = event["committer"][attr]
                    else:
                        pass
                    
                    ir["events"].append(e)

                if is_pull:
                    item["pull_list"].append(ir)
                else:
                    item["issue_list"].append(ir)
        
        for url in url_dict["commit"]:
            gh_commit = GH_COMMIT.match(url)
            repo = gh_commit.group(2)
            commit_id = gh_commit.group(4)

            commit_metadata_path = DATA_PATH + "commits_metadata/" + f"{repo.replace('/', '.').lower()}.{commit_id}.json"
            if os.path.exists(commit_metadata_path):
                commit_metadata = json.load(open(commit_metadata_path, 'r'))

                patch = {"repo": repo}
                for attr in ["sha", "message"]:
                    patch[attr] = commit_metadata[attr]
                for attr in ["name", "date"]:
                    patch[f"author_{attr}"] = commit_metadata["author"][attr]
                    patch[f"committer_{attr}"] = commit_metadata["committer"][attr]
                patch["parents"] = [_["sha"] for _ in commit_metadata["parents"]]
                if len(patch["parents"]) > 1:
                    continue

                item["commit_list"].append(patch)

        if (len(item["issue_list"]) + len(item["pull_list"]) + len(item["commit_list"])) > 0:
            item["issue_list"].sort(key=lambda x:x["created_at"])
            item["pull_list"].sort(key=lambda x:x["created_at"])
            item["commit_list"].sort(key=lambda x:x["committer_date"])
            dataset.append(item)

    with open(DATA_PATH + "artifact_data.json", 'w') as f:
        json.dump(dataset, f, indent=4)


def analyze_log_file(file_name):
    log_file = open(file_name, 'r')

    invalid_urls = INVALID_URL or []
    mappings = MAPPINGS or {}

    count_find = 0
    count_none = 0

    print("#invalid URLs:", len(invalid_urls))
    print("#mappings:", len(mappings))
    for line in log_file.readlines():
        if line[:3] in ["404", "410", "409"]:
            url = re.search(r"https?://\S+", line).group(0)
            if "graphql" in url:
                continue
            if url not in invalid_urls:
                invalid_urls.append(url)
        elif "[MAPPING]" in line:
            _, old, new = line.split(' ')
            if old not in mappings:
                new = new[:-1]
                if new == "None":
                    new = None
                mappings[old] = new
        elif "ERROR" in line:
            print(line)
        elif "[FIND]" in line:
            count_find += 1
        elif "[NONE]" in line:
            count_none += 1
        elif "[SINGLE]" in line:
            print(line)
    
    print("#count find:", count_find)
    print("#count none:", count_none)

    print("#invalid URLs:", len(invalid_urls))
    with open("invalid_urls.json", 'w') as f:
        json.dump(invalid_urls, f, indent=4)
    
    print("#mappings:", len(mappings))
    with open("mappings.json", 'w') as f:
        json.dump(mappings, f, indent=4)


# regex expressions
GH_URL = re.compile(r"http(s?)://github.com/([^/]+/[^/]+)/\S*\s*")
GH_ISSUE_PULL = re.compile(r"http(s?)://github.com/([^/]+/[^/]+)/(issues|pull)/([0-9]+)\S*\s*")
GH_COMMIT = re.compile(r"http(s?)://github.com/([^/]+/[^/]+)/(commit|pull/[0-9]+/commits)/([0-9a-f]{5,40})\S*\s*")
GH_COMMIT_API = re.compile(r"http(s?)://api.github.com/repos/([^/]+/[^/]+)/commits/([0-9a-f]{5,40})")
GH_SEC_ADVISORY = re.compile(r"http(s?)://github.com/([^/]+/[^/]+/security/){0,1}advisories/(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})\S*\s*")
GHSA_ID = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}")
CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]+")

GH_PACKAGE = re.compile(r'(github.com/){0,1}([^/]+/[^/]+)')

ISSUE_ID = re.compile(r'([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+){0,1}#([0-9]+)')
COMMIT_ID = re.compile(r'([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@){0,1}([0-9a-f]{7,40})')

MD_LINK = re.compile(r'\[([^\[\]]*)\]\((.*?)\)')
URL = re.compile('((http|https)://)[-a-zA-Z0-9@:%._\\+~#?&//=]{2,256}\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%._\\+~#?&//=]*)')

CPE = re.compile(r'cpe:2.3:[a-z]:([^:]+:[^:]+):\S+?,')
# black list and white list of repositoris for GitHub link extraction
INVALID_USER_REPO = re.compile(r'cve|(\b|[^a-z])poc(s?)(\b|[^a-z])|(\b|[^a-z])xss(\b|[^a-z])|(\b|[^a-z])vul(n?)(s?)(\b|[^a-z])|disclosure|disclose|security|research|vulnerability|vulnerabilities|arbitrary|exploit(s?)|advisory|advisories', flags=re.I)
BLACK_LIST = ["security-research", "iot_hunter", "imagemlt", "cq674350529", "ifmacedo", "mikeccltt", "bug_report", "mikeccltt", "bugbounty", "emreovunc", "asjdf", "pwnninja", "maybe-why-not", "aliasrobotics"]
WHITE_LIST = ["democritus-project", "wanghaiwei"]

INVALID_URL = json.load(open("invalid_urls.json", 'r'))  # empty URLs, build from log file
MAPPINGS = json.load(open("mappings.json", 'r'))  # mappings from prefix of commit hash to full commit hash

DATA_PATH = "./data/"

if __name__ == '__main__':
    # ========== STEP1 =========
    nvd_path = DATA_PATH + "NVD/"
    # collect_nvd_gh_url(directory_path=nvd_path)
    # collect_cve_dict(directory_path=nvd_path)

    # osv_path = DATA_PATH + "OSV/"
    # collect_osv_gh_url(directory_path=osv_path)
    # collect_osv_dict(directory_path=osv_path)

    # ========== STEP2 =========
    # merge_multisource_gh_url()
    # clean_update_gh_url(file_name="merged_gh_url")

    # merge_multisource_cve_dict()

    # ========== STEP3 =========
    # complete_gh_url(file_name="merged_gh_url_cleaned")

    # clean_update_gh_url(file_name="merged_gh_url_cleaned_completed")

    # NOTE we iterate STEP3 until the closure

    # ========== STEP4 =========
    # prepare_artifact(file_name="merged_gh_url_final")

    # ========== STEP5 =========
    # generate_dataset(file_name="merged_gh_url_final")