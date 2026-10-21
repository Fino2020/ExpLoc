#!/usr/bin/python3
# _*_ coding: utf-8 _*_
#
# Copyright (C) 2026 - 2026 Fino, Inc. All Rights Reserved 
#
# @Time    : 2026/3/11 15:25
# @Author  : Fino
# @File    : issue_history_generation.py
# @IDE     : PyCharm
import json
import os
import subprocess
from multiprocessing import Pool, cpu_count
from functools import partial
import time


def process_vulnerability(vuln, save_dir, max_entries):
    """处理单个漏洞数据"""
    repo = vuln['issue_list'][0]['repo']
    filename = repo.replace('/', '_')
    save_path = os.path.join(save_dir, filename + '.json')

    # 检查文件是否存在且非空
    if not os.path.exists(save_path) or os.path.getsize(save_path) == 0:
        print(f"Processing: {save_path}")
        get_issue_cmd = f"gh issue list --repo {repo} --state all --limit {max_entries} --json assignees,author,body,closed,closedAt,closedByPullRequestsReferences,comments,createdAt,id,isPinned,labels,milestone,number,projectItems,reactionGroups,state,stateReason,title,updatedAt,url 2>/dev/null | python -m json.tool > {save_path}"

        try:
            result = subprocess.run(get_issue_cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Error processing {repo}: {result.stderr}")
                return False
            return True
        except Exception as e:
            print(f"Exception occurred while processing {repo}: {str(e)}")
            return False
    else:
        print(f"Skipping (already exists): {save_path}")
        return True


def main():
    save_dir = './history'
    max_entries = 5000

    # 创建保存目录
    os.makedirs(save_dir, exist_ok=True)

    # 加载数据集
    with open('../Generate_IssueReport_File/dataset_with_changed_files.json', 'r', encoding='utf-8') as f:
        load = json.load(f)

    # 获取CPU核心数并创建进程池
    num_processes = min(cpu_count(), len(load))  # 不超过漏洞数量
    print(f"Using {num_processes} processes for processing {len(load)} vulnerabilities")

    # 创建处理函数的偏函数
    process_func = partial(process_vulnerability, save_dir=save_dir, max_entries=max_entries)

    # 使用进程池并行处理
    with Pool(processes=num_processes) as pool:
        results = pool.map(process_func, load)

    # 统计结果
    success_count = sum(results)
    print(
        f"\nCompleted processing {len(load)} vulnerabilities: {success_count} succeeded, {len(load) - success_count} failed"
    )


if __name__ == '__main__':
    main()
