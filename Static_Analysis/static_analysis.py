#!/usr/bin/python3
# _*_ coding: utf-8 _*_
#
# Copyright (C) 2026 - 2026 Fino, Inc. All Rights Reserved 
#
# @Time    : 2026/3/30 16:46
# @Author  : Fino
# @File    : static_analysis.py
# @IDE     : PyCharm
import os
import shutil
import chardet
from pathlib import Path

import scubatrace

# Initialize a ScubaTrace Project
# language can be set to one of the following:
# scubatrace.language.[C, JAVA, PYTHON, JAVASCRIPT, GO, RUST, RUBY, PHP, CSHARP, SWIFT]
# D:\Desktop\Localization_Repo_1\CVE-2020-8112\uclouvain\openjpeg\src\bin\jp2
root_path = '/mnt/d/Desktop/Localization_Repo/CVE-2020-15930/laurent22/joplin'
# 对root_path目录及子目录下所有文件全部重新进行utf-8编码
# 常见文本文件扩展名（可根据需要扩展）
TEXT_EXTENSIONS = {
    '.c', '.h', '.cpp', '.hpp', '.cc', '.cxx', '.java', '.py', '.sh', '.txt',
    '.md', '.rst', '.xml', '.json', '.yml', '.yaml', '.ini', '.cfg', '.csv',
    '.html', '.htm', '.js', '.css', '.php', '.rb', '.go', '.rs', '.toml',
    '.cmake', '.mk', '.gradle', '.properties', '.sql', '.pl', '.pm'
}


def is_text_file(file_path):
    """根据扩展名判断是否可能是文本文件"""
    return file_path.suffix.lower() in TEXT_EXTENSIONS


def convert_to_utf8(file_path):
    try:
        # 读取原始内容并检测编码
        with open(file_path, 'rb') as f:
            raw_data = f.read()

        if not raw_data:
            return  # 空文件跳过

        detected = chardet.detect(raw_data)
        encoding = detected['encoding']
        confidence = detected['confidence']

        # 如果已经是 UTF-8（或高置信度），跳过
        if encoding and 'utf' in encoding.lower() and confidence > 0.9:
            return

        # 尝试解码
        if encoding is None:
            encoding = 'utf-8'  # fallback

        try:
            text = raw_data.decode(encoding, errors='replace')
        except (UnicodeDecodeError, LookupError):
            # 如果解码失败，尝试 latin-1（不会失败）
            text = raw_data.decode('latin-1', errors='replace')

        # 写回 UTF-8
        backup_path = file_path.with_suffix(file_path.suffix + '.bak')
        shutil.copy2(file_path, backup_path)  # 备份原文件
        with open(file_path, 'w', encoding='utf-8', newline='') as f:
            f.write(text)

        print(f"✅ Converted: {file_path} (from {encoding})")

    except Exception as e:
        print(f"❌ Failed to process {file_path}: {e}")


root = Path(root_path)
if not root.exists():
    print("Root path does not exist!")

for file_path in root.rglob('*'):
    if file_path.is_file() and is_text_file(file_path):
        convert_to_utf8(file_path)
project = scubatrace.Project.create(root_path, language=scubatrace.language.JAVASCRIPT)
print(project)
project.export_callgraph(output_path='./')
print(project.callgraph)
