#!/usr/bin/python3
# _*_ coding: utf-8 _*_
#
# Copyright (C) 2026 - 2026 Fino, Inc. All Rights Reserved 
#
# @Time    : 2026/5/20 9:08
# @Author  : Fino
# @File    : CPG_ScubaTrace.py
# @IDE     : PyCharm
import scubatrace

# joern_config = scubatrace.JoernConfig(
#     cpg_output_dir="./build/joern-cpg",
#     overwrite=True,
#     Language=scubatrace.language.C,
# )
#
# project_with_joern = scubatrace.Project.create(
#     "/mnt/e/Desktop/Localization_Repo/Localization_Repo/CVE-2015-1862/abrt/abrt",
#     language=scubatrace.language.C,
#     joern_config=joern_config,
# )
#
# cpg = project_with_joern.cpg
import scubatrace

# Initialize a ScubaTrace Project
# language can be set to one of the following:
# scubatrace.language.[C, JAVA, PYTHON, JAVASCRIPT, GO, RUST, RUBY, PHP, CSHARP, SWIFT]
project = scubatrace.Project.create("path/to/your/codebase", language=scubatrace.language.C)
# Get a file from the project
file = project.files["relative/path/to/your/file.c"]

# Get a function from the file
function = file.functions[0]
print(f"Function Name: {function.name}")
print(f"Source Code: {function.text}")

# Get the function's callers and print their names and callsites
callers = function.callers
for caller, callsites in callers.items():
    print(f"Caller: {caller.name}")
    for callsite in callsites:
        print(f"  Callsite: {callsite.text}")

# Get the first statement in file line
statement = file.statements_by_line(10)[0]

# Get the first variable in statement
variable = statement.variables[0]
print(f"Variable: {variable.name}")

# Get tree-sitter node in a file/function/statement
file_node = file.node
function_node = function.node
statement_node = statement.node
