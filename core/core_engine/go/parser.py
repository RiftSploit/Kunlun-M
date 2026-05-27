#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Go AST Parser — Go 反向污点追踪引擎
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Go 语言静态分析引擎，支持正则匹配和 AST 污点追踪。

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""
import re
import traceback
import ast
import tokenize
import io

from utils.log import logger
from core.pretreatment import ast_object as _ast_object_singleton
from core.core_engine.trace_cache import TraceCache
from core.core_engine.go.builtin_knowledge import lookup as lookup_builtin

scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []

# 追踪缓存 + 内置知识库
_trace_cache = TraceCache("go")

# Go 特有的可控输入源
GO_CONTROLLED_SOURCES = [
    "r.URL.Query()", "r.FormValue", "r.PostFormValue",
    "r.Header.Get", "r.Header.Get",
    "r.Body", "r.URL.Path", "r.URL.RawPath",
    "r.Host", "r.RemoteAddr", "r.UserAgent",
    "r.Referer", "r.Method",
    "os.Args", "os.Getenv",
    "flag.String", "flag.Int", "flag.Bool",
    "gin.Default", "c.Query", "c.Param", "c.PostForm",
    "c.ShouldBind", "c.ShouldBindJSON", "c.ShouldBindQuery",
    "c.GetHeader", "c.GetCookie",
    "echo.QueryParams", "echo.FormValue",
    "fiber.Query", "fiber.Params", "fiber.Body",
    "beego.Input", "beego.GetString", "beego.GetStrings",
]

# Go 特有的敏感函数列表
GO_SENSITIVE_SINKS = [
    "exec.Command", "exec.CommandContext",
    "os.Open", "os.Create", "os.Remove", "os.RemoveAll",
    "ioutil.ReadFile", "ioutil.WriteFile",
    "os.ReadFile", "os.WriteFile",
    "http.Get", "http.Post", "http.NewRequest",
    "sql.Open", "db.Query", "db.QueryRow", "db.Exec",
    "db.Prepare", "tx.Exec", "tx.Query",
    "template.HTML", "template.JS", "template.CSS",
    "template.URL", "template.HTMLAttr",
    "fmt.Sprintf", "fmt.Fprintf", "fmt.Printf",
    "log.Printf", "log.Fatalf",
    "net.Dial", "net.Listen",
    "xml.NewDecoder", "json.Unmarshal",
    "yaml.Unmarshal", "toml.Decode",
    "filepath.Join", "filepath.Abs",
    "regexp.Compile", "regexp.MustCompile",
]


def _go_line_to_text(file_path, lineno):
    """从源文件读取指定行的文本"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            if 1 <= lineno <= len(lines):
                return lines[lineno - 1].strip()
    except Exception:
        pass
    return ""


def _extract_function_name(line_text):
    """从 Go 代码行提取函数调用名"""
    if not line_text:
        return None

    # 匹配常见 Go 函数调用模式
    # 如: exec.Command(...), os.Open(...), r.URL.Query().Get(...)
    patterns = [
        r'(\w+(?:\.\w+)+)\s*\(',  # pkg.Func( or obj.Method(
        r'(\w+)\s*\(',              # Func(
    ]

    for pattern in patterns:
        m = re.search(pattern, line_text)
        if m:
            return m.group(1)
    return None


def _is_controllable_source(expr_str, controlled_params=None):
    """检查表达式是否是可控输入源"""
    if controlled_params is None:
        controlled_params = is_controlled_params

    for cp in controlled_params:
        if cp in expr_str:
            return True

    for src in GO_CONTROLLED_SOURCES:
        if src in expr_str:
            return True

    return False


def _is_repair_function(expr_str, repair_functions=None):
    """检查表达式是否包含修复函数"""
    if repair_functions is None:
        repair_functions = is_repair_functions

    for rf in repair_functions:
        if rf in expr_str:
            return True
    return False


def _trace_variable_in_lines(file_path, var_name, from_line, to_line,
                              repair_functions=None, controlled_params=None,
                              depth=0, max_depth=5):
    """
    在指定行范围内追踪变量的数据流

    从 from_line 向上扫描到 to_line，查找 var_name 的赋值和来源。

    返回值:
        1  — 可控（污点到达用户输入源）
        2  — 已修复（经过修复函数处理）
        3  — 未确认
        -1 — 不可控
    """
    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    if depth > max_depth:
        return -1

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return -1

    if not lines:
        return -1

    # 限制扫描范围
    start = max(0, to_line - 1)
    end = min(len(lines), from_line)

    # 从 vul_lineno 向上扫描
    for i in range(start, max(-1, start - 200), -1):
        line = lines[i].strip()

        # 跳过空行和注释
        if not line or line.startswith('//') or line.startswith('/*'):
            continue

        # 检查赋值语句: var_name = expr 或 var_name := expr
        assign_patterns = [
            r'{}\s*:?=\s*(.+)'.format(re.escape(var_name)),
            r'var\s+{}\s+\w+\s*=\s*(.+)'.format(re.escape(var_name)),
            r'{}\s*,\s*\w+\s*:?=\s*(.+)'.format(re.escape(var_name)),
        ]

        for pattern in assign_patterns:
            m = re.search(pattern, line)
            if m:
                expr = m.group(1).strip()

                # 检查赋值来源是否可控
                if _is_controllable_source(expr, controlled_params):
                    logger.debug("[AST][Go] Variable {} is controllable from: {}".format(var_name, expr))
                    return 1

                # 检查是否经过修复函数
                if _is_repair_function(expr, repair_functions):
                    logger.debug("[AST][Go] Variable {} is repaired by: {}".format(var_name, expr))
                    return 2

                # 检查内置知识库
                func_name = _extract_function_name(expr)
                if func_name:
                    knowledge = lookup_builtin(func_name)
                    if knowledge:
                        if knowledge.get("safe"):
                            logger.debug("[AST][Go] Variable {} safe function: {}".format(var_name, func_name))
                            return -1
                        elif knowledge.get("passthrough"):
                            # 透传函数，继续追踪参数
                            for arg_idx in knowledge["passthrough"]:
                                # 简单提取第一个参数
                                arg_match = re.search(r'\(([^,)]+)', expr)
                                if arg_match:
                                    arg_name = arg_match.group(1).strip()
                                    if arg_name and arg_name != var_name:
                                        result = _trace_variable_in_lines(
                                            file_path, arg_name, i, to_line,
                                            repair_functions, controlled_params,
                                            depth + 1, max_depth
                                        )
                                        if result in (1, 2):
                                            return result

                # 检查函数调用中的参数透传
                # 如: result := someFunc(userInput)
                func_call = re.search(r'(\w+(?:\.\w+)*)\s*\((.+)\)', expr)
                if func_call:
                    func = func_call.group(1)
                    args_str = func_call.group(2)

                    # 检查内置知识库
                    knowledge = lookup_builtin(func)
                    if knowledge:
                        if knowledge.get("safe"):
                            return -1
                        elif knowledge.get("passthrough"):
                            # 透传，追踪参数
                            args = [a.strip() for a in args_str.split(',')]
                            for arg_idx in knowledge["passthrough"]:
                                if arg_idx < len(args):
                                    arg = args[arg_idx]
                                    if arg == var_name:
                                        continue
                                    result = _trace_variable_in_lines(
                                        file_path, arg, i, to_line,
                                        repair_functions, controlled_params,
                                        depth + 1, max_depth
                                    )
                                    if result in (1, 2):
                                        return result

                # 简单赋值 a = b，追踪 b
                simple_var = re.match(r'^(\w+)$', expr)
                if simple_var and simple_var.group(1) != var_name:
                    result = _trace_variable_in_lines(
                        file_path, simple_var.group(1), i, to_line,
                        repair_functions, controlled_params,
                        depth + 1, max_depth
                    )
                    if result in (1, 2):
                        return result

    return -1


def scan_parser(rule_match, vul_lineno, file_path,
                repair_functions=None, controlled_params=None,
                svid=None, is_config_vuln=False):
    """
    Go AST 扫描入口

    :param rule_match: 规则匹配的函数名列表
    :param vul_lineno: 漏洞行号
    :param file_path: 文件路径
    :param repair_functions: 修复函数列表
    :param controlled_params: 可控参数列表
    :param svid: 规则编号
    :param is_config_vuln: 是否配置型漏洞
    :return: 扫描结果列表
    """
    if repair_functions is None:
        repair_functions = []
    if controlled_params is None:
        controlled_params = []

    results = []

    try:
        vul_lineno = int(vul_lineno)
    except (ValueError, TypeError):
        logger.warning("[AST][Go] Invalid vul_lineno: {}".format(vul_lineno))
        return results

    # 获取源码行
    line_text = _go_line_to_text(file_path, vul_lineno)
    if not line_text:
        logger.warning("[AST][Go] Cannot read line {} from {}".format(vul_lineno, file_path))
        return results

    logger.debug("[AST][Go] Scanning line {}: {}".format(vul_lineno, line_text))

    # 检查行中是否包含规则匹配的函数
    matched_func = None
    for func in rule_match:
        # 清理正则转义
        clean_func = func.replace('\\.', '.').replace('\\(', '(').replace('\\)', ')')
        if clean_func in line_text:
            matched_func = clean_func
            break

    if not matched_func:
        # 模糊匹配
        for func in rule_match:
            clean_func = func.replace('\\.', '.').replace('\\(', '(').replace('\\)', ')')
            parts = clean_func.split('.')
            if any(p in line_text for p in parts if len(p) > 2):
                matched_func = clean_func
                break

    if not matched_func:
        logger.debug("[AST][Go] No matching function found in line")
        return results

    # 提取函数参数中的变量名
    # 简单模式：提取函数调用的第一个参数
    func_pattern = r'{}\s*\(([^)]*)\)'.format(re.escape(matched_func))
    func_match = re.search(func_pattern, line_text)

    if not func_match:
        # 尝试不带转义的模式
        func_pattern = r'{}\s*\(([^)]*)\)'.format(re.escape(matched_func.split('.')[-1]))
        func_match = re.search(func_pattern, line_text)

    if not func_match:
        # 尝试更宽泛的匹配
        func_pattern = r'{}\s*\((.+?)\)'.format(re.escape(matched_func.split('.')[-1]))
        func_match = re.search(func_pattern, line_text)

    if func_match:
        args_str = func_match.group(1).strip()

        # 提取参数（简单分割，不处理嵌套括号）
        args = [a.strip() for a in args_str.split(',') if a.strip()]

        if not args:
            # 没有参数，检查是否是配置型漏洞
            if is_config_vuln:
                results.append({
                    'code': 4,
                    'source': matched_func,
                    'chain': [('sink', matched_func, file_path, vul_lineno)]
                })
            return results

        # 遍历所有参数，找到第一个可控的
        for arg_idx, arg in enumerate(args):
            # 跳过字符串字面量
            if (arg.startswith('"') and arg.endswith('"')) or \
               (arg.startswith('`') and arg.endswith('`')):
                logger.debug("[AST][Go] Arg[{}] is string literal: {}".format(arg_idx, arg))
                continue

            # 检查内置知识库
            knowledge = lookup_builtin(matched_func)
            if knowledge:
                if knowledge.get("safe"):
                    logger.debug("[AST][Go] Function {} is safe per knowledge base".format(matched_func))
                    results.append({
                        'code': -1,
                        'chain': []
                    })
                    return results
                elif knowledge.get("passthrough"):
                    logger.debug("[AST][Go] Function {} is passthrough".format(matched_func))

            # 检查参数是否直接可控
            if _is_controllable_source(arg, controlled_params):
                logger.debug("[AST][Go] Parameter is controllable: {}".format(arg))
                results.append({
                    'code': 1,
                    'chain': [
                        ('source', arg, file_path, vul_lineno),
                        ('sink', matched_func, file_path, vul_lineno)
                    ]
                })
                return results

            # 反向追踪变量
            trace_result = _trace_variable_in_lines(
                file_path, arg, vul_lineno, vul_lineno,
                repair_functions, controlled_params
            )

            if trace_result == 1:
                results.append({
                    'code': 1,
                    'chain': [
                        ('source', arg, file_path, vul_lineno),
                        ('sink', matched_func, file_path, vul_lineno)
                    ]
                })
                return results
            elif trace_result == 2:
                results.append({
                    'code': 2,
                    'chain': [
                        ('repair', arg, file_path, vul_lineno),
                        ('sink', matched_func, file_path, vul_lineno)
                    ]
                })
                return results
            elif trace_result == 3:
                results.append({
                    'code': 3,
                    'chain': [
                        ('unconfirmed', arg, file_path, vul_lineno),
                        ('sink', matched_func, file_path, vul_lineno)
                    ]
                })
                return results

        # 所有参数都不可控
        results.append({
            'code': -1,
            'chain': []
        })
    else:
        # 无法提取函数参数
        if is_config_vuln:
            results.append({
                'code': 4,
                'source': matched_func,
                'chain': [('sink', matched_func, file_path, vul_lineno)]
            })
        else:
            results.append({
                'code': -1,
                'chain': []
            })

    return results


def analysis_params(param_name, parent_func_names, vul_function, lineno, file_path,
                    repair_functions=None, controlled_params=None, isexternal=False):
    """
    Go 变量可控性分析（供 CAST 跨文件分析调用）

    :param param_name: 要追踪的变量名
    :param parent_func_names: 父函数名列表（Go 中暂不使用）
    :param vul_function: 漏洞函数列表
    :param lineno: 当前行号
    :param file_path: 文件路径
    :param repair_functions: 修复函数列表
    :param controlled_params: 可控参数列表
    :param isexternal: 是否外部调用
    :return: (is_controllable, controlled_params, expr_lineno, chain)
        is_controllable: 1=可控, -1=不可控, 3=未确认, 4=新漏洞函数
    """
    if repair_functions is None:
        repair_functions = []
    if controlled_params is None:
        controlled_params = []

    try:
        lineno = int(lineno)
    except (ValueError, TypeError):
        return -1, [], 0, []

    # 追踪变量
    trace_result = _trace_variable_in_lines(
        file_path, param_name, lineno, lineno,
        repair_functions, controlled_params
    )

    if trace_result == 1:
        return 1, controlled_params, lineno, [('source', param_name, file_path, lineno)]
    elif trace_result == 2:
        return 2, controlled_params, lineno, [('repair', param_name, file_path, lineno)]
    elif trace_result == 3:
        return 3, controlled_params, lineno, [('unconfirmed', param_name, file_path, lineno)]
    else:
        return -1, [], 0, []
