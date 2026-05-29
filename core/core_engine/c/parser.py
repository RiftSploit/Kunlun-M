#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    C/C++ AST Parser — C/C++ 反向污点追踪引擎
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    使用 tree-sitter-c 解析 C/C++ 源码 AST，从 sink（敏感函数调用参数）
    反向追踪到 source（可控输入源），支持跨函数追踪。

    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
import traceback
import os
from typing import Optional, List, Dict, Set, Tuple, Any

from utils.log import logger
from core.pretreatment import ast_object as _ast_object_singleton
from core.core_engine.trace_cache import TraceCache
from core.core_engine.c.builtin_knowledge import KNOWLEDGE as _BUILTIN_KNOWLEDGE
from core.core_engine.c.summary_generator import lookup_summary, _summary_registry
from core.core_engine.function_summary import SummaryCacheManager

# tree-sitter C AST 解析
try:
    import tree_sitter_c as _tsc
    from tree_sitter import Language as _TS_Language, Parser as _TS_Parser

    _C_TS_LANGUAGE = _TS_Language(_tsc.language())
    _ts_parser = _TS_Parser(_C_TS_LANGUAGE)
    _HAS_TREE_SITTER = True
except Exception as e:
    logger.warning("[AST][C] tree-sitter-c 初始化失败: {}".format(e))
    _ts_parser = None
    _HAS_TREE_SITTER = False

# ---------------------------------------------------------------------------
# 全局状态（与 Go/Python parser 保持一致的模式）
# ---------------------------------------------------------------------------
scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []

# 追踪缓存
_trace_cache = TraceCache("c")

# 跨函数追踪递归防护栈
_scan_function_stack = []

# 函数摘要状态
_summaries_initialized = False
_file_summaries = {}

# AST 缓存: file_path → tree
_ast_cache = {}

# 函数定义索引: (file_path, func_name) → (param_names, func_body_node, def_lineno, end_lineno)
_func_def_index = {}
_func_def_indexed_files = set()

# ---------------------------------------------------------------------------
# C/C++ 可控输入源
# ---------------------------------------------------------------------------
C_CONTROLLED_SOURCES = [
    "argv", "argc",
    "getenv", "secure_getenv",
    "scanf", "fscanf", "sscanf",
    "fgets", "gets", "getline", "getdelim",
    "read", "fread", "recv", "recvfrom", "recvmsg",
    "stdin", "STDIN_FILENO", "FILE stdin", "std::cin",
    "cin",
]

# C/C++ 字面量节点类型
_LITERAL_NODE_TYPES = frozenset({
    "number_literal", "string_literal", "char_literal",
    "true", "false", "null",
})


# ---------------------------------------------------------------------------
# 内置知识库 lookup
# ---------------------------------------------------------------------------
def lookup_builtin(func_name: str):
    """查询 C/C++ 内置函数知识库。

    :param func_name: 函数/方法名
    :return: {"passthrough": [...], "safe": bool} 或 None
    """
    # 精确匹配
    if func_name in _BUILTIN_KNOWLEDGE:
        return _BUILTIN_KNOWLEDGE[func_name]
    # 短名匹配（如 "mysql_real_escape_string" 或 "::" 分隔的 C++ 名）
    if "::" in func_name:
        short_name = func_name.split("::")[-1]
        if short_name in _BUILTIN_KNOWLEDGE:
            return _BUILTIN_KNOWLEDGE[short_name]
    return None


# ---------------------------------------------------------------------------
# tree-sitter AST 辅助函数
# ---------------------------------------------------------------------------

def _node_text(node) -> str:
    """获取 tree-sitter 节点的文本内容。"""
    if node is None:
        return ""
    return node.text.decode("utf-8", errors="ignore")


def _is_literal_node(node) -> bool:
    """检查 AST 节点是否为字面量。"""
    if node is None:
        return False
    if node.type in _LITERAL_NODE_TYPES:
        return True
    if node.type == "identifier" and _node_text(node) in ("NULL", "nullptr", "true", "false"):
        return True
    # 带符号的数字字面量: -42, +3.14
    if node.type == "unary_expression" and node.children:
        op = _node_text(node.children[0])
        if op in ("-", "+") and len(node.children) >= 2:
            return _is_literal_node(node.children[-1])
    return False


def _parse_c_ast(file_path):
    """用 tree-sitter 解析 C/C++ 文件，返回 AST tree（带缓存）。"""
    if file_path in _ast_cache:
        return _ast_cache[file_path]
    try:
        with open(file_path, "rb") as f:
            source = f.read()
        if _ts_parser is None:
            return None
        tree = _ts_parser.parse(source)
        _ast_cache[file_path] = tree
        return tree
    except Exception:
        return None


def _get_source_lines(file_path):
    """读取源文件的所有行。"""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except Exception:
        return []


def _c_line_to_text(file_path, lineno):
    """从源文件读取指定行的文本。"""
    lines = _get_source_lines(file_path)
    if lines and 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()
    return ""


def _get_call_func_text(call_node) -> str:
    """获取 call_expression 节点的函数名文本。"""
    if call_node is None or not call_node.children:
        return ""
    func_child = call_node.children[0]
    return _node_text(func_child)


def _get_call_func_name(call_node) -> Optional[str]:
    """获取 call_expression 的函数名（支持 identifier 和 field_expression）。"""
    if call_node is None or not call_node.children:
        return None
    func_child = call_node.children[0]
    if func_child.type == "identifier":
        return _node_text(func_child)
    elif func_child.type == "field_expression":
        return _node_text(func_child)
    elif func_child.type == "subscript_expression":
        return _node_text(func_child)
    return None


def _get_call_args_from_ast(call_node):
    """从 call_expression 节点提取参数 AST 节点列表（不含括号和逗号）。"""
    if call_node is None:
        return []
    for child in call_node.children:
        if child.type == "argument_list":
            args = []
            for arg_child in child.children:
                if arg_child.type not in ("(", ")", ","):
                    args.append(arg_child)
            return args
    return []


def _collect_identifiers_from_ast(node):
    """从 AST 节点中递归收集所有 identifier（变量名）。

    排除 C 关键字和类型名。
    """
    if node is None:
        return []

    _C_KEYWORDS = frozenset({
        "auto", "break", "case", "char", "const", "continue", "default", "do",
        "double", "else", "enum", "extern", "float", "for", "goto", "if",
        "inline", "int", "long", "register", "restrict", "return", "short",
        "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
        "unsigned", "void", "volatile", "while",
        # C99
        "bool", "true", "false", "restrict",
        # C11
        "alignas", "alignof", "atomic", "generic", "noreturn",
        "static_assert", "thread_local",
        # NULL
        "NULL", "nullptr",
        # 常见类型名
        "size_t", "ssize_t", "ptrdiff_t", "int8_t", "int16_t", "int32_t", "int64_t",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "FILE", "stdin", "stdout", "stderr",
        "errno",
    })

    identifiers = []
    seen = set()

    def _walk(n):
        if n.type == "identifier":
            name = _node_text(n)
            if name and name not in _C_KEYWORDS and name not in seen:
                identifiers.append(name)
                seen.add(name)
        elif n.type == "field_expression":
            # a.b → 收集 a 作为变量
            if n.children and n.children[0].type == "identifier":
                base = _node_text(n.children[0])
                if base and base not in _C_KEYWORDS and base not in seen:
                    identifiers.append(base)
                    seen.add(base)
            # 继续递归（可能嵌套更深）
            for child in n.children:
                _walk(child)
        elif n.type == "subscript_expression":
            # arr[i] → 收集 arr
            array_node = n.child_by_field_name("array") or n.child_by_field_name("argument")
            if array_node and array_node.type == "identifier":
                name = _node_text(array_node)
                if name and name not in _C_KEYWORDS and name not in seen:
                    identifiers.append(name)
                    seen.add(name)
            for child in n.children:
                _walk(child)
        elif n.type == "call_expression":
            # 函数调用：只收集参数中的标识符
            for child in n.children:
                if child.type == "argument_list":
                    for arg_child in child.children:
                        if arg_child.type not in ("(", ")", ","):
                            _walk(arg_child)
        else:
            for child in n.children:
                _walk(child)

    _walk(node)
    return identifiers


# ---------------------------------------------------------------------------
# 函数查找辅助
# ---------------------------------------------------------------------------

def _find_enclosing_function(tree, lineno):
    """在 AST 中查找包含指定行号的函数定义。

    返回 (func_name, param_names, func_body_node, start_line, end_line) 或 None。
    """
    if tree is None:
        return None

    result = [None]

    def _search(node):
        if result[0] is not None:
            return
        if node.type == "function_definition":
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            if start_line <= lineno <= end_line:
                func_name = ""
                param_names = []
                body_node = None
                declarator = node.child_by_field_name("declarator")
                body = node.child_by_field_name("body")

                if body:
                    body_node = body

                if declarator:
                    # 函数名
                    inner_decl = declarator.child_by_field_name("declarator")
                    if inner_decl and inner_decl.type == "identifier":
                        func_name = _node_text(inner_decl)
                    else:
                        # pointer_declarator 等包裹
                        for child in declarator.children:
                            if child.type == "identifier" and not func_name:
                                func_name = _node_text(child)
                            elif child.type in ("pointer_declarator", "parenthesized_declarator"):
                                name = _extract_declarator_name_simple(child)
                                if name and not func_name:
                                    func_name = name

                    # 参数列表
                    param_node = declarator.child_by_field_name("parameters")
                    if param_node and param_node.type == "parameter_list":
                        param_names = _extract_param_names(param_node)

                # 备选
                if not func_name:
                    for child in node.children:
                        if child.type == "function_declarator" and not func_name:
                            inner = child.child_by_field_name("declarator")
                            if inner and inner.type == "identifier":
                                func_name = _node_text(inner)
                            p = child.child_by_field_name("parameters")
                            if p and p.type == "parameter_list":
                                param_names = _extract_param_names(p)
                        elif child.type == "compound_statement" and not body_node:
                            body_node = child

                if func_name:
                    result[0] = (func_name, param_names, body_node, start_line, end_line)
                    return

        for child in node.children:
            _search(child)

    _search(tree.root_node)
    return result[0]


def _extract_declarator_name_simple(decl_node) -> str:
    """从声明符节点中提取名称（简单版本）。"""
    for child in decl_node.children:
        if child.type == "identifier":
            return _node_text(child)
        if child.type in ("pointer_declarator", "array_declarator",
                          "parenthesized_declarator", "init_declarator",
                          "parameter_declarator"):
            name = _extract_declarator_name_simple(child)
            if name:
                return name
    return ""


def _extract_param_names(param_list_node) -> List[str]:
    """从 parameter_list 节点提取形参名列表。"""
    names = []
    if param_list_node is None:
        return names
    for child in param_list_node.children:
        if child.type == "parameter_declaration":
            name = _extract_declarator_name_simple(child)
            if name:
                names.append(name)
    return names


def _find_call_at_line(tree, lineno, func_name):
    """在 AST 中查找指定行号上的 call_expression 节点。

    匹配 func_name（支持 system、mysql_query 等）。
    """
    if tree is None:
        return None

    short_name = func_name.split("::")[-1] if "::" in func_name else func_name
    short_name = short_name.split(".")[-1] if "." in short_name else short_name

    def _search(node):
        if node.type == "call_expression":
            node_line = node.start_point[0] + 1
            if node_line == lineno:
                # 先递归搜索子节点，找内层调用
                for child in node.children:
                    result = _search(child)
                    if result:
                        return result

                func_text = _get_call_func_text(node)
                if func_name in func_text or short_name in func_text:
                    return node
                return None

        for child in node.children:
            result = _search(child)
            if result:
                return result
        return None

    return _search(tree.root_node)


def _find_assignment_at_line(tree, lineno, var_name, to_line=None):
    """在 AST 中查找 <= lineno 的 var_name 赋值节点。

    返回 (lhs_name, rhs_node, assign_lineno) 或 None。
    支持多种 C 赋值形式：
    - declaration > init_declarator (带初始化的声明)
    - expression_statement > assignment_expression
    - expression_statement > declaration > init_declarator
    """
    if tree is None:
        return None

    result = [None]
    search_limit = to_line if to_line else lineno

    def _search(node):
        if result[0] is not None:
            return
        node_line = node.start_point[0] + 1
        if node_line > search_limit:
            return  # 超过搜索范围

        # declaration > init_declarator > declarator(identifier) = value
        if node.type == "declaration":
            for child in node.children:
                if child.type == "init_declarator":
                    _check_init_declarator(child, lineno)
                elif child.type == "declarator":
                    # 无初始化的声明，跳过
                    pass
            # 继续递归子节点
            for child in node.children:
                _search(child)
            return

        # expression_statement > assignment_expression
        if node.type == "expression_statement":
            for child in node.children:
                if child.type == "assignment_expression":
                    _check_assignment(child, lineno)
                elif child.type == "declaration":
                    _search(child)
            return

        # 直接的 assignment_expression（可能在 for 循环等中）
        if node.type == "assignment_expression":
            _check_assignment(node, lineno)
            for child in node.children:
                _search(child)
            return

        for child in node.children:
            _search(child)

    def _check_init_declarator(init_decl, limit):
        if result[0] is not None:
            return
        name = ""
        value_node = None
        found_eq = False
        for sub in init_decl.children:
            if sub.type == "declarator":
                name = _extract_declarator_name_simple(sub)
            elif sub.type == "=":
                found_eq = True
            elif found_eq and sub.type not in (";", ",") and value_node is None:
                value_node = sub

        if name == var_name and value_node is not None:
            decl_line = init_decl.start_point[0] + 1
            if decl_line <= limit:
                result[0] = (name, value_node, decl_line)

    def _check_assignment(assign_node, limit):
        if result[0] is not None:
            return
        left = None
        right = None
        found_eq = False
        for child in assign_node.children:
            if child.type == "=" or child.type.endswith("_assignment"):
                found_eq = True
                continue
            if not found_eq:
                left = child
            else:
                if right is None:
                    right = child

        if left is not None and right is not None:
            lhs_name = ""
            if left.type == "identifier":
                lhs_name = _node_text(left)
            elif left.type == "subscript_expression":
                arr = left.child_by_field_name("array") or left.child_by_field_name("argument")
                if arr and arr.type == "identifier":
                    lhs_name = _node_text(arr)

            if lhs_name == var_name:
                assign_line = assign_node.start_point[0] + 1
                if assign_line <= limit:
                    result[0] = (lhs_name, right, assign_line)

    _search(tree.root_node)
    return result[0]


def _find_call_with_var_as_arg(tree, to_line, var_name, to_line_limit):
    """在 AST 中查找 <= to_line 的、以 var_name 作为参数的 call_expression。

    返回 (call_node, arg_index, call_lineno) 或 None。
    用于处理 snprintf(cmd, ...) 等通过参数修改变量的模式。
    """
    if tree is None:
        return None

    result = [None]

    def _search(node):
        if result[0] is not None:
            return
        node_line = node.start_point[0] + 1
        if node_line > to_line_limit:
            return

        if node.type == "call_expression":
            call_line = node.start_point[0] + 1
            if call_line <= to_line_limit:
                args = _get_call_args_from_ast(node)
                for idx, arg in enumerate(args):
                    if arg.type == "identifier" and _node_text(arg) == var_name:
                        # 优先使用最近（行号最大）的匹配
                        if result[0] is None or call_line > result[0][2]:
                            result[0] = (node, idx, call_line)
            # 不递归进入 call_expression 子节点（避免匹配内层调用）
            return

        for child in node.children:
            _search(child)

    _search(tree.root_node)
    return result[0]


def _get_callee_name(call_node):
    """从 call_expression 节点提取被调用函数名。"""
    if call_node is None:
        return None
    func = call_node.child_by_field_name("function")
    if func:
        return _node_text(func)
    # 回退：第一个 identifier 子节点
    for child in call_node.children:
        if child.type == "identifier":
            return _node_text(child)
    return None


def _find_function_def_in_ast(tree, func_name):
    """在 AST 中查找函数定义节点。

    返回 (func_name, param_names, func_body_node, start_line, end_line) 或 None。
    """
    if tree is None:
        return None

    short_name = func_name.split("::")[-1] if "::" in func_name else func_name

    def _search(node):
        if node.type == "function_definition":
            func_n = ""
            param_names = []
            body_node = None

            declarator = node.child_by_field_name("declarator")
            body = node.child_by_field_name("body")
            if body:
                body_node = body

            if declarator:
                inner_decl = declarator.child_by_field_name("declarator")
                if inner_decl and inner_decl.type == "identifier":
                    func_n = _node_text(inner_decl)
                else:
                    for child in declarator.children:
                        if child.type == "identifier" and not func_n:
                            func_n = _node_text(child)
                        elif child.type in ("pointer_declarator", "parenthesized_declarator"):
                            name = _extract_declarator_name_simple(child)
                            if name and not func_n:
                                func_n = name

                param_node = declarator.child_by_field_name("parameters")
                if param_node and param_node.type == "parameter_list":
                    param_names = _extract_param_names(param_node)

            if not func_n:
                for child in node.children:
                    if child.type == "function_declarator" and not func_n:
                        inner = child.child_by_field_name("declarator")
                        if inner and inner.type == "identifier":
                            func_n = _node_text(inner)
                        p = child.child_by_field_name("parameters")
                        if p and p.type == "parameter_list":
                            param_names = _extract_param_names(p)
                    elif child.type == "compound_statement" and not body_node:
                        body_node = child

            if func_n == short_name:
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                return (func_n, param_names, body_node, start_line, end_line)

        for child in node.children:
            r = _search(child)
            if r:
                return r
        return None

    return _search(tree.root_node)


# ---------------------------------------------------------------------------
# 函数定义索引
# ---------------------------------------------------------------------------

def _build_func_def_index(file_path):
    """预扫描文件，索引所有 function_definition。"""
    if file_path in _func_def_indexed_files:
        return
    _func_def_indexed_files.add(file_path)

    tree = _parse_c_ast(file_path)
    if tree is None:
        return

    def _walk(node):
        if node.type == "function_definition":
            func_n = ""
            param_names = []
            body_node = None

            declarator = node.child_by_field_name("declarator")
            body = node.child_by_field_name("body")
            if body:
                body_node = body

            if declarator:
                inner_decl = declarator.child_by_field_name("declarator")
                if inner_decl and inner_decl.type == "identifier":
                    func_n = _node_text(inner_decl)
                else:
                    for child in declarator.children:
                        if child.type == "identifier" and not func_n:
                            func_n = _node_text(child)
                        elif child.type in ("pointer_declarator", "parenthesized_declarator"):
                            name = _extract_declarator_name_simple(child)
                            if name and not func_n:
                                func_n = name

                param_node = declarator.child_by_field_name("parameters")
                if param_node and param_node.type == "parameter_list":
                    param_names = _extract_param_names(param_node)

            if not func_n:
                for child in node.children:
                    if child.type == "function_declarator" and not func_n:
                        inner = child.child_by_field_name("declarator")
                        if inner and inner.type == "identifier":
                            func_n = _node_text(inner)
                        p = child.child_by_field_name("parameters")
                        if p and p.type == "parameter_list":
                            param_names = _extract_param_names(p)
                    elif child.type == "compound_statement" and not body_node:
                        body_node = child

            if func_n and (file_path, func_n) not in _func_def_index:
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                _func_def_index[(file_path, func_n)] = (param_names, body_node, start_line, end_line)

        for child in node.children:
            _walk(child)

    _walk(tree.root_node)


def _build_func_def_index_cross_file():
    """预扫描所有 C/C++ 文件的函数定义（跨文件索引）。"""
    pt = _ast_object_singleton
    if not pt or not hasattr(pt, "pre_result"):
        return
    for other_fp, other_data in pt.pre_result.items():
        if other_data.get("language") in ("c", "cpp", "c++"):
            _build_func_def_index(other_fp)


# ---------------------------------------------------------------------------
# 可控源判定
# ---------------------------------------------------------------------------

def _is_controllable_source(expr_str, controlled_params=None):
    """检查表达式是否是可控输入源。

    C/C++ 可控源包括 argv、getenv、scanf/fgets 等标准输入。
    """
    if controlled_params is None:
        controlled_params = is_controlled_params

    for cp in controlled_params:
        if cp in expr_str:
            return True

    for src in C_CONTROLLED_SOURCES:
        if src in expr_str:
            return True

    return False


def _is_repair_function(expr_str, repair_functions=None):
    """检查表达式是否包含修复函数。"""
    if repair_functions is None:
        repair_functions = is_repair_functions

    for rf in repair_functions:
        if rf in expr_str:
            return True

    # 也检查 builtin_knowledge 中标记 safe 的函数
    for func_name in _BUILTIN_KNOWLEDGE:
        knowledge = _BUILTIN_KNOWLEDGE[func_name]
        if knowledge.get("safe") and func_name in expr_str:
            return True

    return False


# ---------------------------------------------------------------------------
# 参数分割工具
# ---------------------------------------------------------------------------

def _split_args_respecting_parens(args_str):
    """分割函数参数字符串，正确处理嵌套括号和引号内的逗号。"""
    if not args_str or not args_str.strip():
        return []
    args = []
    current = ""
    depth = 0
    in_string = False
    string_char = None
    i = 0
    while i < len(args_str):
        ch = args_str[i]
        if in_string:
            current += ch
            if ch == "\\" and i + 1 < len(args_str):
                current += args_str[i + 1]
                i += 2
                continue
            if ch == string_char:
                in_string = False
            i += 1
            continue
        if ch in ("\"", "'", "`"):
            in_string = True
            string_char = ch
            current += ch
        elif ch == "(":
            depth += 1
            current += ch
        elif ch == ")":
            depth -= 1
            current += ch
        elif ch == "," and depth == 0:
            args.append(current.strip())
            current = ""
        else:
            current += ch
        i += 1
    if current.strip():
        args.append(current.strip())
    return args


# ---------------------------------------------------------------------------
# 函数摘要初始化
# ---------------------------------------------------------------------------

def _init_function_summaries(file_path):
    """初始化当前文件及依赖文件的函数摘要（带缓存）。"""
    global _summaries_initialized, _file_summaries

    if _summaries_initialized:
        return

    try:
        from core.core_engine.c.summary_generator import generate_summaries_for_target

        target_dir = file_path
        pt = _ast_object_singleton
        if pt and hasattr(pt, "target_directory"):
            target_dir = pt.target_directory
        elif pt and hasattr(pt, "pre_result"):
            paths = list(pt.pre_result.keys())
            if len(paths) > 1:
                target_dir = os.path.commonpath(paths)
            elif paths:
                target_dir = os.path.dirname(paths[0])

        cache_mgr = SummaryCacheManager()

        files_dict = {}
        if pt and hasattr(pt, "pre_result"):
            for fp, data in pt.pre_result.items():
                if data.get("language") in ("c", "cpp", "c++"):
                    try:
                        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                            files_dict[fp] = f.read()
                    except Exception:
                        pass
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                files_dict[file_path] = f.read()
        except Exception:
            pass

        if files_dict:
            cached = cache_mgr.load_or_generate(target_dir, files_dict)
            need_generate = {fp: content for fp, content in files_dict.items()
                             if not cached.get(fp) or not cached[fp].functions}
            if need_generate:
                new_summaries = generate_summaries_for_target(target_dir, need_generate)
                for fp, fs in new_summaries.items():
                    cached[fp] = fs
                    cache_mgr.save_file_summary(target_dir, fp, fs)
            _file_summaries = cached
            logger.debug("[AST][C] 摘要初始化完成: {} 个文件".format(len(_file_summaries)))

        _summaries_initialized = True
    except Exception as e:
        logger.debug("[AST][C] 摘要初始化失败: {}".format(e))
        _summaries_initialized = True


# ---------------------------------------------------------------------------
# 反向污点追踪核心
# ---------------------------------------------------------------------------

def _trace_variable_in_lines(file_path, var_name, from_line, to_line,
                              repair_functions=None, controlled_params=None,
                              depth=0, max_depth=5):
    """在指定行范围内追踪变量的数据流（缓存包装层）。

    返回: (code, source_lineno) 元组
        code: 1 (可控), 2 (已修复), 3 (未确认), -1 (不可控)
    """
    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    # 顶层调用查缓存
    if depth == 0 and file_path and to_line:
        cached = _trace_cache.get(file_path, var_name, int(to_line))
        if cached is not None:
            return (cached[0], cached[2] if len(cached) > 2 else to_line)

    code, source_lineno = _trace_variable_in_lines_impl(
        file_path, var_name, from_line, to_line,
        repair_functions, controlled_params, depth, max_depth
    )

    # 顶层调用写缓存（仅确定性结果）
    if depth == 0 and file_path and to_line and code in (1, 2, -1):
        _trace_cache.put(file_path, var_name, int(to_line), (code, [], source_lineno))

    return (code, source_lineno)


def _trace_variable_in_lines_impl(file_path, var_name, from_line, to_line,
                                  repair_functions, controlled_params,
                                  depth, max_depth):
    """在指定行范围内追踪变量的数据流（实现层）。

    使用 tree-sitter AST 查找 var_name 的赋值，按节点类型分派分析。

    算法：
    1. 解析文件 AST
    2. 找到包含 vul_lineno 的函数体
    3. 在函数体内从 to_line 向上查找 var_name 的赋值
    4. 分析 RHS：字面量/变量/函数调用/表达式
    5. 如果 var_name 是函数形参，追踪调用点
    """
    if depth > max_depth:
        return (-1, 0)

    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    tree = _parse_c_ast(file_path)
    if not tree:
        logger.debug("[AST][C] 无法解析 AST: {}".format(file_path))
        return (-1, 0)

    # 找到包含 to_line 的函数体
    func_info = _find_enclosing_function(tree, to_line)
    if not func_info:
        logger.debug("[AST][C] 未找到包含行 {} 的函数".format(to_line))
        return (-1, 0)

    func_name, param_names, body_node, func_start, func_end = func_info

    # ---- 检查 var_name 是否直接是可控源 ----
    if _is_controllable_source(var_name, controlled_params):
        logger.debug("[AST][C] Variable {} is controllable source".format(var_name))
        return (1, to_line)

    # argv[1] 等下标形式也直接判定为可控
    if var_name == "argv":
        logger.debug("[AST][C] Variable argv is controllable source")
        return (1, to_line)

    # ---- 检查 var_name 是否是函数形参 ----
    if var_name in param_names:
        logger.debug("[AST][C] Variable {} is a parameter of function {}".format(
            var_name, func_name))
        # 搜索调用点
        call_result = _trace_param_at_call_sites(
            func_name, var_name, file_path, tree,
            repair_functions, controlled_params, depth, max_depth
        )
        if call_result is not None:
            return call_result

        # 跨文件搜索
        pt = _ast_object_singleton
        if pt and hasattr(pt, "pre_result"):
            for other_fp, other_data in pt.pre_result.items():
                if other_fp == file_path:
                    continue
                if other_data.get("language") not in ("c", "cpp", "c++"):
                    continue
                other_tree = _parse_c_ast(other_fp)
                if not other_tree:
                    continue
                call_result = _trace_param_at_call_sites(
                    func_name, var_name, other_fp, other_tree,
                    repair_functions, controlled_params, depth, max_depth
                )
                if call_result is not None:
                    return call_result

        return (-1, 0)

    # ---- 在函数体内查找 var_name 的赋值 ----
    assign_result = _find_assignment_at_line(tree, to_line, var_name, to_line)
    if assign_result:
        lhs_name, rhs_node, assign_lineno = assign_result

        # 分析 RHS
        result = _analyze_rhs_node(
            rhs_node, var_name, file_path, assign_lineno, to_line,
            repair_functions, controlled_params, depth, max_depth
        )
        if result is not None:
            return result

    # ---- 查找以 var_name 作为参数的函数调用（如 snprintf(cmd, ...)）----
    call_result = _find_call_with_var_as_arg(tree, to_line, var_name, to_line)
    if call_result:
        call_node, arg_index, call_lineno = call_result
        callee_name = _get_call_func_name(call_node)
        if callee_name:
            knowledge = lookup_builtin(callee_name)
            if knowledge and arg_index in knowledge.get("passthrough", []):
                logger.debug("[AST][C] Variable {} is passthrough arg {} of {}".format(
                    var_name, arg_index, callee_name))
                # 检查其他参数是否包含可控源
                args = _get_call_args_from_ast(call_node)
                for i, arg in enumerate(args):
                    if i == arg_index:
                        continue
                    if _is_literal_node(arg):
                        continue
                    arg_text = _node_text(arg)
                    if _is_controllable_source(arg_text, controlled_params):
                        logger.debug("[AST][C] Passthrough arg {} of {} is controllable: {}".format(
                            i, callee_name, arg_text[:80]))
                        return (1, call_lineno)
                    # 递归追踪参数中的变量
                    sub_vars = _collect_identifiers_from_ast(arg)
                    for sv in sub_vars:
                        sub_code, sub_lineno = _trace_variable_in_lines(
                            file_path, sv, call_lineno, call_lineno,
                            repair_functions, controlled_params, depth + 1, max_depth
                        )
                        if sub_code == 1:
                            return (1, sub_lineno)

    # ---- 查找以 var_name 作为参数的函数调用（如 snprintf(cmd, ...)）----
    call_write_result = _find_call_with_var_as_arg(tree, to_line, var_name, to_line)
    if call_write_result:
        call_node, arg_index, call_lineno = call_write_result
        callee_name = _get_callee_name(call_node)
        if callee_name:
            knowledge = lookup_builtin(callee_name)
            if knowledge:
                # 如果 var_name 在 passthrough 列表中，说明此参数是输出参数
                if arg_index in knowledge.get("passthrough", []):
                    # 检查其他参数是否包含可控源
                    args = _get_call_args_from_ast(call_node)
                    for i, arg in enumerate(args):
                        if i == arg_index:
                            continue
                        if _is_literal_node(arg):
                            continue
                        arg_text = _node_text(arg)
                        if _is_controllable_source(arg_text, controlled_params):
                            logger.debug("[AST][C] Variable {} written by {} via arg[{}], other arg[{}] is controllable: {}".format(
                                var_name, callee_name, arg_index, i, arg_text[:80]))
                            return (1, call_lineno)
                        # 递归追踪其他参数中的变量
                        sub_vars = _collect_identifiers_from_ast(arg)
                        for sv in sub_vars:
                            sub_code, sub_lineno = _trace_variable_in_lines(
                                file_path, sv, call_lineno, call_lineno,
                                repair_functions, controlled_params, depth + 1, max_depth
                            )
                            if sub_code == 1:
                                return (1, sub_lineno)

    # ---- 文本回退：逐行扫描 ----
    return _text_trace_variable(file_path, var_name, to_line,
                                repair_functions, controlled_params, depth, max_depth)


def _analyze_rhs_node(rhs_node, var_name, file_path, lineno, to_line,
                      repair_functions, controlled_params, depth, max_depth):
    """根据 RHS AST 节点类型分派分析。

    返回: (code, source_lineno) 如果确定，None 如果需要继续扫描。
    """
    rhs_text = _node_text(rhs_node)

    # 快速检查：可控源
    if _is_controllable_source(rhs_text, controlled_params):
        logger.debug("[AST][C] Variable {} RHS is controllable source: {}".format(
            var_name, rhs_text[:80]))
        return (1, lineno)

    # 快速检查：修复函数
    if _is_repair_function(rhs_text, repair_functions):
        logger.debug("[AST][C] Variable {} RHS is repaired: {}".format(
            var_name, rhs_text[:80]))
        return (2, lineno)

    node_type = rhs_node.type

    # 字面量 → 安全
    if _is_literal_node(rhs_node):
        return (-1, 0)

    # 函数调用
    if node_type == "call_expression":
        return _handle_call_expression_rhs(
            rhs_node, var_name, file_path, lineno, to_line,
            repair_functions, controlled_params, depth, max_depth
        )

    # 字符串拼接 (binary_expression with +)
    if node_type == "binary_expression":
        return _handle_binary_expression_rhs(
            rhs_node, var_name, file_path, lineno, to_line,
            repair_functions, controlled_params, depth, max_depth
        )

    # 简单变量赋值: x = y
    if node_type == "identifier":
        name = rhs_text
        if name == var_name:
            return None  # 自赋值，跳过
        if _is_controllable_source(name, controlled_params):
            return (1, lineno)
        return _trace_variable_in_lines(
            file_path, name, lineno, to_line,
            repair_functions, controlled_params, depth + 1, max_depth
        )

    # subscript_expression (如 argv[1])
    if node_type == "subscript_expression":
        array = rhs_node.child_by_field_name("array") or rhs_node.child_by_field_name("argument")
        if array:
            array_text = _node_text(array)
            # argv[i] → 可控源
            if array_text == "argv" or array_text.startswith("argv"):
                logger.debug("[AST][C] Variable {} from argv subscript: {}".format(
                    var_name, rhs_text[:80]))
                return (1, lineno)
            if _is_controllable_source(array_text, controlled_params):
                return (1, lineno)
            if array.type == "identifier":
                return _trace_variable_in_lines(
                    file_path, array_text, lineno, to_line,
                    repair_functions, controlled_params, depth + 1, max_depth
                )

    # field_expression (如 obj.field, ptr->field)
    if node_type == "field_expression":
        operand = (rhs_node.child_by_field_name("argument")
                   or rhs_node.child_by_field_name("expression"))
        if operand:
            operand_text = _node_text(operand)
            if _is_controllable_source(operand_text, controlled_params):
                return (1, lineno)
            if operand.type == "identifier":
                return _trace_variable_in_lines(
                    file_path, operand_text, lineno, to_line,
                    repair_functions, controlled_params, depth + 1, max_depth
                )

    # parenthesized_expression → 解包
    if node_type == "parenthesized_expression":
        for child in rhs_node.children:
            if child.type not in ("(", ")"):
                return _analyze_rhs_node(
                    child, var_name, file_path, lineno, to_line,
                    repair_functions, controlled_params, depth, max_depth
                )

    # cast_expression / type_conversion → 追踪被转换的值
    if node_type in ("cast_expression", "type_conversion"):
        value = rhs_node.child_by_field_name("value")
        if value:
            return _analyze_rhs_node(
                value, var_name, file_path, lineno, to_line,
                repair_functions, controlled_params, depth, max_depth
            )

    # unary_expression (如 !x, -x, *ptr, &x, sizeof(x))
    if node_type == "unary_expression":
        operand = rhs_node.child_by_field_name("operand") or rhs_node.child_by_field_name("argument")
        if operand:
            return _analyze_rhs_node(
                operand, var_name, file_path, lineno, to_line,
                repair_functions, controlled_params, depth, max_depth
            )

    # pointer_expression / dereference_expression → 追踪被解引用的变量
    if node_type in ("pointer_expression", "dereference_expression"):
        operand = rhs_node.child_by_field_name("operand") or rhs_node.child_by_field_name("argument")
        if operand:
            return _analyze_rhs_node(
                operand, var_name, file_path, lineno, to_line,
                repair_functions, controlled_params, depth, max_depth
            )

    # conditional_expression (三元运算符 ? :)
    if node_type == "conditional_expression":
        consequence = rhs_node.child_by_field_name("consequence")
        alternative = rhs_node.child_by_field_name("alternative")
        for part in (consequence, alternative):
            if part:
                result = _analyze_rhs_node(
                    part, var_name, file_path, lineno, to_line,
                    repair_functions, controlled_params, depth, max_depth
                )
                if result and result[0] in (1, 2):
                    return result
        return None

    # 其他：收集标识符逐一追踪
    var_names = _collect_identifiers_from_ast(rhs_node)
    for vn in var_names:
        if vn == var_name:
            continue
        if _is_controllable_source(vn, controlled_params):
            return (1, lineno)
        r = _trace_variable_in_lines(
            file_path, vn, lineno, to_line,
            repair_functions, controlled_params, depth + 1, max_depth
        )
        if r[0] in (1, 2):
            return r

    return None


def _handle_call_expression_rhs(call_node, var_name, file_path, lineno, to_line,
                                repair_functions, controlled_params, depth, max_depth):
    """处理函数调用赋值的 RHS 分析。"""
    func_text = _get_call_func_text(call_node)
    args = _get_call_args_from_ast(call_node)

    # 检查内置知识库
    knowledge = lookup_builtin(func_text)
    if knowledge:
        if knowledge.get("safe") and not knowledge.get("passthrough"):
            logger.debug("[AST][C] RHS call {} is safe per knowledge base".format(func_text))
            return (-1, 0)
        if knowledge.get("passthrough"):
            # 追踪所有非字面量参数
            for arg_node in args:
                if _is_literal_node(arg_node):
                    continue
                var_names = _collect_identifiers_from_ast(arg_node)
                for vn in var_names:
                    if vn == var_name:
                        continue
                    if _is_controllable_source(vn, controlled_params):
                        return (1, lineno)
                    r = _trace_variable_in_lines(
                        file_path, vn, lineno, to_line,
                        repair_functions, controlled_params, depth + 1, max_depth
                    )
                    if r[0] in (1, 2):
                        return r
            return None

    # 可控源函数（如 getenv, scanf, fgets 等）
    short_name = func_text.split("::")[-1] if "::" in func_text else func_text
    if short_name in C_CONTROLLED_SOURCES or func_text in C_CONTROLLED_SOURCES:
        logger.debug("[AST][C] RHS call {} is controlled source".format(func_text))
        return (1, lineno)

    # 未知函数 → 跨函数追踪 (deps 机制)
    args_str = ", ".join(_node_text(a) for a in args)
    fb_result = function_back_c(
        func_text, args_str, lineno, file_path,
        repair_functions, controlled_params
    )
    if isinstance(fb_result, tuple) and len(fb_result) == 2:
        code, caller_deps = fb_result
        if code == "deps" and caller_deps:
            for dep_var in caller_deps:
                if dep_var == var_name:
                    continue
                r = _trace_variable_in_lines(
                    file_path, dep_var, lineno, to_line,
                    repair_functions, controlled_params, depth + 1, max_depth
                )
                if r[0] in (1, 2):
                    return r
            return (3, lineno)
        elif code in (1, 2):
            return (code, lineno)
        elif code == 3:
            return (3, lineno)

    return None


def _handle_binary_expression_rhs(bin_node, var_name, file_path, lineno, to_line,
                                  repair_functions, controlled_params, depth, max_depth):
    """处理字符串拼接 (binary_expression) 的 RHS 分析。"""
    for child in bin_node.children:
        if child.type in ("+", "-", "*", "/", "%", "||", "&&", "|", "&", "^",
                          "<<", ">>", "<", ">", "<=", ">=", "==", "!="):
            continue
        if _is_literal_node(child):
            continue
        var_names = _collect_identifiers_from_ast(child)
        for vn in var_names:
            if vn == var_name:
                continue
            if _is_controllable_source(vn, controlled_params):
                return (1, lineno)
            r = _trace_variable_in_lines(
                file_path, vn, lineno, to_line,
                repair_functions, controlled_params, depth + 1, max_depth
            )
            if r[0] in (1, 2):
                return r
    return None


def _text_trace_variable(file_path, var_name, vul_lineno,
                          repair_functions=None, controlled_params=None,
                          depth=0, max_depth=5):
    """纯文本 fallback 追踪：不依赖 tree-sitter AST。

    从 vul_lineno 向上逐行查找 var_name 的赋值，判断是否来自可控源。
    返回: (code, source_lineno)
    """
    if repair_functions is None:
        repair_functions = []
    if controlled_params is None:
        controlled_params = []

    if depth > max_depth:
        return (-1, 0)

    lines = _get_source_lines(file_path)
    if not lines:
        return (-1, 0)

    # 向上查找赋值
    for i in range(vul_lineno - 2, -1, -1):
        line = lines[i].strip()

        # 匹配 C 赋值: type var = ... 或 var = ...
        # 先匹配带类型的声明: int/char/... var = expr
        m_decl = re.match(
            r'(?:\w+(?:\s*\*)*)\s+' + re.escape(var_name) + r'\s*=\s*(.+)',
            line
        )
        if m_decl:
            rhs = m_decl.group(1).strip().rstrip(";")
        else:
            # 匹配纯赋值: var = expr
            m_assign = re.match(
                r'(?:' + re.escape(var_name) + r')\s*=\s*(.+)',
                line
            )
            if not m_assign:
                continue
            rhs = m_assign.group(1).strip().rstrip(";")

        src_lineno = i + 1

        # 检查是否是可控源函数调用
        if _is_controllable_source(rhs, controlled_params):
            return (1, src_lineno)

        # 检查是否是修复函数
        if _is_repair_function(rhs, controlled_params):
            return (2, src_lineno)

        # 检查子变量
        sub_vars = re.findall(r'[a-zA-Z_]\w*', rhs)
        for sv in sub_vars:
            if sv in ("true", "false", "NULL", "nullptr", "sizeof", "int", "char",
                       "void", "long", "short", "unsigned", "signed", "const",
                       "return", "if", "else", "for", "while", "sizeof"):
                continue
            if sv == var_name:
                continue
            if _is_controllable_source(sv, controlled_params):
                return (1, src_lineno)
            sub_code, sub_line = _text_trace_variable(
                file_path, sv, src_lineno,
                repair_functions, controlled_params, depth + 1, max_depth
            )
            if sub_code == 1:
                return (1, sub_line)

    return (-1, 0)


# ---------------------------------------------------------------------------
# 跨函数追踪
# ---------------------------------------------------------------------------

def _trace_param_at_call_sites(func_name, param_name, file_path, tree,
                               repair_functions, controlled_params,
                               depth, max_depth):
    """用 AST 搜索函数调用点，追踪实参来源。

    返回 (code, source_lineno) 或 None。
    """
    call_sites = []

    def _find_calls(node):
        if node.type == "call_expression":
            call_func = _get_call_func_name(node)
            if call_func and func_name in call_func:
                call_sites.append(node)
        for child in node.children:
            _find_calls(child)

    _find_calls(tree.root_node)

    for call_node in call_sites:
        args = _get_call_args_from_ast(call_node)
        call_lineno = call_node.start_point[0] + 1

        # 获取函数定义的形参列表
        func_def = _find_function_def_in_ast(tree, func_name)
        if not func_def:
            # 用索引
            for (idx_fp, idx_name), idx_val in _func_def_index.items():
                if idx_name == func_name:
                    formal_params = idx_val[0]
                    _trace_from_index = True
                    break
            else:
                continue
        else:
            formal_params = func_def[1]
            _trace_from_index = False

        # 找到 param_name 在形参中的位置
        param_idx = -1
        for i, fp in enumerate(formal_params):
            if fp == param_name:
                param_idx = i
                break

        if param_idx < 0 or param_idx >= len(args):
            continue

        # 获取对应的实参
        actual_arg = args[param_idx]
        actual_arg_text = _node_text(actual_arg)

        # 追踪实参
        if actual_arg.type == "identifier":
            result = _trace_variable_in_lines(
                file_path, actual_arg_text, call_lineno, call_lineno,
                repair_functions, controlled_params, depth + 1, max_depth
            )
        else:
            result = _analyze_rhs_node(
                actual_arg, param_name, file_path, call_lineno, call_lineno,
                repair_functions, controlled_params, depth + 1, max_depth
            )
        if isinstance(result, tuple) and result[0] in (1, 2):
            return result

    return None


def function_back_c(func_name, call_args, vul_lineno, file_path,
                    repair_functions=None, controlled_params=None):
    """回溯用户自定义函数定义，分析返回值与参数的依赖关系。

    仿照 Go 引擎的 function_back_go() 模式。

    返回:
        (code, caller_var_names)
        code: 'deps' — 返回值依赖调用者变量，需继续追踪
              1 — 返回值直接可控
              2 — 返回值经过修复函数
              3 — 未确认
              -1 — 不可控/未找到函数
    """
    global _scan_function_stack

    if func_name in _scan_function_stack:
        logger.debug("[AST][C] Recursive function trace detected: {} -> skip".format(
            " -> ".join(_scan_function_stack + [func_name])))
        return (-1, [])

    _scan_function_stack.append(func_name)

    try:
        if repair_functions is None:
            repair_functions = is_repair_functions
        if controlled_params is None:
            controlled_params = is_controlled_params

        # 1. 检查内置知识库
        knowledge = lookup_builtin(func_name)
        if knowledge:
            if knowledge.get("safe") and not knowledge.get("passthrough"):
                return (-1, [])

        # 1.5. 查函数摘要
        callee_summary = lookup_summary(func_name)
        if callee_summary and callee_summary.return_flow:
            return _judge_from_summary(callee_summary, call_args, controlled_params)

        # 2. 查函数定义索引
        result = _func_def_index.get((file_path, func_name))
        callee_fp = file_path

        # 3. 索引未命中，实时搜索
        if result is None:
            tree = _parse_c_ast(file_path)
            if tree:
                result = _find_function_def_in_ast(tree, func_name)
                if result:
                    callee_fp = file_path
                    param_names, body_node, def_lineno, end_lineno = result
                    result = (param_names, body_node, def_lineno, end_lineno)

        # 4. 跨文件搜索
        if result is None:
            pt = _ast_object_singleton
            if pt and hasattr(pt, "pre_result"):
                short_name = func_name.split("::")[-1] if "::" in func_name else func_name
                for other_fp, other_data in pt.pre_result.items():
                    if other_fp == file_path:
                        continue
                    if other_data.get("language") not in ("c", "cpp", "c++"):
                        continue
                    result = _func_def_index.get((other_fp, short_name))
                    if result is not None:
                        callee_fp = other_fp
                        break
                    other_tree = _parse_c_ast(other_fp)
                    if other_tree:
                        found = _find_function_def_in_ast(other_tree, short_name)
                        if found:
                            callee_fp = other_fp
                            result = found
                            break

        if result is None:
            return (-1, [])

        if len(result) == 4:
            param_names, body_node, def_lineno, end_lineno = result
        else:
            return (-1, [])

        # 4.5. 进入 callee 函数体检查 sink 调用
        sink_result = _trace_callee_body_for_sinks(
            callee_fp, func_name, param_names, call_args,
            file_path, repair_functions, controlled_params
        )
        if sink_result is not None:
            return sink_result

        # 5. fallback: 分析返回值依赖
        return _analyze_return_deps_c(
            param_names, body_node, call_args,
            file_path, repair_functions, controlled_params
        )

    finally:
        if _scan_function_stack and _scan_function_stack[-1] == func_name:
            _scan_function_stack.pop()
        else:
            try:
                _scan_function_stack.remove(func_name)
            except ValueError:
                pass


def _judge_from_summary(summary, call_args_str, controlled_params):
    """根据函数摘要判定返回值可控性。

    返回: (code, caller_var_names)
    """
    if controlled_params is None:
        controlled_params = is_controlled_params

    for rf in summary.return_flow:
        if rf.origin_type == "param":
            actual_args = _split_args_respecting_parens(call_args_str) if call_args_str else []
            for param_idx in rf.dep_params:
                if param_idx < len(actual_args):
                    actual_expr = actual_args[param_idx].strip()
                    if _is_controllable_source(actual_expr, controlled_params):
                        return (1, [])

            actual_args = _split_args_respecting_parens(call_args_str) if call_args_str else []
            deps = set()
            for param_idx in rf.dep_params:
                if param_idx < len(actual_args):
                    actual_expr = actual_args[param_idx].strip()
                    names = _collect_identifiers_from_ast_str(actual_expr)
                    if names:
                        deps.update(names)
            if deps:
                return ("deps", list(deps))

        elif rf.origin_type == "call":
            knowledge = lookup_builtin(rf.origin)
            if knowledge:
                if knowledge.get("safe") and not knowledge.get("passthrough"):
                    continue
                if knowledge.get("passthrough"):
                    for param_idx in rf.dep_params:
                        if param_idx < len(summary.params):
                            actual_args = _split_args_respecting_parens(call_args_str) if call_args_str else []
                            if param_idx < len(actual_args):
                                if _is_controllable_source(actual_args[param_idx], controlled_params):
                                    return (1, [])
            else:
                if _is_controllable_source(rf.origin, controlled_params):
                    return (1, [])

        elif rf.origin_type == "global":
            if _is_controllable_source(rf.origin, controlled_params):
                return (1, [])

        elif rf.origin_type == "literal":
            continue

    return (-1, [])


def _collect_identifiers_from_ast_str(expr_str):
    """从表达式字符串中提取标识符（回退方案）。"""
    if not expr_str:
        return []
    return re.findall(r'[a-zA-Z_]\w*', expr_str)


def _trace_callee_body_for_sinks(callee_file_path, callee_func_name, formal_params,
                                  call_args_str, caller_file_path,
                                  repair_functions=None, controlled_params=None):
    """进入 callee 函数体，搜索 sink 调用，追踪参数数据流。

    返回: (code, caller_var_names) 或 None。
    """
    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    tree = _parse_c_ast(callee_file_path)
    if not tree:
        return None

    lookup_name = callee_func_name.split("::")[-1] if "::" in callee_func_name else callee_func_name
    func_def = _find_function_def_in_ast(tree, lookup_name)
    if not func_def:
        return None

    _, _, body_node, _, _ = func_def
    if not body_node:
        return None

    # Walk 函数体，找所有已知 sink 的 call_expression
    sink_calls = []

    def _walk_for_sinks(node):
        if node.type == "call_expression":
            func_text = _get_call_func_text(node)
            if func_text:
                knowledge = lookup_builtin(func_text)
                if knowledge and not knowledge.get("safe", True):
                    sink_calls.append((func_text, node))
        for child in node.children:
            _walk_for_sinks(child)

    _walk_for_sinks(body_node)
    if not sink_calls:
        return None

    # 建立形参→实参映射
    actual_args = _split_args_respecting_parens(call_args_str) if call_args_str else []
    arg_map = {}
    for idx, fp_name in enumerate(formal_params):
        if idx < len(actual_args):
            arg_map[fp_name] = actual_args[idx].strip()

    for sink_func, sink_node in sink_calls:
        args = _get_call_args_from_ast(sink_node)
        for arg_node in args:
            if _is_literal_node(arg_node):
                continue

            arg_identifiers = _collect_identifiers_from_ast(arg_node)
            for ident in arg_identifiers:
                if ident not in arg_map:
                    continue

                actual_expr = arg_map[ident]

                if _is_controllable_source(actual_expr, controlled_params):
                    logger.debug("[AST][C] Sink {} in callee body uses controllable param: {} -> {}".format(
                        sink_func, ident, actual_expr))
                    return (1, [])

                caller_var_names = set()
                names = _collect_identifiers_from_ast_str(actual_expr)
                if names:
                    caller_var_names.update(names)
                else:
                    simple = re.match(r'^([a-zA-Z_]\w*)$', actual_expr)
                    if simple:
                        caller_var_names.add(simple.group(1))

                if caller_var_names:
                    logger.debug("[AST][C] Sink {} in callee body depends on caller vars: {}".format(
                        sink_func, caller_var_names))
                    return ("deps", list(caller_var_names))

    return None


def _analyze_return_deps_c(formal_params, body_node, call_args_str,
                           file_path, repair_functions, controlled_params):
    """分析函数返回值与形参的依赖关系（C 版本）。

    使用 tree-sitter AST 进行分析。

    返回: (code, caller_var_names)
    """
    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    actual_args = _split_args_respecting_parens(call_args_str) if call_args_str else []

    # 收集实参变量名（用于 fallback deps）
    caller_var_names = set()
    for arg in actual_args:
        arg = arg.strip()
        if not arg:
            continue
        if (arg.startswith('"') and arg.endswith('"')) or \
           (arg.startswith("'") and arg.endswith("'")):
            continue
        if re.match(r'^\d+(\.\d+)?$', arg):
            continue
        names = _collect_identifiers_from_ast_str(arg)
        if names:
            caller_var_names.update(names)
        else:
            simple = re.match(r'^([a-zA-Z_]\w*)$', arg)
            if simple:
                caller_var_names.add(simple.group(1))

    # 建立形参→实参映射
    arg_map = {}
    controllable_formal = set()
    for idx, fp_name in enumerate(formal_params):
        if idx < len(actual_args):
            actual_expr = actual_args[idx].strip()
            arg_map[fp_name] = actual_expr
            if _is_controllable_source(actual_expr, controlled_params):
                controllable_formal.add(fp_name)

    # 赋值链传播（AST 遍历函数体）
    controllable_local = set(controllable_formal)
    if body_node:
        for _ in range(3):
            changed = _propagate_controllable_in_body(body_node, controllable_local)
            if not changed:
                break

    # 分析 return 语句
    if body_node:
        return_items = _collect_return_values(body_node)
        for ret_expr_text, ret_node in return_items:
            # 返回值本身是可控源
            if _is_controllable_source(ret_expr_text, controlled_params):
                logger.debug("[AST][C] Function returns controllable source: {}".format(
                    ret_expr_text[:80]))
                return (1, [])

            # 返回值是修复函数
            if _is_repair_function(ret_expr_text, repair_functions):
                return (2, [])

            # 检查返回值变量是否在 controllable_local 中
            if ret_node:
                ret_idents = _collect_identifiers_from_ast(ret_node)
            else:
                ret_idents = _collect_identifiers_from_ast_str(ret_expr_text)

            matched = ret_idents & controllable_local
            if matched:
                deps = set()
                for var in matched:
                    if var in arg_map:
                        actual_expr = arg_map[var]
                        if _is_controllable_source(actual_expr, controlled_params):
                            return (1, [])
                        actual_names = _collect_identifiers_from_ast_str(actual_expr)
                        if actual_names:
                            deps.update(actual_names)
                        else:
                            simple = re.match(r'^([a-zA-Z_]\w*)$', actual_expr)
                            if simple:
                                deps.add(simple.group(1))
                    else:
                        deps.update(ret_idents)
                if deps:
                    logger.debug("[AST][C] Function return depends on caller vars: {}".format(deps))
                    return ("deps", list(deps))

            # fallback: 文本匹配形参名
            for fp_name, actual_expr in arg_map.items():
                if _is_controllable_source(actual_expr, controlled_params):
                    if fp_name in ret_expr_text:
                        logger.debug("[AST][C] Function returns controllable param {} (text match)".format(
                            fp_name))
                        return (1, [])

    if caller_var_names:
        return ("deps", list(caller_var_names))

    return (3, [])


def _propagate_controllable_in_body(body_node, controllable_local):
    """在函数体 AST 中传播可控变量标记。

    返回 True 如果有新的变量被标记为可控。
    """
    changed = False

    def _walk(node):
        nonlocal changed
        lhs_name = None
        rhs_identifiers = []

        if node.type == "declaration":
            for child in node.children:
                if child.type == "init_declarator":
                    _process_init_declarator(child)
        elif node.type == "expression_statement":
            for child in node.children:
                if child.type == "assignment_expression":
                    _process_assignment(child)
        elif node.type == "assignment_expression":
            _process_assignment(node)

        for child in node.children:
            _walk(child)

    def _process_init_declarator(init_decl):
        nonlocal changed
        name = ""
        value_node = None
        found_eq = False
        for sub in init_decl.children:
            if sub.type == "declarator":
                name = _extract_declarator_name_simple(sub)
            elif sub.type == "=":
                found_eq = True
            elif found_eq and sub.type not in (";", ",") and value_node is None:
                value_node = sub

        if name and name not in controllable_local and value_node:
            rhs_ids = _collect_identifiers_from_ast(value_node)
            if rhs_ids and (rhs_ids & controllable_local):
                controllable_local.add(name)
                changed = True

    def _process_assignment(assign_node):
        nonlocal changed
        left = None
        right = None
        found_eq = False
        for child in assign_node.children:
            if child.type == "=" or child.type.endswith("_assignment"):
                found_eq = True
                continue
            if not found_eq:
                left = child
            else:
                if right is None:
                    right = child

        if left and right:
            lhs_name = ""
            if left.type == "identifier":
                lhs_name = _node_text(left)
            elif left.type == "subscript_expression":
                arr = left.child_by_field_name("array") or left.child_by_field_name("argument")
                if arr and arr.type == "identifier":
                    lhs_name = _node_text(arr)

            if lhs_name and lhs_name not in controllable_local:
                rhs_ids = _collect_identifiers_from_ast(right)
                if rhs_ids and (rhs_ids & controllable_local):
                    controllable_local.add(lhs_name)
                    changed = True

    _walk(body_node)
    return changed


def _collect_return_values(body_node):
    """从函数体 AST 中收集所有 return 语句的返回值。

    返回 [(expr_text, expr_node), ...]
    """
    results = []

    def _walk(node):
        if node.type == "return_statement":
            for child in node.children:
                if child.type in ("return", ";") or child.type.endswith("_comment"):
                    continue
                results.append((_node_text(child), child))
                break  # 通常只取第一个表达式
        else:
            for child in node.children:
                _walk(child)

    _walk(body_node)
    return results


# ---------------------------------------------------------------------------
# scan_parser — 入口
# ---------------------------------------------------------------------------

def scan_parser(rule_match, vul_lineno, file_path,
                repair_functions=None, controlled_params=None,
                svid=None, is_config_vuln=False):
    """C/C++ AST 扫描入口

    :param rule_match: 规则匹配的函数名列表
    :param vul_lineno: 漏洞行号
    :param file_path: 文件路径
    :param repair_functions: 修复函数列表
    :param controlled_params: 可控参数列表
    :param svid: 规则编号
    :param is_config_vuln: 是否配置型漏洞
    :return: 扫描结果列表

    返回格式（与所有语言一致）：
        [{"code": 1, "vul_func": "system", "param": "cmd", "language": "c",
          "source_file": "...", "source_lineno": 10}]
    code 含义：1=可控, 2=已修复, 3=未确认, 4=NewFunction, -1=不可控
    """
    global scan_results, is_repair_functions, is_controlled_params, scan_chain

    if repair_functions is None:
        repair_functions = []
    if controlled_params is None:
        controlled_params = []

    # 保存到模块全局（与其他引擎一致）
    is_repair_functions = repair_functions
    is_controlled_params = controlled_params

    # ---- 预建函数定义索引 ----
    _build_func_def_index(file_path)
    _build_func_def_index_cross_file()

    # ---- 初始化函数摘要 ----
    global _summaries_initialized
    _summaries_initialized = False
    _init_function_summaries(file_path)

    results = []

    try:
        vul_lineno = int(vul_lineno)
    except (ValueError, TypeError):
        logger.warning("[AST][C] Invalid vul_lineno: {}".format(vul_lineno))
        return results

    # 获取源码行
    line_text = _c_line_to_text(file_path, vul_lineno)
    if not line_text:
        logger.warning("[AST][C] Cannot read line {} from {}".format(vul_lineno, file_path))
        return results

    logger.debug("[AST][C] Scanning line {}: {}".format(vul_lineno, line_text))

    # 检查行中是否包含规则匹配的函数
    matched_func = None
    for func in rule_match:
        clean_func = func.replace("\\.", ".").replace("\\(", "(").replace("\\)", ")")
        if clean_func in line_text:
            matched_func = clean_func
            break

    if not matched_func:
        # 模糊匹配
        for func in rule_match:
            clean_func = func.replace("\\.", ".").replace("\\(", "(").replace("\\)", ")")
            parts = clean_func.split(".")
            if any(p in line_text for p in parts if len(p) > 2):
                matched_func = clean_func
                break

    if not matched_func:
        logger.debug("[AST][C] No matching function found in line")
        return results

    # ---- tree-sitter 解析 AST ----
    ast_tree = _parse_c_ast(file_path)
    call_node = None
    ast_args = []

    if ast_tree is not None:
        call_node = _find_call_at_line(ast_tree, vul_lineno, matched_func)
        if call_node is not None:
            ast_args = _get_call_args_from_ast(call_node)

    # AST 提取成功 → 用 AST 节点分析参数
    if ast_args:
        # 检查内置知识库
        knowledge = lookup_builtin(matched_func)
        if knowledge and knowledge.get("safe"):
            results.append({"code": -1, "chain": []})
            return results

        for arg_idx, arg_node in enumerate(ast_args):
            arg_text = _node_text(arg_node)

            # 字面量 → 跳过
            if _is_literal_node(arg_node):
                logger.debug("[AST][C] Arg[{}] is literal: {}".format(arg_idx, arg_text))
                continue

            # 提取参数中的所有标识符
            var_names = _collect_identifiers_from_ast(arg_node)

            for var_name in var_names:
                # 直接可控源
                if _is_controllable_source(var_name, controlled_params):
                    logger.debug("[AST][C] Variable {} controllable".format(var_name))
                    source_lineno = vul_lineno  # 默认
                    # 尝试找到更精确的 source 行号
                    _, sl = _trace_variable_in_lines(
                        file_path, var_name, vul_lineno, vul_lineno,
                        repair_functions, controlled_params
                    )
                    if sl:
                        source_lineno = sl

                    results.append({
                        "code": 1,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": source_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results

                # 反向追踪
                trace_code, src_lineno = _trace_variable_in_lines(
                    file_path, var_name, vul_lineno, vul_lineno,
                    repair_functions, controlled_params
                )
                if trace_code == 1:
                    results.append({
                        "code": 1,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": src_lineno if src_lineno else vul_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results
                elif trace_code == 2:
                    results.append({
                        "code": 2,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": src_lineno if src_lineno else vul_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results
                elif trace_code == 3:
                    results.append({
                        "code": 3,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": src_lineno if src_lineno else vul_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results

        results.append({"code": -1, "chain": []})
        return results

    # ---- AST 未提取到参数，文本回退 ----
    # 从源码行提取参数
    args_str = _extract_args_from_line(line_text, matched_func)
    if args_str:
        for arg in _split_args_respecting_parens(args_str):
            arg = arg.strip()
            if not arg:
                continue
            # 跳过字面量
            if (arg.startswith('"') and arg.endswith('"')) or \
               (arg.startswith("'") and arg.endswith("'")):
                continue
            if re.match(r'^\d+(\.\d+)?$', arg):
                continue

            # 提取变量名
            var_names = re.findall(r'[a-zA-Z_]\w*', arg)
            for var_name in var_names:
                if _is_controllable_source(var_name, controlled_params):
                    results.append({
                        "code": 1,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": vul_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results

                trace_code, src_lineno = _trace_variable_in_lines(
                    file_path, var_name, vul_lineno, vul_lineno,
                    repair_functions, controlled_params
                )
                if trace_code == 1:
                    results.append({
                        "code": 1,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": src_lineno if src_lineno else vul_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results
                elif trace_code == 2:
                    results.append({
                        "code": 2,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": src_lineno if src_lineno else vul_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results
                elif trace_code == 3:
                    results.append({
                        "code": 3,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": src_lineno if src_lineno else vul_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results

    # ---- NewFunction / 配置型漏洞 ----
    if is_config_vuln:
        results.append({
            "code": 4,
            "vul_func": matched_func,
            "param": matched_func,
            "language": "c",
            "source_file": file_path,
            "source_lineno": vul_lineno,
        "chain": [],
        })
    else:
        results.append({"code": -1, "chain": []})

    scan_results = results
    return results


def _extract_args_from_line(line_text, func_name):
    """从代码行中提取函数调用的参数字符串（括号计数法）。"""
    idx = line_text.find(func_name + "(")
    if idx < 0:
        short_name = func_name.split("::")[-1] if "::" in func_name else func_name
        short_name = short_name.split(".")[-1] if "." in short_name else short_name
        idx = line_text.find(short_name + "(")
        if idx < 0:
            return None
        idx += len(short_name)
    else:
        idx += len(func_name)

    if idx >= len(line_text) or line_text[idx] != "(":
        return None

    depth = 0
    in_string = False
    string_char = None
    start = idx + 1
    for i in range(idx, len(line_text)):
        ch = line_text[i]
        if in_string:
            if ch == "\\" and i + 1 < len(line_text):
                continue
            if ch == string_char:
                in_string = False
            continue
        if ch in ("\"", "'"):
            in_string = True
            string_char = ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return line_text[start:i]
    return None


# ---------------------------------------------------------------------------
# analysis_params — CAST 跨文件分析接口
# ---------------------------------------------------------------------------

def analysis_params(param_name, parent_func_names, vul_function, lineno, file_path,
                    repair_functions=None, controlled_params=None, isexternal=False):
    """C/C++ 变量可控性分析（供 CAST 跨文件分析调用）

    :param param_name: 要追踪的变量名
    :param parent_func_names: 父函数名列表
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

    # 保存到模块全局
    global is_repair_functions, is_controlled_params
    is_repair_functions = repair_functions
    is_controlled_params = controlled_params

    # 预建函数定义索引
    _build_func_def_index(file_path)

    try:
        lineno = int(lineno)
    except (ValueError, TypeError):
        return -1, [], 0, []

    # 追踪变量
    trace_code, src_lineno = _trace_variable_in_lines(
        file_path, param_name, lineno, lineno,
        repair_functions, controlled_params
    )

    if trace_code == 1:
        return 1, controlled_params, lineno, [
            ("source", param_name, file_path, src_lineno if src_lineno else lineno)
        ]
    elif trace_code == 2:
        return 2, controlled_params, lineno, [
            ("repair", param_name, file_path, src_lineno if src_lineno else lineno)
        ]
    elif trace_code == 3:
        return 3, controlled_params, lineno, [
            ("unconfirmed", param_name, file_path, src_lineno if src_lineno else lineno)
        ]
    else:
        return -1, [], 0, []
