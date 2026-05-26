#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Python AST Parser — Python 反向污点追踪引擎
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    仿照 Java parser 实现，使用 Python 内置 ast 模块进行污点分析。

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""
import ast
import os
import re
import traceback

from utils.log import logger
from core.pretreatment import ast_object as _ast_object_singleton

# 全局状态（与 PHP/Java parser 保持一致的模式）
scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []

# 内置敏感函数列表（用于跨文件间接 sink 检测）
BUILTIN_SENSITIVE_SINKS = [
    'os.system', 'os.popen', 'os.spawnl', 'os.spawnlp', 'os.spawnv', 'os.spawnve',
    'subprocess.call', 'subprocess.run', 'subprocess.Popen', 'subprocess.check_output',
    'subprocess.check_call',
    'eval', 'exec', 'compile',
    'pickle.loads', 'pickle.load', 'yaml.load', 'yaml.unsafe_load',
    'requests.get', 'requests.post', 'requests.put', 'requests.delete',
    'urllib.request.urlopen', 'urllib.request.urlretrieve',
    'open', 'file',
    'socket.connect', 'socket.send',
]


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _parse_imports(tree, file_path):
    """解析 AST 中的 import 语句，返回 {imported_name: module_file_path} 映射
    
    支持:
      from helpers import run_command  →  {'run_command': '/path/helpers.py'}
      import helpers                   →  {'helpers': '/path/helpers.py'}
      from pkg.helpers import func     →  {'func': '/path/pkg/helpers.py'}
    """
    import_map = {}
    base_dir = os.path.dirname(file_path)
    
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module_name = node.module or ''
            # 尝试将模块名转换为文件路径
            module_path = _resolve_module_path(module_name, base_dir)
            if module_path:
                for alias in node.names:
                    name = alias.asname or alias.name
                    import_map[name] = module_path
                    
        elif isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name
                module_path = _resolve_module_path(name, base_dir)
                if module_path:
                    import_map[name] = module_path
    
    return import_map


def _resolve_module_path(module_name, base_dir):
    """尝试将 Python 模块名解析为文件路径"""
    parts = module_name.split('.')
    # 尝试 as file: base_dir/part1/part2/.../partN.py
    candidate = os.path.join(base_dir, *parts[:-1], parts[-1] + '.py') if parts else None
    if candidate and os.path.isfile(candidate):
        return os.path.normpath(candidate)
    # 尝试 as package: base_dir/part1/.../partN/__init__.py
    candidate = os.path.join(base_dir, *parts, '__init__.py')
    if os.path.isfile(candidate):
        return os.path.normpath(candidate)
    return None


def _resolve_variable_type(tree, var_name, target_line, import_map):
    """尝试推断变量的类型名（用于跨文件类方法追踪）
    
    ex = Executor(base) → 返回 'Executor'
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                tname = _get_name(t)
                if tname == var_name and isinstance(node.value, ast.Call):
                    # ex = Executor(...)
                    if isinstance(node.value.func, ast.Name):
                        return node.value.func.id
                    elif isinstance(node.value.func, ast.Attribute):
                        return node.value.func.attr
    return None


def _get_call_name(node):
    """从 ast.Call 节点提取完整函数调用名，如 os.system, subprocess.call, eval"""
    if not isinstance(node, ast.Call):
        return None

    func = node.func

    # direct call: eval(...)
    if isinstance(func, ast.Name):
        return func.id

    # attribute call: os.system(...), subprocess.call(...)
    if isinstance(func, ast.Attribute):
        parts = []
        current = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        parts.reverse()
        return '.'.join(parts)

    return None


def _get_name(node):
    """从 AST 节点提取变量名（支持 Name, Attribute, Subscript 等）"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _get_name(node.value)
        if base:
            return '{}.{}'.format(base, node.attr)
    if isinstance(node, ast.Subscript):
        return _get_name(node.value)
    if isinstance(node, ast.Starred):
        return _get_name(node.value)
    return None


def _contains_name(node, name):
    """检查 AST 节点（表达式）是否包含指定名称的变量"""
    if node is None:
        return False

    if isinstance(node, ast.Name):
        return node.id == name

    if isinstance(node, ast.BinOp):
        return _contains_name(node.left, name) or _contains_name(node.right, name)

    if isinstance(node, ast.BoolOp):
        return any(_contains_name(v, name) for v in node.values)

    if isinstance(node, ast.Compare):
        return _contains_name(node.left, name) or any(_contains_name(c, name) for c in node.comparators)

    if isinstance(node, ast.UnaryOp):
        return _contains_name(node.operand, name)

    if isinstance(node, ast.Call):
        # 检查函数名和参数
        if _contains_name(node.func, name):
            return True
        return any(_contains_name(arg, name) for arg in (node.args or []))

    if isinstance(node, ast.Attribute):
        return _contains_name(node.value, name)

    if isinstance(node, ast.Subscript):
        return _contains_name(node.value, name) or _contains_name(node.slice, name)

    if isinstance(node, ast.IfExp):
        return (_contains_name(node.test, name) or
                _contains_name(node.body, name) or
                _contains_name(node.orelse, name))

    if isinstance(node, ast.Lambda):
        # 不进入 lambda 体内搜索外部变量
        return False

    if isinstance(node, ast.JoinedStr):
        # f-string
        return any(_contains_name(v, name) for v in node.values
                    if isinstance(v, ast.FormattedValue))

    if isinstance(node, ast.FormattedValue):
        return _contains_name(node.value, name)

    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_contains_name(elt, name) for elt in node.elts)

    if isinstance(node, ast.Dict):
        return (any(_contains_name(k, name) for k in (node.keys or []) if k) or
                any(_contains_name(v, name) for v in (node.values or [])))

    if isinstance(node, ast.Starred):
        return _contains_name(node.value, name)

    if isinstance(node, ast.Constant):
        return False

    return False


def _collect_names(node, names=None):
    """递归收集表达式中所有变量名"""
    if names is None:
        names = set()

    if node is None:
        return names

    if isinstance(node, ast.Name):
        names.add(node.id)

    elif isinstance(node, ast.BinOp):
        _collect_names(node.left, names)
        _collect_names(node.right, names)

    elif isinstance(node, ast.BoolOp):
        for v in node.values:
            _collect_names(v, names)

    elif isinstance(node, ast.UnaryOp):
        _collect_names(node.operand, names)

    elif isinstance(node, ast.Call):
        _collect_names(node.func, names)
        for arg in (node.args or []):
            _collect_names(arg, names)
        for kw in (node.keywords or []):
            _collect_names(kw.value, names)

    elif isinstance(node, ast.Attribute):
        # 保留完整属性名（如 self.base, obj.attr），而不是只取 value
        full_name = _get_name(node)
        if full_name:
            names.add(full_name)
        else:
            _collect_names(node.value, names)

    elif isinstance(node, ast.Subscript):
        _collect_names(node.value, names)
        _collect_names(node.slice, names)

    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            _collect_names(elt, names)

    elif isinstance(node, ast.JoinedStr):
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                _collect_names(v.value, names)

    elif isinstance(node, ast.IfExp):
        _collect_names(node.test, names)
        _collect_names(node.body, names)
        _collect_names(node.orelse, names)

    elif isinstance(node, ast.Dict):
        for k in (node.keys or []):
            if k:
                _collect_names(k, names)
        for v in (node.values or []):
            _collect_names(v, names)

    return names


def _expr_to_str(node):
    """将 AST 表达式转为可读字符串（简化版）"""
    if node is None:
        return ''
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant):
        return repr(node.value)
    if isinstance(node, ast.Attribute):
        base = _expr_to_str(node.value)
        return '{}.{}'.format(base, node.attr) if base else node.attr
    if isinstance(node, ast.Call):
        return '{}(...)'.format(_get_call_name(node) or '...')
    if isinstance(node, ast.BinOp):
        return '{} + {}'.format(_expr_to_str(node.left), _expr_to_str(node.right))
    if isinstance(node, ast.Subscript):
        return '{}[...]'.format(_expr_to_str(node.value))
    return ast.dump(node)[:80]


# ---------------------------------------------------------------------------
# 污点判断
# ---------------------------------------------------------------------------

def is_controllable(expr_str, controlled_params=None):
    """检查表达式字符串是否包含可控输入源"""
    if controlled_params is None:
        controlled_params = is_controlled_params

    if not controlled_params:
        return False

    for cp in controlled_params:
        if cp in expr_str:
            return True
        # 特殊处理：可控源是 func() 形式，表达式是 func(...) 或纯 func 名
        if cp.endswith('()'):
            func_name = cp[:-2]
            if expr_str == func_name or expr_str.startswith(func_name + '('):
                return True

    return False


def is_repair(expr_str, repair_functions=None):
    """检查表达式字符串是否包含修复函数"""
    if repair_functions is None:
        repair_functions = is_repair_functions

    if not repair_functions:
        return False

    for rf in repair_functions:
        if rf in expr_str:
            return True
    return False


# ---------------------------------------------------------------------------
# 核心反向追踪
# ---------------------------------------------------------------------------

def parameters_back(param_name, nodes, vul_lineno, file_path,
                     repair_functions=None, controlled_params=None,
                     visited_funcs=None, depth=0):
    """
    从 vul_lineno 行向上遍历 AST 节点，反向追踪 param_name 的数据流来源。

    返回值:
        1  — 可控（污点到达用户输入源）
        2  — 已修复（经过修复函数处理）
        3  — 未确认
        4  — 新漏洞函数（追踪到函数参数，需要生成新规则）
        5  — global 变量
        -1 — 不可控
    """
    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params
    if visited_funcs is None:
        visited_funcs = set()

    if depth > 10:
        return -1, None

    tree = _ast_object_singleton.get_nodes(file_path)
    if not tree or not hasattr(tree, 'body'):
        return -1, None

    # 收集 vul_lineno 之前的所有顶层语句
    all_stmts = tree.body
    relevant_stmts = [s for s in all_stmts
                       if hasattr(s, 'lineno') and s.lineno <= int(vul_lineno)]

    # 找到包含 vul_lineno 的函数（如果有的话）
    func_node = _find_function_at_line(tree, int(vul_lineno))

    if func_node:
        # 在函数内追踪
        return _trace_in_function(param_name, func_node, int(vul_lineno),
                                   file_path, repair_functions, controlled_params,
                                   visited_funcs, depth, tree)
    else:
        # 模块级别追踪
        return _trace_in_stmts(param_name, relevant_stmts, int(vul_lineno),
                                file_path, repair_functions, controlled_params,
                                visited_funcs, depth, tree)


def _find_function_at_line(tree, target_line):
    """找到包含目标行号的函数定义"""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if hasattr(node, 'lineno') and hasattr(node, 'end_lineno') and node.end_lineno:
                if node.lineno <= target_line <= node.end_lineno:
                    return node
            elif hasattr(node, 'lineno') and node.lineno <= target_line:
                # fallback: 没有 end_lineno，估算到下一个同级节点
                return node
    return None


def _find_class_at_line(tree, target_line):
    """找到包含目标行号的类定义"""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            if hasattr(node, 'lineno') and hasattr(node, 'end_lineno') and node.end_lineno:
                if node.lineno <= target_line <= node.end_lineno:
                    return node
    return None


def _find_class_containing_method(tree, method_node):
    """找到包含指定方法的类定义"""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if item is method_node:
                    return node
    return None


def _trace_self_attribute(attr_name, class_node, vul_lineno, file_path,
                           repair_functions, controlled_params,
                           visited_funcs, depth, tree):
    """追踪 self.xxx 属性的来源
    
    在类的 __init__ 方法中查找 self.xxx = expr 赋值，
    然后追踪 expr 的来源（通常是构造函数参数）。
    
    返回值同 parameters_back: (code, source)
    """
    # 提取属性名（去掉 self. 前缀）
    # attr_name = 'self.base' → attr = 'base'
    if not attr_name.startswith('self.'):
        return None
    attr = attr_name[5:]  # 去掉 'self.'

    # 在类中查找 __init__ 方法
    init_method = None
    for item in class_node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == '__init__':
            init_method = item
            break

    if not init_method:
        # 没有 __init__，可能在类级别直接定义（class attribute）
        for item in class_node.body:
            if isinstance(item, ast.Assign):
                for t in item.targets:
                    if _get_name(t) == attr_name:
                        return _trace_expr(attr_name, item.value, item.lineno, file_path,
                                            repair_functions, controlled_params,
                                            visited_funcs, depth, tree)
        return None

    # 在 __init__ 体内查找 self.attr = expr
    for stmt in init_method.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                target_name = _get_name(target)
                if target_name == attr_name:
                    logger.debug("[AST][Python] Tracing self attribute: {} = expr at L{}".format(
                        attr_name, stmt.lineno))
                    # 追踪右部表达式
                    result = _trace_expr(attr_name, stmt.value, stmt.lineno, file_path,
                                          repair_functions, controlled_params,
                                          visited_funcs, depth, tree)
                    if result and result[0] != -1:
                        return result
                    # 如果 _trace_expr 返回 -1 或 None，检查右部是否是构造函数参数
                    rhs_name = _get_name(stmt.value)
                    if rhs_name:
                        # 检查是否是 __init__ 的参数（排除 self）
                        for arg in init_method.args.args:
                            if arg.arg == rhs_name and arg.arg != 'self':
                                logger.debug("[AST][Python] self.{} comes from __init__ param {}".format(
                                    attr, rhs_name))
                                return 4, init_method

    return None


def _trace_in_function(param_name, func_node, vul_lineno, file_path,
                        repair_functions, controlled_params,
                        visited_funcs, depth, tree):
    """在函数体内追踪变量来源"""
    # 注意：不把当前函数名加入 visited_funcs
    # 因为同一函数内可能需要追踪多个变量的来源（如 full_cmd → arg）
    # visited_funcs 用于防止跨函数循环追踪，由 parameters_back 的调用者管理

    stmts = func_node.body
    return _trace_in_stmts(param_name, stmts, vul_lineno, file_path,
                            repair_functions, controlled_params,
                            visited_funcs, depth, tree,
                            func_node=func_node)


def _trace_in_stmts(param_name, stmts, vul_lineno, file_path,
                     repair_functions, controlled_params,
                     visited_funcs, depth, tree,
                     func_node=None):
    """在语句列表中反向追踪变量来源"""

    # 过滤出 vul_lineno 之前的语句，倒序遍历
    prior_stmts = []
    for s in stmts:
        if hasattr(s, 'lineno') and s.lineno <= vul_lineno:
            prior_stmts.append(s)

    for stmt in reversed(prior_stmts):
        result = _trace_stmt(param_name, stmt, vul_lineno, file_path,
                              repair_functions, controlled_params,
                              visited_funcs, depth, tree, func_node)
        if result is not None:
            return result

    # 如果在函数内且没找到赋值，检查是否是函数参数
    if func_node and isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for arg in func_node.args.args:
            if arg.arg == param_name:
                logger.debug("[AST][Python] Param {} is function argument of {}".format(
                    param_name, func_node.name))
                # 返回 code 4：新漏洞函数
                return 4, func_node

    # 如果是 self.xxx 属性，到 __init__ 中查找赋值
    if func_node and param_name.startswith('self.'):
        class_node = _find_class_containing_method(tree, func_node)
        if class_node:
            attr_result = _trace_self_attribute(param_name, class_node, vul_lineno, file_path,
                                                  repair_functions, controlled_params,
                                                  visited_funcs, depth, tree)
            if attr_result is not None:
                return attr_result

    # 如果是 global 声明的变量
    if func_node:
        for s in func_node.body:
            if isinstance(s, ast.Global) and param_name in s.names:
                logger.debug("[AST][Python] Param {} is global variable".format(param_name))
                return 5, None

    return -1, None


def _trace_stmt(param_name, stmt, vul_lineno, file_path,
                 repair_functions, controlled_params,
                 visited_funcs, depth, tree, func_node):
    """处理单个语句的追踪逻辑"""

    # --- 赋值语句: x = expr ---
    if isinstance(stmt, ast.Assign):
        for target in stmt.targets:
            target_name = _get_name(target)
            if target_name == param_name:
                # 找到赋值，追踪右部表达式
                return _trace_expr(param_name, stmt.value, stmt.lineno, file_path,
                                    repair_functions, controlled_params,
                                    visited_funcs, depth, tree)

    # --- 增量赋值: x += expr ---
    elif isinstance(stmt, ast.AugAssign):
        target_name = _get_name(stmt.target)
        if target_name == param_name:
            return _trace_expr(param_name, stmt.value, stmt.lineno, file_path,
                                repair_functions, controlled_params,
                                visited_funcs, depth, tree)

    # --- 注入赋值: x: type = expr ---
    elif isinstance(stmt, ast.AnnAssign) and stmt.value:
        target_name = _get_name(stmt.target)
        if target_name == param_name:
            return _trace_expr(param_name, stmt.value, stmt.lineno, file_path,
                                repair_functions, controlled_params,
                                visited_funcs, depth, tree)

    # --- with 语句: with open(...) as f ---
    elif isinstance(stmt, ast.With):
        for item in stmt.items:
            if item.optional_vars:
                var_name = _get_name(item.optional_vars)
                if var_name == param_name:
                    return _trace_expr(param_name, item.context_expr, stmt.lineno,
                                        file_path, repair_functions, controlled_params,
                                        visited_funcs, depth, tree)
        # 在 with 体内继续搜索
        result = _trace_in_stmts(param_name, stmt.body, vul_lineno, file_path,
                                  repair_functions, controlled_params,
                                  visited_funcs, depth, tree, func_node)
        if result and result[0] != -1:
            return result

    # --- if 语句 ---
    elif isinstance(stmt, ast.If):
        # 先搜 if 体
        result = _trace_in_stmts(param_name, stmt.body, vul_lineno, file_path,
                                  repair_functions, controlled_params,
                                  visited_funcs, depth, tree, func_node)
        if result and result[0] != -1:
            return result
        # 再搜 else/elif 体
        if stmt.orelse:
            result = _trace_in_stmts(param_name, stmt.orelse, vul_lineno, file_path,
                                      repair_functions, controlled_params,
                                      visited_funcs, depth, tree, func_node)
            if result and result[0] != -1:
                return result

    # --- for 循环 ---
    elif isinstance(stmt, ast.For):
        # 检查循环变量
        target_name = _get_name(stmt.target)
        if target_name == param_name:
            return _trace_expr(param_name, stmt.iter, stmt.lineno, file_path,
                                repair_functions, controlled_params,
                                visited_funcs, depth, tree)
        # 在循环体内搜索
        result = _trace_in_stmts(param_name, stmt.body, vul_lineno, file_path,
                                  repair_functions, controlled_params,
                                  visited_funcs, depth, tree, func_node)
        if result and result[0] != -1:
            return result

    # --- while 循环 ---
    elif isinstance(stmt, ast.While):
        result = _trace_in_stmts(param_name, stmt.body, vul_lineno, file_path,
                                  repair_functions, controlled_params,
                                  visited_funcs, depth, tree, func_node)
        if result and result[0] != -1:
            return result

    # --- try/except ---
    elif isinstance(stmt, ast.Try):
        for block in [stmt.body, stmt.handlers, stmt.orelse, stmt.finalbody]:
            if not block:
                continue
            if isinstance(block, list):
                # except handlers 是 ExceptHandler 对象列表
                if block and isinstance(block[0], ast.ExceptHandler):
                    for handler in block:
                        result = _trace_in_stmts(param_name, handler.body, vul_lineno,
                                                  file_path, repair_functions, controlled_params,
                                                  visited_funcs, depth, tree, func_node)
                        if result and result[0] != -1:
                            return result
                else:
                    result = _trace_in_stmts(param_name, block, vul_lineno, file_path,
                                              repair_functions, controlled_params,
                                              visited_funcs, depth, tree, func_node)
                    if result and result[0] != -1:
                        return result

    # --- return 语句 ---
    # return 语句不阻断追踪：变量出现在 return 中只是说明它被使用了，
    # 不影响在之前的赋值语句中找到它的来源
    # （不返回任何结果，让遍历继续到之前的赋值语句）

    return None


def _trace_expr(param_name, expr, lineno, file_path,
                 repair_functions, controlled_params,
                 visited_funcs, depth, tree):
    """追踪表达式的来源"""

    expr_str = _expr_to_str(expr)

    # 1. 检查是否是可控输入源
    if is_controllable(expr_str, controlled_params):
        logger.debug("[AST][Python] Found controllable source: {} at line {}".format(expr_str, lineno))
        return 1, expr_str

    # 2. 检查是否经过修复函数
    if is_repair(expr_str, repair_functions):
        logger.debug("[AST][Python] Found repair function: {} at line {}".format(expr_str, lineno))
        return 2, expr_str

    # 3. 如果表达式是函数调用，检查参数
    if isinstance(expr, ast.Call):
        call_name = _get_call_name(expr)
        # 检查调用参数中是否包含可控变量
        for arg in (expr.args or []):
            arg_str = _expr_to_str(arg)
            if is_controllable(arg_str, controlled_params):
                logger.debug("[AST][Python] Call {} with controllable arg: {}".format(call_name, arg_str))
                return 1, arg_str

            # 递归追踪参数
            arg_names = _collect_names(arg)
            for an in arg_names:
                result = parameters_back(an, [], lineno, file_path,
                                          repair_functions, controlled_params,
                                          visited_funcs, depth + 1)
                if result and result[0] in (1, 2):
                    return result

        # .format() 调用检查: "str".format(x) — x 可控则结果可控
        if isinstance(expr.func, ast.Attribute) and expr.func.attr == 'format':
            for arg in (expr.args or []):
                result = _trace_expr(param_name, arg, lineno, file_path,
                                      repair_functions, controlled_params,
                                      visited_funcs, depth, tree)
                if result and result[0] in (1, 2):
                    return result
            for kw in (expr.keywords or []):
                result = _trace_expr(param_name, kw.value, lineno, file_path,
                                      repair_functions, controlled_params,
                                      visited_funcs, depth, tree)
                if result and result[0] in (1, 2):
                    return result

        # 检查是否是修复函数调用
        if call_name and is_repair(call_name, repair_functions):
            return 2, call_name

        # 尝试进入函数定义追踪
        if call_name:
            func_def = _find_function_def(tree, call_name)
            if func_def and call_name not in visited_funcs:
                logger.debug("[AST][Python] Entering function {} for tracing".format(call_name))
                return _trace_function_return(func_def, expr, lineno, file_path,
                                               repair_functions, controlled_params,
                                               visited_funcs, depth, tree)

    # 4. 如果是二元运算，收集两边变量名并反向追踪
    if isinstance(expr, ast.BinOp):
        names = _collect_names(expr)
        for name in names:
            result = parameters_back(name, [], lineno, file_path,
                                      repair_functions, controlled_params,
                                      visited_funcs, depth + 1)
            if result and result[0] in (1, 2):
                return result
        # fallback: 递归检查子表达式
        result = _trace_expr(param_name, expr.left, lineno, file_path,
                              repair_functions, controlled_params,
                              visited_funcs, depth, tree)
        if result and result[0] in (1, 2):
            return result
        result = _trace_expr(param_name, expr.right, lineno, file_path,
                              repair_functions, controlled_params,
                              visited_funcs, depth, tree)
        if result and result[0] in (1, 2):
            return result

    # 5. f-string (JoinedStr)
    if isinstance(expr, ast.JoinedStr):
        for v in expr.values:
            if isinstance(v, ast.FormattedValue):
                result = _trace_expr(param_name, v.value, lineno, file_path,
                                      repair_functions, controlled_params,
                                      visited_funcs, depth, tree)
                if result and result[0] in (1, 2):
                    return result

    # 6. Subscript: x[0], x[key] — 追踪基础对象
    if isinstance(expr, ast.Subscript):
        result = _trace_expr(param_name, expr.value, lineno, file_path,
                              repair_functions, controlled_params,
                              visited_funcs, depth, tree)
        if result and result[0] in (1, 2):
            return result

    # 7. 如果表达式包含变量名，继续反向追踪这些变量
    names = _collect_names(expr)
    code4_candidates = []
    for name in names:
        result = parameters_back(name, [], lineno, file_path,
                                  repair_functions, controlled_params,
                                  visited_funcs, depth + 1)
        if result and result[0] in (1, 2):
            return result
        if result and result[0] == 4:
            code4_candidates.append(result)

    # code=4 候选排序：__init__ 优先级最低（需要类名匹配才能解析），
    # 普通函数优先级更高（有明确的调用者匹配）
    if code4_candidates:
        code4_candidates.sort(key=lambda r: 1 if hasattr(r[1], 'name') and r[1].name == '__init__' else 0)
        return code4_candidates[0]

    return 3, None


def _find_function_def(tree, func_name):
    """在 AST 树中查找函数定义"""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == func_name:
                return node
    return None


def _trace_function_return(func_def, call_node, lineno, file_path,
                            repair_functions, controlled_params,
                            visited_funcs, depth, tree):
    """追踪函数的返回值是否可控"""
    func_name = func_def.name

    # 建立参数映射：调用实参 → 函数形参
    arg_map = {}
    func_args = func_def.args.args
    call_args = call_node.args or []

    # 收集哪些形参对应的实参是可控的
    controllable_param_names = set()
    for i, param in enumerate(func_args):
        if i < len(call_args):
            arg_str = _expr_to_str(call_args[i])
            arg_map[param.arg] = arg_str
            # 检查实参是否可控（直接或通过变量追踪）
            if is_controllable(arg_str, controlled_params):
                controllable_param_names.add(param.arg)
            else:
                # 反向追踪实参中的变量
                arg_names = _collect_names(call_args[i])
                for an in arg_names:
                    code, _ = parameters_back(an, [], lineno, file_path,
                                              repair_functions, controlled_params,
                                              visited_funcs, depth + 1)
                    if code == 1:
                        controllable_param_names.add(param.arg)
                        break

    # 在函数体内做赋值链传播：如果赋值右边包含可控形参，左边也标记可控
    controllable_local = set(controllable_param_names)
    for _ in range(3):  # 迭代传播
        for stmt in func_def.body:
            if isinstance(stmt, ast.Assign) and stmt.value:
                for target in stmt.targets:
                    tname = _get_name(target)
                    if tname and tname not in controllable_local:
                        rhs_names = _collect_names(stmt.value)
                        if rhs_names & controllable_local:
                            controllable_local.add(tname)

    # 在函数体中查找 return 语句
    for node in ast.walk(func_def):
        if isinstance(node, ast.Return) and node.value:
            # 先检查返回值表达式本身是否是可控源
            return_str = _expr_to_str(node.value)
            if is_controllable(return_str, controlled_params):
                logger.debug("[AST][Python] Function {} returns controllable source directly: {}".format(
                    func_name, return_str))
                return 1, return_str

            # 检查返回值中引用的变量是否可控
            # 先反向追踪：如果返回的变量是可控的
            return_names = _collect_names(node.value)
            for rn in return_names:
                code, cp = parameters_back(rn, [], node.lineno if hasattr(node, 'lineno') else lineno,
                                            file_path, repair_functions, controlled_params,
                                            visited_funcs, depth + 1)
                if code == 1:
                    logger.debug("[AST][Python] Function {} returns controllable var {} via parameters_back".format(
                        func_name, rn))
                    return 1, cp

            # 检查返回值是否包含可控局部变量（赋值链传播结果）
            matched = return_names & controllable_local
            if matched:
                # 找到匹配的可控变量，获取其来源
                for var_name in matched:
                    if var_name in arg_map:
                        src = arg_map[var_name]
                        logger.debug("[AST][Python] Function {} returns controllable param {} (source: {})".format(
                            func_name, var_name, src))
                        return 1, src
                    else:
                        # 局部变量间接传播到 return
                        logger.debug("[AST][Python] Function {} returns controllable local var {}".format(
                            func_name, var_name))
                        return 1, var_name

            # fallback: 文本匹配
            return_str = _expr_to_str(node.value)
            for param_name, arg_str in arg_map.items():
                if is_controllable(arg_str, controlled_params):
                    if param_name in return_str or _contains_name(node.value, param_name):
                        logger.debug("[AST][Python] Function {} returns controllable param {} (text match)".format(
                            func_name, param_name))
                        return 1, arg_str

    return 3, None


# ---------------------------------------------------------------------------
# 入口函数
# ---------------------------------------------------------------------------

def scan_parser(sensitive_func, vul_lineno, file_path, repair_functions=[], controlled_params=[], svid=None):
    """
    Python AST scan parser - 分析敏感函数参数是否可控

    :param sensitive_func: 要检测的敏感函数列表，如 ["os.system", "eval"]
    :param vul_lineno: 漏洞函数所在行号
    :param file_path: 文件路径
    :param repair_functions: 修复函数列表
    :param controlled_params: 可控参数列表
    :param svid: 规则 ID
    :return: scan_results 列表，每个元素是 {"code": N, "chain": [...], "source": ...}
    """
    global scan_results, is_repair_functions, is_controlled_params, scan_chain

    try:
        scan_chain = ["start"]
        scan_results = []
        is_repair_functions = repair_functions
        is_controlled_params = controlled_params

        if _ast_object_singleton is None:
            logger.debug("[AST][Python] ast_object is None, skip")
            return scan_results

        tree = _ast_object_singleton.get_nodes(file_path)
        if not tree or not hasattr(tree, 'body'):
            logger.debug("[AST][Python] No AST nodes for {}".format(file_path))
            return scan_results

        target_line = int(vul_lineno)

        # 解析 import 语句，用于跨文件追踪
        import_map = _parse_imports(tree, file_path)

        # 读取源码行用于日志
        source_lines = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                source_lines = f.readlines()
        except Exception:
            pass

        # 在 AST 中查找在目标行调用了敏感函数的节点
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = _get_call_name(node)
            if not call_name:
                continue

            # 检查是否匹配敏感函数（支持 module.func 和纯 func 匹配）
            matched = False
            for sf in sensitive_func:
                if call_name == sf or call_name.endswith('.' + sf):
                    matched = True
                    break
            if not matched:
                continue

            # 检查行号
            if not hasattr(node, 'lineno') or node.lineno != target_line:
                continue

            logger.debug("[AST][Python] Found sensitive call: {}() at line {}".format(call_name, target_line))

            # ---- 赋值链迭代传播 ----
            # 找到目标行所在的函数，在函数内做变量传播：
            # 如果 x = tainted_var，则 x 也标记为可控
            func_node = _find_function_at_line(tree, target_line)
            extra_controlled = set()
            if func_node:
                # 收集函数体内所有赋值关系: {lhs: set_of_rhs_names}
                assign_map = {}
                for s in ast.walk(func_node):
                    if isinstance(s, ast.Assign) and s.value:
                        for t in s.targets:
                            tname = _get_name(t)
                            if tname:
                                assign_map[tname] = _collect_names(s.value)

                # 第一轮：用 parameters_back 标记 rhs 中可控的变量
                for lhs_name, rhs_names in assign_map.items():
                    for rn in rhs_names:
                        code, _ = parameters_back(rn, [], target_line, file_path,
                                                   repair_functions, controlled_params)
                        if code == 1:
                            extra_controlled.add(lhs_name)
                            break

                # 后续迭代传播：如果 rhs 包含已传播变量，lhs 也标记
                changed = True
                iterations = 0
                while changed and iterations < 5:
                    changed = False
                    iterations += 1
                    for lhs_name, rhs_names in assign_map.items():
                        if lhs_name in extra_controlled:
                            continue
                        if rhs_names & extra_controlled:
                            extra_controlled.add(lhs_name)
                            changed = True

            extended_controlled = list(controlled_params) + list(extra_controlled)

            # 分析每个参数
            for arg in (node.args or []):
                arg_str = _expr_to_str(arg)

                # 直接检查参数是否是可控源（含传播后的变量）
                if is_controllable(arg_str, extended_controlled):
                    chain = ["{}:{}".format(target_line, source_lines[target_line - 1].strip() if target_line <= len(source_lines) else arg_str)]
                    scan_results.append({"code": 1, "chain": chain, "source": arg_str})
                    break

                # 收集参数中的变量名，反向追踪
                arg_names = _collect_names(arg)
                for an in arg_names:
                    code, cp = parameters_back(an, [], target_line, file_path,
                                                repair_functions, extended_controlled)

                    chain = ["{}:{}".format(target_line, source_lines[target_line - 1].strip() if target_line <= len(source_lines) else arg_str)]

                    if code == 1:
                        scan_results.append({"code": 1, "chain": chain, "source": cp})
                        break
                    elif code == 2:
                        scan_results.append({"code": 2, "chain": chain, "source": cp})
                        break
                    elif code == 4:
                        # code=4: 变量是函数参数，需要继续追踪
                        # cp 是包含该参数的 FunctionDef 对象
                        # 策略：检查该函数是否包含敏感函数调用（参数间接流入 sink）
                        # 同时检查调用处的实参是否可控
                        func_def = cp
                        if isinstance(func_def, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            # 检查函数体内是否有敏感调用
                            has_sink = False
                            for inner_node in ast.walk(func_def):
                                if isinstance(inner_node, ast.Call):
                                    inner_name = _get_call_name(inner_node)
                                    if inner_name:
                                        for sf in sensitive_func:
                                            if inner_name == sf or inner_name.endswith('.' + sf):
                                                has_sink = True
                                                break
                                    if has_sink:
                                        break

                            if has_sink:
                                # 确定要匹配的调用名
                                # __init__ → 用类名匹配 ClassName(...)
                                # 普通方法 → 用函数名匹配
                                call_names_to_match = [func_def.name]
                                if func_def.name == '__init__':
                                    # 找到 __init__ 所属的类，用类名匹配
                                    parent_class = _find_class_containing_method(tree, func_def)
                                    if parent_class:
                                        call_names_to_match = [parent_class.name]

                                # 在整个文件中查找谁调用了这个函数
                                for caller_node in ast.walk(tree):
                                    if isinstance(caller_node, ast.Call):
                                        cn = _get_call_name(caller_node)
                                        matched = False
                                        for match_name in call_names_to_match:
                                            if cn and (cn == match_name or cn.endswith('.' + match_name)):
                                                matched = True
                                                break
                                        if matched and hasattr(caller_node, 'lineno'):
                                            # 找到调用点，检查实参
                                            for caller_arg in (caller_node.args or []):
                                                ca_str = _expr_to_str(caller_arg)
                                                if is_controllable(ca_str, extended_controlled):
                                                    scan_results.append({"code": 1, "chain": chain, "source": ca_str})
                                                    break
                                                # 反向追踪实参
                                                ca_names = _collect_names(caller_arg)
                                                for can in ca_names:
                                                    ccode, ccp = parameters_back(can, [], caller_node.lineno, file_path,
                                                                                  repair_functions, extended_controlled)
                                                    if ccode == 1:
                                                        scan_results.append({"code": 1, "chain": chain, "source": ccp})
                                                        break
                                                if scan_results:
                                                    break
                                            break  # 只处理第一个调用点
                                if scan_results:
                                    break

                        if not scan_results:
                            scan_results.append({"code": 4, "chain": chain, "source": arg_str})
                        break
                    elif code == 3:
                        scan_results.append({"code": 3, "chain": chain, "source": cp})
                else:
                    continue
                break

            if not scan_results:
                # 没有在当前文件找到敏感调用，尝试跨文件追踪
                # 检查目标行调用的函数是否是从其他文件 import 的
                cross_file_result = _try_cross_file_trace(
                    tree, target_line, sensitive_func, file_path,
                    repair_functions, controlled_params, import_map, source_lines)
                if cross_file_result:
                    scan_results = cross_file_result
                else:
                    # 最终 fallback
                    chain = ["{}:{}".format(target_line, source_lines[target_line - 1].strip() if target_line <= len(source_lines) else call_name)]
                    scan_results.append({"code": -1, "chain": chain, "source": None})

            # 只处理第一个匹配的调用
            break

        # 如果主循环没有匹配到任何敏感函数调用，尝试跨文件追踪
        if not scan_results and import_map:
            cross_file_result = _try_cross_file_trace(
                tree, target_line, sensitive_func, file_path,
                repair_functions, controlled_params, import_map, source_lines)
            if cross_file_result:
                scan_results = cross_file_result

    except Exception:
        logger.warning("[AST][Python] scan_parser error: {}".format(traceback.format_exc()))

    return scan_results


def _try_cross_file_trace(tree, target_line, sensitive_func, file_path,
                           repair_functions, controlled_params, import_map, source_lines):
    """跨文件追踪：检查目标行调用的 import 函数内部是否包含敏感调用"""
    
    # 找到目标行的所有调用
    target_calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and hasattr(node, 'lineno') and node.lineno == target_line:
            call_name = _get_call_name(node)
            if call_name:
                target_calls.append((call_name, node))
    
    if not target_calls:
        return None
    
    for call_name, call_node in target_calls:
        # 提取被调用的函数名（去掉对象前缀）
        func_name = call_name.split('.')[-1] if '.' in call_name else call_name
        
        # 尝试多种匹配策略：
        # 1. 函数名直接在 import_map 中（如 run_command）
        # 2. 对象的类名在 import_map 中（如 Executor → ex.run()）
        # 3. 完整调用名在 import_map 中
        imported_path = None
        imported_func_name = func_name
        is_class_method = False
        
        if func_name in import_map:
            imported_path = import_map[func_name]
        elif '.' in call_name:
            # ex.run() → obj_name='ex', 尝试从 import_map 找 ex 对应的类
            # 也尝试直接匹配完整名
            if call_name in import_map:
                imported_path = import_map[call_name]
            else:
                # 尝试从当前 AST 中找到 ex 的类型
                obj_name = call_name.split('.')[0]
                obj_type = _resolve_variable_type(tree, obj_name, target_line, import_map)
                if obj_type and obj_type in import_map:
                    imported_path = import_map[obj_type]
                    is_class_method = True
        
        if not imported_path:
            continue
        
        # 加载被 import 文件的 AST
        imported_tree = None
        try:
            if _ast_object_singleton:
                imported_tree = _ast_object_singleton.get_nodes(imported_path)
            if not imported_tree:
                with open(imported_path, 'r', encoding='utf-8', errors='replace') as f:
                    imported_tree = ast.parse(f.read(), filename=imported_path)
        except Exception:
            continue
        
        if not imported_tree:
            continue
        
        # 在被 import 文件中找到函数定义
        func_def = _find_function_def(imported_tree, imported_func_name)
        if not func_def and is_class_method:
            # 类方法：在类中查找方法
            for cls_node in ast.walk(imported_tree):
                if isinstance(cls_node, ast.ClassDef):
                    for item in cls_node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == func_name:
                            func_def = item
                            break
                    if func_def:
                        break
        if not func_def:
            continue
        
        # 检查函数内部是否调用了敏感函数
        for inner_node in ast.walk(func_def):
            if not isinstance(inner_node, ast.Call):
                continue
            inner_name = _get_call_name(inner_node)
            if not inner_name:
                continue
            
            # 检查是否匹配内置敏感函数 + 规则配置的函数
            is_sink = False
            for sf in BUILTIN_SENSITIVE_SINKS + list(sensitive_func):
                if inner_name == sf or inner_name.endswith('.' + sf):
                    is_sink = True
                    break
            if not is_sink:
                continue
            
            # 找到了间接 sink！
            # 检查当前调用点的实参是否可控
            for arg in (call_node.args or []):
                arg_str = _expr_to_str(arg)
                
                # 直接检查可控性
                if is_controllable(arg_str, controlled_params):
                    chain = ["{}:{}".format(
                        target_line,
                        source_lines[target_line - 1].strip() if target_line <= len(source_lines) else call_name)]
                    return [{"code": 1, "chain": chain, "source": arg_str}]
                
                # 反向追踪
                arg_names = _collect_names(arg)
                for an in arg_names:
                    code, cp = parameters_back(an, [], target_line, file_path,
                                                repair_functions, controlled_params)
                    if code == 1:
                        chain = ["{}:{}".format(
                            target_line,
                            source_lines[target_line - 1].strip() if target_line <= len(source_lines) else call_name)]
                        return [{"code": 1, "chain": chain, "source": cp}]

            # 直接参数不可控，如果是类方法，检查 self.xxx 属性来源
            # 通过 __init__ 追踪构造函数参数
            if is_class_method:
                self_result = _trace_cross_file_self_attribute(
                    imported_tree, func_def, tree, call_node, target_line,
                    file_path, repair_functions, controlled_params, source_lines)
                if self_result:
                    return self_result
        
        # 没有找到间接 sink，检查是否需要返回不可控
        chain = ["{}:{}".format(
            target_line,
            source_lines[target_line - 1].strip() if target_line <= len(source_lines) else call_name)]
        return [{"code": -1, "chain": chain, "source": None}]
    
    return None


def _trace_cross_file_self_attribute(imported_tree, method_def, caller_tree,
                                      call_node, target_line, file_path,
                                      repair_functions, controlled_params,
                                      source_lines):
    """跨文件 self.xxx 属性追踪
    
    当 ex.run('ls') 中 'ls' 不可控时，检查方法体内是否通过 self.xxx 
    使用了构造函数参数。完整链路：
    
    ex = Executor(user_input)          ← caller_tree 中
         ↓ __init__(self, base)        ← imported_tree 中
         ↓ self.base = base
    ex.run('ls')                       ← call_node
         ↓ os.popen(self.base + arg)   ← method_def 中
         ↑ self.base 可控因为 __init__ 参数 base 来自 user_input
    
    :return: [{"code": 1, ...}] or None
    """
    # 1. 找到方法所属的类
    class_node = None
    for node in ast.walk(imported_tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if item is method_def:
                    class_node = node
                    break
            if class_node:
                break
    
    if not class_node:
        return None
    
    # 2. 收集方法体内使用的 self.xxx 属性名
    #    通过 _collect_names 收集所有 self.xxx，然后筛选 self. 前缀的
    used_self_attrs = set()
    for inner in ast.walk(method_def):
        if isinstance(inner, ast.Attribute) and isinstance(inner.value, ast.Name) and inner.value.id == 'self':
            used_self_attrs.add('self.' + inner.attr)
    
    if not used_self_attrs:
        return None
    
    # 3. 在 __init__ 中建立 self.xxx → __init__参数名 的映射
    init_method = None
    for item in class_node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == '__init__':
            init_method = item
            break
    
    if not init_method:
        return None
    
    # self.attr → init_param_name 映射
    self_attr_to_param = {}
    for stmt in init_method.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                target_name = _get_name(target)
                if target_name and target_name in used_self_attrs:
                    # self.base = base → {'self.base': 'base'}
                    rhs_name = _get_name(stmt.value)
                    if rhs_name:
                        # 验证 rhs_name 确实是 __init__ 参数
                        for arg in init_method.args.args:
                            if arg.arg == rhs_name and arg.arg != 'self':
                                self_attr_to_param[target_name] = rhs_name
    
    if not self_attr_to_param:
        return None
    
    # 4. 找到构造函数调用处：ex = Executor(...)
    #    从 caller_tree 中查找 ClassName(...) 的调用
    class_name = class_node.name
    constructor_calls = []
    for node in ast.walk(caller_tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == class_name:
                constructor_calls.append(node)
            elif isinstance(node.func, ast.Attribute) and node.func.attr == class_name:
                constructor_calls.append(node)
    
    # 5. 对每个构造调用，检查构造参数是否可控
    for ctor_call in constructor_calls:
        # 建立 构造参数位置 → 参数名 的映射
        init_params = [a for a in init_method.args.args if a.arg != 'self']
        
        for i, ctor_arg in enumerate(ctor_call.args or []):
            # 找到这个位置对应的 __init__ 参数名
            param_name = init_params[i].arg if i < len(init_params) else None
            if not param_name:
                continue
            
            # 检查这个参数是否被 self.xxx 使用
            if param_name not in self_attr_to_param.values():
                continue
            
            # 检查构造调用的实参是否可控
            arg_str = _expr_to_str(ctor_arg)
            if is_controllable(arg_str, controlled_params):
                chain = ["{}:{}".format(
                    target_line,
                    source_lines[target_line - 1].strip() if target_line <= len(source_lines) else _get_call_name(call_node))]
                return [{"code": 1, "chain": chain, "source": arg_str}]
            
            # 反向追踪构造参数
            arg_names = _collect_names(ctor_arg)
            for an in arg_names:
                code, cp = parameters_back(an, [], ctor_call.lineno if hasattr(ctor_call, 'lineno') else target_line,
                                            file_path, repair_functions, controlled_params)
                if code == 1:
                    chain = ["{}:{}".format(
                        target_line,
                        source_lines[target_line - 1].strip() if target_line <= len(source_lines) else _get_call_name(call_node))]
                    return [{"code": 1, "chain": chain, "source": cp}]
    
    return None


def analysis_params(param, expr_lineno, vul_function, line, file_path,
                     repair_functions, controlled_params, isexternal=True):
    """
    分析参数可控性（供 CAST.is_controllable_param 调用）

    :param param: 变量名字符串
    :param expr_lineno: 表达式行号列表（Python 版暂不使用）
    :param vul_function: 漏洞函数名
    :param line: 行号
    :param file_path: 文件路径
    :param repair_functions: 修复函数列表
    :param controlled_params: 可控参数列表
    :param isexternal: 是否外部调用
    :return: (code, cp, expr_lineno, chain)
    """
    try:
        code, cp = parameters_back(param, [], int(line), file_path,
                                    repair_functions, controlled_params)

        # 构建 chain
        source_lines = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                source_lines = f.readlines()
        except Exception:
            pass

        chain = ["{}:{}".format(line, source_lines[int(line) - 1].strip() if int(line) <= len(source_lines) else param)]

        return code, cp, line, chain

    except Exception:
        logger.warning("[AST][Python] analysis_params error: {}".format(traceback.format_exc()))
        return -1, None, line, []
