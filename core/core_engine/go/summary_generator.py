#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Go 函数摘要生成器
    ~~~~~~~~~~~~~~~~~
    用 tree-sitter 解析 Go 源文件，提取每个函数的返回值数据流摘要。
    摘要只记录数据流事实，不做安全判定。

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Set

from core.core_engine.function_summary import FileSummary, FunctionSummary, ReturnFlowItem
from utils.log import logger

# tree-sitter 初始化
import tree_sitter_go as _tsgo
from tree_sitter import Language as _TS_Language, Parser as _TS_Parser

_GO_TS_LANGUAGE = _TS_Language(_tsgo.language())
_ts_parser = _TS_Parser(_GO_TS_LANGUAGE)
_HAS_TREE_SITTER = True

# Go 字面量标识符
_LITERAL_IDENTS = frozenset({"nil", "true", "false"})

_MAX_TRACE_DEPTH = 10

# 模块级摘要注册表，用于跨函数递归分析
_summary_registry: Dict[str, FunctionSummary] = {}


def lookup_summary(func_name: str) -> Optional[FunctionSummary]:
    """查询已生成的函数摘要（短名匹配）。"""
    short_name = func_name.split(".")[-1] if "." in func_name else func_name
    return _summary_registry.get(short_name)


def _node_text(node) -> str:
    """获取 tree-sitter 节点的文本内容。"""
    return node.text.decode("utf-8")


def _is_literal(node) -> bool:
    """判断节点是否为字面量（数字、字符串、布尔、nil）。"""
    if node.type in (
        "int_literal", "float_literal", "imaginary_literal",
        "rune_literal", "interpreted_string_literal",
        "raw_string_literal", "true", "false", "nil",
    ):
        return True
    if node.type == "identifier" and _node_text(node) in _LITERAL_IDENTS:
        return True
    return False


def _extract_param_names(param_list_node) -> List[str]:
    """从 parameter_list 节点提取形参名列表。

    Go 参数列表由 parameter_declaration 子节点组成，每个 declaration
    的第一个 identifier 子节点为形参名。
    """
    names: List[str] = []
    for child in param_list_node.children:
        if child.type == "parameter_declaration":
            for sub in child.children:
                if sub.type == "identifier":
                    names.append(_node_text(sub))
                    break
    return names


def _extract_receiver_name(receiver_node) -> str:
    """从 method_declaration 的接收者参数列表提取变量名。

    Go method_declaration 中接收者是第一个 parameter_list，内部结构与普通参数一致。
    """
    for child in receiver_node.children:
        if child.type == "parameter_declaration":
            for sub in child.children:
                if sub.type == "identifier":
                    return _node_text(sub)
    return ""


def _find_assignments(func_body) -> Dict[str, object]:
    """在函数体中收集短变量声明 (:=) 和赋值 (=) 的左值 -> 右值节点映射。

    仅记录 identifier = expr 形式的简单赋值。多值赋值中每个左值
    单独映射到对应位置的右值节点。
    """
    assignments: Dict[str, object] = {}

    def _walk(node):
        for child in node.children:
            if child.type in ("short_var_declaration", "assignment_statement"):
                lhs_exprs: List[object] = []
                rhs_exprs: List[object] = []
                saw_eq = False
                for c in child.children:
                    if c.type in (":=", "="):
                        saw_eq = True
                        continue
                    if not saw_eq:
                        if c.type == "expression_list":
                            lhs_exprs = c.children
                        elif c.type == "identifier":
                            lhs_exprs.append(c)
                    else:
                        if c.type == "expression_list":
                            rhs_exprs = c.children
                        elif c.type not in (";",):
                            rhs_exprs.append(c)

                for i, lhs_node in enumerate(lhs_exprs):
                    if lhs_node.type == "identifier":
                        name = _node_text(lhs_node)
                        if i < len(rhs_exprs):
                            assignments[name] = rhs_exprs[i]

            elif child.type in (
                "if_statement", "for_statement", "switch_statement",
                "select_statement", "block", "statement_list",
            ):
                _walk(child)

    _walk(func_body)
    return assignments


def _trace_dataflow(
    expr_node,
    param_names: List[str],
    file_lines: List[str],
    func_body=None,
    assignments: Optional[Dict[str, object]] = None,
    visited: Optional[Set[int]] = None,
    depth: int = 0,
) -> dict:
    """从表达式节点反向追踪数据流。

    返回字典包含 origin, origin_type, dep_params, path 四个字段。
    不做安全判定，只记录数据流事实。
    """
    if visited is None:
        visited = set()
    if depth > _MAX_TRACE_DEPTH:
        return {
            "origin": _node_text(expr_node),
            "origin_type": "unknown",
            "dep_params": [],
            "path": [],
        }

    node_id = expr_node.id if hasattr(expr_node, "id") else id(expr_node)
    if node_id in visited:
        return {
            "origin": _node_text(expr_node),
            "origin_type": "unknown",
            "dep_params": [],
            "path": [],
        }
    visited = visited | {node_id}

    # 1. 字面量
    if _is_literal(expr_node):
        return {
            "origin": _node_text(expr_node),
            "origin_type": "literal",
            "dep_params": [],
            "path": [],
        }

    # 2. identifier
    if expr_node.type == "identifier":
        name = _node_text(expr_node)
        if name in param_names:
            idx = param_names.index(name)
            return {
                "origin": name,
                "origin_type": "param",
                "dep_params": [idx],
                "path": [],
            }

        # 检查函数内是否有对 name 的赋值
        if assignments and name in assignments and func_body is not None:
            rhs_node = assignments[name]
            result = _trace_dataflow(
                rhs_node, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )
            result["path"].append({
                "node": name,
                "type": "assign",
                "line": rhs_node.start_point.row + 1,
            })
            return result

        return {
            "origin": name,
            "origin_type": "global",
            "dep_params": [],
            "path": [],
        }

    # 3. call_expression
    if expr_node.type == "call_expression":
        children = expr_node.children
        func_node = children[0] if children else None
        func_name = _node_text(func_node) if func_node else "<unknown>"

        dep_params: List[int] = []
        # 追踪函数名部分（selector_expression 可能包含参数引用）
        if func_node:
            sub = _trace_dataflow(
                func_node, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))
        # 收集参数节点的数据流信息（用于递归展开时做参数映射）
        arg_flows: List[dict] = []
        for arg in children[1:]:
            if arg.type == "argument_list":
                for a in arg.children:
                    if a.type == ",":
                        continue
                    sub = _trace_dataflow(
                        a, param_names, file_lines, func_body, assignments,
                        visited, depth + 1,
                    )
                    dep_params.extend(sub.get("dep_params", []))
                    arg_flows.append(sub)

        # 递归查摘要注册表，展开自定义方法调用
        short_name = func_name.split(".")[-1] if "." in func_name else func_name
        callee_summary = _summary_registry.get(short_name)

        if callee_summary and callee_summary.return_flow and depth < _MAX_TRACE_DEPTH:
            # 用被调用函数的 return_flow 展开，映射参数依赖
            expanded_deps: List[int] = []
            for rf in callee_summary.return_flow:
                for callee_param_idx in rf.dep_params:
                    if callee_param_idx < len(arg_flows):
                        # 被调用函数的第 callee_param_idx 个参数 → 对应当前调用处的第 callee_param_idx 个参数
                        expanded_deps.extend(arg_flows[callee_param_idx].get("dep_params", []))

            if expanded_deps:
                # 有参数映射，合并并返回展开后的结果
                all_deps = list(dict.fromkeys(dep_params + expanded_deps))
                return {
                    "origin": func_name,
                    "origin_type": "call",
                    "dep_params": all_deps,
                    "path": [{
                        "node": func_name,
                        "type": "call",
                        "line": expr_node.start_point.row + 1,
                    }],
                    "expanded_from": short_name,
                }

        return {
            "origin": func_name,
            "origin_type": "call",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{
                "node": func_name,
                "type": "call",
                "line": expr_node.start_point.row + 1,
            }],
        }

    # 4. selector_expression（如 r.URL.Query）
    if expr_node.type == "selector_expression":
        full_text = _node_text(expr_node)
        dep_params: List[int] = []
        left = expr_node.child_by_field_name("operand")
        if left:
            sub = _trace_dataflow(
                left, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))

        return {
            "origin": full_text,
            "origin_type": "global",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{
                "node": full_text,
                "type": "selector",
                "line": expr_node.start_point.row + 1,
            }],
        }

    # 5. binary_expression（如 a + b）
    if expr_node.type == "binary_expression":
        left = expr_node.child_by_field_name("left")
        right = expr_node.child_by_field_name("right")
        dep_params: List[int] = []
        path: List[dict] = []
        for side in (left, right):
            if side is None:
                continue
            sub = _trace_dataflow(
                side, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))
            if sub.get("path"):
                path.extend(sub["path"])

        return {
            "origin": _node_text(expr_node),
            "origin_type": "unknown",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": path,
        }

    # 6. unary_expression
    if expr_node.type == "unary_expression":
        operand = expr_node.child_by_field_name("operand")
        if operand:
            return _trace_dataflow(
                operand, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )

    # 7. index_expression / slice_expression
    if expr_node.type in ("index_expression", "slice_expression"):
        operand = expr_node.child_by_field_name("operand")
        if operand:
            return _trace_dataflow(
                operand, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )

    # 8. expression_list（递归拆解）
    if expr_node.type == "expression_list":
        # 多值场景由 _analyze_return_value 处理，此处只处理单值
        if len(expr_node.children) == 1:
            return _trace_dataflow(
                expr_node.children[0], param_names, file_lines, func_body,
                assignments, visited, depth + 1,
            )

    # 其他情况
    return {
        "origin": _node_text(expr_node),
        "origin_type": "unknown",
        "dep_params": [],
        "path": [],
    }


def _analyze_return_value(
    return_node,
    param_names: List[str],
    func_body,
    file_path: str,
    file_lines: List[str],
    assignments: Optional[Dict[str, object]] = None,
) -> List[ReturnFlowItem]:
    """分析单个 return 语句中每个返回值的数据流。

    Go 的 return_statement 中返回值被包裹在 expression_list 子节点内。
    多返回值时 expression_list 包含多个表达式子节点（逗号分隔）。
    """
    if assignments is None:
        assignments = {}

    # 找到 expression_list 子节点，其中包含返回值表达式
    expr_nodes: List[object] = []
    for child in return_node.children:
        if child.type == "expression_list":
            # 过滤逗号等语法节点，只保留实际表达式
            for expr in child.children:
                if expr.type not in (",", ";") and not expr.type.endswith("_comment"):
                    expr_nodes.append(expr)
            break

    items: List[ReturnFlowItem] = []
    for return_index, expr_node in enumerate(expr_nodes):
        result = _trace_dataflow(
            expr_node, param_names, file_lines, func_body, assignments,
        )

        item = ReturnFlowItem(
            order=len(items),
            return_index=return_index,
            origin=result["origin"],
            origin_type=result["origin_type"],
            dep_params=result.get("dep_params", []),
            path=result.get("path", []),
        )
        items.append(item)

    return items


def _process_func_node(
    func_node,
    file_path: str,
    file_lines: List[str],
    is_method: bool = False,
) -> Optional[FunctionSummary]:
    """处理单个 function_declaration 或 method_declaration 节点，生成摘要。"""
    func_name = ""
    param_names: List[str] = []
    receiver_name = ""
    func_body = None
    param_list_count = 0

    for child in func_node.children:
        if child.type in ("identifier", "field_identifier"):
            if not func_name:
                func_name = _node_text(child)
        elif child.type == "parameter_list":
            param_list_count += 1
            if is_method and param_list_count == 1:
                # method_declaration 的第一个 parameter_list 是 receiver
                receiver_name = _extract_receiver_name(child)
            elif (not is_method and param_list_count == 1) or (is_method and param_list_count == 2):
                # 普通函数的第 1 个 parameter_list，或方法的第 2 个，是形参
                param_names = _extract_param_names(child)
        elif child.type == "block":
            func_body = child

    if not func_name:
        return None

    # receiver 变量名加入 param_names（作为第 0 个参数）
    if receiver_name:
        param_names.insert(0, receiver_name)

    start_line = func_node.start_point.row + 1
    end_line = func_node.end_point.row + 1

    # 收集函数体中的赋值
    assignments = _find_assignments(func_body) if func_body else {}

    # 找到所有 return 语句
    return_items: List[ReturnFlowItem] = []
    if func_body:
        _collect_returns(func_body, param_names, func_body, file_path,
                         file_lines, assignments, return_items)

    return FunctionSummary(
        name=func_name,
        params=param_names,
        line_range=(start_line, end_line),
        return_flow=return_items,
        receiver_name=receiver_name,
        is_method=is_method,
    )


def _collect_returns(
    node,
    param_names: List[str],
    func_body,
    file_path: str,
    file_lines: List[str],
    assignments: Dict[str, object],
    result: List[ReturnFlowItem],
) -> None:
    """递归遍历 AST 节点，收集所有 return_statement 的数据流。"""
    for child in node.children:
        if child.type == "return_statement":
            items = _analyze_return_value(
                child, param_names, func_body, file_path, file_lines, assignments,
            )
            result.extend(items)
        elif child.type in (
            "if_statement", "for_statement", "switch_statement",
            "select_statement", "block", "statement_list",
            "expression_case", "default_case", "communication_case",
        ):
            _collect_returns(child, param_names, func_body, file_path,
                             file_lines, assignments, result)


def generate_file_summaries(file_path: str, file_content: str) -> FileSummary:
    """解析单个 Go 文件，生成该文件所有函数的摘要。

    用 tree-sitter 解析 Go AST，遍历所有 function_declaration 和
    method_declaration 节点，对每个函数提取返回值数据流。

    :param file_path: 文件路径，用于记录在摘要中
    :param file_content: Go 源文件内容
    :return: FileSummary 实例，tree-sitter 不可用时返回空摘要
    """
    content_hash = hashlib.sha256(file_content.encode("utf-8")).hexdigest()

    if not _HAS_TREE_SITTER or _ts_parser is None:
        logger.debug(f"tree-sitter 不可用，跳过摘要生成: {file_path}")
        return FileSummary(file=file_path, content_hash=content_hash, functions=[])

    try:
        tree = _ts_parser.parse(file_content.encode("utf-8"))
    except Exception as e:
        logger.warning(f"解析 Go 文件失败 {file_path}: {e}")
        return FileSummary(file=file_path, content_hash=content_hash, functions=[])

    file_lines = file_content.splitlines()
    root = tree.root_node
    functions: List[FunctionSummary] = []

    for child in root.children:
        if child.type == "function_declaration":
            summary = _process_func_node(child, file_path, file_lines, is_method=False)
            if summary:
                functions.append(summary)
        elif child.type == "method_declaration":
            summary = _process_func_node(child, file_path, file_lines, is_method=True)
            if summary:
                functions.append(summary)

    return FileSummary(file=file_path, content_hash=content_hash, functions=functions)


def generate_summaries_for_target(
    target_path: str,
    files_dict: Dict[str, str],
) -> Dict[str, FileSummary]:
    """便捷入口：遍历所有 Go 文件，生成摘要。

    两遍处理：
    1. 第一遍：生成所有文件的摘要，注册到全局注册表
    2. 第二遍：对有自定义方法调用的函数做二次分析（可递归展开）

    :param target_path: 扫描目标路径（仅用于日志）
    :param files_dict: {file_path: file_content} 字典
    :return: {file_path: FileSummary} 字典
    """
    global _summary_registry
    _summary_registry = {}  # 重置注册表

    summaries: Dict[str, FileSummary] = {}

    # 第一遍：生成所有摘要并注册
    for file_path, content in files_dict.items():
        if not file_path.endswith(".go"):
            continue
        logger.debug(f"生成函数摘要: {file_path}")
        fs = generate_file_summaries(file_path, content)
        summaries[file_path] = fs
        # 注册到全局注册表
        for fn in fs.functions:
            _summary_registry[fn.name] = fn

    # 第二遍：对有自定义方法调用的函数做二次分析
    for file_path, content in files_dict.items():
        if not file_path.endswith(".go"):
            continue
        old_fs = summaries[file_path]
        new_fs = generate_file_summaries(file_path, content)
        # 更新有变化的函数
        changed = False
        for i, fn in enumerate(new_fs.functions):
            if fn.return_flow:
                old_fn = old_fs.functions[i]
                if len(fn.return_flow) != len(old_fn.return_flow):
                    old_fs.functions[i] = fn
                    changed = True
                else:
                    for j, rf in enumerate(fn.return_flow):
                        if rf.dep_params != old_fn.return_flow[j].dep_params:
                            old_fs.functions[i] = fn
                            changed = True
                            break
        if changed:
            summaries[file_path] = old_fs

    logger.debug(f"函数摘要生成完成: {len(summaries)} 个文件, {len(_summary_registry)} 个函数")
    return summaries
