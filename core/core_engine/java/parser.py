#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import traceback
import javalang
from utils.log import logger
from core.pretreatment import ast_object as _ast_object_singleton

scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []


def _expr_to_text(expr, source_lines):
    """将 AST 表达式转为源码文本（从源码行读取，fallback 用 str()）"""
    if expr is None:
        return ''
    if isinstance(expr, str):
        return expr
    if hasattr(expr, 'position') and expr.position and source_lines:
        lineno = expr.position.line
        if 1 <= lineno <= len(source_lines):
            return source_lines[lineno - 1]
    return str(expr)


def _collect_member_references(expr, refs=None):
    """递归收集表达式中的所有变量引用名（MemberReference.member）"""
    if refs is None:
        refs = []
    if expr is None:
        return refs

    if isinstance(expr, str):
        # 纯字符串（源码文本 fallback 传入的参数名）
        refs.append(expr)
        return refs

    if isinstance(expr, javalang.tree.MemberReference):
        refs.append(expr.member)

    elif isinstance(expr, javalang.tree.BinaryOperation):
        _collect_member_references(expr.operandl, refs)
        _collect_member_references(expr.operandr, refs)

    elif isinstance(expr, javalang.tree.MethodInvocation):
        if expr.arguments:
            for arg in expr.arguments:
                _collect_member_references(arg, refs)
        # qualifier 如果是变量名也收集（排除类名：首字母大写）
        if expr.qualifier and isinstance(expr.qualifier, str) and expr.qualifier[0].islower():
            refs.append(expr.qualifier)

    elif isinstance(expr, javalang.tree.Cast):
        _collect_member_references(expr.expression, refs)

    elif isinstance(expr, javalang.tree.TernaryExpression):
        _collect_member_references(expr.condition, refs)
        _collect_member_references(expr.if_true, refs)
        _collect_member_references(expr.if_false, refs)

    elif isinstance(expr, javalang.tree.Assignment):
        _collect_member_references(expr.value, refs)

    elif isinstance(expr, javalang.tree.ClassCreator):
        # new SomeClass(arg1, arg2, ...) → 递归检查参数中的变量引用
        if expr.arguments:
            for arg in expr.arguments:
                _collect_member_references(arg, refs)

    elif isinstance(expr, (list, tuple)):
        for item in expr:
            _collect_member_references(item, refs)

    return refs


def _find_method_at_line(tree, target_line):
    """找到包含目标行号的 MethodDeclaration"""
    target = int(target_line)
    # 收集所有方法并按行号排序
    methods = []
    for path, node in tree.filter(javalang.tree.MethodDeclaration):
        if node.position:
            methods.append(node)
    methods.sort(key=lambda m: m.position.line)

    # 找到目标行所在的方法：target >= start 且 target < next_method.start
    for i, method in enumerate(methods):
        start = method.position.line
        # 用下一个方法的起始行作为当前方法的上界
        if i + 1 < len(methods):
            upper = methods[i + 1].position.line
        else:
            upper = target + 1  # 最后一个方法，只要 >= start 就算
        if start <= target < upper:
            return method

    # Fallback: grep 10行缓冲可能导致行号偏移，扩大搜索范围
    for offset in range(1, 11):
        for direction in (offset, -offset):
            adj_target = target + direction
            if adj_target < 1:
                continue
            for i, method in enumerate(methods):
                start = method.position.line
                if i + 1 < len(methods):
                    upper = methods[i + 1].position.line
                else:
                    upper = adj_target + 1
                if start <= adj_target < upper:
                    return method
    return None


def _collect_controllable_vars(method_node, request_var_names, source_lines=None):
    """
    收集方法体中的可控变量名集合
    可控来源：
    1. HttpServletRequest 参数变量本身
    2. request.getParameter/getHeader/... 赋值的局部变量
    3. 方法参数（如果是 String 类型且在 controlled_params 中）
    """
    controllable = set()

    # request 变量本身可控
    for rvn in request_var_names:
        controllable.add(rvn)

    # 方法参数识别 —— 基于类型和注解
    SPRING_PARAM_ANNOTATIONS = {
        'RequestParam', 'PathVariable', 'RequestBody',
        'RequestHeader', 'CookieValue', 'ModelAttribute',
    }

    JAXRS_PARAM_ANNOTATIONS = {
        'PathParam', 'QueryParam', 'FormParam',
        'HeaderParam', 'BeanParam',
    }

    ALL_PARAM_ANNOTATIONS = SPRING_PARAM_ANNOTATIONS | JAXRS_PARAM_ANNOTATIONS

    if method_node.parameters:
        for param in method_node.parameters:
            param_type = ""
            if hasattr(param, 'type') and param.type:
                param_type = param.type.name if hasattr(param.type, 'name') else str(param.type)

            # 1. HttpServletRequest 等含 Request 的类型 → 可控（Servlet API）
            if 'Request' in param_type:
                controllable.add(param.name)
                logger.debug("[AST][Java] Controllable method param (Request type): {}".format(param.name))
                continue

            # 2. MultipartFile / InputStream 类型 → 可控（文件上传/输入流）
            if 'MultipartFile' in param_type or 'InputStream' in param_type:
                controllable.add(param.name)
                logger.debug("[AST][Java] Controllable method param (File/Stream type): {}".format(param.name))
                continue

            # 3. Principal 类型 → 可控（认证主体可能被伪造）
            if 'Principal' in param_type:
                controllable.add(param.name)
                continue

            # 4. 检查参数注解（Spring / JAX-RS）
            if hasattr(param, 'annotations') and param.annotations:
                for ann in param.annotations:
                    ann_name = ann.name if hasattr(ann, 'name') else str(ann)
                    # 处理全限定名如 org.springframework.web.bind.annotation.RequestParam
                    if '.' in ann_name:
                        ann_name = ann_name.split('.')[-1]
                    if ann_name in ALL_PARAM_ANNOTATIONS:
                        controllable.add(param.name)
                        logger.debug("[AST][Java] Controllable method param (annotation @{}): {}".format(
                            ann_name, param.name))
                        break

    if not method_node.body:
        return controllable

    # 遍历局部变量声明，找 request.getParameter() 等赋值
    for stmt in method_node.body:
        if isinstance(stmt, javalang.tree.LocalVariableDeclaration):
            for declarator in stmt.declarators:
                if declarator.initializer:
                    init = declarator.initializer
                    if isinstance(init, javalang.tree.MethodInvocation):
                        # request.getParameter / request.getHeader / request.getInputStream 等
                        if (init.qualifier in request_var_names and
                                init.member in ("getParameter", "getHeader", "getInputStream",
                                                "getReader", "getQueryString", "getCookies",
                                                "getParameterValues", "getParameterMap",
                                                "getPart", "getParts")):
                            controllable.add(declarator.name)
                            logger.debug("[AST][Java] Controllable var: {} from {}.{}()".format(
                                declarator.name, init.qualifier, init.member))

                        # Spring 常见获取输入的方式
                        # 如: params.get("key"), map.get("key") 当 params/map 是 @RequestParam Map 时
                        # 如: body.get("key") 当 body 是 Map 类型来自 @RequestBody 时
                        if init.member == 'get' and init.qualifier in controllable:
                            controllable.add(declarator.name)
                            logger.debug("[AST][Java] Controllable var: {} from {}.get()".format(
                                declarator.name, init.qualifier))

    # 对象级污点传播：多轮传播直到稳定
    # 处理: obj = new SomeClass(controllable_arg) → obj 可控
    # 处理: obj = controllable.method() → obj 可控
    # 处理: obj = other.method(controllable_arg) → obj 可控
    _propagate_object_taint(method_node, controllable, source_lines=source_lines)

    return controllable


def _propagate_object_taint(method_node, controllable, max_rounds=5, source_lines=None):
    """
    对象级污点传播：追踪 new SomeClass(controllable) / controllable.method() 等赋值

    :param method_node: 方法 AST 节点
    :param controllable: 可控变量集合（会被原地修改）
    :param max_rounds: 最大传播轮数
    :param source_lines: 源码行列表（1-indexed），用于 javalang 解析失败时的文本 fallback
    """
    if not method_node.body:
        return

    changed = True
    rounds = 0
    while changed and rounds < max_rounds:
        changed = False
        rounds += 1

        for stmt in method_node.body:
            if not isinstance(stmt, javalang.tree.LocalVariableDeclaration):
                continue

            for declarator in stmt.declarators:
                if not declarator.initializer or declarator.name in controllable:
                    continue

                init = declarator.initializer
                target_var = declarator.name

                # 模式A: obj = new SomeClass(controllable_arg)
                # 如: ObjectInputStream ois = new ObjectInputStream(bytes)
                # 如: URL url = new URL(userInput)
                if isinstance(init, javalang.tree.ClassCreator):
                    if init.arguments:
                        for arg in init.arguments:
                            refs = _collect_member_references(arg)
                            if set(refs) & controllable:
                                controllable.add(target_var)
                                logger.debug("[AST][Java] Object taint propagation: {} = new {}(...) [from {}]".format(
                                    target_var, init.type.name if init.type else "?", set(refs) & controllable))
                                changed = True
                                break

                # 模式B: x = obj.method(controllable_arg) 或 x = controllable.method()
                elif isinstance(init, javalang.tree.MethodInvocation):
                    # B1: 方法参数包含可控变量
                    if init.arguments:
                        refs = set()
                        for arg in init.arguments:
                            refs.update(_collect_member_references(arg))
                        if refs & controllable:
                            controllable.add(target_var)
                            logger.debug("[AST][Java] Object taint propagation: {} from {}.{}() args".format(
                                target_var, init.qualifier or "?", init.member))
                            changed = True

                    # B2: qualifier 可控 (如 targetUrl.openConnection())
                    if not changed and isinstance(init.qualifier, str) and init.qualifier in controllable:
                        controllable.add(target_var)
                        logger.debug("[AST][Java] Object taint propagation: {} = {}.{})() [qualifier]".format(
                            target_var, init.qualifier, init.member))
                        changed = True

                # 模式C: 字符串拼接 x = y + z
                elif isinstance(init, javalang.tree.BinaryOperation):
                    refs = _collect_member_references(init)
                    if set(refs) & controllable:
                        controllable.add(target_var)
                        changed = True

                # 模式D: 类型转换 x = (Type) y
                elif isinstance(init, javalang.tree.Cast):
                    refs = _collect_member_references(init.expression)
                    if set(refs) & controllable:
                        controllable.add(target_var)
                        changed = True

                # 模式E: 赋值语句 x = y
                elif isinstance(init, javalang.tree.MemberReference):
                    if init.member in controllable:
                        controllable.add(target_var)
                        changed = True

    # 源码文本 fallback：javalang 无法正确解析链式调用时（如 Base64.getDecoder().decode(data)），
    # 直接检查赋值语句的源码文本中是否包含可控变量名
    # 排除字符串字面量内的匹配（避免 "SELECT * FROM users WHERE name=?" 中的 name 被误判）
    if source_lines and controllable:
        for stmt in method_node.body:
            if not isinstance(stmt, javalang.tree.LocalVariableDeclaration):
                continue
            for declarator in stmt.declarators:
                if declarator.name in controllable or not declarator.initializer:
                    continue
                # 用 AST position 定位到源码行
                lineno = stmt.position.line if stmt.position else 0
                if lineno <= 0 or lineno > len(source_lines):
                    continue
                line_text = source_lines[lineno - 1]
                # 去掉字符串字面量（单引号和双引号内容），防止误判
                code_only = re.sub(r'"[^"]*"', '""', line_text)
                code_only = re.sub(r"'[^']*'", "''", code_only)
                # 检查剩余文本中是否包含任何可控变量名（单词边界匹配）
                for var in list(controllable):
                    if re.search(r'\b' + re.escape(var) + r'\b', code_only):
                        controllable.add(declarator.name)
                        logger.debug("[AST][Java] Source-text fallback propagation: {} (line {} contains '{}')".format(
                            declarator.name, lineno, var))
                        break


def _find_request_var_names(method_node):
    """从方法参数中找到 HttpServletRequest 类型的变量名"""
    request_vars = set()
    if method_node.parameters:
        for param in method_node.parameters:
            if hasattr(param, 'type') and param.type:
                type_name = param.type.name if hasattr(param.type, 'name') else str(param.type)
                if 'Request' in type_name or 'HttpServletRequest' in type_name:
                    request_vars.add(param.name)
    return request_vars


def _find_annotated_param_names(method_node):
    """从方法参数注解中找到被 Spring/JAX-RS 注解标记的参数名"""
    SPRING_ANN = {'RequestParam', 'PathVariable', 'RequestBody',
                  'RequestHeader', 'CookieValue', 'ModelAttribute'}
    JAXRS_ANN = {'PathParam', 'QueryParam', 'FormParam',
                 'HeaderParam', 'BeanParam'}
    ALL_ANN = SPRING_ANN | JAXRS_ANN

    annotated_params = set()
    if method_node.parameters:
        for param in method_node.parameters:
            if hasattr(param, 'annotations') and param.annotations:
                for ann in param.annotations:
                    ann_name = ann.name if hasattr(ann, 'name') else str(ann)
                    if '.' in ann_name:
                        ann_name = ann_name.split('.')[-1]
                    if ann_name in ALL_ANN:
                        annotated_params.add(param.name)
                        break
    return annotated_params


def _is_passthrough_method(method_node, param_name, repair_functions, class_methods=None, depth=0, max_depth=3,
                            global_methods=None):
    """
    检查方法的某个参数是否被直接透传返回（或经安全方法处理后返回）
    
    透传条件：
    1. 方法体有 ReturnStatement，返回的是该参数或其方法调用
    2. 返回链上没有经过修复函数
    
    支持跨文件递归查找：当 return otherMethod(s) 中的 otherMethod 不在当前文件时，
    去 global_methods 中查找。
    
    支持嵌套调用透传：return obj.method(s.trim()) 
    当 s 是参数时，检查 obj.method 的第一个参数是否透传。
    
    :param method_node: 方法 AST 节点
    :param param_name: 参数名
    :param repair_functions: 修复函数列表
    :param class_methods: 同类其他方法的 dict（用于递归分析）
    :param depth: 当前递归深度
    :param max_depth: 最大递归深度
    :param global_methods: 跨文件全局方法映射
    :return: True 表示参数被透传
    """
    if depth >= max_depth or not method_node or not method_node.body:
        return False

    for stmt in method_node.body:
        if isinstance(stmt, javalang.tree.ReturnStatement) and stmt.expression:
            expr = stmt.expression

            # 直接返回参数引用
            if isinstance(expr, javalang.tree.MemberReference):
                if expr.member == param_name:
                    return True

            # 返回参数的方法调用 (如 s.trim(), s.toLowerCase())
            if isinstance(expr, javalang.tree.MethodInvocation):
                # 检查是否是修复函数
                if expr.member in repair_functions:
                    return False

                # qualifier 是参数名 → 直接透传
                if isinstance(expr.qualifier, str) and expr.qualifier == param_name:
                    return True
                if isinstance(expr.qualifier, javalang.tree.MemberReference):
                    if expr.qualifier.member == param_name:
                        return True

                # 嵌套调用透传：return obj.method(s.trim())
                # 检查参数中是否包含对 param_name 的引用
                called_name = expr.member
                if expr.arguments and depth + 1 < max_depth:
                    # 找到哪些参数位置包含对 param_name 的引用
                    param_has_ref = False
                    for arg in expr.arguments:
                        refs = _collect_member_references(arg)
                        if param_name in refs:
                            param_has_ref = True
                            break
                    
                    if param_has_ref:
                        # 1. 先在同文件方法映射中找
                        found_target = False
                        if class_methods and called_name in class_methods:
                            target_method = class_methods[called_name]
                            if target_method.parameters:
                                target_param_name = target_method.parameters[0].name
                                if _is_passthrough_method(target_method, target_param_name, repair_functions,
                                                          class_methods, depth + 1, max_depth,
                                                          global_methods=global_methods):
                                    return True
                            found_target = True
                        
                        # 2. 去全局映射中找（跨文件递归）
                        if not found_target and global_methods:
                            call_arg_count = len(expr.arguments) if expr.arguments else 0
                            key = (called_name, call_arg_count)
                            if key in global_methods:
                                for remote_tree, remote_method, remote_filepath in global_methods[key]:
                                    if remote_method.parameters:
                                        target_param_name = remote_method.parameters[0].name
                                        remote_cm = _build_class_method_map(remote_tree)
                                        if _is_passthrough_method(remote_method, target_param_name, repair_functions,
                                                                  remote_cm, depth + 1, max_depth,
                                                                  global_methods=global_methods):
                                            return True

    return False


def _build_class_method_map(tree):
    """从 AST 树中构建 类名→方法 的映射"""
    class_methods = {}
    for path, node in tree.filter(javalang.tree.MethodDeclaration):
        class_methods[node.name] = node
    return class_methods


def _build_global_method_map(ast_obj, current_filepath):
    """
    遍历所有 Java 文件的 AST，构建全局方法映射（用于跨文件传播）
    
    返回: {(method_name, param_count): [(tree, method_node, filepath), ...]}
    - method_name: 方法名
    - param_count: 参数数量（用于消歧义）
    - tree: 文件的 AST 树
    - method_node: 方法声明节点
    - filepath: 文件路径
    """
    global_methods = {}
    
    if ast_obj is None or not hasattr(ast_obj, 'pre_result'):
        return global_methods
    
    for filepath, file_data in ast_obj.pre_result.items():
        # 跳过非 Java 文件
        if not filepath.endswith('.java'):
            continue
        
        ast_nodes = file_data.get('ast_nodes')
        if not ast_nodes:
            continue
        
        try:
            for ast_tree in (ast_nodes if isinstance(ast_nodes, list) else [ast_nodes]):
                for _, node in ast_tree.filter(javalang.tree.MethodDeclaration):
                    param_count = len(node.parameters) if node.parameters else 0
                    key = (node.name, param_count)
                    if key not in global_methods:
                        global_methods[key] = []
                    global_methods[key].append((ast_tree, node, filepath))
        except Exception:
            continue
    
    return global_methods


def _flatten_statements(body):
    """递归展开方法体中的嵌套控制结构（TryStatement, IfStatement 等），返回扁平语句列表。"""
    if not body:
        return []
    result = []
    for stmt in body:
        result.append(stmt)
        # TryStatement: block, catches, finally_block
        if isinstance(stmt, javalang.tree.TryStatement):
            result.extend(_flatten_statements(stmt.block))
            for catch in (stmt.catches or []):
                result.extend(_flatten_statements(catch.block))
            result.extend(_flatten_statements(stmt.finally_block))
        # IfStatement: then_statement, else_statement
        elif isinstance(stmt, javalang.tree.IfStatement):
            result.extend(_flatten_statements(stmt.then_statement if isinstance(stmt.then_statement, list) else [stmt.then_statement] if stmt.then_statement else []))
            result.extend(_flatten_statements(stmt.else_statement if isinstance(stmt.else_statement, list) else [stmt.else_statement] if stmt.else_statement else []))
        # ForStatement, WhileStatement, DoStatement: body
        elif hasattr(stmt, 'body') and isinstance(getattr(stmt, 'body', None), list):
            result.extend(_flatten_statements(stmt.body))
        # BlockStatement: statements
        elif isinstance(stmt, javalang.tree.BlockStatement):
            result.extend(_flatten_statements(stmt.statements))
    return result


def _check_caller_controllability(current_method, ast_obj, repair_functions, global_methods=None, depth=0, max_depth=3):
    """
    反向调用链分析：检查当前方法的调用者是否传入了可控参数。
    
    当当前方法中没有 request source（controllable 为空）时，
    通过全局方法映射找到所有调用当前方法的地方，检查调用者传的参数是否可控。
    
    支持递归：如果调用者本身也没有 request source，递归检查调用者的调用者。
    
    返回: set of 参数名 → 这些参数被调用者传入了可控数据
    """
    controllable_params = set()
    
    if depth >= max_depth:
        return controllable_params
    
    if ast_obj is None or not hasattr(ast_obj, 'pre_result'):
        return controllable_params
    
    if not current_method.parameters:
        return controllable_params
    
    current_method_name = current_method.name
    
    # 遍历所有文件，找到调用当前方法的地方
    for filepath, file_data in ast_obj.pre_result.items():
        if not filepath.endswith('.java'):
            continue
        
        ast_nodes = file_data.get('ast_nodes')
        if not ast_nodes:
            continue
        
        try:
            # 找到所有方法声明，检查其方法体中是否调用了 current_method_name
            for ast_tree in (ast_nodes if isinstance(ast_nodes, list) else [ast_nodes]):
                for _, caller_method in ast_tree.filter(javalang.tree.MethodDeclaration):
                    if not caller_method.body:
                        continue
                    
                    flat_stmts = _flatten_statements(caller_method.body)
                    for stmt in flat_stmts:
                        call_expr = None
                        
                        # 查找 LocalVariableDeclaration 中的方法调用
                        if isinstance(stmt, javalang.tree.LocalVariableDeclaration):
                            for declarator in stmt.declarators:
                                if not declarator.initializer:
                                    continue
                                init = declarator.initializer
                                if isinstance(init, javalang.tree.MethodInvocation):
                                    if init.member == current_method_name and init.arguments:
                                        call_expr = init
                        
                        # 查找 ReturnStatement 中的方法调用
                        elif isinstance(stmt, javalang.tree.ReturnStatement) and stmt.expression:
                            expr = stmt.expression
                            if isinstance(expr, javalang.tree.MethodInvocation):
                                if expr.member == current_method_name and expr.arguments:
                                    call_expr = expr
                        
                        # 查找 StatementExpression 中的方法调用（void 方法调用如 deserialize(data)）
                        elif isinstance(stmt, javalang.tree.StatementExpression) and stmt.expression:
                            expr = stmt.expression
                            if isinstance(expr, javalang.tree.MethodInvocation):
                                if expr.member == current_method_name and expr.arguments:
                                    call_expr = expr
                        
                        if call_expr is None:
                            continue
                        
                        # 找到调用！分析调用者方法的可控变量
                        request_vars = _find_request_var_names(caller_method)
                        
                        caller_source_lines = []
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                                caller_source_lines = f.readlines()
                        except Exception:
                            pass
                        
                        caller_controllable = _collect_controllable_vars(
                            caller_method, request_vars, source_lines=caller_source_lines)
                        
                        # 跨方法传播（含跨文件）
                        if global_methods:
                            _propagate_controllable_across_calls(
                                caller_method, ast_tree, caller_controllable, repair_functions,
                                global_methods=global_methods)
                        
                        # 如果调用者也没有可控变量，递归反向检查
                        if not caller_controllable and depth + 1 < max_depth:
                            reverse_params = _check_caller_controllability(
                                caller_method, ast_obj, repair_functions, 
                                global_methods=global_methods, depth=depth+1, max_depth=max_depth)
                            if reverse_params:
                                caller_controllable.update(reverse_params)
                        
                        # 检查调用参数是否可控
                        for arg in call_expr.arguments:
                            refs = _collect_member_references(arg)
                            if set(refs) & caller_controllable:
                                for param in current_method.parameters:
                                    controllable_params.add(param.name)
                                    logger.debug("[AST][Java] Reverse cross-file (depth={}): param '{}' of {}() is controllable (called from {}:{})".format(
                                        depth, param.name, current_method_name, filepath,
                                        caller_method.position.line if caller_method.position else '?'))
                                return controllable_params  # 已找到可控来源，提前返回
        except Exception:
            continue
    
    return controllable_params


def _propagate_controllable_across_calls(method_node, tree, controllable, repair_functions, 
                                          max_depth=3, global_methods=None):
    """
    跨方法污点传播：分析方法体中的方法调用赋值，追踪可控变量传递
    
    支持同文件和跨文件方法查找。
    
    :param method_node: 当前方法 AST 节点
    :param tree: 整个文件的 AST 树（用于查找被调方法）
    :param controllable: 当前可控变量集合（会被原地修改）
    :param repair_functions: 修复函数列表
    :param max_depth: 传播递归深度上限
    :param global_methods: 跨文件全局方法映射 {(name, param_count): [(tree, node, path), ...]}
    """
    if not method_node.body:
        return

    # 构建同文件的方法映射
    class_methods = _build_class_method_map(tree)

    # 多轮传播，直到不再有新变量加入
    changed = True
    rounds = 0
    while changed and rounds < max_depth:
        changed = False
        rounds += 1

        for stmt in method_node.body:
            if not isinstance(stmt, javalang.tree.LocalVariableDeclaration):
                continue

            for declarator in stmt.declarators:
                if not declarator.initializer:
                    continue

                init = declarator.initializer
                target_var = declarator.name

                # 已经是可控的，跳过
                if target_var in controllable:
                    continue

                # 模式1: String x = someMethod(y) where y is controllable
                if isinstance(init, javalang.tree.MethodInvocation):
                    # 检查参数中是否有可控变量
                    call_args_controllable = False
                    if init.arguments:
                        for arg in init.arguments:
                            refs = _collect_member_references(arg)
                            if set(refs) & controllable:
                                call_args_controllable = True
                                break

                    if call_args_controllable:
                        called_method_name = init.member
                        call_arg_count = len(init.arguments) if init.arguments else 0
                        
                        # 1. 先在同文件中查找
                        found = False
                        if called_method_name in class_methods:
                            called_method = class_methods[called_method_name]
                            if called_method.parameters:
                                for arg in init.arguments:
                                    refs = _collect_member_references(arg)
                                    for ref in refs:
                                        if ref in controllable:
                                            if _is_passthrough_method(called_method, called_method.parameters[0].name,
                                                                     repair_functions, class_methods, 0, max_depth,
                                                                     global_methods=global_methods):
                                                controllable.add(target_var)
                                                logger.debug("[AST][Java] Cross-method propagation: {} → {} via {}()".format(
                                                    ref, target_var, called_method_name))
                                                changed = True
                                                found = True
                                                break
                                    if found:
                                        break

                        # 2. 同文件没找到，去全局映射中查找（跨文件传播）
                        if not found and global_methods:
                            key = (called_method_name, call_arg_count)
                            if key in global_methods:
                                for remote_tree, remote_method, remote_filepath in global_methods[key]:
                                    if remote_method.parameters:
                                        for arg in init.arguments:
                                            refs = _collect_member_references(arg)
                                            for ref in refs:
                                                if ref in controllable:
                                                    # 构建远程文件的方法映射（用于递归查找）
                                                    remote_class_methods = _build_class_method_map(remote_tree)
                                                    if _is_passthrough_method(remote_method, remote_method.parameters[0].name,
                                                                             repair_functions, remote_class_methods, 0, max_depth,
                                                                             global_methods=global_methods):
                                                        controllable.add(target_var)
                                                        logger.debug("[AST][Java] Cross-FILE propagation: {} → {} via {}() (from {})".format(
                                                            ref, target_var, called_method_name, remote_filepath))
                                                        changed = True
                                                        found = True
                                                        break
                                            if found:
                                                break
                                    if found:
                                        break

                # 模式2: String x = y + z (字符串拼接), 其中 y 或 z 可控
                elif isinstance(init, javalang.tree.BinaryOperation):
                    refs = _collect_member_references(init)
                    if set(refs) & controllable:
                        controllable.add(target_var)
                        logger.debug("[AST][Java] Propagation via concatenation: {} is controllable".format(target_var))
                        changed = True

                # 模式3: String x = (String) y (类型转换)
                elif isinstance(init, javalang.tree.Cast):
                    refs = _collect_member_references(init.expression)
                    if set(refs) & controllable:
                        controllable.add(target_var)
                        changed = True

                # 模式4: String x = y.toString() / String.valueOf(y)
                elif isinstance(init, javalang.tree.MethodInvocation):
                    if init.member in ('toString', 'valueOf', 'format', 'String'):
                        refs = []
                        if init.qualifier and isinstance(init.qualifier, str):
                            if init.qualifier in controllable:
                                controllable.add(target_var)
                                changed = True
                        if init.arguments:
                            for arg in init.arguments:
                                refs.extend(_collect_member_references(arg))
                        if set(refs) & controllable:
                            controllable.add(target_var)
                            changed = True


def _has_repair_function(expr, repair_functions):
    """检查表达式中是否调用了修复函数"""
    if expr is None or not repair_functions:
        return False

    if isinstance(expr, javalang.tree.MethodInvocation):
        if expr.member in repair_functions:
            return True
        # 检查 qualifier 是否是修复函数的返回值
        if isinstance(expr.qualifier, javalang.tree.MethodInvocation):
            if expr.qualifier.member in repair_functions:
                return True
        # 检查参数
        if expr.arguments:
            for arg in expr.arguments:
                if _has_repair_function(arg, repair_functions):
                    return True

    elif isinstance(expr, javalang.tree.BinaryOperation):
        return _has_repair_function(expr.operandl, repair_functions) or \
               _has_repair_function(expr.operandr, repair_functions)

    elif isinstance(expr, javalang.tree.Cast):
        return _has_repair_function(expr.expression, repair_functions)

    return False


def _analyze_call(sink_name, arguments, lineno, controllable, repair_functions, scan_chain,
                  qualifier=None, is_config_vuln=False):
    """分析敏感函数/构造函数的参数可控性，返回 result dict 或 None
    
    :param qualifier:...[truncated]
    """
    if not arguments:
        # 无参数方法：检查 qualifier 是否可控
        # 如 ois.readObject() → qualifier="ois" → 如果 ois 可控则返回 code=1
        if qualifier and isinstance(qualifier, str) and qualifier in controllable:
            logger.debug("[AST][Java] No-arg method with controllable qualifier: {}.{}()".format(
                qualifier, sink_name))
            return {
                "code": 1,
                "source": [qualifier],
                "source_lineno": lineno,
                "sink": sink_name,
                "sink_param:": qualifier,
                "sink_lineno": lineno,
                "chain": scan_chain + [qualifier, sink_name],
            }
        
        return {
            "code": 3,
            "source": [],
            "source_lineno": lineno,
            "sink": sink_name,
            "sink_param:": "",
            "sink_lineno": lineno,
            "chain": scan_chain + [sink_name],
        }

    # 提取参数中的所有变量引用
    param_var_refs = []
    literal_values = []
    for arg in arguments:
        refs = _collect_member_references(arg)
        param_var_refs.extend(refs)
        # 提取字面量参数值
        if isinstance(arg, javalang.tree.Literal):
            val = getattr(arg, 'value', None)
            if val is not None:
                literal_values.append(str(val))
    param_var_refs = list(set(param_var_refs))

    # 字面量/常量参数危险行为检测：当所有参数都不是用户可控变量时，
    # 检查是否构成危险配置。这类漏洞不依赖外部输入可控性。
    # 如 setAutoTypeSupport(true) / enableDefaultTyping(NON_FINAL)
    # 注意：仅对规则声明了 is_config_vuln=True 的 sink 生效，避免对普通 sink 误判
    if is_config_vuln:
        if not param_var_refs and literal_values:
            # 字面量参数包含 true — 不安全配置
            for lit in literal_values:
                if lit.lower() == 'true':
                    logger.debug("[AST][Java] Dangerous literal arg in {}: {}({}) — config vulnerability".format(
                        sink_name, sink_name, ', '.join(literal_values)))
                    return {
                        "code": 4,
                        "source": literal_values,
                        "source_lineno": lineno,
                        "sink": sink_name,
                        "sink_param:": str(literal_values),
                        "sink_lineno": lineno,
                        "chain": scan_chain + literal_values + [sink_name],
                    }
        # 枚举/常量参数但无可控变量：如 enableDefaultTyping(ObjectMapper.DefaultTyping.OBJECT_AND_NON_CONCRETE)
        # param_var_refs 可能包含枚举常量名，但它们不在 controllable 中
        if param_var_refs and not (set(param_var_refs) & controllable):
            # 所有参数引用都不在可控变量集合中 → 固定配置调用
            # 提取参数文本描述
            arg_desc = param_var_refs + literal_values
            logger.debug("[AST][Java] Fixed-config call in {}: {}({}) — config vulnerability".format(
                sink_name, sink_name, ', '.join(arg_desc)))
            return {
                "code": 4,
                "source": arg_desc,
                "source_lineno": lineno,
                "sink": sink_name,
                "sink_param:": str(arg_desc),
                "sink_lineno": lineno,
                "chain": scan_chain + arg_desc + [sink_name],
            }

    # 检查是否有修复函数
    is_repaired = False
    for arg in arguments:
        if _has_repair_function(arg, repair_functions):
            is_repaired = True
            break

    if is_repaired:
        return {
            "code": 2,
            "source": [],
            "source_lineno": lineno,
            "sink": sink_name,
            "sink_param:": str(param_var_refs),
            "sink_lineno": lineno,
            "chain": scan_chain + ["repaired", sink_name],
        }

    # 检查参数是否可控
    is_controllable = bool(set(param_var_refs) & controllable)
    if is_controllable:
        source_vars = list(set(param_var_refs) & controllable)
        logger.debug("[AST][Java] Param controllable! vars={} -> {}".format(
            source_vars, sink_name))
        return {
            "code": 1,
            "source": source_vars,
            "source_lineno": lineno,
            "sink": sink_name,
            "sink_param:": str(param_var_refs),
            "sink_lineno": lineno,
            "chain": scan_chain + source_vars + [sink_name],
        }
    else:
        # 参数不可控，但 qualifier 可控时也报告（对象本身携带可控数据）
        if qualifier and isinstance(qualifier, str) and qualifier in controllable:
            logger.debug("[AST][Java] Param not controllable but qualifier is: {}.{}()".format(
                qualifier, sink_name))
            return {
                "code": 1,
                "source": [qualifier],
                "source_lineno": lineno,
                "sink": sink_name,
                "sink_param:": qualifier,
                "sink_lineno": lineno,
                "chain": scan_chain + [qualifier, sink_name],
            }

        logger.debug("[AST][Java] Param not clearly controllable: {}".format(param_var_refs))
        return {
            "code": 3,
            "source": [],
            "source_lineno": lineno,
            "sink": sink_name,
            "sink_param:": str(param_var_refs),
            "sink_lineno": lineno,
            "chain": scan_chain + [sink_name],
        }


def _find_class_creators_in_body(method_node, target_line, sensitive_func):
    """在方法体中查找匹配的 ClassCreator 节点及其行号"""
    results = []
    if not method_node.body:
        return results
    target = int(target_line)
    for stmt in method_node.body:
        stmt_line = stmt.position.line if stmt.position else 0
        if stmt_line != target:
            continue
        # 从语句中提取 ClassCreator
        if isinstance(stmt, javalang.tree.LocalVariableDeclaration):
            for declarator in stmt.declarators:
                if isinstance(declarator.initializer, javalang.tree.ClassCreator):
                    creator = declarator.initializer
                    type_name = creator.type.name if creator.type else ""
                    if type_name in sensitive_func:
                        results.append((type_name, creator.arguments, stmt_line))
        elif isinstance(stmt, javalang.tree.ReturnStatement):
            if isinstance(stmt.expression, javalang.tree.ClassCreator):
                creator = stmt.expression
                type_name = creator.type.name if creator.type else ""
                if type_name in sensitive_func:
                    results.append((type_name, creator.arguments, stmt_line))
        elif isinstance(stmt, javalang.tree.StatementExpression):
            expr = stmt.expression
            # 直接 new SomeClass(...) 调用（如 new FileInputStream(filename);）
            if isinstance(expr, javalang.tree.ClassCreator):
                creator = expr
                type_name = creator.type.name if creator.type else ""
                if type_name in sensitive_func:
                    results.append((type_name, creator.arguments, stmt_line))
            # 赋值: x = new SomeClass(...)
            elif isinstance(expr, javalang.tree.Assignment):
                if isinstance(expr.value, javalang.tree.ClassCreator):
                    creator = expr.value
                    type_name = creator.type.name if creator.type else ""
                    if type_name in sensitive_func:
                        results.append((type_name, creator.arguments, stmt_line))
    return results


def scan_parser(sensitive_func, vul_lineno, file_path, repair_functions=[], controlled_params=[], is_config_vuln=False):
    """
    Java AST scan parser - 分析敏感函数参数是否可控
    :param sensitive_func: 要检测的敏感函数列表，如 ["executeQuery", "exec"]
    :param vul_lineno: 漏洞函数所在行号（字符串或整数）
    :param file_path: 文件路径
    :param repair_functions: 修复函数列表，如 ["PreparedStatement"]
    :param controlled_params: 可控参数列表
    :return: scan_results 列表，每个元素是 {"code": N, "chain": [...], ...}
    """
    global scan_results, is_repair_functions, is_controlled_params, scan_chain

    try:
        scan_chain = ["start"]
        scan_results = []
        is_repair_functions = repair_functions
        is_controlled_params = controlled_params

        if _ast_object_singleton is None:
            logger.debug("[AST][Java] ast_object is None, skip")
            return scan_results

        _nodes = _ast_object_singleton.get_nodes(file_path)

        if not _nodes:
            logger.debug("[AST][Java] No AST nodes for {}".format(file_path))
            return scan_results

        target_line = int(vul_lineno)

        # 1. 找到包含目标行号的方法
        method = _find_method_at_line(_nodes, target_line)
        if not method:
            logger.debug("[AST][Java] No method found at line {}".format(target_line))
            return scan_results

        # 2. 收集可控变量（传入源码行用于文本 fallback）
        source_lines = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                source_lines = f.readlines()
        except Exception:
            pass

        request_vars = _find_request_var_names(method)
        controllable = _collect_controllable_vars(method, request_vars, source_lines=source_lines)

        # 加入外部指定的可控参数
        if controlled_params:
            controllable.update(controlled_params)

        # 跨方法污点传播（含跨文件）
        global_methods = _build_global_method_map(_ast_object_singleton, file_path)
        _propagate_controllable_across_calls(method, _nodes, controllable, repair_functions,
                                              global_methods=global_methods)

        # 反向调用链分析：当没有 request source 时，检查调用者是否传入可控数据
        if not controllable:
            reverse_params = _check_caller_controllability(
                method, _ast_object_singleton, repair_functions, global_methods=global_methods)
            if reverse_params:
                controllable.update(reverse_params)
                logger.debug("[AST][Java] Reverse cross-file: added controllable params: {}".format(reverse_params))

        logger.debug("[AST][Java] Controllable vars: {}".format(controllable))

        # 2b. 局部变量赋值传播：如果赋值表达式右边包含可控变量，左边也标记为可控
        #     如 String query = "SELECT * FROM users WHERE name = '" + user.getName() + "'"
        #     → user 可控 → query 可控
        if controllable and source_lines:
            changed = True
            iterations = 0
            while changed and iterations < 5:
                changed = False
                iterations += 1
                for stmt in (method.body or []):
                    if not isinstance(stmt, javalang.tree.LocalVariableDeclaration):
                        continue
                    for decl in stmt.declarators:
                        if not hasattr(decl, 'initializer') or decl.initializer is None:
                            continue
                        if decl.name in controllable:
                            continue
                        # 检查 initializer 文本中是否包含任何可控变量名
                        init_text = _expr_to_text(decl.initializer, source_lines)
                        for cv in list(controllable):
                            if re.search(r'\b' + re.escape(cv) + r'\b', init_text):
                                controllable.add(decl.name)
                                logger.debug("[AST][Java] Local var propagation: {} is controllable (init contains '{}')".format(
                                    decl.name, cv))
                                changed = True
                                break

        # 3. 在方法体中找到目标行号的敏感函数调用
        if not method.body:
            return scan_results

        # 3a. 搜索 MethodInvocation
        for path, node in _nodes.filter(javalang.tree.MethodInvocation):
            if node.member not in sensitive_func:
                continue

            lineno = node.position.line if node.position else 0
            if lineno != target_line:
                continue

            logger.debug("[AST][Java] Found sensitive call: {}() at line {}".format(node.member, lineno))
            result = _analyze_call(node.member, node.arguments, lineno,
                                   controllable, repair_functions, scan_chain,
                                   qualifier=node.qualifier, is_config_vuln=is_config_vuln)
            if result:
                scan_results.append(result)

            if len(scan_results) > 0:
                break

        # 3b. 搜索 ClassCreator（构造函数调用）
        if not scan_results:
            creators = _find_class_creators_in_body(method, target_line, sensitive_func)
            for type_name, arguments, lineno in creators:
                logger.debug("[AST][Java] Found sensitive constructor: new {}() at line {}".format(
                    type_name, lineno))
                result = _analyze_call(type_name, arguments, lineno,
                                       controllable, repair_functions, scan_chain,
                                       is_config_vuln=is_config_vuln)
                if result:
                    scan_results.append(result)

                if len(scan_results) > 0:
                    break

        # 3c. 源码文本 fallback：javalang 链式调用 bug 导致 AST 丢失 sink 时，
        #     直接在源码文本中搜索 sink 函数名
        if not scan_results and source_lines:
            # 从 target_line 开始搜索附近行
            for line_offset in range(0, 15):
                check_line = target_line + line_offset
                if check_line > len(source_lines):
                    break
                source_line = source_lines[check_line - 1]
                for func_name in sensitive_func:
                    # 精确匹配：func_name 后面紧跟 (
                    pattern = r'(?<!\w)' + re.escape(func_name) + r'\s*\('
                    if re.search(pattern, source_line):
                        # 从源码文本提取参数（简单正则：取括号内第一个参数）
                        arg_match = re.search(
                            re.escape(func_name) + r'\s*\(\s*([^,)]+)', source_line)
                        arg_name = arg_match.group(1).strip() if arg_match else ''
                        logger.debug(
                            "[AST][Java] Source-text fallback: found {}.{}() at line {} [arg={}]".format(
                                func_name, '' if not arg_name else '', check_line, arg_name))
                        result = _analyze_call(func_name, [arg_name], check_line,
                                               controllable, repair_functions, scan_chain,
                                               is_config_vuln=is_config_vuln)
                        if result:
                            scan_results.append(result)
                        if len(scan_results) > 0:
                            break
                if len(scan_results) > 0:
                    break

    except javalang.parser.JavaSyntaxError:
        logger.warning("[AST][Java] Syntax error parsing {}".format(file_path))
    except Exception:
        logger.warning("[AST][Java] Error: {}".format(traceback.format_exc()))

    return scan_results
