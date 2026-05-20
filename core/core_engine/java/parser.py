#!/usr/bin/env python
# -*- coding: utf-8 -*-
import traceback
import javalang
from utils.log import logger
from core.pretreatment import ast_object as _ast_object_singleton

scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []


def _collect_member_references(expr, refs=None):
    """递归收集表达式中的所有变量引用名（MemberReference.member）"""
    if refs is None:
        refs = []
    if expr is None:
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
        # qualifier 如果是变量名也收集
        if expr.qualifier and not isinstance(expr.qualifier, javalang.tree.ASTNode):
            # qualifier 是字符串表示变量名（如 request、stmt）
            # 排除类名（首字母大写的通常是类名）
            if expr.qualifier and expr.qualifier[0].islower():
                refs.append(expr.qualifier)

    elif isinstance(expr, javalang.tree.Cast):
        _collect_member_references(expr.expression, refs)

    elif isinstance(expr, javalang.tree.TernaryExpression):
        _collect_member_references(expr.condition, refs)
        _collect_member_references(expr.if_true, refs)
        _collect_member_references(expr.if_false, refs)

    elif isinstance(expr, javalang.tree.Assignment):
        _collect_member_references(expr.value, refs)

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
    return None


def _collect_controllable_vars(method_node, request_var_names):
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

    return controllable


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


def _analyze_call(sink_name, arguments, lineno, controllable, repair_functions, scan_chain):
    """分析敏感函数/构造函数的参数可控性，返回 result dict 或 None"""
    if not arguments:
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
    for arg in arguments:
        refs = _collect_member_references(arg)
        param_var_refs.extend(refs)
    param_var_refs = list(set(param_var_refs))

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
            if isinstance(expr, javalang.tree.Assignment):
                if isinstance(expr.value, javalang.tree.ClassCreator):
                    creator = expr.value
                    type_name = creator.type.name if creator.type else ""
                    if type_name in sensitive_func:
                        results.append((type_name, creator.arguments, stmt_line))
    return results


def scan_parser(sensitive_func, vul_lineno, file_path, repair_functions=[], controlled_params=[]):
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

        # 2. 收集可控变量
        request_vars = _find_request_var_names(method)
        controllable = _collect_controllable_vars(method, request_vars)

        # 加入外部指定的可控参数
        if controlled_params:
            controllable.update(controlled_params)

        logger.debug("[AST][Java] Controllable vars: {}".format(controllable))

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
                                   controllable, repair_functions, scan_chain)
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
                                       controllable, repair_functions, scan_chain)
                if result:
                    scan_results.append(result)

                if len(scan_results) > 0:
                    break

    except javalang.parser.JavaSyntaxError:
        logger.warning("[AST][Java] Syntax error parsing {}".format(file_path))
    except Exception:
        logger.warning("[AST][Java] Error: {}".format(traceback.format_exc()))

    return scan_results
