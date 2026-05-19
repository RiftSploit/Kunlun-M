#!/usr/bin/env python
# -*- coding: utf-8 -*-
import traceback
import javalang
from utils.log import logger

scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []
ast_object = None


def scan_parser(sensitive_func, vul_lineno, file_path, repair_functions=[], controlled_params=[]):
    """
    Java AST scan parser
    :param sensitive_func: 要检测的敏感函数列表
    :param vul_lineno: 漏洞函数所在行号
    :param file_path: 文件路径
    :param repair_functions: 修复函数列表
    :param controlled_params: 可控参数列表
    :return: scan_results
    """
    global scan_results, is_repair_functions, is_controlled_params, scan_chain, ast_object

    try:
        scan_chain = ["start"]
        scan_results = []
        is_repair_functions = repair_functions
        is_controlled_params = controlled_params

        _nodes = ast_object.get_nodes(file_path)

        if not _nodes:
            return scan_results

        # javalang 返回的是 CompilationUnit 对象
        # 遍历所有方法调用，检查是否匹配敏感函数
        for path, node in _nodes.filter(javalang.tree.MethodInvocation):
            if node.member in sensitive_func:
                # 找到敏感函数调用
                lineno = node.position.line if node.position else int(vul_lineno)

                result = {
                    "code": 1,
                    "source": [node],
                    "lineno": lineno,
                    "chain": ["start", node.member],
                }
                scan_results.append(result)
                logger.debug("[AST][Java] Found sensitive function: {} at line {}".format(node.member, lineno))
                break

    except SyntaxError:
        logger.warning("[AST] [ERROR] Java parser SyntaxError for {}".format(file_path))
    except Exception:
        logger.warning("[AST] something error, {}".format(traceback.format_exc()))

    return scan_results
