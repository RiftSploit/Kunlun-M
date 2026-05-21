# -*- coding: utf-8 -*-

"""
    Java SQL Injection Rule (AST-enhanced)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re

from utils.api import *


class CVI_6001():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6001
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "SQL Injection"
        self.description = "通过AST分析检测Statement的executeQuery/executeUpdate/execute等方法参数是否来自用户可控输入，追踪数据流以发现SQL注入漏洞。建议使用PreparedStatement进行参数化查询。"
        self.level = 8

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "createStatement|executeQuery|executeUpdate|execute|addBatch"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [
            r"PreparedStatement",
            r"prepareStatement",
            r"@Query",
        ]

        self.vul_function = ["executeQuery", "executeUpdate", "execute", "addBatch"]


    def main(self, regex_string):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的SQL执行调用，
        排除PreparedStatement等安全写法。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 排除安全的 PreparedStatement/prepareStatement 写法
        safe_patterns = [
            r"PreparedStatement",
            r"prepareStatement",
            r"@Query",
        ]
        for safe_pat in safe_patterns:
            if re.search(safe_pat, regex_string):
                return False

        # 确认包含危险的 Statement 执行调用（不要求 . 前缀）
        dangerous_patterns = [
            r"createStatement\s*\(\s*\)",
            r"executeQuery\s*\(",
            r"executeUpdate\s*\(",
            r"execute\s*\(",
            r"addBatch\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
