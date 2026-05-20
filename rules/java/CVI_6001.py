# -*- coding: utf-8 -*-

"""
    Java SQL Injection Rule (AST-enhanced)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

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
        self.match = [
            r"createStatement\s*\(\s*\)",
            r"\.executeQuery\s*\(",
            r"\.executeUpdate\s*\(",
            r"\.execute\s*\(",
            r"\.addBatch\s*\(",
        ]

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
        pass
