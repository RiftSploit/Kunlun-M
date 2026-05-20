# -*- coding: utf-8 -*-

"""
    Java Log Injection Rule
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6010():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6010
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Log Injection"
        self.description = "将用户输入直接拼接到日志语句中，未进行换行符过滤或编码，可能导致日志注入漏洞。通过AST分析追踪数据流，检测用户输入是否流入日志方法。"
        self.level = 3

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = [r"log(?:ger)?\.(?:info|debug|warn|error|fatal)\s*\("]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"sanitize", r"encode", r"escape", r"replace\(\"\\n\"", r"replace\(\"\\r\""]

        self.vul_function = ["info", "debug", "warn", "error", "fatal"]

    def main(self, regex_string):
        pass
