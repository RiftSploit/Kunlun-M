# -*- coding: utf-8 -*-

"""
    Java Reflected XSS Rule (AST-enhanced)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2024 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6002():
    def __init__(self):
        self.svid = 6002
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Reflected XSS"
        self.description = "直接将用户输入输出到HTTP响应中，未进行编码转义。通过AST分析追踪数据流，结合精确grep定位response输出上下文。"
        self.level = 3

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = [
            r"getWriter\s*\(\s*\)\s*\.\s*(?:print|write|println)",
            r"getOutputStream\s*\(\s*\)",
            r"PrintWriter.*\.(?:print|write|println)",
        ]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for regex
        self.unmatch = [
            r"encodeURL",
            r"encodeForHTML",
            r"escapeHtml",
            r"ESAPI\.encoder",
            r"StringEscapeUtils",
            r"URLEncoder\.encode",
        ]

        self.vul_function = ["print", "write", "println"]

    def main(self, regex_string):
        pass
