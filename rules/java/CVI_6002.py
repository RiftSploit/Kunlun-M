# -*- coding: utf-8 -*-

"""
    Java Reflected XSS Rule (AST-enhanced)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2024 LoRexxar. All rights reserved
"""

import re

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
        self.match = r"print|write|println|addObject|ModelAndView"

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
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除 import 语句
        if regex_string.lstrip().startswith("import "):
            return False
        # 排除文件操作
        if re.search(r"Files\.write|FileOutputStream|FileWriter|System\.out|System\.err", regex_string):
            return False
        # 排除经过转义的安全输出
        if re.search(r"escapeHtml|htmlEscape|escapeHtml4|HtmlUtils|encode|sanitize", regex_string, re.I):
            return False
        return None

