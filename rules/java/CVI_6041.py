# -*- coding: utf-8 -*-

"""
    SSTI (Server-Side Template Injection) (AST-enhanced)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6041():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6041
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Server-Side Template Injection (SSTI)"
        self.description = "用户输入直接用于模板引擎渲染（FreeMarker/Velocity/Thymeleaf），存在SSTI/RCE风险"
        self.level = 9

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "process|evaluate"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"autoEscape", r"escapeHtml", r"StringEscapeUtils"]

        self.vul_function = ["process", "evaluate"]

    def main(self, regex_string):
        pass
