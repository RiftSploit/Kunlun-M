# -*- coding: utf-8 -*-

"""
    Java Log Injection Rule (AST-enhanced)
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
        self.description = "用户输入直接拼接到日志中可能导致日志注入攻击"
        self.level = 3

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "info|debug|warn|error|fatal"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["info", "debug", "warn", "error", "fatal"]


    def main(self, regex_string):
        """log 方法交给 AST 分析判断上下文"""
        return None

