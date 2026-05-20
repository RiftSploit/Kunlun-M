# -*- coding: utf-8 -*-

"""
    Java Command Injection Rule (AST-enhanced)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6003():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6003
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Command Injection"
        self.description = "通过AST分析检测Runtime.getRuntime().exec()或ProcessBuilder构造参数是否来自用户可控输入，追踪数据流以发现命令注入漏洞。"
        self.level = 9

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = [
            r"Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(",
            r"new\s+ProcessBuilder\s*\(",
        ]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = []

        self.vul_function = ["exec", "ProcessBuilder"]

    def main(self, regex_string):
        pass
