# -*- coding: utf-8 -*-

"""
    Java ProcessBuilder Command Injection (function-param-controllable)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6038():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6038
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "ProcessBuilder Command Injection (function-param-controllable)"
        self.description = "通过AST分析检测ProcessBuilder构造参数是否来自用户可控输入，命令注入可导致远程代码执行。"
        self.level = 9

        # status
        self.status = False

        # 部分配置
        # ProcessBuilder 通过 ClassCreator 匹配，match 为精确正则避免匹配注释
        self.match_mode = "java-function-param-regex"
        self.match = r"new\s+ProcessBuilder\s*\("

        # for solidity
        self.match_name = None
        self.black_list = []

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = []

        # AST 分析搜索 ProcessBuilder ClassCreator
        self.vul_function = ["ProcessBuilder"]

    def main(self, regex_string):
        pass
