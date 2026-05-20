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
        self.status = True

        # 部分配置
        # ProcessBuilder 通过 ClassCreator 匹配，match 为类型名
        self.match_mode = "function-param-regex"
        self.match = "ProcessBuilder"

        # for solidity
        self.match_name = None
        self.black_list = []

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = []

        self.vul_function = None

    def main(self, regex_string):
        pass
