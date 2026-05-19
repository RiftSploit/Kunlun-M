# -*- coding: utf-8 -*-

"""
    Java Command Injection Rule
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
        self.description = "使用了Runtime.getRuntime().exec()或ProcessBuilder执行系统命令，如果命令参数可控，可能导致命令注入漏洞。"
        self.level = 9

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [r"Runtime\.getRuntime\(\)\.exec"]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = []

        self.vul_function = None

    def main(self, regex_string):
        pass
