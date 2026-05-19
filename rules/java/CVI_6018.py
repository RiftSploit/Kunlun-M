# -*- coding: utf-8 -*-

"""
    Java Insecure Reflection Rule
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6018():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6018
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Insecure Reflection"
        self.description = "使用了Class.forName、getDeclaredMethod、getMethod、invoke等反射调用，如果反射的目标类或方法名可控，可能导致远程代码执行。"
        self.level = 7

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [r"Class\.forName"]

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
