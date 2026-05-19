# -*- coding: utf-8 -*-

"""
    Java Path Traversal Rule
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6004():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6004
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Path Traversal"
        self.description = "使用用户输入构造文件路径（如new File(request)或FileInputStream(getParameter)），未进行路径校验，可能导致路径遍历漏洞。"
        self.level = 7

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [r"new\s+File\(.*?request"]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"normalize\(\)", r"getCanonicalPath"]

        self.vul_function = None

    def main(self, regex_string):
        pass
