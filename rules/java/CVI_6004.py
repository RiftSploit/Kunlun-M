# -*- coding: utf-8 -*-

"""
    Java Path Traversal Rule (AST-enhanced)
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
        self.description = "通过AST分析检测File/FileInputStream等文件操作构造函数参数是否来自用户可控输入，追踪数据流以发现路径遍历漏洞。建议对文件路径进行normalize和getCanonicalPath校验。"
        self.level = 7

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = [r"new\s+(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\("]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"normalize\(\)", r"getCanonicalPath"]

        self.vul_function = ["File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter"]

    def main(self, regex_string):
        pass
