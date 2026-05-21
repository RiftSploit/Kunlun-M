# -*- coding: utf-8 -*-

"""
    Java Insecure Cookie Rule
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6014():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6014
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Insecure Cookie"
        self.description = "Cookie设置了不安全的属性，如setSecure(false)或setHttpOnly(false)，可能导致会话劫持或XSS窃取Cookie。"
        self.level = 3

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [
            r'\.setSecure\s*\(\s*false\s*\)',
            r'\.setHttpOnly\s*\(\s*false\s*\)',
        ]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"setSecure\s*\(\s*true", r"setHttpOnly\s*\(\s*true"]

        self.vul_function = None

    def main(self, regex_string):
        pass
