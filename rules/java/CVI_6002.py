# -*- coding: utf-8 -*-

"""
    Java Reflected XSS Rule
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6002():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6002
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Reflected XSS"
        self.description = "直接将用户输入（如getParameter获取的参数）输出到响应中，未进行编码转义，可能导致反射型XSS漏洞。"
        self.level = 6

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [r"getWriter\(\)\.(?:print|write|println)"]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"encode", r"escape", r"sanitize", r"HtmlUtils", r"ESAPI"]

        self.vul_function = None

    def main(self, regex_string):
        pass
