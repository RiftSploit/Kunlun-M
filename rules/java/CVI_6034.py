# -*- coding: utf-8 -*-

"""
    Java SSRF (function-param-controllable)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6034():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6034
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "SSRF (function-param-controllable)"
        self.description = "通过AST分析检测openConnection参数是否来自用户可控输入，包括HttpURLConnection、RestTemplate、WebClient等HTTP请求。"
        self.level = 8

        # status
        self.status = True

        # 部分配置
        self.match_mode = "java-function-param-regex"
        self.match = "openConnection"

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
