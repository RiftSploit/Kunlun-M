# -*- coding: utf-8 -*-

"""
    Java SSRF Rule (AST-enhanced)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6006():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6006
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "SSRF"
        self.description = "通过AST分析检测URL.openConnection()、HttpURLConnection、RestTemplate等HTTP请求方法的URL参数是否来自用户可控输入，追踪数据流以发现SSRF漏洞。"
        self.level = 7

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = [
            r"\.openConnection\s*\(\s*\)",
            r"new\s+URL\s*\(",
            r"RestTemplate\.\w+\s*\(",
            r"HttpClient\.\w+",
        ]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = []

        self.vul_function = ["openConnection", "URL", "RestTemplate"]

    def main(self, regex_string):
        pass
