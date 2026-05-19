# -*- coding: utf-8 -*-

"""
    Java SSRF Rule
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
        self.description = "使用用户输入构造URL并发起HTTP请求（如new URL(getParameter)、HttpURLConnection、RestTemplate等），可能导致服务端请求伪造漏洞。"
        self.level = 7

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [r"openConnection\(\)"]

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
