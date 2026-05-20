# -*- coding: utf-8 -*-

"""
    Java Open Redirect Rule (AST-enhanced)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6015():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6015
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Open Redirect"
        self.description = "使用用户输入（如getParameter获取的参数）作为重定向目标地址（sendRedirect或Location头），未进行白名单校验，可能导致开放重定向漏洞。"
        self.level = 5

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "sendRedirect"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"validateRedirect", r"isValidRedirect", r"allowedDomains"]

        self.vul_function = ["sendRedirect"]

    def main(self, regex_string):
        pass
