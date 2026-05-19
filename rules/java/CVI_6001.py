# -*- coding: utf-8 -*-

"""
    Java SQL Injection Rule
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6001():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6001
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "SQL Injection"
        self.description = "使用了不安全的SQL查询方式（如createStatement、executeQuery等），可能导致SQL注入漏洞。建议使用PreparedStatement进行参数化查询。"
        self.level = 8

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [r"createStatement\(\)"]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"PreparedStatement", r"prepareStatement", r"@Query"]

        self.vul_function = None

    def main(self, regex_string):
        pass
