# -*- coding: utf-8 -*-

"""
    Java XXE Rule
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6007():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6007
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "XXE"
        self.description = "使用了不安全的XML解析器（如DocumentBuilderFactory、SAXParserFactory等），未禁用外部实体，可能导致XXE漏洞。建议设置disallow-doctype-decl或FEATURE_SECURE_PROCESSING。"
        self.level = 8

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)"]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"setFeature.*disallow-doctype-decl", r"FEATURE_SECURE_PROCESSING", r"setExpandEntityReferences\(false\)"]

        self.vul_function = None

    def main(self, regex_string):
        pass
