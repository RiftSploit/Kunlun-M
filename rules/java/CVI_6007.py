# -*- coding: utf-8 -*-

"""
    Java XXE Rule (AST-enhanced)
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
        self.description = "通过AST分析检测DocumentBuilderFactory/SAXParserFactory/XMLInputFactory等XML解析器是否未禁用外部实体，追踪数据流以发现XXE漏洞。建议设置disallow-doctype-decl或FEATURE_SECURE_PROCESSING。"
        self.level = 8

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = [
            r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(\s*\)",
            r"SAXParser\s*\.\s*parse\s*\(",
            r"DocumentBuilder\s*\.\s*parse\s*\(",
            r"XMLReader\s*\.\s*parse\s*\(",
        ]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [
            r"setFeature.*disallow-doctype-decl",
            r"FEATURE_SECURE_PROCESSING",
            r"setExpandEntityReferences\(false\)",
        ]

        self.vul_function = ["parse", "DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory"]

    def main(self, regex_string):
        pass
