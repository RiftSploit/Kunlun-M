# -*- coding: utf-8 -*-

"""
    Java SpEL/OGNL Injection Rule
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6012():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6012
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "SpEL/OGNL Injection"
        self.description = "使用了SpEL表达式解析（parseExpression）或OGNL表达式求值，如果表达式内容可控，可能导致远程代码执行漏洞。建议使用SimpleEvaluationContext限制表达式能力。"
        self.level = 9

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [r"(?:parseExpression|Ognl\.getValue|Ognl\.parseExpression)"]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"SimpleEvaluationContext"]

        self.vul_function = None

    def main(self, regex_string):
        pass
