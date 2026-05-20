# -*- coding: utf-8 -*-

"""
    Java Fastjson Deserialization (only-regex)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6037():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6037
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Fastjson Deserialization"
        self.description = "使用了Fastjson的JSON.parseObject/parse方法进行反序列化，若未启用safeMode或AutoType黑名单，可能导致远程代码执行。建议升级Fastjson到1.2.83+或使用Fastjson2。"
        self.level = 9

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [r"JSON\.(?:parseObject|parse)\("]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"safeMode", r"AutoTypeSafeCache", r"ParserConfig\.getGlobalInstance\(\)\.setAutoTypeSupport\(false\)"]

        self.vul_function = None

    def main(self, regex_string):
        pass
