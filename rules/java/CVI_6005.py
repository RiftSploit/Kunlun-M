# -*- coding: utf-8 -*-

"""
    Java Insecure Deserialization Rule
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6005():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6005
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Insecure Deserialization"
        self.description = "使用了ObjectInputStream、readObject()、XMLDecoder等不安全的反序列化方式，可能导致远程代码执行漏洞。建议使用ObjectInputFilter或ValidatingObjectInputStream进行过滤。"
        self.level = 9

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [r"readObject\(\)"]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"ObjectInputFilter", r"ValidatingObjectInputStream", r"SafeObjectInputStream"]

        self.vul_function = None

    def main(self, regex_string):
        pass
