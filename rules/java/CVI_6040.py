# -*- coding: utf-8 -*-

"""
    Jackson Deserialization Vulnerability
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""
from utils.api import *


class CVI_6040():
    def __init__(self):
        self.svid = 6040
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Jackson Deserialization (enableDefaultTyping)"
        self.description = "Jackson ObjectMapper启用了enableDefaultTyping，可能导致反序列化漏洞（CVE-2017-7525等）"
        self.level = 9
        self.status = True
        self.match_mode = "only-regex"
        self.match = [r'enableDefaultTyping\(\)']
        self.unmatch = [r'PolymorphicTypeValidator', r'activateDefaultTyping']
        self.black_list = []
        self.keyword = None
        self.vul_function = None

    def main(self, regex_string):
        pass
