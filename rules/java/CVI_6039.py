# -*- coding: utf-8 -*-

"""
    MyBatis SQL Injection via ${} interpolation
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""
from utils.api import *


class CVI_6039():
    def __init__(self):
        self.svid = 6039
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "MyBatis SQL Injection (${...} interpolation)"
        self.description = "MyBatis mapper中使用${...}进行字符串拼接而非#{...}参数化查询，存在SQL注入风险"
        self.level = 8
        self.status = True
        self.match_mode = "only-regex"
        self.match = [r'\$\{[^}]+\}']
        self.unmatch = []
        self.black_list = []
        self.keyword = None
        self.vul_function = None

    def main(self, regex_string):
        pass
