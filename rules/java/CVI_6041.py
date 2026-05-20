# -*- coding: utf-8 -*-

"""
    Java SSTI Rule (AST-enhanced)
    ~~~~
"""

from utils.api import *


class CVI_6041():
    def __init__(self):
        self.svid = 6041
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "SSTI"
        self.description = "用户输入进入模板引擎渲染可能导致服务端模板注入"
        self.level = 4

        self.status = True
        self.match_mode = "function-param-regex"
        self.match = "process|evaluate"
        self.match_name = None
        self.black_list = None
        self.keyword = None
        self.unmatch = [r"AutoEscaping", r"sandbox", r"SecurityManager"]
        self.vul_function = ["process", "evaluate"]

    def main(self, regex_string):
        """二次筛选：交给 AST 分析判断"""
        return None
