# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6031():
    def __init__(self):
        self.svid = 6031
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "JDBC SQL Injection (function-param-controllable)"
        self.description = "通过AST分析检测executeQuery参数是否来自用户可控输入"
        self.level = 9
        self.status = True
        self.match_mode = "java-function-param-regex"
        self.match = "executeQuery|executeUpdate"
        self.unmatch = []
        self.match_name = None
        self.black_list = []
        self.keyword = None
        self.vul_function = ["executeQuery", "executeUpdate"]

    def main(self, regex_string):
        pass
