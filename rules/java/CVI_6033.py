# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6033():
    def __init__(self):
        self.svid = 6033
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "File Path Traversal (function-param-controllable)"
        self.description = "通过AST分析检测FileInputStream/FileOutputStream参数是否来自用户可控输入"
        self.level = 8
        self.status = False
        self.match_mode = "java-function-param-regex"
        self.match = "FileInputStream|FileOutputStream"
        self.unmatch = []
        self.match_name = None
        self.black_list = []
        self.keyword = None
        self.vul_function = None

    def main(self, regex_string):
        pass
