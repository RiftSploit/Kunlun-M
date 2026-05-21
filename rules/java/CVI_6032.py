# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6032():
    def __init__(self):
        self.svid = 6032
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Command Injection (function-param-controllable)"
        self.description = "通过AST分析检测Runtime.exec参数是否来自用户可控输入"
        self.level = 9
        self.status = True
        self.match_mode = "java-function-param-regex"
        self.match = "exec"
        self.unmatch = []
        self.match_name = None
        self.black_list = []
        self.keyword = None
        self.vul_function = None

    def main(self, regex_string):
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除 Playground scenario 字符串
        if re.search(r'scenario', regex_string, re.I):
            return False
        return None
