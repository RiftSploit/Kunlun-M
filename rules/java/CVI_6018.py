# -*- coding: utf-8 -*-

"""
    Java Insecure Reflection Rule (AST-enhanced)
    ~~~~
"""

from utils.api import *


class CVI_6018():
    def __init__(self):
        self.svid = 6018
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Insecure Reflection"
        self.description = "用户可控的反射调用可能导致绕过安全检查或代码执行"
        self.level = 3

        self.status = True
        self.match_mode = "function-param-regex"
        self.match = "forName|getDeclaredMethod|getMethod"
        self.match_name = None
        self.black_list = None
        self.keyword = None
        self.unmatch = None
        self.vul_function = ["forName", "getDeclaredMethod", "getMethod"]

    def main(self, regex_string):
        """函数名足够精确，不做额外筛选"""
        return None
