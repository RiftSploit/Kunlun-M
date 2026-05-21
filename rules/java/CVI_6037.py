# -*- coding: utf-8 -*-

"""
    Java Fastjson Deserialization Rule (AST-enhanced)
    ~~~~
"""

from utils.api import *


class CVI_6037():
    def __init__(self):
        self.svid = 6037
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Fastjson Deserialization"
        self.description = "Fastjson反序列化用户可控JSON可能导致远程代码执行"
        self.level = 4

        self.status = True
        self.match_mode = "java-function-param-regex"
        self.match = "parseObject|parse"
        self.match_name = None
        self.black_list = None
        self.keyword = None
        self.unmatch = [r"SafeMode", r"autoTypeFilter", r"ParserConfig.getGlobalInstance\\(\\).setAutoTypeSupport"]
        self.vul_function = ["parseObject", "parse"]

    def main(self, regex_string):
        """二次筛选：只保留 JSON/Fastjson 上下文"""
        code = regex_string.strip() if isinstance(regex_string, str) else str(regex_string)
        if not re.search(r'JSON|json|fastjson|alibaba', code, re.I):
            return False
        return None
