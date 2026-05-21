# -*- coding: utf-8 -*-

"""
    Java Open Redirect Rule (AST-enhanced)
    ~~~~
"""

from utils.api import *


class CVI_6015():
    def __init__(self):
        self.svid = 6015
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Open Redirect"
        self.description = "用户可控的重定向URL可能导致开放重定向攻击"
        self.level = 2

        self.status = True
        self.match_mode = "function-param-regex"
        self.match = "sendRedirect"
        self.match_name = None
        self.black_list = None
        self.keyword = None
        self.unmatch = [r"isValidRedirect", r"whitelist", r"allowedDomains"]
        self.vul_function = ["sendRedirect"]

    def main(self, regex_string):
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除有白名单校验的写法
        if re.search(r"isUrlAllowed|ALLOWED_HOSTS|allowedHosts|whitelist|urlWhitelist|isValidRedirect", regex_string, re.I):
            return False
        return None
