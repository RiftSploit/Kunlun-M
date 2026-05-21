# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6023():
    def __init__(self):
        self.svid = 6023
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "ProcessBuilder Command Injection"
        self.description = "请求参数直接传入ProcessBuilder构建命令，存在命令注入风险"
        self.level = 9
        self.status = True
        self.match_mode = "regex-return-regex"
        self.match = [r"new\s+ProcessBuilder\(.*?=padding="]
        self.unmatch = []
        self.match_name = r"(?:String\s+(\w+)\s*=\s*request\.(?:getParameter|getHeader|getInputStream|getReader|getQueryString|getParameterValues|getParameterMap|getCookies)\([^)]*\)|@(?:RequestParam|PathVariable|RequestHeader|CookieValue|QueryParam|FormParam)\s*(?:\([^)]*\)\s*)?String\s+(\w+))"
        self.black_list = []
        self.keyword = None
        self.vul_function = None

    def main(self, regex_string):
        pass
