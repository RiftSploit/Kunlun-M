# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6024():
    def __init__(self):
        self.svid = 6024
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "SSRF via Request Parameter"
        self.description = "请求参数直接用于构建URL对象发起网络请求，存在SSRF风险"
        self.level = 7
        self.status = True
        self.match_mode = "regex-return-regex"
        self.match = [r"new\s+URL\(=padding=\)"]
        self.unmatch = []
        self.match_name = r"(?:String\s+(\w+)\s*=\s*request\.(?:getParameter|getHeader|getInputStream|getReader|getQueryString|getParameterValues|getParameterMap|getCookies)\([^)]*\)|@(?:RequestParam|PathVariable|RequestHeader|CookieValue|QueryParam|FormParam)\s*(?:\([^)]*\)\s*)?String\s+(\w+))"
        self.black_list = []
        self.keyword = None
        self.vul_function = None

    def main(self, regex_string):
        pass
