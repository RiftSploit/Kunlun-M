# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6025():
    def __init__(self):
        self.svid = 6025
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Path Traversal via Request Parameter"
        self.description = "请求参数直接用于构建文件路径，存在路径遍历风险"
        self.level = 7
        self.status = True
        self.match_mode = "regex-return-regex"
        self.match = [r"(?:new\s+File\(.{0,20}=padding=\)|new\s+FileInputStream\(.{0,20}=padding=\))"]
        self.unmatch = [r"normalize\(\)", r"getCanonicalPath"]
        self.match_name = r"(?:String\s+(\w+)\s*=\s*request\.(?:getParameter|getHeader|getInputStream|getReader|getQueryString|getParameterValues|getParameterMap|getCookies)\([^)]*\)|@(?:RequestParam|PathVariable|RequestHeader|CookieValue|QueryParam|FormParam)\s*(?:\([^)]*\)\s*)?String\s+(\w+))"
        self.black_list = []
        self.keyword = None
        self.vul_function = None

    def main(self, regex_string):
        pass
