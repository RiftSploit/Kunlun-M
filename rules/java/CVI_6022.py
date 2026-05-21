# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6022():
    def __init__(self):
        self.svid = 6022
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "XSS via HttpServletResponse"
        self.description = "请求参数未经编码直接通过Response输出，存在反射型XSS风险"
        self.level = 6
        self.status = True
        self.match_mode = "regex-return-regex"
        self.match = [r"getWriter\(\)\.print\(.*?=padding="]
        self.unmatch = [r"encode", r"escape", r"HtmlUtils", r"ESAPI"]
        self.match_name = r"(?:String\s+(\w+)\s*=\s*request\.(?:getParameter|getHeader|getInputStream|getReader|getQueryString|getParameterValues|getParameterMap|getCookies)\([^)]*\)|@(?:RequestParam|PathVariable|RequestHeader|CookieValue|QueryParam|FormParam)\s*(?:\([^)]*\)\s*)?String\s+(\w+))"
        self.black_list = []
        self.keyword = None
        self.vul_function = None

    def main(self, regex_string):
        pass
