# -*- coding: utf-8 -*-

"""
    SSTI (Server-Side Template Injection)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""
from utils.api import *


class CVI_6041():
    def __init__(self):
        self.svid = 6041
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Server-Side Template Injection (SSTI)"
        self.description = "用户输入直接用于模板引擎渲染（FreeMarker/Velocity/Thymeleaf），存在SSTI/RCE风险"
        self.level = 9
        self.status = True
        self.match_mode = "only-regex"
        self.match = [r'Template\s*\.\s*process\(', r'Velocity\.evaluate\(', r'FreeMarkerTemplateEngine', r'StringTemplateLoader']
        self.unmatch = [r'autoEscape', r'escapeHtml', r'StringEscapeUtils']
        self.black_list = []
        self.keyword = None
        self.vul_function = None

    def main(self, regex_string):
        pass
