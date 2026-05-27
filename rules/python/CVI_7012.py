# -*- coding: utf-8 -*-
from utils.api import *


class CVI_7012():
    """
    Python XPath 注入
    覆盖: lxml.etree.xpath, xml.etree.ElementTree xpath 调用
    """
    def __init__(self):
        self.svid = 7012
        self.language = "python"
        self.author = "LoRexxar"
        self.vulnerability = "XPath注入"
        self.description = "XPath查询使用了可能可控的查询字符串，可能导致XPath注入"
        self.level = 6
        self.status = True
        self.match_mode = "function-param-regex"
        self.match = r"\.xpath\(|lxml\.etree\.xpath|etree\.xpath|ElementTree\.xpath|tree\.xpath|root\.xpath"
        self.match_name = None
        self.black_list = None
        self.keyword = None
        self.unmatch = None
        self.vul_function = ["xpath"]

    def main(self, regex_string):
        pass
