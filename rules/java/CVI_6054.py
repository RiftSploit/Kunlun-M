# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6054():
    """
    Apache Struts2 OGNL 远程代码执行 (S2-001~S2-016)
    struts2-core <=2.3.15 存在多个 OGNL 表达式注入漏洞
    """
    def __init__(self):
        self.svid = 6054
        self.language = "java"
        self.vulnerability = "Struts2 OGNL 表达式注入 RCE"
        self.level = 7
        self.status = True
        self.author = "Kunlun-M"
        self.description = "Struts2 <=2.3.15 存在多个OGNL表达式注入漏洞(S2-001/003/005/007/009/012/013/015/016)"

        self.match_mode = "framework-dependency"
        self.match = None

        self.framework_deps = [
            {
                "group_id": "org.apache.struts",
                "artifact_id": "struts2-core",
                "version_range": ">=2.0.0,<=2.3.15",
                "cve": "CVE-2008-6502~CVE-2013-2251",
                "description": "Struts2 OGNL注入 (S2-001~S2-016)",
            },
        ]
        self.config_patterns = []
        self.exclude_patterns = []

        self.match_name = None
        self.black_list = None
        self.keyword = None
        self.unmatch = None
        self.vul_function = None
        self.main = None
