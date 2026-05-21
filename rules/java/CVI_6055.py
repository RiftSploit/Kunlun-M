# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6055():
    """
    Apache Struts2 Jakarta Multipart Parser RCE (S2-045/S2-046)
    CVE-2017-5638 / CVE-2017-5639
    基于 Content-Type 头的 OGNL 注入
    """
    def __init__(self):
        self.svid = 6055
        self.language = "java"
        self.vulnerability = "Struts2 Jakarta Multipart RCE (S2-045)"
        self.level = 7
        self.status = True
        self.author = "Kunlun-M"
        self.description = "Struts2 2.3.5-2.3.32 / 2.5.0-2.5.10 Jakarta Multipart OGNL注入(CVE-2017-5638)"

        self.match_mode = "framework-dependency"
        self.match = None

        self.framework_deps = [
            {
                "group_id": "org.apache.struts",
                "artifact_id": "struts2-core",
                "version_range": ">=2.3.5,<=2.3.32",
                "cve": "CVE-2017-5638",
                "description": "Struts2 Jakarta Multipart RCE (S2-045)",
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
