# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6056():
    """
    Apache Struts2 后续 RCE 漏洞 (S2-048~S2-059)
    S2-048(2.3.32), S2-057(2.3.34), S2-059(2.5.16)
    """
    def __init__(self):
        self.svid = 6056
        self.language = "java"
        self.vulnerability = "Struts2 RCE (S2-048/057/059)"
        self.level = 7
        self.status = True
        self.author = "Kunlun-M"
        self.description = "Struts2 2.3.x/2.5.x 多个RCE漏洞(S2-048/057/059)"

        self.match_mode = "framework-dependency"
        self.match = None

        self.framework_deps = [
            {
                "group_id": "org.apache.struts",
                "artifact_id": "struts2-core",
                "version_range": ">=2.3.20,<=2.3.34",
                "cve": "CVE-2017-9791/CVE-2018-11776",
                "description": "Struts2 S2-048/S2-057",
            },
            {
                "group_id": "org.apache.struts",
                "artifact_id": "struts2-core",
                "version_range": ">=2.5.0,<=2.5.16",
                "cve": "CVE-2019-0230",
                "description": "Struts2 S2-059 OGNL注入",
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
