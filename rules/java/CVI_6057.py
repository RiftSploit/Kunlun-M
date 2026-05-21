# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6057():
    """
    Apache Struts2 S2-061/062 OGNL 远程代码执行
    CVE-2020-17530 (S2-061), CVE-2021-31805 (S2-062)
    """
    def __init__(self):
        self.svid = 6057
        self.language = "java"
        self.vulnerability = "Struts2 S2-061/062 OGNL RCE"
        self.level = 7
        self.status = True
        self.author = "Kunlun-M"
        self.description = "Struts2 2.0.0-2.5.29 S2-061/062 OGNL远程代码执行"

        self.match_mode = "framework-dependency"
        self.match = None

        self.framework_deps = [
            {
                "group_id": "org.apache.struts",
                "artifact_id": "struts2-core",
                "version_range": ">=2.0.0,<=2.5.29",
                "cve": "CVE-2020-17530/CVE-2021-31805",
                "description": "Struts2 S2-061/062 OGNL RCE",
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
