# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6063():
    """
    Fastjson 1.2.68-1.2.80 autoType safeMode 绕过
    """
    def __init__(self):
        self.svid = 6063
        self.language = "java"
        self.vulnerability = "Fastjson safeMode 绕过 RCE"
        self.author = "Kunlun-M"
        self.level = 7
        self.status = True
        self.description = "Fastjson 1.2.68引入safeMode但有绕过,1.2.80之前版本仍存在expectClass利用链"

        self.match_mode = "framework-dependency"
        self.match = None

        self.framework_deps = [
            {
                "group_id": "com.alibaba",
                "artifact_id": "fastjson",
                "version_range": ">=1.2.68,<=1.2.80",
                "cve": "CVE-2022-25845",
                "description": "Fastjson autoType safeMode 绕过",
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
