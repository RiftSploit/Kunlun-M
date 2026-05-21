# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6062():
    """
    Fastjson 1.2.25-1.2.47 autoType 绕过
    """
    def __init__(self):
        self.svid = 6062
        self.language = "java"
        self.vulnerability = "Fastjson autoType 绕过 RCE"
        self.author = "Kunlun-M"
        self.level = 8
        self.status = True
        self.description = "Fastjson 1.2.25-1.2.47 autoType黑名单可被多次绕过,包括缓存投毒、expectClass等多种bypass"

        self.match_mode = "framework-dependency"
        self.match = None

        self.framework_deps = [
            {
                "group_id": "com.alibaba",
                "artifact_id": "fastjson",
                "version_range": ">=1.2.25,<=1.2.47",
                "cve": "CVE-2019-14441/CVE-2020-14165",
                "description": "Fastjson autoType 多次绕过",
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
