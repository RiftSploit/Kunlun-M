# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6061():
    """
    Fastjson ≤1.2.24 autoType 反序列化 RCE
    """
    def __init__(self):
        self.svid = 6061
        self.language = "java"
        self.vulnerability = "Fastjson autoType 反序列化 RCE"
        self.author = "Kunlun-M"
        self.level = 9
        self.status = True
        self.description = "Fastjson ≤1.2.24 autoType默认开启,攻击者可构造恶意JSON触发任意类实例化(CVE-2017-18349)"

        self.match_mode = "framework-dependency"
        self.match = None

        self.framework_deps = [
            {
                "group_id": "com.alibaba",
                "artifact_id": "fastjson",
                "version_range": "<=1.2.24",
                "cve": "CVE-2017-18349",
                "description": "Fastjson autoType 默认开启反序列化",
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
