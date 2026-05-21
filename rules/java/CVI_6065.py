# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6065():
    """
    XStream ≤1.4.14 反序列化 RCE
    """
    def __init__(self):
        self.svid = 6065
        self.language = "java"
        self.vulnerability = "XStream 反序列化 RCE"
        self.author = "Kunlun-M"
        self.level = 8
        self.status = True
        self.description = "XStream ≤1.4.14 存在多个反序列化漏洞(CVE-2020-26217等),攻击者可构造恶意XML触发任意代码执行"

        self.match_mode = "framework-dependency"
        self.match = None

        self.framework_deps = [
            {
                "group_id": "com.thoughtworks.xstream",
                "artifact_id": "xstream",
                "version_range": "<=1.4.14",
                "cve": "CVE-2020-26217/CVE-2021-21341",
                "description": "XStream 多个反序列化漏洞",
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
