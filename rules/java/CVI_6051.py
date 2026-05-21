# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6051():
    """
    Apache Shiro 1.2.5-1.4.2 Padding Oracle 漏洞 (CVE-2019-11963)
    rememberMe cookie 的 CBC 模式加密存在 Padding Oracle 攻击面
    """
    def __init__(self):
        self.svid = 6051
        self.language = "java"
        self.vulnerability = "Shiro Padding Oracle"
        self.level = 7
        self.status = True
        self.author = "Kunlun-M"
        self.description = "Shiro 1.2.5-1.4.2 CBC模式Padding Oracle漏洞"

        self.match_mode = "framework-dependency"
        self.match = None

        self.framework_deps = [
            {
                "group_id": "org.apache.shiro",
                "artifact_id": "shiro-spring",
                "version_range": ">=1.2.5,<=1.4.2",
                "cve": "CVE-2019-11963",
                "description": "Shiro Padding Oracle CBC模式漏洞",
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
