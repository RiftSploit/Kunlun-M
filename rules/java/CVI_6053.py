# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6053():
    """
    Apache Shiro 硬编码/弱密钥 (>=1.4.2)
    使用已知弱密钥列表中的密钥配置 CookieRememberMeManager
    """
    def __init__(self):
        self.svid = 6053
        self.language = "java"
        self.vulnerability = "Shiro 弱密钥"
        self.level = 7
        self.status = True
        self.author = "Kunlun-M"
        self.description = "Shiro 使用硬编码弱密钥,可被利用构造恶意rememberMe"

        self.match_mode = "framework-dependency"
        self.match = None

        self.framework_deps = [
            {
                "group_id": "org.apache.shiro",
                "artifact_id": "shiro-spring",
                "version_range": ">=1.4.2",
                "cve": "",
                "description": "Shiro 可能使用弱密钥",
            },
        ]
        # 使用了 rememberMe + 硬编码密钥
        self.config_patterns = ["DEFAULT_KEY", "kPH+bIxk5D2deZiIxcaaaA=="]
        self.exclude_patterns = []

        self.match_name = None
        self.black_list = None
        self.keyword = None
        self.unmatch = None
        self.vul_function = None
        self.main = None
