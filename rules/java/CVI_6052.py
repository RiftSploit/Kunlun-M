# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6052():
    """
    Apache Shiro 认证绕过漏洞
    CVE-2020-1957 (<=1.5.2), CVE-2020-11989 (<=1.5.3), CVE-2020-17523 (<=1.7.1)
    Shiro 过滤链配置不当可绕过权限校验
    """
    def __init__(self):
        self.svid = 6052
        self.language = "java"
        self.vulnerability = "Shiro 认证绕过"
        self.level = 7
        self.status = True
        self.author = "Kunlun-M"
        self.description = "Shiro 过滤链配置不当导致认证绕过"

        self.match_mode = "framework-dependency"
        self.match = None

        self.framework_deps = [
            {
                "group_id": "org.apache.shiro",
                "artifact_id": "shiro-spring",
                "version_range": "<=1.7.1",
                "cve": "CVE-2020-1957/CVE-2020-11989/CVE-2020-17523",
                "description": "Shiro 认证绕过(多个CVE)",
            },
        ]
        self.config_patterns = ["ShiroFilterFactoryBean", "filterChainDefinitionMap"]
        self.exclude_patterns = []

        self.match_name = None
        self.black_list = None
        self.keyword = None
        self.unmatch = None
        self.vul_function = None
        self.main = None
