# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6060():
    """
    Log4j2 JNDI 远程代码执行 (Log4Shell)
    """
    def __init__(self):
        self.svid = 6060
        self.language = "java"
        self.vulnerability = "Log4j2 JNDI RCE (Log4Shell)"
        self.author = "Kunlun-M"
        self.level = 9
        self.status = True
        self.description = "Log4j2 2.0-beta9~2.14.1 存在JNDI注入漏洞(CVE-2021-44228),攻击者可通过日志消息触发远程代码执行"

        self.match_mode = "framework-dependency"
        self.match = None

        self.framework_deps = [
            {
                "group_id": "org.apache.logging.log4j",
                "artifact_id": "log4j-core",
                "version_range": ">=2.0,<=2.14.1",
                "cve": "CVE-2021-44228",
                "description": "Log4j2 JNDI RCE (Log4Shell)",
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
