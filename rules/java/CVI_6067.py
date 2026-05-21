# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6067():
    """
    Spring Boot Actuator 未授权访问
    """
    def __init__(self):
        self.svid = 6067
        self.language = "java"
        self.vulnerability = "Spring Boot Actuator 未授权访问"
        self.author = "Kunlun-M"
        self.level = 7
        self.status = True
        self.description = "Spring Boot Actuator 端点默认可能对外暴露(env/health/heapdump等),敏感信息泄露或RCE风险"

        self.match_mode = "framework-dependency"
        self.match = None

        self.framework_deps = [
            {
                "group_id": "org.springframework.boot",
                "artifact_id": "spring-boot-starter-actuator",
                "version_range": ">=1.0,<=2.6",
                "cve": "",
                "description": "Spring Boot Actuator 可能未授权访问",
            },
        ]

        self.config_patterns = []
        self.exclude_patterns = ["management.security.enabled=true", "management.endpoints.web.exposure.exclude", "endpoints.enabled=false"]

        self.match_name = None
        self.black_list = None
        self.keyword = None
        self.unmatch = None
        self.vul_function = None
        self.main = None
