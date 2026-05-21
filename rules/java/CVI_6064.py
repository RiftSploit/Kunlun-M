# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6064():
    """
    Commons Collections ≤3.2.1 InvokerTransformer 反序列化链
    """
    def __init__(self):
        self.svid = 6064
        self.language = "java"
        self.vulnerability = "Commons Collections 反序列化 RCE"
        self.author = "Kunlun-M"
        self.level = 8
        self.status = True
        self.description = "Commons Collections ≤3.2.1 的 InvokerTransformer 可被利用构造反序列化利用链,配合反序列化入口触发RCE"

        self.match_mode = "framework-dependency"
        self.match = None

        self.framework_deps = [
            {
                "group_id": "commons-collections",
                "artifact_id": "commons-collections",
                "version_range": "<=3.2.1",
                "cve": "CVE-2015-7501",
                "description": "Commons Collections InvokerTransformer 反序列化链",
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
