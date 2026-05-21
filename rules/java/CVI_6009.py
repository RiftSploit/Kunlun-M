# -*- coding: utf-8 -*-

"""
    Java Hardcoded Password/Key Rule
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6009():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6009
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Hardcoded Password/Key"
        self.description = "代码中存在硬编码的密码、密钥或API Key，可能导致敏感信息泄露。建议通过环境变量或配置文件动态获取。"
        self.level = 5

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [
            r'(?:password|passwd|PASSWORD|secret|SECRET|apiKey|api_key|API_KEY|accessKey|access_key|secretKey|secret_key|private[_\-]?[Kk]ey|token|AUTH_TOKEN|credential)\s*=\s*(?:new\s+String\s*\(\s*)?"[^"]{4,}"(?:\s*\)?)?',
        ]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [
            r"System\.getenv",
            r"@Value\s*\(",
            r"properties\.getProperty",
            r"config\.get",
            r"getenv\s*\(",
            r"Optional\.of",
            r"Strings\.isEmpty",
            r"\.equals\s*\(",
        ]

        self.vul_function = None

    def main(self, regex_string):
        pass
