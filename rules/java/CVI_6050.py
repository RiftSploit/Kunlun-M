# -*- coding: utf-8 -*-
from utils.api import *


class CVI_6050():
    """
    Apache Shiro <= 1.2.4 RememberMe 默认密钥反序列化漏洞 (CVE-2016-4437)
    使用 CookieRememberMeManager 且未设置自定义 cipherKey 时，
    攻击者可利用默认密钥构造恶意序列化数据触发 RCE
    """
    def __init__(self):
        self.svid = 6050
        self.language = "java"
        self.vulnerability = "Shiro RememberMe 反序列化 RCE"
        self.level = 7
        self.status = True
        self.author = "Kunlun-M"
        self.description = "Shiro <=1.2.4 使用默认密钥 kPH+bIxk5D2deZiIxcaaaA== 的 CookieRememberMeManager，可被利用执行任意代码"

        self.match_mode = "framework-dependency"
        self.match = None

        # 框架依赖配置
        self.framework_deps = [
            {
                "group_id": "org.apache.shiro",
                "artifact_id": "shiro-spring",
                "version_range": "<=1.2.4",
                "cve": "CVE-2016-4437",
                "description": "Shiro rememberMe 默认密钥反序列化",
            },
        ]

        # 二次确认: 代码中使用了 CookieRememberMeManager
        self.config_patterns = ["CookieRememberMeManager"]

        # 排除: 明确设置了非默认 cipherKey（出现 cipherKey + 不出现 DEFAULT_KEY/默认密钥）
        # 注意: setCipherKey(DEFAULT_KEY_BYTES) 仍然是弱密钥，不应排除
        self.exclude_patterns = []

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None
        self.vul_function = None
        self.main = None
