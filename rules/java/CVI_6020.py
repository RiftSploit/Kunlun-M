# -*- coding: utf-8 -*-

"""
    Java Insecure JWT Rule
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6020():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6020
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Insecure JWT"
        self.description = "JWT使用了不安全的配置，如Algorithm.none()无签名或空字符串作为签名密钥，可能导致JWT伪造和身份冒充。应使用HMAC、RSA或ECDSA等安全签名算法。"
        self.level = 6

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [
            r'Algorithm\.none\s*\(\s*\)',
            r'\.signWith\s*\(\s*Algorithm\.none',
            r'\.setSigningKey\s*\(\s*""\s*\)',
            r'JWT\.require\s*\(\s*Algorithm\.none',
        ]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"HMAC", r"RSA", r"ECDSA", r"SecretKey", r"KeyPair"]

        self.vul_function = None

    def main(self, regex_string):
        pass
