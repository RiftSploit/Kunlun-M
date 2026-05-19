# -*- coding: utf-8 -*-

"""
    Java Insecure Cryptography Rule
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6008():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6008
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Insecure Cryptography"
        self.description = "使用了不安全的加密算法（如DES、RC2、RC4、Blowfish）或弱哈希算法（如MD5、SHA-1），建议使用AES、RSA、HmacSHA256、BCrypt等安全算法。"
        self.level = 5

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [r"Cipher\.getInstance\(\s*\"(?:DES|RC4|Blowfish)\")"]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"AES", r"RSA", r"HmacSHA256", r"BCrypt", r"PBKDF2", r"SHA-256", r"SHA-512"]

        self.vul_function = None

    def main(self, regex_string):
        pass
