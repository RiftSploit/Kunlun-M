# -*- coding: utf-8 -*-

"""
    Java Insecure Random Rule
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6016():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6016
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Insecure Random"
        self.description = "使用了不安全的随机数生成器（如java.util.Random或Math.random()），在安全敏感场景下应使用SecureRandom。"
        self.level = 3

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [
            r'(?:java\.util\.Random|new\s+Random\s*\(\s*\)|Math\.random\s*\(\s*\))',
        ]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"SecureRandom"]

        self.vul_function = None

    def main(self, regex_string):
        pass
