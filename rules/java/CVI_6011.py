# -*- coding: utf-8 -*-

"""
    Java Insecure File Upload Rule
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_6011():
    """
    rule class
    """

    def __init__(self):
        self.svid = 6011
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Insecure File Upload"
        self.description = "处理文件上传时使用了MultipartFile及相关方法，未对文件类型或扩展名进行校验，可能导致恶意文件上传漏洞。"
        self.level = 7

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = [r"MultipartFile"]

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = [r"validateFile", r"checkExtension", r"allowedExtensions"]

        self.vul_function = None

    def main(self, regex_string):
        pass
