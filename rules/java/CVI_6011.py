# -*- coding: utf-8 -*-

"""
    Java Insecure File Upload Rule (AST-enhanced)
    ~~~~
"""

from utils.api import *


class CVI_6011():
    def __init__(self):
        self.svid = 6011
        self.language = "java"
        self.author = "KunLun-M"
        self.vulnerability = "Insecure File Upload"
        self.description = "用户可控的文件上传可能导致恶意文件上传攻击"
        self.level = 3

        self.status = True
        self.match_mode = "function-param-regex"
        self.match = "transferTo|getInputStream|getBytes|getOriginalFilename"
        self.match_name = None
        self.black_list = None
        self.keyword = None
        self.unmatch = [r"isValidExtension", r"checkFileType", r"MimeTypeUtils"]
        self.vul_function = ["transferTo", "getInputStream", "getBytes", "getOriginalFilename"]


    def main(self, regex_string):
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除有扩展名白名单校验的写法
        if re.search(r"ALLOWED_EXTENSIONS|allowedExtensions|isValidExtension|checkFileType|ImageIO\.read|MimeTypeUtils", regex_string, re.I):
            return False
        return None

