# -*- coding: utf-8 -*-
"""
    demo
    ~~~~
    Java default repair functions and controlled params
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""
JAVA_IS_REPAIR_DEFAULT = {
    # SQL 注入修复：使用 PreparedStatement
    "prepareStatement": [6001, 6031],
    "setString": [6001, 6031],
    "setInt": [6001, 6031],
    "setLong": [6001, 6031],
    # XSS 修复：HTML 转义
    "encodeForHTML": [6002, 6022],
    "escapeHtml": [6002, 6022],
    "escapeHtml4": [6002, 6022],
    "encodeForJavaScript": [6002, 6022],
    # 命令注入修复
    "escapeShellArg": [6003, 6032, 6038],
    # 路径遍历修复：路径标准化
    "normalize": [6004, 6033],
    "getCanonicalPath": [6004, 6033],
    # SSRF 修复：URL 白名单校验
    "isUrlAllowed": [6006, 6034],
    "validateUrl": [6006, 6034],
    # 反序列化修复
    "ObjectInputFilter": [6005, 6035],
    "resolveClass": [6005, 6035],
}

JAVA_IS_CONTROLLED_DEFAULT = [
    "request",
]
