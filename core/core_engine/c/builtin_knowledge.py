# -*- coding: utf-8 -*-
# @Time    : 2025
# @Author  : KunLun-M
# @File    : builtin_knowledge.py

"""
    C/C++ 内置函数知识库
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

KNOWLEDGE = {
    # ============ 字符串处理 — 透传 ============
    "strlen": {"passthrough": [0], "safe": True},
    "strcpy": {"passthrough": [1], "safe": False},
    "strncpy": {"passthrough": [1], "safe": False},
    "strcat": {"passthrough": [0, 1], "safe": False},
    "strncat": {"passthrough": [0, 1], "safe": False},
    "strdup": {"passthrough": [0], "safe": True},
    "strndup": {"passthrough": [0], "safe": True},
    "memcpy": {"passthrough": [1], "safe": False},
    "memmove": {"passthrough": [1], "safe": False},
    "memset": {"passthrough": [], "safe": True},  # 用固定值填充，不透传
    "memcmp": {"passthrough": [], "safe": True},
    "strstr": {"passthrough": [0, 1], "safe": True},
    "strtok": {"passthrough": [0], "safe": False},
    "strsep": {"passthrough": [0], "safe": False},

    # ============ 格式化输出 — 按参数位置透传 ============
    "sprintf": {"passthrough": [0], "safe": False},    # 格式化到缓冲区
    "snprintf": {"passthrough": [0], "safe": False},
    "printf": {"passthrough": [], "safe": True},       # 输出到 stdout
    "fprintf": {"passthrough": [], "safe": True},      # 输出到 FILE*
    "sscanf": {"passthrough": [], "safe": True},
    "fscanf": {"passthrough": [], "safe": True},

    # ============ 类型转换 — 透传 ============
    "atoi": {"passthrough": [0], "safe": True},
    "atol": {"passthrough": [0], "safe": True},
    "atof": {"passthrough": [0], "safe": True},
    "strtol": {"passthrough": [0], "safe": True},
    "strtoul": {"passthrough": [0], "safe": True},
    "strtod": {"passthrough": [0], "safe": True},
    "strtof": {"passthrough": [0], "safe": True},
    "strtol": {"passthrough": [0], "safe": True},
    "strtoll": {"passthrough": [0], "safe": True},
    "strtoull": {"passthrough": [0], "safe": True},

    # ============ 内存分配 ============
    "malloc": {"passthrough": [], "safe": True},       # 分配大小可控不等于内容可控
    "calloc": {"passthrough": [], "safe": True},
    "realloc": {"passthrough": [0], "safe": True},
    "free": {"passthrough": [], "safe": True},
    "alloca": {"passthrough": [], "safe": True},

    # ============ 安全/修复函数 — 标记 safe ============
    "mysql_real_escape_string": {"passthrough": [], "safe": True},
    "PQescapeString": {"passthrough": [], "safe": True},
    "PQescapeLiteral": {"passthrough": [], "safe": True},
    "PQescapeByteaConn": {"passthrough": [], "safe": True},
    "sqlite3_bind_text": {"passthrough": [], "safe": True},
    "sqlite3_bind_parameter_index": {"passthrough": [], "safe": True},
    "sqlite3_mprintf": {"passthrough": [], "safe": True},
    "sqlite3_vmprintf": {"passthrough": [], "safe": True},
    "sqlite3_snprintf": {"passthrough": [], "safe": True},
    "addslashes": {"passthrough": [], "safe": True},
    "mysql_escape_string": {"passthrough": [], "safe": True},
    "pg_escape_string": {"passthrough": [], "safe": True},
    "sqlite3_escape": {"passthrough": [], "safe": True},

    # ============ 终止函数 ============
    "exit": {"passthrough": [], "safe": True},
    "abort": {"passthrough": [], "safe": True},
    "_exit": {"passthrough": [], "safe": True},
    "quick_exit": {"passthrough": [], "safe": True},

    # ============ I/O 函数 ============
    "fgets": {"passthrough": [0], "safe": False},       # 缓冲区被填充
    "gets": {"passthrough": [0], "safe": False},         # 已废弃，但需追踪
    "getline": {"passthrough": [0], "safe": False},
    "fread": {"passthrough": [0], "safe": False},
    "fwrite": {"passthrough": [0], "safe": True},
    "fputs": {"passthrough": [0], "safe": True},
    "puts": {"passthrough": [0], "safe": True},
    "fgetc": {"passthrough": [], "safe": True},         # 返回单个字符
    "getc": {"passthrough": [], "safe": True},
    "getchar": {"passthrough": [], "safe": True},
    "read": {"passthrough": [1], "safe": False},        # POSIX read，缓冲区被填充
    "write": {"passthrough": [1], "safe": True},
    "recv": {"passthrough": [1], "safe": False},
    "recvfrom": {"passthrough": [1], "safe": False},
    "send": {"passthrough": [1], "safe": True},
    "sendto": {"passthrough": [1], "safe": True},
    "scanf": {"passthrough": [], "safe": False},
    "fscanf": {"passthrough": [], "safe": False},
}
