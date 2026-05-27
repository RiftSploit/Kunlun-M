#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Go Engine — Go 自动规则生成引擎
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Phase 1: 暂不支持自动规则生成，返回 None

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""
import traceback
from utils.log import logger


def init_match_rule(data):
    """
    处理 Go 新生成规则初始化正则匹配
    Phase 1: 暂不支持自动规则生成，返回 None
    """
    logger.debug("[New Rule] Go auto rule generation not supported in Phase 1")
    return None, None, None, 0, "None"
