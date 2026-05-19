#!/usr/bin/env python
# -*- coding: utf-8 -*-
import traceback
from utils.log import logger


def init_match_rule(data):
    """
    处理 Java 新生成规则初始化正则匹配
    Phase 1: 暂不支持自动规则生成，返回 None
    """
    logger.debug("[New Rule] Java auto rule generation not supported in Phase 1")
    return None, None, None, 0, "None"
