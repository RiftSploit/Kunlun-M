"""
JAVASCRIPT 内置函数/方法可控性知识库

为静态分析引擎提供该语言内置函数的返回值可控性信息，避免对已知函数进行不必要的函数体分析。

知识条目结构:
    {"函数名": {"passthrough": [参数位置列表], "safe": bool}}

    - passthrough: 返回值依赖哪些参数的位置（0-indexed）。
      [] 表示返回值与输入参数无关（如 len() 返回整数）。
    - safe: True 表示该函数做了有效安全过滤，返回值不再构成安全威胁。
"""
from typing import Dict, List, Optional, Union

# {"函数名": {"passthrough": [参数位置列表], "safe": bool}}
KNOWLEDGE: Dict[str, Dict[str, Union[List[int], bool]]] = {
        # ===== String 方法（透传 this） =====
        "toUpperCase":      {"passthrough": [0], "safe": False},
        "toLowerCase":      {"passthrough": [0], "safe": False},
        "trim":             {"passthrough": [0], "safe": False},
        "trimStart":        {"passthrough": [0], "safe": False},
        "trimEnd":          {"passthrough": [0], "safe": False},
        "trimLeft":         {"passthrough": [0], "safe": False},
        "trimRight":        {"passthrough": [0], "safe": False},
        "replace":          {"passthrough": [0], "safe": False},
        "replaceAll":       {"passthrough": [0], "safe": False},
        "split":            {"passthrough": [0], "safe": False},
        "substring":        {"passthrough": [0], "safe": False},
        "substr":           {"passthrough": [0], "safe": False},
        "slice":            {"passthrough": [0], "safe": False},
        "concat":           {"passthrough": [0], "safe": False},
        "padStart":         {"passthrough": [0], "safe": False},
        "padEnd":           {"passthrough": [0], "safe": False},
        "repeat":           {"passthrough": [0], "safe": False},
        "toString":         {"passthrough": [0], "safe": False},
        "valueOf":          {"passthrough": [0], "safe": False},
        "charAt":           {"passthrough": [0], "safe": False},
        "charCodeAt":       {"passthrough": [], "safe": True},
        "codePointAt":      {"passthrough": [], "safe": True},
        "normalize":        {"passthrough": [0], "safe": False},
        "localeCompare":    {"passthrough": [], "safe": True},
        "match":            {"passthrough": [0], "safe": False},
        "matchAll":         {"passthrough": [0], "safe": False},
        "search":           {"passthrough": [], "safe": True},
        "at":               {"passthrough": [0], "safe": False},
        "fontsize":         {"passthrough": [0], "safe": False},
        "fixed":            {"passthrough": [0], "safe": False},
        "bold":             {"passthrough": [0], "safe": False},
        "italics":          {"passthrough": [0], "safe": False},
        "link":             {"passthrough": [0], "safe": False},

        # ===== Array 方法 =====
        "map":              {"passthrough": [0], "safe": False},
        "filter":           {"passthrough": [0], "safe": False},
        "reduce":           {"passthrough": [0], "safe": False},
        "flat":             {"passthrough": [0], "safe": False},
        "flatMap":          {"passthrough": [0], "safe": False},
        "sort":             {"passthrough": [0], "safe": False},
        "reverse":          {"passthrough": [0], "safe": False},
        "splice":           {"passthrough": [0], "safe": False},
        "slice":            {"passthrough": [0], "safe": False},
        "concat":           {"passthrough": [0], "safe": False},
        "join":             {"passthrough": [0], "safe": False},
        "find":             {"passthrough": [0], "safe": False},
        "findIndex":        {"passthrough": [], "safe": True},
        "indexOf":          {"passthrough": [], "safe": True},
        "lastIndexOf":      {"passthrough": [], "safe": True},
        "includes":         {"passthrough": [], "safe": True},
        "every":            {"passthrough": [], "safe": True},
        "some":             {"passthrough": [], "safe": True},
        "forEach":          {"passthrough": [], "safe": True},
        "push":             {"passthrough": [], "safe": True},
        "pop":              {"passthrough": [0], "safe": False},
        "shift":            {"passthrough": [0], "safe": False},
        "unshift":          {"passthrough": [], "safe": True},
        "fill":             {"passthrough": [0], "safe": False},
        "copyWithin":       {"passthrough": [0], "safe": False},

        # ===== 全局函数 =====
        "String":           {"passthrough": [0], "safe": False},
        "Number":           {"passthrough": [], "safe": True},
        "Boolean":          {"passthrough": [], "safe": True},
        "parseInt":         {"passthrough": [], "safe": True},
        "parseFloat":       {"passthrough": [], "safe": True},
        "isNaN":            {"passthrough": [], "safe": True},
        "isFinite":         {"passthrough": [], "safe": True},
        "Array.from":       {"passthrough": [0], "safe": False},
        "Array.of":         {"passthrough": [0], "safe": False},
        "Object.keys":      {"passthrough": [0], "safe": False},
        "Object.values":    {"passthrough": [0], "safe": False},
        "Object.entries":   {"passthrough": [0], "safe": False},
        "Object.assign":    {"passthrough": [0, 1], "safe": False},
        "Object.create":    {"passthrough": [0], "safe": False},

        # ===== 编解码 =====
        "JSON.stringify":       {"passthrough": [0], "safe": False},
        "JSON.parse":           {"passthrough": [0], "safe": False},
        "encodeURI":            {"passthrough": [0], "safe": False},
        "encodeURIComponent":   {"passthrough": [0], "safe": False},
        "decodeURI":            {"passthrough": [0], "safe": False},
        "decodeURIComponent":   {"passthrough": [0], "safe": False},
        "btoa":                 {"passthrough": [0], "safe": False},
        "atob":                 {"passthrough": [0], "safe": False},
        "escape":               {"passthrough": [0], "safe": False},
        "unescape":             {"passthrough": [0], "safe": False},

        # ===== 安全过滤 =====
        "DOMPurify.sanitize":   {"passthrough": [0], "safe": True},
        "sanitize":             {"passthrough": [0], "safe": True},

        # ===== 不透传 =====
        "length":       {"passthrough": [], "safe": True},
        "typeof":       {"passthrough": [], "safe": True},
        "instanceof":   {"passthrough": [], "safe": True},
        "console.log":  {"passthrough": [], "safe": True},
        "console.warn": {"passthrough": [], "safe": True},
        "console.error": {"passthrough": [], "safe": True},
        "alert":        {"passthrough": [], "safe": True},
        "Math.floor":   {"passthrough": [], "safe": True},
        "Math.ceil":    {"passthrough": [], "safe": True},
        "Math.round":   {"passthrough": [], "safe": True},
        "Math.abs":     {"passthrough": [], "safe": True},
        "Math.max":     {"passthrough": [], "safe": True},
        "Math.min":     {"passthrough": [], "safe": True},
        "Math.random":  {"passthrough": [], "safe": True},

        # ===== Express =====
        "express":              {"passthrough": [], "safe": True},

        # ===== jQuery =====
        "html":                 {"passthrough": [0], "safe": False},
        "append":               {"passthrough": [0], "safe": False},
        "prepend":              {"passthrough": [0], "safe": False},
        "after":                {"passthrough": [0], "safe": False},
        "before":               {"passthrough": [0], "safe": False},
        "replaceWith":          {"passthrough": [0], "safe": False},
        "text":                 {"passthrough": [], "safe": True},
        "attr":                 {"passthrough": [1], "safe": False},
        "val":                  {"passthrough": [0], "safe": False},
        "css":                  {"passthrough": [1], "safe": False},

        # ===== Vue.js =====
        "v-html":               {"passthrough": [0], "safe": False},
        "$createElement":        {"passthrough": [0], "safe": False},

        # ===== React =====
        "dangerouslySetInnerHTML": {"passthrough": [0], "safe": False},

        # ===== template engines =====
        "res.render":           {"passthrough": [0], "safe": False},
        "res.send":             {"passthrough": [0], "safe": False},
        "res.json":             {"passthrough": [0], "safe": False},
        "res.sendFile":         {"passthrough": [0], "safe": False},
        "res.redirect":         {"passthrough": [0], "safe": False},
        "res.write":            {"passthrough": [0], "safe": False},
        "ejs.render":           {"passthrough": [0], "safe": False},
        "ejs.renderFile":       {"passthrough": [0], "safe": False},
        "pug.render":           {"passthrough": [0], "safe": False},
        "handlebars.compile":   {"passthrough": [0], "safe": False},
        "nunjucks.render":      {"passthrough": [0], "safe": False},

        # ===== Angular =====
        "bypassSecurityTrustHtml":        {"passthrough": [0], "safe": False},
        "bypassSecurityTrustStyle":       {"passthrough": [0], "safe": False},
        "bypassSecurityTrustScript":      {"passthrough": [0], "safe": False},
        "bypassSecurityTrustUrl":         {"passthrough": [0], "safe": False},
        "bypassSecurityTrustResourceUrl": {"passthrough": [0], "safe": False},
        "sanitize":                       {"passthrough": [0], "safe": True},
        "DomSanitizer.sanitize":          {"passthrough": [0], "safe": True},
        "DomSanitizer.bypassSecurityTrustHtml":        {"passthrough": [0], "safe": False},
        "DomSanitizer.bypassSecurityTrustStyle":       {"passthrough": [0], "safe": False},
        "DomSanitizer.bypassSecurityTrustScript":      {"passthrough": [0], "safe": False},
        "DomSanitizer.bypassSecurityTrustUrl":         {"passthrough": [0], "safe": False},
        "DomSanitizer.bypassSecurityTrustResourceUrl": {"passthrough": [0], "safe": False},

        # ===== Next.js =====
        "getServerSideProps":  {"passthrough": [0], "safe": False},
        "getStaticProps":      {"passthrough": [0], "safe": False},
        "getStaticPaths":      {"passthrough": [0], "safe": False},
        "getInitialProps":     {"passthrough": [0], "safe": False},
        "NextResponse.json":   {"passthrough": [0], "safe": False},
        "NextResponse.redirect": {"passthrough": [0], "safe": False},
        "NextResponse.rewrite":  {"passthrough": [0], "safe": False},
        "NextRequest.nextUrl":    {"passthrough": [0], "safe": False},
        "NextRequest.cookies":    {"passthrough": [0], "safe": False},
        "NextRequest.searchParams": {"passthrough": [0], "safe": False},

        # ===== NestJS =====
        "Controller":          {"passthrough": [0], "safe": False},
        "Get":                 {"passthrough": [0], "safe": False},
        "Post":                {"passthrough": [0], "safe": False},
        "Put":                 {"passthrough": [0], "safe": False},
        "Delete":              {"passthrough": [0], "safe": False},
        "Patch":               {"passthrough": [0], "safe": False},
        "Body":                {"passthrough": [0], "safe": False},
        "Query":               {"passthrough": [0], "safe": False},
        "Param":               {"passthrough": [0], "safe": False},
        "Headers":             {"passthrough": [0], "safe": False},
        "Req":                 {"passthrough": [0], "safe": False},
        "Res":                 {"passthrough": [0], "safe": False},
        "HttpException":       {"passthrough": [0], "safe": False},
        "HttpStatus":          {"passthrough": [], "safe": True},
        " NestFactory.create": {"passthrough": [0], "safe": False},
        "ValidationPipe":      {"passthrough": [0], "safe": False},

        # ===== Koa =====
        "ctx.body":            {"passthrough": [0], "safe": False},
        "ctx.redirect":        {"passthrough": [0], "safe": False},
        "ctx.render":          {"passthrough": [0], "safe": False},
        "ctx.attachment":      {"passthrough": [0], "safe": False},
        "ctx.set":             {"passthrough": [1], "safe": False},
        "ctx.append":          {"passthrough": [1], "safe": False},
        "ctx.query":           {"passthrough": [0], "safe": False},
        "ctx.params":          {"passthrough": [0], "safe": False},
        "ctx.request.body":    {"passthrough": [0], "safe": False},
        "ctx.request.query":   {"passthrough": [0], "safe": False},
        "ctx.request.header":  {"passthrough": [0], "safe": False},
        "ctx.request.headers": {"passthrough": [0], "safe": False},
        "ctx.throw":           {"passthrough": [0], "safe": False},
        "ctx.type":            {"passthrough": [0], "safe": False},
        "ctx.status":          {"passthrough": [], "safe": True},

        # ===== Lodash =====
        "_.escape":            {"passthrough": [0], "safe": True},
        "_.unescape":          {"passthrough": [0], "safe": False},
        "_.template":          {"passthrough": [0], "safe": False},
        "_.merge":             {"passthrough": [0, 1], "safe": False},
        "_.extend":            {"passthrough": [0, 1], "safe": False},
        "_.assign":            {"passthrough": [0, 1], "safe": False},
        "_.assignIn":          {"passthrough": [0, 1], "safe": False},
        "_.defaults":          {"passthrough": [0, 1], "safe": False},
        "_.defaultsDeep":      {"passthrough": [0, 1], "safe": False},
        "_.clone":             {"passthrough": [0], "safe": False},
        "_.cloneDeep":         {"passthrough": [0], "safe": False},
        "_.pick":              {"passthrough": [0], "safe": False},
        "_.omit":              {"passthrough": [0], "safe": False},
        "_.get":               {"passthrough": [0], "safe": False},
        "_.set":               {"passthrough": [0], "safe": False},
        "_.has":               {"passthrough": [], "safe": True},
        "_.isString":          {"passthrough": [], "safe": True},
        "_.isObject":          {"passthrough": [], "safe": True},
        "_.isArray":           {"passthrough": [], "safe": True},
        "_.isEmpty":           {"passthrough": [], "safe": True},
        "_.trim":              {"passthrough": [0], "safe": False},
        "_.lowerCase":         {"passthrough": [0], "safe": False},
        "_.upperCase":         {"passthrough": [0], "safe": False},
        "_.camelCase":         {"passthrough": [0], "safe": False},
        "_.snakeCase":         {"passthrough": [0], "safe": False},
        "_.kebabCase":         {"passthrough": [0], "safe": False},
        "_.deburr":            {"passthrough": [0], "safe": False},
        "_.truncate":          {"passthrough": [0], "safe": False},
        "_.replace":           {"passthrough": [0], "safe": False},
        "_.split":             {"passthrough": [0], "safe": False},
        "_.join":              {"passthrough": [0], "safe": False},
        "_.sortBy":            {"passthrough": [0], "safe": False},
        "_.groupBy":           {"passthrough": [0], "safe": False},
        "_.flatten":           {"passthrough": [0], "safe": False},
        "_.flattenDeep":       {"passthrough": [0], "safe": False},
        "_.uniqueId":          {"passthrough": [], "safe": True},
        "_.result":            {"passthrough": [0], "safe": False},
        "_.invoke":            {"passthrough": [0], "safe": False},

        # ===== Axios =====
        "axios.get":           {"passthrough": [0], "safe": False},
        "axios.post":          {"passthrough": [0], "safe": False},
        "axios.put":           {"passthrough": [0], "safe": False},
        "axios.delete":        {"passthrough": [0], "safe": False},
        "axios.patch":         {"passthrough": [0], "safe": False},
        "axios.head":          {"passthrough": [0], "safe": False},
        "axios.options":       {"passthrough": [0], "safe": False},
        "axios.request":       {"passthrough": [0], "safe": False},
        "axios.create":        {"passthrough": [], "safe": True},
        "axios.all":           {"passthrough": [0], "safe": False},
        "axios.spread":        {"passthrough": [0], "safe": False},
        "axios.CancelToken":   {"passthrough": [], "safe": True},
        "axios.isCancel":      {"passthrough": [], "safe": True},
}


def lookup(func_name: str) -> Optional[Dict[str, Union[List[int], bool]]]:
    """
    查询该语言的内置函数知识库

    :param func_name: 函数/方法名
    :return: {"passthrough": [...], "safe": bool} 或 None
    """
    # 精确匹配
    if func_name in KNOWLEDGE:
        return KNOWLEDGE[func_name]

    # 短名匹配（方法名不带类/模块前缀）
    # 如 "html.escape" -> 尝试 "escape"
    if "." in func_name:
        short_name = func_name.split(".")[-1]
        if short_name in KNOWLEDGE:
            return KNOWLEDGE[short_name]

    return None