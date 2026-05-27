"""
PHP 内置函数/方法可控性知识库

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
        # ===== 字符串函数 =====
        "trim":             {"passthrough": [0], "safe": False},
        "ltrim":            {"passthrough": [0], "safe": False},
        "rtrim":            {"passthrough": [0], "safe": False},
        "strtoupper":       {"passthrough": [0], "safe": False},
        "strtolower":       {"passthrough": [0], "safe": False},
        "ucfirst":          {"passthrough": [0], "safe": False},
        "lcfirst":          {"passthrough": [0], "safe": False},
        "ucwords":          {"passthrough": [0], "safe": False},
        "substr":           {"passthrough": [0], "safe": False},
        "substring":        {"passthrough": [0], "safe": False},
        "str_replace":      {"passthrough": [2], "safe": False},  # 透传 subject
        "str_ireplace":     {"passthrough": [2], "safe": False},
        "implode":          {"passthrough": [1], "safe": False},  # 透传 array
        "explode":          {"passthrough": [1], "safe": False},  # 透传 string
        "sprintf":          {"passthrough": [1], "safe": False},
        "printf":           {"passthrough": [1], "safe": False},
        "str_pad":          {"passthrough": [0], "safe": False},
        "str_repeat":       {"passthrough": [0], "safe": False},
        "strrev":           {"passthrough": [0], "safe": False},
        "str_shuffle":      {"passthrough": [0], "safe": False},
        "nl2br":            {"passthrough": [0], "safe": False},
        "chunk_split":      {"passthrough": [0], "safe": False},
        "wordwrap":         {"passthrough": [0], "safe": False},
        "strtok":           {"passthrough": [0], "safe": False},
        "parse_str":        {"passthrough": [0], "safe": False},

        # ===== 编解码 =====
        "base64_encode":        {"passthrough": [0], "safe": False},
        "base64_decode":        {"passthrough": [0], "safe": False},
        "urldecode":            {"passthrough": [0], "safe": False},
        "urlencode":            {"passthrough": [0], "safe": False},
        "rawurldecode":         {"passthrough": [0], "safe": False},
        "rawurlencode":         {"passthrough": [0], "safe": False},
        "html_entity_decode":   {"passthrough": [0], "safe": False},
        "json_encode":          {"passthrough": [0], "safe": False},
        "json_decode":          {"passthrough": [0], "safe": False},
        "serialize":            {"passthrough": [0], "safe": False},
        "unserialize":          {"passthrough": [0], "safe": False},
        "utf8_encode":          {"passthrough": [0], "safe": False},
        "utf8_decode":          {"passthrough": [0], "safe": False},
        "iconv":                {"passthrough": [2], "safe": False},  # 透传 string
        "mb_convert_encoding":  {"passthrough": [0], "safe": False},
        "mb_strtolower":        {"passthrough": [0], "safe": False},
        "mb_strtoupper":        {"passthrough": [0], "safe": False},
        "mb_substr":            {"passthrough": [0], "safe": False},
        "mb_ereg_replace":      {"passthrough": [2], "safe": False},
        "preg_replace":         {"passthrough": [2], "safe": False},  # 透传 subject

        # ===== 类型转换 =====
        "strval":       {"passthrough": [0], "safe": False},
        "intval":       {"passthrough": [], "safe": True},   # 返回整数
        "floatval":     {"passthrough": [], "safe": True},
        "settype":      {"passthrough": [], "safe": True},
        "array_values": {"passthrough": [0], "safe": False},
        "array_keys":   {"passthrough": [0], "safe": False},
        "array_map":    {"passthrough": [1], "safe": False},
        "array_filter": {"passthrough": [0], "safe": False},
        "array_merge":  {"passthrough": [0, 1], "safe": False},
        "array_reverse": {"passthrough": [0], "safe": False},
        "array_slice":  {"passthrough": [0], "safe": False},
        "array_unique": {"passthrough": [0], "safe": False},
        "sort":         {"passthrough": [0], "safe": False},
        "asort":        {"passthrough": [0], "safe": False},
        "ksort":        {"passthrough": [0], "safe": False},
        "compact":      {"passthrough": [0], "safe": False},
        "extract":      {"passthrough": [0], "safe": False},

        # ===== 安全过滤函数 =====
        "htmlspecialchars":             {"passthrough": [0], "safe": True},
        "htmlentities":                 {"passthrough": [0], "safe": True},
        "strip_tags":                   {"passthrough": [0], "safe": True},
        "mysql_real_escape_string":     {"passthrough": [0], "safe": True},
        "mysqli_real_escape_string":    {"passthrough": [0], "safe": True},
        "pg_escape_string":             {"passthrough": [0], "safe": True},
        "sqlite_escape_string":         {"passthrough": [0], "safe": True},
        "addslashes":                   {"passthrough": [0], "safe": True},
        "stripslashes":                 {"passthrough": [0], "safe": False},
        "escapeshellcmd":               {"passthrough": [0], "safe": True},
        "escapeshellarg":               {"passthrough": [0], "safe": True},
        "filter_var":                   {"passthrough": [0], "safe": True},
        "filter_input":                 {"passthrough": [], "safe": True},
        "ctype_digit":                  {"passthrough": [], "safe": True},
        "ctype_alpha":                  {"passthrough": [], "safe": True},
        "ctype_alnum":                  {"passthrough": [], "safe": True},
        "preg_match":                   {"passthrough": [], "safe": True},
        "number_format":                {"passthrough": [], "safe": True},
        "chr":                          {"passthrough": [], "safe": True},

        # ===== 不透传 =====
        "strlen":       {"passthrough": [], "safe": True},
        "strpos":       {"passthrough": [], "safe": True},
        "strrpos":      {"passthrough": [], "safe": True},
        "stripos":      {"passthrough": [], "safe": True},
        "strripos":     {"passthrough": [], "safe": True},
        "strcmp":       {"passthrough": [], "safe": True},
        "strcasecmp":   {"passthrough": [], "safe": True},
        "substr_count": {"passthrough": [], "safe": True},
        "count":        {"passthrough": [], "safe": True},
        "sizeof":       {"passthrough": [], "safe": True},
        "is_array":     {"passthrough": [], "safe": True},
        "is_string":    {"passthrough": [], "safe": True},
        "is_int":       {"passthrough": [], "safe": True},
        "is_integer":   {"passthrough": [], "safe": True},
        "is_numeric":   {"passthrough": [], "safe": True},
        "is_null":      {"passthrough": [], "safe": True},
        "is_bool":      {"passthrough": [], "safe": True},
        "isset":        {"passthrough": [], "safe": True},
        "empty":        {"passthrough": [], "safe": True},
        "defined":      {"passthrough": [], "safe": True},
        "function_exists": {"passthrough": [], "safe": True},
        "class_exists": {"passthrough": [], "safe": True},
        "method_exists": {"passthrough": [], "safe": True},
        "property_exists": {"passthrough": [], "safe": True},
        "in_array":     {"passthrough": [], "safe": True},
        "array_key_exists": {"passthrough": [], "safe": True},
        "array_search": {"passthrough": [], "safe": True},
        "print":        {"passthrough": [], "safe": True},
        "echo":         {"passthrough": [], "safe": True},
        "var_dump":     {"passthrough": [], "safe": True},
        "print_r":      {"passthrough": [], "safe": True},
        "die":          {"passthrough": [], "safe": True},
        "exit":         {"passthrough": [], "safe": True},
        "header":       {"passthrough": [], "safe": True},
        "http_response_code": {"passthrough": [], "safe": True},

        # ===== Laravel =====
        "e":                    {"passthrough": [0], "safe": True},
        "csrf_field":           {"passthrough": [], "safe": True},
        "csrf_token":           {"passthrough": [], "safe": True},
        "redirect":             {"passthrough": [0], "safe": False},
        "route":                {"passthrough": [], "safe": True},
        "asset":                {"passthrough": [], "safe": True},
        "url":                  {"passthrough": [0], "safe": False},
        "action":               {"passthrough": [], "safe": True},
        "response":             {"passthrough": [0], "safe": False},
        "old":                  {"passthrough": [0], "safe": False},
        "session":              {"passthrough": [0], "safe": False},
        "cookie":               {"passthrough": [0], "safe": False},
        "config":               {"passthrough": [0], "safe": False},
        "env":                  {"passthrough": [0], "safe": False},
        "app":                  {"passthrough": [0], "safe": False},
        "request":              {"passthrough": [0], "safe": False},
        "Illuminate\\Support\\Str::limit":     {"passthrough": [0], "safe": False},
        "Illuminate\\Support\\Str::words":     {"passthrough": [0], "safe": False},
        "Illuminate\\Support\\Str::slug":      {"passthrough": [0], "safe": False},
        "Illuminate\\Support\\Str::studly":    {"passthrough": [0], "safe": False},
        "Illuminate\\Support\\Str::camel":     {"passthrough": [0], "safe": False},
        "Illuminate\\Support\\Str::kebab":     {"passthrough": [0], "safe": False},
        "Illuminate\\Support\\Str::snake":     {"passthrough": [0], "safe": False},
        "Illuminate\\Support\\Str::title":     {"passthrough": [0], "safe": False},

        # ===== ThinkPHP =====
        "input":                {"passthrough": [0], "safe": False},
        "I":                    {"passthrough": [0], "safe": False},

        # ===== WordPress =====
        "esc_html":             {"passthrough": [0], "safe": True},
        "esc_attr":             {"passthrough": [0], "safe": True},
        "esc_url":              {"passthrough": [0], "safe": True},
        "esc_js":               {"passthrough": [0], "safe": True},
        "esc_textarea":         {"passthrough": [0], "safe": True},
        "wp_kses":              {"passthrough": [0], "safe": True},
        "wp_kses_post":         {"passthrough": [0], "safe": True},
        "sanitize_text_field":  {"passthrough": [0], "safe": True},
        "sanitize_email":       {"passthrough": [0], "safe": True},
        "sanitize_title":       {"passthrough": [0], "safe": True},
        "sanitize_file_name":   {"passthrough": [0], "safe": True},
        "wp_nonce_field":       {"passthrough": [], "safe": True},
        "wp_nonce_url":         {"passthrough": [0], "safe": False},
        "wp_verify_nonce":      {"passthrough": [], "safe": True},
        "wp_safe_redirect":     {"passthrough": [0], "safe": True},
        "absint":               {"passthrough": [], "safe": True},
        "wp_kses_allowed_html": {"passthrough": [0], "safe": True},

        # ===== CodeIgniter =====
        "xss_clean":            {"passthrough": [0], "safe": True},
        "html_escape":          {"passthrough": [0], "safe": True},

        # ===== Symfony =====
        "Symfony\\Component\\Form\\FormFactoryInterface::createForm":   {"passthrough": [0], "safe": False},
        "Symfony\\Component\\Form\\FormInterface::getData":             {"passthrough": [0], "safe": False},
        "Symfony\\Component\\Form\\FormInterface::handleRequest":       {"passthrough": [0], "safe": False},
        "Symfony\\Component\\Form\\FormInterface::submit":              {"passthrough": [0], "safe": False},
        "Symfony\\Component\\Form\\FormInterface::isValid":             {"passthrough": [], "safe": True},
        "Symfony\\Component\\HttpFoundation\\Request::get":             {"passthrough": [0], "safe": False},
        "Symfony\\Component\\HttpFoundation\\Request::query":           {"passthrough": [0], "safe": False},
        "Symfony\\Component\\HttpFoundation\\Request::request":         {"passthrough": [0], "safe": False},
        "Symfony\\Component\\HttpFoundation\\Request::headers":         {"passthrough": [0], "safe": False},
        "Symfony\\Component\\HttpFoundation\\Request::getContent":      {"passthrough": [0], "safe": False},
        "Symfony\\Component\\HttpFoundation\\Request::getClientIp":     {"passthrough": [], "safe": True},
        "Symfony\\Component\\Templating\\EngineInterface::render":      {"passthrough": [0], "safe": False},
        "Twig\\Environment::render":                                    {"passthrough": [0], "safe": False},
        "Twig\\Environment::createTemplate":                            {"passthrough": [0], "safe": False},
        "Twig\\Extension\\EscaperExtension::escape":                    {"passthrough": [0], "safe": True},
        "Symfony\\Component\\HttpFoundation\\Response::setContent":      {"passthrough": [0], "safe": False},
        "Symfony\\Component\\HttpFoundation\\JsonResponse::setData":     {"passthrough": [0], "safe": False},
        "Symfony\\Component\\Security\\Csrf\\CsrfTokenManager::getToken": {"passthrough": [], "safe": True},
        "Symfony\\Component\\Security\\Csrf\\CsrfTokenManager::isTokenValid": {"passthrough": [], "safe": True},
        "twig_escape_filter":                   {"passthrough": [0], "safe": True},

        # ===== Drupal =====
        "check_plain":                  {"passthrough": [0], "safe": True},
        "check_markup":                 {"passthrough": [0], "safe": True},
        "filter_xss":                   {"passthrough": [0], "safe": True},
        "filter_xss_admin":             {"passthrough": [0], "safe": True},
        "drupal_html_escape":           {"passthrough": [0], "safe": True},
        "drupal_html_to_text":          {"passthrough": [0], "safe": True},
        "Drupal\\Component\\Utility\\Html::escape":            {"passthrough": [0], "safe": True},
        "Drupal\\Component\\Utility\\Html::decodeEntities":    {"passthrough": [0], "safe": False},
        "Drupal\\Component\\Utility\\UrlHelper::filterQueryParameters": {"passthrough": [0], "safe": True},
        "Drupal\\Component\\Utility\\UrlHelper::isValid":      {"passthrough": [], "safe": True},
        "Drupal\\Component\\Utility\\Xss::filter":             {"passthrough": [0], "safe": True},
        "Drupal\\Component\\Utility\\Xss::filterAdmin":        {"passthrough": [0], "safe": True},
        "Drupal\\Core\\Render\\Markup::create":                {"passthrough": [0], "safe": False},
        "Drupal\\Core\\Render\\Element\\HtmlTag":              {"passthrough": [0], "safe": False},
        "format_string":                {"passthrough": [0], "safe": False},
        "t":                            {"passthrough": [0], "safe": False},
        "theme":                        {"passthrough": [0], "safe": False},

        # ===== Yii =====
        "Yii\\helpers\\Html::encode":              {"passthrough": [0], "safe": True},
        "Yii\\helpers\\Html::encodePurified":      {"passthrough": [0], "safe": True},
        "Yii\\helpers\\HtmlPurifier::process":     {"passthrough": [0], "safe": True},
        "Yii\\helpers\\Html::tag":                 {"passthrough": [1], "safe": False},
        "Yii\\helpers\\Html::beginTag":            {"passthrough": [0], "safe": False},
        "Yii\\helpers\\Html::endTag":              {"passthrough": [0], "safe": False},
        "Yii\\helpers\\Html::a":                   {"passthrough": [1], "safe": False},
        "Yii\\helpers\\Html::img":                 {"passthrough": [0], "safe": False},
        "Yii\\helpers\\Html::script":              {"passthrough": [0], "safe": False},
        "Yii\\helpers\\Html::style":               {"passthrough": [0], "safe": False},
        "Yii\\helpers\\Html::csrfMetaTags":        {"passthrough": [], "safe": True},
        "Yii\\helpers\\Html::csrfField":           {"passthrough": [], "safe": True},
        "Yii\\helpers\\Json::encode":              {"passthrough": [0], "safe": False},
        "Yii\\helpers\\Json::decode":              {"passthrough": [0], "safe": False},
        "Yii\\helpers\\Url::to":                   {"passthrough": [0], "safe": False},
        "Yii\\web\\Request::get":                  {"passthrough": [0], "safe": False},
        "Yii\\web\\Request::post":                 {"passthrough": [0], "safe": False},
        "Yii\\web\\Request::getBodyParam":         {"passthrough": [0], "safe": False},
        "Yii\\web\\Request::getQueryParam":        {"passthrough": [0], "safe": False},
        "Yii\\web\\Response::content":             {"passthrough": [0], "safe": False},
        "Yii\\web\\Response::redirect":            {"passthrough": [0], "safe": False},

        # ===== Guzzle =====
        "GuzzleHttp\\Client::request":             {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Client::get":                 {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Client::post":                {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Client::put":                 {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Client::delete":              {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Client::patch":               {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Client::head":                {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Client::send":                {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Client::sendAsync":           {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Client::requestAsync":        {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Client::getConfig":           {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Psr7\\Request":               {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Psr7\\Response::getBody":     {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Psr7\\Response::getHeader":   {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Psr7\\Response::getHeaders":  {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Utils::jsonDecode":           {"passthrough": [0], "safe": False},
        "GuzzleHttp\\Utils::jsonEncode":           {"passthrough": [0], "safe": False},
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