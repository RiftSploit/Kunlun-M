#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Go AST Parser — Go 反向污点追踪引擎
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Go 语言静态分析引擎，支持正则匹配和 AST 污点追踪。

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""
import re
import traceback
import ast
import tokenize
import io

from utils.log import logger
from core.pretreatment import ast_object as _ast_object_singleton
from core.core_engine.trace_cache import TraceCache
from core.core_engine.go.builtin_knowledge import lookup as lookup_builtin
from core.core_engine.go.summary_generator import generate_file_summaries, lookup_summary, _summary_registry
from core.core_engine.function_summary import SummaryCacheManager

# tree-sitter Go AST 解析
try:
    import tree_sitter_go as _tsgo
    from tree_sitter import Language as _TS_Language, Parser as _TS_Parser
    _GO_TS_LANGUAGE = _TS_Language(_tsgo.language())
    _ts_parser = _TS_Parser(_GO_TS_LANGUAGE)
    _HAS_TREE_SITTER = True
except ImportError:
    _HAS_TREE_SITTER = False
    _ts_parser = None
    _GO_TS_LANGUAGE = None

scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []

# 追踪缓存 + 内置知识库
_trace_cache = TraceCache("go")

# 跨函数追踪递归防护栈
_scan_function_stack = []

# 函数摘要状态
_summaries_initialized = False
_file_summaries = {}

# Go 特有的可控输入源
GO_CONTROLLED_SOURCES = [
    "r.URL.Query()", "r.FormValue", "r.PostFormValue",
    "r.Header.Get", "r.Header.Get",
    "r.Body", "r.URL.Path", "r.URL.RawPath",
    "r.Host", "r.RemoteAddr", "r.UserAgent",
    "r.Referer", "r.Method",
    "os.Args", "os.Getenv",
    "flag.String", "flag.Int", "flag.Bool",
    "gin.Default", "c.Query", "c.Param", "c.PostForm",
    "c.ShouldBind", "c.ShouldBindJSON", "c.ShouldBindQuery",
    "c.GetHeader", "c.GetCookie",
    "echo.QueryParams", "echo.FormValue",
    "fiber.Query", "fiber.Params", "fiber.Body",
    "beego.Input", "beego.GetString", "beego.GetStrings",
]

# Go 特有的敏感函数列表
GO_SENSITIVE_SINKS = [
    "exec.Command", "exec.CommandContext",
    "os.Open", "os.Create", "os.Remove", "os.RemoveAll",
    "ioutil.ReadFile", "ioutil.WriteFile",
    "os.ReadFile", "os.WriteFile",
    "http.Get", "http.Post", "http.NewRequest",
    "sql.Open", "db.Query", "db.QueryRow", "db.Exec",
    "db.Prepare", "tx.Exec", "tx.Query",
    "template.HTML", "template.JS", "template.CSS",
    "template.URL", "template.HTMLAttr",
    "fmt.Sprintf", "fmt.Fprintf", "fmt.Printf",
    "log.Printf", "log.Fatalf",
    "net.Dial", "net.Listen",
    "xml.NewDecoder", "json.Unmarshal",
    "yaml.Unmarshal", "toml.Decode",
    "filepath.Join", "filepath.Abs",
    "regexp.Compile", "regexp.MustCompile",
]


def _extract_var_names_from_expr(expr):
    """
    从 Go 表达式中提取变量名（标识符），用于复合表达式的污点追踪。
    支持：字符串拼接 ("a" + var + "b")、fmt.Sprintf("...%s", var)、简单变量
    """
    if not expr or not expr.strip():
        return []

    expr = expr.strip()
    names = []

    # 字符串拼接: "SELECT..." + userId + "..." + name
    if '+' in expr:
        parts = expr.split('+')
        for part in parts:
            part = part.strip()
            # 跳过字符串字面量
            if (part.startswith('"') and part.endswith('"')) or \
               (part.startswith('`') and part.endswith('`')):
                continue
            # 跳过数字字面量
            if re.match(r'^\d+(\.\d+)?$', part):
                continue
            # 提取标识符（允许 a.b 形式的字段/方法调用）
            ident = re.match(r'^([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)', part)
            if ident:
                name = ident.group(1)
                # 排除 Go 内置常量/类型
                if name not in ('true', 'false', 'nil', 'int', 'string', 'bool',
                                'float32', 'float64', 'byte', 'rune', 'error',
                                'len', 'cap', 'make', 'new', 'append', 'copy',
                                'delete', 'panic', 'recover', 'print', 'println',
                                'complex', 'real', 'imag', 'close'):
                    names.append(name)
        return names

    # fmt.Sprintf / fmt.Fprintf 等格式化函数调用
    fmt_match = re.match(r'fmt\.\w+\s*\(\s*"[^"]*"(?:\s*,\s*(.+))?\)', expr)
    if fmt_match:
        extra_args = fmt_match.group(1)
        if extra_args:
            for arg in extra_args.split(','):
                arg = arg.strip()
                ident = re.match(r'^([a-zA-Z_]\w*)', arg)
                if ident:
                    names.append(ident.group(1))
        return names

    # 函数调用透传: someFunc(variable)
    call_match = re.match(r'^(\w+(?:\.\w+)*)\s*\((.+)\)$', expr)
    if call_match:
        func_name = call_match.group(1)
        # 检查内置知识库
        knowledge = lookup_builtin(func_name)
        if knowledge and knowledge.get("passthrough"):
            inner_args = call_match.group(2)
            for a in inner_args.split(','):
                a = a.strip()
                ident = re.match(r'^([a-zA-Z_]\w*)', a)
                if ident and not (a.startswith('"') and a.endswith('"')):
                    names.append(ident.group(1))
        return names

    # 简单变量名
    simple = re.match(r'^([a-zA-Z_]\w*)$', expr)
    if simple:
        names.append(simple.group(1))

    return names


def _go_line_to_text(file_path, lineno):
    """从源文件读取指定行的文本"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            if 1 <= lineno <= len(lines):
                return lines[lineno - 1].strip()
    except Exception:
        pass
    return ""


def _init_function_summaries(file_path):
    """初始化当前文件及依赖文件的函数摘要（带缓存）"""
    global _summaries_initialized, _file_summaries

    if _summaries_initialized:
        return

    try:
        from core.core_engine.function_summary import SummaryCacheManager
        from core.core_engine.go.summary_generator import generate_file_summaries, generate_summaries_for_target

        # 确定缓存目录（扫描目标根目录下的 .kunlun_cache）
        target_dir = file_path
        pt = _ast_object_singleton
        if pt and hasattr(pt, 'target_directory'):
            target_dir = pt.target_directory
        elif pt and hasattr(pt, 'pre_result'):
            # 取公共前缀作为 target_dir
            paths = list(pt.pre_result.keys())
            if len(paths) > 1:
                target_dir = os.path.commonpath(paths)
            elif paths:
                target_dir = os.path.dirname(paths[0])

        cache_mgr = SummaryCacheManager()

        # 收集所有 Go 文件内容
        files_dict = {}
        if pt and hasattr(pt, 'pre_result'):
            for fp, data in pt.pre_result.items():
                if data.get('language') == 'go':
                    try:
                        with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                            files_dict[fp] = f.read()
                    except Exception:
                        pass
        # 也加入当前文件
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                files_dict[file_path] = f.read()
        except Exception:
            pass

        if files_dict:
            # 尝试从缓存加载
            cached = cache_mgr.load_or_generate(target_dir, files_dict)

            # 需要重新生成的文件
            need_generate = {fp: content for fp, content in files_dict.items()
                             if not cached.get(fp) or not cached[fp].functions}

            # 生成缺失的摘要
            if need_generate:
                new_summaries = generate_summaries_for_target(target_dir, need_generate)
                for fp, fs in new_summaries.items():
                    cached[fp] = fs
                    # 保存到缓存
                    cache_mgr.save_file_summary(target_dir, fp, fs)

            _file_summaries = cached
            logger.debug(f"[AST][Go] 摘要初始化完成: {len(_file_summaries)} 个文件"
                         f" (缓存命中 {len(files_dict) - len(need_generate)}/{len(files_dict)})")

        _summaries_initialized = True
    except Exception as e:
        logger.debug(f"[AST][Go] 摘要初始化失败: {e}")
        _summaries_initialized = True


# ---- tree-sitter AST 辅助函数 ----

_ast_cache = {}  # file_path → tree
_import_cache = {}  # file_path → {别名: [文件路径列表]}
_package_name_cache = {}  # file_path → package_name


def _parse_go_ast(file_path):
    """用 tree-sitter 解析 Go 文件，返回 AST tree（带缓存）"""
    if not _HAS_TREE_SITTER:
        return None
    if file_path in _ast_cache:
        return _ast_cache[file_path]
    try:
        with open(file_path, 'rb') as f:
            source = f.read()
        tree = _ts_parser.parse(source)
        _ast_cache[file_path] = tree
        return tree
    except Exception:
        return None


def _get_package_name(file_path):
    """从 AST 中获取 Go 文件的 package 名（带缓存）"""
    if file_path in _package_name_cache:
        return _package_name_cache[file_path]
    tree = _parse_go_ast(file_path)
    if not tree:
        _package_name_cache[file_path] = None
        return None
    for child in tree.root_node.children:
        if child.type == 'package_clause':
            for cc in child.children:
                if cc.type == 'package_identifier':
                    name = cc.text.decode('utf-8', errors='ignore')
                    _package_name_cache[file_path] = name
                    return name
    _package_name_cache[file_path] = None
    return None


def _parse_go_imports(file_path):
    """解析 Go import 语句，返回 {别名: [文件路径列表]} 映射（带缓存）

    Go import 路径不是本地文件路径，需要通过包名匹配：
    1. 解析当前文件的 import 语句，提取 import 路径和别名
    2. 从 pre_result 获取所有 Go 文件的包名
    3. import 路径最后一段 == 包名 → 匹配为本地文件
    """
    if file_path in _import_cache:
        return _import_cache[file_path]

    tree = _parse_go_ast(file_path)
    if not tree:
        _import_cache[file_path] = {}
        return {}

    # 第一步：从 AST 解析 import 声明，收集 (别名, import路径)
    raw_imports = []  # [(alias, import_path)]

    def _collect_imports(node):
        if node.type == 'import_declaration':
            for child in node.children:
                if child.type == 'import_spec':
                    _parse_single_import_spec(child)
                elif child.type == 'import_spec_list':
                    for spec_child in child.children:
                        if spec_child.type == 'import_spec':
                            _parse_single_import_spec(spec_child)

    def _parse_single_import_spec(spec_node):
        alias = None
        import_path = None
        is_blank = False

        for child in spec_node.children:
            if child.type == 'package_identifier':
                alias = child.text.decode('utf-8', errors='ignore')
            elif child.type == 'blank_identifier':
                is_blank = True
            elif child.type == 'interpreted_string_literal':
                # 提取引号内的文本
                text = child.text.decode('utf-8', errors='ignore')
                if text.startswith('"') and text.endswith('"'):
                    import_path = text[1:-1]
                elif text.startswith('`') and text.endswith('`'):
                    import_path = text[1:-1]

        # 跳过 blank import
        if is_blank:
            return
        if not import_path:
            return

        # 确定别名：显式别名 > 默认取路径最后一段
        if alias is None:
            alias = import_path.rsplit('/', 1)[-1] if '/' in import_path else import_path

        raw_imports.append((alias, import_path))

    _collect_imports(tree.root_node)

    # 第二步：从 pre_result 构建 包名 → [文件路径] 映射
    pt = _ast_object_singleton
    if not pt or not hasattr(pt, 'pre_result'):
        _import_cache[file_path] = {}
        return {}

    pkg_to_files = {}  # 包名 → [文件路径列表]
    for other_fp, other_data in pt.pre_result.items():
        if other_data.get('language') != 'go':
            continue
        pkg_name = _get_package_name(other_fp)
        if pkg_name:
            pkg_to_files.setdefault(pkg_name, []).append(other_fp)

    # 第三步：用 import 路径最后一段匹配包名
    import_map = {}  # {别名: [文件路径列表]}
    for alias, import_path in raw_imports:
        path_last_segment = import_path.rsplit('/', 1)[-1] if '/' in import_path else import_path
        matched_files = pkg_to_files.get(path_last_segment, [])
        if matched_files:
            existing = import_map.get(alias, [])
            for fp in matched_files:
                if fp not in existing:
                    existing.append(fp)
            import_map[alias] = existing

    _import_cache[file_path] = import_map
    return import_map


def _find_call_at_line(tree, lineno, func_name):
    """
    在 AST 中查找指定行号上的 call_expression 节点。
    匹配 func_name（支持 db.Query、exec.Command 等完整名称）。
    优先返回有参数的内层调用（如 exec.Command(...) 而非 .Output()）。
    """
    if tree is None:
        return None

    # func_name 的短名称（如 exec.Command → Command）
    short_name = func_name.split('.')[-1]

    def _get_args_text(node):
        """获取 call_expression 的参数文本"""
        for child in node.children:
            if child.type == 'argument_list':
                return child.text.decode('utf-8', errors='ignore')
        return ''

    def _search(node):
        if node.type == 'call_expression':
            node_line = node.start_point[0] + 1  # tree-sitter 0-indexed
            if node_line == lineno:
                # 先递归搜索所有子节点，找内层调用
                for child in node.children:
                    result = _search(child)
                    if result:
                        return result
                
                # 内层没有匹配，检查当前节点
                func_text = _get_call_func_text(node)
                if func_name in func_text or short_name in func_text:
                    return node
                return None
        
        for child in node.children:
            result = _search(child)
            if result:
                return result
        return None

    return _search(tree.root_node)


def _get_call_func_text(call_node):
    """获取 call_expression 的函数名文本"""
    if call_node.children:
        return call_node.children[0].text.decode('utf-8', errors='ignore')
    return ''


def _get_call_args_from_ast(call_node):
    """
    从 call_expression 节点提取参数列表。
    返回 AST 节点列表（不含括号和逗号）。
    """
    for child in call_node.children:
        if child.type == 'argument_list':
            args = []
            for arg_child in child.children:
                if arg_child.type not in ('(', ')', ','):
                    args.append(arg_child)
            return args
    return []


def _collect_identifiers_from_ast(node):
    """
    从 AST 节点中递归收集所有 identifier（变量名）。
    排除包名（qualified_type 中的 package_identifier）和类型名。
    """
    identifiers = []

    def _walk(n):
        if n.type == 'identifier':
            name = n.text.decode('utf-8', errors='ignore')
            # 排除 Go 关键字和内置常量
            if name not in ('true', 'false', 'nil', 'int', 'string', 'bool',
                            'float32', 'float64', 'byte', 'rune', 'error',
                            'len', 'cap', 'make', 'new', 'append', 'copy',
                            'delete', 'panic', 'recover', 'print', 'println',
                            'complex', 'real', 'imag', 'close', 'iota',
                            'new', 'defer', 'go', 'select', 'case', 'default',
                            'func', 'return', 'if', 'else', 'for', 'range',
                            'switch', 'type', 'struct', 'interface', 'map',
                            'chan', 'package', 'import', 'const', 'var'):
                identifiers.append(name)
        elif n.type == 'selector_expression':
            # a.b → 收集基础变量 a（不收集 .b 因为它是属性/方法名）
            if n.children and n.children[0].type == 'identifier':
                base_name = n.children[0].text.decode('utf-8', errors='ignore')
                identifiers.append(base_name)
            # 也收集完整表达式文本（如 r.URL.Query）
            full_text = n.text.decode('utf-8', errors='ignore')
            if full_text not in identifiers:
                pass  # 不收集完整链式表达式，只收集基础变量
            # 递归处理子节点（可能包含 call_expression）
            for child in n.children:
                _walk(child)
        elif n.type == 'call_expression':
            # 函数调用：只收集参数中的标识符，不收集函数名本身
            for child in n.children:
                if child.type == 'argument_list':
                    for arg_child in child.children:
                        _walk(arg_child)
        else:
            for child in n.children:
                _walk(child)

    _walk(node)
    # 去重保持顺序
    seen = set()
    unique = []
    for name in identifiers:
        if name not in seen:
            seen.add(name)
            unique.append(name)
    return unique


# ---- AST-based 赋值分析辅助函数 ----

_LITERAL_NODE_TYPES = frozenset([
    'interpreted_string_literal', 'raw_string_literal',
    'int_literal', 'float_literal',
    'true', 'false', 'nil',
    'composite_literal',  # struct/map/slice literals
    'rune_literal',
])


def _is_literal_node(node):
    """检查 AST 节点是否是字面量"""
    if node.type in _LITERAL_NODE_TYPES:
        return True
    # int/float with sign prefix: - 作为 unary_expression 也算
    if node.type == 'unary_expression' and node.children:
        op = node.children[0].text.decode('utf-8', errors='ignore') if node.children else ''
        if op in ('-', '+') and len(node.children) >= 2:
            return _is_literal_node(node.children[-1])
    return False


def _get_node_identifier(node):
    """从 AST 节点提取标识符文本（处理 selector_expression）"""
    if node.type == 'identifier':
        return node.text.decode('utf-8', errors='ignore')
    if node.type == 'selector_expression':
        return node.text.decode('utf-8', errors='ignore')
    if node.type == 'field_identifier':
        return node.text.decode('utf-8', errors='ignore')
    return None


def _find_assignment_rhs_at_line(tree, lineno, var_name):
    """
    在 AST 中查找指定行上 var_name 的赋值 RHS 节点。
    支持：
      - short_var_declaration (a := expr)
      - assignment_statement (a = expr)
      - var_declaration (var a Type = expr)
    返回 RHS expression_list 节点或 None。
    """
    if tree is None:
        return None

    result = [None]

    def _search(node):
        if result[0] is not None:
            return
        # 检查行范围：节点必须在目标行上
        node_line = node.start_point[0] + 1
        if node_line > lineno:
            return  # 超过目标行，剪枝

        if node.type == 'short_var_declaration':
            if node_line == lineno:
                # 结构: expression_list (LHS) := expression_list (RHS)
                lhs_list = None
                rhs_list = None
                for child in node.children:
                    if child.type == 'expression_list':
                        if lhs_list is None:
                            lhs_list = child
                        else:
                            rhs_list = child
                if lhs_list and rhs_list:
                    # 检查 LHS 是否包含 var_name
                    for lhs_child in lhs_list.children:
                        if lhs_child.type == 'identifier':
                            name = lhs_child.text.decode('utf-8', errors='ignore')
                            if name == var_name:
                                # RHS 的 expression_list 中取第一个表达式
                                if rhs_list.children:
                                    # 取 expression_list 的第一个非逗号子节点
                                    for rc in rhs_list.children:
                                        if rc.type != ',':
                                            result[0] = rc
                                            return
                                result[0] = rhs_list
                                return

        elif node.type == 'assignment_statement':
            if node_line == lineno:
                lhs_list = None
                rhs_list = None
                for child in node.children:
                    if child.type == 'expression_list':
                        if lhs_list is None:
                            lhs_list = child
                        else:
                            rhs_list = child
                if lhs_list and rhs_list:
                    for lhs_child in lhs_list.children:
                        if lhs_child.type == 'identifier':
                            name = lhs_child.text.decode('utf-8', errors='ignore')
                            if name == var_name:
                                if rhs_list.children:
                                    for rc in rhs_list.children:
                                        if rc.type != ',':
                                            result[0] = rc
                                            return
                                result[0] = rhs_list
                                return

        elif node.type == 'var_declaration':
            if node_line == lineno:
                # var a Type = expr  →  var_spec 内部
                for child in node.children:
                    if child.type == 'var_spec':
                        # var_spec: name type = value
                        name_node = None
                        value_list = None
                        for sc in child.children:
                            if sc.type == 'identifier':
                                name_node = sc
                            elif sc.type == 'expression_list':
                                value_list = sc
                        if name_node:
                            name = name_node.text.decode('utf-8', errors='ignore')
                            if name == var_name and value_list:
                                if value_list.children:
                                    for vc in value_list.children:
                                        if vc.type != ',':
                                            result[0] = vc
                                            return
                                result[0] = value_list
                                return

        # 继续递归子节点
        for child in node.children:
            _search(child)
            if result[0] is not None:
                return

    _search(tree.root_node)
    return result[0]


def _get_call_expr_from_node(node):
    """
    从节点中查找第一个 call_expression。
    用于处理 expression_list 包裹的情况。
    """
    if node.type == 'call_expression':
        return node
    for child in node.children:
        result = _get_call_expr_from_node(child)
        if result:
            return result
    return None


def _find_enclosing_function(tree, lineno):
    """
    在 AST 中查找包含指定行的函数定义。
    返回函数的 parameter_list 节点和函数名，或 None。
    """
    if tree is None:
        return None

    result = [None]

    def _search(node):
        if result[0] is not None:
            return
        if node.type in ('function_declaration', 'method_declaration'):
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            if start_line <= lineno <= end_line:
                func_name = None
                params = None
                for child in node.children:
                    if child.type == 'identifier':
                        func_name = child.text.decode('utf-8', errors='ignore')
                    elif child.type == 'parameter_list' and params is None:
                        params = child
                    elif child.type == 'field_identifier':
                        func_name = child.text.decode('utf-8', errors='ignore')
                result[0] = (func_name, params, start_line, end_line)
                return
        for child in node.children:
            _search(child)

    _search(tree.root_node)
    return result[0]


def _get_formal_param_names(param_list_node):
    """从 parameter_list AST 节点提取形参名列表"""
    if param_list_node is None:
        return []
    names = []
    for child in param_list_node.children:
        if child.type == 'parameter_declaration':
            for sc in child.children:
                if sc.type == 'identifier':
                    names.append(sc.text.decode('utf-8', errors='ignore'))
                    break
    return names


def _find_return_nodes(tree, start_line, end_line):
    """
    在 AST 中查找指定行范围内的 return_statement 节点列表。
    """
    if tree is None:
        return []

    returns = []

    def _search(node):
        node_line = node.start_point[0] + 1
        if node_line > end_line:
            return
        if node.type == 'return_statement':
            if start_line <= node_line <= end_line:
                returns.append(node)
        for child in node.children:
            _search(child)

    _search(tree.root_node)
    return returns


def _extract_args_with_nesting(text, func_name):
    """从代码行中提取函数调用的完整参数字符串，支持嵌套括号（回退方案）"""
    idx = text.find(func_name + '(')
    if idx < 0:
        short_name = func_name.split('.')[-1]
        idx = text.find(short_name + '(')
        if idx < 0:
            return None
        idx += len(short_name)
    else:
        idx += len(func_name)
    if idx >= len(text) or text[idx] != '(':
        return None
    depth = 0
    in_string = False
    string_char = None
    start = idx + 1
    for i in range(idx, len(text)):
        ch = text[i]
        if in_string:
            if ch == '\\' and i + 1 < len(text):
                continue
            if ch == string_char:
                in_string = False
            continue
        if ch in ('"', "'", '`'):
            in_string = True
            string_char = ch
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return text[start:i]
    return None


def _extract_function_name(line_text):
    """从 Go 代码行提取函数调用名"""
    if not line_text:
        return None

    # 匹配常见 Go 函数调用模式
    # 如: exec.Command(...), os.Open(...), r.URL.Query().Get(...)
    patterns = [
        r'(\w+(?:\.\w+)+)\s*\(',  # pkg.Func( or obj.Method(
        r'(\w+)\s*\(',              # Func(
    ]

    for pattern in patterns:
        m = re.search(pattern, line_text)
        if m:
            return m.group(1)
    return None


def _is_controllable_source(expr_str, controlled_params=None):
    """检查表达式是否是可控输入源"""
    if controlled_params is None:
        controlled_params = is_controlled_params

    for cp in controlled_params:
        if cp in expr_str:
            return True

    for src in GO_CONTROLLED_SOURCES:
        if src in expr_str:
            return True

    return False


def _is_repair_function(expr_str, repair_functions=None):
    """检查表达式是否包含修复函数"""
    if repair_functions is None:
        repair_functions = is_repair_functions

    for rf in repair_functions:
        if rf in expr_str:
            return True
    return False


def _split_args_respecting_parens(args_str):
    """
    分割函数参数，正确处理嵌套括号和引号内的逗号
    """
    if not args_str or not args_str.strip():
        return []
    args = []
    current = ''
    depth = 0
    in_string = False
    string_char = None
    i = 0
    while i < len(args_str):
        ch = args_str[i]
        if in_string:
            current += ch
            if ch == '\\' and i + 1 < len(args_str):
                current += args_str[i + 1]
                i += 2
                continue
            if ch == string_char:
                in_string = False
            i += 1
            continue
        if ch in ('"', "'", '`'):
            in_string = True
            string_char = ch
            current += ch
        elif ch == '(':
            depth += 1
            current += ch
        elif ch == ')':
            depth -= 1
            current += ch
        elif ch == ',' and depth == 0:
            args.append(current.strip())
            current = ''
        else:
            current += ch
        i += 1
    if current.strip():
        args.append(current.strip())
    return args


def _parse_func_call_from_expr(expr):
    """
    从表达式中提取第一个函数调用的函数名和参数字符串。
    支持嵌套括号和引号内的括号。
    返回 (func_name, args_str) 或 None
    """
    if not expr:
        return None
    # 找到第一个 '(' 的位置
    idx = expr.find('(')
    if idx <= 0:
        return None
    # 提取函数名：前一个 token
    prefix = expr[:idx].strip()
    # 函数名可能是 a.b.c 格式
    m = re.match(r'^([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)$', prefix)
    if not m:
        return None
    func_name = m.group(1)
    # 用括号计数法提取参数
    depth = 0
    in_string = False
    string_char = None
    start = idx + 1
    for j in range(idx, len(expr)):
        ch = expr[j]
        if in_string:
            if ch == '\\' and j + 1 < len(expr):
                continue
            if ch == string_char:
                in_string = False
            continue
        if ch in ('"', "'", '`'):
            in_string = True
            string_char = ch
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return (func_name, expr[start:j])
    return None


# ---- 函数定义索引 ----
# _func_def_index[(file_path, func_name)] = (formal_params, body_lines, def_lineno)
# 在 scan_parser 入口构建，function_back_go 查表
_func_def_index = {}
_func_def_indexed_files = set()


def _build_func_def_index(file_path):
    """预扫描文件，索引所有 func 定义"""
    if file_path in _func_def_indexed_files:
        return
    _func_def_indexed_files.add(file_path)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return

    pat_func = re.compile(r'^func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(')
    for i, line in enumerate(lines):
        stripped = line.strip()
        m = pat_func.match(stripped)
        if m:
            func_name = m.group(1)
            # 避免重复索引（同名方法可能有 receiver 变体）
            if (file_path, func_name) in _func_def_index:
                continue
            result = _find_function_def_in_lines(lines, func_name, from_line=i + 2)
            if result is not None:
                _func_def_index[(file_path, func_name)] = result


def _build_func_def_index_cross_file():
    """预扫描所有 Go 文件的函数定义（跨文件索引）"""
    pt = _ast_object_singleton
    if not pt or not hasattr(pt, 'pre_result'):
        return
    for other_fp, other_data in pt.pre_result.items():
        if other_data.get('language') == 'go':
            _build_func_def_index(other_fp)


def _find_function_def_in_lines(lines, func_name, from_line=None):
    """
    在代码行列表中搜索 Go 函数定义。
    支持：func Name(...) 和 func (receiver) Name(...)
    返回 (formal_params, func_body_lines, def_lineno) 或 None
    """
    # 搜索范围：from_line 之前的所有行（向后搜索）
    search_range = from_line if from_line else len(lines)

    # 模式1: func (receiver) Name(
    # 模式2: func Name(
    pat_method = re.compile(r'^func\s*\([^)]+\)\s*' + re.escape(func_name) + r'\s*\(')
    pat_func = re.compile(r'^func\s+' + re.escape(func_name) + r'\s*\(')

    for i in range(search_range - 1, -1, -1):
        line = lines[i].strip()
        if pat_method.match(line) or pat_func.match(line):
            # 提取参数列表
            paren_idx = line.find('(')
            if paren_idx < 0:
                continue

            # 对于方法定义 func (r *T) Name(...，需要跳过 receiver 的括号
            if line.startswith('func') and paren_idx > 4:
                prefix = line[:paren_idx].strip()
                # 检查是否有 receiver
                receiver_match = re.match(r'^func\s*\(([^)]*)\)\s*' + re.escape(func_name), line)
                if receiver_match:
                    # 找到参数的 '(' (receiver 之后的)
                    after_receiver = line[receiver_match.end():]
                    param_start = after_receiver.find('(')
                    if param_start < 0:
                        continue
                    # 完整行中找到参数的括号对
                    # receiver_match.end() 在完整行中指向 receiver 之后的位置
                    full_param_start = receiver_match.end() + param_start
                else:
                    full_param_start = paren_idx
            else:
                full_param_start = paren_idx

            # 提取参数（可能跨多行）
            full_line = line
            # 如果行中没有闭合括号，继续读下一行
            j = i
            while full_line.count('(') > full_line.count(')') and j + 1 < len(lines):
                j += 1
                full_line += ' ' + lines[j].strip()

            # 找到参数列表的括号对
            param_start = full_line.find('(', full_param_start)
            if param_start < 0:
                continue
            depth = 0
            param_end = -1
            for k in range(param_start, len(full_line)):
                if full_line[k] == '(':
                    depth += 1
                elif full_line[k] == ')':
                    depth -= 1
                    if depth == 0:
                        param_end = k
                        break
            if param_end < 0:
                continue

            param_text = full_line[param_start + 1:param_end]
            # 解析形参名
            formal_params = []
            for part in _split_args_respecting_parens(param_text):
                # "name type" 格式
                tokens = part.strip().rsplit(' ', 1)
                if len(tokens) >= 2:
                    formal_params.append(tokens[0].strip())

            # 找到函数体的开始 '{' 和结束 '}'
            brace_idx = full_line.find('{', param_end)
            if brace_idx < 0:
                continue
            body_start_line = j + 1  # 从函数定义行之后开始（0-indexed）
            # 对于跨行的情况，body_start_line 需要准确
            # 简单方案：用 brace 计数从 brace_idx 开始
            brace_depth = 0
            body_lines = []
            started = False
            # 从定义行的 '{' 开始
            for bi in range(i, len(lines)):
                bl = lines[bi].strip()
                for ch in bl:
                    if ch == '{':
                        brace_depth += 1
                        if not started:
                            started = True
                    elif ch == '}':
                        brace_depth -= 1
                        if started and brace_depth == 0:
                            return (formal_params, body_lines, i + 1)  # 1-indexed
                if started:
                    body_lines.append(bl)
            # 如果没找到闭合括号，返回已有内容
            if body_lines:
                return (formal_params, body_lines, i + 1)
            break
    return None


def _judge_from_summary(summary, call_args_str, controlled_params):
    """根据函数摘要判定返回值可控性。

    对 return_flow 中每条路径独立判定，只要任意一条可控就返回 (1, [])。

    返回: (code, caller_var_names) — 与 function_back_go 返回值格式一致
    """
    if controlled_params is None:
        controlled_params = is_controlled_params

    for rf in summary.return_flow:
        if rf.origin_type == "param":
            # 返回值来自形参 → 追踪对应实参
            for param_idx in rf.dep_params:
                if param_idx < len(summary.params):
                    # 从 call_args_str 中提取第 param_idx 个参数
                    actual_args = _split_args_respecting_parens(call_args_str) if call_args_str else []
                    if param_idx < len(actual_args):
                        actual_expr = actual_args[param_idx].strip()
                        if _is_controllable_source(actual_expr, controlled_params):
                            return (1, [])
            # 依赖形参但实参不可控 → 返回 deps
            actual_args = _split_args_respecting_parens(call_args_str) if call_args_str else []
            deps = set()
            for param_idx in rf.dep_params:
                if param_idx < len(actual_args):
                    actual_expr = actual_args[param_idx].strip()
                    names = _extract_var_names_from_expr(actual_expr)
                    if names:
                        deps.update(names)
            if deps:
                return ('deps', list(deps))

        elif rf.origin_type == "call":
            # 返回值来自方法调用 → 查内置知识库
            knowledge = lookup_builtin(rf.origin)
            if knowledge:
                if knowledge.get("safe") and not knowledge.get("passthrough"):
                    continue  # 安全函数，检查下一条路径
                if knowledge.get("passthrough"):
                    # 有 passthrough → 检查参数是否可控
                    for pt_idx in knowledge["passthrough"]:
                        # 摘要里这个 call 的 dep_params 对应的是当前函数的形参
                        for param_idx in rf.dep_params:
                            if param_idx < len(summary.params):
                                actual_args = _split_args_respecting_parens(call_args_str) if call_args_str else []
                                if param_idx < len(actual_args):
                                    if _is_controllable_source(actual_args[param_idx], controlled_params):
                                        return (1, [])
            else:
                # 不是内置函数，检查是否在可控源列表中
                if _is_controllable_source(rf.origin, controlled_params):
                    return (1, [])

        elif rf.origin_type == "global":
            # 返回值来自全局变量 → 检查是否是可控源
            if _is_controllable_source(rf.origin, controlled_params):
                return (1, [])

        elif rf.origin_type == "literal":
            continue  # 字面量不可控

    # 所有路径都不可控
    return (-1, [])


def function_back_go(func_name, call_args, vul_lineno, file_path,
                     repair_functions=None, controlled_params=None):
    """
    回溯用户自定义函数定义，分析返回值与参数的依赖关系。
    仿照 PHP 引擎的 function_back() + deps 机制。

    返回:
        (code, caller_var_names)
        code: 'deps' — 返回值依赖调用者变量，需继续追踪
              1 — 返回值直接可控
              2 — 返回值经过修复函数
              3 — 未确认
              -1 — 不可控/未找到函数
    """
    global _scan_function_stack

    if func_name in _scan_function_stack:
        logger.debug("[AST][Go] Recursive function trace detected: {}, skip.".format(
            " -> ".join(_scan_function_stack + [func_name])))
        return (-1, [])

    _scan_function_stack.append(func_name)

    try:
        # 1. 检查内置知识库
        knowledge = lookup_builtin(func_name)
        if knowledge:
            if knowledge.get("safe") and not knowledge.get("passthrough"):
                return (-1, [])
            # passthrough 已在 _trace_variable_in_lines 中处理

        # 1.5. 查函数摘要
        callee_summary = lookup_summary(func_name)
        if callee_summary and callee_summary.return_flow:
            # 摘要中有 return_flow，尝试直接判定
            return _judge_from_summary(callee_summary, call_args, controlled_params)

        # 2. 查函数定义索引（预建）
        result = _func_def_index.get((file_path, func_name))
        callee_fp = file_path  # 默认 callee 在当前文件

        # 3. 索引未命中，回退到实时搜索
        if result is None:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            except Exception:
                return (-1, [])
            result = _find_function_def_in_lines(lines, func_name, vul_lineno)

        # 4. 跨文件搜索（优先用 import_map 精确定位）
        if result is None:
            pt = _ast_object_singleton
            if pt and hasattr(pt, 'pre_result'):
                # 先用 import_map 精确查找
                import_map = _parse_go_imports(file_path)
                # func_name 可能是 "pkg.Func" 格式
                lookup_name = func_name.split('.')[-1] if '.' in func_name else func_name

                # 从 import_map 找候选文件
                candidate_files = []
                if '.' in func_name:
                    # pkg.Func → 查 import_map[pkg]
                    pkg_alias = func_name.split('.')[0]
                    candidate_files = import_map.get(pkg_alias, [])
                else:
                    # Func → 搜索所有 import 的文件
                    for alias, files in import_map.items():
                        candidate_files.extend(files)

                for other_fp in candidate_files:
                    if other_fp == file_path:
                        continue
                    result = _func_def_index.get((other_fp, lookup_name))
                    if result is not None:
                        logger.debug("[AST][Go] Found function {} via import_map: {}".format(
                            func_name, other_fp))
                        callee_fp = other_fp
                        break
                    # 回退到实时搜索
                    other_lines = pt.pre_result.get(other_fp, {}).get('source_lines', [])
                    if not other_lines:
                        continue
                    result = _find_function_def_in_lines(other_lines, lookup_name)
                    if result is not None:
                        logger.debug("[AST][Go] Found function {} via import_map (realtime): {}".format(
                            func_name, other_fp))
                        callee_fp = other_fp
                        break

                # fallback: 如果 import_map 没找到，保留原有暴力搜索
                if result is None:
                    for other_fp, other_data in pt.pre_result.items():
                        if other_fp == file_path:
                            continue
                        if other_data.get('language') != 'go':
                            continue
                        # 先查跨文件索引
                        result = _func_def_index.get((other_fp, lookup_name))
                        if result is not None:
                            logger.debug("[AST][Go] Found function {} in cross-file index: {}".format(
                                func_name, other_fp))
                            callee_fp = other_fp
                            break
                        # 回退到实时搜索
                        other_lines = other_data.get('source_lines', [])
                        if not other_lines:
                            continue
                        result = _find_function_def_in_lines(other_lines, lookup_name)
                        if result is not None:
                            logger.debug("[AST][Go] Found function {} in cross-file: {}".format(
                                func_name, other_fp))
                            callee_fp = other_fp
                            break
        if result is None:
            return (-1, [])

        formal_params, body_lines, def_lineno = result

        # 4.5 先尝试进入 callee 函数体检查 sink 调用
        #     类似 Python 引擎的 _try_cross_file_trace
        sink_result = _trace_callee_body_for_sinks(
            callee_fp, func_name, formal_params, call_args,
            file_path,  # caller file
            repair_functions, controlled_params
        )
        if sink_result is not None:
            return sink_result

        # 5. fallback: 分析返回值依赖
        return _analyze_return_deps_go(
            formal_params, body_lines, call_args,
            file_path, repair_functions, controlled_params
        )

    finally:
        if _scan_function_stack and _scan_function_stack[-1] == func_name:
            _scan_function_stack.pop()
        else:
            try:
                _scan_function_stack.remove(func_name)
            except ValueError:
                pass


def _trace_callee_body_for_sinks(callee_file_path, callee_func_name, formal_params,
                                  call_args_str, caller_file_path,
                                  repair_functions=None, controlled_params=None):
    """
    进入 callee 函数体，用 AST 搜索 sink 调用，追踪参数数据流。

    当 function_back_go 找到 callee 函数定义后，先检查函数体中是否有已知 sink。
    如果有，追踪 sink 参数的可控性（通过 形参→实参 映射回到 caller）。

    类似 Python 引擎的 _try_cross_file_trace。

    返回: (code, caller_var_names) 或 None（未找到 sink）
    """
    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    # 1. 解析 callee 文件的 AST
    tree = _parse_go_ast(callee_file_path)
    if not tree:
        return None

    # 2. 在 AST 中找到 callee 函数定义
    #    callee_func_name 可能是 "pkg.Func" 格式，AST 中只存 "Func"
    lookup_name = callee_func_name.split('.')[-1] if '.' in callee_func_name else callee_func_name
    func_node = None
    for child in tree.root_node.children:
        if child.type in ('function_declaration', 'method_declaration'):
            name = None
            for cc in child.children:
                if cc.type in ('identifier', 'field_identifier'):
                    name = cc.text.decode('utf-8', errors='ignore')
                    break
            if name == lookup_name:
                func_node = child
                break

    if not func_node:
        return None

    # 3. 获取函数体 block
    body_block = None
    for child in func_node.children:
        if child.type == 'block':
            body_block = child
            break

    if not body_block:
        return None

    # 4. Walk 函数体，找所有 call_expression 中的已知 sink
    sink_calls = []

    def _walk_for_sinks(node):
        if node.type == 'call_expression':
            func_text = _get_call_func_text(node)
            if func_text:
                knowledge = lookup_builtin(func_text)
                # 已知 sink：在知识库中且 safe=False
                if knowledge and not knowledge.get('safe', True):
                    sink_calls.append((func_text, node))
        for child in node.children:
            _walk_for_sinks(child)

    _walk_for_sinks(body_block)

    if not sink_calls:
        return None

    # 5. 建立形参→实参映射
    actual_args = _split_args_respecting_parens(call_args_str) if call_args_str else []
    arg_map = {}  # formal_name → actual_expr
    for idx, fp_name in enumerate(formal_params):
        if idx < len(actual_args):
            arg_map[fp_name] = actual_args[idx].strip()

    # 6. 对每个 sink 调用，检查参数是否引用了 callee 的形参
    for sink_func, sink_node in sink_calls:
        args = _get_call_args_from_ast(sink_node)
        for arg_node in args:
            # 检查参数是否直接是字面量（不可控）
            if arg_node.type in _LITERAL_NODE_TYPES:
                continue

            # 提取参数中的标识符
            arg_identifiers = _collect_identifiers_from_ast(arg_node)
            for ident in arg_identifiers:
                if ident not in arg_map:
                    continue

                # 这个 sink 参数引用了 callee 的形参
                actual_expr = arg_map[ident]

                # 6a. 检查实参是否直接可控
                if _is_controllable_source(actual_expr, controlled_params):
                    logger.debug(
                        "[AST][Go] Sink {} in callee body uses controllable param: {} -> {}".format(
                            sink_func, ident, actual_expr))
                    return (1, [])

                # 6b. 提取实参中的变量名，在 caller 中追踪
                caller_var_names = set()
                names = _extract_var_names_from_expr(actual_expr)
                if names:
                    caller_var_names.update(names)
                else:
                    simple = re.match(r'^([a-zA-Z_]\w*)$', actual_expr)
                    if simple:
                        caller_var_names.add(simple.group(1))

                if caller_var_names:
                    logger.debug(
                        "[AST][Go] Sink {} in callee body depends on caller vars: {}".format(
                            sink_func, caller_var_names))
                    return ('deps', list(caller_var_names))

    return None


def _propagate_assignments_ast(tree, func_lines, controllable_local):
    """
    用 AST 在函数体中传播可控变量标记。
    遍历 AST 中的赋值语句，如果 RHS 包含可控变量，则标记 LHS。
    修改 controllable_local in-place。
    """
    if tree is None:
        return

    def _walk(node):
        lhs_name = None
        rhs_identifiers = []

        if node.type == 'short_var_declaration':
            lhs_list = None
            rhs_list = None
            for child in node.children:
                if child.type == 'expression_list':
                    if lhs_list is None:
                        lhs_list = child
                    else:
                        rhs_list = child
            if lhs_list and lhs_list.children:
                first_lhs = lhs_list.children[0]
                if first_lhs.type == 'identifier':
                    lhs_name = first_lhs.text.decode('utf-8', errors='ignore')
            if rhs_list:
                rhs_identifiers = _collect_identifiers_from_ast(rhs_list)

        elif node.type == 'assignment_statement':
            lhs_list = None
            rhs_list = None
            for child in node.children:
                if child.type == 'expression_list':
                    if lhs_list is None:
                        lhs_list = child
                    else:
                        rhs_list = child
            if lhs_list and lhs_list.children:
                first_lhs = lhs_list.children[0]
                if first_lhs.type == 'identifier':
                    lhs_name = first_lhs.text.decode('utf-8', errors='ignore')
            if rhs_list:
                rhs_identifiers = _collect_identifiers_from_ast(rhs_list)

        if lhs_name and lhs_name not in controllable_local:
            if any(v in controllable_local for v in rhs_identifiers):
                controllable_local.add(lhs_name)

        for child in node.children:
            _walk(child)

    _walk(tree.root_node)


def _analyze_return_deps_go(formal_params, func_lines, call_args_str,
                            file_path, repair_functions=None, controlled_params=None):
    """
    分析函数返回值与形参的依赖关系（Go 版本的 deps 机制）。

    使用 tree-sitter AST 进行精确分析，正则作为 fallback。

    算法：
    1. 建立形参→实参映射
    2. 标记可控形参
    3. 赋值链传播（函数体内，使用 AST）
    4. 分析 return 语句（使用 AST）

    返回: (code, caller_var_names)
    """
    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    # 1. 解析实参
    actual_args = _split_args_respecting_parens(call_args_str) if call_args_str else []

    # 收集实参中的变量名（用于 fallback deps）
    caller_var_names = set()
    for arg in actual_args:
        arg = arg.strip()
        if not arg:
            continue
        # 跳过字面量
        if (arg.startswith('"') and arg.endswith('"')) or \
           (arg.startswith('`') and arg.endswith('`')):
            continue
        if re.match(r'^\d+(\.\d+)?$', arg):
            continue
        names = _extract_var_names_from_expr(arg)
        if names:
            caller_var_names.update(names)
        else:
            simple = re.match(r'^([a-zA-Z_]\w*)$', arg)
            if simple:
                caller_var_names.add(simple.group(1))

    # 2. 建立形参→实参映射，标记可控形参
    arg_map = {}       # formal_name → actual_expr
    controllable_formal = set()

    for idx, fp_name in enumerate(formal_params):
        if idx < len(actual_args):
            actual_expr = actual_args[idx].strip()
            arg_map[fp_name] = actual_expr
            # 检查实参是否可控
            if _is_controllable_source(actual_expr, controlled_params):
                controllable_formal.add(fp_name)

    # 3. 赋值链传播（AST 优先，正则 fallback）
    controllable_local = set(controllable_formal)

    # 尝试用 AST 进行赋值链传播
    tree = _parse_go_ast(file_path) if file_path else None
    if tree:
        # 在 AST 中查找函数体中的所有赋值语句
        for _ in range(3):
            changed = False
            _propagate_assignments_ast(tree, func_lines, controllable_local)
            # 如果没有新变量被标记，停止
            if not changed:
                break

    # AST 传播后，用正则补充（兼容性）
    for _ in range(3):
        changed = False
        for line_text in func_lines:
            assign_match = re.match(r'(\w+)\s*:?=\s*(.+)', line_text)
            if not assign_match:
                continue
            lhs = assign_match.group(1)
            rhs = assign_match.group(2).strip()
            if lhs in controllable_local:
                continue
            rhs_var_names = set(_extract_var_names_from_expr(rhs))
            simple_rhs = re.match(r'^(\w+)$', rhs)
            if simple_rhs:
                rhs_var_names.add(simple_rhs.group(1))
            if rhs_var_names & controllable_local:
                controllable_local.add(lhs)
                changed = True
        if not changed:
            break

    # 4. 分析 return 语句
    for line_text in func_lines:
        return_match = re.match(r'return\s+(.+)', line_text)
        if not return_match:
            continue
        return_expr = return_match.group(1).strip()

        # 多返回值：取第一个
        if ',' in return_expr:
            depth = 0
            first_comma = -1
            for ci, ch in enumerate(return_expr):
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    depth -= 1
                elif ch == ',' and depth == 0:
                    first_comma = ci
                    break
            if first_comma > 0:
                return_expr = return_expr[:first_comma].strip()

        # 4a. 返回值本身是可控源
        if _is_controllable_source(return_expr, controlled_params):
            logger.debug("[AST][Go] Function returns controllable source directly: {}".format(return_expr))
            return (1, [])

        # 4b. 返回值是修复函数
        if _is_repair_function(return_expr, repair_functions):
            return (2, [])

        # 4c. 提取返回值中的变量名，检查是否依赖可控形参
        return_var_names = set(_extract_var_names_from_expr(return_expr))
        simple_ret = re.match(r'^(\w+)$', return_expr)
        if simple_ret:
            return_var_names.add(simple_ret.group(1))

        matched = return_var_names & controllable_local
        if matched:
            deps = set()
            for var in matched:
                if var in arg_map:
                    actual_expr = arg_map[var]
                    if _is_controllable_source(actual_expr, controlled_params):
                        return (1, [])
                    actual_names = _extract_var_names_from_expr(actual_expr)
                    if actual_names:
                        deps.update(actual_names)
                    else:
                        simple = re.match(r'^(\w+)$', actual_expr)
                        if simple:
                            deps.add(simple.group(1))
                else:
                    deps.update(return_var_names)
            if deps:
                logger.debug("[AST][Go] Function return depends on caller vars: {}".format(deps))
                return ('deps', list(deps))

        # 4d. fallback: 文本匹配形参名
        for fp_name, actual_expr in arg_map.items():
            if _is_controllable_source(actual_expr, controlled_params):
                if fp_name in return_expr:
                    logger.debug("[AST][Go] Function returns controllable param {} (text match)".format(fp_name))
                    return (1, [])

    # 5. Fallback: 未确认，返回调用者变量名供继续追踪
    if caller_var_names:
        return ('deps', list(caller_var_names))

    return (3, [])


def _text_trace_variable(file_path, var_name, vul_lineno,
                          repair_functions=None, controlled_params=None):
    """
    纯文本 fallback 追踪：不依赖 tree-sitter AST。
    从 vul_lineno 向上逐行查找 var_name 的赋值，判断是否来自可控源。
    返回: (code, source_lineno)
    """
    import re as _re
    if repair_functions is None:
        repair_functions = []
    if controlled_params is None:
        controlled_params = []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return (-1, 0)

    # 向上查找赋值
    for i in range(vul_lineno - 2, -1, -1):
        line = lines[i].strip()
        # 匹配 var_name := ... 或 var_name = ...
        m = _re.match(r'(?:' + _re.escape(var_name) + r')\s*(?::=|=)\s*(.+)', line)
        if not m:
            # 短变量声明 x, y := ... 形式
            m2 = _re.match(r'[\w,\s]*\b' + _re.escape(var_name) + r'\b\s*:=\s*(.+)', line)
            if not m2:
                continue
            rhs = m2.group(1).strip()
        else:
            rhs = m.group(1).strip()

        src_lineno = i + 1

        # 检查是否是函数调用结果
        # fmt.Fprintf(os.Stdin, ..., r.FormValue(...)) 等
        # r.FormValue / r.URL.Query / req.FormValue 等 HTTP source
        http_patterns = [
            r'\.FormValue\s*\(', r'\.Query\s*\(\)', r'\.Get\s*\(',
            r'\.URL\.Query', r'\.PostFormValue', r'\.Form\s*\[',
            r'\.Cookie\s*\(', r'\.Cookies\s*\(',
        ]
        for pat in http_patterns:
            if _re.search(pat, rhs):
                return (1, src_lineno)

        # 检查是否来自其他变量赋值 → 递归追踪
        sub_vars = _re.findall(r'[a-zA-Z_]\w*', rhs)
        for sv in sub_vars:
            if sv in ('true', 'false', 'nil', 'string', 'int', 'fmt', 'err', 'nil'):
                continue
            if sv == var_name:
                continue
            # 可控参数列表
            if sv in controlled_params:
                return (1, src_lineno)
            # 递归追踪子变量
            sub_code, sub_line = _text_trace_variable(
                file_path, sv, src_lineno, repair_functions, controlled_params
            )
            if sub_code == 1:
                return (1, sub_line)

        # 没有子变量，不可控
        return (-1, src_lineno)

    return (-1, 0)


def _trace_variable_in_lines(file_path, var_name, from_line, to_line,
                              repair_functions=None, controlled_params=None,
                              depth=0, max_depth=5):
    """
    在指定行范围内追踪变量的数据流（缓存包装层）

    入口查缓存，出口写缓存（仅缓存 depth=0 的顶层调用）。
    实际逻辑在 _trace_variable_in_lines_impl 中。

    返回: (code, source_lineno) 元组
    """
    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    # 顶层调用才查/写缓存
    if depth == 0 and file_path and to_line:
        cached = _trace_cache.get(file_path, var_name, int(to_line))
        if cached is not None:
            # cached 格式: (code, [], to_line) → 返回 (code, source_lineno)
            return (cached[0], cached[2] if len(cached) > 2 else to_line)

    code, source_lineno = _trace_variable_in_lines_impl(
        file_path, var_name, from_line, to_line,
        repair_functions, controlled_params, depth, max_depth
    )

    # 顶层调用写缓存（仅确定性结果）
    if depth == 0 and file_path and to_line and code in (1, 2, -1):
        _trace_cache.put(file_path, var_name, int(to_line), (code, [], source_lineno))

    return (code, source_lineno)


def _analyze_rhs_node(rhs_node, var_name, file_path, lineno, to_line,
                      repair_functions, controlled_params, depth, max_depth):
    """
    根据 RHS AST 节点类型分派分析。
    返回: (code, source_lineno) 如果确定，None 如果需要继续扫描。
    """
    rhs_text = rhs_node.text.decode('utf-8', errors='ignore')

    # 快速检查：可控源
    if _is_controllable_source(rhs_text, controlled_params):
        logger.debug("[AST][Go] Variable {} RHS is controllable source: {}".format(var_name, rhs_text[:80]))
        return (1, lineno)

    # 快速检查：修复函数
    if _is_repair_function(rhs_text, repair_functions):
        logger.debug("[AST][Go] Variable {} RHS is repaired: {}".format(var_name, rhs_text[:80]))
        return (2, lineno)

    node_type = rhs_node.type

    # 字面量 → 安全
    if _is_literal_node(rhs_node):
        return (-1, 0)

    # 函数调用
    if node_type == 'call_expression':
        return _handle_call_expression_rhs(
            rhs_node, var_name, file_path, lineno, to_line,
            repair_functions, controlled_params, depth, max_depth
        )

    # 字符串拼接 (binary_expression with +)
    if node_type == 'binary_expression':
        return _handle_binary_expression_rhs(
            rhs_node, var_name, file_path, lineno, to_line,
            repair_functions, controlled_params, depth, max_depth
        )

    # 简单变量赋值 a = b
    if node_type == 'identifier':
        name = rhs_node.text.decode('utf-8', errors='ignore')
        if name == var_name:
            return None  # 自赋值，跳过
        if _is_controllable_source(name, controlled_params):
            return (1, lineno)
        return _trace_variable_in_lines(
            file_path, name, lineno, to_line,
            repair_functions, controlled_params, depth + 1, max_depth
        )

    # selector_expression (如 r.URL.Query().Get("key"))
    # 这通常包含在 call_expression 中，但如果是裸的 selector，检查可控源
    if node_type == 'selector_expression':
        if _is_controllable_source(rhs_text, controlled_params):
            return (1, lineno)
        # 检查基础变量
        if rhs_node.children and rhs_node.children[0].type == 'identifier':
            base = rhs_node.children[0].text.decode('utf-8', errors='ignore')
            if _is_controllable_source(base, controlled_params):
                return (1, lineno)

    # parenthesized_expression → 解包
    if node_type == 'parenthesized_expression':
        for child in rhs_node.children:
            if child.type not in ('(', ')'):
                return _analyze_rhs_node(
                    child, var_name, file_path, lineno, to_line,
                    repair_functions, controlled_params, depth, max_depth
                )

    # type_conversion_expression (如 string(body))
    if node_type == 'type_conversion_expression':
        args = [c for c in rhs_node.children if c.type not in ('(', ')') and not c.type.endswith('_type')]
        for arg in args:
            result = _analyze_rhs_node(
                arg, var_name, file_path, lineno, to_line,
                repair_functions, controlled_params, depth, max_depth
            )
            if result is not None:
                return result

    # 其他类型：收集标识符逐一追踪
    var_names = _collect_identifiers_from_ast(rhs_node)
    for vn in var_names:
        if vn == var_name:
            continue
        if _is_controllable_source(vn, controlled_params):
            return (1, lineno)
        r = _trace_variable_in_lines(
            file_path, vn, lineno, to_line,
            repair_functions, controlled_params, depth + 1, max_depth
        )
        if r[0] in (1, 2):
            return r

    return None  # 未确定，继续扫描


def _handle_call_expression_rhs(call_node, var_name, file_path, lineno, to_line,
                                 repair_functions, controlled_params, depth, max_depth):
    """处理函数调用赋值的 RHS 分析，返回 (code, source_lineno) 或 None"""
    func_text = _get_call_func_text(call_node)
    args = _get_call_args_from_ast(call_node)

    # 检查内置知识库
    knowledge = lookup_builtin(func_text)
    if knowledge:
        if knowledge.get("safe") and not knowledge.get("passthrough"):
            logger.debug("[AST][Go] RHS call {} is safe per knowledge base".format(func_text))
            return (-1, 0)
        if knowledge.get("passthrough"):
            # 关键修复：追踪 ALL 非字面量参数，不只是 passthrough 索引
            for arg_node in args:
                if _is_literal_node(arg_node):
                    continue
                var_names = _collect_identifiers_from_ast(arg_node)
                for vn in var_names:
                    if vn == var_name:
                        continue
                    if _is_controllable_source(vn, controlled_params):
                        return (1, lineno)
                    r = _trace_variable_in_lines(
                        file_path, vn, lineno, to_line,
                        repair_functions, controlled_params, depth + 1, max_depth
                    )
                    if r[0] in (1, 2):
                        return r
            return None  # passthrough 但参数都安全

    # 未知函数 → 跨函数追踪 (deps 机制)
    args_str = ', '.join(a.text.decode('utf-8', errors='ignore') for a in args)
    fb_result = function_back_go(
        func_text, args_str, lineno, file_path,
        repair_functions, controlled_params
    )
    if isinstance(fb_result, tuple) and len(fb_result) == 2:
        code, caller_deps = fb_result
        if code == 'deps' and caller_deps:
            for dep_var in caller_deps:
                if dep_var == var_name:
                    continue
                r = _trace_variable_in_lines(
                    file_path, dep_var, lineno, to_line,
                    repair_functions, controlled_params, depth + 1, max_depth
                )
                if r[0] in (1, 2):
                    return r
            return (3, lineno)  # 所有依赖都未确认
        elif code in (1, 2):
            return (code, lineno)
        elif code == 3:
            return (3, lineno)
    return None


def _handle_binary_expression_rhs(bin_node, var_name, file_path, lineno, to_line,
                                   repair_functions, controlled_params, depth, max_depth):
    """处理字符串拼接 (binary_expression with +) 的 RHS 分析，返回 (code, source_lineno) 或 None"""
    for child in bin_node.children:
        if child.type in ('+', '-', '||', '&&'):
            continue
        if _is_literal_node(child):
            continue
        var_names = _collect_identifiers_from_ast(child)
        for vn in var_names:
            if vn == var_name:
                continue
            if _is_controllable_source(vn, controlled_params):
                return (1, lineno)
            r = _trace_variable_in_lines(
                file_path, vn, lineno, to_line,
                repair_functions, controlled_params, depth + 1, max_depth
            )
            if r[0] in (1, 2):
                return r
    return None


def _trace_variable_in_lines_impl(file_path, var_name, from_line, to_line,
                                   repair_functions, controlled_params,
                                   depth, max_depth):
    """
    在指定行范围内追踪变量的数据流（纯 AST 版本）

    使用 tree-sitter AST 查找 var_name 的赋值，按节点类型分派分析。
    完全移除正则，参考 Python 引擎的 _trace_stmt / _trace_expr 模式。

    返回值:
        (code, source_lineno) 元组
        code: 1 (可控), 2 (已修复), 3 (未确认), -1 (不可控)
        source_lineno: source 赋值行号
    """
    from core.core_engine.go._ast_trace import (
        trace_go_stmt, trace_go_expr, _find_assignment_in_block,
        _get_node_text, _is_controlled_source_node,
        _get_formal_param_names as _get_formal_param_names_ast,
        ASSIGNMENT_TYPES,
    )

    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    if depth > max_depth:
        return (-1, 0)

    # 用 tree-sitter 解析文件
    tree = _parse_go_ast(file_path)
    if not tree:
        return (-1, 0)  # 无 AST，无法分析

    # 获取函数体（block 节点）
    func_info = _find_enclosing_function(tree, to_line)
    if not func_info:
        return (-1, 0)

    func_name, params_node, func_start, func_end = func_info

    # 在函数体内查找 var_name 的赋值
    # 找到函数体的 block 节点
    func_node = None
    def _find_func(node):
        nonlocal func_node
        if node.type in ('function_declaration', 'method_declaration'):
            if node.start_point[0] + 1 <= to_line <= node.end_point[0] + 1:
                func_node = node
                return
        for child in node.children:
            _find_func(child)
            if func_node:
                return
    _find_func(tree.root_node)

    if not func_node:
        return (-1, 0)

    # 获取函数体 block
    body_block = None
    for child in func_node.children:
        if child.type == 'block':
            body_block = child
            break

    if not body_block:
        return (-1, 0)

    # 在函数体中查找赋值
    result_tuple = _find_assignment_in_block(body_block, var_name)
    if result_tuple:
        rhs_node, lineno = result_tuple
        # 用 trace_go_expr 分析 RHS（trace_go_expr 返回 (code, source_lineno)）
        result = trace_go_expr(
            var_name, rhs_node, file_path, lineno, to_line,
            repair_functions, controlled_params, depth, max_depth,
            function_back_go, _trace_variable_in_lines
        )
        return result

    # ---- 未找到赋值来源：检查 var_name 是否是函数形参 ----
    if params_node:
        formal_param_names = _get_formal_param_names_ast(params_node)
        if var_name in formal_param_names:
            logger.debug("[AST][Go] Variable {} is a parameter of function {}, searching call sites".format(
                var_name, func_name))
            # 搜索调用点
            call_result = _trace_param_at_call_sites_ast(
                func_name, var_name, file_path, tree,
                repair_functions, controlled_params, depth, max_depth
            )
            if call_result is not None:
                return call_result

            # 跨文件搜索调用点（优先用 import_map 精确定位）
            pt = _ast_object_singleton
            if pt and hasattr(pt, 'pre_result'):
                import_map = _parse_go_imports(file_path)
                # 优先搜索 import 的文件
                candidate_files = []
                for alias, files in import_map.items():
                    candidate_files.extend(files)
                # 去重
                seen = set()
                unique_candidates = []
                for fp in candidate_files:
                    if fp not in seen:
                        seen.add(fp)
                        unique_candidates.append(fp)

                for other_fp in unique_candidates:
                    if other_fp == file_path:
                        continue
                    other_tree = _parse_go_ast(other_fp)
                    if not other_tree:
                        continue
                    call_result = _trace_param_at_call_sites_ast(
                        func_name, var_name, other_fp, other_tree,
                        repair_functions, controlled_params, depth, max_depth
                    )
                    if call_result is not None:
                        return call_result

                # fallback: 暴力搜索未被 import_map 覆盖的文件
                for other_fp, other_data in pt.pre_result.items():
                    if other_fp == file_path or other_fp in seen:
                        continue
                    if other_data.get('language') != 'go':
                        continue
                    other_tree = _parse_go_ast(other_fp)
                    if not other_tree:
                        continue
                    call_result = _trace_param_at_call_sites_ast(
                        func_name, var_name, other_fp, other_tree,
                        repair_functions, controlled_params, depth, max_depth
                    )
                    if call_result is not None:
                        return call_result

    return (-1, 0)


def _trace_param_at_call_sites_ast(func_name, param_name, file_path, tree,
                                    repair_functions, controlled_params,
                                    depth, max_depth):
    """
    用 AST 搜索函数调用点，追踪实参来源。
    完全基于 tree-sitter，无正则。
    """
    from core.core_engine.go._ast_trace import (
        _get_call_func_name, _get_call_args, _get_node_text,
        _get_formal_param_names as _get_formal_param_names_ast,
        trace_go_expr, _is_controlled_source_node,
    )

    # 在 AST 中搜索所有 call_expression
    call_sites = []

    def _find_calls(node):
        if node.type == 'call_expression':
            call_func = _get_call_func_name(node)
            if call_func and func_name in call_func:
                call_sites.append(node)
        for child in node.children:
            _find_calls(child)

    _find_calls(tree.root_node)

    for call_node in call_sites:
        # 获取实参
        args = _get_call_args(call_node)
        call_lineno = call_node.start_point[0] + 1

        # 获取函数定义的形参列表
        # 先在当前文件找
        func_def_node = None
        def _find_func_def(node):
            nonlocal func_def_node
            if node.type in ('function_declaration', 'method_declaration'):
                name_node = None
                for child in node.children:
                    if child.type == 'identifier':
                        name_node = child
                        break
                if name_node and _get_node_text(name_node) == func_name:
                    func_def_node = node
                    return
            for child in node.children:
                _find_func_def(child)
                if func_def_node:
                    return
        _find_func_def(tree.root_node)

        if not func_def_node:
            # 当前文件找不到，用 _func_def_index 跨文件搜索
            formal_params_from_index = None
            for (idx_fp, idx_name), idx_val in _func_def_index.items():
                if idx_name == func_name:
                    formal_params_from_index = idx_val[0]  # (formal_params, body_lines, def_lineno)
                    break
            if formal_params_from_index is None:
                continue

            # 直接用索引中的形参列表，跳过 AST 搜索形参的步骤
            # 找到 param_name 在形参中的位置
            param_idx = -1
            for i, fp in enumerate(formal_params_from_index):
                if fp == param_name:
                    param_idx = i
                    break

            if param_idx < 0 or param_idx >= len(args):
                continue

            # 获取对应的实参并追踪
            actual_arg = args[param_idx]
            actual_arg_text = _get_node_text(actual_arg)

            if actual_arg.type == 'identifier':
                result = _trace_variable_in_lines(
                    file_path, actual_arg_text, call_lineno, call_lineno,
                    repair_functions, controlled_params, depth + 1, max_depth
                )
            else:
                result = trace_go_expr(
                    param_name, actual_arg, file_path, call_lineno, call_lineno,
                    repair_functions, controlled_params, depth + 1, max_depth,
                    function_back_go, _trace_variable_in_lines
                )
            if isinstance(result, tuple) and result[0] in (1, 2):
                return result
            continue

        # 获取形参列表
        params_node = None
        for child in func_def_node.children:
            if child.type == 'parameter_list':
                params_node = child
                break

        if not params_node:
            continue

        formal_params = _get_formal_param_names_ast(params_node)

        # 找到 param_name 在形参中的位置
        param_idx = -1
        for i, fp in enumerate(formal_params):
            if fp == param_name:
                param_idx = i
                break

        if param_idx < 0 or param_idx >= len(args):
            continue

        # 获取对应的实参
        actual_arg = args[param_idx]
        actual_arg_text = _get_node_text(actual_arg)

        # 关键：实际参数是 caller 作用域的变量，不是 callee 的 param_name
        # 应该用 _trace_variable_in_lines 追踪 caller 的变量
        if actual_arg.type == 'identifier':
            # 简单变量：直接用 _trace_variable_in_lines 追踪
            result = _trace_variable_in_lines(
                file_path, actual_arg_text, call_lineno, call_lineno,
                repair_functions, controlled_params, depth + 1, max_depth
            )
        else:
            # 复杂表达式：用 trace_go_expr 分析
            result = trace_go_expr(
                param_name, actual_arg, file_path, call_lineno, call_lineno,
                repair_functions, controlled_params, depth + 1, max_depth,
                function_back_go, _trace_variable_in_lines
            )
        if isinstance(result, tuple) and result[0] in (1, 2):
            return result

    return None


def _trace_param_at_call_sites(func_name, param_name, file_path, lines,
                               repair_functions=None, controlled_params=None,
                               depth=0, max_depth=5):
    """
    在文件中搜索函数调用点，找到参数名对应的实参，然后追踪实参。

    返回: 1/2 如果找到可控来源，None 如果未找到
    """
    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    # 搜索模式: func_name(
    call_pattern = re.compile(re.escape(func_name) + r'\s*\(')

    for i in range(len(lines)):
        line = lines[i].strip()
        # 跳过函数定义行和注释
        if line.startswith('func ') or line.startswith('//') or line.startswith('/*'):
            continue

        m = call_pattern.search(line)
        if not m:
            continue

        # 提取调用的参数
        call_start = line.find('(', m.end() - 1)
        if call_start < 0:
            continue
        # 提取完整参数（括号计数）
        depth_p = 0
        in_str = False
        str_ch = None
        args_end = -1
        for j in range(call_start, len(line)):
            ch = line[j]
            if in_str:
                if ch == '\\' and j + 1 < len(line):
                    continue
                if ch == str_ch:
                    in_str = False
                continue
            if ch in ('"', "'", '`'):
                in_str = True
                str_ch = ch
                continue
            if ch == '(':
                depth_p += 1
            elif ch == ')':
                depth_p -= 1
                if depth_p == 0:
                    args_end = j
                    break
        if args_end < 0:
            continue
        args_str = line[call_start + 1:args_end]
        actual_args = _split_args_respecting_parens(args_str)

        # 找到形参在参数列表中的位置
        func_def = _find_function_def_in_lines(lines, func_name, i + 1)
        if func_def is None:
            continue
        formal_params = func_def[0]

        # 找到 param_name 的位置
        param_idx = -1
        for pi, fp in enumerate(formal_params):
            if fp == param_name:
                param_idx = pi
                break
        if param_idx < 0 or param_idx >= len(actual_args):
            continue

        # 获取对应的实参
        actual_arg = actual_args[param_idx].strip()

        # 跳过字面量
        if (actual_arg.startswith('"') and actual_arg.endswith('"')) or \
           (actual_arg.startswith('`') and actual_arg.endswith('`')):
            continue

        # 追踪实参（在调用者函数的作用域中，从调用行向上追踪）
        trace_result = _trace_variable_in_lines(
            file_path, actual_arg, i + 1, i + 1,
            repair_functions, controlled_params,
            depth + 1, max_depth
        )
        if isinstance(trace_result, tuple) and trace_result[0] in (1, 2):
            return trace_result

    return None


def scan_parser(rule_match, vul_lineno, file_path,
                repair_functions=None, controlled_params=None,
                svid=None, is_config_vuln=False):
    """
    Go AST 扫描入口

    :param rule_match: 规则匹配的函数名列表
    :param vul_lineno: 漏洞行号
    :param file_path: 文件路径
    :param repair_functions: 修复函数列表
    :param controlled_params: 可控参数列表
    :param svid: 规则编号
    :param is_config_vuln: 是否配置型漏洞
    :return: 扫描结果列表
    """
    if repair_functions is None:
        repair_functions = []
    if controlled_params is None:
        controlled_params = []

    # ---- 预建函数定义索引（仅首次调用时构建） ----
    _build_func_def_index(file_path)
    _build_func_def_index_cross_file()

    # ---- 初始化函数摘要 ----
    global _summaries_initialized
    _summaries_initialized = False
    _init_function_summaries(file_path)

    results = []

    try:
        vul_lineno = int(vul_lineno)
    except (ValueError, TypeError):
        logger.warning("[AST][Go] Invalid vul_lineno: {}".format(vul_lineno))
        return results

    # 获取源码行
    line_text = _go_line_to_text(file_path, vul_lineno)
    if not line_text:
        logger.warning("[AST][Go] Cannot read line {} from {}".format(vul_lineno, file_path))
        return results

    logger.debug("[AST][Go] Scanning line {}: {}".format(vul_lineno, line_text))

    # 检查行中是否包含规则匹配的函数
    matched_func = None
    for func in rule_match:
        # 清理正则转义
        clean_func = func.replace('\\.', '.').replace('\\(', '(').replace('\\)', ')')
        if clean_func in line_text:
            matched_func = clean_func
            break

    if not matched_func:
        # 模糊匹配
        for func in rule_match:
            clean_func = func.replace('\\.', '.').replace('\\(', '(').replace('\\)', ')')
            parts = clean_func.split('.')
            if any(p in line_text for p in parts if len(p) > 2):
                matched_func = clean_func
                break

    if not matched_func:
        logger.debug("[AST][Go] No matching function found in line")
        return results

    # ---- tree-sitter 解析整个文件，获取 AST ----
    ast_tree = _parse_go_ast(file_path)
    call_node = None
    ast_args = []  # AST 节点列表

    if ast_tree is not None:
        # 在 AST 中查找 vul_lineno 上的 call_expression
        call_node = _find_call_at_line(ast_tree, vul_lineno, matched_func)
        if call_node is not None:
            ast_args = _get_call_args_from_ast(call_node)

    # AST 提取成功 → 用 AST 节点分析参数
    if ast_args:
        # 检查内置知识库
        knowledge = lookup_builtin(matched_func)
        if knowledge and knowledge.get("safe"):
            results.append({'code': -1, 'chain': []})
            return results

        for arg_idx, arg_node in enumerate(ast_args):
            arg_text = arg_node.text.decode('utf-8', errors='ignore')

            # 字符串字面量 → 跳过
            if arg_node.type in ('interpreted_string_literal', 'raw_string_literal',
                                  'int_literal', 'float_literal', 'true', 'false', 'nil'):
                logger.debug("[AST][Go] Arg[{}] is literal: {}".format(arg_idx, arg_text))
                continue

            # 提取参数中的所有标识符
            var_names = _collect_identifiers_from_ast(arg_node)

            for var_name in var_names:
                # 直接可控源
                if _is_controllable_source(var_name, controlled_params):
                    logger.debug("[AST][Go] Variable {} controllable".format(var_name))
                    results.append({'code': 1, 'chain': [
                        ('source', var_name, file_path, vul_lineno),
                        ('sink', matched_func, file_path, vul_lineno)
                    ]})
                    return results

                # 反向追踪
                trace_code, src_lineno = _trace_variable_in_lines(
                    file_path, var_name, vul_lineno, vul_lineno,
                    repair_functions, controlled_params
                )
                if trace_code == 1:
                    results.append({'code': 1, 'chain': [
                        ('source', var_name, file_path, src_lineno if src_lineno else vul_lineno),
                        ('sink', matched_func, file_path, vul_lineno)
                    ]})
                    return results
                elif trace_code == 2:
                    results.append({'code': 2, 'chain': [
                        ('repair', var_name, file_path, src_lineno if src_lineno else vul_lineno),
                        ('sink', matched_func, file_path, vul_lineno)
                    ]})
                    return results
                elif trace_code == 3:
                    results.append({'code': 3, 'chain': [
                        ('unconfirmed', var_name, file_path, src_lineno if src_lineno else vul_lineno),
                        ('sink', matched_func, file_path, vul_lineno)
                    ]})
                    return results

        results.append({'code': -1, 'chain': []})
        return results

    # ---- AST 失败：使用 line_text 文本 fallback ----
    if not is_config_vuln and line_text:
        import re as _re_fallback
        escaped_func = _re_fallback.escape(matched_func)
        call_match = _re_fallback.search(escaped_func + r'\s*\(([^)]*)\)', line_text)
        if call_match:
            args_text = call_match.group(1)
            for arg in _re_fallback.split(r',\s*', args_text):
                arg = arg.strip()
                if _re_fallback.match(r'^"[^"]*"$', arg):
                    continue
                var_match = _re_fallback.findall(r'[a-zA-Z_]\w*', arg)
                for var_name in var_match:
                    if var_name in ('sh', 'bash', 'c', 'true', 'false', 'nil', 'string', 'int'):
                        continue
                    # 简单文本追踪：向上查找 var_name 的赋值来源
                    code, src_line = _text_trace_variable(
                        file_path, var_name, vul_lineno,
                        repair_functions, controlled_params
                    )
                    if code == 1:
                        results.append({'code': 1, 'chain': [
                            ('source', var_name, file_path, src_line if src_line else vul_lineno),
                            ('sink', matched_func, file_path, vul_lineno)
                        ]})
                        return results

    if is_config_vuln:
        results.append({
            'code': 4,
            'source': matched_func,
            'chain': [('sink', matched_func, file_path, vul_lineno)]
        })
    else:
        results.append({'code': -1, 'chain': []})

    return results


def analysis_params(param_name, parent_func_names, vul_function, lineno, file_path,
                    repair_functions=None, controlled_params=None, isexternal=False):
    """
    Go 变量可控性分析（供 CAST 跨文件分析调用）

    :param param_name: 要追踪的变量名
    :param parent_func_names: 父函数名列表（Go 中暂不使用）
    :param vul_function: 漏洞函数列表
    :param lineno: 当前行号
    :param file_path: 文件路径
    :param repair_functions: 修复函数列表
    :param controlled_params: 可控参数列表
    :param isexternal: 是否外部调用
    :return: (is_controllable, controlled_params, expr_lineno, chain)
        is_controllable: 1=可控, -1=不可控, 3=未确认, 4=新漏洞函数
    """
    if repair_functions is None:
        repair_functions = []
    if controlled_params is None:
        controlled_params = []

    # ---- 预建函数定义索引 ----
    _build_func_def_index(file_path)

    try:
        lineno = int(lineno)
    except (ValueError, TypeError):
        return -1, [], 0, []

    # 追踪变量
    trace_code, src_lineno = _trace_variable_in_lines(
        file_path, param_name, lineno, lineno,
        repair_functions, controlled_params
    )

    if trace_code == 1:
        return 1, controlled_params, lineno, [('source', param_name, file_path, src_lineno if src_lineno else lineno)]
    elif trace_code == 2:
        return 2, controlled_params, lineno, [('repair', param_name, file_path, src_lineno if src_lineno else lineno)]
    elif trace_code == 3:
        return 3, controlled_params, lineno, [('unconfirmed', param_name, file_path, src_lineno if src_lineno else lineno)]
    else:
        return -1, [], 0, []
