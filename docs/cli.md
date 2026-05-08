# CLI 使用说明

Kunlun-M 的命令入口是：
```bash
python kunlun.py <subcommand> [args]
```

## 子命令一览

### init
初始化/迁移数据库：
```bash
python kunlun.py init initialize
python kunlun.py init checksql
```

### config
同步规则与 tamper（文件 <-> 数据库）：
```bash
python kunlun.py config load
python kunlun.py config recover
python kunlun.py config loadtamper
python kunlun.py config retamper
```

### scan
扫描目标路径或压缩包：
```bash
python kunlun.py scan -t tests/vulnerabilities
python kunlun.py scan -t tests/vulnerabilities -r 1000,1001
python kunlun.py scan -t tests/vulnerabilities -tp wordpress
python kunlun.py scan -t tests/vulnerabilities -f html -o /tmp/report.html
python kunlun.py scan -t tests/vulnerabilities -f md -o /tmp/report.md
```

常用参数：
- `-t/--target`：目标文件/目录（必填）
- `-f/--format`：输出格式（`csv/json/xml/md/html`；默认 `csv`）
- `-o/--output`：输出路径（为空则输出到控制台或默认路径；为文件路径则写入文件）
- `-r/--rule`：只跑指定规则（逗号分隔 CVI 编号）
- `-lan/--language`：指定语言（逗号分隔）；不传会自动识别主语言/框架
- `-b/--blackpath`：黑名单路径列表（逗号分隔，例如 `-b vendor,node_modules`）
- `--without-vendor`：关闭组件漏洞（SCA）扫描
- `-d/--debug`：开启 debug 日志

说明：
- 目标为 `.zip` 时会尝试自动解压后扫描。
- 未指定 `-o` 输出文件名时，会默认写到 `result/<target>.<format>`。
- `-f json`：导出的 JSON 会包含更完整的信息（例如 `meta/summary`，以及规范化后的 `vulnerabilities` 字段）。
- `-f md`：输出 Markdown 报告，包含全部漏洞详情（analysis/code/chain/raw）。
- `-f html`：输出单文件自包含的 HTML 报告，支持搜索、按严重度筛选、展开/收起全部。

示例报告（可直接打开）：
- `docs/sample-cli-report.html`

### show
查看规则与 tamper：
```bash
python kunlun.py show rule
python kunlun.py show rule -k php
python kunlun.py show tamper
```

### search
搜索组件/项目（vendor）信息：
```bash
python kunlun.py search vendor <keyword_name> <keyword_value> --with-vuls
```

### console
进入交互式控制台：
```bash
python kunlun.py console
```

### plugin
运行插件：
```bash
python kunlun.py plugin <plugin_name> -h
python kunlun.py plugin entrance_finder -t <target_path> -l 3
python kunlun.py plugin php_unserialize_chain_tools -t <target_path>
```

### web
启动 Web（Dashboard/API）：
```bash
python kunlun.py web -p 9999
```
