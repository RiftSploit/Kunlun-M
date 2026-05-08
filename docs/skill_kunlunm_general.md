# Kunlun-M 通用 Skill（kunlun-m-general）

本 Skill 目标是把 Kunlun-M 的常用流程自动化：扫描漏洞、生成 rule、生成 tamper、同步与验证。

## 前置条件与初始化

Kunlun-M 的 CLI 运行在 Django 环境中。首次使用前需要完成依赖安装与数据库初始化，否则扫描/同步会报数据库相关错误。

## 获取 Kunlun-M（当环境里只有 skill 时）

如果环境里只有 skill，没有 Kunlun-M 项目目录（找不到 `kunlun.py`），需要先下载项目：

### 方式 0：直接跑 bootstrap 脚本（推荐）

```bash
python skills/kunlun-m-general/scripts/bootstrap_kunlunm.py --repo-dir ./Kunlun-M
```

### 方式 A：git clone（推荐）

```bash
git clone https://github.com/LoRexxar/Kunlun-M.git
cd Kunlun-M
```

### 方式 B：下载 zip（无 git 环境）

```bash
curl -L -o Kunlun-M.zip https://github.com/LoRexxar/Kunlun-M/archive/refs/heads/master.zip
unzip Kunlun-M.zip
cd Kunlun-M-master
```

然后在项目根目录继续执行初始化命令：

```bash
pip install -r requirements.txt
cp Kunlun_M/settings.py.bak Kunlun_M/settings.py
python kunlun.py init initialize
python kunlun.py config load
python kunlun.py config loadtamper
```

## 安装

把仓库内的 `skills/kunlun-m-general` 安装到本机 Trae/SOLO skills 目录：

```bash
python tools/install_trae_skill.py --name kunlun-m-general --force
```

安装成功会输出目标目录路径，例如：

```
C:\Users\<you>\.trae\skills\kunlun-m-general
```

## CLI 流程速查

更完整的 CLI 文档见：

- [cli.md](file:///d:/program/Kunlun_M/docs/cli.md)
- [rules.md](file:///d:/program/Kunlun_M/docs/rules.md)
- [tamper.md](file:///d:/program/Kunlun_M/docs/tamper.md)

## 概念速查（为什么要生成 rule/tamper）

### Rule（规则）

- 作用：定义漏洞识别逻辑（命中点、匹配模式、必要时的参数抽取与语义回溯入口）
- 什么时候需要：漏报补齐、新漏洞模式沉淀、团队/CI 交付
- 如何落地：`generate rule` 先出骨架 → 修改 `match/match_mode/main()` → `scan -r <id>` 小范围验证

### Tamper（污点/修复策略）

- 作用：告诉引擎哪些是“过滤/净化函数（repair）”以及哪些是“可控输入源（controlled）”，用于降低误报与适配框架封装
- 什么时候需要：误报集中在某框架/CMS、输入源封装导致回溯无法识别可控来源
- 如何落地：`generate tamper` 先出骨架 → 补齐过滤函数/输入源 → `scan -tp <name>` 回归验证

### 1) 扫描漏洞

```bash
python kunlun.py scan -t <target_path>
python kunlun.py scan -t <target_path> -lan php -b vendor,node_modules -d
python kunlun.py scan -t <target_path> -r 1000,1001
python kunlun.py scan -t <target_path> -tp wordpress
```

### 2) 生成 rule（脚手架）

```bash
python kunlun.py generate rule -lan php --name "Reflected XSS"
python kunlun.py generate rule -lan php --name "Reflected XSS" --match "echo|print" --sync
```

默认编号按语言分段并自增：

- php：1000+
- javascript：2000+
- solidity：3000+
- chrome_ext：4000+

### 3) 生成 tamper（脚手架）

```bash
python kunlun.py generate tamper --name wordpress
python kunlun.py generate tamper --name wordpress --controlled "$_GET,$_POST" --sync
python kunlun.py generate tamper --name wordpress --filter-func "{\"esc_html\": [1000], \"esc_attr\": [1000]}"
```

### 4) 单独同步（文件 ↔ 数据库）

```bash
python kunlun.py config load
python kunlun.py config loadtamper
```

## 端到端示例

### 示例 A：扫描一个目录

```bash
python kunlun.py scan -t ./my_project -lan php -b vendor,node_modules -d
```

### 示例 B：生成一个 php rule → 小范围验证

```bash
python kunlun.py generate rule -lan php --name "My Test Rule"
python kunlun.py scan -t ./my_project -lan php -r 1000
```

### 示例 C：生成一个 tamper → 回归验证

```bash
python kunlun.py generate tamper --name mycms --controlled "$_GET,$_POST"
python kunlun.py scan -t ./my_project -lan php -tp mycms
```

## 常见错误与排查

- 报数据库表不存在/迁移问题：先执行 `python kunlun.py init initialize`
- `--sync` 报错：确认数据库可写，且已执行过 `config load/loadtamper`
- `ModuleNotFoundError`：确认依赖已 `pip install -r requirements.txt`
