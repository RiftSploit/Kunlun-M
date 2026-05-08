---
name: kunlun-m-general
description: "自动化 Kunlun-M 工作流：下载/初始化 Kunlun-M，运行 CLI 扫描漏洞，生成 rule/tamper，并提供回归验证与可选同步。"
compatibility: "需要 Python 3 + pip；需要联网；可选依赖 git（优先 clone）与 unzip（zip 回退路径）。"
metadata:
  repo: "https://github.com/LoRexxar/Kunlun-M"
---

# Kunlun-M 通用 Skill（脚本落地版）

本 skill 只包含可直接执行的脚本与最小流程，优先用脚本完成动作，不在 SKILL.md 里展开原理解释。

## 0. 一键准备环境（没有 Kunlun-M 时）

```bash
python skills/kunlun-m-general/scripts/bootstrap_kunlunm.py --repo-dir ./Kunlun-M
```

默认行为：优先 git clone，失败回退 zip；然后执行 `pip install`、复制 `settings.py`、初始化 DB、load rules/tamper。

## 1. 用脚本执行日常动作（推荐）

约定：`--repo-root` 指向 Kunlun-M 目录（里面有 `kunlun.py`）。

### 扫描

```bash
python skills/kunlun-m-general/scripts/kunlun_ops.py --repo-root ./Kunlun-M scan -t <target> -lan php -b vendor,node_modules -d
```

### 生成 rule（漏报补齐）

```bash
python skills/kunlun-m-general/scripts/kunlun_ops.py --repo-root ./Kunlun-M gen-rule -lan php --name "<rule_name>" --match "<regex>"
python skills/kunlun-m-general/scripts/kunlun_ops.py --repo-root ./Kunlun-M scan -t <target> -lan php -r <id>
```

### 生成 tamper（误报治理/框架适配）

```bash
python skills/kunlun-m-general/scripts/kunlun_ops.py --repo-root ./Kunlun-M gen-tamper --name <proj> --controlled "$_GET,$_POST"
python skills/kunlun-m-general/scripts/kunlun_ops.py --repo-root ./Kunlun-M scan -t <target> -lan php -tp <proj>
```

### 同步到数据库（可选：仅 Web 管理需要）

```bash
python skills/kunlun-m-general/scripts/kunlun_ops.py --repo-root ./Kunlun-M sync --rule --tamper
```

## 2. 最小概念（只留决策点）

- 规则（rule）≈ sink（危险点）：要扫哪些危险函数/语句就生成/调整 rule，然后用 `scan -r <id>` 回归
- 污点策略（tamper）≈ source + repair：要定义输入源或净化函数就生成/调整 tamper，然后用 `scan -tp <name>` 回归

更详细的概念与场景说明见：[concepts.md](file:///d:/program/Kunlun_M/skills/kunlun-m-general/references/concepts.md)

## 多平台结构（同一份内容）

- 该 skill 不维护多份表述；不同平台主要差异是“放在哪个目录/可选元数据文件”
- 平台落地路径与说明： [README.md](file:///d:/program/Kunlun_M/skills/kunlun-m-general/platforms/README.md)
- 一键复制到目标平台目录（可选）：`python skills/kunlun-m-general/scripts/install_platform.py --platform <openclaw|codex|claude-code|hermes> --scope <user|project> --repo-root <repo>`

## 安全约束

- 不在 rule/tamper 中写入真实密钥、token、真实 URL、账号密码等敏感信息
- 只维护“函数名 / 输入源 / 规则编号 / 规则逻辑”这类抽象信息
