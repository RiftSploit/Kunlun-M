# 概念与场景（可选阅读）

这个文件用于放“为什么/什么时候要 rule 或 tamper”的补充说明；SKILL.md 本体保持脚本驱动与短流程。

## Rule/Tamper 与 Source/Sink 的关系（推荐心智模型）

当你希望“主动指定 source 和 sink 进行扫描”时，可以用下面的映射理解 Kunlun-M 的可配置点：

- Sink（危险点/汇聚点）→ Rule（规则）负责描述
  - 常见落点：`match_mode` + `match`（命中哪些函数/语句/关键字）
- Source（可控输入源）→ Tamper 负责描述
  - 常见落点：`<tamper>_controlled`（例如 `$_GET`、`$_POST`，或框架封装后的输入入口）
- 可选：Sanitizer/Repair（净化函数）→ Tamper 也负责描述
  - 常见落点：`<tamper>` 字典（过滤/净化函数 → 适用规则列表），用于在回溯中“判定已过滤/终止回溯”

因此：当你要为一个新框架/新项目“自定义 source/sink”扫描时，通常需要同时生成一个 tamper（source/repair）+ 一个 rule（sink）。

## 什么时候需要 Rule（偏 sink）

- 你想新增/调整 sink：例如新增一类危险函数、危险语句形态、或特定调用链入口
- 你要把“某类 sink + 回溯策略”固化成可复用规则（团队/CI 交付）

回归方式：

- `scan -r <id>` 只跑该规则做快速验证

## 什么时候需要 Tamper（偏 source/repair）

- 你想新增/调整 source：例如框架把输入封装成 `request->input()` / `ctx.query` 等，导致默认 source 不生效
- 你想新增/调整 repair：例如框架/CMS 有统一过滤函数（sanitize/escape），需要告诉引擎“经过该函数视为已净化”

回归方式：

- `scan -tp <name>` 指定 tamper 做回归
