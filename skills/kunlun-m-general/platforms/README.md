# 平台结构适配（同一份 skill，不写多份表述）

kunlun-m-general 走 AgentSkills 标准：同一份 skill 目录可以被多个平台加载；差异主要在“放在哪个目录”与“可选平台元数据文件”。

## OpenClaw

- 推荐（项目级）：`<workspace>/skills/kunlun-m-general/`
- 推荐（用户级）：`~/.openclaw/skills/kunlun-m-general/`
- 规范与加载位置参考：OpenClaw Skills 文档（AgentSkills 兼容） https://docs.openclaw.ai/tools/skills

## Codex

- 推荐（项目级）：`<repo-root>/.agents/skills/kunlun-m-general/`
- 推荐（用户级）：`~/.agents/skills/kunlun-m-general/`
- 可选元数据：`agents/openai.yaml`（本 skill 已提供）
- 参考：Codex Agent Skills 文档 https://developers.openai.com/codex/skills

## Claude Code

- 推荐（项目级）：`<repo-root>/.claude/skills/kunlun-m-general/`
- 推荐（用户级）：`~/.claude/skills/kunlun-m-general/`
- 参考：Claude Code Skills 文档 https://code.claude.com/docs/en/skills

## Hermes

- 推荐（用户级）：`~/.hermes/skills/<category>/kunlun-m-general/`（category 可选，例如 `security`）
- 参考：Hermes Skills System 文档 https://hermes-agent.nousresearch.com/docs/user-guide/features/skills

