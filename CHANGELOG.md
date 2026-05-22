# Changelog

## [2.9.1] - 2025-05-22

### Bug Fixes

- **Java 链式调用漏报修复**：javalang 解析器将链式方法调用（如 `Runtime.getRuntime().exec(cmd)`、`new ProcessBuilder(cmd).start()`）中的后续方法放入扁平的 `selectors` 列表，导致 sink 搜索和污点传播遗漏链式调用中的关键方法。新增 `_flatten_chained_calls()` 辅助函数展开 selectors，并在 sink 搜索、变量收集、对象污点传播三个环节增加 selectors 遍历支持。（[b2d40c7](https://github.com/LoRexxar/Kunlun-M/commit/b2d40c7))

### Changed

- javalang 依赖从本地 Ljavalang fork 切回 PyPI 默认库（`javalang>=0.13.0`），链式调用兼容性已由 parser 侧修复覆盖。（[877a644](https://github.com/LoRexxar/Kunlun-M/commit/877a644)）

---

## [2.9.0] - 2025-05-20

### Highlights

- **新增 Java 静态代码扫描引擎**：完整支持 Java 源码的 AST 解析与污点分析，包含 58 条检测规则（54 条启用 / 4 条高误报禁用）。

### Features

- Java AST 解析引擎（基于 javalang）：变量声明追踪、方法调用分析、污点传播
- Java 规则覆盖：命令执行（6001-6003）、文件操作（6004）、反序列化（6005）、SSRF（6006）、XXE（6007）、SpEL 注入（6012）、模板注入（6014）、开放重定向（6015）、JNDI 注入（6018）、SQL 注入（6023/6032/6034/6038/6043）、加密（6025）、反射（6027/6028）等
- Framework-dependency 扫描模式：基于 pom.xml 版本比较 + config/exclude 二次确认 + parent 版本继承，检测已知框架漏洞（Shiro、Struts2、Log4j、Fastjson、Collections、XStream、Jackson、Actuator、FileUpload）
- 20+ 靶场验证通过（JavaVul）

### Bug Fixes

- 禁用 13 个高误报 Java 规则（only-regex 误报率 >20%）
- Java function 规则 match 收窄 + main() 过滤优化

---

## [2.8.1] - 2025-05-14

### Bug Fixes

- 修复多个 PHP/JS 扫描引擎稳定性问题

---

## [2.8.0] - 2025-05-10

### Features

- 新增规则管理界面优化

---

> 更早版本的历史记录请查看 [GitHub Releases](https://github.com/LoRexxar/Kunlun-M/releases)
