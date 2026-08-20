# WP 台账(append-only;状态只准:pending / in progress / closed)

| WP | 标题 | 拥有文件 | 依赖 | 状态 | 关闭日期 | 开发日志 |
|---|---|---|---|---|---|---|
| WP-01 | exec 层 + 智能输出层 | `tools/bash.py`、`tools/output.py` | 无 | pending | — | — |
| WP-02 | scope 护栏 v0 + 哈希链审计 | `guard/` | 无 | closed | 2026-08-20 | docs/dev-logs/WP-02.md |
| WP-03 | LLM 后端(兼容层 + Claude) | `agent/backends/` | 无 | pending | — | — |
| WP-04 | agent 主环 | `agent/loop.py`、`agent/prompts.py`、`cli.py` 初版 | 01/02/03 | pending | — | — |
| WP-05 | 持久 PTY 会话层(含 msfconsole) | `tools/session.py` | 01 | pending | — | — |
| WP-06 | 状态层(文件仓 + SQLite 索引) | `state/`、`tools/state.py` | 01 | pending | — | — |
| WP-07 | parse 增强库 | `tools/parse.py` | 06 | pending | — | — |
| WP-08 | 工具地图(全库盘点注入 prompt) | `agent/toolmap.py` | 04 | pending | — | — |
| WP-09 | TUI(迎宾屏 → 主界面) | `tui/` | 04 | pending | — | — |
| WP-10 | CLI 闭环(run/resume/replay/report) | `cli.py`、`replay.py` | 02/04/06 | pending | — | — |
| WP-11 | e2e 场景一:容器靶场 Web 全链 | `tests/e2e/`、`docs/e2e/` | 04-08 | pending | — | — |
| WP-12 | e2e 场景二:Metasploitable2 + msf shell | `tests/e2e/`、`docs/e2e/` | 05 | pending | — | — |
| WP-13 | 总体整合 + 发布准备 | 全仓只读 + 文档 | 全部 | pending | — | — |

## 关闭记录(新条目追加在下方)

- 2026-08-20 **WP-02 closed**:scope 护栏 v0(guard/scope.py)+ 哈希链审计
  (guard/audit.py);本 WP 测试 108 项全绿,全仓 170 项全绿;绕过面清单与
  误判案例见开发日志。
