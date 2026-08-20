# WP 台账(append-only;状态只准:pending / in progress / closed)

| WP | 标题 | 拥有文件 | 依赖 | 状态 | 关闭日期 | 开发日志 |
|---|---|---|---|---|---|---|
| WP-01 | exec 层 + 智能输出层 | `tools/bash.py`、`tools/output.py` | 无 | closed | 2026-08-20 | docs/dev-logs/WP-01.md |
| WP-02 | scope 护栏 v0 + 哈希链审计 | `guard/` | 无 | closed | 2026-08-20 | docs/dev-logs/WP-02.md |
| WP-03 | LLM 后端(兼容层 + Claude) | `agent/backends/` | 无 | closed | 2026-08-20 | docs/dev-logs/WP-03.md |
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
- 2026-08-20 **WP-01 closed**:exec 层(tools/bash.py:run_command /
  read_output / list_jobs / kill_job,provider 中立 TOOL_SCHEMAS +
  dispatch 单入口)+ 智能输出层(tools/output.py:合流+分流三文件三
  sha256 落盘、head+tail 截断视图、字节分页、ring buffer 有界,100MB
  实测 Python 峰值 0.80MB);本 WP 测试 31 项全绿,全仓 170 项全绿。
- 2026-08-20 **WP-03 closed**:LLM 后端(agent/backends/:统一事件流
  TextDelta/ToolCall/Usage + 结构化错误树,OpenAI 兼容层 + Anthropic
  httpx 直连;双格式契约测试逐字节一致,防 key 泄漏脱敏有专项测试);
  本 WP 测试 31 项全绿,全仓 170 项全绿。Kimi K3 实测:tool 参数合法
  JSON 率 100%(15/15),触发率 15/16(A4 一次幻觉执行),渗透类授权
  prompt 审核拦截 0/8;Claude 及其余后端无凭据未实测(如实记录)。
