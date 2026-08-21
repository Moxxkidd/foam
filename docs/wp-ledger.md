# WP 台账(append-only;状态只准:pending / in progress / closed)

| WP | 标题 | 拥有文件 | 依赖 | 状态 | 关闭日期 | 开发日志 |
|---|---|---|---|---|---|---|
| WP-01 | exec 层 + 智能输出层 | `tools/bash.py`、`tools/output.py` | 无 | closed | 2026-08-20 | docs/dev-logs/WP-01.md |
| WP-02 | scope 护栏 v0 + 哈希链审计 | `guard/` | 无 | closed | 2026-08-20 | docs/dev-logs/WP-02.md |
| WP-03 | LLM 后端(兼容层 + Claude) | `agent/backends/` | 无 | closed | 2026-08-20 | docs/dev-logs/WP-03.md |
| WP-04 | agent 主环 | `agent/loop.py`、`agent/prompts.py`、`cli.py` 初版 | 01/02/03 | closed | 2026-08-21 | docs/dev-logs/WP-04.md |
| WP-05 | 持久 PTY 会话层(含 msfconsole) | `tools/session.py` | 01 | closed | 2026-08-21 | docs/dev-logs/WP-05.md |
| WP-06 | 状态层(文件仓 + SQLite 索引) | `state/`、`tools/state.py` | 01 | closed | 2026-08-21 | docs/dev-logs/WP-06.md |
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
- 2026-08-21 **WP-06 closed**:状态层(state/files.py engagement 目录布局
  幂等创建/校验、engagement.json 记 scope sha256、ENGAGEMENT.md 读写接口;
  state/index.py SQLite 六表 upsert/关系查询;tools/state.py 三工具与
  WP-01 schema 同构,creds 对 LLM 默认掩码中段有专项测试);本 WP 测试
  29 项全绿,全仓 245 项全绿(含 WP-04/WP-05 在飞文件,未动未入库)。
- 2026-08-21 **WP-05 closed**:持久 PTY 会话层(tools/session.py:
  session_open/send/read/close/list,复用 WP-01 输出层 split=False 全量
  落盘 + sha256;提示识别正则库命中返回结构化 waiting_for_input 事件;
  ANSI 清洗只作用 LLM 视图、落盘原文;会话上限 + 进程组强杀孤儿回收);
  本 WP 测试 46 项全绿 + 2 项环境门控 skip(ssh localhost:本机 sshd 未
  运行;msfconsole:非 Kali,待 Kali 实测补跑),全仓 245 项全绿。
- 2026-08-21 **WP-04 closed**:agent 主环(agent/loop.py:消息状态机 +
  可追加 ToolRegistry + run_command 逐条过 scope 护栏 + 两阶段 context
  压缩 + 插话/pause/kill 控制面;消化 K3 实测:幻觉执行纠正、
  MalformedToolCall 回灌、首事件超时默认 30s;agent/prompts.py:授权
  声明/方法论骨架/红线,工具地图注入点,全文快照无品牌名;cli.py
  初版:headless run 子命令);本 WP 测试 32 项全绿,全仓 277 项全绿
  (+2 项 WP-05 环境门控 skip);本会话无 LLM 凭据,真实模型 e2e 未跑
  (fake 后端按 WP-03 实测事件形状合成),有凭据后用 `kalicode run` 补跑。
