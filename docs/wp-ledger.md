# WP 台账(append-only;状态只准:pending / in progress / closed)

| WP | 标题 | 拥有文件 | 依赖 | 状态 | 关闭日期 | 开发日志 |
|---|---|---|---|---|---|---|
| WP-01 | exec 层 + 智能输出层 | `tools/bash.py`、`tools/output.py` | 无 | closed | 2026-08-20 | docs/dev-logs/WP-01.md |
| WP-02 | scope 护栏 v0 + 哈希链审计 | `guard/` | 无 | closed | 2026-08-20 | docs/dev-logs/WP-02.md |
| WP-03 | LLM 后端(兼容层 + Claude) | `agent/backends/` | 无 | closed | 2026-08-20 | docs/dev-logs/WP-03.md |
| WP-04 | agent 主环 | `agent/loop.py`、`agent/prompts.py`、`cli.py` 初版 | 01/02/03 | closed | 2026-08-21 | docs/dev-logs/WP-04.md |
| WP-05 | 持久 PTY 会话层(含 msfconsole) | `tools/session.py` | 01 | closed | 2026-08-21 | docs/dev-logs/WP-05.md |
| WP-06 | 状态层(文件仓 + SQLite 索引) | `state/`、`tools/state.py` | 01 | closed | 2026-08-21 | docs/dev-logs/WP-06.md |
| WP-07 | parse 增强库 | `tools/parse.py` | 06 | closed | 2026-08-22 | docs/dev-logs/WP-07.md |
| WP-08 | 工具地图(全库盘点注入 prompt) | `agent/toolmap.py` | 04 | closed | 2026-08-22 | docs/dev-logs/WP-08.md |
| WP-09 | TUI(迎宾屏 → 主界面) | `tui/` | 04 | closed | 2026-08-22 | docs/dev-logs/WP-09.md |
| WP-10 | CLI 闭环(run/resume/replay/report) | `cli.py`、`replay.py` | 02/04/06 | closed | 2026-08-22 | docs/dev-logs/WP-10.md |
| WP-11 | e2e 场景一:容器靶场 Web 全链 | `tests/e2e/`、`docs/e2e/` | 04-08 | pending | — | — |
| WP-12 | e2e 场景二:Metasploitable2 + msf shell | `tests/e2e/`、`docs/e2e/` | 05 | pending | — | — |
| WP-13 | 总体整合 + 发布准备 | 全仓只读 + 文档 | 全部 | pending | — | — |

## 里程碑门(milestone;挂牌不改 WP 制,见 HANDOVER 同名节)

| 门 | 标志 | 门口动作 | 状态 |
|---|---|---|---|
| M1 | WP-04 关闭 | 能力演示:真实 K3 后端 `foam run` 跑通 lab scope 内无害链(补 WP-04 未跑的真实模型 e2e);方向复评 | **已通过(2026-08-21)**:演示补跑通过(exit 0/finished/6 轮,审计链 verify 通过,幻觉纠正真实触发一次且模型以核验响应,零越界零泄漏,证据见 docs/dev-logs/WP-04.md「补跑」节)+ 方向复评**放行**;WP-08/09/10 开闸 |
| M2 | WP-09+10 关闭 | TUI/CLI 可演示,对照 strix/Claude Code 观感打分;方向复评 | **已触发(2026-08-22 WP-09 关闭)**:观感自查证据 docs/dev-logs/WP-09.md 验收 3;门口动作(观感打分 + 方向复评)待执行 |
| M3 | WP-11+12 关闭 | 双场景实弹;对照唯一目标复评:1+1≫2?全库工具真被用上? | 待触发 |
| M4 | WP-13 关闭 | 发布评审 | 待触发 |

门口纪律:产出三选一——放行 / 规格更正当 / 砍后续 WP;不开新坑(新想法
入 WP-13 的 v1 立项清单)。波次中途不受理方向争论。门口动作是协调层动作,
不改变任何 WP 的验收标准与关闭纪律。(2026-08-21 挂牌)

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
  (fake 后端按 WP-03 实测事件形状合成),有凭据后用 `foam run` 补跑。
- 2026-08-22 **WP-08 closed**:工具地图(agent/tool_catalog.py 静态目录
  7 组 137 工具,name 即 which/路径/dpkg 探测键,死链从结构上不可能;
  agent/toolmap.py 三级探测命中即停——which → 常见目录(含 /opt 目录形态)
  → dpkg -l 包名兜底,缺失只标注附 apt 包名、绝不自动装;地图文本 ≤2KB
  四级降级(3 全文 → 0 只余可用名),current_phase 组细节升一级,可用名
  全保为地板;注入契约经真实 build_system_prompt 走通,零品牌名);本 WP
  测试 16 项全绿,全仓(减 WP-07 在飞文件 test_parse.py)293 项全绿;
  Kali 实测覆盖率待补(WP-11 前,见 docs/dev-logs/WP-08.md)。
- 2026-08-22 **WP-10 closed**:CLI 闭环(cli.py 重写:run 收尾接 WP-06
  Engagement.create + WP-05/WP-06 工具经 ToolRegistry 全量注册 + WP-08
  工具地图注入;resume 同步 preflight——链验/objective 与 scope 对账
  (sha256 或摘要)/legacy 布局幂等修复,上下文=system 重建 +
  ENGAGEMENT.md + resume 简报,非全量回放;replay verify 先行,断链报
  首个断点 seq 绝不回放;report 中文 markdown 全必备节,凭证全值直接
  读落盘 index.sqlite,缺件逐级降级不炸;tui 占位约定
  foam.tui.app:main(args);loop.py 最小改动:ENGAGEMENT.md 走
  state/files.py 接口、kill 清理面扩到 session.aclose());本 WP 相关
  4 测试文件 53 例全绿,暂存树(=提交快照,不含 WP-07/09 在飞文件)
  独立验证 314 绿 + 2 环境门控 skip,ruff 全过;live 证据:m1-demo
  副本 replay/resume/篡改断点 seq=9/legacy 报告 + 真实 K3 fresh run
  6 轮 finished(护栏真实拦截版本串误判一次,模型据纠正说明改写通过)。
  另:顺手更正 WP-08 台账表格行 pending→closed(其关闭记录条目本就
  完整,表格行漏改,已在 WP-10 日志声明)。
- 2026-08-22 **Kali 实机补测核销**(非 WP 动作):WP-05 验收 3(ssh
  localhost)真跑通过;验收 4(msfconsole)真跑——提示库无碍,测试
  wait_pattern 写死 `msf6 >`(本机 6.4.84 已改回 `msf >`,落盘实证),
  已修两代兼容并经 Kali 侧手工全链 4.4s 走通。WP-08 验收 4:覆盖率
  96/137 = 70.1%(which 91 + dpkg 兜底 5),dpkg 断言平台化。全仓 337
  项 335 过 2 败(即上述两项),Linux PTY EIO-EOF 分支首次真 Linux 全绿。
  证据回填 docs/dev-logs/WP-05.md 与 WP-08.md 的「补测」节。
- 2026-08-22 **WP-07 closed**:parse 增强库(tools/parse.py:解析器
  注册表 + maybe_parse 单入口,「增强而非门槛」——注册表未命中
  静默走通用路径不记审计,解析失败记 parse_fallback debug 审计,
  绝不抛给 LLM;6 解析器:nmap XML/grepable/文本三格式(grepable
  补录无开放端口存活主机、rDNS 回填)、sqlmap(stdout 注入确认 +
  loot CSV 登记与口令列提 cred)、gobuster/nikto(SSL Info 剔除、
  Target IP 定 facts 归属)/hydra(连字符模块)/whatweb;summary
  ≤500B LLM 视图掩码,facts 经 apply_facts 喂 WP-06 索引,cred
  完整值落盘)。ultracode 对抗审查 29 agent 确认 20 项全修并配
  回归测试(21→38 项);二次复审子代理配额 403 未启动,主会话
  三项变异抽查补位(如实记录,见日志)。本 WP 测试 38 项全绿,
  全仓 375 项全绿 + 2 环境门控 skip(含 WP-09 在飞文件,未动未
  入库),ruff 全过。
- 2026-08-22 **WP-09 closed**:TUI(tui/:迎宾屏纯呼号门[空呼号拒入、
  呼号三去向 engagement.json operator+审计载荷+~/.foam 预填] →
  主界面[叙述流:思考块折叠/工具卡紧凑流+六类异常自展开/ENGAGEMENT.md
  阶段分隔条;侧栏:阶段/索引/token 预算条/jobs/sessions;双通道控制面:
  插话+七斜杠命令补全,Ctrl-X 二次确认 kill、Ctrl-P 暂停、F2 侧栏,
  无 `!` shell 前缀];`foam tui` 经 foam.tui.app:main(args) 按 WP-10
  约定接线,cli 零改动)。ReasoningDelta 链路(base/openai_compat/loop
  三处声明增量)思考流上屏、审计只记 sha256+chars;loop 另增
  extract_phase/on_phase 与 operator 入 operator_interject 载荷;
  state/files.py 增 set_operator;tests/test_cli.py 占位测试按约定
  更新 1 个(均见日志声明节)。观感自查(验收 3,对照 strix/Claude
  Code 逐屏文字描述)入日志,M2 门核心证据。本 WP 23 项 + cli 接线
  13 项全绿,全仓 375 项全绿 + 2 环境门控 skip(WP-07 已先关闭入库,
  提交面即 git diff 全量),ruff 全过。textual 踩坑 11 条入日志
  (switch_screen 自死锁/Widget.name/MessagePump._running 等)。
