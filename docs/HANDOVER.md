# HANDOVER —— 交接文档(append-only 修订,见 AGENTS.md §3)

> 读法:先看「当前状态」定位,再看「下一 WP」,「已知陷阱」防重复踩坑。
> 每个 WP 关闭时更新本文件(契约第 2.3 条)。

## 当前状态

- 2026-08-19:**阶段 0 完成**——仓库骨架(pyproject/LICENSE/README/
  scopes/包目录)、开发契约(AGENTS.md)、本文件、台账、全部 WP 规格
  文档就绪;GitHub 私有 repo 已建并推送 main。尚无任何功能代码。
- 2026-08-20:**WP-02 关闭**——scope 护栏 v0(`guard/scope.py`:CIDR/
  主机名/通配域/URL 前缀解析,启发式目标提取,拒绝时给 LLM 可行动纠正
  说明)+ 哈希链审计(`guard/audit.py`:append-only JSONL,`verify`
  全链重算,LLM 内容只记哈希与 token 数)。绕过面清单与误判案例见
  `docs/dev-logs/WP-02.md`。
- 2026-08-20:**WP-01 关闭**——exec 层(`tools/bash.py`:run_command /
  read_output / list_jobs / kill_job,进程组强杀防孤儿,timeout 默认
  放宽到 1800s、显式 null 不限时,list_jobs 带超时剩余秒数)+ 智能输出
  层(`tools/output.py`:合流 + stdout/stderr 分流三文件、三个流式
  sha256 全量落盘,head+tail 截断视图,字节级分页,ring buffer 有界
  ——100MB 实测 Python 峰值 0.80MB)。工具 schema 为 provider 中立
  `{name, description, parameters}` 纯 dict(`TOOL_SCHEMAS` +
  `BashTool.dispatch`):WP-03 负责翻译、WP-04 直接注册、WP-06 同构。
  设计取舍与踩坑见 `docs/dev-logs/WP-01.md`。
- 2026-08-20:**WP-03 关闭**——LLM 后端(`agent/backends/`:统一
  `chat(messages, tools)` 异步事件流,事件仅 TextDelta/ToolCall/Usage
  三种,ToolCall.arguments 必为合法 dict;结构化错误树区分可重试
  (网络/超时/限流/5xx)与 provider 拒绝(审核/鉴权/坏请求);
  provider 错误回显 key 的脱敏有专项测试)。OpenAI 兼容层实测 Kimi K3
  (`k3`,思考型,reasoning_content 本层 v1 不消费):参数合法 JSON 率
  100%,授权渗透 prompt 审核拦截 0/8,首事件延迟中位约 4.3s。Claude
  端凭据未提供未实测。详见 `docs/dev-logs/WP-03.md`。
- 2026-08-20:**仓库历史重写**(非 WP 动作,与开发条目正交)——为让
  GitHub 贡献正确归属,全部 commit 的作者/提交者统一重写为
  `Moxxkidd <Moxxkidd@users.noreply.github.com>`,5 个 commit 哈希全部
  变更(重写前后逐对校验 tree 字节一致,内容零变化);旧哈希在仓库跟踪
  文件中无任何引用,无需替换。本地单一工作区、无其他克隆,无连带影响。
  此后新 commit 均带正确身份,无需再做此类重写。
- 2026-08-21:**WP-06 关闭**——状态层(`state/files.py`:engagement
  目录布局幂等创建/校验,`engagement.json` 记 scope 文件 sha256,
  `ENGAGEMENT.md` 读写接口留 loop 每轮调用;`state/index.py`:SQLite
  六表 upsert/关系查询/通用 query;`tools/state.py`:state_query /
  state_add_note / state_add_loot 三工具,schema 与 WP-01 同构)。
  **outputs/ 契约**:`Engagement.paths.outputs` 即 WP-01 输出层的
  output_root,WP-04/WP-10 接线时传入 `BashTool(output_dir=...)`;
  creds 对 LLM 默认掩码中段(完整值仅在落盘 index.sqlite,WP-10 经
  索引层取)。详见 `docs/dev-logs/WP-06.md`。
- 2026-08-21:**WP-05 关闭**——持久 PTY 会话层(`tools/session.py`:
  session_open/send/read/close/list,复用 WP-01 输出层 `split=False`
  全量落盘 + 流式 sha256,分流字段固定 None;pty 显式取 ctty,ssh
  `/dev/tty` 密码提示可达;提示识别正则库(msf6/meterpreter/password/
  ssh yes-no/sqlmap Y-n)命中返回结构化 `waiting_for_input` 事件,尾部
  锚定 + offset 去重防误报/重复;ANSI 清洗只作用 LLM 视图,落盘原文;
  会话上限默认 8 按未关闭计,进程组 SIGKILL 回收孤儿,`aclose()` 供
  WP-04 kill switch)。msfconsole/ssh 两项环境门控 skip 待补测,见
  `docs/dev-logs/WP-05.md`。
- 2026-08-21:**WP-04 关闭**——agent 主环(`agent/loop.py`:消息状态机
  user→assistant(tool_call)→tool 结果直至 finish;可追加 ToolRegistry
  (未知工具名/非法参数回 error dict 让模型自我纠正);每条 run_command
  先过 scope 护栏,拒绝连同纠正说明回消息流;两阶段 context 压缩(先旧
  tool 结果→占位含落盘路径+sha256,再旧对话,system/ENGAGEMENT.md/
  objective/最近窗口永不压缩);插话 turn 边界注入、pause/resume、kill
  立即 cancel 当前 turn 并杀全部活动 job;消化 K3 实测:幻觉执行动作
  声明纠正(预算 2 次)、MalformedToolCall 空参重建帧+坏 JSON 回灌
  (连续 3 次熔断)、首事件超时默认 30s;新增审计 kind:run_started/
  run_finished/loop_correction/llm_retry/context_compressed)。
  `agent/prompts.py`:授权声明(scope 规则原文+加载时间)、方法论骨架、
  红线、工具地图注入点,快照测试逐字锁定、零品牌名。`cli.py` 初版:
  `foam run` headless(退出码 0/130/1/2,Ctrl-C 两次语义)。
  真实模型 e2e 已于关闭后补跑(M1 门):K3 六轮跑通 lab 无害链,幻觉
  纠正真实触发一次(设计内误报,模型以真实核验响应),审计链 verify
  通过,零越界零泄漏——证据见 `docs/dev-logs/WP-04.md`「补跑」节。
  接线点与已知限制见同日志。
- 2026-08-22:**正式定名 Foam**(非 WP 动作,与开发条目正交)——
  暂用代号「Kali Code」退役(同日曾短暂定名 The Form,数小时内更正,
  未产生任何外部引用)。包名 `foam`、命令 `foam`/`fm`、
  env `FOAM_*`、家目录 `~/.foam.env`;`__app_name__ = "Foam"`。
  品牌纪律价值获验证:全仓仅 pyproject/README/`__init__.py`/AGENTS.md
  §0 四处需手工收口,其余为机械替换;测试快照零品牌串。WP-13 的改名
  验证项已核销。
- 2026-08-22:**WP-08 关闭**——工具地图(`agent/tool_catalog.py`:静态
  目录 7 组 137 工具,name 即 which/路径/dpkg 探测键,死链从结构上不可能;
  `agent/toolmap.py`:which → 常见目录(含 /opt 目录形态)→ `dpkg -l`
  包名兜底,三级探测命中即停,缺失只标注附 apt 包名、绝不自动装;地图
  文本 ≤2KB 四级降级(3 全文 → 0 只余可用名),`current_phase` 组细节升
  一级,可用名全保为地板;注入契约经真实 `build_system_prompt` 走通,零
  品牌名)。cli 接线接口(scan_tools/render_tool_map/render_startup_line)
  已备,接线本身属 WP-10(见下节⑤)。本 WP 测试 16 项全绿;关闭时全仓
  310 绿 + 3 红,红全部位于 WP-07 在飞文件(test_parse.py,未入库),与
  本 WP 零耦合。Kali 实测覆盖率待补(WP-11 前,与 WP-05 msfconsole 同趟),
  详见 `docs/dev-logs/WP-08.md`。
- 2026-08-22:**WP-10 关闭**——CLI 闭环(`cli.py` 重写:run 收尾接
  WP-06 `Engagement.create` 幂等布局 + WP-05 会话/WP-06 状态工具经
  `ToolRegistry.register_module` 全量注册 + WP-08 工具地图注入 prompt;
  `resume` 同步 preflight 链验 + objective/scope 对账(sha256 或摘要,
   drift 拒绝、显式 `--scope` 视为重新授权)+ legacy 目录幂等修复,
  上下文=system 重建 + ENGAGEMENT.md + resume 简报(非全量回放);
  `replay` verify 先行,断链报首个断点 seq、绝不回放不可信历史;
  `report` 中文 markdown 全必备节,凭证全值直接读落盘 index.sqlite
  (LLM 视图仍掩码),缺件逐级降级不炸;`tui` 占位,入口约定
  `foam.tui.app:main(args)`)。`cli.py` 所有权 WP-04 → WP-10;loop.py
  最小改动:ENGAGEMENT.md 读写走 `state/files.py` 接口、kill 清理面
  扩到 `session.aclose()`。live 证据(真实 K3 + m1-demo 副本):replay
  31 条链完整、篡改断点 seq=9 精确命中、legacy 报告降级、fresh run
  6 轮 finished 且护栏真实拦截版本串误判一次(模型据纠正说明改写
  通过)。详见 `docs/dev-logs/WP-10.md`(含并行窗口:WP-09 在飞
  hunk 的隔离提交手法)。
- 2026-08-22:**Kali 实机补测核销**(非 WP 动作,WP-05/WP-08 待补测项
  同趟完成;Kali 侧 agent 执行,原始记录已入库
  `docs/dev-logs/Kali-补测.md`;环境 Kali Rolling **arm64** / Python
  3.13.7,组件比开发机新)——WP-05:ssh localhost
  真跑通过;msfconsole 真跑,提示识别库两代兼容无碍,是测试
  wait_pattern 写死旧字面量 `msf6 >`(本机 metasploit 6.4.84 已改回
  `msf >`,落盘原文实证),已修 `msf[56]?` 并经 Kali 侧手工全链 4.4s
  走通(pytest 形态留下次 Kali 会话顺手复跑,WP-12 开工时做掉)。
  WP-08:覆盖率 **96/137 = 70.1%**(which 91 + dpkg 兜底 5),dpkg 断言
  改平台自适应;缺失 41 多为 Go 系新工具(apt 可装,正是缺失标注的
  设计场景)。全仓 337 项在真 Linux 335 过 2 败(即上述两项已修根因),
  Linux PTY EIO-EOF 分支首次在真实 Linux 全绿。详见两份 dev log 的
  「补测」节。
- 2026-08-22:**WP-07 关闭**——parse 增强库(`tools/parse.py`:
  解析器注册表 + `maybe_parse` 单入口,**增强而非门槛**——注册表
  未命中静默走 WP-01 通用路径(不记审计),解析失败记
  `parse_fallback` debug 审计、绝不抛给 LLM;6 解析器:nmap
  XML/grepable/文本三格式(grepable 补录无开放端口存活主机、
  rDNS 回填主机名)、sqlmap(stdout 注入确认 + loot CSV 登记与
  口令列提 cred)、gobuster/nikto(SSL Info 剔除、Target IP 定
  facts 归属)/hydra(连字符模块)/whatweb;产出 summary ≤500B
  (LLM 视图,secret 掩码)+ facts 经 `apply_facts` 喂 WP-06 索引
  (cred 完整值落盘,报告可见)。ultracode 对抗审查确认 20 项全
  修(38 项测试全绿);二次复审子代理配额 403 未启动,主会话
  三项变异抽查补位。**接线点**(后续 WP):`maybe_parse(cmd,
  output, output_path=…, audit=…)` 返回 None 走通用截断视图,
  否则 summary 给 LLM、facts 经 `apply_facts(index, …)` 进索引——
  挂上 loop 命令结果钩子即接上 prompts.py「自动入库由解析层
  后续版本提供」的占位。详见 `docs/dev-logs/WP-07.md`。
- 2026-08-22:**WP-09 关闭**——TUI(`tui/`:迎宾屏纯呼号门[scope/backend
  走 CLI 参数,空呼号拒入;呼号三去向:engagement.json `operator` +
  operator_interject 审计载荷 + `~/.foam/config.json` 预填] → 主界面
  [叙述流:折叠思考块/工具卡紧凑流+六类异常自展开/ENGAGEMENT.md 阶段
  分隔条;侧栏:阶段/索引/token 预算条/jobs/sessions(<110 列自动隐藏,
  F2 唤出);双通道控制面:插话 + `/` 七命令补全,Ctrl-X 二次确认 kill、
  Ctrl-P 暂停;无 `!` shell 前缀])。`foam tui` 按 WP-10 约定接
  `foam.tui.app:main(args)`,cli 零改动;思考流走新增的
  ReasoningDelta 链路上屏,审计只记 sha256+chars。观感自查(对照
  strix/Claude Code 逐屏文字描述)与 textual 踩坑 11 条见
  `docs/dev-logs/WP-09.md`;**M2 门已触发,门口动作待执行**。
- 2026-08-24:**WP-09 更正当落地——loop 常驻待命(idle-wake 连续
  对话)**。M2 门口裁决否掉「终态后输入被丢弃」:loop 增
  `wait_on_finish`(默认 False,headless 语义不变;TUI 经
  `TUIConfig` 默认 True),终答后置 `idle` 待命、阻塞在既有插话
  队列,插话唤醒续段;rounds/token 累计延续,`max_rounds` 按待命
  段计;待命不写 run_finished,kill 走既有清理面;engagement.json
  objective 永远首条消息。顶栏加「待命」,终态「run 已结束」提示
  去重。声明/验收/语义定案见 `docs/dev-logs/WP-09.md` 更正当节;
  WP-04 既有 24 项测试零改动通过,全仓 378+2 skip。
- 2026-08-25:**WP-11 关闭**——e2e 场景一(容器靶场 Web 全链) +
  parse 接线落地。任务一:loop.py 声明改动,run_command 终态挂
  `maybe_parse` 钩子——命中换 LLM 视图为解析摘要、facts 经
  `apply_facts` 入索引(终态才解析、≤1MiB 读落盘全文、无 index
  只换视图);prompts.py 占位句退役(六家解析器自动入库如实描述);
  `tools/state.py` +3 行只读 `index` property、`tui/app.py` +1 行
  接线(均声明,全仓测试零影响)。任务二实弹:Juice Shop @
  127.0.0.1:3000,`foam run` K3 一次启动到底,18 轮 5m57s,token
  317,641/13,095,零人工零插话;登录绕过 + UNION 注入实际利用,
  Users 表 23 行 dump 与 PoC 两档 loot 登记可核,审计链 replay
  校验通过,报告入库 `docs/e2e/scenario1-report.md`。**未达标如实
  收录**(M3 输入,见「下一 WP」):索引 hosts/ports/creds/vulns=0、
  sqlmap 未选用、claim-correction 总结误触发 4 次。详见
  `docs/dev-logs/WP-11.md`。
- 2026-08-26:**WP-12 关闭**——e2e 场景二(Metasploitable2 容器 +
  msfconsole 交互拿 shell,Kali 实弹,Mac 经 SSH 协调)。`foam run`
  k3-256k 一次启动到底:29 轮 6m33.7s,token 290,166/5,227,零人工
  零插话;nmap 全端口(25 口,解析层自动入库 hosts 1/ports 25——
  WP-11 的索引空表缺口未复现)→ 模型**自选** UnrealIRCd 后门(非
  剧本首选 vsftpd)→ 持久 PTY 驱动 msfconsole use/set×4/exploit
  **一击成功** → root shell 内 id/uname 取证 → 转录落 loot 并登记,
  审计链 replay 49 条完整。结构化提示识别生产实证:真实转录字节
  离线复演 12 命中(含 6.4.84 无版本号 `msf >`,陷阱 16 再坐实)。
  顺手核销:修正版 msf/dpkg 两测试 pytest 形态 Kali 复跑 2 passed
  (回填 WP-05/WP-08 补测节)。**未达标如实收录**(M3 输入):会话
  操作不入审计链、提示事件不落盘、loot 登记尺寸快照语义、工具盘点
  漂移 93/137、护栏把笔记里版本号误识别为越界 IP 的新误报形态(2 次
  fail-closed,模型改写自救)。详见 `docs/dev-logs/WP-12.md`。
  **M3 门随之触发,门口动作待总指挥执行**。
- 2026-08-27:**WP-13 关闭**——总体整合 + 发布准备(最后一个 WP,
  关闭即触发 M4)。13 份规格 63 条验收条款逐条核销
  (`docs/spec-verification.md`:✅62 + 🟡1[WP-03 其余后端无凭据
  未实测,v1 并案] + ❌0;M3 挂账 9 条全部落位条款旁注;M1–M3
  门口记录齐全核对通过);双场景 replay 复核 56/49 条双 exit 0,
  与 M3 复验一致;全新环境安装实测:Kali rolling arm64 干净目录
  pipx 装 0.0.1(--help/fm/双场景 replay/真实后端冒烟全过,冒烟
  经已安装包直调后端,reply 与 reasoning 流正常)+ Mac 干净 clone
  venv 对照组(代理 env 摘除后装通;系统 py3.9 被 `requires-python`
  版本地板正确拒装);密钥扫描当前树 + 全 29 commit 历史零命中
  (3 处 TESTONLY 合成 fixture 豁免);品牌占位复核:许可两处 +
  元记录 5 处,README 2 处随终版重写收口——README 终版零品牌串,
  首行命名纪律等价声明(旧「代号可改」声明的等价表述);演示材料
  `docs/demo/`(操作记录文本 walkthrough + 场景二报告现生成);
  已知问题总表 `docs/known-issues.md`(M3 挂账 9 + 在册 3 +
  新发现 2);v1 立项清单 14 项按 P0–P3 排入下方「v1 立项清单」节。
  **补记:仓库现路径为 `~/Desktop/foam`(陷阱 15 所记
  `~/Documents/foam` 已过时,append-only 不动原条目)。**
  **M4 门随之触发,门口动作待总指挥执行**。
- 2026-08-27:**命名纪律退役**(非 WP 动作,总指挥指示)——定名 Foam
  即最终:AGENTS.md §0 修订为「命名」并附历史注记,README 去声明、
  直书 Foam;下述陷阱 1 同步废止。历史文档(WP 规格/开发日志/核销表)
  中的「本项目」等旧表述为彼时真实记录,不强制回改。

## 下一 WP

**WP-13 已关闭(2026-08-27);M4 门同日通过(见「里程碑门」)——
13/13 WP 全部收口,M1–M4 全放行,项目发布就绪。**v1 立项清单 14 项
P0–P3 在下方待命,开闸与否总指挥随时可裁;M3 挂账 9 条原始候选表述
保留于下备查。
- M4 门口三裁决已定论(2026-08-27):sqlmap 演示项(挂账⑨)→ v1-P3
  不挡发布;会话审计 kind(挂账④)与 loot 登记语义(挂账⑥)随 v1
  清单 P0-2/P1-6 立项即定论;v1 阶段开闸与否不影响放行,后续随时。
- (以下 9 条为 M3 挂账原始候选表述,2026-08-26 门口移交,
  **2026-08-27 已全部并入「v1 立项清单」节**,保留备查;原表述:
  已知问题 8 条 + sqlmap 演示项,属候选非规格——WP-13 若动验收
  口径须走更正当):
  ① creds/vulns 仅经解析 facts 入库,state 工具面无 add_vuln/
  add_cred——手工成果无处登记(场景一索引四表空的主因;场景二
  同缺口但无需凭证);② claim-correction 启发式对「总结历史动作」
  稳定误触发(场景一 4 次、场景二 1 次;场景二的误报促成真实二次
  核验),候选方向:豁免无新动作声明的总结段;③ 模型自截断输出
  (`| tail -20`)使解析器 no_match(场景二未复现)——prompts 可引导
  「扫描类命令保持完整输出」;④ **PTY 会话操作(session_open/send/
  read/list)不入审计链**,replay 时间线在纯会话阶段只剩 LLM 交换
  元记录——会话审计 kind 是否补,门口裁决;⑤ 结构化提示事件
  (events/matched)只喂模型不落盘(CLI 渲染亦无 prompt_type)——
  验收引用要靠运行日志+转录+离线复演补强;⑥ loot 索引登记尺寸为
  登记时刻快照(终态文件可被后续重拷撑大),语义待门口定夺;⑦
  **护栏目标提取把版本号(`4.7p1`/`3.2.8.1`)误判为越界 IP**
  (场景二 heredoc 笔记两次 fail-closed)——WP-02 提取器新误报形态;
  ⑧ ENGAGEMENT.md「进展」占位文案与 loop.py:172 注释口径不一
  (WP-06 模板 nit);⑨ **sqlmap 类交互向导工具实弹零覆盖**(场景一
  模型用 curl 手工完成注入;交互向导类 PTY 适配目前仅 msfconsole
  一个生产样本)——M3 挂账演示项:WP-13 演示阶段补一场 sqlmap
  友好靶场实弹(objective 不指定工具,观察自选)。
- **Kali 实机补测已于 2026-08-22 核销**;msf/dpkg 两测试 pytest 形态
  复跑已于 2026-08-26 核销(WP-12 顺手项,2 passed)。

## v1 立项清单(2026-08-27 WP-13 编排;**2026-09-08 v0.1.0 封包合并处置**,总指挥拍板)

> 来源:WP-13 规格点名 5 项 + M3 挂账 9 条 + 各 WP 遗留在册项,合并去重。
> **2026-09-08 处置口径**:v0.1.0 封包时整体重排为两条线——
> **v0.1.x 维护批**(实弹反复证实、低成本的审计/核验缺口,共 8 项)
> 与 **v0.2 波次**(平台级能力,共 9 项);原 14 项编号保留备查,
> Meow 实弹(2026-09-08)4 项清单外新发现并入。原优先级口径:
> P0=安全与审计底线;P1=登记面与正确性;P2=平台能力;P3=演示与维护。
> **(2026-09-11 订正:原误记 10 项,算术口径 18-1=17=维护批 8+v0.2 9)**

### v0.1.x 维护批(实弹证实,逐项成本 ≤1 WP)

1. **会话操作审计 kind + 结构化提示事件落盘**(原 P0-2,挂账④⑤)——
   第三次实弹证实(WP-12 msfconsole、Meow telnet 两形态;Meow 28 事件中
   会话 7 调用零记录)。**维护批首选**。
2. **`foam verify <engagement>` 子命令**(Meow 新发现③)——审计核验
   免手搓,结项顺手跑;verify 逻辑现成,纯 CLI 接线。
3. **结项标准证据页**(Meow 新发现④,与原 P1-6 loot 语义并案)——
   run finished 时自动产出一页:loot 索引 + sha256 + verify 结果。
4. **网络探测命令自重超时引导**(Meow 新发现①)——工具描述引导
   `-w`/超时参数,或输出层「首字节后静默 N 秒早终」选项。
5. **护栏目标提取器改进**(原 P0-3,挂账⑦)——版本号误报根治 +
   误判案例台账常态化。
6. **claim-correction 启发式豁免总结段**(原 P1-5,挂账②)——WP-11 4 次/
   WP-12 1 次误触发治理;Meow 15 轮零触发为阴性对照样本。
7. **prompts 引导「扫描类命令保持完整输出」**(原 P1-7,挂账③)——
   降低自截断致解析 no_match;不越「不内置 playbook」红线。
8. **state 工具面 add_vuln/add_cred 登记接口**(原 P1-4,挂账①)——
   手工成果入库,场景一索引四表空的主因修复。

### v0.2 波次(平台级能力,另行立项开闸)

9. nftables 网络级出口护栏(原 P0-1,规格点名)——v0 参数级护栏绕过面根治。
10. 多后端 failover(原 P2-8)+ Claude/DeepSeek/GLM/OpenRouter 实测补足。
11. 报告模板化(原 P2-9,含 PDF/HTML 导出)。
12. meterpreter 语义层(原 P2-10,通道已通)。
13. 跨 engagement 经验库(原 P2-11,远期)。
14. headless 监督面探针(Meow 新发现②:`foam status <engagement>` 或
    engagement.json 心跳字段)。
15. sqlmap 类交互向导实弹演示(原 P3-12,挂账⑨)——与战绩表下一行合并执行。
16. 工具目录新鲜度机制(原 P3-13)——96/137→93/137 漂移再校准。
17. TUI `!` shell 前缀(原 P3-14)——须过护栏,不破审计。

## WP 依赖速查

```
WP-01 ──┬─ WP-04 ──┬─ WP-08 ── WP-11(场景一)
WP-02 ──┤          ├─ WP-09(TUI)
WP-03 ──┘          └─ WP-10(CLI 闭环)
WP-05(会话)── WP-12(场景二)
WP-06 ── WP-07(parse)
WP-13(整合)依赖全部
```

## 里程碑门(2026-08-21 挂牌;WP 制不变,门口纪律见台账同名节)

- **M1 = WP-04 关闭**:**已通过(2026-08-21)**——演示补跑(真实 K3,
  finished/6 轮/审计链完整/幻觉纠正真实触发一次/零越界零泄漏,证据
  见 `docs/dev-logs/WP-04.md`「补跑」节)+ 方向复评结论:**放行**。
  WP-08/09/10 开闸(WP-07 此前已解锁)。
- **M2 = WP-09+10 关闭**:**已通过(2026-08-25)**——门口更正当「loop
  常驻待命」落地并过监理复核(连续对话,commit 4c19e02);总指挥实机
  演示(k3-256k:idle-wake 两轮插话、思考块折叠、紧凑工具卡、首事件
  重试可见)观感打分通过(设计+响应速度)+ 方向复评结论:**放行**。
  WP-11/12 开闸(WP-12 需 Kali 环境)。
- **M3 = WP-11+12 关闭**:**已通过(2026-08-26)**——双场景实弹俱闭并经
  监理独立复验(场景一 56 条/场景二 49 条审计链 replay 均 exit 0,
  loot/索引/算术逐项重算一致);对照题复评:1+1≫2 成立(全库工具
  自选实证:场景一 ffuf 自荐、场景二 UnrealIRCd 四选一决策 +
  msfconsole 持久 PTY 全链交互生产实证),「全库工具真被用上?」
  以两场景 ~11 种工具如实记录;总指挥裁决:**放行**,WP-13 开闸。
  复评挂账(已知问题 8 条 + sqlmap 类交互向导工具实弹未覆盖)随
  WP-13 候选清单带走,不改 WP-13 既有验收口径。
- **M4 = WP-13 关闭**:**已通过(2026-08-27)**——发布评审:WP-13 验收
  五条经监理独立复验全过(双场景 replay 56/49 双 exit 0、Kali pipx +
  Mac venv 双平台安装实测、发布 checklist 11 项、密钥扫描当前树+全
  29 commit 历史零命中、383+2 与 ruff 复跑一致;63 条规格
  ✅62+🟡1+❌0)。门口三裁决定论(总指挥拍板):① sqlmap 演示项→
  v1-P3,不挡发布;② 会话审计 kind(挂账④)与 loot 登记语义(挂账⑥)
  随 v1 清单 P0-2/P1-6 立项,即算定论;③ v1 阶段开闸与否不影响放行,
  后续随时可开。结论:**放行**——13/13 WP 全部收口,项目发布就绪。
门口产出三选一:放行 / 规格更正当 / 砍后续 WP;不开新坑;波次中途
不受理方向争论。

## 已知陷阱

1. **品牌名禁令**:**已于 2026-08-27 退役**(总指挥指示:定名 Foam 即
   最终,见 AGENTS.md §0 与「当前状态」同日条目)。原条文存档:写代码/
   文档时不得出现品牌字符串——违者后续改名时逐处返工(纪律在改名中
   验证过价值;历史文档的旧表述不回改)。
2. **运行时产物别入库**:engagements/ 已被 .gitignore 挡住;提交前
   `git status` 自查。
3. **WP-03 实测任务**:Kimi K3 对渗透类 prompt 的审核容忍度与 JSON 纪律
   是实测项,被拦就如实记录,**不改写 prompt 去规避审核**。
4. **共享 .venv 的 editable install 在并行开发时会被踩坏**(`import
   foam` 突然失败):先查 `.venv` 状态,`PYTHONPATH=src` 可绕过;
   pyproject 已配 `pythonpath = ["src"]`(pytest)与 tests 目录 S101 豁免。
   另:本机 pip 走 SOCKS 代理但缺 `pysocks`,联网安装会失败。
5. **护栏语义细节**(WP-02):URL 前缀与 CIDR 是「或」关系——要端口级细
   粒度,scope 里就不能有更宽的 CIDR;`*.example.com` 不匹配裸域;CIDR
   目标必须 `subnet_of` scope 网段。完整绕过面见 `docs/dev-logs/WP-02.md`。
6. **裸 python 脚本要手动 `PYTHONPATH=src`**(陷阱 4 同源):pytest 靠
   pyproject `pythonpath=["src"]` 免配置,但直接 `.venv/bin/python` 跑
   临时脚本时 editable .pth 可能不生效。另:ruff ASYNC230/240 已对
   `tests/**` 豁免(测试内小文件阻塞读是有意的),源码目录不豁免——
   WP-05 复用 `tools/output.py` 时保持同步原子写,别在协程里加阻塞调用。
7. **.pth 失效的根因(WP-03 查明)**:sandbox 写出的文件带 macOS
   `UF_HIDDEN` 旗标,Homebrew 补丁版 site.py **跳过 hidden .pth**;
   `chflags nohidden <pth>` 可修,但任何人重装 editable 会复发——别修
   了,直接用陷阱 6 的 `PYTHONPATH=src`。另:httpx 走 socks5 代理需
   `socksio`(本机 .venv 已装,环境工具非项目依赖)。
8. **noqa 后不能跟括号说明文字**(WP-02/WP-06 各踩一次):`# noqa: Sxxx(理由)`
   被 ruff 判非法指令,理由须写成上方独立注释。S105/S106 还会误伤**名字
   含 secret 的变量/键名**(如 `secret_note` 键)——测试目录已豁免,源码
   目录起名避开。SQL 白名单拼接(表名/列名常量化、值参数化)触 S608 时
   用 noqa 并注明依据。
9. **PTY 三坑**(WP-05):① 子进程光 setsid 不够,要 `ioctl(0, TIOCSCTTY)`
   拿控制终端,否则 ssh 读 `/dev/tty` 拿不到密码提示;② PTY EOF 在
   Linux 报 EIO、macOS 报空读,两种都要按 EOF 处理;③ 「被杀」与
   「自然退出」要靠 closing 旗标区分——收割协程先醒,直接标 exited 会
   把被杀的会话标错。另:async 等待循环里 `event.clear()` 必须先于读
   数据,否则丢唤醒傻等到超时。
10. **护栏测试里的引号坑**(WP-04):`echo "recon 127.0.0.1"` 经 shlex
    分词后 `recon 127.0.0.1` 是**一个词元**,护栏正确地提取不到目标——
    写护栏相关用例先想词元边界,目标要裸写(`echo recon 127.0.0.1`)。
11. **压缩/预算测试先算后写**(WP-04):`estimate_tokens` 是字符数/4;
    keep_recent 默认 6 条会把小对话几乎全保护(无可压对象导致假失败)——
    构造超限用例时显式传小窗口,并按总字符数/4 精确定预算,别拍脑袋。
    另:ruff E501 对字符串内长行同样生效,长快照文本拆拼接串(noqa 在
    字符串里会变成内容,无效)。
12. **noqa 要挂在诊断锚定行**(陷阱 8 变体,WP-08 踩):同一调用
    `subprocess.run(["dpkg", "-l"], …)` 的 S603 锚在调用行、S607 锚在
    参数列表行——合写 `# noqa: S603 S607` 在调用行盖不住 S607,须拆成
    两行各挂,理由注释仍按陷阱 8 写在上方独立行。另:ruff format 不是
    本仓门槛(已入库文件过半与 format 规范有出入),对齐 `ruff check`
    即可,别跑 format 制造风格孤岛。
13. **zsh 管道退出码**(WP-10 踩):`cmd | tail; echo $?` 打到的是 tail 的
    退出码——zsh 用 `$pipestatus`(下标 1 起),bash 的 `${PIPESTATUS[0]}`
    在 zsh 里是空串。抄录命令退出码当证据前先想这层;另 zsh 里裸
    `echo ====` 会被当命令解析,分隔线用 `echo ---`。
14. **篡改类测试先证「真篡改了」**(WP-10 踩):`str.replace` 目标串不
    存在时是静默空操作——拿「篡改后 replay 报断点」当证据前,先断言
    `not verify(...)`,否则可能录下一条链仍完整的假证据。
15. **仓库已搬家**:`~/Documents/kali-code` → `~/Documents/foam`
    (2026-08-21/22 之交,随定名 Foam)。旧路径是孤儿目录,内有并行
    会话的零星写入,**勿在旧路径提交任何东西**;所有会话确认 pwd 再
    动手。(补记 2026-08-22:现 `kali-code` 已改为指向 `foam` 的符号
    链接,旧路径落笔实际进活仓;唯一工作路径仍一律用 `foam`。)
16. **交互工具提示符跨版本漂移**(WP-05 Kali 补测踩):metasploit 6.4.84
    把 `msf6 >` 改回 `msf >`——测试的 wait_pattern/断言别写死版本号
    字面量,用与 PROMPT_PATTERNS 同款的代兼容写法(`msf[56]?`);
    harness 正则库当年就写对了,是测试自己写死了。
17. **解析器头行过滤前缀要带冒号精确化**(WP-07 踩):skip 前缀
    `+ Target` 会把同族有效行 `+ Target Port:` 一并吞掉,端口解析
    静默全丢——凡是「跳过某些头行」的过滤器,前缀精确到字段分隔符
    (`+ Target IP:`),并给同族有效行配回归测试。另:`urlsplit()`
    不校验端口,`SplitResult.port` 惰性求值、访问时才抛 ValueError,
    try 块要包到属性访问而非只包构造。
18. **textual 组件命名先 grep 框架源码**(WP-09 连踩三处):`Widget.name`
    是只读 property(赋值即 AttributeError);`MessagePump._running` 是
    泵状态字段(自定义同名标志在挂载时被覆写,spinner 失控);
    `Widget._render()` 是框架取 Visual 的内部方法(自定义同名「重绘」
    返回 None 直接渲染崩溃)。另:`await switch_screen()` 写在被换下
    屏幕自己的消息处理器里会自死锁(走 `app.run_worker`);焦点在
    Input 时 ctrl+x/c/p 被 cut/copy/命令面板遮蔽,安全类快捷键必须
    `priority=True`。完整 11 条见 `docs/dev-logs/WP-09.md`「textual
    踩坑」。
19. **待命/初始同名字典值:等待迁移序列,不等瞬时值**(WP-09 更正当):
    loop 构造初始 `_status` 本就叫 `"idle"`,idle-wake 待命态按规格
    也叫 `"idle"`——`wait_for(loop.status == "idle")` 在 run 启动前
    即命中,断言打在 loop 跑起来之前。等 `observer.on_status` 的
    迁移序列(如 `["running", "idle"]`)或加业务守卫(`_rounds >= 1
    and status == "idle"`)。凡给状态机新增与既有值同名的状态,检查
    所有「等待某状态」的调用点是否其实想等「迁移到某状态」。
20. **shell 拼后缀多字节符号会粘进变量名**(WP-11 踩):`"$t✓"` 被
    POSIX 解析成变量 `t✓`(`set -u` 下直接 fatal)——拼接一律
    `${t}…`。同族:本机 `ALL_PROXY` 指向死代理时 agent 的 curl 全军
    覆没而 LLM API 恰可直连——跑 e2e 的环境处理见
    `docs/e2e/scenario1-setup.md`「代理坑」。
21. **macOS 自带 rsync 是 openrsync,缺省目标=cwd,会删家目录**
    (2026-08-26 协调层操作事故):同步命令里 `'--exclude=X' /path/src`
    的空格被粘贴吞掉 → 本地源路径粘进 exclude,只剩一个远程参数当源;
    GNU rsync 缺目标只列文件,**openrsync 缺目标默认 DEST=当前目录**,
    `--delete` 把家目录当镜像目标删了 39.2 万条(已在 /tmp 实测复现)。
    教训(给用户/agent 的任何 rsync 命令都按此办):① 源/目标用变量
    分行写并加源标记闸门(如 `[ -f "$SRC/pyproject.toml" ]`);② 永远
    先 `-n` 演习,删除清单人工过目再实传;③ `--delete` 与缺省路径
    行为的组合是雷区。
    补记(同日第二次踩,零损失):**zsh 在赋值语句里会展开冒号后的 `~`**
    ——`DST=doma@host:~/foam/` 被本地展开成 `doma@host:/Users/an/foam/`
    (zshexpn:赋值词中 `:`/`=` 后的 ~ 做 tilde expansion),远端收到
    错误的绝对路径。命令行内联写法不展开,一进变量赋值就展开。远端
    路径一律写绝对路径(`doma@host:/home/doma/foam/`)或对 ~ 加引号。
22. **docker 两坑(WP-12 踩)**:① 镜像 CMD 以交互 shell 收尾时(如
    `sh -c "services.sh && bash"`)裸 `docker run -d` 无 TTY/STDIN,
    bash 即退、容器 `Exited (0)` 假死——日志里服务明明全起来了;
    必须 `-dit`(ms2 靶场实测,见 `docs/e2e/scenario2-setup.md`)。
    ② docker CLI 对无响应 daemon **无限阻塞**(macOS 开发机实测探针
    卡死)——自动化/探针里一律给上界(`timeout 15 docker`;macOS 无
    timeout(1),脚本先判 `command -v timeout` 再决定包不包)。
23. **zsh 的 env 落点是 `~/.zshenv`,且折行会酿事故**(WP-12 踩):
    非交互 SSH 远端命令(`ssh host 'cmd'`)不读 bashrc/profile,但
    zsh 对所有 shell 形态都 source `~/.zshenv`——跨机注入 env 只认
    它。回填时若编辑器/粘贴把长行硬折行:孤儿的 `export ` 行会在
    source 时**打印全部导出变量**(污染每次 SSH 输出,含敏感变量名
    值),带前导空格的 `  FOO=bar` 静默不生效。改 zshenv 用行号手术
    或整体重写,改完 `ssh host 'env | grep -c FOAM'` 类只数不印值
    的方式验证。

## 当前状态(2026-09-04 协调层记录两条,总指挥拍板)

1. **Kali 凭据边界放宽(2026-08-31 拍板)**:允许 Kali 侧配置 GitHub read-only deploy key(仅 foam 单仓、禁 write、禁 PAT/账号级 token),Kali 本地 agent 可自助 `git pull` + `pipx install --force .` 更新;落地形态:~/foam-dev = deploy key 克隆,~/update-foam.sh 一键更新;~/foam(rsync 镜像)退役,闸门版 rsync 保留为无凭据后备通道。其余纪律不变(密钥只走 env、不给其他机器 SSH 凭据)。
2. **基准评测搁置(2026-09-04 拍板)**:CyberGym-E2E / ExploitBench 因成本(amd64 云机 + token + 工期)放弃;战绩表走全本地免费路线——存量 Juice Shop(WP-11)+ MS2(WP-12)两行,补跑 sqlmap 场(顺带销 v1-P3)+ 全库盲选场;第三方判分缺口由对比臂(同模型裸 CLI vs Foam)+ 证据层(审计链+回放)+ 可复现发布(靶场 compose/objective/产出全公开)补。演示叙事主轴 =「LLM 与 Kali 工具库有机结合」,审计回放定位为证据层。
   **(2026-09-11 注记:「靶场 compose」至今未兑现——仓内无任何 compose 文件,实际复现形态为 `docs/e2e/scenario1-setup.md`/`docs/e2e/scenario2-setup.md` 的 docker run 记录,当前复现路径以该两份 setup 文档为准;compose 补产或正式修订口径留待后续拍板。)**

## 当前状态(2026-09-08 v0.1.0 封包收官,总指挥拍板)

- **战绩表第 3 行**:HTB Starting Point「Meow」实弹交付经监理独立复验
  通过(telnet root 空密码 → uid=0 flag;15 轮/审计窗 8m53s/token
  102052+2398;28 事件哈希链经 Kali pipx 安装体 `verify()` 复核 True;
  零插话零纠正;P0-2 会话审计断档第三次实弹证实;交付方自曝 4 项清单外
  新发现)。报告+截图入库 `docs/demo/htb-meow-20260908/`(公开版 IP/flag
  脱敏),汇总表 `docs/track-record.md` 新建。
- **v0.1.0 封包**:版本号 0.0.1→0.1.0;`website/` 散件(站点脚手架,
  零引用)移出仓库至 `~/Desktop/foam-website-staging`;v1 立项清单 14 项
  +Meow 新发现 4 项合并处置为 **v0.1.x 维护批(8 项)** 与 **v0.2 波次
  (9 项)**,原编号保留备查;README 状态节刷新。**封包后仓库转公开**。
  **(2026-09-11 订正:原误记 10 项,算术口径 18-1=17=维护批 8+v0.2 9)**
- **下一动作**:v0.1.x 维护批开闸随时(首选 = 会话审计 kind,维护批
  第 1 项);战绩表下一行候选 = Appointment(SQLi,现 VPN 零成本)或
  sqlmap 场(v0.2 第 15 项合并执行)。
