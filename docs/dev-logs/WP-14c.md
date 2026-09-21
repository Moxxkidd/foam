# WP-14c 开发日志:TUI 确认仪式与 scope 热换

> 落地日期:2026-09-20(实施跨 2026-09-18..20)。执行:WP-14c 实施会话。
> 事实源:docs/work-packages/WP-14c.md + docs/work-packages/WP-14.md
> 「设计定案」节(D1-D14,冲突以定案为准)。剂量:T2(片内定案评审即终);
> T1 面(护栏热换:replace_scope、/scope 状态机、冻结写序消费)满配对抗
> 审查两轮,记录见「评审记录」节。文件所有权:WP-14c.md「涉及文件」节
> 授权的 src/foam/tui/{app,widgets}.py、styles.tcss、loop.py 单点、
> tests/test_tui.py、README/AGENTS.md/docs 四件——之外一字未动
> (cli.py 归 14b,全程未碰;14b 已先行关闭并入 main,本片工作树直接
> 落在其 merge commit ec6a98b 之上,两片文件零交叠)。

## 结果一览

| 验收条款(WP-14c.md 编号) | 结论 |
|---|---|
| 1. 验收 4:仪式三分支 pilot(D8/D9 复用) | ✅ `test_scope_ceremony_confirm_branch` / `_correct_recompiles` / `_cancel_then_resend_reuses_engagement`;单例守卫 `test_scope_ceremony_singleton_guard`;D7 编译审计每次调用落 llm_exchange_meta(含失败/取消路径,`test_scope_ceremony_compile_failure_then_correct_recovers` 链序断言) |
| 2. 验收 5:/scope 热换全链(T1) | ✅ 放行反转 `test_scope_hot_swap_allows_previously_denied`(D13 逐键+对象同一性+meta 同步+裸 /scope+简报可见);收窄反转 `test_scope_hot_swap_denies_previously_allowed`;终态拒绝 `test_scope_command_rejected_states` + `test_replace_scope_terminal_states_raise`(对抗直调);T1 两轮对抗审查见「评审记录」 |
| 3. 验收 6 TUI 半:file 流零仪式逐字节 | ✅ `test_file_flow_zero_ceremony_and_scope_confirmed`(全程无卡、编译调用数 0、Q8 补写与 W14b-2 payload 逐键);既有 file 流用例全绿;裸/带参 /scope 两例入 `test_scope_command_rejected_states` |
| 4. 验收 12:D4 隔离 | ✅ 热换测试末段:`loop.messages` 全序列无 NL 修正原文/编译 system prompt 片段/编译应答 JSON;动态段 = 确认后 canonical |
| 5. 验收 11:日志与文档 | ✅ 本日志(真实 pytest 输出见「验收实录」)+ README scope 节重写 + AGENTS.md 一句锚点 + HANDOVER/wp-ledger append;已关闭文件改动逐条声明见「交付物」 |

测试实录见文末「验收实录」。

## 交付物(逐文件声明)

`src/foam/agent/loop.py`(WP-04 已关闭文件,规格授权单点,+12 行):

- `AgentLoop.replace_scope`(D2):frozen dataclass 一次引用赋值原子换
  (asyncio 单线程无撕裂),终态(finished/killed/error)raise
  RuntimeError;docstring 明记 D10——不加公开 scope 读取面(无
  property/getter),执行面私有状态只能经本方法原子换。其余一字未动。

`src/foam/tui/widgets.py`(WP-09 已关闭文件,规格授权):

- `ScopeCardAction(Message)`:卡动作消息(action/correction 两字段),
  经 message bubbling 上浮,`MainScreen.on_scope_card_action` 命名约定
  接收。
- `ScopeConfirmCard(Vertical)`:三状态(compiling/error/ok)单卡复用;
  `_ready` mount 时序模式(textual 8.2.8:`_redraw` 仅在 ready 后触达
  子件);`set_compiling`/`update_compilation`/`update_error`;
  confirm 键 disabled 态由编译中/错误态/无产物三路收拢(卡侧保证
  confirm 只在有合法产物时发出);修正为空时 hint 不发动作;Q9 空规则
  「(空——任何网络目标都会被拒)」text+CSS(`scope-empty` class)
  双通道。
- `NarrativeView.mount_scope_card`:叙述流挂载点。
- `SLASH_COMMANDS` +`("/scope", "查看/修改授权 scope(确认仪式)")`
  (7→8 项,既有 popup 测试断言更新,见「Q8 有意变更声明」)。

`src/foam/tui/styles.tcss`:`#scopecard` 卡片样式(cyan 边框)、
`#scope-card-body.scope-empty`(Q9 醒目)、`.scope-error`、按钮行与
`#scope-correction`。

`src/foam/tui/app.py`(WP-09/10 已关闭文件,规格授权,主战场):

- `TUIConfig.scope: Scope | None`(原 `Scope`):None = NL 仪式流
  (D9/D10 注记);`WelcomeInfo.scope_declared` 驱动迎宾屏
  「scope 待声明(主界面确认) · 规则 — · sha256:—」;file 流迎宾
  行 f-string 逐字节保持。
- `MainScreen`:`/scope` 分派(裸→`_show_scope` 只读展示:canonical
  逐行+计数+来源+sha256 短哈希,数据源 TUIConfig.scope,D3/D10;哈希
  口径与链上/迎宾屏/meta 对齐,见评审 #7;带参→`_request_scope_change`
  状态机:仪式中→拒;run 终态→「run 已结束,scope 不可更改(D2)」;
  活动 run→update;未启动+未声明或已 NL 冻结→predeclare;file 流未
  启动→拒并指引)。
- `TuiApp` 仪式面:`start_scope_ceremony`(单例守卫 D9;含 eager worker
  完结防护,评审 G 修复)→ `_scope_ceremony`(engagement 获取 D8 →
  编译循环 → 冻结 → 两段结构 D9;update 用运行中共享审计句柄,
  startup/predeclare 自开 AuditLog 并在 start_run 前关闭续链;
  worker 自捕一切异常上屏,run_worker 默认 exit_on_error 不炸 app);
  编译循环含 update 仪式 run 终态化的 ValueError 收口(评审 #3/#5);
  `_await_card_action`/`resolve_scope_card_action`(asyncio.Future
  回填,done-守卫)。
- `_ceremony_engagement`:D8 取消-重发复用(`engagement.json` 存在走
  `Engagement.open` 绕过 create 的 objective 冲突检查;否则
  `create(objective=text, scope_path=None)`);predeclare 加
  `scope-predeclare-` 前缀(评审 C 修复)。
- `submit_text`:仪式守卫(普通文本提示并忽略,D9)→ scope None 走
  startup 仪式 → NL 冻结先 `_prepare_nl_run_engagement` 再
  `start_run`(评审 #0/#2)→ file 流 `start_run` 后
  `_append_file_scope_confirm`(Q8)。
- `_prepare_nl_run_engagement`(评审 #0/#2 修复,两段结构 D9 的预声明
  变体):run 目录不存在→按当前冻结 scope 创建+写动态段(loop 首轮
  上下文即含规则,生产 eager 调度下亦然);已存在→meta.scope 对账为
  当前冻结 scope(漂移在 run 链上落 scope_updated/scope_confirmed
  留痕)+动态段重写;之后 start_run 幂等复开同参通过。
- `_append_file_scope_confirm`(Q8):`scope_event_payload` 单源构造,
  W14b-2 语义(path=as-given、canonical_sha256=文件字节 sha256 取
  engagement meta,免 TOCTOU);NL 冻结来源跳过(评审 B);共享句柄已关
  时重开链补写(评审 #1 极端形态)。
- `main(args)`:`args.scope is None` → `scope=None, scope_source=""`,
  跳过 load_scope;给定则逐字节照旧。
- **声明**:本片 import 了 `foam.state.files` 的下划线私有
  `_default_engagement_id`——D8「以当前文本 derive id」的取消-重发
  复用语义要求与 `Engagement.create` 内部派生逐字同一函数,files.py
  未提供公开导出;若后续 WP 将其改公开,本片应跟进切换。

`tests/test_tui.py`:既有用例语义保持 + popup 断言 7→8(见下节声明)
+ 新增 24 例——首交付 13 例(三分支/单例守卫/编译失败恢复/Q9 空规则/
热换双向/预声明/拒绝状态/file 流零仪式/迎宾与裸命令/loop 级终态对抗)
+ 第一轮评审回归 3 例(update 仪式中 run 终态化/纯中文预声明无冲突/
file 源热换哈希谱系)+ 第二轮评审回归 8 例(跨 session 对账/首轮上下文
契约/编译在途终态化/已关句柄重开/file 流 sha 口径/Q9 展示/重新声明/
eager 守卫)+ nl_sha256 断言加固(评审 I)+ file 流 Q8 docstring 加注
生产 eager 位次差异(评审 #11)。

`README.md`:快速开始重写为 NL 仪式主流(`foam tui` 首条消息声明 →
确认卡三分支;`/scope` 查看/热换);scope 文件降为 headless/CI 可选
路径(`--scope` / `--scope-text` 并提);命令速览表 tui 行注记。

`AGENTS.md`:差异化锚点段增一句「NL scope 编译:自然语言声明 → 编译
为护栏规则 → operator 确认冻结(确认权在 operator,执行权在代码)」。

## Q8 有意变更声明(例外条款,逐条)

规格「file 流零仪式逐字节回归」的例外=Q8 审计补写,波及的测试断言
逐条声明:

1. `test_slash_commands_and_completion_popup`:popup 条目数断言 7→8
   (新增 /scope 条目为规格要求的命令面变更,注释标注)。
2. file 流链上 kinds 序列:`scope_loaded` 之后有
   `scope_confirmed(source="file")`(新例
   `test_file_flow_zero_ceremony_and_scope_confirmed` 显式断言位次与
   payload;既有 file 流用例不依赖 kinds 位次,零改动通过)。
   **第二轮评审裁定注记**:规格钉「之后有」;测试环境 kinds[1] 相邻
   位次是 run_test 不设 eager_task_factory 的确定性时序,生产 eager
   下 run_started 可先落链——位次不属规格契约(评审 #1/#4/#11)。

## 片内定案 W14c-1..4(评审即终)

- **W14c-1**:`config.scope_source` 在冻结后一律取
  `engagement.metadata()["scope"]["path"]`(freeze 刚落盘的 meta,
  单源):macOS `/var`→`/private/var` 符号链接下,`update_scope_metadata`
  resolve 过的路径才与 start_run 幂等复开时 create 的冲突检查口径
  一致;另起第二处路径推导必然漂移。
- **W14c-2**:未启动 + 已 NL 冻结(predeclare 完成)时带参 /scope 允许
  再走预声明仪式(以 `_scope_frozen_via_nl` 来源旗标判别;file 流仍
  拒):run 未启动即无执行面,重新声明不触碰任何已授权运行,与「确认
  权在 operator」一致;旗标同时服务评审 B 的来源判别。
- **W14c-3**(第二轮评审 #2 修复带出的语义):NL 冻结后首条消息开跑
  时,若 run 目录已存在(同 objective 此前跑过旧 scope),先把其
  meta.scope 对账为当前冻结 scope 再 start_run——对账 = startup 仪式
  freeze_scope ② 写 meta 的同义动作;漂移在 run 链上留痕(旧值有
  sha256 → `scope_updated` old/new 键;旧值为空(曾取消的仪式目录)
  → `scope_confirmed(source="nl")` 指针记录),确认事实与 NL 出处键
  不重复(在仪式 engagement 链上,经 meta path 交叉索引)。
- **W14c-4**(第二轮评审 #1/#3/#4/#5 的处置口径):生产 eager 调度
  (textual run_async 在 Python≥3.12 设 eager_task_factory)下:
  (a)Q8 补写位次不钉相邻(见上节裁定注记);(b)共享审计句柄已被
  run 收尾关闭时,Q8 补写重开链落账(重开恢复尾序,单写者无竞态);
  (c)update 仪式编译在途时 run 终态化 → 编译落账 finally 在已关句柄
  炸 ValueError,按 D2 中文指引收口;该次编译的 D7 llm_exchange_meta
  记录随句柄关闭而缺(链本身完整可验;记录无法如实重建——哈希与
  token 随异常丢失,不合成假值),如实记为已知边界。

## 设计取舍

1. **仪式 worker 两段结构(D9)**:freeze 完成(含 config/旗标同步)
   后才调既有 `start_run`,其同步方法体一字不动——file 流与 NL 流在
   start_run 处合流,幂等复开同参目录(objective/scope meta 已由冻结
   写齐);代价是仪式期状态(卡、守卫字段、自有审计句柄)全部挂在
   app 侧,须 finally 全量收口。
2. **审计句柄分工**:update 直接用运行中共享句柄(D13 写序⑤落在
   同一条链;双开句柄会因各自缓存尾序而分叉哈希链,不可取);
   startup/predeclare 自开 AuditLog,关闭先于 start_run 的重开
   (seq/prev_hash 续链不断,`verify()` 跨重开通过——测试实证)。
3. **卡动作经 asyncio.Future 回填**:按钮 → ScopeCardAction bubbling
   → MainScreen → app.resolve → future.set_result;编译循环挂起在
   future 上,取消/修正/确认三分支在同一循环体,无回调地狱。
4. **Q9 空规则双通道**(text「(空——任何网络目标都会被拒)」+
   `scope-empty` CSS class):fail-closed 语义不让样式单点承担。
5. **D10 权威引用在 TUIConfig**:裸 /scope、`_show_scope`、热换后的
   同步全部以 `config.scope`/`config.scope_source` 为准,loop 侧无
   读取面;`replace_scope` 是唯一的执行面写入通道。

## 评审记录(T1 面满配对抗审查,两轮)

### 第一轮(2026-09-18,五维满配 + 逐发现对抗核实)

评审 workflow(脚本 `wp14c-adversarial-review-r1-wf_81383344-f62.js`):
5 视角 find(冻结写序/状态机/规格符合/测试充分性/textual 并发语义)
+ 逐发现对抗核实(T1 面 3 票、其余 2 票),规划 52 agents。执行中
kimi 后端配额 403 中断两次,经 journal.jsonl 恢复:17 条原始发现、
19 张有效核验票(28 张核验票死于配额,其发现由实施侧按同一对抗
标准裁定,标注于下)。

**确认 6 条,全部修复并配回归测试;驳回 1 条(F)。**

| # | 级别 | 票数 | 发现 | 修复 |
|---|---|---|---|---|
| A | blocker | 6/6 | update 仪式挂起等卡期间 run 终态化(kill/自然收尾)→ freeze_scope ①-④ 落盘后 ⑤ audit.append 在已关句柄炸 ValueError → 半冻结态:链上无 scope_updated,resume 静默采纳无审计 scope | 确认分支先复检 `active_loop`(D2),终态则不冻结、如实提示;复检与 freeze 同步体之间无 await,单线程原子。回归:`test_scope_update_ceremony_aborts_when_run_ends_mid_ceremony` |
| B | major | 3/3 | 预声明(NL 冻结)后首条消息走 file 分支 → run 链补写 `scope_confirmed(source="file")`,来源错标 | `_append_file_scope_confirm` 以 `_scope_frozen_via_nl` 门控跳过;确认事实留在仪式 engagement 链上(source="nl")。回归:预声明两例断言 run 链无 source="file" 记录 |
| C | major | 5/5+3/3 | 预声明 engagement objective=scope 文本,与首条消息派生同目录时 create 幂等复开 objective 冲突 → run 永远起不来(纯中文输入 slug 恒为 "engagement",必然相碰) | 预声明 derive id 加 `scope-predeclare-` 前缀,与 objective 派生目录隔命名空间;同文本→同目录复用(D8 初衷)不变。回归:`test_scope_predeclare_cjk_no_objective_conflict` |
| D | minor | 3/3 | file 源旧 scope 热换时 old_sha256 取 canonical 渲染哈希,与链上前条 source="file" 记录(文件字节哈希)口径不一 → 谱系断 | old_sha256 取 engagement meta sha256(NL 冻结物即 canonical 字节,恒等;file 流即文件字节,与链同口径)。回归:`test_scope_hot_swap_from_file_source_keeps_hash_lineage` |
| E | major | 2/2 | 开发日志/HANDOVER/wp-ledger 未落 | 本日志与四件文档(本节即记录) |
| G | major | 实物证据 | textual Python≥3.12 设 eager_task_factory(.venv textual/app.py:2282-2283;worker.py:401 create_task 经该工厂):仪式协程同步失败早退时在 run_worker 内同步跑完,finally 清守卫后已完成 worker 被赋回 `_ceremony` → 单例守卫永久锁死(核验票死于配额,实施侧以源码实证确认) | `start_scope_ceremony` 赋回前查 `worker.is_finished`,已完成则保持 None。回归:`test_scope_ceremony_eager_finished_worker_releases_guard`(打桩 run_worker 覆盖两分支) |
| I | minor | 实施侧裁定 | 测试对 nl_sha256 键零断言(D7/D13 NL 出处键,核验票死于配额) | confirm 分支与热换两例补 nl_sha256 逐值断言 |

**驳回 1 条**:F「update 仪式中守卫吞插话」——WP-14c 规格 submit_text
节明文「仪式进行中再发普通文本 → 提示并忽略」,未限定 startup 形态;
且 scope 变更中途让插话入队的授权时序反而含糊,阻塞是安全方向。

### 第二轮(2026-09-20,修复后终态复审)

评审 workflow `wp14c-adversarial-review-r2`(run wf_34aab201-e96):
4 视角 find(冻结写序/状态机/规格符合/测试充分性)+ 逐发现对抗核实
(T1 面 3 票、其余 2 票),41 agents 规划;kimi 配额中断致 9 张
test-adequacy 视角核验票未投出(该视角 4 条发现由实施侧按同一对抗
标准裁定)。14 条原始发现:**投票确认 7 条(6 条代码修复 + 1 条文档
缺口),投票不足/驳倒 7 条全部由实施侧裁定处置(6 条修复、1 条
处置)。**

| # | 级别 | 票数 | 发现 | 处置 |
|---|---|---|---|---|
| #0 | major | 3/3 | 生产 eager 调度下预声明路径首轮 LLM 上下文是「尚未冻结」占位:修复 H 的写段在 start_run 返回后,而 create_task 在生产 eager 下同步开跑,首轮 messages 已于此前读盘 | `_sync_run_scope_section` 废止,改 `_prepare_nl_run_engagement` 前置(start_run 前建目录+写段)。回归:`test_scope_predeclare_first_round_context_has_rules`(messages[1] 含规则、无占位的时序契约) |
| #1 | minor | 3/3 | file 流 Q8 链序在生产 eager 下变为 scope_loaded→run_started→scope_confirmed;非挂起后端下同根因升级为已关句柄 append 炸 ValueError 丢记录 | (a)位次:规格钉「之后有」不钉相邻,测试 docstring 加注、不作契约(见 W14c-4);(b)ValueError:重开链补写。回归:`test_file_scope_confirm_reopens_closed_audit` |
| #2 | major | 3/3 | 重复预声明(跨 session 换 scope)后同一 objective 永远起不了 run:create 幂等复开撞 scope 一致性检查,报错对 NL 用户无可行动指引 | `_prepare_nl_run_engagement` 对账 meta.scope 后再 start_run(W14c-3)。回归:`test_scope_redeclare_then_same_objective_reconciles_across_sessions`(跨 session 双 app) |
| #3 | minor | 3/3 | update 仪式编译在途期间 run 终态化 → compile_scope 落账 finally 在已关句柄炸 ValueError,裸内部异常上屏、D7 记录缺失 | 编译循环捕 ValueError:update+run 已终态 → D2 中文指引收口;D7 缺口如实记录(W14c-4c)。回归:`test_scope_update_compile_in_flight_when_run_ends`(闸门后端挂起编译) |
| #4 | major | 3/3 | 同 #1 链序错位(spec-conformance 视角重复发现) | 同 #1 处置 |
| #5 | major | 3/3 | #3 孪生面:终态化后点「按修正重编译」同炸(同一根因) | 与 #3 同一处 catch 覆盖 |
| #6 | minor | 1/3(投票不过半) | latent:同步完结后端 + eager → Q8 补写在已关句柄 append 逃逸 submit_text | 机制与 #1 极端形态相同(真后端网络 await 必挂起,生产不可达),防御性修复已随 #1 落地并有回归;实施侧裁定保留 |
| #7 | minor | 1/2(投票不过半) | 裸 /scope 的 file 流 sha 口径(canonical 渲染)与链上/迎宾屏/engagement meta(文件字节)不一致:同一「canonical sha256」标签两个值 | 实施侧裁定修复(实物证据:`_scope_sha` 用文件字节):`_show_scope` 取文件字节 sha256(W14b-2 同口径),OSError 回退渲染口径。回归:`test_bare_scope_file_flow_shows_file_bytes_sha` |
| #8 | minor | 2/2 | 验收 11 文档缺口(HANDOVER/wp-ledger/验收实录) | 本节即记录;四件文档随本片收尾落地 |
| #9 | minor | 0/2 | 交付树遗留 throwaway 复现文件 | 实施侧处置:`tests/test_tmp_repro_w14c.py`(自留核实件)与核验 agent 散件 `test_tmp_adv_*.py`/`test_tmp_verify_*.py` 全数删除;缺陷证据已转化为正式回归测试 |
| #10 | major | 0/1(票死于配额) | 修复 G(eager 守卫)零回归覆盖,且 run_test 不设 eager → 守卫锁死全体测试仍绿 | 实施侧裁定修复:打桩 run_worker 单测覆盖两分支(无需 eager 环境)。回归:`test_scope_ceremony_eager_finished_worker_releases_guard` |
| #11 | major | 0/0(票死于配额) | Q8 断言 kinds[1] 只钉住测试 harness 人造时序 | 实施侧裁定:规格原文为「之后有」非「相邻」;docstring 加注生产 eager 位次差异,断言保留(测试环境确定性) |
| #12 | minor | 0/0(票死于配额) | 「未启动+已 NL 冻结→重新声明」状态机分支无测试 | 实施侧裁定修复。回归:`test_scope_redeclare_after_predeclare`(两预声明分目录+新 scope 开跑) |
| #13 | minor | 0/0(票死于配额) | 裸 /scope 空规则 Q9 展示无测试 | 实施侧裁定修复。回归:`test_bare_scope_empty_rules_q9_display` |

两轮合计:确认/裁定修复 19 条(含文档 2 条),驳回 1 条,清理散件 1 类;
T1 面三个子面(replace_scope/状态机/冻结写序消费)均有确认级发现与
回归测试闭环。

## 已知边界(如实记录)

- **TUI file 流 ENGAGEMENT.md 动态段保持「scope 尚未冻结」占位**:
  本片钉死 start_run 一字不动 + file 流逐字节回归,动态段写入点只
  批给 headless(14b cli.py 两处)与 NL 流;护栏执行面不受影响
  (loop._scope 经 config 装配,判定正确),仅模型每轮所见的
  messages[1] 信息面缺当前规则。后续候选:小片统一 TUI file 流写段
  (一行 render+update,与 14b 同原语)。
- **生产 eager 调度下 file 流链序可为 scope_loaded→run_started→
  scope_confirmed**(评审 #1/#4):记录存在性与 payload 不受影响,
  `recover_scope_record` 取末条语义不变;规格钉「之后有」,位次
  差异如实记录。
- **update 仪式编译在途时 run 终态化的 D7 缺口**(评审 #3, W14c-4c):
  该次编译调用的 llm_exchange_meta 无法落账(句柄已被 run 收尾关闭,
  哈希/token 随异常丢失,不合成假值);链完整可验,仪式按 D2 收口。
- **预声明与 run 分属两个 engagement 目录**(D8 derive id 语义使然;
  run 的 meta.scope.path 指向预声明目录的 scope.confirmed,跨目录
  引用;resume 经 14b 双来源消费无碍,评审 C 前缀后两目录命名空间
  不再相碰;跨 session 重声明经 W14c-3 对账不再卡死)。
- **run 链上不补 NL 来源的 scope_confirmed**(评审 B 修复的反面,
  W14c-3 对账留痕除外):NL 预声明后开跑的 run 链只有 scope_loaded;
  确认事实在预声明 engagement 链上,经 meta path 可交叉索引。

## 验收实录

最终态(两轮评审修复全部落地后,2026-09-20 实测):

```
$ .venv/bin/python -m pytest tests/test_tui.py -q
..................................................                       [100%]
50 passed in 113.36s (0:01:53)

$ .venv/bin/python -m pytest tests/ -q
........................                                                 [100%]
526 passed, 2 skipped in 122.61s (0:02:02)

$ .venv/bin/python -m ruff check src/ tests/
All checks passed!
```

基线对照:本片落地前(14b merge 后)全仓 502 passed + 2 skipped
(2026-09-21 评估订正:原记「515+2」系首交付中间态,与下行
「中间态备查」自相矛盾;评估审计员实证,并在 ec6a98b 临时
worktree 复跑确认 502 passed + 2 skipped,与 WP-14b 台账关闭
记录「本片 502+2」一致);
本片新增 24 例、修改既有断言 1 处(popup 7→8,已声明),零回归。
中间态备查:首交付后 39 passed(test_tui)/515+2(全仓);第一轮
修复后 42/520+2;第二轮修复后 50/526+2(上录)。

## 2026-09-21 评估修复实录

WP-14 四片关闭后,总指挥组织七路评估(2026-09-21);本节如实
记录评估结论、本批修复与修复后实测。

### 评估结论摘要(七路)

- 全仓测试复跑:526 passed + 2 skipped 全绿(与「验收实录」
  上录一致)。
- WP-14a / WP-14b / WP-14d 三片:通过。
- 本片(WP-14c):**有条件通过**,条件 = 本批四项修复全部闭环。
- T1 面(护栏/热换)两条实锤确认:① PTY 会话命令无护栏检查点
  (既有洞,非 WP-14 引入;本批登记 known-issues ⑮,根治归
  v0.2 第 9 项 nftables 网络级出口护栏);② NL 编译产物的
  url_prefix 规则无内容校验——`parse_scope` 对该形态只过 scheme
  正则,注入串可逐字进 canonical 与 ENGAGEMENT.md 动态段(主环
  模型每轮必读);本批修复 1 闭环(代码面)。

### 本批修复(四项;1–3 代码面,4 文档面)

1. **url_prefix 闸门**(代码面):T1 实锤②闭环——编译器
   round-trip 门禁(Q2)增 url_prefix 字符级校验,拒绝空白字符/
   控制与格式字符(Unicode Cc/Cf)/尖括号的 url_prefix 规则,
   中文可行动报错;只收紧 NL 闸门,file 流逐字节兼容不动;
   回归测试见 tests/test_scope_compiler.py 新增用例。
2. **flaky 测试治理**(代码面):评估复跑中暴露的不稳定用例
   定点修复,见代码侧交付记录。
3. **过渡实参清理**(代码面):`build_system_prompt` 的 WP-14d
   过渡形参 `scope`/`source`/`loaded_at`(「旧调用方零适配」
   过渡形态)删除,定案 D11 终态落地,调用方(cli.py/loop.py)
   切到正式签名。
4. **known-issues 登记**(文档面,本节同批):docs/known-issues.md
   增 D 节——PTY 会话护栏缺失登记为 ⑮(已知问题④的姊妹项),
   并以低严重度附记两小项(engagement.json 经 `_write_metadata`
   裸写非原子,files.py:223;TUI file 流 scope 加载→哈希绑定
   TOCTOU 分钟级窗口,app.py:1500→1028-1034)。

同批文档面另订正本日志两处事实(与四项修复同批落地):基线对照
「515+2」订正为 502+2(见「验收实录」基线行订正注记);loop.py
归属「WP-09」订正为 WP-04(依 docs/wp-ledger.md 文件所有权)。

### 修复后全量实测

代码面三项落地、工作树稳定后,本文档面于 2026-09-21 复跑实测
(两次全量均 exit 0;末次复跑期间工作树内容零变动):

```
$ .venv/bin/python -m pytest -q
........................................................................ [ 53%]
........................................................................ [ 67%]
...................................................................ss... [ 80%]
........................................................................ [ 94%]
...............................                                          [100%]
533 passed, 2 skipped in 123.18s (0:02:03)
```

计数对账:533 = 526(「验收实录」终态)+ 8(url_prefix 闸门回归
5 函数 8 例:PoC 原串逐字 1 + 禁用字符变体 parametrize 4 + 换行
打闸门 1 + 裸标记片段 1 + 合法前缀放行 1;tests/test_scope_compiler.py)
− 1(过渡形参收缩移除 `test_build_system_prompt_legacy_call_form_
transitional`);flaky 治理为零计数稳定性修复(条件等待替固定
sleep,tests/test_tui.py 仍 50 例);2 skipped 为既有环境门控
(ssh localhost / msfconsole),前后一致。
