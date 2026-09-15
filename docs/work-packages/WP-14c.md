# WP-14c:TUI 确认仪式与 scope 热换(确认权在 operator,执行权在代码)

状态:pending|依赖:WP-14a(基座)关闭——消费其契约四件(compile_scope/
ScopeCompilation/ScopeCompileError/freeze_scope)、scope_event_payload、
render_canonical_rules、update_scope_section、audit 三新 kind 常量、
replay 归一化与 interesting 集(scope_updated);与 WP-14b/14d 并行(阶段 2),
四片中最后落地并收口文档

> 总纲 `docs/work-packages/WP-14.md`(426 行,2026-09-16 定稿)的切片;
> 冲突以总纲「设计定案」节为准,本文引用定案编号(D1-D13/Q1-Q9)。
> 剂量分级(总指挥 2026-09-16):护栏热换面 T1 满配对抗审查,其余 T2。

## 目标

- **NL 确认仪式(TUI)**:不给 `--scope` 时首条消息承载 objective+NL
  scope(定案 Q5)→ 仪式 worker 两段结构(编译 → 确认卡 → 冻结,完成后
  才调既有 `start_run`,其同步方法体一字不动,定案 D9);engagement 在
  首条消息到达即建(scope_path=None,定案 D8);operator 确认 / NL 修正
  重编译 / 取消三分支,确认后冻结(复用 14a `freeze_scope` 唯一入口)。
- **`/scope` 命令**:裸命令=只读展示当前 canonical 规则/来源/sha256 短
  哈希(数据源为 TUI 侧权威引用 `TUIConfig.scope`,定案 D3/D10);带参=
  NL 热换——同一仪式实现(无第二套流程,Q5),确认后 `replace_scope`
  原子换(定案 D2)+ 审计 `scope_updated`(payload 契约 D13)。
- **file 流零仪式回归**:`--scope` 文件流行为逐字节不变(唯一有意变更:
  链上 `scope_loaded` 之后补一条 `scope_confirmed(source="file")`,
  定案 Q8,经 14a `scope_event_payload` 单源构造 payload、在 `start_run`
  返回后 append;payload 语义对齐 14b W14b-2)。
- **文档收口**:README scope 段改写(NL 入口为主)、AGENTS.md 差异化
  锚点段补一句、HANDOVER append 当前状态节、wp-ledger 四片终态登记。

## 排除项

- `cli.py`(`tui --scope` 改可选向归属片提一致性请求,见文末)、
  `replay.py`、`prompts.py`、`refusal.py`、`scope.py`、`audit.py`、
  `files.py`、`scope_compiler.py`——本片只消费其契约,不注册不定义。
- 编译器实现与 round-trip 门禁(总纲验收 1/2,归 14a);headless
  `--scope-text`(14b);拒答检测与授权段改写(14d);resume 双来源
  对账(14b)。
- ENGAGEMENT.md 动态段 markers 定义与写入助手实现(14a;本片逐字消费
  `<!-- foam:scope:begin -->`/`<!-- foam:scope:end -->` 做断言)。
- 自由文本意图识别改 scope(定案 Q1:只走显式 `/scope`);file 流
  未启动时的 NL 改 scope(拒绝并指引,见下);Web UI 仪式。

## 涉及文件(本片拥有)

### `src/foam/agent/loop.py`(WP-03 已关闭文件,声明级最小新增)

- 操作员控制面段(`kill()` 之后,loop.py:484 后)新增:

  ```python
  def replace_scope(self, scope: Scope) -> None:
      """原子换护栏 scope(定案 D2):frozen dataclass 一次引用赋值,
      asyncio 单线程无撕裂,下一条命令即生效;不重建 system prompt
      (Q3),不动会话/jobs/索引。终态拒绝:run 已收尾不可再授权。"""
      if self._status in ("finished", "killed", "error"):
          raise RuntimeError("run 已终态,不可更换 scope(D2)")
      self._scope = scope
  ```

  唯一消费点 `check_command(command, self._scope, ...)`(loop.py:759)
  零改——引用赋值对它天然原子。
- **不加任何公开 scope 读取面**(定案 D10):无 property、无 getter;
  TUI 读取面一律走 `TUIConfig.scope`。
- 本片在 loop.py 仅此一处;拒答检测挂载(14d)在 `_collect_round`
  尾部,两片互不引用对方改动。

### `src/foam/tui/app.py`(WP-09/10 已关闭文件)

- `TUIConfig.scope`(app.py:147)改 `Scope | None`;docstring 补:None
  =NL 仪式流,冻结后赋值、`scope_source` 置 scope.confirmed 绝对路径;
  `/scope` 确认后同步更新(D9/D10)。file 流照旧非 None。
- `WelcomeInfo`(app.py:313-323)加 `scope_declared: bool = True`;
  `WelcomeScreen.compose`(app.py:337-343)无 scope 分支渲染单行
  「scope 待声明(主界面确认)」(规则计数与 sha 占位「—」),file 流
  渲染逐字节不变;`on_mount`(app.py:786-799)按 `config.scope is None`
  组装占位;`_scope_sha`(app.py:801-806)None 时返回「—」。
- `submit_text`(app.py:826-854)首条消息分支改造:
  - 仪式进行中(见下守卫字段)再发普通文本 → 提示「scope 确认仪式
    进行中,请先完成确认卡」并忽略(worker 单例守卫,D9,与
    `start_run` 单 run 守卫同构)。
  - `config.scope is None`(NL 流):objective 回显后启动
    `run_worker(self._scope_ceremony(text, mode="startup"))`,不再直接
    调 `start_run`。
  - file 流:`start_run(text)` 照旧;返回后若 `self._audit` 就绪,经
    14a `scope_event_payload` 构造 payload 后 append
    `scope_confirmed(source="file")`(Q8;链序 `scope_loaded` →
    `scope_confirmed`;payload 语义对齐 14b W14b-2)。
- 新增 `_scope_ceremony(text, *, mode)` 协程(mode ∈
  `startup`/`predeclare`/`update`,三路共用同一仪式实现,Q5):
  1. **engagement 获取(D8)**:startup/predeclare 以当前文本 derive id
     ——`(root/"engagement.json")` 存在走 `Engagement.open`(绕过
     create 的 objective 冲突检查,files.py:128-141),不存在才
     `Engagement.create(objective=text, scope_path=None)`;update 用
     `self.engagement`/`self._audit`(运行中链条)。worker 自开
     `AuditLog`(重开续链,WP-02 契约),`finally` 关闭;不污染
     `self._audit`(update 除外,直接用运行中句柄)。
  2. **编译循环**:调 14a `compile_scope(…, audit=<本 worker 的 AuditLog>)`
     (复用 `config.backend` 同一实例,D5);**每次调用**(含修正、失败
     路径)由编译器经 `audit` 形参现场落 `llm_exchange_meta`(哈希+token
     不记全文,D7)——本片不重复 append;挂 `ScopeConfirmCard` 并 await
     operator 动作 future;`correct` → corrections 累积重编译、卡重渲染;
     `confirm` → 冻结;`cancel` → 提示「已取消;重发首条消息可重新
     声明」收工(loop 不启动/不动)。`compile_attempts` 计每次调用。
  3. **冻结与两段结构(D9)**:confirm 后 `freeze_scope(...)`(14a
     唯一入口;startup/predeclare 发 `scope_confirmed`,update 传
     `old_sha256` 发 `scope_updated`,payload 契约 D13)→
     `config.scope`/`config.scope_source` 赋值(D10)→ startup 才调
     `start_run(text)`(幂等复开同参目录:freeze 已把 objective/
     scope meta 写齐,D9 前提钉死);update 依次
     `loop.replace_scope(compilation.scope)` → 通知块留痕(新规则
     计数+短哈希);predeclare 不启动 loop,提示「scope 已冻结,发送
     首条消息启动 run」。
  - 守卫字段:`TuiApp.__init__` 增 `self._ceremony`(worker 引用)与
    `self._ceremony_action`(asyncio.Future|None);卡动作经
    `MainScreen.on_scope_card_action` 回填 future。
- `execute_command`(app.py:521-550)增 `/scope`:
  - 裸:`_show_scope()`——canonical 逐行(14a 渲染助手)+ 计数 +
    来源 + canonical sha256 短哈希 12 位(数据源 `config.scope`,
    D10;None → 引导「首条消息或 /scope <描述> 启动确认仪式」)。
  - 带参状态机:仪式中 → 拒(worker 单例);`run_handle` 非 None 且
    `active_loop` None → 「run 已结束,scope 不可更改」(D2);run
    活动 → `mode="update"`;未启动 + scope None → `mode="predeclare"`;
    未启动 + file 流 → 拒并指引「scope 已由 --scope 指定;改用 NL
    声明请不带 --scope 重启」。
- `_HELP_TEXT`(app.py:109-122)增 `/scope` 行(查看/热换两义),
  `SLASH_COMMANDS`(widgets.py:632-640)同步进补全。
- `start_run`(app.py:858-899)**方法体一字不动**(D9)。
- `main(args)`(app.py:967-1003):`args.scope` 为 None 时跳过
  `load_scope`,`TUIConfig(scope=None, scope_source="")`;给定时
  逐字节照旧(配合 cli.py:307 改可选,归属片改动)。

### `src/foam/tui/widgets.py`(WP-09/10 已关闭文件)

- 新增 `ScopeConfirmCard`(启动与 `/scope` 共用同一实现):
  - 展示:canonical 规则逐行(`markup=False`)+ 计数 + canonical
    sha256 短哈希 + 来源(NL 编译);**空 rules 醒目文案「(空——任何
    网络目标都会被拒)」**(定案 Q9,文字+CSS 双通道)。
  - 三操作:确认 / NL 修正(卡内输入框 + 重编译钮;修正意见只进编译
    上下文,**不经过主输入坞**,D4 隔离天然成立)/ 取消;编译中按钮
    禁用并示「编译中…」。
  - `ScopeCardAction` Message(action ∈ confirm/correct/cancel +
    correction 文本);`update_compilation(compilation, attempts)` 重
    渲染并清空修正框;关闭后由主界面留通知块摘要。
- `SLASH_COMMANDS` 增 `("/scope", "查看/修改授权 scope(确认仪式)")`。

### `tests/test_tui.py`

复用 `ScriptedBackend`(编译应答脚本排在 loop 应答之前,时序确定)与
`make_config` 的 `scope=None` 变体;新增用例按下方验收条目逐条对应
(函数名自取,日志实录)。loop 级 `replace_scope` 终态 raise 单测同放
本文件(既有 loop 级用例先例:test_loop_idle_wake 等)。

### 文档四件(本片收口,边界契约第 7 条)

- `README.md`(快速开始 56-72 行区):scope 步骤改写——NL 入口为主
  (`foam tui` 不带 `--scope`:首条消息自然语言声明目标与范围 → 确认
  卡展示 canonical 规则+sha256 → 确认/修正/取消 → 冻结进审计链;
  `/scope` 中途查看与修改);scope 文件降为 headless/CI 可选
  (`--scope my.scope` 零仪式照旧;`--scope-text` 一句带过);法律与
  边界段不动;命令速览表 `tui` 行最小补注。
- `AGENTS.md`(差异化锚点段 27-28 行):补一句「NL scope 编译(自然
  语言声明 → 编译为护栏规则 → operator 确认冻结)」——锚点不变:
  代码护栏;最小修订,不整段覆写。
- `docs/HANDOVER.md`:append「当前状态」节——WP-14 四片(A/B/C/D)
  终态汇总、本片要点、下一动作;只 append。
- `docs/wp-ledger.md`:append 本片行 + WP-14 四片合并终态注记
  (WP-14 关闭);只 append。

## 验收标准(编号沿用总纲,括号内为剂量级)

1. **验收 4(总纲):TUI 仪式三分支 pilot,对齐 D8/D9 复用策略(T2)**
   - [ ] 确认分支:首条消息到达即建 engagement(`meta["scope"]` 为
     None);确认后冻结完成才调 `start_run`(worker → start_run 两段
     结构);ENGAGEMENT.md 动态段内容 = canonical 规则(markers 逐字
     成对);engagement.json objective 与 ENGAGEMENT.md 目标行为冻结
     时文本;链序 `scope_confirmed` → `scope_loaded`(D9 注记)。
   - [ ] 修正分支:修正意见进 corrections 重编译,卡重渲染为新规则,
     `compile_attempts` 计数含每次调用。
   - [ ] 取消分支:不启动 loop(`run_handle` 仍 None);重发首条消息
     走 `Engagement.open` 复用(engagement.json 不重建:created_at
     不变;审计链 prev_hash 续写;重发文本不同亦不触发 create 的
     objective 冲突检查)。
   - [ ] worker 单例守卫:仪式中再发普通文本/带参 `/scope` 各一例,
     提示且忽略,worker 不重复启动。
   - [ ] 每次编译调用(含修正、取消、失败路径)落
     `llm_exchange_meta`,payload 只含哈希与 token(D7)。
2. **验收 5(总纲):/scope 热换全链(T1 满配对抗)**
   - [ ] 确认后 `loop.replace_scope` 生效:换前被护栏拒绝的命令换后
     放行一例;反向(换前放行换后拒绝)一例。
   - [ ] `scope_updated` payload 契约(D13):
     old_sha256/new_sha256/path(scope.confirmed 绝对路径)/
     cidrs/hosts/wildcards/url_prefixes 四键摘要/source/
     canonical_sha256 逐键断言。
   - [ ] ENGAGEMENT.md 动态段重写 = 新 canonical;engagement.json
     meta 同步(path+sha256);system prompt 不重建(对象同一性
     断言);会话/jobs/索引不动。
   - [ ] `TUIConfig.scope`/`scope_source` 同步更新(D10);裸 /scope
     展示新规则一例(以 TUI 侧权威引用为准)。
   - [ ] `summarize_recent_rounds` 简报可见本次 scope 变更(消费侧
     断言;interesting 集实现归 14a,对齐总纲验收 15)。
   - [ ] 终态(finished/killed/error)带参 `/scope` 拒绝并提示一例;
     `replace_scope` 终态直调 raise RuntimeError 一例(对抗断言)。
   - [ ] T1:护栏热换面(replace_scope、/scope 状态机、冻结写序消费)
     满配对抗审查 ≥2 轮,审查记录入开发日志。
3. **验收 6(总纲)的 TUI 半:file 流零仪式逐字节回归(T2)**
   - [ ] 既有 file 流 TUI 用例全绿;显式断言全程无 ScopeConfirmCard
     挂载一例。
   - [ ] file 流链上 `scope_loaded` 后有 `scope_confirmed
     (source="file")` 一例(Q8 有意变更,快照断言更新入日志声明)。
   - [ ] file 流裸 /scope 展示一例;未启动时带参 /scope 拒绝并指引
     一例。
4. **验收 12(总纲):D4 隔离断言(T1,随验收 5 一并对抗)**
   - [ ] /scope 全流程后检查主环 `loop.messages` 全序列:NL 修正原文
     与编译对话内容(编译 system prompt 片段、编译应答 JSON)零出现;
     动态段内容 = 确认后 canonical。
5. **验收 11(总纲):日志与文档(T2/T3)**
   - [ ] 开发日志 `docs/dev-logs/WP-14c.md` 记录真实 pytest 输出;
     对 WP-03/09/10 已关闭文件的改动逐条声明(WP-09 Q6 先例)。
   - [ ] 文档四件(README/AGENTS.md/HANDOVER/wp-ledger)按上文要点
     落地。

## 向他片的一致性请求(落地前须对齐)

1. →14a:`freeze_scope` 内部完成 ENGAGEMENT.md 动态段重写(NL 冻结与
   /scope 更新两写入点经同一入口覆盖,D6);markers 逐字
   `<!-- foam:scope:begin -->`/`<!-- foam:scope:end -->`。
2. →14a(**已承接**,2026-09-16 跨片对账):D7 编译审计由 14a
   `compile_scope` 的 `audit` 关键字形参现场落 `llm_exchange_meta`(含
   失败路径);本片 worker 传入自有 AuditLog、不重复 append,
   `ScopeCompilation`/`ScopeCompileError` 无需携带 llm meta。
3. →14a(**已承接**,2026-09-16 跨片对账):file 流
   `scope_confirmed(source="file")` 由调用方以 14a `scope_event_payload`
   单源构造 payload 后 append(headless 走 14b `_append_file_scope_confirm`,
   TUI file 流走本片 `submit_text`;`start_run` 方法体不动,Q8);payload
   语义对齐 14b W14b-2(path=as-given 原串、canonical_sha256=文件字节
   sha256)。
4. →14a:canonical 渲染助手(Scope → 每行一条、保持顺序、无注释;
   scope.py 最小新增,总纲涉及文件节已预留),裸 /scope 展示消费。
5. →cli.py 归属片(14b):`tui --scope` 由 required=True 改
   可选(cli.py:307);本片 `app.py:main` 已按 None 容错。
6. →14a/14b:登记 audit kind(scope_confirmed/scope_updated)与
   `summarize_recent_rounds` interesting 集含 `scope_updated`(总纲
   验收 15);本片只消费不注册。14d 在 loop.py 的拒答挂载与本片
   `replace_scope` 无重叠,无请求。
