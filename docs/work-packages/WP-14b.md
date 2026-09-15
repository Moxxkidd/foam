# WP-14b:headless 双通道与 resume 对账(WP-14 切片 B)

状态:pending|依赖:WP-14a 关闭(编译器 `scope_compiler.py`、`freeze_scope`、
replay 归一化、audit 三新 kind 注册)|并行:WP-14c(阶段 2,互不引用对方改动;
本片不碰 loop.py/prompts.py/tui/*)|剂量:**T2**(正确性一轮评审,总指挥
2026-09-16 指示)

> 本片是总纲 docs/work-packages/WP-14.md(2026-09-16 定稿)的切片落地,
> 只覆盖 headless(`run`/`resume`)与 `tui` 入口的 argparse 放行;与总纲
> 冲突处以「设计定案」节为准(D1-D13/Q1-Q9)。铁律同总纲:确认权在
> operator,执行权在代码;headless 的确认动作 = 命令行显式写下授权
> (`--scope` 文件或 `--scope-text` NL,Q6)。

## 目标

- **run 双通道**:`--scope` 与 `--scope-text` 互斥组必给其一;`--scope-text`
  走编译(14a `compile_scope`)+ 自动冻结(14a `freeze_scope`),成功
  canonical 上屏 + `scope_confirmed(source="nl")` 审计;失败中文报错 +
  非零退出,无进程内重试(Q6)。
- **file 流补确认**:file 流装配时补写 `scope_confirmed(source="file")`
  审计记录(Q8:零仪式 ≠ 无审计;`scope_loaded` 之后、`run_started` 之前
  相邻落链),file 流其余行为逐字节回归。
- **tui --scope 放行使能**:argparse 面由 required 改可选;缺席的 NL 仪式
  流全归 14c,本片只放行、不实现、不测试该下行路径。
- **resume 双来源零适配对账**:`_resolve_scope`(cli.py:707-754)经 14a 的
  `recover_scope_record` 归一化消费 `scope_loaded`/`scope_confirmed`/
  `scope_updated` 三种 kind,**不新增分支**(D13);双来源对账正确性由本片
  测试锁定(验收 7/8)。
- **测试**:互斥组、`--scope-text` 成功/失败/空规则、file 流回归(含
  Q8 断言更新)、resume 双来源三例、删 engagement.json 纯链恢复逐键相等。

## 排除项

- tui/* 全部(NL 确认仪式、`ScopeConfirmCard`、`/scope` 命令归 14c);
  tui 不带 `--scope` 的下行行为由 14c 定义并测试。
- `loop.py`(14c/14d)、`prompts.py`(14d)、`replay.py`/`audit.py`/
  `files.py`/`scope_compiler.py`(14a)——本片只 import 使用,一字不改。
- 动态段 markers 定义与写入助手(14a,markers 逐字
  `<!-- foam:scope:begin -->`/`<!-- foam:scope:end -->`);D6 五写入点中
  落在 cli.py 的两点归属未在片约列出,见一致性请求 5。
- resume `--scope-text` 与 TUI `--scope-text`(总纲排除项);headless 中途
  改 scope(与现状一致零介入,总纲目标节)。
- 编译器自动重试/多后端 failover/流式编译(总纲排除项)。
- README/AGENTS.md/HANDOVER(归 14c);wp-ledger 落地时本片自登记一行
  (边界契约 7)。

## 涉及文件(本片拥有)

### `src/foam/cli.py`

1. **模块 docstring**(cli.py:1-43)增 WP-14b 段:run 双通道与
   `--scope-text` 编译冻结语义、file 流补写 `scope_confirmed`(Q8)、
   tui `--scope` 改可选(仪式归 14c)、resume 双来源零适配(D13);退出码
   表补一行「编译失败归 2(scope 输入前置条件,W14b-4)」。既有 docstring
   其余行不动。
2. **run 参数面**(cli.py:254):`--scope` 改为
   `add_mutually_exclusive_group(required=True)` 双选项——`--scope`(文件)
   与 `--scope-text`(metavar `NL`);`--scope-text` help 钉「自然语言授权
   声明,headless 非交互自动确认:编译 → canonical 上屏+落审计;编译失败
   中文报错+退出码 2,无进程内重试(Q6)」。两给/两缺均 argparse 自报
   退出码 2。
3. **import**:自 `foam.agent.scope_compiler` 引入 `compile_scope`/
   `freeze_scope`/`ScopeCompileError`(14a 模块,Q4);自 `foam.guard.audit`
   引入 `KIND_SCOPE_CONFIRMED` 常量(14a 注册,本片只引用,边界契约 2)。
4. **`_cmd_run` NL 分支**(cli.py:652-688 内新增,`args.scope_text is not
   None` 时),顺序钉死:
   `resolve_backend_args` → `backend_factory`+`_save_profile_if_requested`
   (ConfigError → 2,照旧)→ `_create_engagement(args)`(`args.scope=None`
   → `meta["scope"]=None`,files.py:184-193 允许,D8 同构:编译调用的
   `llm_exchange_meta` 有链可落)→ **W14b-1 拒绝检查** → 自建
   `AuditLog(engagement.paths.audit_jsonl)` →
   `await compile_scope(args.scope_text, backend, audit=audit)`(D5 复用
   同一后端实例;每次调用含失败路径落 `llm_exchange_meta`,D7;`audit`
   形参名以 14a 规格为准,一致性请求 1)→ `ScopeCompileError`:stderr
   中文 `[错误] scope 编译失败: <原因>` + audit/backend/engagement 关停 +
   **退出码 2**(W14b-4),无重试 →
   `freeze_scope(engagement, audit, compilation, source="nl",
   nl_text=args.scope_text)`(14a 唯一冻结入口,D13 写序:先
   `scope.confirmed` tmp+rename 后 `update_scope_metadata`;OSError →
   中文报错 + 退出码 1)→ 关自建 audit → **canonical 全文上屏**
   (`[scope]` 行 + 规则逐行;空 rules 附醒目行「(空——任何网络目标都会
   被拒)」,Q9)→ `_assemble_runtime(scope=compilation.scope,
   scope_source=<scope.confirmed 绝对路径,resolve 口径>)`(D13;一致性
   请求 4)→ `_drive` 照旧。链上时序:`llm_exchange_meta`(编译)→
   `scope_confirmed`(冻结)→ `scope_loaded`(装配),与 D9 时序注记同构。
5. **`_cmd_run` file 流分支**:`_assemble_runtime` 之后、`_drive` 之前调
   `_append_file_scope_confirm(runtime.audit, scope, str(args.scope))`
   (Q8;与 `scope_loaded` 相邻、`run_started` 之前)。
6. **新助手 `_append_file_scope_confirm(audit, scope, scope_source)`**:
   payload 经 14a `scope_event_payload` 单源构造、钉死(W14b-2)——`path=scope_source`(as-given 原串,与
   `scope_loaded.source`、engagement.json meta 同串)、`source="file"`、
   `canonical_sha256=scope 文件字节 sha256`(= meta sha256,冻结物=文件
   本体,Q8)、四键摘要=`scope.summary()`(D13 契约);append
   `KIND_SCOPE_CONFIRMED`。
7. **tui 参数**(cli.py:307):`--scope` 由 `required=True` 改可选
   (`default=None`),help 注「缺席进入 NL 确认仪式(WP-14c)」;
   `args.scope=None` 的下行处理全归 14c,`_cmd_tui` 其余逻辑零改。
8. **`_cmd_resume`**(cli.py:840-870):`args.scope` 显式覆盖时,装配后同样
   补 `_append_file_scope_confirm`(W14b-3:覆盖=命令行显式重新授权,
   Q8 同义);plain resume(恢复值)**不补**。
   `_resolve_scope`(cli.py:707-754)与 `_resume_preflight` 主体**零改**——
   双来源由 14a 归一化记录零适配消费:NL 流 meta 路径(719-731)对账
   `scope.confirmed` 字节 sha256 天然成立(freeze 写的就是它);链上回退
   (739-748)消费归一化记录的 `source`(=path)+四键摘要(D13)。
9. **声明零改**:`_create_engagement`(639-649,`args.scope=None` 时
   `scope_path=None` 自然成立)、`_assemble_runtime`(515-572,签名与行为
   不动;补写走调用方,保证 NL 流不重入)、`_drive`、replay/report 子命令。

### `tests/test_cli.py`

- **更新**(Q8 有意变更,开发日志逐条声明):既有 kinds 断言补
  `scope_confirmed` 位次;`test_resume_scope_drift_detected` 增覆盖 resume
  后确认记录计数 +1 与新文件 sha 断言;其余 file 流断言逐字节保持。
- **新增**:互斥组两例、`--scope-text` 成功/空规则/失败/同目录已冻结
  四例、file 流确认记录一例、resume 双来源三例、纯链恢复一例、tui
  argparse 放行一例、`run --help` 含 `--scope-text` 一例(明细见验收)。

## 设计定案引用与片内定案

引用总纲:D1(scope.confirmed 单文件)、D5(后端复用)、D7(编译审计)、
D8(engagement 即建,同构)、D9(时序注记)、D13(payload 契约与归一化
映射)、Q4(编译器归属)、Q6(headless 非交互自动确认)、Q8(file 流同写
`scope_confirmed`,回归边界:解析/护栏/meta/resume 语义不动,回退仅摘
补写记录)、Q9(空 rules 合法,fail-closed 方向)。

片内定案(T2 剂量,评审即终):

- **W14b-1 同目录已冻结 scope 拒绝**:NL 流 `_create_engagement` 后若
  `engagement.metadata()["scope"]` 非 None,stderr 中文「该 engagement
  目录已有冻结 scope;headless 无换 scope 通道,请换 --workdir 或另建
  engagement」+ 退出码 2。理由:LLM 编译有渲染非确定性,无法区分「同
  意图重渲」与「真换 scope」,静默覆盖等于无审计换授权;fail-closed
  方向,对齐 file 流参数冲突语义(files.py:136-141),代价=NL 流同目录
  幂等复跑不支持(file 流支持),回退=换 workdir。
- **W14b-2 file 流 payload 语义**:`path`/`canonical_sha256` 取原文件
  as-given 串与文件字节 sha256(不 resolve、不渲染 canonical)——file 流
  逐字节回归(验收 6)压倒 D13 的绝对路径注记(该注记为 NL 流 cwd
  无关性而设);resume 对账只消费四键摘要,本字段不进判定面。
- **W14b-3 补写时机**:`scope_confirmed(source="file")` 只在「本次命令行
  显式传 `--scope`」时补写(run file 流必给;resume 覆盖时);plain
  resume 不补——确认事实已在链上,重复补写只增噪音且会污染
  `recover_scope_record` 的取末条语义。
- **W14b-4 退出码**:编译失败(含后端错误包装)一律 2——operator 修正
  声明后重跑(Q6),与 file 流 scope 加载失败(cli.py:656-658)同码同
  语义线;freeze 落盘 OSError 归 1(写盘故障,非输入问题)。

## 验收标准(本片条目剂量级 **T2**,片内定案 W14b-1..4 评审即终)

1. **互斥组**(验收 7(总纲)前半):`run --scope F --scope-text T` →
   退出码 2 + stderr 互斥报错;两者皆缺 → 退出码 2;`run --help` 输出含
   `--scope-text`。
2. **`--scope-text` 成功**(验收 7(总纲)+ 验收 3(总纲)headless 实例
   + D7):fake 后端脚本化返回 `{"rules": [...]}` → rc 0;stdout 含
   canonical 规则逐行全文;审计链含 `scope_confirmed`,payload 契约
   (D13):`source="nl"`、`path`=scope.confirmed **绝对路径**、四键摘要
   与规则一致、`canonical_sha256` = scope.confirmed 落盘字节 sha256 =
   engagement.json `meta["scope"]["sha256"]`、`nl_sha256`/`nl_chars`/
   `compile_attempts` 三键在;编译的 `llm_exchange_meta` 先于
   `scope_confirmed`,`scope_confirmed` 先于 `scope_loaded`(D9 同构);
   哈希链 verify 通过。
3. **空 rules**(验收 7(总纲)关联 + Q9):编译产 `{"rules": []}` → rc 0,
   stdout 含「(空——任何网络目标都会被拒)」醒目行,`scope_confirmed`
   四键全空照常冻结。
4. **`--scope-text` 失败**(验收 7(总纲)后半 + D7 失败路径):fake 返回
   非 JSON → rc 2 + stderr 中文编译报错;无重试(编译调用次数 == 1,
   链上无 `run_started`);失败路径 `llm_exchange_meta` 仍在链;
   engagement.json `meta["scope"]` 为 None(未冻结,无半冻结态)。
5. **同目录已冻结拒绝**(W14b-1):file 流先跑一次,同 workdir 再以
   `--scope-text` 跑 → rc 2 + 中文指引;链上无 `scope_updated`、
   scope.confirmed 不存在(未发生静默换授权)。
6. **file 流回归 + 确认记录**(验收 6(总纲)CLI 半 + Q8):run file 流
   kinds[0]=`scope_loaded`、kinds[1]=`scope_confirmed`;payload 按
   W14b-2(path=as-given、source="file"、canonical_sha256=文件字节
   sha256=meta sha256、四键=`scope.summary()`);既有 test_cli.py 其余
   断言全绿(仅 Q8 相关 kinds 断言按总纲验收 6 例外条款更新,开发日志
   声明);`test_scope.py` 不动全绿。
7. **resume 双来源三例**(验收 8(总纲)):
   (a) NL engagement 经 engagement.json 对账恢复一例——`--scope-text`
   跑完后 plain resume → rc 0,resume 新落的 `scope_loaded` 四键与冻结时
   `scope_confirmed` 四键逐键相等,链 verify;
   (b) 链上只有 `scope_confirmed` 无 `scope_loaded` 一例——手工造链
   (Engagement.create(scope_path=None) + AuditLog 逐条 append
   `scope_confirmed`(D13 payload)+ `run_started`),删 engagement.json
   后 resume → rc 0,归一化记录零适配进 `_resolve_scope` 链上回退
   (cli.py:739-748);
   (c) file 流 resume 回归一例——既有 resume 测试套件全绿(plain resume
   后链上 `scope_confirmed` 计数不变,W14b-3;`--scope` 覆盖 resume 后
   计数 +1 且 sha 为新文件)。
8. **纯链恢复逐键相等**(验收 17(总纲)e2e 部分):NL engagement 删
   engagement.json → resume → rc 0(legacy 修复路径);恢复出的 Scope
   (以 resume 新落 `scope_loaded` 的 source 重载)与冻结时 **逐键相等**
   (cidrs/hosts/wildcards/url_prefixes + rules);归一化记录
   `source`=scope.confirmed 绝对路径、`origin="nl"`(D13 映射)。
9. **tui argparse 放行**(本片 tui 项,验收 6(总纲)关联):`tui` 不带
   `--scope`、无 base_url env → rc 2 且 stderr 为 `FOAM_LLM_BASE_URL`
   报错(证明已过 argparse 关到达后端预检,非 required 报错);带
   `--scope` 的既有 tui 入口测试不动全绿;不带 `--scope` 的 NL 仪式下行
   行为不断言(归 14c)。
10. **cli.py 两写入点**(总纲验收 13 相应两点,2026-09-16 协调层裁定归
    本片):file 流装配时、resume 对账完成时各经 14a 交付的
    render_scope_section + update_scope_section 落动态段——各一例:
    file 流 run 后 ENGAGEMENT.md markers 间内容 = 当次 scope 渲染、
    markers 外字节不变;resume 对账完成后 markers 间内容 = 恢复后
    scope 渲染(幂等重写)。
11. **日志**(验收 11(总纲)本片部分):开发日志记录真实 pytest 输出;
    Q8 有意变更(file 流链上多一条 `scope_confirmed`)与 W14b-1..4 逐条
    声明;wp-ledger 自登记本片。

## 一致性请求(向他片)

1. **→14a**:`compile_scope` 契约草图(总纲涉及文件节)未列 audit 通道,
   而 D7 要求 headless 编译调用(含失败路径)落 `llm_exchange_meta`——
   请钉死形参(建议 `audit` 关键字),并钉 `ScopeCompilation` 字段名
   (`canonical_text`/`scope`/`rules`)、`ScopeCompileError` 与
   `freeze_scope` 的导入面(`foam.agent.scope_compiler`)。
2. **→14a**:`recover_scope_record` 归一化输出键集请逐字确认:
   `source`(=`scope_confirmed`/`scope_updated` payload 的 `path`)、
   `origin`(=payload 的 `source`,file|nl)、四键摘要原样,
   `canonical_sha256` 是否携带;本片 `_resolve_scope` 只消费
   `source`+四键,零新分支(D13)。
3. **→14a**:`KIND_SCOPE_CONFIRMED` 常量名确认(audit.py 注册归 14a,
   本片只引用);`scope.confirmed` 文件名(D1)如 14a 出常量/路径助手,
   cli.py 引用之,否则本片按 D1 硬编码 `"scope.confirmed"` 并声明。
4. **→14a**:NL 流绝对路径口径对齐(D13)——`freeze_scope`/
   `update_scope_metadata` 写的 engagement.json meta path、`scope_confirmed`
   payload path、与本片 `_assemble_runtime` 的 `scope_source`(取
   `(engagement.paths.root / "scope.confirmed").resolve()`)三者须同串;
   若 14a 另钉 resolve 口径(如 symlinks),以 14a 为准本片跟随。
5. **→14a/14c(已裁定,2026-09-16 协调层)**:D6 五写入点中落在 cli.py
   的两点(file 流装配时、resume 对账完成时)**归本片**——cli.py 所有权
   本来在本片,一处一行调用(render_scope_section + update_scope_section,
   签名以 14a 交付为准)+ 各一例测试,承接总纲验收 13 相应两点。
6. **→14c**:TUI file 流装配(app.py:876 `scope_loaded` 一带)同样补
   `scope_confirmed(source="file")`,payload 语义按 W14b-2;tui `--scope`
   缺席的 argparse 放行本片已做,`None` 下行处理(仪式流/WelcomeInfo
   占位)全归 14c。
7. **→14d**:`build_system_prompt` 若随 D11 改签名(去 `source`/
   `loaded_at`),cli.py:538 调用点的适配责任请在 14d 规格写明(本片
   不动该调用;如需 14b 配合请在对账期提出)。
