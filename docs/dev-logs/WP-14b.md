# WP-14b 开发日志:headless 双通道与 resume 对账

> 落地日期:2026-09-18。执行:WP-14b 实施会话。事实源:
> docs/work-packages/WP-14b.md + docs/work-packages/WP-14.md「设计定案」节
> (D1-D14,冲突以定案为准)。剂量:T2(一轮评审,片内定案 W14b-1..4
> 评审即终)。文件所有权:src/foam/cli.py、tests/test_cli.py(之外一字未动)。

## 结果一览

| 验收条款 | 结论 |
|---|---|
| 1. 互斥组(两给/两缺 rc 2 + run --help 含 --scope-text) | ✅ `test_run_scope_mutex_group` + `test_help_all_subcommands` 追加断言 |
| 2. --scope-text 成功(canonical 上屏+payload 逐键+链序+verify) | ✅ `test_run_scope_text_success` |
| 3. 空 rules(Q9) | ✅ `test_run_scope_text_empty_rules`(醒目行+四键空+空文件 sha) |
| 4. 编译失败 rc 2 无重试、meta 无半冻结 | ✅ `test_run_scope_text_compile_failure_no_retry` |
| 5. 同目录已冻结拒绝(W14b-1) | ✅ `test_run_scope_text_refuses_already_frozen`(拒绝先于任何 LLM 调用) |
| 6. file 流回归 + scope_confirmed 位次与 payload(W14b-2) | ✅ `test_run_file_flow_appends_scope_confirmed` + 既有例 kinds 断言补位 |
| 7. resume 双来源三例(meta 路径/纯链回退/plain 不补 + 覆盖 +1) | ✅ `test_resume_nl_engagement_via_metadata`/`test_resume_chain_only_scope_confirmed`/既有两例更新 |
| 8. 纯链恢复逐键相等 + D13 归一化映射 | ✅ `test_resume_pure_chain_recovery_scope_equal` |
| 9. tui --scope 缺席过 argparse 关 | ✅ `test_tui_without_scope_passes_argparse` |
| 10. cli.py 两写入点(markers 间=渲染输出、file 流 markers 外逐字节不变) | ✅ `test_file_flow_run_writes_scope_section`/`test_resume_rewrites_scope_section` |
| 11. 开发日志 + wp-ledger 自登记 | ✅ 本日志 + 台账 WP-14b 行与关闭记录 |

测试实录见文末「验收实录」。

## 交付物

`src/foam/cli.py`(全部改动):

- 模块 docstring 增 WP-14b 段(双通道语义/Q8 补写/tui 放行/resume 零适配/
  两写入点);退出码表补「编译失败归 2(W14b-4)、freeze 落盘 OSError 归 1」。
- run 参数面:`--scope`/`--scope-text` 互斥组 `required=True`
  (`--scope-text` metavar `NL`,help 钉 Q6 非交互自动确认语义)。
- import:`compile_scope`/`freeze_scope`/`ScopeCompileError`/
  `scope_event_payload`(14a)、`KIND_SCOPE_CONFIRMED`(14a 注册,本片
  只引用)、`render_scope_section`(14d)。
- `_cmd_run`:`args.scope_text is not None` 时转 `_cmd_run_nl`;file 流
  逐字节保持,仅在 `_assemble_runtime` 后、`_drive` 前增两行——
  `_append_file_scope_confirm`(Q8)+ `_write_scope_section`(D6 写入点①)。
- `_cmd_run_nl`(新增):顺序按规格钉死——resolve_backend_args(共用入口
  已先跑)→ backend_factory+`_save_profile_if_requested`(ConfigError→2
  照旧)→ `_create_engagement`(args.scope=None → meta["scope"]=None)→
  **W14b-1 已冻结拒绝**(先于任何 LLM 调用与审计写入)→ 自建 AuditLog →
  `compile_scope`(D7 llm_exchange_meta 由编译器现场落,本侧不重复)→
  ScopeCompileError→中文报错+三方关停+rc 2 无重试 → `freeze_scope`
  (OSError→rc 1)→ 关自建 audit → canonical 全文上屏(`[scope]` 行+规则
  逐行;空 rules 附 Q9 醒目行)→ `_assemble_runtime(scope=compilation.
  scope, scope_source=scope.confirmed resolve 绝对路径)` → `_drive`。
  链序:llm_exchange_meta → scope_confirmed → scope_loaded(D9 同构)。
- `_append_file_scope_confirm`(新增):payload 经 14a `scope_event_payload`
  单源构造(W14b-2:path=as-given 原串、canonical_sha256=scope 文件字节
  sha256、四键=scope.summary())。
- `_write_scope_section`(新增):D6 两写入点共用——render_scope_section
  (唯一渲染来源)+ update_scope_section(唯一写入助手)各一行;
  sha256=scope 文件字节 sha256,frozen_at=写入时刻(信息面,对账权威
  在审计链;file 流无冻结时刻可取,写入时刻是唯一自洽语义)。
- `_cmd_resume`:对账完成(preflight 成功)即 `_write_scope_section`
  幂等重写(D6 写入点②);`args.scope` 显式覆盖时装配后补
  `_append_file_scope_confirm`(W14b-3);plain resume 不补。
- tui 参数:`--scope` 改可选(default=None,help 注 NL 仪式归 WP-14c);
  `_cmd_tui` 其余逻辑零改,None 下行未实现(归 14c)。
- 顺手修复一处 HEAD 既有 ruff E501(P1-1 遗留的 [config] 警告行,93>88,
  仅折行零行为变化;本片门禁「改动文件 ruff 全绿」所要求,特此声明)。

`tests/test_cli.py`:既有 13 例语义保持 + Q8 例外条款更新 3 处(见下节
逐条声明)+ 新增 12 例(上表)。`replay.py`、`_resolve_scope`、
`_resume_preflight`、`_assemble_runtime`、`_create_engagement`、`_drive`
零改(规格第 8/9 条声明项,双来源消费全部经 14a 归一化记录,无新分支)。

## Q8 有意变更声明(例外条款,逐条)

规格「tests/test_cli.py 更新」节授权仅动 kinds 相关断言,逐条如下:

1. `test_run_creates_wp06_layout_and_registers_all_tools`:增
   `kinds[1] == "scope_confirmed"`(file 流装配后补确认,位次与
   scope_loaded 相邻);其余断言逐字节保持。
2. `test_resume_scope_drift_detected`:增覆盖 resume 后确认记录计数 +1
   (==2)、末条 payload source="file"/path=as-given/canonical_sha256=
   新文件字节 sha256、新 CIDR 生效;原有 drift 拒绝与放行断言不动。
3. `test_resume_rebuilds_context`:增 plain resume 后
   `kinds.count("scope_confirmed") == 1`(W14b-3:不补写)。
4. `test_help_all_subcommands`:增 `run --help` 含 `--scope-text`(验收 1
   第三例,规格授权归入互斥组条目)。

## 片内定案 W14b-1..4 逐条声明(评审即终)

- **W14b-1**:`_cmd_run_nl` 在 `_create_engagement` 之后、自建 AuditLog 与
  编译调用之前检查 `engagement.metadata().get("scope")` 非 None → stderr
  「该 engagement 目录已有冻结 scope;headless 无换 scope 通道,请换
  --workdir 或另建 engagement」+ rc 2。fail-closed:LLM 编译有渲染非
  确定性,静默覆盖等于无审计换授权;代价=NL 流同目录幂等复跑不支持
  (file 流支持),回退=换 workdir。测试实证拒绝先于任何 LLM 调用
  (`backend.calls == []`)且链上零新增。
- **W14b-2**:file 流 payload `path`=as-given 原串(与 scope_loaded.source、
  engagement.json meta 同串,测试断三串相等)、`canonical_sha256`=文件
  字节 sha256(不 resolve、不渲染 canonical)——file 流逐字节回归压倒
  D13 绝对路径注记(该注记为 NL 流 cwd 无关性而设,NL 流三处同串由
  一致性请求 4 的断言锁定:meta path = payload path = scope_loaded.source
  = scope.confirmed resolve 路径)。
- **W14b-3**:`scope_confirmed(source="file")` 只在本次命令行显式传
  `--scope` 时补写(run file 流必给、resume 覆盖时);plain resume 不补
  (确认事实已在链上,重复补写污染 `recover_scope_record` 取末条语义)。
- **W14b-4**:编译失败(含后端错误包装,经 ScopeCompileError)一律 rc 2,
  与 file 流 scope 加载失败同码同语义线;freeze 落盘 OSError 归 rc 1。
  无进程内重试(Q6):operator 修正声明后重跑。

## 设计取舍

1. **NL 分支独立成 `_cmd_run_nl`**,`_cmd_run` 入口仅一行分流:file 流
   逐字节回归(Q8 回归边界)压倒代码复用;两流共用段(resolve_backend_args/
   backend_factory/_create_engagement/_assemble_runtime/_drive)保持同一
   调用点形态,差异只在 scope 来源与确认语义。
2. **scope.confirmed 文件名按 D1 硬编码**(一致性请求 3):14a 未导出
   常量/路径助手,本片在 `_cmd_run_nl` 注释中声明;resolve 口径与
   freeze_scope 落 meta/payload 的 path 同串(一致性请求 4,测试锁定)。
3. **两写入点各一行**(一致性请求 5,2026-09-16 协调层裁定归本片):
   file 流装配时、resume 对账完成时,均经 `_write_scope_section` 一行调
   render_scope_section + update_scope_section;NL 流 run 的动态段由
   freeze_scope ④ 落(14a 写入点),本片不重入。
4. **resume 写入点放在 preflight 成功即刻**(对账完成语义点),先于后端
   装配:信息面幂等重写,后端 ConfigError 路径留了段更新无副作用顾虑
   (内容即当前 scope 事实)。
5. **`_resolve_scope` 零新分支实证**:验收 7b/8 两例分别以「链上仅
   scope_confirmed」「删 engagement.json 纯链」驱动 resume 成功,并直断
   recover_scope_record 归一化输出 source/origin(D13 映射);NL 流 meta
   路径对账 scope.confirmed 字节 sha256 天然成立(freeze 写的就是它)。

## 评审结论(T2:四视角评审 + 逐发现对抗核实一轮)

评审 workflow 两轮完成(首轮 8 agents 中 6 个因子后端配额 403 中断;
resume 续跑 10/10 完成,已完成的 2 个视角缓存重放后实际重跑,合计四
视角全覆盖:spec-fidelity / correctness / audit-semantics / tests;
audit-semantics 与 tests 两轮各跑一遍,发现取并集逐条核实)。
**确认 1 条(minor),驳回 5 条,1 条 nit 孤儿发现由实施侧按同一对抗
标准裁定并顺手加固**(其核实 agent 死于首轮配额中断,次轮 tests 视角
未再提出)。

确认缺陷与修复(修复后目标两文件与全量复跑全绿):

| # | 级别 | 发现 | 修复 |
|---|---|---|---|
| 1 | minor | 验收 10 file 流例的「markers 外字节不变」只被首尾+单锚抽样锁定,END 后引用块/meta 行/进展标题未验(14a 同措辞两处均为写前快照 prefix/suffix 全字节比对;核实员驳回 resume 半边——规格对该点未枚举 markers 外断言,file 半边成立) | `test_file_flow_run_writes_scope_section` 改为预建目录拿写前快照、prefix/suffix 逐字节比对(与 14a 形态一致);段内相等断言保留 |

驳回 5 条(核实员逐条给据,不行动):

| # | 发现 | 驳回理由要点 |
|---|---|---|
| 1 | resume 写入点 frozen_at 覆写真实冻结时刻(minor) | 规格未钉 frozen_at 取值;file 流本就无冻结时刻(不调 freeze_scope),写入时刻是唯一自洽语义;D11 对账权威在审计链,段内 sha256 跨 resume 字节不变;「与链上 ts 对不上」经脚本实证为假(与该次 resume 自落 scope_loaded.ts 秒级一致);幂等=收敛覆盖语义(14a 验收 4 同口径) |
| 2 | tests/test_cli.py 新增块 ruff format 漂移(nit) | 仓风格栏=「ruff check 全绿」(pyproject 仅配 lint;14a 台账同口径且其交付物本身有同类漂移被接收);仓基线另有 22 文件 format 漂移 |
| 3 | freeze OSError→rc 1 路径零测试(minor) | 测试要求为封闭枚举(涉及文件节+验收 1-11 均未下单该项);代码分支正确;总纲 D13 对写序/故障结构面明示「结构保证,不设专项断言」 |
| 4 | --save-profile × NL 流组合零覆盖(minor) | 同上封闭枚举未下单;_save_profile_if_requested 本体由 test_config.py 六例看守;failure_scenario 为假设性未来回归 |
| 5 | frozen_at 自提取回灌使相等断言对该字段同义反复(nit) | 不 mock 钟时这是满足验收 10 字面(段==渲染输出)的唯一写法;规格未要求对该字段设约束 |

孤儿 nit 裁定(实施侧,同一对抗标准):「互斥组测试两例断言可被
WP-14b 之前的旧 parser 糊弄」——事实上成立(旧 parser 的报错文本恰含
相同子串),但互斥组存在性已被 `test_help_all_subcommands`(--scope-text
上屏)与全部 NL 成功例(旧 parser 直接 SystemExit)锁定;仍顺手把两给
例断言升级为 argparse 互斥组专属形态「not allowed with argument」,
使该例独立成立。 correctness 视角与 audit-semantics 次轮均零发现。

## 验收实录(真实输出,2026-09-18)

目标两文件(本片测试 25 例 + replay 19 例,含既有):

```text
$ .venv/bin/python -m pytest tests/test_cli.py tests/test_replay.py -q
............................................                             [100%]
44 passed in 0.79s
```

ruff(本片改动文件):

```text
$ .venv/bin/ruff check src/foam/cli.py tests/test_cli.py
All checks passed!
```

全量零回归(计数链如实记录):布置任务时干净 HEAD(WP-14a 关闭后)
基线 490 passed + 2 skipped;本片 +12 例 → 中途实测 502 passed +
2 skipped(首轮全量曾出现 1 个瞬时失败:tests/test_tui.py::
test_slash_commands_and_completion_popup——该文件属 14c 在飞面,与本片
改动零交互,孤立复跑 3 次与全量复跑均绿,判定为既有 TUI 计时敏感
抖动,如实记录);评审修复后收尾全量:

```text
$ .venv/bin/python -m pytest -q
.............                                                            [100%]
515 passed, 2 skipped in 83.46s
```

(515 = 490 + 本片 12 + 14c 同树在飞 13;零失败。commit 只含本片两文件。)
