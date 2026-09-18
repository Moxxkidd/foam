# WP-14a 开发日志:scope 编译与冻结基座

> 落地日期:2026-09-18。执行:WP-14a 实施会话(与 WP-14d 实施会话同树并行,
> 文件所有权零重叠,跨片契约经跨会话对账确认)。事实源:
> docs/work-packages/WP-14a.md + docs/work-packages/WP-14.md「设计定案」节。
> 剂量:T2(正确性一轮评审);freeze_scope 写序与 payload 契约按 T2+ 对待。

## 结果一览

| 验收条款 | 结论 |
|---|---|
| 1. 编译器契约(fake 后端) | ✅ tests/test_scope_compiler.py 验收 1 区六例 |
| 2. round-trip 门禁 | ✅ 脏输入归一化/空规则集(Q9)/render 单测三例 |
| 3. 冻结一致性(T2+) | ✅ 三方 sha256 一致/payload 逐键/无 tmp 残留/动态段=render_scope_section 输出/markers 外字节不变/审计成败各一 |
| 4. update_scope_section 单形态(助手级) | ✅ 重写保外字节/幂等/空段边界/不成对容错/缺失附加重建 五例 |
| 5. audit_stats refusals + 报告展示 | ✅ 计数例 + 报告行例 + 旧链 refusals=0 例 |
| 6. interesting 集 +scope_updated | ✅ 简报出现变更行 + 旧链不变例 |
| 7. create 开箱 markers + 两处初始形态合一 | ✅ markers 成对例 + 与 14d `_ENGAGEMENT_TEMPLATE` 动态段逐字比对例 |
| 8. replay 归一化(T2+) | ✅ 三 kind 各例 + 混合链取末条 + 旧链不变 + 模拟 _resolve_scope 比对消费例 |
| 9. 开发日志 + wp-ledger 自登记 | ✅ 本日志 + 台账 WP-14a 行与关闭记录 |

测试实录见文末「验收实录」。

## 交付物

- 新建 `src/foam/agent/scope_compiler.py`:`compile_scope`(一次性 LLM 调用,
  独立 system prompt 内嵌四种规则形态精确语义,严格 JSON,无工具无流式;
  归一化 → `render_canonical_rules` → `parse_scope` round-trip 门禁 Q2;
  `audit` 形参每次调用含失败路径落 `llm_exchange_meta`,口径对齐
  loop.py:729-737)、`ScopeCompilation`(frozen)、`ScopeCompileError`
  (中文可行动,三类来源)、`freeze_scope`(唯一冻结入口,D13 写序
  ①scope.confirmed tmp+rename → ②update_scope_metadata → ③objective
  同步 D8 → ④动态段重写(消费 14d `prompts.render_scope_section`)→
  ⑤审计)、`scope_event_payload`(D13 payload 契约单源)。
- 新建 `tests/test_scope_compiler.py`(17 例,fake 后端 duck-type,
  RFC 5737 + example.com,全 tmp_path)。
- 修改 `src/foam/guard/scope.py`:**仅**新增 `render_canonical_rules`
  (置 `scope_payload` 附近)+ Iterable import;判定/解析逻辑零改。
- 修改 `src/foam/state/files.py`:`SCOPE_SECTION_BEGIN/END` 常量(markers
  定义权本片,与 14d 模板逐字一致)、`_render_initial_md` 加「授权范围」
  动态段(初始形态与 14d `_ENGAGEMENT_TEMPLATE` 逐字合一)、
  `update_scope_section`(单形态 markers 间原子重写 + 容错附加恢复)、
  `update_scope_metadata`(resolve 绝对路径 + 字节 sha256)、
  `update_objective`(json + md 目标行)、`update_progress` 与模块
  docstring 互斥声明(行为零改)。
- 修改 `src/foam/guard/audit.py`:KNOWN_KINDS 注册 `scope_confirmed`/
  `scope_updated`/`refusal_detected` 三常量(他片只使用不注册)。
- 修改 `src/foam/replay.py`:`recover_scope_record` 三 kind 归一化
  (D13 映射:source=path、origin=file|nl、四键透传、canonical_sha256
  透传、缺键 .get 容忍)、interesting 集 +`scope_updated`、
  `audit_stats` +`refusals`、`build_report` 统计行末尾 +「/ 拒答 N 次」。
- `tests/test_state.py` +11 例、`tests/test_replay.py` +9 例(WP-14a 段)。

## 设计取舍

1. **归一化与渲染分工**:规则行归一化(按行拆分/去行内 `#`/strip/丢空行)
   在编译器侧(与 `parse_scope` 注释语义一致),`render_canonical_rules`
   只做纯文本渲染(保序、去空白行、尾部单换行、空列表→空串)——round-trip
   后 `scope.rules == 归一化元组` 理论恒等,代码里以显式 AssertionError
   防守(src 目录 ruff S101 禁用 assert 语句,等价语义手工 raise)。
2. **审计落点唯一**:失败路径(后端错误/JSON 失败/round-trip 拒绝)无返回
   值,只有编译器在现场能落 `llm_exchange_meta`(D7),故 `compile_scope`
   增 `audit` 形参(对总纲草图的增补,规格已注理由);调用侧不得重复落。
   口径对齐 loop.py:prompt=消息序列 JSON、response=`{"text": ...}` JSON,
   只有哈希与 token;`Usage` 未到达(后端抛错)时 token 记 None
   (`usage.input_tokens or None`,与 loop.py 同口径)。
3. **freeze_scope 增补参数**:`objective`(D8 冻结时同步 engagement.json 与
   ENGAGEMENT.md 目标行)与 `compile_attempts`(D7 NL payload 记尝试次数,
   只有仪式调用方知道)——规格「设计定案引用与细化声明」节已备
   案,不矛盾。
4. **file 流不调 freeze_scope**(Q8):file 流 `scope_confirmed(source="file")`
   由 14b/14c 装配侧用 `scope_event_payload` 直写审计,`path` = as-given
   原串(与 `scope_loaded.source`、engagement.json meta 同串,对齐 14b
   W14b-2:file 流逐字节回归压倒绝对路径注记);D13 字面「path(scope.
   confirmed 绝对路径)」按 NL 流写。本片 `test_scope_event_payload_file_
   flow_as_given` 锁定该口径。
5. **动态段渲染唯一来源**:本片不自建第二份渲染——`freeze_scope` ④ 与
   `update_scope_section` 测试均直调 14d `prompts.render_scope_section`
   (14d 一致性请求 2)。`update_scope_section` 保持 `section: str` 入参、
   markers 间原子重写;「harness 维护,勿手改」说明为 markers 外模板静态
   文本,两份初始模板各自携带,不经写入助手重写。
6. **容错附加不是第二形态**(D12 细化):模型可写 ENGAGEMENT.md(D6 信息面
   容错)。「markers 间」以 marker 字面量本身为界——BEGIN 字面量之后、END
   字面量之前的全部内容(含同行残留文本)都算段内,整段替换;故同行
   markers、END 行前缀残留等手改形态都在正常路径内收敛(T2 评审确认缺陷
   后改此不变量)。markers 缺失/不成对(END 在 BEGIN 前、只剩其一)时,
   容错分支先剥离游离 marker 字面量、再将完整段附加到文件末尾一次恢复
   markers;正常路径永远是 markers 间重写。空段(BEGIN 行紧邻 END 行)等
   下标边界均有专项测试锁定(见「评审结论」)。
7. **update_progress 互斥降为声明级**(总指挥 2026-09-16 减肥注记):整文件
   重写会抹掉 markers,目前运行期无调用方(仅 tests/test_state.py 触达),
   行为零改;声明入 files.py 模块 docstring 与 `update_progress` docstring。
8. **replay 归一化是两处 source 语义的唯一转接点**(D13):payload 的
   source=来源枚举 file|nl,归一化输出的 source=scope 文件路径;
   cli.py:739-748 零适配消费由 `test_normalized_record_feeds_resolve_
   scope_logic` 逐行模拟比对逻辑锁定(纯链恢复 e2e 归 14b 验收 8)。

## 对已关闭 WP 文件的最小改动声明(WP-09 Q6 先例)

- `guard/scope.py`(WP-02):仅新增 `render_canonical_rules` 纯文本函数 +
  `Iterable` import;`parse_scope`/`check_command`/`extract_targets`/
  `scope_payload` 一字未动,既有 test_scope.py 全绿。语法面零新增。
- `guard/audit.py`(WP-02):仅 KNOWN_KINDS 增三常量并注册(该表本为扩展
  预留:「后续 WP 可扩展」);`append` 不强制校验 kind 的现状不变。
- `state/files.py`(WP-06):`_render_initial_md` 新增「授权范围」段
  (create 路径产物变化属本片有意行为,验收 7);`update_progress`/
  `create`/`_scope_metadata` 行为零改(仅 docstring 互斥声明);
  新增三个方法与两个模块常量。
- `replay.py`(WP-10):整体归本片(边界契约 4)。`format_record` 不动
  (新 kind 走通用摘要兜底);`build_resume_briefing` 概览行不动;
  scope_loaded-only 旧链 `recover_scope_record` 输出逐键不变(有测试例);
  `build_report` 统计行末尾追加「/ 拒答 N 次」(既有「命令 1 条」等断言
  不受影响,有旧链回归例)。
- cli.py/loop.py/tui/* 零触碰(分属 14b/14c/14d 面)。

## 跨片对账记录(与 WP-14d 实施会话)

- markers 字面量(契约 1):本片 files.py 定义 `<!-- foam:scope:begin -->`/
  `<!-- foam:scope:end -->`;14d `_ENGAGEMENT_TEMPLATE` 逐字一致,
  `test_initial_md_scope_block_matches_prompts_template` 双侧逐字比对锁定。
- `render_scope_section` 签名与输出形态(契约:rules, *, source, sha256,
  frozen_at;空 rules 文案;不含 markers 无尾换行):14d 落地 commit
  51a0b2a,本片消费侧验收 3④ 逐字比对通过。
- `refusal_detected` 字面量(契约 2):本片 audit.py 注册,与 14d
  `refusal.KIND_REFUSAL_DETECTED` 逐字一致;`audit_stats` 只消费
  round/text_sha256/patterns 之外的计数语义(只数 kind,不读 payload 键)。
- 基线计数注记:本片启动时全量基线 441 passed + 2 skipped(工作树已含
  14d 在飞测试);14d 先行 commit 后,本片收尾全量见下文实录。

## 验收实录(真实输出,2026-09-18)

本片目标三文件(编译器 17 + state 追加 11 + replay 追加 9,含既有):

```text
$ .venv/bin/python -m pytest tests/test_scope_compiler.py tests/test_state.py tests/test_replay.py -q
........................................................................ [ 94%]
....                                                                     [100%]
76 passed in 0.57s
```

全量零回归(含 14d 已入库测试):

```text
$ .venv/bin/python -m pytest -q
...  (尾部)
490 passed, 2 skipped in 41.48s
```

ruff(本片改动文件):

```text
$ .venv/bin/ruff check src/foam/guard/scope.py src/foam/guard/audit.py \
    src/foam/state/files.py src/foam/replay.py src/foam/agent/scope_compiler.py \
    tests/test_scope_compiler.py tests/test_state.py tests/test_replay.py
All checks passed!
```

## 评审结论(T2:四视角评审 + 逐发现对抗核实一轮)

评审 workflow(21 agents:4 视角评审 + 17 条发现的对抗核实)结论:
**确认 7 条(major 2 / minor 4 / nit 1),驳回 9 条**(驳回主因:规格本就
如此规定、或验收枚举字面已满足的超规格加固偏好——如 CRLF 围栏容忍、
缺键链测试、file 流定义域收紧、多行 objective 消毒等,均不行动)。

确认缺陷与修复(修复后全部测试复跑全绿):

| # | 级别 | 发现 | 修复 |
|---|---|---|---|
| 1 | major | update_scope_section:BEGIN/END 同行时 paired 恒 False,容错分支每次调用追加完整块,永不收敛、ENGAGEMENT.md 无界增长 | 「markers 间」改以 marker 字面量本身为界(同行残留文本一并替换);`test_..._same_line_markers_converge` 锁定幂等收敛与零增长 |
| 2 | major | wp-ledger 无本片登记(表行与关闭记录均缺)而本日志曾提前宣称 ✅ | 台账表行 + 关闭记录补齐(本 commit 内);声明以事实为准 |
| 3 | minor | compile_scope 的 aclose() 抛 BackendError 时原样逃逸(未包装)且跳过 D7 审计 | aclose 加守卫归并进 backend_error;审计移入 finally,任何退出路径恰落一条;`test_compile_aclose_backend_error_wrapped_and_audited` 锁定 |
| 4 | minor | END 不在行首时同行前缀文本永久残留段内,违反「markers 间整段替换」 | 同 #1 的字面量边界不变量一并解决;`test_..._end_line_prefix_replaced` 锁定 |
| 5 | minor | 非法 JSON 测试断言过弱(仅 match "JSON",中文可行动指引不捕获回归) | 断言加「请重试/更明确的范围描述」指引子串 |
| 6 | nit | 本日志「验收实录」计数曾自相矛盾(state 追加 11 vs 交付物节 +9) | 评审后 state 段实为 +11(新增两例边界测试),交付物节已订正为 +11,两处一致 |
| 7 | nit | 同 #2(另一视角重复发现) | 同 #2 |

另:评审前自查已修复一处同类下标缺陷(空段 BEGIN 行紧邻 END 行时
rfind 空区间返回 -1 导致全文复制),`test_..._empty_section_rewrite`
锁定;该缺陷在评审 #5 发现中被确认「已解决,不再列为发现」。

基线计数注记(同树并行开发的计数链,如实记录):布置任务时口径基线
438 passed + 2 skipped;本片启动实测 441(工作树已含 14d 在飞测试);
14d commit 51a0b2a 后干净 HEAD 基线 453 passed + 2 skipped;
本片 +37 例(编译器 17 + state 11 + replay 9)→ 收尾 490 passed +
2 skipped,全程零失败。
