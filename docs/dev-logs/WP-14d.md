# WP-14d 开发日志:反拒答授权与拒答观测(纯观测)

> 交付日期:2026-09-18。执行:WP-14d 实施会话。事实源:
> docs/work-packages/WP-14d.md + WP-14.md「设计定案」节(D1-D13/Q1-Q9)。
> 防御剂量:T3 精简(纯观测;总指挥 2026-09-16 分级指示)。
> 本片为四片拆分中最先交付片,零代码依赖,独立可 commit。

## 结果一览

| 验收条款(编号沿用总纲) | 结论 |
|---|---|
| 9. 反拒答授权段:快照逐字更新 + 授权语义四要点 + 反向断言 + markers/render_scope_section/过渡兼容 | ✅(tests/test_prompts.py 9 项全绿,§验收9) |
| 10. 拒答检测单测:中英命中各 ≥2、零误报样例锁定、payload 三键无全文、行为零变更、reasoning/空正文不触发 | ✅(tests/test_refusal.py 12 项全绿,§验收10) |
| 11. 开发日志记录真实 pytest 输出 + 声明快照有意变更;wp-ledger 登记 | ✅(本日志 §验收11 + docs/wp-ledger.md) |

## 声明(快照纪律与边界)

1. **prompt 快照更新属本片有意行为,与 file 流无关**:`EXPECTED_SYSTEM_PROMPT`
   逐字更新是唯一事实源规格(WP-14d.md「授权声明段整段替换」最终稿)要求的
   同步动作——授权声明按 2026-09-16 拍板反拒答措辞整段改写,scope 现状字段
   (`source`/`loaded_at`/规则原文)按定案 D11 让位 ENGAGEMENT.md 动态段,
   静态 prompt 不再保留任何 scope 现状字段。快照纪律不破:改动有意、同步
   更新、本日志留痕。
2. **改动面严格限定本片所有文件**:`src/foam/agent/prompts.py`、
   `src/foam/agent/refusal.py`(新建)、`src/foam/agent/loop.py`(仅两处:
   import 块 + `_collect_round` 尾部挂载块,逐字按规格)、
   `tests/test_prompts.py`、`tests/test_refusal.py`(新建)、
   `docs/dev-logs/WP-14d.md`(本文件)、`docs/wp-ledger.md`(登记)。
   cli.py/tui/*/replay.py/audit.py KNOWN_KINDS/state/files.py 一字未动
   (归 14a/14b/14c)。
3. **ruff 把 loop.py 新增 import 拆成两行**(`from foam.agent.refusal import
   KIND_REFUSAL_DETECTED` / `import detect as refusal_detect`):规格写法是单行
   合并 import,ruff isort(I001)的 canonical 形态要求同模块带别名条目独占
   一行,以 ruff 为准——语义仍是规格的「唯一新增 import」。
4. **链上 `refusal_detected` 暂未注册 `KNOWN_KINDS`**:注册归 14a(契约 2,
   与 scope_confirmed/scope_updated 同批),本片只使用字面量。已核实
   `AuditLog.append`(audit.py:137-153)与 `verify` 不校验 kind、replay 未知
   kind 走通用摘要兜底(replay.py:218),零风险;独立验证(下节)在不含
   14a 任何改动的干净 HEAD 上进行,verify 通过实证该结论。
5. **预存缺陷照实记录,不属本片**:HEAD 的 `src/foam/cli.py:386` 有既有
   E501(93>88,P1-1 commit fb81c78 带入,`git show HEAD:src/foam/cli.py`
   复验同报)。cli.py 归 14b/14c 面,本片不碰;本片所有文件 ruff 全绿。
6. **同树并行注记**:实施期间 WP-14a 实施会话在同一工作树在飞
   (audit.py/scope.py/files.py 有其未入库改动)。两片文件所有权零重叠
   (契约 5);本片 commit 只含上列本片文件,14a 在飞文件不add不入账。
   `render_scope_section` 已按一致性请求 2 交付为动态段渲染唯一来源,
   签名与空 rules 文案与规格逐字一致,已知会 14a 会话。

## 验收 9:反拒答授权段

逐字核验(脚本比对 WP-14d.md 围栏块与仓内产物,输出实录):

```
1) 授权声明段:逐字一致 ✓            (规格最终稿 ⊆ _SYSTEM_TEMPLATE)
2) 动态段占位:逐字一致 ✓            (markers 对 + 「harness 维护,勿手改」⊆ _ENGAGEMENT_TEMPLATE)
3) render_scope_section 输出形态:逐字一致 ✓
4) 词表 18 条(中 9 + 英 9)与 kind 字面量:一致 ✓
5) 静态 prompt 零 scope 现状字段、旧措辞清零 ✓
```

测试面(tests/test_prompts.py 重写):

- `test_system_prompt_snapshot_exact`:全文快照逐字(授权声明新稿含于其中)。
- `test_system_prompt_contains_authorization_and_redlines`:授权语义四要点
  断言(operator 已确认 / 代码 fail-closed / 不拒绝不犹豫不附加保留 /
  高风险操作提替代建议)+ 反向断言(`127.0.0.0/8` 等规则原文、
  `scopes/lab.scope` 来源路径、`- scope 文件:`/`- 加载时间:` 均不出现;
  指向动态段的指引句在);红线、方法论、工具纪律断言保留。
- `test_build_system_prompt_legacy_call_form_transitional`:旧调用形态
  `build_system_prompt(scope, source=..., loaded_at=..., workdir=...)` 与新
  形态输出逐字相等(三形参保留但不渲染;14b/14c 删实参后本测试随之收缩)。
- `test_render_scope_section_exact_form`:来源/sha256/冻结时间/规则顺序逐字,
  输出不含 markers;`test_render_scope_section_empty_rules_explicit`:空
  rules 输出「(scope 为空——任何网络目标都会被护栏拒绝)」(原
  `test_empty_scope_is_explicit` 改测渲染助手)。
- `test_engagement_template_scope_section_markers`:markers 逐字成对、位于
  引导引用块之后「## 发现」之前,占位文案与「harness 维护,勿手改」说明在。
- 品牌名禁令测试保留(模板变更后仍无 "kali")。

## 验收 10:拒答检测单测

- 词表命中:中文 3 例(含词表顺序锁定:多命中按 REFUSAL_PATTERNS 顺序而非
  文本出现顺序)、英文 3 例(含「i cannot assist」+「cannot assist」子串
  重叠双命中的既定行为锁定)、规范化 3 例(大写小写化、U+2019 弯引号归一)。
- 零误报样例锁定(规格五条逐字入 parametrize,全返回 []):
  「我不能确定该版本是否受影响」「我无法确定目标是否存活」「该服务对畸形包
  无法处理」「I cannot say whether this version is affected」「The scanner
  cannot identify the OS」。
- fake loop 命中轮:链上恰一条 `refusal_detected`,payload 键恰为
  `{round, text_sha256, patterns}`,`text_sha256` 用正文重算核对,记录无全文;
  行为零变更——run 正常 finish、无 `loop_correction`/`llm_retry`、观测记录
  紧随本轮 `llm_exchange_meta`;对照组(同脚本干净正文)轮数与消息角色序列
  逐一致,审计 kinds 仅差这一条观测记录。
- reasoning 通道(ReasoningDelta 含拒答短语)与纯工具调用轮(正文空)不触发;
  附非空断言(reasoning_sha256 确实到达过审计面,排除 vacuous 测试)。
- `verify(env.audit_path)` 在两例中均通过:未注册 kind 在链上零风险(契约 2)。

## 验收 11:真实 pytest 输出实录

主工作树(含 14a 在飞文件,未动未入库):

```
$ .venv/bin/python -m pytest tests/test_prompts.py tests/test_refusal.py tests/test_loop.py -q
45 passed in 2.11s
$ .venv/bin/python -m pytest -q
453 passed, 2 skipped in 43.02s
```

分文件:test_prompts.py 9 项、test_refusal.py 12 项、test_loop.py 24 项,全绿。

独立可 commit 验证(干净 HEAD worktree 仅应用本片五个文件,不含 14a 任何
在飞改动——链上 KNOWN_KINDS 无 refusal_detected 注册):

```
HEAD is now at 1989018 WP-14 规格定稿并拆四片:NL scope 入口+代码强制+反拒答(2026-09-16 拍板)
$ pytest tests/test_prompts.py tests/test_refusal.py tests/test_loop.py -q
45 passed in 1.92s
$ pytest -q
453 passed, 2 skipped in 41.83s
$ ruff check src/foam/agent/ tests/test_prompts.py tests/test_refusal.py
All checks passed!
```

ruff:本片五文件全绿;全仓 `ruff check .` 余 cli.py:386 E501 一条,HEAD
既有(见声明 5),非本片引入、非本片所有权。

## 设计取舍与口径注记

1. **`_format_scope_rules` 签名随用途改**:原收 `Scope`,现收
   `Sequence[str]`(规则序列),改由 `render_scope_section` 复用(规格
   「保留,改由 render_scope_section 使用」);空 rules 文案逐字不变。
2. **多命中按词表顺序**:detect 返回 `[p for p in REFUSAL_PATTERNS if p in
   normalized]`,顺序是词表序而非文本出现序;子串重叠(如「i cannot
   assist」含「cannot assist」)双命中属纯子串匹配的既定行为,均入测试锁定,
   供 14a `audit_stats` 计数口径参考(同一短语事件可命中多条模式)。
3. **过渡形参零渲染**:`build_system_prompt` 的 `scope`/`source`/`loaded_at`
   保留接收但完全不进 `_SYSTEM_TEMPLATE.format(...)`;旧调用方(cli.py、
   tui/app.py、tests/test_loop.py `make_loop`)零适配继续工作,清理归
   14b/14c(一致性请求 3)。
4. **loop.py 误删重建兜底零改继承**:ENGAGEMENT.md 误删重建走
   `render_engagement_template`(loop.py:1041-1052),模板加了动态段占位后
   该路径自动继承 markers,无需任何额外改动(规格注记已核)。
5. **已知限制(入 refusal.py docstring)**:中文标点变体不归一;词表迭代
   只动 `REFUSAL_PATTERNS` 一处,以观测数据为准(Q7)。
