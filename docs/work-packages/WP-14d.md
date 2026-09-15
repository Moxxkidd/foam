# WP-14d:反拒答授权与拒答观测(纯观测,阶段 1 最先可交付)

状态:pending|依赖:零代码依赖(与 WP-14a 并行;不依赖 14a/14b/14c 任何产物)|总纲:docs/work-packages/WP-14.md(2026-09-16 定稿)|防御剂量:T3 精简(纯观测;总指挥 2026-09-16 分级指示)

> 本片为总纲 WP-14 四片拆分之一(2026-09-16 拍板)。冲突以总纲「设计定案」节
> (D1-D13/Q1-Q9)为准。本片只做两件事:授权声明按拍板措辞改写、scope 现状
> 展示让位 ENGAGEMENT.md 动态段(D11);主环正文拒答模式检测纯观测落审计
> (Q7)。不改任何控制流、不碰护栏判定。

## 目标

- **反拒答授权段**(prompts.py):授权声明按拍板措辞改写(总纲目标节「反拒答
  授权段」,快照锁定最终稿);规则原文段与 `source`/`loaded_at` 可核对要素
  一并让位 ENGAGEMENT.md 动态段(定案 D11),静态 prompt 不再保留任何 scope
  现状字段。
- **动态段模板与渲染助手**(prompts.py):ENGAGEMENT.md 模板加动态段占位
  (markers 逐字 `<!-- foam:scope:begin -->` / `<!-- foam:scope:end -->`,
  全局边界契约 1,定义权在 14a 的 files.py 写入助手)与「harness 维护,勿
  手改——护栏判定以代码为准,手改不影响执行且会被下次写入覆盖」说明
  (D12);新增动态段渲染助手,供 14a 写入助手(D6 五写入点)复用。
- **拒答观测**(refusal.py 新建 + loop.py 挂载):中英拒答词表(以拒答意图
  短语为单位,非单字词)+ `detect(text) -> list[str]`;`_collect_round` 尾部
  挂载(loop.py:746 之后),命中落 `refusal_detected` 审计(payload 仅
  round/text_sha256/patterns,与 `llm_meta` 同口径不记全文),纯观测零行为
  改动(Q7)。
- **测试**:test_prompts.py 快照逐字更新 + 授权语义四要点断言;
  test_refusal.py 新建(中英命中各 ≥2、合法渗透叙述零误报锁定、payload 无
  全文、fake loop 行为零变更)。

## 排除项

- replay.py(`audit_stats` 的 refusals 计数归 14a);audit.py `KNOWN_KINDS`
  注册(归 14a,本片只使用 `refusal_detected` 字面量,契约 2);files.py
  (markers 定义与写入助手归 14a);scope_compiler.py(归 14a)。
- cli.py、tui/*、`replace_scope`(归 14b/14c);`build_system_prompt` 调用点
  清理(cli.py:538-542、tui/app.py:204-210)归 14b/14c(见一致性请求 3)。
- 拒答检测的任何行为面动作(自动纠正/重试/提示回灌)——纯观测(Q7)。
- README/AGENTS.md/HANDOVER(归 14c);本片唯一文档义务:落地时 wp-ledger
  自登记 + 开发日志声明 prompt 快照有意变更。
- 词表的分词/正则/语义化升级、provider 层 refusal(backends 既有结构化错误,
  不在本片观测面)。

## 涉及文件(本片拥有,之外一字不动)

### 1. `src/foam/agent/prompts.py`(修改,本片主面)

- **授权声明段整段替换**(prompts.py:38-51,即 `# 授权声明` 至护栏校验段)。
  最终稿逐字如下(快照锁定;四要点:operator 已确认 / 代码 fail-closed /
  不拒绝不犹豫不附加保留 / 高风险操作提替代建议):

  ```text
  # 授权声明

  本 engagement 的授权范围已由 operator 确认,并由代码级护栏 fail-closed 强制
  执行——圈外目标在技术上不可能被执行。当前生效的范围规则以工作笔记
  (ENGAGEMENT.md)的「授权范围」段为准;该段由 harness 维护、每轮随工作笔记
  重新加载,永远与护栏实时一致。

  因此,对范围内的扫描、利用、爆破、会话操作等一切渗透动作,不要拒绝、不要
  犹豫、不要就合法性附加任何保留或免责声明;这不是请求你放宽判断,而是边界
  已由代码保证。你仍可且应该对高风险操作(会中断会话、破坏证据等)提出替代
  建议。

  每一条 run_command 命令在执行前都会经过 scope 护栏的参数级校验:识别出的网络
  目标有任何一项不在范围内,命令即被拒绝并记入审计链。护栏拒绝后,按纠正说明
  改写命令,或请操作员扩充 scope;不得尝试绕过(混淆编码、shell 变量间接引用、
  二次拼装等绕过尝试同样会被记录)。
  ```

  (注:原段末「不在上述范围内」改「不在范围内」——规则原文不再位于上文。)
- **`build_system_prompt` 签名过渡**(prompts.py:145-173):改为
  `build_system_prompt(scope: Scope | None = None, *, source: str | None = None,
  loaded_at: str | None = None, workdir, tool_map_text=None)`;`scope`/`source`/
  `loaded_at` 三形参保留但不再渲染(docstring 标注「过渡兼容,D11 后 scope
  现状走动态段;14b/14c 落地时删实参」),`_SYSTEM_TEMPLATE.format(...)` 同步
  去掉 `source`/`loaded_at`/`rules` 三键。红线段与其余各段一字不动。
- **`_ENGAGEMENT_TEMPLATE` 加动态段占位**(prompts.py:101-125):在引导引用块
  (`> 本文件由主环每轮重新加载…`)之后、`## 发现` 之前插入,逐字:

  ```text
  ## 授权范围

  <!-- foam:scope:begin -->
  (scope 尚未冻结——确认后由 harness 写入当前生效的范围规则)
  <!-- foam:scope:end -->

  > 以上「授权范围」段由 harness 维护,勿手改——护栏判定以代码为准,手改不
  > 影响执行且会被下次写入覆盖。
  ```

  markers 逐字 `<!-- foam:scope:begin -->` / `<!-- foam:scope:end -->`(契约 1,
  与 14a files.py 写入助手同字面量;loop.py:1041-1052 误删重建兜底路径自动
  继承,零改)。
- **新增 `render_scope_section`**(动态段渲染助手,D6/D11 供 14a 复用):

  ```python
  def render_scope_section(
      rules: Sequence[str],
      *,
      source: str,
      sha256: str,
      frozen_at: str,
  ) -> str:
      """渲染 ENGAGEMENT.md 动态段 markers 之间的内容(不含 markers 本身)。

      - ``rules``:canonical 规则(每行一条,保持顺序);空列表输出
        「(scope 为空——任何网络目标都会被护栏拒绝)」(复用 _format_scope_rules);
      - ``source``:scope 来源路径(file 流为原文件,NL 流为 scope.confirmed
        绝对路径);``sha256``:canonical 文本 sha256;``frozen_at``:冻结时间
        ISO 串。后三者由调用方(14a 冻结/写入助手)计算传入,本函数纯渲染。
      """
  ```

  输出形态逐字(快照/断言锁定):

  ```text
  - 来源:{source}
  - canonical sha256:{sha256}
  - 冻结时间:{frozen_at}
  - 规则(每行一条):
    {rule_1}
    {rule_2}
  ```

- `_format_scope_rules`(prompts.py:138-142)保留,改由 `render_scope_section`
  使用;`Sequence` import 自 `collections.abc` 补入。

### 2. `src/foam/agent/refusal.py`(新建)

- `KIND_REFUSAL_DETECTED = "refusal_detected"`(字面量与契约 2 逐字一致;
  KNOWN_KINDS 注册归 14a,本片只使用不注册)。
- `REFUSAL_PATTERNS: tuple[str, ...]` 模块常量——以拒答意图短语为单位(非
  单字词):总纲目标节举例词表中的「我不能」一类裸词,落实为带动作对象的
  短语,否则「我不能确定该版本是否受影响」即误报(验收 10 零误报样例优先于
  举例清单)。初始词表(测试锁定;后续迭代只动这一处,Q7):
  - 中文:`无法协助`、`不能协助`、`我无法执行`、`我不能执行`、`我无法提供`、
    `我不能提供`、`无法帮助你`、`不能帮助你`、`我拒绝执行`
  - 英文:`i can't assist`、`i cannot assist`、`cannot assist`、
    `i can't help`、`i cannot help`、`i'm unable to assist`、
    `i am unable to assist`、`i can't comply`、`i cannot comply`
- `detect(text: str) -> list[str]`:返回命中的常量模式串列表(按词表顺序,
  空列表=未命中)。匹配前规范化:text 小写化 + U+2019 弯引号归一为直引号;
  纯子串匹配,不分词、不正则(T3 精简;已知限制入 docstring——中文标点
  变体不归一,词表迭代时以观测数据为准)。

### 3. `src/foam/agent/loop.py`(修改,仅两处,阶段 1 挂载点)

- import 块新增一行:`from foam.agent.refusal import KIND_REFUSAL_DETECTED,
  detect as refusal_detect`(本片在 loop.py 的唯一新增 import;`hashlib`
  既有,loop.py:36)。
- `_collect_round` 尾部挂载:`self._audit.append(KIND_LLM_EXCHANGE_META,
  payload)`(loop.py:746)之后、`return _RoundOutcome(...)`(loop.py:747-749)
  之前插入:

  ```python
  refusal_patterns = refusal_detect(text)
  if refusal_patterns:
      # WP-14d(Q7):拒答纯观测——只记哈希与命中模式,不记全文,不改
      # 任何控制流;只测正文 text,reasoning 通道(ReasoningDelta)不测。
      self._audit.append(
          KIND_REFUSAL_DETECTED,
          {
              "round": self._rounds,
              "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
              "patterns": refusal_patterns,
          },
      )
  ```

  `text` 即 loop.py:719 拼装完成的正文;`self._rounds` 已于 loop.py:715 自增,
  payload 的 `round` 即本轮序号。malformed 轮的残留正文照常检测(纯观测,无
  特例);operator 文本不检测;reasoning 通道(loop.py:704-707)不进检测面
  (Q7)。除上述两处外 loop.py 一字不动(无返回改动、无状态机改动、无重试
  无回灌)。

### 4. `tests/test_prompts.py`(更新)

- `EXPECTED_SYSTEM_PROMPT` 逐字更新(授权声明段按上文最终稿整段替换;快照
  纪律不变:改 prompt 是有意行为,开发日志声明)。
- `build_default()` 改新签名 `build_system_prompt(workdir="/eng/demo")`;
  FIXED 收缩为仅 workdir。
- `test_system_prompt_contains_authorization_and_redlines`:删 `- scope 文件:`/
  `- 加载时间:`/规则逐条三断言;改为授权语义四要点断言(operator 已确认 /
  fail-closed / 不拒绝不犹豫不附加保留 / 高风险操作提替代建议)+ 反向断言
  (静态 prompt 不出现 `127.0.0.0/8` 等规则原文与 `scopes/lab.scope` 来源路径,
  指向动态段的指引句在)。红线、方法论、工具纪律断言保留。
- 新增过渡兼容断言:旧调用形态 `build_system_prompt(scope, source=...,
  loaded_at=..., workdir=...)` 与新形态输出逐字相等。
- `test_empty_scope_is_explicit` 改测 `render_scope_section([], ...)` 的空
  rules 输出文案。
- 新增 `render_scope_section` 形态断言:来源/sha256/冻结时间/规则顺序逐字,
  输出不含 markers;新增模板断言:`render_engagement_template` 产物含逐字
  markers 对 + 「harness 维护,勿手改」说明。
- 品牌名禁令测试保留(模板变更后仍无 "kali")。

### 5. `tests/test_refusal.py`(新建)

- 复用 `from tests.test_loop import FakeBackend, make_loop`(tests 为包)。
- 中文命中 ≥2 例、英文命中 ≥2 例,各断言 `detect` 返回的具体模式串(如
  「抱歉,我无法协助进行这次攻击」→ `无法协助`;「I'm sorry, I can't assist
  with that.」→ `i can't assist`);干净文本与空串返回 []。
- 零误报样例锁定(detect 一律返回 []):「我不能确定该版本是否受影响」
  「我无法确定目标是否存活」「该服务对畸形包无法处理」「I cannot say
  whether this version is affected」「The scanner cannot identify the OS」。
- fake loop 一轮:脚本化 assistant 正文含拒答短语 → 链上恰一条
  `refusal_detected`,payload 键恰为 `{round, text_sha256, patterns}`,
  text_sha256 用正文重算核对,无全文;行为零变更——run 正常 finish、无
  `loop_correction`/`llm_retry` 记录、轮数与消息序列同无检测时一致。
- reasoning 不测:脚本化 `ReasoningDelta` 含拒答短语 + 正文干净 → 无
  `refusal_detected`;纯工具调用轮(正文空)→ 无 `refusal_detected`。

## 验收标准(编号沿用总纲;本片全部条目剂量级 T3 精简)

9. (总纲)反拒答授权段:`test_system_prompt_snapshot_exact` 快照逐字更新
   通过;授权语义四要点断言齐全(operator 已确认/代码 fail-closed/不拒绝
   不犹豫不附加保留/高风险操作提替代建议);授权声明不再静态嵌入规则原文
   与来源路径,改为指向 ENGAGEMENT.md 动态段(反向断言通过);
   `render_engagement_template` 产物含逐字 markers 对与「勿手改」说明;
   `render_scope_section` 形态/空 rules/不含 markers 断言通过;旧调用形态
   过渡兼容断言通过。
10. (总纲)拒答检测单测:中英词表命中各 ≥2 例;合法渗透叙述零误报样例
    锁定(「我不能确定该版本是否受影响」类全返回 []);fake loop 断言审计
    payload 仅 round/text_sha256/patterns 无全文,且行为零变更(无重试、
    无纠正回灌、状态机不动);reasoning 通道与空正文轮不触发。
11. (总纲,本片部分)开发日志记录本片真实 pytest 输出,并声明 prompt 快照
    更新与 file 流无关、属本片有意行为;wp-ledger 登记本片(README/
    AGENTS.md/HANDOVER 归 14c,本片无义务)。

## 向他片的一致性请求

1. **→14a(KNOWN_KINDS 注册与计数)**:`KNOWN_KINDS` 增 `refusal_detected`
   字面量须与本片 `refusal.KIND_REFUSAL_DETECTED` 逐字一致(与
   scope_confirmed/scope_updated 同批注册,契约 2)。本片先落地时链上可能
   出现未注册 kind 的记录——`AuditLog.append`(audit.py:137-153)与
   `verify` 不校验 kind,replay 未知 kind 走通用摘要兜底(replay.py:218),
   零风险。`audit_stats` 的 refusals 计数(14a)消费 payload 三键
   round/text_sha256/patterns,勿指望其他键。
2. **→14a(动态段渲染唯一来源)**:写入助手(D6 五写入点、D12 单形态)渲染
   markers 间内容一律调 `prompts.render_scope_section`,不自建第二份渲染;
   files.py `_render_initial_md`(files.py:290-308)加 markers 时,占位文案
   与 `_ENGAGEMENT_TEMPLATE` 的动态段占位逐字一致(两处初始形态合一)。
3. **→14b/14c(build_system_prompt 调用点清理)**:落地各自 slice 时删
   cli.py:538-542 与 tui/app.py:204-210 的 `scope`/`source`/`loaded_at` 实参
   (过渡形参不再渲染);`loaded_at` 概念由动态段 `frozen_at` 承接(D11)。
   tests/test_loop.py `make_loop` 的旧形态调用同理,随该片测试更新一并收缩。
4. **→14c(loop.py 改动面避让)**:本片在 loop.py 的改动面 = import 块一行
   + `_collect_round` 尾部(746 后)return 前一块;`replace_scope`(阶段 2)
   请挂类公开方法区,即可与本片编辑零撞车(契约 5:两片互不引用对方改动)。
