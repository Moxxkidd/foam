# WP-14a:scope 编译与冻结基座(总纲 WP-14 切片 A)

状态:pending|依赖:WP-01–WP-13 全部关闭(v0.1.0 基线) + WP-14d 的 prompts.render_scope_section 可用(动态段渲染助手唯一来源——总纲涉及文件节归 prompts.py,14d 阶段 1 先落地或同批,本片消费不重复造);总纲 docs/work-packages/WP-14.md(2026-09-16 定稿)|下游:WP-14b(headless)/ WP-14c(TUI)消费本片接口

防御剂量(总指挥 2026-09-16 分级):**T2**(正确性一轮评审);其中 freeze_scope 写序与 scope_confirmed/scope_updated payload 契约按 **T2+** 对待。

> 本片是总纲的基座切片:编译器、冻结助手、canonical 渲染、动态段写入助手、
> 审计 kind 注册、replay 归一化。不含任何 CLI/TUI 接线。与总纲矛盾处以总纲
> 「设计定案」节为准(引 D1–D13/Q1–Q9)。铁律不变:LLM 可解析可起草,确认权
> 在 operator,执行权在代码;护栏语法面零新增、判定逻辑零改。

## 目标

- **编译器**(总纲 69-84 契约草图落地):`compile_scope` 一次性 LLM 调用,
  独立 system prompt(内嵌护栏四种规则形态精确语义),严格 JSON 输出,
  无工具、无流式;产物经 round-trip 门禁(Q2)100% 落在 `guard/scope.py`
  既有语法内;失败给中文可行动报错。
- **冻结助手**(总纲 84-89 + D13):`freeze_scope` 唯一冻结入口——先写
  `scope.confirmed`(tmp+rename 原子覆盖)后更新 engagement.json,审计
  `scope_confirmed`/`scope_updated` payload 契约单源产出;返回 canonical
  sha256。
- **动态段写入助手单形态**(D6/D12):files.py 定义 markers
  (`<!-- foam:scope:begin -->` / `<!-- foam:scope:end -->`,定义权在本片),
  `_render_initial_md` 开箱含 markers,写入助手仅「markers 间原子重写」
  单一形态;`update_progress` 与动态段互斥降为 docstring 声明级。
- **审计 kind 注册**(边界契约):audit.py KNOWN_KINDS 增
  `scope_confirmed`/`scope_updated`/`refusal_detected` 三常量,他片只使用
  不注册。
- **replay 读侧**(总纲 132-142):`recover_scope_record` 三 kind 归一化
  (D13 映射钉死,`_resolve_scope` 链上回退 cli.py:739-748 零适配消费);
  interesting 集 +`scope_updated`;`audit_stats` +`refusals` 计数且报告
  随之显示。

## 排除项

- 任何 CLI/TUI 接线:`--scope-text`、互斥组、确认仪式、`/scope` 命令、
  ScopeConfirmCard(归 14b/14c)。
- prompts.py 一切(授权声明反拒答段、ENGAGEMENT.md 模板 markers、动态段
  占位,归 14d);loop.py 一切(replace_scope、拒答检测挂载,归 14c/14d);
  refusal.py 与拒答词表(归 14d)。
- D6 五写入点中的消费点接线(file 流装配、/scope 更新、headless 冻结、
  resume 对账)——本片只交付写入助手与 freeze_scope,消费点由各片自测
  (验收 13 分工)。
- 纯链恢复 e2e(删 engagement.json 经 cli.py `_resolve_scope` 端到端,
  归 14b 验收 8)——本片只做归一化单测(验收 17 分工)。
- scope 语法面任何扩展;`check_command`/`extract_targets`/`parse_scope`
  判定与解析逻辑零改。
- 文档四件(README/AGENTS.md/HANDOVER 归 14c;wp-ledger 本片落地时自登记,
  不在本规格写他片文档义务)。
- 编译器自动重试循环、多后端 failover、跨 engagement 缓存(总纲排除项)。

## 涉及文件(本片拥有,此外一字不动)

### 新增

- `src/foam/agent/scope_compiler.py` —— 四件 + 两个共用助手(归属理由
  总纲 Q4:agent→guard 单向依赖,产物合法性仍由 scope.py 裁决):
  - `async def compile_scope(nl_text, backend, *, corrections=(),
    current=None, audit=None) -> ScopeCompilation`
    - system prompt 为模块私有常量,内嵌 scope.py docstring(scope.py:1-27)
      四种规则形态精确语义:CIDR(单 IP 视作 /32、/128)、RFC 1034 主机名、
      `*.` 通配域(匹配任意深度子域、不匹配裸域)、URL 前缀(字符串前缀
      语义);声明严格 JSON 输出 `{"rules": [...]}`、替换语义(全量输出)、
      空规则集合法(Q9)。
    - 对话组装:[system, user];user 含 NL 全文 + `corrections` 历轮修正
      (逐条编号追加)+ `current` 现规则列表(提供时,标注替换语义)。
    - 调 `backend.chat(messages, tools=None)`(backends/base.py:440-460
      抽象签名),收集 TextDelta 拼响应全文(base.py:40-78 事件类型),
      Usage 取 token;ReasoningDelta 忽略(不入编译输出,不单独记审计)。
    - 响应解析:整体 `json.loads`;失败则剥一次 ``` 代码围栏重试;仍失败
      → `ScopeCompileError`(JSON 解析失败类)。结构校验:顶层 dict、
      `rules` 为字符串列表,否则同类报错。
    - round-trip 门禁(Q2):归一化规则行(按行拆分、去行内 `#` 注释、
      strip、丢空行,与 parse_scope 注释语义一致)→
      `render_canonical_rules` 渲染 → `parse_scope` 重解析;ValueError →
      `ScopeCompileError`(指明第几条规则及原因,parse_scope 报错自带行号
      映射);断言 `scope.rules == 归一化规则元组`(防御性,理论恒等)。
    - 审计(D7,对总纲草图的**增补参数** `audit`):提供时每次调用(含
      失败路径——失败无返回值,只有编译器能在现场落审计)append
      `llm_exchange_meta`,口径对齐 loop.py:729-737(prompt=消息序列 JSON、
      response=响应 JSON 的 llm_meta,只有哈希与 token,不记全文)。
    - `BackendError` 及其子类 → `ScopeCompileError`(
      「编译调用失败:<类别>,请检查后端后重试」,总纲 83)。
  - `@dataclass(frozen=True) ScopeCompilation`:`canonical_text`(str,
    尾部单换行;空规则集为空串)+ `scope`(round-trip 后 Scope)+
    `rules`(归一化规则元组)。
  - `class ScopeCompileError(Exception)`:中文可行动报错,三类来源
    (后端错误/JSON 解析失败/round-trip 拒绝),总纲 82-84。
  - `def freeze_scope(engagement, audit, compilation, *, source,
    nl_text=None, old_sha256=None, objective=None, compile_attempts=1) -> str`
    —— 唯一冻结入口(TUI 启动确认、/scope 确认、headless `--scope-text`
    三路复用,总纲 85-86)。`objective`/`compile_attempts` 为对草图的
    **增补参数**(D8 要求冻结助手更新 objective;D7 要求 NL payload 记
    compile_attempts——只有仪式调用方知道尝试次数)。写序钉死(D13,
    结构保证):① `scope.confirmed` 写 canonical_text 字节(tmp+rename
    原子覆盖,D1)→ ② `update_scope_metadata`(engagement.json meta)→
    ③ `objective` 提供时更新 engagement.json objective 与 ENGAGEMENT.md
    目标行(D8)→ ④ 动态段重写(D6 NL 冻结写入点;段内容经 14d
    `prompts.render_scope_section` 渲染——唯一渲染来源,本片消费不自建)
    → ⑤ audit.append(
    old_sha256 提供 → `scope_updated`,否则 `scope_confirmed`)。返回
    canonical sha256。`source ∈ {"file","nl"}`;`source="nl"` 时
    `nl_text` 必填。**file 流不调 freeze_scope**(Q8:meta 仍指原文件,
    无 scope.confirmed 落盘)——file 流的 `scope_confirmed(source="file")`
    由 14b/14c 装配侧用 `scope_event_payload` 直写审计。
  - `def scope_event_payload(scope, *, source, path, canonical_sha256,
    old_sha256=None, nl_text=None, compile_attempts=None) -> dict` ——
    payload 契约单源(D13):`path`(str;NL 流 = scope.confirmed 绝对路径,
    file 流 = as-given 原串——与 `scope_loaded.source`、engagement.json
    meta 同串,口径对齐 14b W14b-2)+ `Scope.summary()` 四键
    (scope.py:102-109)+ `canonical_sha256` + `source`;`old_sha256`
    提供时另含 `old_sha256`/`new_sha256`(=canonical_sha256);
    `nl_text` 提供时另含 `nl_sha256`/`nl_chars`/`compile_attempts`。
    freeze_scope 内部复用;14b/14c file 流装配直接消费。
- `tests/test_scope_compiler.py` —— fake 后端(tests 内定义,duck-type
  `chat` 异步生成器 + `aclose`;可脚本化 TextDelta/Usage 事件序列与
  BackendError 注入)。fixture 纪律同 test_state.py:RFC 5737 网段 +
  example.com,全部 tmp_path。

### 修改

- `src/foam/guard/scope.py` —— **最小新增** `render_canonical_rules(
  rules) -> str`(总纲 152-153):规则列表 → canonical 文本,每行一条、
  保持顺序、无注释空行、尾部单换行;空列表 → 空串。纯文本函数,置
  `scope_payload`(scope.py:468-470)附近;判定/解析逻辑零改,既有
  test_scope.py 全绿;开发日志声明。
- `src/foam/state/files.py`:
  - 模块常量 `SCOPE_SECTION_BEGIN = "<!-- foam:scope:begin -->"` /
    `SCOPE_SECTION_END = "<!-- foam:scope:end -->"`(markers 定义权在本片,
    14d 模板逐字一致,边界契约 1)。
  - `_render_initial_md`(files.py:290-308)在 scope 行之后、「## 进展」
    之前插入「## 授权范围」段,初始形态与 14d `_ENGAGEMENT_TEMPLATE`
    的动态段**逐字合一**(14d 一致性请求 2「两处初始形态合一」):标题 +
    成对 markers + 占位行「(scope 尚未冻结——确认后由 harness 写入当前
    生效的范围规则)」+「harness 维护,勿手改」说明引用块(D12:create
    路径开箱即含 markers,写入助手无插入特例)。
  - 动态段内容渲染**不在本片**:唯一渲染来源为 14d
    `prompts.render_scope_section`(总纲涉及文件节 prompts.py 条
    「动态段渲染助手」;14d 一致性请求 2「不自建第二份渲染」)——
    `update_scope_section` 的 `section` 实参与 freeze_scope ④ 一律
    消费其输出;「harness 维护,勿手改」说明为 markers 外模板静态
    文本,两份初始模板各自携带,不经写入助手重写。
  - `Engagement.update_scope_section(section: str) -> None` —— 单形态
    写入助手:markers 间内容整段替换,tmp+rename 原子写回;markers 外
    字节不变。**容错分支**(对 D12 单形态的细化,docstring 声明):模型可
    写 ENGAGEMENT.md(D6 信息面容错),markers 缺失/不成对时将完整段
    附加到文件末尾一次以恢复 markers——这是容错恢复,不构成第二写入
    形态(正常路径永远是 markers 间重写)。
  - `Engagement.update_scope_metadata(scope_path) -> dict`(总纲 143-145):
    幂等重写 `meta["scope"]`;内部 `Path.resolve()` 落绝对路径(D13:
    cli.py:739 判定不依赖 cwd)+ 文件字节 sha256;文件不存在
    FileNotFoundError;create 路径与 `_scope_metadata`(files.py:183-193)
    行为不变。
  - `Engagement.update_objective(objective: str) -> None`(D8 落点):
    engagement.json objective 覆盖 + ENGAGEMENT.md 首个匹配
    `^- 目标(\(objective\))?[:：]` 行替换为 `- 目标:{objective}`
    (无匹配行则在首个 `# ` 标题行后插入),tmp+rename。
  - `update_progress`(files.py:238-288)**行为零改**;其 docstring 与
    模块 docstring 加互斥声明:「update_progress 整文件重写会抹掉
    markers,与动态段互斥;目前运行期无调用方,未来接运行期调用方必须
    同步改造为保留动态段」(D12,声明级,不占验收条目);开发日志声明。
- `src/foam/guard/audit.py` —— KNOWN_KINDS(audit.py:41-60)增三常量并
  注册:`KIND_SCOPE_CONFIRMED = "scope_confirmed"` /
  `KIND_SCOPE_UPDATED = "scope_updated"` /
  `KIND_REFUSAL_DETECTED = "refusal_detected"`。既有注释「后续 WP 可
  扩展」即本片;append 不强制校验的现状不变。
- `src/foam/replay.py`(整体归本片,边界契约 4):
  - import 三个新 kind 常量。
  - `recover_scope_record`(replay.py:242-247)三 kind 归一化:取链上
    最后一条 `scope_loaded`/`scope_confirmed`/`scope_updated`;
    `scope_loaded` → payload 原样(既有行为,`source` 即路径);
    `scope_confirmed`/`scope_updated` → D13 映射:输出 `source` 键 =
    payload 的 `path`、`origin` 键 = payload 的 `source`(file|nl)、
    四键摘要原样透传、`canonical_sha256` 透传。缺键容忍(.get 兜底)。
    此映射是两处 source 语义(payload=来源枚举,输出=文件路径)的唯一
    转接点,使 cli.py:739-748 零适配消费。
  - `summarize_recent_rounds` interesting 集(replay.py:285-293)增
    `KIND_SCOPE_UPDATED`;行格式走 format_record 通用摘要兜底
    (replay.py:218-220),不新设专用格式。
  - `audit_stats`(replay.py:250-274)增 `"refusals": 0` 键并计数
    `KIND_REFUSAL_DETECTED`;`build_report` 统计行(replay.py:497-501)
    末尾追加「/ 拒答 {refusals} 次」(总纲 141:报告随之显示)。
  - format_record 不动(新 kind 走通用兜底);build_resume_briefing 概览
    行不动(总纲未要求)。

### 测试(更新)

- `tests/test_state.py` —— create 产物 markers 成对;`update_scope_metadata`
  幂等 + 绝对路径;`update_scope_section` markers 间重写 + markers 外字节
  不变 + 容错附加;`update_objective` 一例;既有 update_progress 测试不动。
- `tests/test_replay.py` —— 归一化三 kind 各一例 + 混合链取最后一条 +
  纯 scope_loaded 旧链行为不变;`audit_stats` refusals 计数 + 旧链
  refusals=0 + 报告统计行含拒答;interesting 集简报见验收 15。

## 验收标准

1. (总纲 1)编译器契约测试(fake 后端):NL → 严格 JSON → canonical;
   断言独立 system prompt 含四种规则形态语义、`tools=None` 无工具;
   `corrections` 修正文本与 `current` 现规则注入编译对话(captured
   messages 断言);非法 JSON 一例、越语法规则一例(如「端口 80」类
   非规则文本)→ `ScopeCompileError` 中文可行动报错,round-trip 拒绝例
   指明第几条规则及原因;BackendError 一例 → 「编译调用失败:…」。
2. (总纲 2)round-trip 门禁:`render_canonical_rules` 产物经
   `parse_scope` 重解析成功且 `rules` 逐行相等;含行内注释/空行/多行
   字符串的脏输入经归一化后 round-trip 仍成立;空规则集合法(Q9,
   canonical 为空串)一例。无第三套语法面。
3. (总纲 3,**T2+**)冻结一致性:tmp engagement 上 freeze_scope 后,
   `scope.confirmed` 落盘字节 sha256 = 审计 payload `canonical_sha256` =
   engagement.json meta sha256;写入后目录无 tmp 残留;payload 必含
   `path`(scope.confirmed **绝对**路径)+ cidrs/hosts/wildcards/
   url_prefixes 四键摘要 + `source`;`old_sha256` 提供 → kind 为
   `scope_updated` 且含 old/new_sha256;NL 来源 → 含 nl_sha256/nl_chars/
   compile_attempts;`objective` 提供时 engagement.json 与 ENGAGEMENT.md
   目标行同步更新(D8)一例;每次 compile_scope(audit=…) 调用(成功与
   失败各一)落 `llm_exchange_meta`(D7);④ 动态段重写一例——内容 =
   14d `prompts.render_scope_section` 输出,markers 外字节不变。
4. (总纲 13,助手级)`update_scope_section` 单形态:markers 间重写后
   markers 外内容字节不变(含模型手写段落保留)一例;连续两次写入幂等
   一例;markers 缺失容错附加重建一例。D6 五写入点消费侧分工:NL 冻结 /
   /scope 更新 / headless 冻结均经 freeze_scope 内部重写(随本片验收 3
   与 14b/14c 链路覆盖);落在 cli.py 的两点(file 流装配、resume 对账)
   归属待总指挥裁(14b 一致性请求 5,本片不预置)。
5. (总纲 14)`audit_stats` 含 `refusals` 键:手工构造含 `refusal_detected`
   记录的链计数正确一例;报告统计行显示拒答计数一例;旧链(无新 kind)
   stats/replay 行为不变(refusals=0,不炸)一例。
6. (总纲 15)interesting 集含 `scope_updated`:构造含 scope_updated 的
   链,`summarize_recent_rounds` 输出出现该变更行(format_record 通用
   兜底格式)一例;无 scope_updated 的旧链简报行为不变一例。
7. (总纲 16)create 路径 `_render_initial_md` 产物开箱即含 markers 成对
   一例;初始形态(标题/占位行/说明引用块)与 14d `_ENGAGEMENT_TEMPLATE`
   动态段逐字合一一例;`update_progress` 互斥声明入 files.py docstring
   (声明级,不占测试);既有 test_state.py 全绿。
8. (总纲 17,replay 归一化部分,**T2+**)归一化单测:仅含
   `scope_confirmed`/`scope_updated`(无 `scope_loaded`)的链 → 输出
   `source`=path、`origin`=file|nl、四键摘要逐键相等;混合三 kind 链取
   最后一条;归一化记录键集满足 cli.py:739-748 消费面(source 可作文件
   路径、四键可逐键比对)——以模拟 `_resolve_scope` 比对逻辑的单测断言,
   纯链恢复 e2e 归 14b。
9. (总纲 11,本片部分)开发日志 `docs/dev-logs/WP-14a.md` 记录真实
   pytest 输出;scope.py 最小新增、update_progress 互斥声明、file 流
   payload as-given 口径(对齐 14b W14b-2)与渲染助手归属(14d
   prompts.py)逐条声明;wp-ledger 自登记本片(README/AGENTS.md/
   HANDOVER 归 14c)。

## 设计定案引用与细化声明

- 全文遵循 D1(canonical 落盘形态)/ D4(编译输出永不可信,round-trip +
  operator 确认双闸门——本片交付闸门之一)/ D5(后端复用,CLI 层构造)/
  D6(五写入点,本片交付写入助手)/ D7(编译调用审计)/ D8(冻结时
  objective 更新)/ D12(单形态)/ D13(payload 契约与写序)/ Q2
  (round-trip)/ Q4(agent 归属)/ Q9(空 rules 合法)。
- 对总纲契约草图(69-89)的三处增补,不矛盾、已注理由:
  `compile_scope` 增 `audit` 参数(D7 失败路径只有编译器能落审计);
  `freeze_scope` 增 `objective`(D8)与 `compile_attempts`(D7)参数。
- file 流 `scope_confirmed(source="file")` 的 payload:`path` = 原 scope
  文件 **as-given 原串**(与 `scope_loaded.source`、engagement.json meta
  同串)、`canonical_sha256` = 原文件字节 sha256(= meta sha256,冻结物
  = 文件本体,Q8 回归边界)——与 14b W14b-2 逐字对齐(2026-09-16 跨片
  对账拍板):file 流逐字节回归(总纲验收 6)压倒绝对路径注记;file 流
  链上回退(cli.py:739)的 cwd 相关性是既有 `scope_loaded` 口径,不在
  本 WP 改动面。D13 字面「path(scope.confirmed 绝对路径)」按 NL 流写。
- 动态段渲染助手归属:唯一来源为 14d `prompts.render_scope_section`
  (总纲涉及文件节 prompts.py 条「动态段渲染助手」);本片原草拟的
  files.py 渲染函数撤除(2026-09-16 跨片对账:满足 14d 一致性请求 2,
  消除双渲染源与空规则文案分歧)。`update_scope_section` 保持
  `section: str` 入参、markers 间原子重写不变。
- 动态段 markers 缺失容错附加分支为 D12「单形态」的容错细化(信息面
  容错,D6),正常路径永远 markers 间重写。
