"""scope 编译器与冻结助手(WP-14a:scope 编译与冻结基座)。

铁律落地形态(定案 D4 双闸门):LLM 可解析可起草,确认权在 operator,执行权
在代码。本模块交付两道闸门中的第一道——**编译产物永不可信**,须经
round-trip 门禁(Q2):归一化 → ``render_canonical_rules`` 渲染 canonical 文本
→ ``parse_scope`` 重解析,任一失败即拒,保证产物 100% 落在 ``guard/scope.py``
既有语法内(语法面零新增)。第二道闸门(operator 确认)归 14b/14c 仪式。

归属理由(定案 Q4):``guard/`` 是 LLM-free 护栏层;编译器要调后端,依赖方向
保持 agent→guard 单向,产物合法性仍由 ``guard/scope.py`` 裁决。

- ``compile_scope``:一次性 LLM 调用,独立 system prompt(内嵌四种规则形态
  精确语义),严格 JSON 输出,无工具、无流式;失败给中文可行动报错。
- ``freeze_scope``:唯一冻结入口(TUI 启动确认、/scope 确认、headless
  ``--scope-text`` 三路复用);写序钉死(定案 D13,结构保证)——
  ① ``scope.confirmed``(tmp+rename 原子覆盖)→ ② ``update_scope_metadata``
  (engagement.json meta)→ ③ ``objective`` 提供时更新 engagement.json 与
  ENGAGEMENT.md 目标行(D8)→ ④ 动态段重写(D6;渲染唯一来源为 14d
  ``prompts.render_scope_section``,本片消费不自建)→ ⑤ 审计
  (``scope_confirmed``/``scope_updated``,payload 契约单源
  ``scope_event_payload``)。返回 canonical sha256。
- 审计(D7):``compile_scope`` 带 ``audit`` 形参,提供时每次调用(含失败
  路径——失败无返回值,只有编译器能在现场落审计)落 ``llm_exchange_meta``,
  口径对齐 loop.py:729-737(只有哈希与 token,不记全文);调用侧不得重复落。
- file 流不调 ``freeze_scope``(Q8:meta 仍指原文件,无 scope.confirmed
  落盘);file 流的 ``scope_confirmed(source="file")`` 由 14b/14c 装配侧用
  ``scope_event_payload`` 直写审计(``path`` = as-given 原串)。
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from foam.agent import prompts
from foam.agent.backends.base import (
    BackendError,
    LLMBackend,
    Message,
    TextDelta,
    Usage,
)
from foam.agent.loop import message_to_dict
from foam.guard.audit import (
    KIND_LLM_EXCHANGE_META,
    KIND_SCOPE_CONFIRMED,
    KIND_SCOPE_UPDATED,
    AuditLog,
    llm_meta,
)
from foam.guard.scope import Scope, parse_scope, render_canonical_rules
from foam.state.files import Engagement

#: 编译器独立 system prompt(模块私有常量):内嵌 guard/scope.py docstring
#: (scope.py:1-27)四种规则形态的精确语义,声明严格 JSON 输出、替换语义
#: (全量输出)与空规则集合法(Q9)。
_SYSTEM_PROMPT = """\
你是 scope 规则编译器:把操作员的自然语言授权范围描述,编译为护栏 scope 规则
列表。你的输出会被程序做严格语法门禁校验(round-trip),任何一条不合语法的
规则都会导致整体编译失败——只输出合法规则,不要自由发挥。

# 规则语法(只有四种形态,此外一切皆非法)

1. CIDR 网段:如 192.168.56.0/24、2001:db8::/32;单个 IP 视作 /32(IPv4)
   或 /128(IPv6),裸写单个 IP(如 192.168.56.10)也合法。
2. 主机名:RFC 1034 合法主机名,如 localhost、metasploitable.testlab.local。
3. 通配域:*. 前缀,如 *.example.com——匹配任意深度子域(a.b.example.com 也
   算),但不匹配裸域 example.com 本身;要覆盖裸域须单独再写一条 example.com。
4. URL 前缀:带 scheme 的 URL,如 http://127.0.0.1:3000/——字符串前缀语义,
   凡以该串开头的 URL 都在范围内。

# 输出契约

- 只输出一个 JSON 对象:{"rules": ["规则一", "规则二", ...]};不要输出任何
  其他文字、解释或 markdown 代码围栏。
- 每条规则是数组里的一个字符串,为上述四种形态之一;端口、协议、排除项、
  时间窗等概念语法不支持,一律不得写入规则。
- 替换语义:每次输出都是全量新规则列表,完整替换旧规则,不是增量追加——
  需要保留的旧规则必须照样写出。
- 保持规则顺序稳定、去重。
- 空规则集合法:描述中没有任何可识别的范围内容时,输出 {"rules": []}
  (语义 = 拒绝一切网络目标,fail-closed),不要编造规则。
"""


class ScopeCompileError(Exception):
    """编译失败的中文可行动报错。三类来源:

    - 后端错误:「编译调用失败:<类别>,请检查后端后重试」;
    - JSON 解析失败:输出非合法 JSON(剥除一次代码围栏后仍失败)或结构不符;
    - round-trip 拒绝:产物越出护栏语法,报错指明第几条规则及原因。
    """


@dataclass(frozen=True)
class ScopeCompilation:
    """编译产物(已过 round-trip 门禁,Q2)。

    - ``canonical_text``:canonical 文本(每行一条、保持顺序、无注释空行、
      尾部单换行;空规则集为空串),即 ``scope.confirmed`` 的落盘形态(D1);
    - ``scope``:round-trip 后的 ``Scope``(确认卡展示、落盘、护栏执行三者
      是同一个对象);
    - ``rules``:归一化规则元组(与 ``scope.rules`` 恒等)。
    """

    canonical_text: str
    scope: Scope
    rules: tuple[str, ...]


#: 剥一次 ``` 代码围栏用(整体被围栏包裹时取 body)。
_FENCE_RE = re.compile(r"^```[A-Za-z0-9]*[ \t]*\n(?P<body>.*?)\n?```[ \t]*$", re.DOTALL)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _build_user_message(
    nl_text: str, corrections: Sequence[str], current: Sequence[str] | None
) -> str:
    """编译对话的 user 消息:NL 全文 + 历轮修正(逐条编号追加)+ 现规则
    (提供时,标注替换语义)。NL 原文只进编译对话,不进主环上下文(D4)。"""
    parts = ["# 操作员授权范围描述\n\n" + nl_text.strip()]
    if corrections:
        lines = ["# 操作员历轮修正意见(须全部吸收进本次输出)"]
        for i, correction in enumerate(corrections, start=1):
            lines.append(f"{i}. {correction.strip()}")
        parts.append("\n".join(lines))
    if current:
        parts.append(
            "# 当前生效规则(替换语义:本次输出将全量替换以下规则)\n\n"
            + "\n".join(current)
        )
    return "\n\n".join(parts)


def _strip_code_fence(text: str) -> str | None:
    """整体被 ``` 围栏包裹时剥一层取 body;否则返回 None。"""
    match = _FENCE_RE.match(text.strip())
    return match.group("body") if match else None


def _extract_rules(text: str) -> tuple[str, ...]:
    """响应解析:整体 json.loads;失败剥一次代码围栏重试;仍失败或结构不符
    (顶层非 dict / rules 非字符串列表)→ ScopeCompileError(JSON 解析失败类)。"""
    data: Any = None
    parsed = False
    for candidate in (text, _strip_code_fence(text)):
        if candidate is None:
            continue
        try:
            data = json.loads(candidate)
            parsed = True
            break
        except json.JSONDecodeError:
            continue  # 容忍一次围栏,落入统一报错
    if not parsed:
        raise ScopeCompileError(
            "编译输出不是合法 JSON(剥除一次代码围栏后仍解析失败);"
            "请重试,或改用更明确的范围描述(网段/主机名/域名/URL)"
        ) from None
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("rules"), list)
        or any(not isinstance(rule, str) for rule in data["rules"])
    ):
        raise ScopeCompileError(
            '编译输出结构不符:需要 JSON 对象 {"rules": [规则字符串, ...]};'
            "请重试,或通过修正意见说明范围"
        )
    return tuple(data["rules"])


def _normalize_rules(raw_rules: Sequence[str]) -> tuple[str, ...]:
    """归一化规则行:按行拆分、去行内 ``#`` 注释、strip、丢空行——与
    ``parse_scope`` 的注释语义一致(编译产物可能是多行串/行内注释/空行)。"""
    normalized: list[str] = []
    for raw in raw_rules:
        for line in raw.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                normalized.append(line)
    return tuple(normalized)


def _roundtrip(rules: tuple[str, ...]) -> ScopeCompilation:
    """round-trip 门禁(Q2):渲染 canonical → parse_scope 重解析,不合法即拒。"""
    canonical_text = render_canonical_rules(rules)
    try:
        scope = parse_scope(canonical_text)
    except ValueError as exc:
        # parse_scope 报错自带行号,行号即归一化规则序号(1 起)
        detail = str(exc)
        match = re.search(r"第 (\d+) 行", detail)
        if match and 1 <= (n := int(match.group(1))) <= len(rules):
            detail = f"第 {n} 条规则 {rules[n - 1]!r} 不合语法({detail})"
        raise ScopeCompileError(
            f"编译产物被护栏语法门禁拒绝:{detail};"
            "请通过修正意见给出正确写法(CIDR/主机名/*.通配域/URL 前缀)后重试"
        ) from exc
    if scope.rules != rules:
        # 防御性断言(理论恒等):归一化与 parse_scope 同语义,round-trip 必保序
        raise AssertionError("round-trip 不变量失守:parse_scope.rules != 归一化规则")
    return ScopeCompilation(canonical_text=canonical_text, scope=scope, rules=rules)


def _append_compile_audit(
    audit: AuditLog | None, messages: Sequence[Message], text: str, usage: Usage
) -> None:
    """D7:每次编译调用落一条 llm_exchange_meta(口径对齐 loop.py:729-737:
    prompt=消息序列 JSON、response=响应 JSON;只有哈希与 token,不记全文)。"""
    if audit is None:
        return
    audit.append(
        KIND_LLM_EXCHANGE_META,
        llm_meta(
            json.dumps(
                [message_to_dict(m) for m in messages],
                ensure_ascii=False,
                sort_keys=True,
            ),
            json.dumps({"text": text}, ensure_ascii=False, sort_keys=True),
            prompt_tokens=usage.input_tokens or None,
            response_tokens=usage.output_tokens or None,
        ),
    )


async def compile_scope(
    nl_text: str,
    backend: LLMBackend,
    *,
    corrections: Sequence[str] = (),
    current: Sequence[str] | None = None,
    audit: AuditLog | None = None,
) -> ScopeCompilation:
    """把自然语言授权范围编译为护栏规则(一次性 LLM 调用,无工具、无流式)。

    - ``corrections``:operator 历轮修正意见(逐条编号追加进编译上下文);
    - ``current``:/scope 中途改时的现规则列表(编译始终输出全量新规则,
      替换语义);
    - ``audit``:提供时每次调用(含失败路径)落 llm_exchange_meta(D7),
      调用侧不得重复落。

    失败抛 ``ScopeCompileError``(三类来源见类 docstring)。
    """
    messages = [
        Message.system(_SYSTEM_PROMPT),
        Message.user(_build_user_message(nl_text, corrections, current)),
    ]
    text_parts: list[str] = []
    usage = Usage()
    backend_error: BackendError | None = None
    agen = None
    try:
        agen = backend.chat(messages, tools=None)
        async for event in agen:
            if isinstance(event, TextDelta):
                text_parts.append(event.text)
            elif isinstance(event, Usage):
                usage = event
            # ReasoningDelta 忽略(不入编译输出,不单独记审计);
            # tools=None 下不应出现 ToolCall,出现也不进编译输出。
    except BackendError as exc:
        backend_error = exc
    finally:
        if agen is not None:
            try:
                await agen.aclose()
            except BackendError as exc:
                # aclose 阶段的 BackendError 同属「编译调用失败」,且不得跳过审计
                if backend_error is None:
                    backend_error = exc
        # D7:每次编译调用(含失败路径)落 llm_exchange_meta——放进 finally:
        # 即使非 BackendError 的内部异常逃逸,审计也先于传播落盘;每次调用
        # 恰一条,调用侧不得重复落。
        text = "".join(text_parts)
        _append_compile_audit(audit, messages, text, usage)

    if backend_error is not None:
        raise ScopeCompileError(
            f"编译调用失败:{type(backend_error).__name__},请检查后端后重试"
            f"({backend_error})"
        ) from backend_error
    return _roundtrip(_normalize_rules(_extract_rules(text)))


def scope_event_payload(
    scope: Scope,
    *,
    source: str,
    path: str,
    canonical_sha256: str,
    old_sha256: str | None = None,
    nl_text: str | None = None,
    compile_attempts: int | None = None,
) -> dict[str, Any]:
    """``scope_confirmed``/``scope_updated`` 的 payload 契约单源(定案 D13)。

    - ``path``:NL 流 = scope.confirmed 绝对路径;file 流 = as-given 原串
      (与 ``scope_loaded.source``、engagement.json meta 同串,对齐 14b
      W14b-2:file 流逐字节回归压倒绝对路径注记);
    - 四键摘要(cidrs/hosts/wildcards/url_prefixes)与 ``Scope.summary()``
      同构;
    - ``old_sha256`` 提供时另含 ``old_sha256``/``new_sha256``
      (=canonical_sha256);
    - ``nl_text`` 提供时另含 ``nl_sha256``/``nl_chars``/``compile_attempts``
      (D7;NL 原文不进审计链——operator 如需留存可自行放入 engagement 目录)。

    ``freeze_scope`` 内部复用;14b/14c 的 file 流装配直接消费本函数直写审计。
    """
    payload: dict[str, Any] = {
        "path": str(path),
        **scope.summary(),
        "canonical_sha256": canonical_sha256,
        "source": source,
    }
    if old_sha256 is not None:
        payload["old_sha256"] = old_sha256
        payload["new_sha256"] = canonical_sha256
    if nl_text is not None:
        payload["nl_sha256"] = hashlib.sha256(nl_text.encode("utf-8")).hexdigest()
        payload["nl_chars"] = len(nl_text)
        payload["compile_attempts"] = compile_attempts
    return payload


def freeze_scope(
    engagement: Engagement,
    audit: AuditLog,
    compilation: ScopeCompilation,
    *,
    source: str,
    nl_text: str | None = None,
    old_sha256: str | None = None,
    objective: str | None = None,
    compile_attempts: int = 1,
) -> str:
    """唯一冻结入口(定案 D13 写序钉死,结构保证)。返回 canonical sha256。

    ``source ∈ {"file", "nl"}``;``source="nl"`` 时 ``nl_text`` 必填(D7)。
    **file 流不调本函数**(Q8:meta 仍指原文件,无 scope.confirmed 落盘)——
    file 流的 ``scope_confirmed(source="file")`` 由 14b/14c 装配侧用
    ``scope_event_payload`` 直写审计。``objective``/``compile_attempts`` 为对
    总纲草图的增补参数(D8 要求冻结时更新 objective;D7 要求 NL payload 记
    compile_attempts——只有仪式调用方知道尝试次数)。

    写序:① ``scope.confirmed`` 写 canonical_text 字节(tmp+rename 原子覆盖,
    D1)→ ② ``update_scope_metadata``(engagement.json meta,绝对路径 +
    字节 sha256)→ ③ ``objective`` 提供时更新 engagement.json objective 与
    ENGAGEMENT.md 目标行(D8)→ ④ 动态段重写(D6;段内容经 14d
    ``prompts.render_scope_section`` 渲染——唯一渲染来源,本片消费不自建)→
    ⑤ audit.append(old_sha256 提供 → ``scope_updated``,否则
    ``scope_confirmed``)。崩溃窗口内 engagement.json meta 指向旧哈希,resume
    走既有 drift 报错 fail-closed 兜底(D13)。
    """
    if source not in ("file", "nl"):
        raise ValueError(f'source 必须是 "file" 或 "nl":{source!r}')
    if source == "nl" and nl_text is None:
        raise ValueError(
            'source="nl" 时 nl_text 必填(定案 D7:NL payload 记 '
            "nl_sha256/nl_chars/compile_attempts)"
        )

    confirmed_path = engagement.paths.root / "scope.confirmed"
    data = compilation.canonical_text.encode("utf-8")
    canonical_sha256 = hashlib.sha256(data).hexdigest()

    # ① scope.confirmed 落盘(tmp+rename 原子覆盖)
    tmp_path = confirmed_path.with_name(confirmed_path.name + ".tmp")
    tmp_path.write_bytes(data)
    tmp_path.replace(confirmed_path)

    # ② engagement.json meta(内部 Path.resolve() 落绝对路径)
    meta = engagement.update_scope_metadata(confirmed_path)
    path_str = meta["scope"]["path"]

    # ③ objective 同步(D8)
    if objective is not None:
        engagement.update_objective(objective)

    # ④ 动态段重写(渲染唯一来源:14d prompts.render_scope_section)
    section = prompts.render_scope_section(
        compilation.rules,
        source=path_str,
        sha256=canonical_sha256,
        frozen_at=_utc_now_iso(),
    )
    engagement.update_scope_section(section)

    # ⑤ 审计(old_sha256 提供 → scope_updated,否则 scope_confirmed)
    kind = KIND_SCOPE_UPDATED if old_sha256 is not None else KIND_SCOPE_CONFIRMED
    audit.append(
        kind,
        scope_event_payload(
            compilation.scope,
            source=source,
            path=path_str,
            canonical_sha256=canonical_sha256,
            old_sha256=old_sha256,
            nl_text=nl_text,
            compile_attempts=compile_attempts,
        ),
    )
    return canonical_sha256
