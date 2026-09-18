"""WP-14a scope 编译器与冻结基座测试(验收 1/2/3,其中冻结一致性 T2+)。

fixture 纪律同 test_state.py(契约 §4):RFC 5737 文档保留网段
(192.0.2.0/24、198.51.100.0/24)与 example.com,engagement 一律 tmp_path。
FakeBackend 为 duck-type(chat 返回异步生成器 + aclose),可脚本化
TextDelta/Usage 事件序列与 BackendError 注入。
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from pathlib import Path

import pytest

from foam.agent import prompts
from foam.agent.backends.base import NetworkError, TextDelta, Usage
from foam.agent.scope_compiler import (
    ScopeCompilation,
    ScopeCompileError,
    compile_scope,
    freeze_scope,
    scope_event_payload,
)
from foam.guard.audit import (
    KIND_LLM_EXCHANGE_META,
    KIND_SCOPE_CONFIRMED,
    KIND_SCOPE_UPDATED,
    AuditLog,
    verify,
)
from foam.guard.scope import parse_scope, render_canonical_rules
from foam.replay import read_records
from foam.state.files import (
    SCOPE_SECTION_BEGIN,
    SCOPE_SECTION_END,
    Engagement,
)

NL_TEXT = "请对文档网段 192.0.2.0/24 做侦察,不要碰别的"
RULES_JSON = (
    '{"rules": ["192.0.2.0/24", "*.example.com", "lab.example.com", '
    '"http://192.0.2.10:8080/"]}'
)


class FakeBackend:
    """脚本化假后端(duck-type):script 每项为事件列表或 BackendError 实例;
    fail_close=True 时 aclose() 阶段抛 NetworkError(生成器清理失败形态)。"""

    provider = "fake"

    def __init__(self, script=(), *, fail_close=False):
        self._script = deque(script)
        self._fail_close = fail_close
        self.calls: list[list] = []
        self.tools_seen = "UNSET"
        self.chat_count = 0

    def chat(self, messages, tools=None):
        self.calls.append(list(messages))
        self.tools_seen = tools
        self.chat_count += 1
        entry = self._script.popleft() if self._script else [Usage(1, 1)]
        if self._fail_close:
            return _FailingCloseStream(entry)
        return self._stream(entry)

    async def _stream(self, entry):
        if isinstance(entry, BaseException):
            raise entry
        for event in entry:
            yield event

    async def aclose(self) -> None:
        pass


class _FailingCloseStream:
    """duck-type 异步迭代器:事件照常产出,aclose() 抛 BackendError。"""

    def __init__(self, events):
        self._events = deque(events)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._events:
            raise StopAsyncIteration
        return self._events.popleft()

    async def aclose(self):
        raise NetworkError("[fake] 流清理失败")


def extract_section(md: str) -> str:
    """取出 markers 之间的内容(含首尾换行),供与渲染输出逐字比对。"""
    begin = md.index(SCOPE_SECTION_BEGIN)
    content_start = md.index("\n", begin) + 1
    end = md.index(SCOPE_SECTION_END, content_start)
    end_line_start = md.rfind("\n", content_start, end) + 1
    return md[content_start:end_line_start]


@pytest.fixture()
def engagement(tmp_path):
    return Engagement.create(
        tmp_path / "engagements", "冻结仪式测试", engagement_id="fr-eng"
    )


# ================================================================ 验收 1
# 编译器契约(fake 后端)


async def test_compile_happy_path_and_independent_system_prompt():
    backend = FakeBackend([[TextDelta(RULES_JSON), Usage(10, 5)]])
    result = await compile_scope(NL_TEXT, backend)

    assert isinstance(result, ScopeCompilation)
    assert result.rules == (
        "192.0.2.0/24",
        "*.example.com",
        "lab.example.com",
        "http://192.0.2.10:8080/",
    )
    assert result.canonical_text == (
        "192.0.2.0/24\n*.example.com\nlab.example.com\nhttp://192.0.2.10:8080/\n"
    )
    # round-trip 后的 Scope 与规则逐行相等(Q2)
    assert result.scope.rules == result.rules
    assert str(result.scope.cidrs[0]) == "192.0.2.0/24"
    assert result.scope.hosts == frozenset({"lab.example.com"})
    assert result.scope.wildcards == ("example.com",)
    assert result.scope.url_prefixes == ("http://192.0.2.10:8080/",)

    # 一次性调用、无工具、[system, user] 两段对话
    assert backend.chat_count == 1
    assert backend.tools_seen is None
    messages = backend.calls[0]
    assert [m.role for m in messages] == ["system", "user"]
    assert NL_TEXT in messages[1].content

    # 独立 system prompt:内嵌四种规则形态精确语义(scope.py:1-27),
    # 且不是主环 system prompt(无「# 角色」骨架)
    system = messages[0].content
    for marker in (
        "CIDR",
        "/32",
        "/128",
        "RFC 1034",
        "通配域",
        "任意深度子域",
        "不匹配裸域",
        "URL 前缀",
        "字符串前缀",
    ):
        assert marker in system, marker
    assert "# 角色" not in system


async def test_compile_injects_corrections_and_current():
    backend = FakeBackend([[TextDelta(RULES_JSON), Usage(10, 5)]])
    await compile_scope(
        NL_TEXT,
        backend,
        corrections=["把网段收窄到 192.0.2.0/25", "去掉通配域"],
        current=("198.51.100.0/24", "old.example.com"),
    )
    user = backend.calls[0][1].content
    assert "1. 把网段收窄到 192.0.2.0/25" in user
    assert "2. 去掉通配域" in user
    assert "198.51.100.0/24" in user and "old.example.com" in user
    assert "替换语义" in user  # current 注入须标注替换语义


async def test_compile_invalid_json_raises_actionable_error():
    backend = FakeBackend([[TextDelta("好的,范围是 192.0.2.0/24。"), Usage(3, 3)]])
    with pytest.raises(ScopeCompileError) as excinfo:
        await compile_scope(NL_TEXT, backend)
    message = str(excinfo.value)
    assert "JSON" in message
    # 中文可行动指引须钉死(验收 1:「中文可行动报错」)
    assert "请重试" in message and "更明确的范围描述" in message


async def test_compile_bad_structure_raises():
    backend = FakeBackend([[TextDelta('{"rules": "192.0.2.0/24"}'), Usage(3, 3)]])
    with pytest.raises(ScopeCompileError, match="结构不符"):
        await compile_scope(NL_TEXT, backend)


async def test_compile_strips_one_code_fence():
    fenced = f"```json\n{RULES_JSON}\n```"
    backend = FakeBackend([[TextDelta(fenced), Usage(3, 3)]])
    result = await compile_scope(NL_TEXT, backend)
    assert result.rules[0] == "192.0.2.0/24"


async def test_compile_out_of_syntax_rule_rejected_with_position():
    """越语法规则(「端口 80」类非规则文本)→ round-trip 拒绝,指明第几条及原因。"""
    dirty = '{"rules": ["192.0.2.0/24", "端口 80 开放"]}'
    backend = FakeBackend([[TextDelta(dirty), Usage(3, 3)]])
    with pytest.raises(ScopeCompileError) as excinfo:
        await compile_scope(NL_TEXT, backend)
    message = str(excinfo.value)
    assert "第 2 条规则" in message
    assert "端口 80 开放" in message
    assert "不合语法" in message  # parse_scope 原因透传


async def test_compile_backend_error_wrapped():
    backend = FakeBackend([NetworkError("[fake] 连接被拒")])
    with pytest.raises(ScopeCompileError, match=r"编译调用失败:NetworkError"):
        await compile_scope(NL_TEXT, backend)
    # 中文可行动指引
    backend = FakeBackend([NetworkError("[fake] 连接被拒")])
    with pytest.raises(ScopeCompileError, match="请检查后端后重试"):
        await compile_scope(NL_TEXT, backend)


async def test_compile_aclose_backend_error_wrapped_and_audited(tmp_path):
    """aclose 阶段抛 BackendError(评审确认缺陷修复):同样包装为
    「编译调用失败:…」,且 D7 审计照落(finally 内,每次调用恰一条)。"""
    audit = AuditLog(tmp_path / "audit.jsonl")
    backend = FakeBackend(
        [[TextDelta(RULES_JSON), Usage(10, 5)]], fail_close=True
    )
    with pytest.raises(ScopeCompileError, match="编译调用失败:NetworkError"):
        await compile_scope(NL_TEXT, backend, audit=audit)
    audit.close()
    metas = [
        r
        for r in read_records(tmp_path / "audit.jsonl")
        if r["kind"] == KIND_LLM_EXCHANGE_META
    ]
    assert len(metas) == 1
    # 流正常收完才在关闭阶段失败:token 照常记录
    assert metas[0]["payload"]["prompt_tokens"] == 10
    assert metas[0]["payload"]["response_tokens"] == 5


# ================================================================ 验收 2
# round-trip 门禁(无第三套语法面)


async def test_roundtrip_gate_normalizes_dirty_input():
    """行内注释/空行/多行字符串的脏输入经归一化后 round-trip 仍成立。"""
    dirty_rules = json.dumps(
        {
            "rules": [
                "192.0.2.0/24  # 实验室网段",
                "",
                "   ",
                "198.51.100.0/24\n*.example.com",
                "# 整行注释",
            ]
        }
    )
    backend = FakeBackend([[TextDelta(dirty_rules), Usage(3, 3)]])
    result = await compile_scope(NL_TEXT, backend)
    assert result.rules == ("192.0.2.0/24", "198.51.100.0/24", "*.example.com")
    # canonical 重解析成功且 rules 逐行相等
    reparsed = parse_scope(result.canonical_text)
    assert reparsed.rules == result.rules == result.scope.rules


async def test_empty_rules_legal_q9():
    """空规则集合法(Q9):canonical 为空串,语义=拒绝一切网络目标。"""
    backend = FakeBackend([[TextDelta('{"rules": []}'), Usage(3, 3)]])
    result = await compile_scope("只是聊聊,没有任何范围内容", backend)
    assert result.rules == ()
    assert result.canonical_text == ""
    assert result.scope.rules == ()


def test_render_canonical_rules_format():
    assert render_canonical_rules(["a.example.com", "192.0.2.0/24"]) == (
        "a.example.com\n192.0.2.0/24\n"
    )
    assert render_canonical_rules([]) == ""
    assert render_canonical_rules(["  ", ""]) == ""  # 空白行丢弃
    # round-trip:产物经 parse_scope 重解析成功且逐行相等
    rules = ("192.0.2.0/24", "*.example.com", "http://192.0.2.10/")
    assert parse_scope(render_canonical_rules(rules)).rules == rules


# ================================================================ 验收 3(T2+)
# 冻结一致性:落盘字节 = 审计 payload = engagement.json meta


async def test_freeze_nl_flow_full_consistency(engagement):
    audit = AuditLog(engagement.paths.audit_jsonl)
    backend = FakeBackend([[TextDelta(RULES_JSON), Usage(10, 5)]])
    md_before = engagement.read_progress()

    compilation = await compile_scope(NL_TEXT, backend, audit=audit)
    sha = freeze_scope(
        engagement,
        audit,
        compilation,
        source="nl",
        nl_text=NL_TEXT,
        compile_attempts=2,
    )
    audit.close()

    confirmed = engagement.paths.root / "scope.confirmed"
    expected_path = str(confirmed.resolve())

    # 落盘字节 sha256 = 返回值 = engagement.json meta sha256
    assert confirmed.read_bytes() == compilation.canonical_text.encode("utf-8")
    assert hashlib.sha256(confirmed.read_bytes()).hexdigest() == sha
    meta = engagement.metadata()
    assert meta["scope"] == {"path": expected_path, "sha256": sha}
    assert Path(meta["scope"]["path"]).is_absolute()  # cli.py:739 不依赖 cwd

    # 审计 payload 契约(D13):path + 四键摘要 + canonical_sha256 + source + NL 三键
    records = read_records(engagement.paths.audit_jsonl)
    confirmed_records = [r for r in records if r["kind"] == KIND_SCOPE_CONFIRMED]
    assert len(confirmed_records) == 1
    payload = confirmed_records[0]["payload"]
    assert payload["path"] == expected_path
    assert payload["canonical_sha256"] == sha
    assert payload["source"] == "nl"
    for key in ("cidrs", "hosts", "wildcards", "url_prefixes"):
        assert payload[key] == compilation.scope.summary()[key]
    assert payload["nl_sha256"] == hashlib.sha256(NL_TEXT.encode()).hexdigest()
    assert payload["nl_chars"] == len(NL_TEXT)
    assert payload["compile_attempts"] == 2
    assert "old_sha256" not in payload and "new_sha256" not in payload

    # D7:成功路径的编译调用也落了 llm_exchange_meta(只有哈希与 token)
    meta_records = [r for r in records if r["kind"] == KIND_LLM_EXCHANGE_META]
    assert len(meta_records) == 1
    assert meta_records[0]["payload"]["prompt_tokens"] == 10
    assert meta_records[0]["payload"]["response_tokens"] == 5
    # 审计纪律:NL 原文不记全文(「不要碰别的」只存在于 NL,不进链)
    assert "不要碰别的" not in engagement.paths.audit_jsonl.read_text("utf-8")
    assert verify(engagement.paths.audit_jsonl)

    # ④ 动态段重写:内容 = 14d prompts.render_scope_section 输出(唯一渲染来源)
    section = extract_section(engagement.read_progress())
    frozen_at = re.search(r"^- 冻结时间:(.+)$", section, re.MULTILINE).group(1)
    expected = prompts.render_scope_section(
        compilation.rules, source=expected_path, sha256=sha, frozen_at=frozen_at
    )
    assert section == expected + "\n"

    # markers 外字节不变
    md_after = engagement.read_progress()
    prefix = md_before[: md_before.index(SCOPE_SECTION_BEGIN)]
    suffix = md_before[
        md_before.index(SCOPE_SECTION_END) + len(SCOPE_SECTION_END) :
    ]
    assert md_after.startswith(prefix)
    assert md_after.endswith(suffix)

    # 写入后目录无 tmp 残留
    leftovers = [p.name for p in engagement.paths.root.iterdir()]
    assert [name for name in leftovers if name.endswith(".tmp")] == []


def test_freeze_old_sha256_gives_scope_updated(engagement):
    audit = AuditLog(engagement.paths.audit_jsonl)
    first = ScopeCompilation(
        canonical_text="192.0.2.0/24\n",
        scope=parse_scope("192.0.2.0/24\n"),
        rules=("192.0.2.0/24",),
    )
    old_sha = freeze_scope(engagement, audit, first, source="nl", nl_text="先冻")

    second = ScopeCompilation(
        canonical_text="198.51.100.0/24\n",
        scope=parse_scope("198.51.100.0/24\n"),
        rules=("198.51.100.0/24",),
    )
    new_sha = freeze_scope(
        engagement, audit, second, source="nl", nl_text="改范围", old_sha256=old_sha
    )
    audit.close()

    assert new_sha != old_sha
    records = read_records(engagement.paths.audit_jsonl)
    updated = [r for r in records if r["kind"] == KIND_SCOPE_UPDATED]
    assert len(updated) == 1
    payload = updated[0]["payload"]
    assert payload["old_sha256"] == old_sha
    assert payload["new_sha256"] == new_sha == payload["canonical_sha256"]
    assert engagement.metadata()["scope"]["sha256"] == new_sha
    # 原子覆盖:scope.confirmed 已是新内容
    confirmed = engagement.paths.root / "scope.confirmed"
    assert confirmed.read_text(encoding="utf-8") == "198.51.100.0/24\n"
    assert verify(engagement.paths.audit_jsonl)


def test_freeze_objective_syncs_metadata_and_md(engagement):
    """D8:objective 提供时 engagement.json 与 ENGAGEMENT.md 目标行同步更新。"""
    audit = AuditLog(engagement.paths.audit_jsonl)
    compilation = ScopeCompilation(
        canonical_text="192.0.2.0/24\n",
        scope=parse_scope("192.0.2.0/24\n"),
        rules=("192.0.2.0/24",),
    )
    freeze_scope(
        engagement,
        audit,
        compilation,
        source="nl",
        nl_text="带上最终目标",
        objective="最终目标:复核 192.0.2.0/24 边界",
    )
    audit.close()
    assert engagement.metadata()["objective"] == "最终目标:复核 192.0.2.0/24 边界"
    md = engagement.read_progress()
    assert "- 目标:最终目标:复核 192.0.2.0/24 边界" in md
    assert "- 目标:冻结仪式测试" not in md


async def test_compile_audit_on_success_and_failure(tmp_path):
    """D7:每次 compile_scope(audit=…) 调用落 llm_exchange_meta,失败路径同。"""
    audit = AuditLog(tmp_path / "audit.jsonl")
    backend = FakeBackend([[TextDelta(RULES_JSON), Usage(10, 5)]])
    await compile_scope(NL_TEXT, backend, audit=audit)

    failing = FakeBackend([NetworkError("[fake] 超时")])
    with pytest.raises(ScopeCompileError):
        await compile_scope(NL_TEXT, failing, audit=audit)
    audit.close()

    records = read_records(tmp_path / "audit.jsonl")
    metas = [r for r in records if r["kind"] == KIND_LLM_EXCHANGE_META]
    assert len(metas) == 2  # 成功一次 + 失败一次,各落一条
    ok, failed = metas[0]["payload"], metas[1]["payload"]
    assert ok["prompt_tokens"] == 10 and ok["response_tokens"] == 5
    assert failed["prompt_tokens"] is None and failed["response_tokens"] is None
    # 口径:只有哈希与字符数,不记全文
    for payload in (ok, failed):
        assert set(payload) >= {
            "prompt_sha256",
            "response_sha256",
            "prompt_chars",
            "response_chars",
        }
    assert NL_TEXT not in (tmp_path / "audit.jsonl").read_text("utf-8")


def test_freeze_validates_source_and_nl_text(engagement):
    audit = AuditLog(engagement.paths.audit_jsonl)
    compilation = ScopeCompilation(
        canonical_text="192.0.2.0/24\n",
        scope=parse_scope("192.0.2.0/24\n"),
        rules=("192.0.2.0/24",),
    )
    with pytest.raises(ValueError, match="nl_text"):
        freeze_scope(engagement, audit, compilation, source="nl")
    with pytest.raises(ValueError, match="source"):
        freeze_scope(engagement, audit, compilation, source="api", nl_text="x")
    audit.close()
    # 校验失败不产生任何落盘/审计副作用
    assert not (engagement.paths.root / "scope.confirmed").exists()
    assert read_records(engagement.paths.audit_jsonl) == []


def test_scope_event_payload_file_flow_as_given():
    """file 流装配直写(14b/14c 消费):path = as-given 原串,不绝对化(W14b-2)。"""
    scope = parse_scope("192.0.2.0/24\n*.example.com\n")
    sha = "ab" * 32
    payload = scope_event_payload(
        scope, source="file", path="scopes/lab.scope", canonical_sha256=sha
    )
    assert payload == {
        "path": "scopes/lab.scope",  # as-given 原串,与 scope_loaded.source 同口径
        "cidrs": ["192.0.2.0/24"],
        "hosts": [],
        "wildcards": ["example.com"],
        "url_prefixes": [],
        "canonical_sha256": sha,
        "source": "file",
    }
    # 提供 old_sha256/nl_text 时的增补键
    rich = scope_event_payload(
        scope,
        source="nl",
        path="/eng/x/scope.confirmed",
        canonical_sha256="cd" * 32,
        old_sha256=sha,
        nl_text="改 scope",
        compile_attempts=3,
    )
    assert rich["old_sha256"] == sha
    assert rich["new_sha256"] == "cd" * 32
    assert rich["nl_chars"] == len("改 scope")
    assert rich["compile_attempts"] == 3
