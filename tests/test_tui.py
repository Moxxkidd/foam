"""WP-09 TUI 测试:迎宾屏 → 主界面(textual pilot)+ 契约 + ReasoningDelta 链路。

验收映射:

- 验收 1:pilot 单测——呼号门 → 主界面挂载;叙述流追加;jobs 面板更新;
  kill 二次确认状态机。
- 验收 2:fake 后端脚本化事件序列 → TUI 渲染契约(思考块/工具卡/阶段条/
  护栏拒绝/失败自展开/插话/暂停)。
- 验收 5:字标读 ``__app_name__``;tui/ 源码 grep 无硬编码品牌串。
- 验收 6:ReasoningDelta 链路——fake 后端 → loop 透传 → observer 钩子;
  审计只有 sha256/字符数,无任何明文(openai_compat 解析用 httpx
  MockTransport,合成 key 走 monkeypatch)。
- 更正当(2026-08-24)验收 1-3:idle 待命两段式(token 累计延续、待命无
  run_finished)、待命 kill 清理审计、TUI 待命提交路径(插话唤醒 +
  「已结束」提示去重)。``make_config`` 默认 ``wait_on_finish=False``
  保持既有 23 项断言语义;待命测试显式传 True。

scope 文本与命令全部为合成/无害(echo/ls 不存在目录/越界目标只到护栏)。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections import deque
from pathlib import Path

import httpx
import pytest
from textual.widgets import Button, Input

import foam.tui
from foam import __app_name__
from foam.agent.backends import openai_compat
from foam.agent.backends.base import (
    LLMBackend,
    Message,
    ReasoningDelta,
    TextDelta,
    ToolCall,
    Usage,
    event_to_dict,
)
from foam.agent.loop import (
    KIND_RUN_FINISHED,
    AgentLoop,
    LoopObserver,
    ToolRegistry,
    extract_phase,
)
from foam.agent.prompts import build_system_prompt
from foam.guard.audit import (
    KIND_KILL_SWITCH,
    KIND_OPERATOR_INTERJECT,
    KIND_SCOPE_CONFIRMED,
    KIND_SCOPE_LOADED,
    KIND_SCOPE_UPDATED,
    AuditLog,
    verify,
)
from foam.guard.scope import parse_scope, scope_payload
from foam.replay import read_records, summarize_recent_rounds
from foam.state.files import SCOPE_SECTION_BEGIN, SCOPE_SECTION_END
from foam.tools.bash import TOOL_SCHEMAS, BashTool
from foam.tui import TuiApp, TUIConfig, default_loop_factory
from foam.tui.app import load_operator, save_operator
from foam.tui.banner import GLYPH_ROWS, render_wordmark
from foam.tui.widgets import (
    InputDock,
    KillConfirmBar,
    NarrativeView,
    NoticeBlock,
    PhaseDivider,
    ScopeConfirmCard,
    SidebarPane,
    StatusBar,
    StreamBlock,
    ThinkingBlock,
    ToolCard,
    _budget_text,
    format_bytes,
    format_duration_ms,
    format_tokens,
    summarize_result,
    tool_call_display,
)

SCOPE_TEXT = "127.0.0.0/8\nlocalhost\n"
FAKE_KEY = "sk-TESTONLY-00000000000000000000000000000000"  # 合成,非真实 key


# ---------------------------------------------------------------------------
# 基座:脚本化后端 + TUI 配置/驱动辅助
# ---------------------------------------------------------------------------


class ScriptedBackend(LLMBackend):
    """脚本化后端:逐轮弹出事件列表;条目可为 callable(messages)(可挂起)。"""

    provider = "fake-k3"

    def __init__(self, script=()):
        self._script = deque(script)
        self.calls: list[list[Message]] = []
        self.chat_count = 0

    async def aclose(self) -> None:
        pass

    def chat(self, messages, tools=None):
        self.calls.append(list(messages))
        self.chat_count += 1
        return self._stream()

    async def _stream(self):
        entry = self._script.popleft() if self._script else [Usage(1, 1)]
        if callable(entry):
            entry = await entry(self.calls[-1])
        for event in entry:
            yield event


def make_config(tmp_path: Path, script, **overrides) -> TUIConfig:
    """TUI 配置:全部指向 tmp_path;script 可为 callable(ctx)→脚本(此时经
    loop_factory 在 engagement 创建后才构造后端,脚本可引用 engagement 路径)。"""
    scope_file = tmp_path / "lab.scope"
    scope_file.write_text(SCOPE_TEXT, encoding="utf-8")
    kwargs = {
        "scope": parse_scope(SCOPE_TEXT),
        "scope_source": str(scope_file),
        "backend": ScriptedBackend(),
        "model_label": "k3-fake",
        "engagements_dir": tmp_path / "engagements",
        "config_home": tmp_path / "home",
        # 更正当:TUI 真实默认是 True(连续对话);测试基座默认 False,
        # 让既有断言 finished 终态的用例语义不变,待命用例显式传 True。
        "wait_on_finish": False,
    }
    if callable(script):

        def factory(ctx):
            ctx.config.backend = ScriptedBackend(script(ctx))
            return default_loop_factory(ctx)

        kwargs["loop_factory"] = factory
    else:
        kwargs["backend"] = ScriptedBackend(script)
    kwargs.update(overrides)
    return TUIConfig(**kwargs)


async def wait_for(predicate):
    """轮询直到断言条件为真;pilot 测试里等待 loop/界面异步收敛。"""
    deadline = asyncio.get_event_loop().time() + 8.0
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.05)
    raise AssertionError("wait_for 超时:条件未达成")


async def enter_main(app: TuiApp, pilot, callsign: str = "nightowl"):
    """迎宾屏输入呼号进入主界面;返回 MainScreen。"""
    await pilot.press(*callsign)
    await pilot.press("enter")
    await wait_for(lambda: app._main is not None)
    await pilot.pause(0.2)
    return app._main


async def start_run_and_wait(app: TuiApp, pilot, objective: str = "recon lab"):
    """主界面输入 objective 启动 run 并等到收尾(final 通知块出现)。"""
    main = app._main
    await pilot.press(*objective)
    await pilot.press("enter")
    await wait_for(lambda: app._final_result is not None)

    def final_notice():
        return any(
            isinstance(w, NoticeBlock) and w.kind == "final"
            for w in main.narrative.children
        )

    await wait_for(final_notice)
    await pilot.pause(0.1)
    return main


def audit_records(app: TuiApp) -> list[dict]:
    path = app.engagement.paths.audit_jsonl
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def narrative_blocks(main, kind: type) -> list:
    return [w for w in main.narrative.children if isinstance(w, kind)]


# ---------------------------------------------------------------------------
# 纯函数单测(快速)
# ---------------------------------------------------------------------------


def test_render_wordmark_uses_app_name_constant():
    """验收 5:字标来自 __app_name__ 点阵渲染,非硬编码图样。"""
    lines = render_wordmark(__app_name__)
    assert len(lines) == GLYPH_ROWS
    assert any("█" in line for line in lines)
    # 改一个字,图样必须跟着变(证明读的是常量而不是贴死的图)
    other = render_wordmark(__app_name__[:-1] + "Z")
    assert other != lines
    # 未收录字符 → 兜底块,不抛错
    fallback = render_wordmark("~")
    assert len(fallback) == GLYPH_ROWS and any("█" in row for row in fallback)


def test_no_hardcoded_brand_string_in_tui_sources():
    """验收 5:tui/ 全部源码/样式 grep 无品牌字串(只能经 __app_name__)。
    品牌纪律已退役(2026-08-27),本测试作为品牌防回归契约保留。"""
    tui_dir = Path(foam.tui.__file__).parent
    offenders = []
    for path in sorted(tui_dir.iterdir()):
        if path.suffix in (".py", ".tcss"):
            content = path.read_text(encoding="utf-8")
            if __app_name__ in content:
                offenders.append(path.name)
    assert offenders == []


def test_extract_phase_last_match_wins():
    assert extract_phase("# 笔记\n- 最近阶段:侦察\n") == "侦察"
    # 最后一次出现为准(loop 每轮重写阶段字段)
    text = "- 最近阶段:侦察\n blah\n- 最近阶段:枚举\n"
    assert extract_phase(text) == "枚举"
    # 标题/加粗/全角冒号变体
    assert extract_phase("## 当前阶段:漏洞验证") == "漏洞验证"
    assert extract_phase("- **当前阶段**: 报告") == "报告"
    assert extract_phase("当前阶段:**利用**\n") == "利用"
    assert extract_phase("没有任何阶段字段\n") is None


def test_summarize_result_semantics():
    # 护栏拒绝:⊘ + denied + 自动展开
    marker, tone, summary, expand = summarize_result(
        "run_command",
        {"status": "denied_by_scope_guard", "violations": ["8.8.8.8"]},
    )
    assert (marker, tone, expand) == ("⊘", "denied", True)
    assert "8.8.8.8" in summary
    # error 字段:✗ + 自动展开
    assert summarize_result("run_command", {"error": "boom"})[3] is True
    # exit 0:✓ + 折叠
    marker, tone, _, expand = summarize_result(
        "run_command",
        {"status": "completed", "exit_code": 0, "duration_ms": 5, "total_bytes": 3},
    )
    assert (marker, tone, expand) == ("✓", "ok", False)
    # 非零退出:✗ + 自动展开(Q2)
    assert summarize_result(
        "run_command", {"status": "completed", "exit_code": 1}
    )[3] is True
    # 超时/被杀:自动展开
    assert summarize_result("run_command", {"status": "timeout"})[0] == "⏱"
    assert summarize_result("run_command", {"status": "killed"})[3] is True
    # 会话有待输入事件:⏳ + 自动展开(Q5 只读提醒)
    marker, _, _, expand = summarize_result(
        "session_read", {"events": [{"type": "password_prompt"}]}
    )
    assert (marker, expand) == ("⏳", True)
    assert summarize_result("session_read", {"events": []})[3] is False


def test_tool_call_display_one_line():
    assert tool_call_display("run_command", {"command": "nmap -sV 127.0.0.1"}) == (
        "nmap -sV 127.0.0.1"
    )
    # 多行命令只取首行并标记截断
    assert tool_call_display("run_command", {"command": "echo a\necho b"}).endswith(
        "…"
    )
    # 非 run_command:紧凑 JSON,上限截断
    shown = tool_call_display("read_output", {"path": "x" * 200})
    assert len(shown) <= 120 and shown.endswith("…")


def test_format_helpers_and_budget_bar():
    assert format_bytes(512) == "512B"
    assert format_bytes(2048) == "2.0KB"
    assert format_tokens(999) == "999"
    assert format_tokens(12345) == "12.3k"
    assert format_duration_ms(1500) == "1.5s"
    # 预算条:10 格 + 数值;三色阈值(文字数值始终在场,双通道)
    low = _budget_text(10, 100)
    high = _budget_text(80, 100)
    full = _budget_text(99, 100)
    assert low.plain.startswith("█") is False  # 10% → 1 格 ▓
    assert low.plain.count("▓") == 1 and "10/100" in low.plain
    assert high.plain.count("▓") == 8
    assert full.plain.count("▓") == 10
    assert "未开始" in _budget_text(None, 100).plain


# ---------------------------------------------------------------------------
# 验收 6:ReasoningDelta 链路(后端 → loop → observer;审计只有哈希)
# ---------------------------------------------------------------------------


def test_reasoning_delta_event_contract():
    """base.py 契约:序列化形状固定,进契约归一化比较不出错。"""
    event = ReasoningDelta(text="想一下")
    assert event_to_dict(event) == {"type": "reasoning_delta", "text": "想一下"}


async def test_openai_compat_parses_reasoning_content(monkeypatch):
    """openai_compat:流式 delta 的 reasoning_content → ReasoningDelta。"""
    monkeypatch.setenv(openai_compat.ENV_API_KEY, FAKE_KEY)

    def handler(request: httpx.Request) -> httpx.Response:
        chunks = [
            {"choices": [{"index": 0, "delta": {"reasoning_content": "先想"}}]},
            {"choices": [{"index": 0, "delta": {"reasoning_content": "再想"}}]},
            {"choices": [{"index": 0, "delta": {"content": "正文"}}]},
            {
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2},
            },
        ]
        lines = [f"data: {json.dumps(c)}\n\n" for c in chunks]
        body = "".join(lines) + "data: [DONE]\n\n"
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=body.encode()
        )

    backend = openai_compat.OpenAICompatBackend(
        base_url="http://fake.test/v1",
        model="fake-k3",
        transport=httpx.MockTransport(handler),
    )
    async with backend:
        events = [
            event
            async for event in backend.chat(
                [Message(role="user", content="hi")], tools=None
            )
        ]
    reasoning = [e for e in events if isinstance(e, ReasoningDelta)]
    text = [e for e in events if isinstance(e, TextDelta)]
    usage = [e for e in events if isinstance(e, Usage)]
    assert [e.text for e in reasoning] == ["先想", "再想"]
    assert [e.text for e in text] == ["正文"]
    assert usage and usage[-1].input_tokens == 3


class _RecordingObserver(LoopObserver):
    def __init__(self) -> None:
        self.reasoning: list[str] = []
        self.statuses: list[str] = []

    def on_reasoning_delta(self, text: str) -> None:
        self.reasoning.append(text)

    def on_status(self, status: str) -> None:
        self.statuses.append(status)


def _make_loop_env(tmp_path: Path, script, **loop_kw):
    scope = parse_scope(SCOPE_TEXT)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.append(KIND_SCOPE_LOADED, scope_payload(scope, "test.scope"))
    bash = BashTool(tmp_path / "outputs")
    registry = ToolRegistry()
    registry.register_module(TOOL_SCHEMAS, bash.dispatch)
    prompt = build_system_prompt(workdir=tmp_path)
    observer = _RecordingObserver()
    loop = AgentLoop(
        backend=ScriptedBackend(script),
        bash=bash,
        scope=scope,
        audit=audit,
        workdir=tmp_path,
        system_prompt=prompt,
        registry=registry,
        observer=observer,
        **loop_kw,
    )
    return loop, audit, observer


async def test_loop_reasoning_passthrough_audit_hash_only(tmp_path):
    """验收 6 主用例:observer 收到明文增量;审计只有 sha256 + 字符数。"""
    secret_thought = "这一步的推理不走审计明文"
    script = [
        [ReasoningDelta(secret_thought), TextDelta("正文"), Usage(5, 3)],
    ]
    loop, audit, observer = _make_loop_env(tmp_path, script)
    result = await loop.run("obj")
    audit.close()
    assert result.status == "finished"
    assert observer.reasoning == [secret_thought]

    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert secret_thought not in raw  # 审计链任何位置无明文
    records = (json.loads(x) for x in raw.splitlines())
    meta = [r for r in records if r["kind"] == "llm_exchange_meta"]
    assert len(meta) == 1
    payload = meta[0]["payload"]
    assert payload["reasoning_sha256"] == hashlib.sha256(
        secret_thought.encode("utf-8")
    ).hexdigest()
    assert payload["reasoning_chars"] == len(secret_thought)


async def test_loop_without_reasoning_has_no_reasoning_fields(tmp_path):
    """对照组:无思考的轮次不得出现 reasoning_* 字段(防误记)。"""
    loop, audit, _ = _make_loop_env(tmp_path, [[TextDelta("t"), Usage(1, 1)]])
    await loop.run("obj")
    audit.close()
    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "reasoning_sha256" not in raw
    assert "reasoning_chars" not in raw


# ---------------------------------------------------------------------------
# 更正当(2026-08-24):loop 常驻待命(idle-wake 连续对话)
# ---------------------------------------------------------------------------


def _audit_kinds(path: Path) -> list[str]:
    return [
        json.loads(line)["kind"]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


async def test_loop_idle_wake_two_segments(tmp_path):
    """更正当验收 1:终答 → idle 待命(无 run_finished)→ 插话唤醒续段;
    rounds/token 累计延续,objective 不变。"""
    script = [
        [TextDelta("第一段结论。"), Usage(3, 2)],  # 无工具调用 → idle 待命
        [
            TextDelta("继续挖。\n"),
            ToolCall(
                id="c1", name="run_command", arguments={"command": "echo two"}
            ),
            Usage(5, 4),
        ],
        [TextDelta("第二段结论。"), Usage(2, 1)],  # 再次终答 → 再待命
    ]
    loop, audit, observer = _make_loop_env(tmp_path, script, wait_on_finish=True)
    task = asyncio.create_task(loop.run("obj"))

    # 第一段终答 → idle 待命:run 未返回,审计无 run_finished(run 未结束)
    # (待命与构造初始态同字符串「idle」,等 on_status 迁移序列而非瞬时值)
    await wait_for(lambda: observer.statuses == ["running", "idle"])
    assert loop.status == "idle"
    assert not task.done()
    assert KIND_RUN_FINISHED not in _audit_kinds(tmp_path / "audit.jsonl")

    # 插话唤醒 → 第二段(工具轮 + 终答轮)→ 再待命
    loop.interject("keep going")
    await wait_for(lambda: loop._rounds >= 3 and loop.status == "idle")
    assert not task.done()
    assert observer.statuses == ["running", "idle", "running", "idle"]
    # rounds/token 累计延续不归零(3 轮 = 1 + 2)
    assert loop._rounds == 3
    assert loop._total_input == 3 + 5 + 2
    assert loop._total_output == 2 + 4 + 1
    # 插话作为新 user 消息进上下文;objective 仍是首条消息,不变更
    user_texts = [m.content for m in loop.messages if m.role == "user"]
    assert user_texts[0] == "obj"
    assert any("【操作员插话】keep going" in (c or "") for c in user_texts)
    assert loop._objective == "obj"
    # 待命期间始终无 run_finished;插话审计在第二段边界落下
    kinds = _audit_kinds(tmp_path / "audit.jsonl")
    assert KIND_RUN_FINISHED not in kinds
    assert KIND_OPERATOR_INTERJECT in kinds

    loop.kill("收工")
    result = await asyncio.wait_for(task, timeout=5)
    assert result.status == "killed"
    assert result.rounds == 3  # killed 结果同样带累计轮数
    audit.close()


async def test_loop_kill_from_idle_cleanup_audit(tmp_path):
    """更正当验收 2:idle 待命时 kill → killed + 既有清理面审计齐全。"""
    script = [[TextDelta("结论。"), Usage(1, 1)]]
    loop, audit, observer = _make_loop_env(tmp_path, script, wait_on_finish=True)
    task = asyncio.create_task(loop.run("obj"))
    await wait_for(lambda: observer.statuses == ["running", "idle"])
    assert KIND_RUN_FINISHED not in _audit_kinds(tmp_path / "audit.jsonl")

    loop.kill("操作员收工")
    result = await asyncio.wait_for(task, timeout=5)
    assert result.status == "killed"
    assert loop.status == "killed"
    audit.close()
    records = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    kinds = [r["kind"] for r in records]
    assert KIND_KILL_SWITCH in kinds
    kill_rec = records[kinds.index(KIND_KILL_SWITCH)]
    assert kill_rec["payload"]["reason"] == "操作员收工"
    # killed 的收尾审计是 WP-04 既有语义;且只出现在 kill 之后(待命期间无)
    assert kinds[-1] == KIND_RUN_FINISHED
    assert kinds.index(KIND_KILL_SWITCH) < kinds.index(KIND_RUN_FINISHED)
    final_rec = records[-1]
    assert final_rec["payload"]["status"] == "killed"
    assert observer.statuses == ["running", "idle", "killed"]


# ---------------------------------------------------------------------------
# 验收 1/2:pilot 测试
# ---------------------------------------------------------------------------


async def test_welcome_gate_rejects_empty_callsign(tmp_path):
    """验收 1:空呼号被拒——报错可见、停在迎宾屏、不建 engagement。"""
    app = TuiApp(make_config(tmp_path, []))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.3)
        from foam.tui.app import WelcomeScreen

        assert isinstance(app.screen, WelcomeScreen)
        await pilot.press("enter")  # 空呼号直接回车
        await pilot.pause(0.2)
        assert isinstance(app.screen, WelcomeScreen)  # 没换屏
        error = app.screen.query_one("#gate-error").content
        assert "呼号不能为空" in error
        assert app._main is None
        assert not (tmp_path / "engagements").exists() or not list(
            (tmp_path / "engagements").iterdir()
        )


async def test_full_flow_narrative_cards_and_sidebar(tmp_path):
    """验收 1+2:呼号门 → 主界面 → objective 开跑 → 叙述流/卡片/侧栏/jobs。"""
    script = [
        [
            ReasoningDelta("先看目标可达性。"),
            TextDelta("开始侦察。\n"),
            ToolCall(
                id="c1",
                name="run_command",
                arguments={"command": "echo recon 127.0.0.1"},
            ),
            Usage(10, 5),
        ],
        [ReasoningDelta("齐了。"), TextDelta("结论:目标存活。"), Usage(20, 8)],
    ]
    app = TuiApp(make_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.3)
        # 迎宾屏要素:字标/后端/scope/红线/呼号框
        logo = app.screen.query_one("#wm-logo").content
        assert logo  # 字标非空(具体内容验收 5 已锁)
        meta = app.screen.query_one("#wm-meta").content
        assert "fake-k3" in meta and "lab.scope" in meta
        assert "scope 护栏" in app.screen.query_one("#wm-redline").content

        main = await enter_main(app, pilot)
        # 主界面挂载:四大件就位,loop 未启动(Q1:首条消息前不启动)
        assert main.query_one("#statusbar", StatusBar)
        assert main.query_one("#narrative", NarrativeView)
        assert main.query_one("#sidebar", SidebarPane)
        assert main.query_one("#inputdock", InputDock)
        assert app.run_handle is None

        await start_run_and_wait(app, pilot)
        assert app._final_result.status == "finished"

        # 顶栏:engagement id + 呼号;状态 finished
        assert "呼号 nightowl" in main.query_one("#sb-center").content
        assert "已完成" in str(main.query_one("#sb-right").render())
        # 叙述流:objective 回显 → 思考块①(折叠)→ 正文① → 工具卡(✓ 折叠)
        # → 思考块② → 正文② → final(每轮思考独立成块)
        kinds = [type(w).__name__ for w in main.narrative.children]
        assert kinds == [
            "NoticeBlock",
            "ThinkingBlock",
            "StreamBlock",
            "ToolCard",
            "ThinkingBlock",
            "StreamBlock",
            "NoticeBlock",
        ]
        objective = narrative_blocks(main, NoticeBlock)[0]
        assert objective.kind == "objective"
        assert "nightowl" in objective.content and "recon lab" in objective.content
        thinkings = narrative_blocks(main, ThinkingBlock)
        assert [t.text for t in thinkings] == ["先看目标可达性。", "齐了。"]
        assert all(t.expanded is False and t.done is True for t in thinkings)
        card = narrative_blocks(main, ToolCard)[0]
        assert card.running is False and card.expanded is False
        assert "✓" in card.query_one(".card-header").content
        assert "exit 0" in card.summary
        streams = narrative_blocks(main, StreamBlock)
        assert streams[0].text == "开始侦察。\n"
        assert streams[1].text == "结论:目标存活。"
        # jobs 面板更新(验收 1):侧栏已有完成 job 记录
        await wait_for(lambda: len(main.sidebar.jobs) >= 1)
        assert "echo recon" in str(main.query_one("#side-jobs").render())
        # 呼号去向(D1):engagement.json operator 字段
        meta_json = json.loads(
            app.engagement.paths.metadata.read_text(encoding="utf-8")
        )
        assert meta_json["operator"] == "nightowl"
        # 审计:scope_loaded 在首位;reasoning 只有哈希
        records = audit_records(app)
        assert records[0]["kind"] == KIND_SCOPE_LOADED
        raw = app.engagement.paths.audit_jsonl.read_text(encoding="utf-8")
        assert "先看目标可达性" not in raw
        assert "reasoning_sha256" in raw


async def test_failed_command_card_auto_expands(tmp_path):
    """验收 2/Q2:非零退出 → 卡片自动展开,体含 stderr 与落盘行。"""
    script = [
        [
            TextDelta("试一下。\n"),
            ToolCall(
                id="c1",
                name="run_command",
                arguments={"command": "ls /nonexistent-dir-xyz"},
            ),
            Usage(4, 2),
        ],
        [TextDelta("失败已留痕。"), Usage(4, 2)],
    ]
    app = TuiApp(make_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await start_run_and_wait(app, pilot)
        card = narrative_blocks(main, ToolCard)[0]
        assert card.expanded is True  # Q2 自动展开
        header = card.query_one(".card-header").content
        assert header.startswith("✗") and "exit 1" in header
        body = card.query_one(".card-body").content
        assert "No such file or directory" in body
        assert "落盘" in body and "sha256:" in body


async def test_guard_denial_card_auto_expands_never_executes(tmp_path):
    """验收 2/Q2+红线:越界目标被护栏拒绝,卡片 ⊘ 自展开,命令永不执行。"""
    script = [
        [
            TextDelta("探测外网。\n"),
            ToolCall(
                id="c1",
                name="run_command",
                arguments={"command": "ping -c1 8.8.8.8"},
            ),
            Usage(4, 2),
        ],
        [TextDelta("被拦,改打内网。"), Usage(4, 2)],
    ]
    app = TuiApp(make_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await start_run_and_wait(app, pilot)
        card = narrative_blocks(main, ToolCard)[0]
        assert card.expanded is True
        header = card.query_one(".card-header").content
        assert header.startswith("⊘") and "护栏拒绝" in header
        assert "8.8.8.8" in card.query_one(".card-body").content
        # 护栏拒绝的命令不产生 job(outputs 目录无该命令落盘日志)
        assert main.sidebar.jobs == [] or all(
            "8.8.8.8" not in str(j.get("command")) for j in main.sidebar.jobs
        )


async def test_phase_divider_driven_by_engagement_md(tmp_path):
    """验收 2/Q3:模型写 ENGAGEMENT.md 阶段字段 → 分隔条 + 侧栏阶段。"""

    def script(ctx):
        progress = ctx.engagement.paths.progress_md
        return [
            [
                TextDelta("记录阶段。\n"),
                ToolCall(
                    id="c1",
                    name="run_command",
                    arguments={
                        "command": f"printf -- '- 最近阶段:枚举\\n' >> '{progress}'"
                    },
                ),
                Usage(4, 2),
            ],
            [TextDelta("完毕。"), Usage(4, 2)],
        ]

    app = TuiApp(make_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await start_run_and_wait(app, pilot)
        dividers = narrative_blocks(main, PhaseDivider)
        assert len(dividers) == 1 and dividers[0].phase == "枚举"
        assert "枚举" in str(main.query_one("#side-phase").render())


async def test_kill_double_confirm_state_machine(tmp_path):
    """验收 1:kill 二次确认——首次武装亮红条,Esc 解除;连按两次执行。"""
    gate = asyncio.Event()

    async def hang(messages):
        await asyncio.wait_for(gate.wait(), timeout=60)
        return [Usage(1, 1)]

    app = TuiApp(make_config(tmp_path, [hang]))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"recon lab")
        await pilot.press("enter")
        backend = app.config.backend
        await wait_for(lambda: backend.chat_count >= 1)  # 首轮在飞(挂起)
        killbar = main.query_one("#killbar", KillConfirmBar)

        # 无武装直接 Esc 不炸;第一次 Ctrl-X:武装 + 红条可见
        await pilot.press("escape")
        assert main.kill_armed is False
        await pilot.press("ctrl+x")
        await pilot.pause(0.1)
        assert main.kill_armed is True and killbar.display is True
        # Esc 解除
        await pilot.press("escape")
        await pilot.pause(0.1)
        assert main.kill_armed is False and killbar.display is False
        # 连按两次:执行 kill
        await pilot.press("ctrl+x")
        await pilot.pause(0.1)
        assert main.kill_armed is True
        await pilot.press("ctrl+x")
        await wait_for(lambda: app._final_result is not None)
        assert app._final_result.status == "killed"
        await wait_for(lambda: app.run_handle.loop.status == "killed")
        assert killbar.display is False  # 执行后收条
        kinds = [r["kind"] for r in audit_records(app)]
        assert KIND_KILL_SWITCH in kinds
        gate.set()  # 放行(实际已被 cancel;防御性)


async def test_pause_resume_toggle(tmp_path):
    """Q4:Ctrl-P 暂停(turn 边界生效)/再按继续;状态栏同步。"""
    gate = asyncio.Event()

    async def round_two(messages):
        await asyncio.wait_for(gate.wait(), timeout=30)
        # 带 tool_call:run 在第二轮后不结束,边界上 pause 才会被看到
        return [
            TextDelta("第二轮。\n"),
            ToolCall(id="c2", name="run_command", arguments={"command": "echo two"}),
            Usage(2, 1),
        ]

    script = [
        [
            TextDelta("第一轮。\n"),
            ToolCall(
                id="c1",
                name="run_command",
                arguments={"command": "echo one"},
            ),
            Usage(2, 1),
        ],
        round_two,
        [TextDelta("收尾。"), Usage(2, 1)],
    ]
    app = TuiApp(make_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"recon lab")
        await pilot.press("enter")
        backend = app.config.backend
        await wait_for(lambda: backend.chat_count >= 2)  # 第二轮在飞(挂起)
        # 暂停请求:第二轮跑完后的边界生效
        await pilot.press("ctrl+p")
        gate.set()
        await wait_for(lambda: app.run_handle.loop.status == "paused")
        await wait_for(
            lambda: "已暂停" in str(main.query_one("#sb-right").render())
        )
        # 再按继续 → 第三轮 → 跑完
        await pilot.press("ctrl+p")
        await wait_for(lambda: app._final_result is not None)
        assert app._final_result.status == "finished"


async def test_slash_commands_and_completion_popup(tmp_path):
    """验收 1/Q4:斜杠补全弹层、过滤、接受高亮;/help /status /xyz 分派。"""
    app = TuiApp(make_config(tmp_path, []))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        dock = main.query_one("#inputdock", InputDock)
        popup = dock.popup

        # 输入 "/" → 弹层出 8 条候选(WP-14c 增 /scope,7→8 有意变更)
        await pilot.press("/")
        await wait_for(lambda: dock.popup_visible)
        assert len(popup.children) == 8
        # 继续输入 "sta" → 过滤到 /status;Enter 接受高亮(不直接提交)
        await pilot.press("s", "t", "a")
        await wait_for(lambda: len(popup.children) == 1)
        await pilot.press("enter")
        await pilot.pause(0.15)
        assert dock.input_box.value == "/status"
        assert dock.popup_visible is False  # 完整命令后弹层收起
        # 再 Enter 提交 → /status 通知块(呼号/后端/状态)
        await pilot.press("enter")
        await wait_for(
            lambda: any(
                isinstance(w, NoticeBlock) and "呼号 nightowl" in w.content
                for w in main.narrative.children
            )
        )
        # /help → 帮助块;/xyz → 未知命令如实报错
        for text, expect in (("/help", "/pause"), ("/xyz", "未知命令 /xyz")):
            await pilot.press(*text)
            await pilot.press("enter")
            await wait_for(
                lambda e=expect: any(
                    isinstance(w, NoticeBlock) and e in w.content
                    for w in main.narrative.children
                )
            )
        # /jobs 与 /sessions 在无 run 时给如实提示
        await pilot.press(*"/jobs")
        await pilot.press("enter")
        await wait_for(
            lambda: any(
                isinstance(w, NoticeBlock) and "尚无 run" in w.content
                for w in main.narrative.children
            )
        )


async def test_interject_reaches_audit_with_operator(tmp_path):
    """Q4+D1:运行中插话 → ❯ 回显;审计 operator_interject 含呼号。"""
    submitted = asyncio.Event()
    seen: list[list[Message]] = []

    async def round_one(messages):
        await asyncio.wait_for(submitted.wait(), timeout=30)
        # 带 tool_call:run 继续,插话在随后的边界被排干、进第二轮 messages
        return [
            TextDelta("第一轮。\n"),
            ToolCall(id="c1", name="run_command", arguments={"command": "echo x"}),
            Usage(2, 1),
        ]

    async def round_two(messages):
        seen.append(list(messages))
        return [TextDelta("收到插话。"), Usage(2, 1)]

    app = TuiApp(make_config(tmp_path, [round_one, round_two]))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"recon lab")
        await pilot.press("enter")
        backend = app.config.backend
        await wait_for(lambda: backend.chat_count >= 1)  # 首轮挂起中
        # 普通文本 = 插话(非斜杠)
        await pilot.press(*"hold fire")
        await pilot.press("enter")
        await wait_for(
            lambda: any(
                isinstance(w, NoticeBlock)
                and w.kind == "interject"
                and "hold fire" in w.content
                for w in main.narrative.children
            )
        )
        submitted.set()
        await start_run_and_wait_no_input(app, main)
        # 插话进了第二轮的 messages(user 角色)
        flattened = [m.content for m in seen[0] if m.role == "user"]
        assert any("hold fire" in (c or "") for c in flattened)
        # 审计载荷:文本 + 呼号(D1)
        interjects = [
            r
            for r in audit_records(app)
            if r["kind"] == KIND_OPERATOR_INTERJECT
        ]
        assert len(interjects) == 1
        assert interjects[0]["payload"]["text"] == "hold fire"
        assert interjects[0]["payload"]["operator"] == "nightowl"


async def start_run_and_wait_no_input(app: TuiApp, main):
    await wait_for(lambda: app._final_result is not None)
    await wait_for(
        lambda: any(
            isinstance(w, NoticeBlock) and w.kind == "final"
            for w in main.narrative.children
        )
    )


async def test_tui_idle_submit_goes_to_interject(tmp_path):
    """更正当验收 3:idle 待命时输入文本 → loop 收到插话(呼号载荷)→
    审计 operator_interject + 叙述流插话卡,无「已结束」提示;真终态后
    「run 已结束」只发一次(观感去重)。"""
    script = [
        [TextDelta("初步结论。"), Usage(3, 2)],  # 段 1 终答 → idle 待命
        [
            TextDelta("继续挖。\n"),
            ToolCall(
                id="c1",
                name="run_command",
                arguments={"command": "echo deeper"},
            ),
            Usage(5, 4),
        ],
        [TextDelta("补充结论。"), Usage(2, 1)],  # 段 2 终答 → 再待命
    ]
    app = TuiApp(make_config(tmp_path, script, wait_on_finish=True))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"recon lab")
        await pilot.press("enter")
        await wait_for(lambda: app.run_handle is not None)
        loop = app.run_handle.loop
        # 段 1 跑完进待命(初始构造态也叫 idle,用 rounds 守卫区别)
        await wait_for(lambda: loop._rounds >= 1 and loop.status == "idle")

        # 待命状态面:顶栏「待命」+ placeholder 待命文案;run 未收尾
        await wait_for(
            lambda: "待命" in str(main.query_one("#sb-right").render())
        )
        assert main.input_dock.input_box.placeholder.startswith("待命")
        assert "Ctrl-X kill" in main.input_dock.input_box.placeholder
        assert app._final_result is None

        def ended_notices() -> list:
            return [
                w
                for w in main.narrative.children
                if isinstance(w, NoticeBlock) and "已结束" in w.content
            ]

        assert ended_notices() == []  # 待命不是终态,不得出现「已结束」

        # 输入普通文本(ASCII:pilot.press 不支持 CJK)→ 插话唤醒续段
        await pilot.press(*"keep digging")
        await pilot.press("enter")
        await wait_for(
            lambda: any(
                isinstance(w, NoticeBlock)
                and w.kind == "interject"
                and "keep digging" in w.content
                for w in main.narrative.children
            )
        )
        await wait_for(lambda: loop._rounds >= 3 and loop.status == "idle")
        # 段 2 真跑了工具(卡片在),token 累计 = 两段之和
        assert any(
            "echo deeper" in c.query_one(".card-header").content
            for c in narrative_blocks(main, ToolCard)
        )
        assert loop._total_input == 3 + 5 + 2
        assert loop._total_output == 2 + 4 + 1
        # 审计:operator_interject 含呼号载荷;仍无 run_finished、无「已结束」
        interjects = [
            r
            for r in audit_records(app)
            if r["kind"] == KIND_OPERATOR_INTERJECT
        ]
        assert len(interjects) == 1
        assert interjects[0]["payload"]["text"] == "keep digging"
        assert interjects[0]["payload"]["operator"] == "nightowl"
        assert KIND_RUN_FINISHED not in [
            r["kind"] for r in audit_records(app)
        ]
        assert ended_notices() == []
        # objective 不变更:engagement.json 仍是首条消息
        meta_json = json.loads(
            app.engagement.paths.metadata.read_text(encoding="utf-8")
        )
        assert meta_json["objective"] == "recon lab"

        # 待命态 Ctrl-X 两次 → kill(真终态)
        await pilot.press("ctrl+x")
        await pilot.pause(0.1)
        await pilot.press("ctrl+x")
        await wait_for(lambda: app._final_result is not None)
        assert app._final_result.status == "killed"
        assert main.input_dock.input_box.placeholder.startswith("run 已结束")

        # 真终态后再输入:「run 已结束」提示只发一次,不重复刷屏
        await pilot.press(*"hello again")
        await pilot.press("enter")
        await wait_for(lambda: len(ended_notices()) == 1)
        await pilot.press(*"and again")
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert len(ended_notices()) == 1


async def test_sidebar_autohide_below_110_cols_and_f2(tmp_path):
    """D3:<110 列侧栏自动隐藏,F2 唤出/收回;宽屏默认可见。"""
    app = TuiApp(make_config(tmp_path, []))
    async with app.run_test(headless=True, size=(100, 24)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        sidebar = main.query_one("#sidebar", SidebarPane)
        assert sidebar.display is False  # 100 < 110 自动隐藏
        await pilot.press("f2")
        await pilot.pause(0.1)
        assert sidebar.display is True  # F2 唤出
        await pilot.press("f2")
        await pilot.pause(0.1)
        assert sidebar.display is False


async def test_sidebar_visible_on_wide_terminal(tmp_path):
    app = TuiApp(make_config(tmp_path, []))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        assert main.query_one("#sidebar", SidebarPane).display is True
        # 手动收回后,on_resize 不得把它又顶出来(override 优先)
        await pilot.press("f2")
        await pilot.pause(0.1)
        sidebar = main.query_one("#sidebar", SidebarPane)
        assert sidebar.display is False
        await pilot.resize_terminal(150, 40)
        await pilot.pause(0.2)
        assert sidebar.display is False


async def test_operator_persisted_and_prefilled_next_launch(tmp_path):
    """D1:呼号写 ~/.foam/config.json(0600),下次启动迎宾屏预填。"""
    home = tmp_path / "home"
    app = TuiApp(make_config(tmp_path, []))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        await enter_main(app, pilot, callsign="nightowl")
    config_file = home / "config.json"
    assert json.loads(config_file.read_text(encoding="utf-8"))["operator"] == (
        "nightowl"
    )
    assert (config_file.stat().st_mode & 0o777) == 0o600
    assert load_operator(home) == "nightowl"

    # 第二次启动:呼号预填进输入框
    app2 = TuiApp(make_config(tmp_path, []))
    async with app2.run_test(headless=True, size=(140, 40)) as pilot2:
        await pilot2.pause(0.3)
        assert app2.screen.query_one("#callsign").value == "nightowl"


def test_save_operator_merges_existing_keys(tmp_path):
    """save_operator 保留配置里其他键(面向未来的本地配置)。"""
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.json").write_text(
        json.dumps({"other": 1, "operator": "old"}), encoding="utf-8"
    )
    save_operator(home, "new")
    data = json.loads((home / "config.json").read_text(encoding="utf-8"))
    assert data == {"other": 1, "operator": "new"}
    # 读取容错:坏 JSON/非字符串都按「无预填」
    (home / "config.json").write_text("not-json{{{", encoding="utf-8")
    assert load_operator(home) == ""


# ---------------------------------------------------------------------------
# WP-14c:scope 确认仪式(NL 流)与 /scope 热换
# ---------------------------------------------------------------------------

NL_OBJECTIVE = "recon 192.0.2.0/24 only"


def make_nl_config(tmp_path: Path, script, **overrides) -> TUIConfig:
    """NL 仪式流配置(scope=None,D9);其余与 make_config 同。"""
    return make_config(tmp_path, script, scope=None, scope_source="", **overrides)


def scope_card(main) -> ScopeConfirmCard | None:
    cards = list(main.narrative.query(ScopeConfirmCard))
    return cards[0] if cards else None


async def wait_scope_card(main) -> ScopeConfirmCard:
    """等确认卡挂载且当次编译落定(出结果或错误态)。"""

    def settled() -> bool:
        card = scope_card(main)
        return card is not None and card._ready and not card._compiling

    await wait_for(settled)
    card = scope_card(main)
    assert card is not None
    return card


def press_card(card: ScopeConfirmCard, button_id: str) -> None:
    card.query_one(f"#{button_id}", Button).press()


def only_engagement_root(tmp_path: Path) -> Path:
    roots = list((tmp_path / "engagements").iterdir())
    assert len(roots) == 1
    return roots[0]


def scope_section_text(root: Path) -> str:
    """ENGAGEMENT.md 动态段 markers 间内容(断言 markers 逐字成对)。"""
    text = (root / "ENGAGEMENT.md").read_text(encoding="utf-8")
    assert text.count(SCOPE_SECTION_BEGIN) == 1
    assert text.count(SCOPE_SECTION_END) == 1
    begin = text.index(SCOPE_SECTION_BEGIN) + len(SCOPE_SECTION_BEGIN)
    return text[begin : text.index(SCOPE_SECTION_END)]


def notices_containing(main, needle: str) -> list:
    return [
        w
        for w in main.narrative.children
        if isinstance(w, NoticeBlock) and needle in w.content
    ]


async def test_scope_ceremony_confirm_branch(tmp_path):
    """验收 4 确认分支:首条消息即建 engagement(meta["scope"] 为 None,D8);
    确认冻结后才调 start_run(两段结构 D9);动态段 = canonical;objective 为
    冻结时文本;链序 scope_confirmed → scope_loaded(D9 注记)。"""
    script = [
        # 编译调用(NL 流第一个 chat 调用)
        [
            TextDelta('{"rules": ["192.0.2.0/24", "lab.example.com"]}'),
            Usage(8, 3),
        ],
        [
            TextDelta("开跑。\n"),
            ToolCall(
                id="c1",
                name="run_command",
                arguments={"command": "echo alive 192.0.2.10"},
            ),
            Usage(4, 2),
        ],
        [TextDelta("收工。"), Usage(2, 1)],
    ]
    app = TuiApp(make_nl_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*NL_OBJECTIVE)
        await pilot.press("enter")
        card = await wait_scope_card(main)

        # D8:首条消息到达即建 engagement(meta["scope"] 为 None),loop 未启动
        assert app.run_handle is None
        root = only_engagement_root(tmp_path)
        meta = json.loads((root / "engagement.json").read_text(encoding="utf-8"))
        assert meta["scope"] is None
        # 确认卡:canonical 逐行 + 计数 + 短哈希 + 来源
        body = card.query_one("#scope-card-body").content
        assert "192.0.2.0/24" in body and "lab.example.com" in body
        status = card.query_one("#scope-card-status").content
        assert "共 2 条" in status and "sha256:" in status
        assert "自然语言" in status

        press_card(card, "scope-confirm")
        await wait_for(lambda: app._final_result is not None)
        assert app._final_result.status == "finished"
        await wait_for(lambda: notices_containing(main, "scope 已确认冻结") != [])
        assert scope_card(main) is None  # 卡已关闭

        # 冻结一致性:scope.confirmed 字节 = canonical;动态段 = canonical
        canonical = "192.0.2.0/24\nlab.example.com\n"
        assert (root / "scope.confirmed").read_text(encoding="utf-8") == canonical
        section = scope_section_text(root)
        assert "192.0.2.0/24" in section and "lab.example.com" in section
        # objective 与 ENGAGEMENT.md 目标行为冻结时文本(D8)
        meta = json.loads((root / "engagement.json").read_text(encoding="utf-8"))
        assert meta["objective"] == NL_OBJECTIVE
        md = (root / "ENGAGEMENT.md").read_text(encoding="utf-8")
        assert f"- 目标:{NL_OBJECTIVE}" in md
        # D10:TUI 侧权威引用已更新(meta path = scope.confirmed 绝对路径)
        assert app.config.scope is not None
        assert app.config.scope.rules == ("192.0.2.0/24", "lab.example.com")
        assert app.config.scope_source == meta["scope"]["path"]
        assert Path(meta["scope"]["path"]).is_absolute()
        assert meta["scope"]["path"].endswith("scope.confirmed")

        # 链序:llm_exchange_meta(编译)→ scope_confirmed → scope_loaded(D9 注记)
        records = read_records(root / "audit.jsonl")
        kinds = [r["kind"] for r in records]
        assert kinds[0] == "llm_exchange_meta"
        assert kinds.index(KIND_SCOPE_CONFIRMED) < kinds.index(KIND_SCOPE_LOADED)
        confirmed = records[kinds.index(KIND_SCOPE_CONFIRMED)]["payload"]
        assert confirmed["source"] == "nl"
        assert confirmed["path"] == meta["scope"]["path"]
        assert confirmed["canonical_sha256"] == hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()
        assert confirmed["cidrs"] == ["192.0.2.0/24"]
        assert confirmed["hosts"] == ["lab.example.com"]
        assert confirmed["wildcards"] == [] and confirmed["url_prefixes"] == []
        assert confirmed["compile_attempts"] == 1
        assert confirmed["nl_chars"] == len(NL_OBJECTIVE)
        assert confirmed["nl_sha256"] == hashlib.sha256(
            NL_OBJECTIVE.encode("utf-8")
        ).hexdigest()
        assert verify(root / "audit.jsonl")


async def test_scope_ceremony_correct_recompiles(tmp_path):
    """验收 4 修正分支:修正意见进 corrections 重编译,卡重渲染为新规则,
    compile_attempts 计每次调用;修正框清空;修正文本不进主输入坞。"""
    correction = "also allow 198.51.100.0/24"
    script = [
        [TextDelta('{"rules": ["192.0.2.0/24"]}'), Usage(5, 2)],
        [
            TextDelta('{"rules": ["192.0.2.0/24", "198.51.100.0/24"]}'),
            Usage(6, 3),
        ],
        [TextDelta("完成。"), Usage(2, 1)],
    ]
    app = TuiApp(make_nl_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"recon doc net")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        assert "198.51.100.0/24" not in card.query_one("#scope-card-body").content

        card.query_one("#scope-correction", Input).value = correction
        press_card(card, "scope-correct")
        await wait_for(lambda: card._attempts == 2 and not card._compiling)
        # 修正意见进编译上下文(第二次编译调用的 user 消息)
        backend = app.config.backend
        assert backend.chat_count == 2
        second_compile = backend.calls[1]
        assert any(
            correction in (m.content or "")
            for m in second_compile
            if m.role == "user"
        )
        # 卡重渲染为新规则并清空修正框
        body = card.query_one("#scope-card-body").content
        assert "198.51.100.0/24" in body and "192.0.2.0/24" in body
        assert card.query_one("#scope-correction", Input).value == ""

        press_card(card, "scope-confirm")
        await wait_for(lambda: app._final_result is not None)
        root = only_engagement_root(tmp_path)
        assert (root / "scope.confirmed").read_text(encoding="utf-8") == (
            "192.0.2.0/24\n198.51.100.0/24\n"
        )
        records = read_records(root / "audit.jsonl")
        kinds = [r["kind"] for r in records]
        confirmed_idx = kinds.index(KIND_SCOPE_CONFIRMED)
        assert records[confirmed_idx]["payload"]["compile_attempts"] == 2
        # 每次编译调用各落一条 llm_exchange_meta,且都先于 scope_confirmed(D7)
        assert kinds[:confirmed_idx].count("llm_exchange_meta") == 2
        assert verify(root / "audit.jsonl")


async def test_scope_ceremony_cancel_then_resend_reuses_engagement(tmp_path):
    """验收 4 取消分支:不启动 loop;重发(不同文本同 slug)走
    Engagement.open 复用——engagement.json 不重建(created_at 不变)、
    审计链续写、冻结以最新文本更新 objective。"""
    script = [
        [TextDelta('{"rules": ["192.0.2.0/24"]}'), Usage(5, 2)],  # 编译 1(取消)
        [TextDelta('{"rules": ["198.51.100.0/24"]}'), Usage(5, 2)],  # 编译 2(重发)
        [TextDelta("done"), Usage(1, 1)],
    ]
    app = TuiApp(make_nl_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"recon lab")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        press_card(card, "scope-cancel")
        await wait_for(lambda: notices_containing(main, "已取消") != [])
        assert app.run_handle is None  # 取消不启动 loop
        assert scope_card(main) is None
        root = only_engagement_root(tmp_path)
        meta = json.loads((root / "engagement.json").read_text(encoding="utf-8"))
        assert meta["scope"] is None
        created_at = meta["created_at"]
        assert not (root / "scope.confirmed").exists()
        kinds = [r["kind"] for r in read_records(root / "audit.jsonl")]
        assert kinds == ["llm_exchange_meta"]  # 取消路径编译仍落审计(D7)

        # 重发:不同文本、同 slug("recon   lab" → recon-lab)触发 open 复用
        await pilot.press(*"recon   lab")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        press_card(card, "scope-confirm")
        await wait_for(lambda: app._final_result is not None)
        assert only_engagement_root(tmp_path) == root  # 未新建目录
        meta = json.loads((root / "engagement.json").read_text(encoding="utf-8"))
        assert meta["created_at"] == created_at  # engagement.json 不重建
        assert meta["objective"] == "recon   lab"  # 冻结时最新文本(D8)
        md = (root / "ENGAGEMENT.md").read_text(encoding="utf-8")
        assert "- 目标:recon   lab" in md
        assert (root / "scope.confirmed").read_text(encoding="utf-8") == (
            "198.51.100.0/24\n"
        )
        # 审计链 prev_hash 续写:两次仪式共用一条链,verify 通过
        kinds = [r["kind"] for r in read_records(root / "audit.jsonl")]
        assert kinds[:3] == [
            "llm_exchange_meta",
            "llm_exchange_meta",
            KIND_SCOPE_CONFIRMED,
        ]
        assert verify(root / "audit.jsonl")


async def test_scope_ceremony_singleton_guard(tmp_path):
    """验收 4 worker 单例守卫:仪式中再发普通文本/带参 /scope 各一例,
    提示且忽略,worker 不重复启动(编译调用数不变、仍一张卡)。"""
    script = [
        [TextDelta('{"rules": ["192.0.2.0/24"]}'), Usage(5, 2)],
        [TextDelta("done"), Usage(1, 1)],
    ]
    app = TuiApp(make_nl_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"recon lab")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        backend = app.config.backend
        assert backend.chat_count == 1

        await pilot.press(*"another message")
        await pilot.press("enter")
        await wait_for(
            lambda: notices_containing(main, "scope 确认仪式进行中") != []
        )
        assert backend.chat_count == 1  # 未重复启动编译
        assert app.run_handle is None
        # 带参 /scope 同守卫
        await pilot.press(*"/scope change scope")
        await pilot.press("enter")
        await wait_for(
            lambda: len(notices_containing(main, "scope 确认仪式进行中")) == 2
        )
        assert backend.chat_count == 1
        assert len(main.narrative.query(ScopeConfirmCard)) == 1  # 仍一张卡

        press_card(card, "scope-confirm")
        await wait_for(lambda: app._final_result is not None)
        assert app._final_result.status == "finished"


async def test_scope_ceremony_compile_failure_then_correct_recovers(tmp_path):
    """验收 4 失败路径(D7):编译失败进卡错误态(确认禁用、中文报错上卡),
    llm_exchange_meta 仍落链;修正后重编译成功可确认;全程 NL 原文不进审计。"""
    script = [
        [TextDelta("not json at all"), Usage(5, 2)],  # 编译失败(JSON 解析)
        [TextDelta('{"rules": ["192.0.2.0/24"]}'), Usage(5, 2)],  # 修正后成功
        [TextDelta("done"), Usage(1, 1)],
    ]
    app = TuiApp(make_nl_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"recon lab")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        # 错误态:报错上卡、确认禁用、修正/取消可用
        assert "JSON" in card.query_one("#scope-card-body").content
        assert card.query_one("#scope-confirm", Button).disabled is True
        assert card.query_one("#scope-correct", Button).disabled is False
        root = only_engagement_root(tmp_path)
        kinds = [r["kind"] for r in read_records(root / "audit.jsonl")]
        assert kinds == ["llm_exchange_meta"]  # 失败路径也落审计
        assert json.loads((root / "engagement.json").read_text())["scope"] is None

        # 修正重编译恢复 → 确认冻结
        card.query_one("#scope-correction", Input).value = "cidr only"
        press_card(card, "scope-correct")
        await wait_for(lambda: card._compilation is not None and not card._compiling)
        press_card(card, "scope-confirm")
        await wait_for(lambda: app._final_result is not None)
        records = read_records(root / "audit.jsonl")
        kinds = [r["kind"] for r in records]
        assert kinds[:3] == [
            "llm_exchange_meta",
            "llm_exchange_meta",
            KIND_SCOPE_CONFIRMED,
        ]
        assert records[2]["payload"]["compile_attempts"] == 2
        # 审计口径:只有哈希与 token,编译应答全文不进链(D7)
        raw = (root / "audit.jsonl").read_text(encoding="utf-8")
        assert "not json at all" not in raw
        assert verify(root / "audit.jsonl")


async def test_scope_ceremony_empty_rules_q9(tmp_path):
    """Q9:空规则集合法——卡醒目文案「(空——任何网络目标都会被拒)」(文字 +
    CSS 类双通道);确认后冻结空 scope,护栏拒绝一切网络目标(fail-closed)。"""
    script = [
        [TextDelta('{"rules": []}'), Usage(3, 1)],
        [
            TextDelta("试一下。\n"),
            ToolCall(
                id="c1",
                name="run_command",
                arguments={"command": "echo probe 10.11.0.5"},
            ),
            Usage(4, 2),
        ],
        [TextDelta("全被拒。"), Usage(2, 1)],
    ]
    app = TuiApp(make_nl_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"just look around")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        body = card.query_one("#scope-card-body")
        assert "空——任何网络目标都会被拒" in body.content
        assert body.has_class("scope-empty")  # CSS 第二通道
        press_card(card, "scope-confirm")
        await wait_for(lambda: app._final_result is not None)
        root = only_engagement_root(tmp_path)
        assert (root / "scope.confirmed").read_text(encoding="utf-8") == ""
        confirmed = [
            r
            for r in read_records(root / "audit.jsonl")
            if r["kind"] == KIND_SCOPE_CONFIRMED
        ][0]["payload"]
        assert confirmed["cidrs"] == [] and confirmed["hosts"] == []
        assert confirmed["wildcards"] == [] and confirmed["url_prefixes"] == []
        # 空 scope 下 echo 10.11.0.5 被护栏拒绝(fail-closed)
        denied = narrative_blocks(main, ToolCard)[0]
        assert denied.query_one(".card-header").content.startswith("⊘")


async def test_scope_hot_swap_allows_previously_denied(tmp_path):
    """验收 5 主用例(T1 面):/scope 确认后 replace_scope 生效——换前被护栏
    拒绝的命令换后放行;D13 payload 逐键断言;system prompt 对象同一性;
    D4 隔离;D10 裸 /scope 以 TUI 侧权威引用为准;简报可见 scope_updated。"""
    correction = "add 10.11.0.0/16 instead"
    script = [
        [TextDelta('{"rules": ["192.0.2.0/24"]}'), Usage(5, 2)],  # 启动编译
        [
            TextDelta("探测。\n"),
            ToolCall(
                id="c1",
                name="run_command",
                arguments={"command": "echo probe 10.11.0.5"},
            ),
            Usage(4, 2),
        ],  # 轮 1:换前被拒
        [TextDelta("被拦,待命。"), Usage(2, 1)],  # 轮 2:终答 → idle
        [TextDelta('{"rules": ["192.0.2.0/24"]}'), Usage(5, 2)],  # /scope 编译 1
        [TextDelta('{"rules": ["10.11.0.0/16"]}'), Usage(5, 2)],  # /scope 编译 2
        [
            TextDelta("重试。\n"),
            ToolCall(
                id="c2",
                name="run_command",
                arguments={"command": "echo probe 10.11.0.5"},
            ),
            Usage(4, 2),
        ],  # 轮 3:换后放行
        [TextDelta("通了。"), Usage(2, 1)],  # 轮 4:终答 → idle
    ]
    app = TuiApp(make_nl_config(tmp_path, script, wait_on_finish=True))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"recon doc net")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        press_card(card, "scope-confirm")
        await wait_for(lambda: app.run_handle is not None)
        loop = app.run_handle.loop
        await wait_for(lambda: loop._rounds >= 2 and loop.status == "idle")
        cards = narrative_blocks(main, ToolCard)
        assert cards[0].query_one(".card-header").content.startswith("⊘")
        prompt_before = loop._system_prompt
        bash_before = loop._bash

        # /scope 热换:编译 → 修正重编译 → 确认
        await pilot.press(*"/scope switch to 10.11.0.0/16")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        backend = app.config.backend
        # current 注入:/scope 编译携带现规则(替换语义)
        update_compile = backend.calls[3]
        assert any(
            "当前生效规则" in (m.content or "") and "192.0.2.0/24" in (m.content or "")
            for m in update_compile
            if m.role == "user"
        )
        card.query_one("#scope-correction", Input).value = correction
        press_card(card, "scope-correct")
        await wait_for(lambda: card._attempts == 2 and not card._compiling)
        press_card(card, "scope-confirm")
        await wait_for(
            lambda: app.config.scope is not None
            and app.config.scope.rules == ("10.11.0.0/16",)
        )

        # D2 原子换生效;system prompt 不重建(Q3,对象同一性);bash/会话不动
        assert loop._scope.rules == ("10.11.0.0/16",)
        assert loop._system_prompt is prompt_before
        assert loop._bash is bash_before
        assert loop.status == "idle"
        # D13 payload 逐键断言
        root = app.engagement.paths.root
        records = read_records(root / "audit.jsonl")
        updated = [r for r in records if r["kind"] == KIND_SCOPE_UPDATED]
        assert len(updated) == 1
        payload = updated[0]["payload"]
        new_canonical = "10.11.0.0/16\n"
        assert payload["old_sha256"] == hashlib.sha256(
            b"192.0.2.0/24\n"
        ).hexdigest()
        assert payload["new_sha256"] == hashlib.sha256(
            new_canonical.encode()
        ).hexdigest()
        assert payload["canonical_sha256"] == payload["new_sha256"]
        assert payload["path"].endswith("scope.confirmed")
        assert Path(payload["path"]).is_absolute()
        assert payload["cidrs"] == ["10.11.0.0/16"]
        assert payload["hosts"] == [] and payload["wildcards"] == []
        assert payload["url_prefixes"] == []
        assert payload["source"] == "nl"
        assert payload["compile_attempts"] == 2
        assert payload["nl_sha256"] == hashlib.sha256(
            b"switch to 10.11.0.0/16"
        ).hexdigest()
        # ENGAGEMENT.md 动态段重写 = 新 canonical;engagement.json meta 同步
        section = scope_section_text(root)
        assert "10.11.0.0/16" in section and "192.0.2.0" not in section
        meta = json.loads((root / "engagement.json").read_text(encoding="utf-8"))
        assert meta["scope"]["sha256"] == payload["new_sha256"]
        assert meta["scope"]["path"] == payload["path"]
        assert app.config.scope_source == payload["path"]  # D10 同步
        # 换后放行:插话触发重试,命令执行成功
        await pilot.press(*"retry probe")
        await pilot.press("enter")
        await wait_for(lambda: loop._rounds >= 4 and loop.status == "idle")
        cards = narrative_blocks(main, ToolCard)
        assert len(cards) == 2
        assert "✓" in cards[1].query_one(".card-header").content
        assert "exit 0" in cards[1].summary

        # D10:裸 /scope 以 TUI 侧权威引用为准(展示新规则)
        await pilot.press(*"/scope")
        await pilot.press("enter")
        await wait_for(lambda: notices_containing(main, "当前授权 scope") != [])
        shown = notices_containing(main, "当前授权 scope")[-1].content
        assert "10.11.0.0/16" in shown and "192.0.2.0" not in shown

        # 验收 15 消费侧:简报最近 N 轮可见本次 scope 变更
        summary_lines = summarize_recent_rounds(records, 5)
        assert any("scope_updated" in line for line in summary_lines)

        # 验收 12(D4 隔离):NL 修正原文与编译对话内容在主环消息序列零出现
        all_content = "\n".join(
            m.content or "" for m in loop.messages if isinstance(m.content, str)
        )
        assert correction not in all_content
        assert "你是 scope 规则编译器" not in all_content
        assert '{"rules"' not in all_content
        assert "switch to 10.11.0.0/16" not in all_content

        loop.kill("收工")
        await wait_for(lambda: app._final_result is not None)


async def test_scope_hot_swap_denies_previously_allowed(tmp_path):
    """验收 5 反向一例:换前放行的命令,换后(收窄 scope)被护栏拒绝。"""
    script = [
        [TextDelta('{"rules": ["10.11.0.0/16"]}'), Usage(5, 2)],
        [
            TextDelta("探测。\n"),
            ToolCall(
                id="c1",
                name="run_command",
                arguments={"command": "echo probe 10.11.0.5"},
            ),
            Usage(4, 2),
        ],  # 轮 1:换前放行
        [TextDelta("通。"), Usage(2, 1)],
        [TextDelta('{"rules": ["192.0.2.0/24"]}'), Usage(5, 2)],  # /scope 收窄
        [
            TextDelta("再打。\n"),
            ToolCall(
                id="c2",
                name="run_command",
                arguments={"command": "echo probe 10.11.0.5"},
            ),
            Usage(4, 2),
        ],  # 轮 3:换后被拒
        [TextDelta("被拦。"), Usage(2, 1)],
    ]
    app = TuiApp(make_nl_config(tmp_path, script, wait_on_finish=True))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"recon lab net")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        press_card(card, "scope-confirm")
        await wait_for(lambda: app.run_handle is not None)
        loop = app.run_handle.loop

        def first_card_succeeded() -> bool:
            # 等 UI 消费轮 1 工具结果(卡片达 ✓ 终态)——不同步轮询 loop
            # 属性:loop 先置 idle,卡片 ✓ 由消息泵后处理,两者间有竞态窗口。
            cards = narrative_blocks(main, ToolCard)
            return (
                bool(cards)
                and loop.status == "idle"
                and "✓" in cards[0].query_one(".card-header").content
            )

        await wait_for(first_card_succeeded)

        await pilot.press(*"/scope narrow to doc net")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        press_card(card, "scope-confirm")
        await wait_for(lambda: loop._scope.rules == ("192.0.2.0/24",))

        await pilot.press(*"go again")
        await pilot.press("enter")

        def second_card_denied() -> bool:
            # 同上:等第二张卡(被拒)达终态,而非同步读 loop._rounds。
            cards = narrative_blocks(main, ToolCard)
            return (
                len(cards) == 2
                and loop.status == "idle"
                and cards[1].query_one(".card-header").content.startswith("⊘")
            )

        await wait_for(second_card_denied)
        cards = narrative_blocks(main, ToolCard)
        assert "10.11.0.5" in cards[1].query_one(".card-body").content
        loop.kill("收工")
        await wait_for(lambda: app._final_result is not None)


async def test_scope_predeclare_then_first_message_starts_run(tmp_path):
    """/scope 预声明(未启动 + scope None → predeclare):同一仪式冻结但不
    启动 loop;首条消息到达直接 start_run(无第二次仪式、无第二次编译)。"""
    script = [
        [TextDelta('{"rules": ["192.0.2.0/24"]}'), Usage(5, 2)],  # 预声明编译
        [TextDelta("跑完。"), Usage(1, 1)],  # loop 首轮(终答)
    ]
    app = TuiApp(make_nl_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"/scope only 192.0.2.0/24")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        press_card(card, "scope-confirm")
        await wait_for(
            lambda: notices_containing(main, "发送首条消息启动 run") != []
        )
        assert app.run_handle is None  # predeclare 不启动 loop
        assert app.config.scope is not None
        assert app.config.scope.rules == ("192.0.2.0/24",)

        await pilot.press(*"recon the lab")
        await pilot.press("enter")
        await wait_for(lambda: app._final_result is not None)
        backend = app.config.backend
        assert backend.chat_count == 2  # 1 次编译 + 1 轮 loop,无第二次仪式
        assert app._final_result.status == "finished"
        # run 的 engagement 链首位 scope_loaded 即冻结 scope(经 config 携带)
        records = read_records(app.engagement.paths.audit_jsonl)
        assert records[0]["kind"] == KIND_SCOPE_LOADED
        assert records[0]["payload"]["cidrs"] == ["192.0.2.0/24"]
        assert records[0]["payload"]["source"] == app.config.scope_source
        # 评审 B 回归:NL 冻结来源不错标——run 链上无 source="file" 补写
        assert not any(r["kind"] == KIND_SCOPE_CONFIRMED for r in records)
        # 评审 H 回归:run 的 ENGAGEMENT.md 动态段已同步为冻结规则(非占位)
        run_root = app.engagement.paths.root
        section = scope_section_text(run_root)
        assert "192.0.2.0/24" in section and "尚未冻结" not in section
        # 预声明与 run 分属两个 engagement 目录(评审 C:前缀隔命名空间)
        roots = list((tmp_path / "engagements").iterdir())
        assert len(roots) == 2
        predeclare_root = next(r for r in roots if r != run_root)
        assert "scope-predeclare" in predeclare_root.name
        # 确认事实留在预声明 engagement 链上(source="nl",含 NL 出处键)
        pre_records = read_records(predeclare_root / "audit.jsonl")
        pre_confirmed = [
            r for r in pre_records if r["kind"] == KIND_SCOPE_CONFIRMED
        ]
        assert len(pre_confirmed) == 1
        assert pre_confirmed[0]["payload"]["source"] == "nl"
        assert pre_confirmed[0]["payload"]["nl_sha256"] == hashlib.sha256(
            b"only 192.0.2.0/24"
        ).hexdigest()


async def test_scope_command_rejected_states(tmp_path):
    """/scope 状态机拒绝面(D2/Q1):file 流未启动带参 → 拒并指引;run 终态
    带参 → 拒;file 流裸 /scope 只读展示一例;scope None 裸 /scope 引导。"""
    # file 流:未启动带参拒绝 + 裸命令展示 + 全程无卡
    app = TuiApp(make_config(tmp_path, []))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"/scope widen the net")
        await pilot.press("enter")
        await wait_for(
            lambda: notices_containing(main, "已由 --scope 指定") != []
        )
        assert scope_card(main) is None
        await pilot.press(*"/scope")
        await pilot.press("enter")
        await wait_for(lambda: notices_containing(main, "当前授权 scope") != [])
        shown = notices_containing(main, "当前授权 scope")[-1].content
        assert "127.0.0.0/8" in shown and "localhost" in shown
        assert "sha256:" in shown and app.config.scope_source in shown

    # 终态拒绝:file 流跑完后带参 /scope → 「run 已结束,scope 不可更改」
    app2 = TuiApp(make_config(tmp_path, [[TextDelta("done"), Usage(1, 1)]]))
    async with app2.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app2, pilot)
        await start_run_and_wait(app2, pilot)
        assert app2.run_handle is not None and app2.active_loop is None
        await pilot.press(*"/scope widen the net")
        await pilot.press("enter")
        await wait_for(
            lambda: notices_containing(main, "run 已结束,scope 不可更改") != []
        )
        assert scope_card(main) is None
        assert not (app2.engagement.paths.root / "scope.confirmed").exists()

    # scope None( NL 流)裸 /scope → 引导
    app3 = TuiApp(make_nl_config(tmp_path, []))
    async with app3.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app3, pilot)
        await pilot.press(*"/scope")
        await pilot.press("enter")
        await wait_for(lambda: notices_containing(main, "尚未声明") != [])


async def test_file_flow_zero_ceremony_and_scope_confirmed(tmp_path):
    """验收 6(TUI 半)+ Q8 有意变更:file 流全程无 ScopeConfirmCard(编译
    调用数 = 0);链上 scope_loaded 之后有 scope_confirmed(source="file"),
    payload 按 W14b-2(path=as-given 原串、canonical_sha256=文件字节 sha256
    = engagement.json meta sha256);其余行为逐字节回归。

    注(第二轮对抗审查裁定):规格钉「scope_loaded 之后有」;本测试环境的
    kinds[1] 相邻位次是 run_test 不设 eager_task_factory 的确定性时序——
    生产 eager 下调度语义允许 run_started 先落链(run_started 先于首个
    网络 await),位次不属规格契约,记录存在性与 payload 才是。"""
    script = [[TextDelta("done"), Usage(1, 1)]]
    app = TuiApp(make_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await start_run_and_wait(app, pilot)
        assert app._final_result.status == "finished"
        assert scope_card(main) is None  # 零仪式:无确认卡
        backend = app.config.backend
        assert backend.chat_count == 1  # 只有 loop 一轮,无任何编译调用

        records = audit_records(app)
        kinds = [r["kind"] for r in records]
        assert kinds[0] == KIND_SCOPE_LOADED
        assert kinds[1] == KIND_SCOPE_CONFIRMED  # Q8 补写(测试环境时序,见 docstring)
        payload = records[1]["payload"]
        assert payload["source"] == "file"
        assert payload["path"] == app.config.scope_source  # as-given 原串
        file_sha = hashlib.sha256(
            Path(app.config.scope_source).read_bytes()
        ).hexdigest()
        assert payload["canonical_sha256"] == file_sha
        meta = app.engagement.metadata()
        assert meta["scope"]["sha256"] == file_sha  # meta 仍指原文件(Q8 边界)
        assert meta["scope"]["path"] == app.config.scope_source
        assert payload["cidrs"] == ["127.0.0.0/8"]
        assert payload["hosts"] == ["localhost"]
        assert "nl_sha256" not in payload  # file 流无 NL 键
        assert verify(app.engagement.paths.audit_jsonl)


async def test_welcome_and_bare_scope_without_scope(tmp_path):
    """D9 迎宾无 scope 分支:单行「scope 待声明(主界面确认)」+ 占位「—」;
    file 流迎宾渲染不变(既有用例锁)。"""
    app = TuiApp(make_nl_config(tmp_path, []))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.3)
        meta = app.screen.query_one("#wm-meta").content
        assert "待声明(主界面确认)" in meta
        assert "—" in meta
        assert app._scope_sha() == "—"
        await enter_main(app, pilot)


async def test_replace_scope_terminal_states_raise(tmp_path):
    """验收 5 对抗断言(loop 级):idle 可换(引用赋值即生效);finished /
    killed 终态直调 replace_scope → RuntimeError。"""
    # idle 可换 + killed 拒绝
    script = [[TextDelta("结论。"), Usage(1, 1)]]
    loop, audit, _ = _make_loop_env(tmp_path, script, wait_on_finish=True)
    task = asyncio.create_task(loop.run("obj"))
    await wait_for(lambda: loop._rounds >= 1 and loop.status == "idle")
    new_scope = parse_scope("10.0.0.0/8\n")
    loop.replace_scope(new_scope)
    assert loop._scope is new_scope  # 一次引用赋值(D2)
    loop.kill("收工")
    result = await asyncio.wait_for(task, timeout=5)
    assert result.status == "killed"
    with pytest.raises(RuntimeError):
        loop.replace_scope(parse_scope("192.0.2.0/24\n"))
    audit.close()

    # finished 拒绝
    loop2, audit2, _ = _make_loop_env(tmp_path, [[TextDelta("t"), Usage(1, 1)]])
    result2 = await loop2.run("obj")
    assert result2.status == "finished"
    with pytest.raises(RuntimeError):
        loop2.replace_scope(parse_scope("10.0.0.0/8\n"))
    audit2.close()


async def test_scope_update_ceremony_aborts_when_run_ends_mid_ceremony(tmp_path):
    """评审 A 回归(T1 冻结写序面):update 仪式挂起等卡期间 run 终态化
    (kill → 审计句柄关闭)→ 确认分支不冻结:链上无 scope_updated、
    scope.confirmed 与 config.scope 不变、如实提示、卡关闭、守卫释放。
    (修复前:freeze_scope 尾步在已关句柄上 append 炸 ValueError,落半冻结态。)"""
    script = [
        [TextDelta('{"rules": ["192.0.2.0/24"]}'), Usage(5, 2)],  # 启动编译
        [TextDelta("跑。"), Usage(2, 1)],  # 轮 1 终答 → idle
        [TextDelta('{"rules": ["10.11.0.0/16"]}'), Usage(5, 2)],  # /scope 编译
    ]
    app = TuiApp(make_nl_config(tmp_path, script, wait_on_finish=True))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"recon doc net")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        press_card(card, "scope-confirm")
        await wait_for(lambda: app.run_handle is not None)
        loop = app.run_handle.loop
        await wait_for(lambda: loop.status == "idle")

        # update 仪式挂起等卡(编译已完成)
        await pilot.press(*"/scope widen to 10.11.0.0/16")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        assert app._ceremony is not None

        # 等卡期间 run 终态化:_run_to_end 收尾并关闭共享审计句柄
        loop.kill("打断")
        await wait_for(lambda: app._final_result is not None)
        root = app.engagement.paths.root
        confirmed_before = (root / "scope.confirmed").read_text(encoding="utf-8")

        # 确认 → D2 终态拒绝:不冻结、链上无 scope_updated、守卫释放
        press_card(card, "scope-confirm")
        await wait_for(
            lambda: notices_containing(main, "run 已结束,scope 不可更改") != []
        )
        await wait_for(lambda: app._ceremony is None)
        assert scope_card(main) is None  # 卡已关闭
        assert (root / "scope.confirmed").read_text(encoding="utf-8") == (
            confirmed_before
        )
        assert app.config.scope is not None
        assert app.config.scope.rules == ("192.0.2.0/24",)
        records = read_records(root / "audit.jsonl")
        assert not any(r["kind"] == KIND_SCOPE_UPDATED for r in records)
        assert verify(root / "audit.jsonl")


async def test_scope_predeclare_cjk_no_objective_conflict(tmp_path):
    """评审 C 回归:纯中文 scope 文本与纯中文首条消息的 slug 恒同(均为
    "engagement")——预声明目录加 scope-predeclare- 前缀隔开命名空间,
    start_run 幂等复开不再撞 objective 冲突,run 照常启动。"""
    script = [
        [TextDelta('{"rules": ["192.0.2.0/24"]}'), Usage(5, 2)],  # 预声明编译
        [TextDelta("跑完。"), Usage(1, 1)],  # loop 首轮(终答)
    ]
    app = TuiApp(make_nl_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        app.submit_text("/scope 只对实验网段做侦察")  # 纯中文(CJK 无法逐键 press)
        card = await wait_scope_card(main)
        press_card(card, "scope-confirm")
        await wait_for(
            lambda: notices_containing(main, "发送首条消息启动 run") != []
        )
        assert app.run_handle is None

        app.submit_text("侦察实验网段并汇总存活主机")  # 与预声明同 slug("engagement")
        await wait_for(lambda: app._final_result is not None)
        assert app._final_result.status == "finished"  # 无 objective 冲突卡死
        roots = list((tmp_path / "engagements").iterdir())
        assert len(roots) == 2
        assert any("scope-predeclare" in r.name for r in roots)
        # run engagement 动态段已同步;链首位 scope_loaded(评审 B/H 同覆盖)
        section = scope_section_text(app.engagement.paths.root)
        assert "192.0.2.0/24" in section and "尚未冻结" not in section
        records = read_records(app.engagement.paths.audit_jsonl)
        assert records[0]["kind"] == KIND_SCOPE_LOADED
        assert verify(app.engagement.paths.audit_jsonl)


async def test_scope_hot_swap_from_file_source_keeps_hash_lineage(tmp_path):
    """评审 D 回归(D13 谱系面):file 流(scope 文件含注释,文件字节哈希
    ≠ canonical 渲染哈希)运行中 /scope 热换——scope_updated.old_sha256
    == 链上前条 source="file" 记录的 canonical_sha256(文件字节哈希),
    谱系不因渲染口径差异而断。"""
    scope_text = "# 实验室授权段\n127.0.0.0/8\nlocalhost\n"  # 含注释行
    script = [
        [
            TextDelta("打。\n"),
            ToolCall(
                id="c1",
                name="run_command",
                arguments={"command": "echo hi 127.0.0.1"},
            ),
            Usage(4, 2),
        ],
        [TextDelta("完。"), Usage(2, 1)],  # 终答 → idle
        [TextDelta('{"rules": ["10.11.0.0/16"]}'), Usage(5, 2)],  # /scope 编译
    ]
    config = make_config(tmp_path, script, wait_on_finish=True)
    scope_file = tmp_path / "lab.scope"
    scope_file.write_text(scope_text, encoding="utf-8")
    config.scope = parse_scope(scope_text)
    config.scope_source = str(scope_file)
    app = TuiApp(config)
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"recon loopback")
        await pilot.press("enter")
        await wait_for(lambda: app.run_handle is not None)
        loop = app.run_handle.loop
        await wait_for(lambda: loop.status == "idle")

        await pilot.press(*"/scope switch to 10.11.0.0/16")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        press_card(card, "scope-confirm")
        await wait_for(
            lambda: app.config.scope is not None
            and app.config.scope.rules == ("10.11.0.0/16",)
        )

        records = read_records(app.engagement.paths.audit_jsonl)
        kinds = [r["kind"] for r in records]
        file_confirmed = records[kinds.index(KIND_SCOPE_CONFIRMED)]["payload"]
        updated = [r for r in records if r["kind"] == KIND_SCOPE_UPDATED]
        assert len(updated) == 1
        payload = updated[0]["payload"]
        file_sha = hashlib.sha256(scope_text.encode("utf-8")).hexdigest()
        assert file_confirmed["source"] == "file"
        assert file_confirmed["canonical_sha256"] == file_sha
        # old_sha256 接续链上前条哈希(文件字节口径),而非 canonical 渲染口径
        assert payload["old_sha256"] == file_sha
        assert payload["old_sha256"] == file_confirmed["canonical_sha256"]
        assert payload["new_sha256"] == hashlib.sha256(
            b"10.11.0.0/16\n"
        ).hexdigest()
        assert verify(app.engagement.paths.audit_jsonl)
        loop.kill("收工")
        await wait_for(lambda: app._final_result is not None)


async def test_scope_redeclare_then_same_objective_reconciles_across_sessions(
    tmp_path,
):
    """评审 R2-1 回归(T1 状态机面):跨 session 重新预声明(新 scope)后
    发同一 objective——_prepare_nl_run_engagement 先把既有 run 目录的
    meta.scope 对账为当前冻结 scope(链上 scope_updated 留痕),start_run
    幂等复开不再撞 create 的 scope 一致性检查(修复前该 objective 当天
    永久无法启动,报错对 NL 用户无可行动指引)。"""
    # session 1:预声明 192.0.2.0/24 → 同 objective 开跑并跑完
    script1 = [
        [TextDelta('{"rules": ["192.0.2.0/24"]}'), Usage(5, 2)],
        [TextDelta("跑完。"), Usage(1, 1)],
    ]
    app1 = TuiApp(make_nl_config(tmp_path, script1))
    async with app1.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app1, pilot)
        await pilot.press(*"/scope only 192.0.2.0/24")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        press_card(card, "scope-confirm")
        await wait_for(
            lambda: notices_containing(main, "发送首条消息启动 run") != []
        )
        await pilot.press(*"recon the lab")
        await pilot.press("enter")
        await wait_for(lambda: app1._final_result is not None)
        assert app1._final_result.status == "finished"
    run_root = app1.engagement.paths.root

    # session 2(同日同 workdir):换 scope 重新预声明 → 发同一 objective
    script2 = [
        [TextDelta('{"rules": ["10.11.0.0/16"]}'), Usage(5, 2)],
        [TextDelta("收工。"), Usage(1, 1)],
    ]
    app2 = TuiApp(make_nl_config(tmp_path, script2))
    async with app2.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app2, pilot)
        await pilot.press(*"/scope switch to 10.11.0.0/16")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        press_card(card, "scope-confirm")
        await wait_for(
            lambda: notices_containing(main, "发送首条消息启动 run") != []
        )
        await pilot.press(*"recon the lab")
        await pilot.press("enter")
        await wait_for(lambda: app2._final_result is not None)
        # 修复前:engagement 创建失败(scope 冲突),run_handle 恒 None
        assert app2._final_result.status == "finished"

        # run 链:对账 scope_updated 承接旧/新 sha256,两侧 verify 均真
        records = read_records(run_root / "audit.jsonl")
        updated = [r for r in records if r["kind"] == KIND_SCOPE_UPDATED]
        assert len(updated) == 1
        payload = updated[0]["payload"]
        assert payload["old_sha256"] == hashlib.sha256(
            b"192.0.2.0/24\n"
        ).hexdigest()
        assert payload["new_sha256"] == hashlib.sha256(
            b"10.11.0.0/16\n"
        ).hexdigest()
        assert payload["source"] == "nl"
        assert payload["path"] == app2.config.scope_source
        assert payload["cidrs"] == ["10.11.0.0/16"]
        # 对账后第二段 scope_loaded 即新 scope;动态段已重写
        loaded = [r for r in records if r["kind"] == KIND_SCOPE_LOADED]
        assert len(loaded) == 2
        assert loaded[1]["payload"]["source"] == app2.config.scope_source
        section = scope_section_text(run_root)
        assert "10.11.0.0/16" in section and "192.0.2.0" not in section
        assert verify(run_root / "audit.jsonl")


async def test_scope_predeclare_first_round_context_has_rules(tmp_path):
    """评审 R2-3 回归(T1 冻结写序消费面):预声明后开跑,loop messages[1]
    (每轮自 ENGAGEMENT.md 动态段刷新)必须含已确认规则、无「尚未冻结」
    占位——_prepare_nl_run_engagement 在 start_run 前写段,生产 eager
    调度下首轮上下文亦不含占位(该时序契约钉死于此)。"""
    script = [
        [TextDelta('{"rules": ["192.0.2.0/24"]}'), Usage(5, 2)],
        [TextDelta("跑完。"), Usage(1, 1)],
    ]
    app = TuiApp(make_nl_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"/scope only 192.0.2.0/24")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        press_card(card, "scope-confirm")
        await wait_for(
            lambda: notices_containing(main, "发送首条消息启动 run") != []
        )
        await pilot.press(*"recon the lab")
        await pilot.press("enter")
        await wait_for(lambda: app._final_result is not None)
        context_msg = app.run_handle.loop.messages[1].content
        assert "192.0.2.0/24" in context_msg
        assert "尚未冻结" not in context_msg


async def test_scope_update_compile_in_flight_when_run_ends(tmp_path):
    """评审 R2-2/6 回归(T1 冻结写序面):update 仪式编译在途期间 run
    终态化(kill)→ 编译返回时共享审计句柄已关,compile_scope 落账炸
    ValueError——按 D2 中文指引收口(非裸「scope 仪式异常」),卡关闭、
    守卫释放、链完整可验、config 不变。"""
    gate = asyncio.Event()

    async def hanging_compile(messages):
        await gate.wait()
        return [TextDelta('{"rules": ["10.11.0.0/16"]}'), Usage(5, 2)]

    script = [
        [TextDelta('{"rules": ["192.0.2.0/24"]}'), Usage(5, 2)],  # 启动编译
        [TextDelta("跑。"), Usage(2, 1)],  # 轮 1 终答 → idle
        hanging_compile,  # /scope 编译:挂起等闸门
    ]
    app = TuiApp(make_nl_config(tmp_path, script, wait_on_finish=True))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"recon doc net")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        press_card(card, "scope-confirm")
        await wait_for(lambda: app.run_handle is not None)
        loop = app.run_handle.loop
        await wait_for(lambda: loop.status == "idle")

        await pilot.press(*"/scope widen to 10.11.0.0/16")
        await pilot.press("enter")
        backend = app.config.backend
        await wait_for(lambda: backend.chat_count == 3)  # 编译调用已在途

        loop.kill("打断")  # 编译在途期间 run 终态化
        await wait_for(lambda: app._final_result is not None)
        gate.set()  # 放开编译应答:落账 finally 撞上已关句柄
        await wait_for(
            lambda: notices_containing(main, "run 已结束,scope 不可更改") != []
        )
        await wait_for(lambda: app._ceremony is None)
        assert scope_card(main) is None
        # D2 中文指引收口,非裸内部异常
        assert notices_containing(main, "scope 仪式异常") == []
        assert app.config.scope is not None
        assert app.config.scope.rules == ("192.0.2.0/24",)
        root = app.engagement.paths.root
        records = read_records(root / "audit.jsonl")
        assert not any(r["kind"] == KIND_SCOPE_UPDATED for r in records)
        assert verify(root / "audit.jsonl")


async def test_file_scope_confirm_reopens_closed_audit(tmp_path):
    """评审 R2-7 回归(T1 面):Q8 补写时共享审计句柄已关闭(生产 eager
    下同步完结的 run 会在 start_run 返回前收尾关句柄;测试环境直关句柄
    模拟)→ 重开链补写落账,链完整可验,不炸 submit_text。"""
    app = TuiApp(make_config(tmp_path, [[TextDelta("done"), Usage(1, 1)]]))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        await enter_main(app, pilot)
        await start_run_and_wait(app, pilot)
        assert app._final_result.status == "finished"
        records = audit_records(app)
        assert (
            sum(1 for r in records if r["kind"] == KIND_SCOPE_CONFIRMED) == 1
        )
        # run 收尾已关句柄(wait_on_finish=False);再触发一次补写 → 重开路径
        app._append_file_scope_confirm()
        records = audit_records(app)
        confirmed = [r for r in records if r["kind"] == KIND_SCOPE_CONFIRMED]
        assert len(confirmed) == 2
        assert confirmed[1]["payload"]["source"] == "file"
        assert confirmed[1]["payload"]["canonical_sha256"] == (
            confirmed[0]["payload"]["canonical_sha256"]
        )
        assert verify(app.engagement.paths.audit_jsonl)


async def test_bare_scope_file_flow_shows_file_bytes_sha(tmp_path):
    """评审 R2-8 回归:file 流裸 /scope 的 sha256 短哈希取文件字节口径
    (与链上 scope_confirmed/engagement meta/迎宾屏一致),含注释的文件
    不再出现「同一标签两个值」。"""
    scope_text = "# 实验室授权段\n127.0.0.0/8\nlocalhost\n"
    config = make_config(tmp_path, [])
    scope_file = tmp_path / "lab.scope"
    scope_file.write_text(scope_text, encoding="utf-8")
    config.scope = parse_scope(scope_text)
    config.scope_source = str(scope_file)
    app = TuiApp(config)
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"/scope")
        await pilot.press("enter")
        await wait_for(lambda: notices_containing(main, "当前授权 scope") != [])
        shown = notices_containing(main, "当前授权 scope")[-1].content
        file_sha = hashlib.sha256(scope_text.encode("utf-8")).hexdigest()[:12]
        canonical_sha = hashlib.sha256(
            b"127.0.0.0/8\nlocalhost\n"
        ).hexdigest()[:12]
        assert file_sha != canonical_sha  # 注释行使两口径分歧(测试前提)
        assert file_sha in shown
        assert canonical_sha not in shown


async def test_bare_scope_empty_rules_q9_display(tmp_path):
    """评审 R2-14 回归:裸 /scope 空规则展示(Q9)——「(空——任何网络
    目标都会被拒)」+ 共 0 条(fail-closed 语义明示)。"""
    config = make_config(tmp_path, [])
    scope_file = tmp_path / "lab.scope"
    scope_file.write_text("", encoding="utf-8")
    config.scope = parse_scope("")
    config.scope_source = str(scope_file)
    app = TuiApp(config)
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"/scope")
        await pilot.press("enter")
        await wait_for(lambda: notices_containing(main, "当前授权 scope") != [])
        shown = notices_containing(main, "当前授权 scope")[-1].content
        assert "(空——任何网络目标都会被拒)" in shown
        assert "共 0 条" in shown


async def test_scope_redeclare_after_predeclare(tmp_path):
    """评审 R2-13 回归(T1 状态机面):未启动 + 已 NL 冻结 → 带参 /scope
    再走预声明仪式重新声明(_scope_frozen_via_nl 析取分支),config 换为
    新规则,首条消息按新 scope 开跑;两次预声明分目录。"""
    script = [
        [TextDelta('{"rules": ["192.0.2.0/24"]}'), Usage(5, 2)],  # 预声明 1
        [TextDelta('{"rules": ["10.11.0.0/16"]}'), Usage(5, 2)],  # 预声明 2
        [TextDelta("跑完。"), Usage(1, 1)],  # loop 首轮
    ]
    app = TuiApp(make_nl_config(tmp_path, script))
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        main = await enter_main(app, pilot)
        await pilot.press(*"/scope only 192.0.2.0/24")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        press_card(card, "scope-confirm")
        await wait_for(
            lambda: notices_containing(main, "发送首条消息启动 run") != []
        )
        assert app.config.scope is not None
        assert app.config.scope.rules == ("192.0.2.0/24",)

        # 未启动 + 已 NL 冻结:重新声明(predeclare 分支,非拒绝)
        await pilot.press(*"/scope switch to 10.11.0.0/16")
        await pilot.press("enter")
        card = await wait_scope_card(main)
        press_card(card, "scope-confirm")
        await wait_for(
            lambda: app.config.scope is not None
            and app.config.scope.rules == ("10.11.0.0/16",)
        )
        assert app.run_handle is None

        await pilot.press(*"recon the lab")
        await pilot.press("enter")
        await wait_for(lambda: app._final_result is not None)
        assert app._final_result.status == "finished"
        records = read_records(app.engagement.paths.audit_jsonl)
        assert records[0]["kind"] == KIND_SCOPE_LOADED
        assert records[0]["payload"]["cidrs"] == ["10.11.0.0/16"]
        roots = list((tmp_path / "engagements").iterdir())
        assert len(roots) == 3
        assert sum("scope-predeclare" in r.name for r in roots) == 2
        assert verify(app.engagement.paths.audit_jsonl)


def test_scope_ceremony_eager_finished_worker_releases_guard(
    tmp_path, monkeypatch
):
    """评审 G/R2-11 回归(T1 面):textual 生产 eager_task_factory 下,仪式
    协程可能在 run_worker 内同步完结——已完结 worker 不得回填 _ceremony
    (否则单例守卫永久锁死,而 pilot 环境不设 eager 工厂,全体测试假绿)。
    打桩 run_worker 直接覆盖守卫逻辑两分支。"""
    app = TuiApp(make_nl_config(tmp_path, []))
    app._main = object()  # 仅需通过 None 检查

    class _FinishedWorker:
        is_finished = True

    class _RunningWorker:
        is_finished = False

    def fake_finished(coro, **kwargs):
        coro.close()  # 免 never-awaited 运行时警告
        return _FinishedWorker()

    monkeypatch.setattr(app, "run_worker", fake_finished)
    app.start_scope_ceremony("recon lab", mode="startup")
    assert app._ceremony is None  # 同步完结:守卫不锁死

    def fake_running(coro, **kwargs):
        coro.close()
        return _RunningWorker()

    monkeypatch.setattr(app, "run_worker", fake_running)
    app.start_scope_ceremony("recon lab", mode="startup")
    assert app._ceremony is not None  # 活动中:正常持有守卫
