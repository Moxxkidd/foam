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

scope 文本与命令全部为合成/无害(echo/ls 不存在目录/越界目标只到护栏)。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections import deque
from pathlib import Path

import httpx

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
from foam.agent.loop import AgentLoop, LoopObserver, ToolRegistry, extract_phase
from foam.agent.prompts import build_system_prompt
from foam.guard.audit import (
    KIND_KILL_SWITCH,
    KIND_OPERATOR_INTERJECT,
    KIND_SCOPE_LOADED,
    AuditLog,
)
from foam.guard.scope import parse_scope, scope_payload
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
FIXED_TS = "2026-08-22T00:00:00+00:00"
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
    """验收 5:tui/ 全部源码/样式 grep 无品牌字串(只能经 __app_name__)。"""
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
    prompt = build_system_prompt(
        scope, source="test.scope", loaded_at=FIXED_TS, workdir=tmp_path
    )
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

        # 输入 "/" → 弹层出 7 条候选
        await pilot.press("/")
        await wait_for(lambda: dock.popup_visible)
        assert len(popup.children) == 7
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
