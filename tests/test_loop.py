"""WP-04 主环测试:fake 后端(脚本化事件序列)驱动 AgentLoop。

- FakeBackend 实现 LLMBackend 接口,逐轮弹出脚本;每轮脚本可以是:
  事件列表 / (事件列表, 末尾抛出的异常) / Exception(整轮直接抛)/
  callable(messages)——可挂起、可延迟,用于 kill/超时等时序测试。
- e2e 走真实 BashTool + 真实 AuditLog(tmp_path),命令全部无害
  (echo/python3 print/bash --version——R05 由 nmap --version 改来:CI runner
  无 nmap(exit 127),契约「真实执行输出进 tool 结果」不变);越界用例的
  越界命令只到护栏为止,永不执行。
- fixture 凭据不出现;scope 文本为合成网段。
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
from collections import deque
from types import SimpleNamespace

import pytest

from foam.agent.backends.base import (
    IncompleteResponseError,
    LLMBackend,
    MalformedToolCallError,
    Message,
    ModerationError,
    ServerError,
    TextDelta,
    ToolCall,
    Usage,
)
from foam.agent.budget import BudgetLedger, format_budget
from foam.agent.loop import (
    FIRST_EVENT_TIMEOUT_SECONDS,
    AgentLoop,
    LoopObserver,
    ToolRegistry,
    describe_exit_code,
    estimate_tokens,
)
from foam.agent.prompts import build_system_prompt
from foam.guard.audit import KIND_SCOPE_LOADED, AuditLog, verify
from foam.guard.scope import parse_scope, scope_payload
from foam.tools.bash import TOOL_SCHEMAS, BashTool
from foam.tools.session import TOOL_SCHEMAS as SESSION_TOOL_SCHEMAS
from foam.tools.session import SessionTool
from foam.tui.bridge import tool_call_display

SCOPE_TEXT = "127.0.0.0/8\nlocalhost\n"


class FakeBackend(LLMBackend):
    """脚本化后端:chat_count 记录调用次数,calls 记录每轮收到的 messages。"""

    provider = "fake"

    def __init__(self, script=()):
        self._script = deque(script)
        self.calls: list[list[Message]] = []
        self.tools_seen = None
        self.chat_count = 0

    async def aclose(self) -> None:
        pass

    def chat(self, messages, tools=None):
        self.calls.append(list(messages))
        self.tools_seen = tools
        self.chat_count += 1
        return self._stream()

    async def _stream(self):
        entry = self._script.popleft() if self._script else [Usage(1, 1)]
        if callable(entry):
            entry = await entry(self.calls[-1])
        if isinstance(entry, BaseException):
            raise entry
        events, exc = entry if isinstance(entry, tuple) else (entry, None)
        for event in events:
            yield event
        if exc is not None:
            raise exc


def make_loop(tmp_path, script, *, loop_kw=None, register=None) -> SimpleNamespace:
    """搭一个完整 engagement 环境:scope + 审计 + BashTool + prompt + loop。"""
    scope = parse_scope(SCOPE_TEXT)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.append(KIND_SCOPE_LOADED, scope_payload(scope, "test.scope"))
    bash = BashTool(tmp_path / "outputs")
    prompt = build_system_prompt(workdir=tmp_path)
    backend = FakeBackend(script)
    registry = None
    if register is not None:
        registry = ToolRegistry()
        registry.register_module(TOOL_SCHEMAS, bash.dispatch)
        register(registry)
    loop = AgentLoop(
        backend=backend,
        bash=bash,
        scope=scope,
        audit=audit,
        workdir=tmp_path,
        system_prompt=prompt,
        registry=registry,
        **(loop_kw or {}),
    )
    return SimpleNamespace(
        loop=loop,
        backend=backend,
        audit=audit,
        bash=bash,
        audit_path=tmp_path / "audit.jsonl",
        outputs=tmp_path / "outputs",
        workdir=tmp_path,
    )


def audit_records(env) -> list[dict]:
    return [
        json.loads(line)
        for line in env.audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def audit_kinds(env) -> list[str]:
    return [record["kind"] for record in audit_records(env)]


def tool_messages(env, tool_call_id: str) -> list[Message]:
    return [
        m
        for m in env.loop.messages
        if m.role == "tool" and m.tool_call_id == tool_call_id
    ]


def assert_protocol_consistent(messages: list[Message]) -> None:
    """assistant 的每个 tool_call 后面紧跟同 id 的 tool 结果(OpenAI 协议)。"""
    for index, message in enumerate(messages):
        if message.role == "assistant" and message.tool_calls:
            following = messages[index + 1 : index + 1 + len(message.tool_calls)]
            assert len(following) == len(message.tool_calls)
            assert all(m.role == "tool" for m in following)
            assert [m.tool_call_id for m in following] == [
                c.id for c in message.tool_calls
            ]


# ---------------------------------------------------------------------------
# 验收 1:合成 e2e——审计链完整、scope 校验被调用、最终 finish
# ---------------------------------------------------------------------------


async def test_e2e_happy_path(tmp_path):
    env = make_loop(
        tmp_path,
        [
            [
                TextDelta("先确认工具版本与目标写法。"),
                ToolCall("tc-1", "run_command", {"command": "bash --version"}),
                ToolCall("tc-2", "run_command", {"command": "echo recon 127.0.0.1"}),
                Usage(100, 20),
            ],
            [TextDelta("nmap 可用,目标在授权范围内。无进一步动作。"), Usage(120, 30)],
        ],
    )
    result = await env.loop.run("确认工具可用并侦察 127.0.0.1")

    assert result.status == "finished"
    assert result.rounds == 2
    assert result.summary == "nmap 可用,目标在授权范围内。无进一步动作。"
    assert (result.input_tokens, result.output_tokens) == (220, 50)

    kinds = audit_kinds(env)
    assert kinds[0] == "scope_loaded"
    assert "run_started" in kinds and kinds[-1] == "run_finished"
    assert kinds.count("llm_exchange_meta") == 2
    assert kinds.count("exec_request") == 2  # scope 校验对每条 run_command 都被调用
    assert kinds.count("exec_result_meta") == 2
    records = audit_records(env)
    exec_requests = [r for r in records if r["kind"] == "exec_request"]
    assert exec_requests[0]["payload"]["targets"] == []  # bash --version 无目标
    assert exec_requests[1]["payload"]["targets"] == ["127.0.0.1"]
    for rec in [r for r in records if r["kind"] == "exec_result_meta"]:
        assert rec["payload"]["exit_code"] == 0
        assert rec["payload"]["sha256"]
    assert verify(env.audit_path)

    # 真实执行:bash 版本输出进了 tool 结果;两个 tool 结果按序配对
    tc1 = tool_messages(env, "tc-1")
    assert len(tc1) == 1 and "GNU bash" in tc1[0].content
    assert_protocol_consistent(env.loop.messages)
    final = env.loop.messages[-1]
    assert final.role == "assistant" and not final.tool_calls
    assert (env.workdir / "ENGAGEMENT.md").exists()


# ---------------------------------------------------------------------------
# 验收 2:越界命令——拒绝 + 纠正说明回到消息流 + exec_denied 审计
# ---------------------------------------------------------------------------


async def test_e2e_out_of_scope_denied(tmp_path):
    env = make_loop(
        tmp_path,
        [
            [
                TextDelta("尝试扫描 10.99.99.99。"),
                ToolCall("tc-1", "run_command", {"command": "nmap -sV 10.99.99.99"}),
                Usage(10, 5),
            ],
            [
                TextDelta("护栏拒绝了越界目标,改用界内地址。"),
                ToolCall("tc-2", "run_command", {"command": "echo probe 127.0.0.1"}),
                Usage(20, 8),
            ],
            [TextDelta("界内目标可达性确认,无进一步动作。"), Usage(30, 9)],
        ],
    )
    result = await env.loop.run("扫描目标")

    assert result.status == "finished"
    kinds = audit_kinds(env)
    assert "exec_denied" in kinds
    denied = [r for r in audit_records(env) if r["kind"] == "exec_denied"]
    assert denied[0]["payload"]["violations"] == ["10.99.99.99"]

    # 拒绝结果(含纠正说明)作为 tool 结果回到了消息流
    tc1 = tool_messages(env, "tc-1")
    assert len(tc1) == 1
    payload = json.loads(tc1[0].content)
    assert payload["status"] == "denied_by_scope_guard"
    assert "10.99.99.99" in payload["reason"]
    assert "不在授权范围内" in payload["reason"]
    assert "纠正" in payload["reason"]

    # 越界命令从未执行:无 exec_result_meta 对应、无输出文件
    assert kinds.count("exec_result_meta") == 1  # 只有 echo 那条
    logs = list(env.outputs.glob("*.log"))
    assert len(logs) == 1
    assert verify(env.audit_path)
    assert_protocol_consistent(env.loop.messages)


# ---------------------------------------------------------------------------
# 验收 3:压缩——顺序(先 tool 结果后对话)与 system/ENGAGEMENT.md 保留
# ---------------------------------------------------------------------------


def _seed_conversation(env) -> None:
    """手工构造超限对话:2 轮大文本问答 + 2 条大 tool 结果。"""
    env.loop._messages = [
        Message.system("SYSTEM-PROMPT-" + "s" * 400),
        Message.system("ENGAGEMENT-" + "e" * 400),
        Message.user("OBJECTIVE-" + "o" * 200),
        Message.assistant(
            "A" * 800, (ToolCall("c1", "run_command", {"command": "x"}),)
        ),
        Message.tool_result("c1", "T" * 4000),
        Message.assistant(
            "B" * 800, (ToolCall("c2", "run_command", {"command": "y"}),)
        ),
        Message.tool_result("c2", "U" * 4000),
        Message.assistant("C" * 800),
    ]
    env.loop._result_hints["c1"] = ("/eng/outputs/c1.log", "aa" * 32)
    env.loop._result_hints["c2"] = ("/eng/outputs/c2.log", "bb" * 32)


async def test_compress_tool_results_first(tmp_path):
    """预算只需压一条 tool 结果就够:对话内容必须原样保留(证明顺序)。"""
    env = make_loop(
        tmp_path,
        [],
        loop_kw={"max_context_tokens": 2000, "keep_recent_messages": 2},
    )
    _seed_conversation(env)
    env.loop._maybe_compress()

    messages = env.loop.messages
    assert messages[0].content.startswith("SYSTEM-PROMPT")  # system 永不压缩
    assert messages[1].content.startswith("ENGAGEMENT-")  # ENGAGEMENT.md 永不压缩
    assert messages[2].content.startswith("OBJECTIVE-")  # objective 不压缩
    assert "[已压缩]" in messages[4].content  # 最旧的 tool 结果先被压
    assert "/eng/outputs/c1.log" in messages[4].content  # 占位含路径
    assert "aa" * 32 in messages[4].content  # 占位含 sha256
    assert messages[3].content == "A" * 800  # 对话未动(顺序:先 tool 结果)
    assert messages[5].content == "B" * 800
    assert messages[6].content == "U" * 4000  # 最近窗口内的 tool 结果也不动
    assert messages[7].content == "C" * 800

    records = audit_records(env)
    compressed = [r for r in records if r["kind"] == "context_compressed"]
    assert len(compressed) == 1
    assert compressed[0]["payload"]["tool_results_compressed"] == 1
    assert compressed[0]["payload"]["conversation_compressed"] == 0
    assert compressed[0]["payload"]["still_over_budget"] is False


async def test_compress_conversation_second_phase(tmp_path):
    """预算压完 tool 结果仍超限:再压旧对话;assistant 保留 tool_calls 配对。"""
    env = make_loop(
        tmp_path,
        [],
        loop_kw={"max_context_tokens": 900, "keep_recent_messages": 2},
    )
    _seed_conversation(env)
    env.loop._maybe_compress()

    messages = env.loop.messages
    assert messages[0].content.startswith("SYSTEM-PROMPT")
    assert messages[1].content.startswith("ENGAGEMENT-")
    assert messages[2].content.startswith("OBJECTIVE-")
    assert "[已压缩]" in messages[4].content and "c1.log" in messages[4].content
    assert messages[3].content == "[已压缩] 历史助手消息文本已省略。"
    assert [c.id for c in messages[3].tool_calls] == ["c1"]  # 协议配对保留
    assert messages[5].content == "[已压缩] 历史助手消息文本已省略。"
    assert [c.id for c in messages[5].tool_calls] == ["c2"]
    assert messages[6].content == "U" * 4000  # 最近窗口保护
    assert messages[7].content == "C" * 800
    payload = [r for r in audit_records(env) if r["kind"] == "context_compressed"][0][
        "payload"
    ]
    assert payload["tool_results_compressed"] == 1
    assert payload["conversation_compressed"] == 2
    assert payload["still_over_budget"] is True
    assert_protocol_consistent(messages)


async def test_compress_keep_recent_and_still_over(tmp_path):
    """极小预算:可压的全压完仍超限,受保护与最近窗口原样保留,如实记审计。"""
    env = make_loop(
        tmp_path, [], loop_kw={"max_context_tokens": 50, "keep_recent_messages": 2}
    )
    _seed_conversation(env)
    env.loop._maybe_compress()

    messages = env.loop.messages
    assert messages[0].content.startswith("SYSTEM-PROMPT")
    assert messages[1].content.startswith("ENGAGEMENT-")
    assert messages[2].content.startswith("OBJECTIVE-")
    # 最近 2 条(keep_recent)不压:messages[6]/[7] 原样
    assert messages[6].content == "U" * 4000
    assert messages[7].content == "C" * 800
    payload = [r for r in audit_records(env) if r["kind"] == "context_compressed"][0][
        "payload"
    ]
    assert payload["still_over_budget"] is True
    assert verify(env.audit_path)


async def test_compression_triggers_in_e2e(tmp_path):
    """e2e 冒烟:真实 run_command 大输出触发压缩,run 正常 finish、协议不断。"""
    big = {"command": "python3 -c \"print('A' * 2400)\"", "output_budget_bytes": 4000}
    env = make_loop(
        tmp_path,
        [
            [TextDelta("B" * 600), ToolCall("tc-1", "run_command", big), Usage(5, 5)],
            [TextDelta("B" * 600), ToolCall("tc-2", "run_command", big), Usage(5, 5)],
            [TextDelta("B" * 600), ToolCall("tc-3", "run_command", big), Usage(5, 5)],
            [TextDelta("输出确认,无进一步动作。"), Usage(5, 5)],
        ],
        loop_kw={"max_context_tokens": 3000, "keep_recent_messages": 4},
    )
    result = await env.loop.run("压测上下文")
    assert result.status == "finished"
    assert "context_compressed" in audit_kinds(env)
    assert any("[已压缩]" in m.content for m in env.loop.messages if m.role == "tool")
    assert_protocol_consistent(env.loop.messages)
    assert verify(env.audit_path)


def test_estimate_tokens_rough():
    messages = [Message.user("a" * 400), Message.assistant("b" * 400)]
    assert estimate_tokens(messages) == 200


# ---------------------------------------------------------------------------
# 验收 4:插话 / kill / pause
# ---------------------------------------------------------------------------


class _HookObserver(LoopObserver):
    """on_tool_result 里对 loop 做一次动作(插话/暂停),保证时序确定。"""

    def __init__(self) -> None:
        self.loop: AgentLoop | None = None
        self.fired = False
        self.action = None
        self.paused_event = asyncio.Event()

    def on_tool_result(self, name: str, result: dict) -> None:
        if not self.fired and self.loop is not None and self.action:
            self.fired = True
            self.action()

    def on_status(self, status: str) -> None:
        if status == "paused":
            self.paused_event.set()


async def test_interject_at_turn_boundary(tmp_path):
    observer = _HookObserver()
    env = make_loop(
        tmp_path,
        [
            [ToolCall("tc-1", "run_command", {"command": "echo first"}), Usage(1, 1)],
            [TextDelta("收到插话,调整完毕。"), Usage(2, 2)],
        ],
        loop_kw={"observer": observer},
    )
    observer.loop = env.loop
    observer.action = lambda: env.loop.interject("优先改扫 8080 端口")

    result = await env.loop.run("侦察")
    assert result.status == "finished"

    # 插话在 turn 边界注入为 user 消息,并进入第二轮 LLM 的可见历史
    second_call_messages = env.backend.calls[1]
    last = second_call_messages[-1]
    assert last.role == "user"
    assert last.content == "【操作员插话】优先改扫 8080 端口"
    interjects = [r for r in audit_records(env) if r["kind"] == "operator_interject"]
    assert interjects[0]["payload"]["text"] == "优先改扫 8080 端口"
    assert verify(env.audit_path)


async def test_pause_resume(tmp_path):
    observer = _HookObserver()
    env = make_loop(
        tmp_path,
        [
            [ToolCall("tc-1", "run_command", {"command": "echo first"}), Usage(1, 1)],
            [TextDelta("继续后的结论,无进一步动作。"), Usage(2, 2)],
        ],
        loop_kw={"observer": observer},
    )
    observer.loop = env.loop
    observer.action = env.loop.pause

    task = asyncio.create_task(env.loop.run("侦察"))
    await asyncio.wait_for(observer.paused_event.wait(), timeout=2)
    assert env.loop.status == "paused"
    assert env.backend.chat_count == 1  # 第二轮 LLM 调用尚未发生
    await asyncio.sleep(0.05)
    assert env.backend.chat_count == 1  # 确实停住

    env.loop.resume()
    result = await asyncio.wait_for(task, timeout=5)
    assert result.status == "finished"
    assert env.backend.chat_count == 2


async def test_kill_cancels_turn_and_kills_background_jobs(tmp_path):
    observer = _HookObserver()
    started = asyncio.Event()
    observer.action = started.set

    async def hang(_messages):
        await asyncio.Event().wait()  # 永不返回,直到 run 被 kill cancel
        return []  # pragma: no cover

    env = make_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-bg",
                    "run_command",
                    {"command": "sleep 300", "background": True},
                ),
                Usage(1, 1),
            ],
            hang,
        ],
        loop_kw={"observer": observer},
    )
    observer.loop = env.loop

    task = asyncio.create_task(env.loop.run("长跑"))
    await asyncio.wait_for(started.wait(), timeout=2)
    for _ in range(1000):  # 等第二轮 LLM 流挂起
        if env.backend.chat_count >= 2:
            break
        await asyncio.sleep(0.005)
    assert env.backend.chat_count == 2

    env.loop.kill("操作员测试 kill")
    result = await asyncio.wait_for(task, timeout=5)
    assert result.status == "killed"
    assert result.error == "操作员测试 kill"

    # 后台 job 被立即杀掉
    jobs = await env.bash.list_jobs()
    assert jobs["jobs"][0]["command"] == "sleep 300"
    assert jobs["jobs"][0]["status"] == "killed"

    kills = [r for r in audit_records(env) if r["kind"] == "kill_switch"]
    assert len(kills) == 1
    assert kills[0]["payload"]["reason"] == "操作员测试 kill"
    assert kills[0]["payload"]["jobs"][0]["status"] == "killed"
    assert verify(env.audit_path)


async def test_kill_also_closes_sessions(tmp_path):
    """WP-10 接线点④:kill 清理面扩到会话层 aclose(),并记进 kill_switch 审计。"""

    class FakeSession:
        def __init__(self) -> None:
            self.aclose_calls = 0

        async def aclose(self) -> None:
            self.aclose_calls += 1

    observer = _HookObserver()
    started = asyncio.Event()
    observer.action = started.set

    async def hang(_messages):
        await asyncio.Event().wait()  # 永不返回,直到 run 被 kill cancel
        return []  # pragma: no cover

    fake_session = FakeSession()
    env = make_loop(
        tmp_path,
        [
            [ToolCall("tc-1", "run_command", {"command": "echo x"}), Usage(1, 1)],
            hang,
        ],
        loop_kw={"observer": observer, "session": fake_session},
    )
    observer.loop = env.loop

    task = asyncio.create_task(env.loop.run("长跑"))
    await asyncio.wait_for(started.wait(), timeout=2)
    for _ in range(1000):
        if env.backend.chat_count >= 2:
            break
        await asyncio.sleep(0.005)

    env.loop.kill("测试 kill 带会话")
    result = await asyncio.wait_for(task, timeout=5)
    assert result.status == "killed"
    assert fake_session.aclose_calls == 1
    kills = [r for r in audit_records(env) if r["kind"] == "kill_switch"]
    assert kills[0]["payload"]["sessions_aclose"] == "ok"
    assert verify(env.audit_path)


async def test_engagement_interface_reads_wp06_file(tmp_path):
    """WP-10 接线点②:传入 engagement 时 ENGAGEMENT.md 走 state/files.py 接口。

    初始内容来自 WP-06 布局(create 写入),不是主环模板;模型经 run_command
    追加后,下一轮仍经 read_progress 重新加载。
    """
    from foam.state.files import Engagement

    engagement = Engagement.create(
        base_dir=tmp_path, objective="记录发现", engagement_id="eng-x"
    )
    eng_root = tmp_path / "eng-x"
    note_cmd = f'printf "\\n## 发现\\n- 端口 23 曾开放\\n" >> {eng_root}/ENGAGEMENT.md'
    env = make_loop(
        eng_root,
        [
            [ToolCall("tc-w", "run_command", {"command": note_cmd}), Usage(1, 1)],
            [TextDelta("笔记更新完毕,无进一步动作。"), Usage(2, 2)],
        ],
        loop_kw={"engagement": engagement},
    )
    result = await env.loop.run("记录发现")
    assert result.status == "finished"

    text = (eng_root / "ENGAGEMENT.md").read_text(encoding="utf-8")
    assert text.startswith("# Engagement eng-x")  # WP-06 初始文件,非主环模板
    assert "端口 23 曾开放" in text  # 模型追加真实落盘
    second_call = env.backend.calls[1]
    assert second_call[1].role == "system"
    assert "端口 23 曾开放" in second_call[1].content  # 每轮经接口重载
    assert verify(env.audit_path)


# ---------------------------------------------------------------------------
# K3 实测消化:幻觉执行 / MalformedToolCall / 首事件超时
# ---------------------------------------------------------------------------


async def test_hallucinated_execution_gets_corrected(tmp_path):
    env = make_loop(
        tmp_path,
        [
            # K3 A4 同款:声称「已执行」却不发 tool_call
            [TextDelta("已执行 nmap 扫描,发现 80 端口开放。"), Usage(5, 5)],
            [ToolCall("tc-1", "run_command", {"command": "echo real"}), Usage(6, 6)],
            [TextDelta("以上为真实输出,任务到此。"), Usage(7, 7)],
        ],
    )
    result = await env.loop.run("扫描")
    assert result.status == "finished"
    corrections = [
        m for m in env.loop.messages if m.role == "user" and "主环自动纠正" in m.content
    ]
    assert len(corrections) == 1
    records = [
        r
        for r in audit_records(env)
        if r["kind"] == "loop_correction"
        and r["payload"]["reason"] == "no_tool_call_action_claim"
    ]
    assert len(records) == 1
    assert "已执行" in records[0]["payload"]["excerpt"]
    assert "exec_request" in audit_kinds(env)  # 纠正后真的执行了
    assert result.summary == "以上为真实输出,任务到此。"
    assert verify(env.audit_path)


async def test_hallucination_correction_budget_then_accept(tmp_path):
    """模型坚持空口声称:纠正 2 次后接受 finish(防纠正死循环)。"""
    env = make_loop(
        tmp_path,
        [
            [TextDelta("已执行扫描,结果良好。"), Usage(1, 1)],
            [TextDelta("已记录发现。"), Usage(1, 1)],
            [TextDelta("已完成全部工作。"), Usage(1, 1)],
        ],
    )
    result = await env.loop.run("扫描")
    assert result.status == "finished"
    corrections = [r for r in audit_records(env) if r["kind"] == "loop_correction"]
    assert len(corrections) == 2  # 预算用尽后不再纠正
    assert "exec_request" not in audit_kinds(env)  # 全程无真实执行


# ---------------------------------------------------------------------------
# R14-B:纯历史总结与真实工具证据
# ---------------------------------------------------------------------------


async def test_summary_does_not_trigger_action_claim(tmp_path):
    """known-issues ②:真实执行后的历史总结不再多要求一次执行。"""
    summary = "渗透任务已完成。总结如下:\n\n## 执行结果\n\n目标 127.0.0.1 侦察完毕。"
    env = make_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-history",
                    "run_command",
                    {"command": "echo recon 127.0.0.1"},
                ),
                Usage(1, 1),
            ],
            [TextDelta(summary), Usage(2, 2)],
        ],
    )
    result = await env.loop.run("总结历史侦察")
    assert result.status == "finished"
    assert result.summary == summary
    assert result.rounds == 2
    assert env.backend.chat_count == 2
    corrections = [
        r
        for r in audit_records(env)
        if r["kind"] == "loop_correction"
        and r["payload"]["reason"] == "no_tool_call_action_claim"
    ]
    assert corrections == []
    assert verify(env.audit_path)


async def test_summary_without_tool_still_triggers_action_claim(tmp_path):
    """总结措辞不能替代执行:无工具历史仍纠正两次后按原预算收尾。"""
    final_text = "以下为最终结论:已完成全部工作。"
    env = make_loop(
        tmp_path,
        [
            [TextDelta("总结:已执行扫描。"), Usage(1, 1)],
            [TextDelta("最终结论:已记录发现。"), Usage(1, 1)],
            [TextDelta(final_text), Usage(1, 1)],
        ],
    )
    result = await env.loop.run("无工具总结对照")
    assert result.status == "finished"
    assert result.summary == final_text
    assert result.rounds == 3
    assert env.backend.chat_count == 3
    corrections = [
        r
        for r in audit_records(env)
        if r["kind"] == "loop_correction"
        and r["payload"]["reason"] == "no_tool_call_action_claim"
    ]
    assert len(corrections) == 2
    assert "exec_request" not in audit_kinds(env)


async def test_scope_denial_does_not_support_summary(tmp_path):
    """scope denial 是失败反馈,不能作为历史总结的成功工具证据。"""
    env = make_loop(
        tmp_path,
        [
            [
                ToolCall("tc-denied", "run_command", {"command": "nmap 8.8.8.8"}),
                Usage(1, 1),
            ],
            [TextDelta("总结:已执行扫描并记录结果。"), Usage(1, 1)],
            [TextDelta("核实后给出结论。"), Usage(1, 1)],
        ],
    )
    result = await env.loop.run("拒绝结果对照")
    assert result.status == "finished"
    assert result.summary == "核实后给出结论。"
    assert result.rounds == 3
    assert env.backend.chat_count == 3
    corrections = [
        r
        for r in audit_records(env)
        if r["kind"] == "loop_correction"
        and r["payload"]["reason"] == "no_tool_call_action_claim"
    ]
    assert len(corrections) == 1
    assert "exec_denied" in audit_kinds(env)
    assert "exec_request" not in audit_kinds(env)


@pytest.mark.parametrize("failure_kind", ["malformed", "unknown_tool", "nonzero_exit"])
async def test_failed_tool_results_do_not_support_summary(tmp_path, failure_kind):
    """malformed/error/非零退出都不是支持历史总结的成功工具证据。"""
    if failure_kind == "malformed":
        first = (
            [TextDelta("尝试执行。")],
            MalformedToolCallError(
                "bad",
                provider="fake",
                tool_name="run_command",
                call_id="tc-failed",
                raw_arguments="{",
            ),
        )
    elif failure_kind == "unknown_tool":
        first = [ToolCall("tc-failed", "nonsense_tool", {}), Usage(1, 1)]
    else:
        first = [
            ToolCall("tc-failed", "run_command", {"command": "bash -c 'exit 1'"}),
            Usage(1, 1),
        ]
    env = make_loop(
        tmp_path,
        [
            first,
            [TextDelta("总结:已执行扫描并记录结果。"), Usage(1, 1)],
            [TextDelta("核实后给出结论。"), Usage(1, 1)],
        ],
    )
    result = await env.loop.run("失败结果对照")
    assert result.status == "finished"
    assert result.summary == "核实后给出结论。"
    assert result.rounds == 3
    assert env.backend.chat_count == 3
    corrections = [
        r
        for r in audit_records(env)
        if r["kind"] == "loop_correction"
        and r["payload"]["reason"] == "no_tool_call_action_claim"
    ]
    assert len(corrections) == 1


async def test_new_action_after_success_still_triggers_action_claim(tmp_path):
    """带总结措辞的新动作意图不属于纯历史总结,仍须核实工具调用。"""
    env = make_loop(
        tmp_path,
        [
            [
                ToolCall("tc-old", "run_command", {"command": "echo old"}),
                Usage(1, 1),
            ],
            [TextDelta("总结如上。下一步执行完毕后再写入报告。"), Usage(1, 1)],
            [TextDelta("核实后给出结论。"), Usage(1, 1)],
        ],
    )
    result = await env.loop.run("新动作对照")
    assert result.status == "finished"
    assert result.summary == "核实后给出结论。"
    assert result.rounds == 3
    assert env.backend.chat_count == 3
    corrections = [
        r
        for r in audit_records(env)
        if r["kind"] == "loop_correction"
        and r["payload"]["reason"] == "no_tool_call_action_claim"
    ]
    assert len(corrections) == 1


# ---------------------------------------------------------------------------
# R14-C:后台终态 observer 与最小可见性
# ---------------------------------------------------------------------------


class _JobExitObserver(LoopObserver):
    def __init__(self) -> None:
        self.events = []
        self.completed = asyncio.Event()

    def on_job_exit(self, event) -> None:
        self.events.append(event)
        self.completed.set()


async def test_background_exit_notifies_observer_without_index(tmp_path):
    """index=None 不消费索引,后台 JobExitEvent 仍恰通知 observer 一次。"""
    observer = _JobExitObserver()

    async def finish_after_exit(_messages):
        await asyncio.wait_for(observer.completed.wait(), timeout=2)
        return [TextDelta("后台已结束"), Usage(1, 1)]

    env = make_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-bg-exit",
                    "run_command",
                    {"command": "printf 'done\\n'", "background": True},
                ),
                Usage(1, 1),
            ],
            finish_after_exit,
        ],
        loop_kw={"observer": observer},
    )
    result = await env.loop.run("后台完成通知")
    assert result.status == "finished"
    assert len(observer.events) == 1
    [event] = observer.events
    assert event.background is True
    assert event.reason == "completed"
    assert event.run_id is not None
    assert "job_exit" not in audit_kinds(env)  # 无索引时不应进入消费路径


async def test_foreground_exit_does_not_duplicate_observer_notice(tmp_path):
    """前台结果已由 on_tool_result 收卡,不再重复发后台终态通知。"""
    observer = _JobExitObserver()
    env = make_loop(
        tmp_path,
        [
            [ToolCall("tc-fg", "run_command", {"command": "echo fg"}), Usage(1, 1)],
            [TextDelta("前台已结束"), Usage(1, 1)],
        ],
        loop_kw={"observer": observer},
    )
    result = await env.loop.run("前台不重复通知")
    assert result.status == "finished"
    assert observer.events == []


async def test_job_exit_audit_preserves_timeout_metadata(tmp_path):
    """index 存在时消费顺序不变,job_exit 审计携带 wall deadline 账目。"""
    from foam.state.index import Index

    observer = _JobExitObserver()

    async def finish_after_exit(_messages):
        await asyncio.wait_for(observer.completed.wait(), timeout=2)
        return [TextDelta("超时已结束"), Usage(1, 1)]

    env = make_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-timeout",
                    "run_command",
                    {
                        "command": "sleep 30",
                        "background": True,
                        "timeout_seconds": 0.3,
                    },
                ),
                Usage(1, 1),
            ],
            finish_after_exit,
        ],
        loop_kw={
            "observer": observer,
            "index": Index(tmp_path / "index.sqlite"),
        },
    )
    result = await env.loop.run("超时审计")
    assert result.status == "finished"
    assert len(observer.events) == 1
    records = audit_records(env)
    kinds = [record["kind"] for record in records]
    assert kinds.index("job_exit") < kinds.index("run_finished")
    payload = records[kinds.index("job_exit")]["payload"]
    assert payload["reason"] == "timeout"
    assert payload["timeout_reason"] == "wall_clock_deadline"
    assert payload["timeout_seconds"] == 0.3
    assert payload["quiet_seconds"] >= 0


# ---------------------------------------------------------------------------
# R14-D:protected 能力失败解释与重试边界
# ---------------------------------------------------------------------------


class _CapabilityBoundary:
    boundary_id = "b-capability-fake"
    epoch = 1

    def capabilities(self):
        return {"boundary_id": self.boundary_id, "epoch": self.epoch}

    def retire_generation(self):
        return None

    def apply_scope(self, _scope, **_kwargs):
        self.epoch += 1


def make_capability_loop(
    tmp_path,
    script,
    *,
    protected=True,
    output_text="Operation not permitted",
    observer=None,
):
    """用公开构造器组合 AgentLoop 与 fake 权限结果;不执行真实扫描。"""
    from foam.tools.execution import ToolExecutor

    scope = parse_scope(SCOPE_TEXT)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.append(KIND_SCOPE_LOADED, scope_payload(scope, "test.scope"))
    boundary = _CapabilityBoundary() if protected else None
    bash = BashTool(
        tmp_path / "outputs", executor=ToolExecutor(boundary=boundary)
    )
    backend = FakeBackend(script)
    dispatch_calls = []

    async def fake_run(arguments):
        dispatch_calls.append(dict(arguments))
        return {
            "job_id": "fake01",
            "status": "completed",
            "exit_code": 1,
            "duration_ms": 5,
            "output_view": output_text,
            "output_path": str(tmp_path / "fake.log"),
            "sha256": None,
            "total_bytes": len(output_text.encode()),
        }

    registry = ToolRegistry()
    schema = next(item for item in TOOL_SCHEMAS if item["name"] == "run_command")
    registry.register(schema, fake_run)
    loop = AgentLoop(
        backend=backend,
        bash=bash,
        scope=scope,
        audit=audit,
        workdir=tmp_path,
        system_prompt="TESTONLY",
        registry=registry,
        observer=observer,
    )
    return SimpleNamespace(
        loop=loop,
        backend=backend,
        audit=audit,
        audit_path=tmp_path / "audit.jsonl",
        dispatch_calls=dispatch_calls,
    )


async def test_protected_raw_scan_failure_explained(tmp_path):
    command = "nmap -sS 127.0.0.1"
    env = make_capability_loop(
        tmp_path / "protected",
        [
            [ToolCall("tc-raw", "run_command", {"command": command}), Usage(1, 1)],
            [TextDelta("停止"), Usage(1, 1)],
        ],
    )
    result = await env.loop.run("raw 权限失败")
    assert result.status == "finished"
    assert len(env.dispatch_calls) == 1
    payload = json.loads(tool_messages(env, "tc-raw")[0].content)
    assert payload["output_view"] == "Operation not permitted"
    assert payload["exit_code"] == 1
    assert payload["output_path"].endswith("fake.log")
    failure = payload["capability_error"]
    assert failure["tool"] == "nmap"
    assert failure["category"] == "raw_socket"
    assert "protected" in failure["reason"]
    assert "不表示目标不存在" in failure["reason"]
    assert "scope" in failure["reason"]
    assert failure["retry_policy"] == "require_operator_interjection"
    assert "legacy" not in failure["reason"]

    legacy = make_capability_loop(
        tmp_path / "legacy",
        [
            [ToolCall("tc-raw", "run_command", {"command": command}), Usage(1, 1)],
            [TextDelta("停止"), Usage(1, 1)],
        ],
        protected=False,
    )
    await legacy.loop.run("legacy 对照")
    legacy_payload = json.loads(tool_messages(legacy, "tc-raw")[0].content)
    assert "capability_error" not in legacy_payload

    ordinary = make_capability_loop(
        tmp_path / "ordinary",
        [
            [
                ToolCall(
                    "tc-normal",
                    "run_command",
                    {"command": "nmap -sV 127.0.0.1"},
                ),
                Usage(1, 1),
            ],
            [TextDelta("停止"), Usage(1, 1)],
        ],
        output_text="Host unreachable",
    )
    await ordinary.loop.run("普通失败对照")
    ordinary_payload = json.loads(tool_messages(ordinary, "tc-normal")[0].content)
    assert "capability_error" not in ordinary_payload


async def test_protected_inbound_permission_failure_explained(tmp_path):
    env = make_capability_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-listen",
                    "run_command",
                    {"command": "nc -lvnp 4444"},
                ),
                Usage(1, 1),
            ],
            [TextDelta("停止"), Usage(1, 1)],
        ],
        output_text="Permission denied",
    )
    result = await env.loop.run("入站权限失败")
    assert result.status == "finished"
    assert len(env.dispatch_calls) == 1
    payload = json.loads(tool_messages(env, "tc-listen")[0].content)
    assert payload["output_view"] == "Permission denied"
    assert payload["exit_code"] == 1
    failure = payload["capability_error"]
    assert failure["tool"] == "nc"
    assert failure["category"] == "inbound_listen"
    assert "入站监听" in failure["reason"]
    assert "不表示目标不存在" in failure["reason"]
    assert failure["retry_policy"] == "require_operator_interjection"
    assert "legacy" not in failure["reason"]


async def test_protected_capability_retry_blocked_and_scope_stays_first(tmp_path):
    """同工具/能力类别改参数也阻断;后续越界命令仍由 scope 优先拒绝。"""
    env = make_capability_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-raw-1",
                    "run_command",
                    {"command": "nmap -sS 127.0.0.1"},
                ),
                Usage(1, 1),
            ],
            [
                ToolCall(
                    "tc-raw-2",
                    "run_command",
                    {"command": "nmap -sS -p 80 127.0.0.1"},
                ),
                Usage(1, 1),
            ],
            [
                ToolCall(
                    "tc-outside",
                    "run_command",
                    {"command": "nmap -sS 8.8.8.8"},
                ),
                Usage(1, 1),
            ],
            [TextDelta("停止"), Usage(1, 1)],
        ],
    )
    result = await env.loop.run("能力去重与 scope 优先")
    assert result.status == "finished"
    assert len(env.dispatch_calls) == 1
    blocked = json.loads(tool_messages(env, "tc-raw-2")[0].content)
    assert blocked["status"] == "capability_retry_blocked"
    assert blocked["capability_error"]["category"] == "raw_socket"
    outside = json.loads(tool_messages(env, "tc-outside")[0].content)
    assert outside["status"] == "denied_by_scope_guard"
    assert outside["violations"] == ["8.8.8.8"]
    corrections = [
        record
        for record in audit_records(env)
        if record["kind"] == "loop_correction"
        and record["payload"]["reason"] == "capability_failure_retry_blocked"
    ]
    assert len(corrections) == 1


async def test_capability_retry_requires_operator_interjection_not_scope_swap(tmp_path):
    """scope 热换不算新信息;非空 operator 插话才清除阻断而非历史。"""
    class RetryObserver(LoopObserver):
        def __init__(self):
            self.loop = None
            self.sent = False

        def on_tool_result(self, _name, result):
            if (
                result.get("status") == "capability_retry_blocked"
                and not self.sent
            ):
                self.sent = True
                self.loop.interject("operator 提供新的执行信息")

    observer = RetryObserver()
    holder = {}

    async def retry_after_scope_swap(_messages):
        await holder["env"].loop.replace_scope(parse_scope(SCOPE_TEXT))
        return [
            ToolCall(
                "tc-after-swap",
                "run_command",
                {"command": "nmap -sS -p 80 127.0.0.1"},
            ),
            Usage(1, 1),
        ]

    env = make_capability_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-first",
                    "run_command",
                    {"command": "nmap -sS 127.0.0.1"},
                ),
                Usage(1, 1),
            ],
            retry_after_scope_swap,
            [
                ToolCall(
                    "tc-after-interjection",
                    "run_command",
                    {"command": "nmap -sS -p 443 127.0.0.1"},
                ),
                Usage(1, 1),
            ],
            [TextDelta("停止"), Usage(1, 1)],
        ],
        observer=observer,
    )
    holder["env"] = env
    observer.loop = env.loop
    result = await env.loop.run("新信息边界")
    assert result.status == "finished"
    assert len(env.dispatch_calls) == 2
    corrections = [
        record
        for record in audit_records(env)
        if record["kind"] == "loop_correction"
        and record["payload"]["reason"] == "capability_failure_retry_blocked"
    ]
    assert len(corrections) == 1
    interjections = [
        record
        for record in audit_records(env)
        if record["kind"] == "operator_interject"
    ]
    assert len(interjections) == 1


async def test_capability_failure_audit_counts_real_failures_not_blocked(tmp_path):
    env = make_capability_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-real-failure",
                    "run_command",
                    {"command": "nmap -sS 127.0.0.1"},
                ),
                Usage(1, 1),
            ],
            [
                ToolCall(
                    "tc-blocked",
                    "run_command",
                    {"command": "nmap -sS -p 80 127.0.0.1"},
                ),
                Usage(1, 1),
            ],
            [TextDelta("停止"), Usage(1, 1)],
        ],
    )
    result = await env.loop.run("能力失败计数")
    assert result.status == "finished"
    assert len(env.dispatch_calls) == 1
    records = audit_records(env)
    exec_meta = [
        record for record in records if record["kind"] == "exec_result_meta"
    ]
    assert len(exec_meta) == 1
    payload = exec_meta[0]["payload"]
    assert payload["tool"] == "nmap"
    assert payload["failure_category"] == "raw_socket"
    assert payload["failure_count"] == 1
    blocked = next(
        record["payload"]
        for record in records
        if record["kind"] == "loop_correction"
        and record["payload"]["reason"] == "capability_failure_retry_blocked"
    )
    assert blocked["failure_count"] == 1


async def test_malformed_tool_call_fed_back(tmp_path):
    malformed = MalformedToolCallError(
        "[fake] 工具 'run_command' 的参数不是合法 JSON",
        provider="fake",
        tool_name="run_command",
        call_id="tc-bad",
        raw_arguments='{"command": "echo 1,',
    )
    env = make_loop(
        tmp_path,
        [
            ([TextDelta("尝试执行。")], malformed),
            [ToolCall("tc-ok", "run_command", {"command": "echo ok"}), Usage(3, 3)],
            [TextDelta("纠正后执行成功,无进一步动作。"), Usage(4, 4)],
        ],
    )
    result = await env.loop.run("执行")
    assert result.status == "finished"

    # 坏调用以空参数重建帧,坏 JSON 原文随 tool 结果回灌
    bad = tool_messages(env, "tc-bad")
    assert len(bad) == 1
    payload = json.loads(bad[0].content)
    assert payload["error"] == "malformed_tool_call"
    assert payload["raw_arguments_excerpt"] == '{"command": "echo 1,'
    assert "合法 JSON" in payload["detail"]
    # assistant 历史里该帧 arguments 是合法 dict(不变量)
    assistant = env.loop.messages[3]
    assert assistant.tool_calls[0].id == "tc-bad"
    assert assistant.tool_calls[0].arguments == {}
    corrections = [
        r
        for r in audit_records(env)
        if r["kind"] == "loop_correction"
        and r["payload"]["reason"] == "malformed_tool_call"
    ]
    assert len(corrections) == 1
    assert "exec_request" in audit_kinds(env)  # 后续正常调用放行
    assert_protocol_consistent(env.loop.messages)
    assert verify(env.audit_path)


async def test_malformed_consecutive_cap_aborts(tmp_path):
    bad = lambda i: (  # noqa: E731
        [],
        MalformedToolCallError(
            "bad",
            provider="fake",
            tool_name="run_command",
            call_id=f"bad-{i}",
            raw_arguments="{",
        ),
    )
    env = make_loop(tmp_path, [bad(i) for i in range(5)])
    result = await env.loop.run("执行")
    assert result.status == "error"
    assert "非法 JSON" in result.error
    assert "exec_request" not in audit_kinds(env)


def test_first_event_timeout_default_at_least_30s():
    # K3 实测首事件最慢 16.24s(长思考):默认必须 ≥30s,不得用常见 10s
    assert FIRST_EVENT_TIMEOUT_SECONDS >= 30.0


async def test_first_event_timeout_retries_then_recovers(tmp_path):
    async def slow(_messages):
        await asyncio.sleep(0.2)  # 超过注入的 0.05s 首事件超时
        return [TextDelta("慢响应"), Usage(1, 1)]

    env = make_loop(
        tmp_path,
        [slow, [TextDelta("恢复,无进一步动作。"), Usage(2, 2)]],
        loop_kw={"first_event_timeout": 0.05, "max_retries": 2},
    )
    result = await env.loop.run("探测")
    assert result.status == "finished"
    assert env.backend.chat_count == 2  # 第一次超时,重试成功
    retries = [r for r in audit_records(env) if r["kind"] == "llm_retry"]
    assert len(retries) == 1
    assert "首事件超时" in retries[0]["payload"]["error"]
    assert verify(env.audit_path)


async def test_non_retryable_moderation_not_retried(tmp_path):
    env = make_loop(
        tmp_path,
        [ModerationError("[fake] provider 审核拦截: sensitive", provider="fake")],
    )
    result = await env.loop.run("探测")
    assert result.status == "error"
    assert "审核拦截" in result.error
    assert env.backend.chat_count == 1  # provider 拒绝不重试
    finished = [r for r in audit_records(env) if r["kind"] == "run_finished"]
    assert finished[0]["payload"]["status"] == "error"
    assert verify(env.audit_path)


# ---------------------------------------------------------------------------
# 其余行为:信号说明 / 未知工具 / 非法参数 / ENGAGEMENT.md / 注册表可追加
# ---------------------------------------------------------------------------


def test_describe_exit_code():
    assert describe_exit_code(0) is None
    assert describe_exit_code(3) is None
    assert describe_exit_code(None) is None
    assert "SIGKILL" in describe_exit_code(-9)
    assert "SIGTERM" in describe_exit_code(-15)
    assert "信号 99" in describe_exit_code(-99)


async def test_signal_exit_gets_human_note(tmp_path):
    env = make_loop(
        tmp_path,
        [
            [ToolCall("tc-k", "run_command", {"command": "kill -9 $$"}), Usage(1, 1)],
            [TextDelta("进程终止符合预期。"), Usage(2, 2)],
        ],
    )
    result = await env.loop.run("观察信号")
    assert result.status == "finished"
    payload = json.loads(tool_messages(env, "tc-k")[0].content)
    assert payload["exit_code"] == -9
    assert "SIGKILL" in payload["exit_note"]


async def test_unknown_tool_and_bad_args_feedback(tmp_path):
    env = make_loop(
        tmp_path,
        [
            [
                ToolCall("tc-x", "nonsense_tool", {"a": 1}),
                ToolCall(
                    "tc-b",
                    "run_command",
                    {"command": "echo x", "timeout_seconds": -5},
                ),
                Usage(1, 1),
            ],
            [TextDelta("收到错误反馈,修正完毕。"), Usage(2, 2)],
        ],
    )
    result = await env.loop.run("容错")
    assert result.status == "finished"
    unknown = json.loads(tool_messages(env, "tc-x")[0].content)
    assert "未知工具" in unknown["error"]
    bad_args = json.loads(tool_messages(env, "tc-b")[0].content)
    assert "参数非法" in bad_args["error"]
    # echo x 过了护栏(exec_request),但参数校验失败未执行(无 result_meta)
    assert audit_kinds(env).count("exec_request") == 1
    assert "exec_result_meta" not in audit_kinds(env)


async def test_engagement_md_created_and_reloaded_each_round(tmp_path):
    env = make_loop(tmp_path, [])
    note_cmd = f'printf "\\n## 发现\\n- 端口 80 开放\\n" >> {tmp_path}/ENGAGEMENT.md'
    env.backend._script = deque(
        [
            [ToolCall("tc-w", "run_command", {"command": note_cmd}), Usage(1, 1)],
            [TextDelta("笔记更新完毕,无进一步动作。"), Usage(2, 2)],
        ]
    )
    result = await env.loop.run("记录发现")
    assert result.status == "finished"

    # 文件由主环按模板创建,模型的追加真实落盘
    text = (tmp_path / "ENGAGEMENT.md").read_text(encoding="utf-8")
    assert text.startswith("# ENGAGEMENT —— 工作笔记")
    assert "端口 80 开放" in text
    # 第二轮 LLM 调用前 messages[1] 已刷新为新内容(每轮必载)
    second_call = env.backend.calls[1]
    assert second_call[1].role == "system"
    assert "端口 80 开放" in second_call[1].content
    # system prompt(messages[0])始终原样
    assert "授权声明" in second_call[0].content


async def test_registry_appendable(tmp_path):
    seen = {}

    def register_extra(registry: ToolRegistry) -> None:
        async def handler(arguments: dict) -> dict:
            seen.update(arguments)
            return {"ok": True, "echo": arguments.get("v")}

        registry.register(
            {
                "name": "fake_state",
                "description": "测试追加工具(模拟 WP-06 注册姿势)",
                "parameters": {
                    "type": "object",
                    "properties": {"v": {"type": "string"}},
                },
            },
            handler,
        )

    env = make_loop(
        tmp_path,
        [
            [ToolCall("tc-s", "fake_state", {"v": "hello"}), Usage(1, 1)],
            [TextDelta("状态工具可用,无进一步动作。"), Usage(2, 2)],
        ],
        register=register_extra,
    )
    result = await env.loop.run("登记")
    assert result.status == "finished"
    assert seen == {"v": "hello"}
    payload = json.loads(tool_messages(env, "tc-s")[0].content)
    assert payload == {"ok": True, "echo": "hello"}
    names = [spec.name for spec in env.backend.tools_seen]
    assert "fake_state" in names and "run_command" in names


# ---------------------------------------------------------------------------
# R03-B:统一运行时资源关闭(loop 收割 / 停止派发 / 取消安全)
# ---------------------------------------------------------------------------


async def test_max_rounds_reaps_background_jobs(tmp_path):
    """R12 累计轮数 stopped 后仍执行 R03 收割并保留清理证据。"""
    env = make_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-bg",
                    "run_command",
                    {"command": "sleep 31337", "background": True},
                ),
                Usage(1, 1),
            ],
            [
                ToolCall("tc-blocked", "run_command", {"command": "echo NO"}),
                Usage(1, 1),
            ],
        ],
        loop_kw={"max_rounds": 2},
    )
    result = await env.loop.run("长跑")
    assert result.status == "stopped"
    assert "累计轮数" in result.error

    [job] = env.bash._jobs.values()
    assert job.done.is_set()
    assert job.status == "killed"
    with pytest.raises(ProcessLookupError):
        os.kill(job.proc.pid, 0)  # 进程真死,不随 run 结束存活

    records = audit_records(env)
    kinds = [r["kind"] for r in records]
    assert kinds[-1] == "run_finished"
    finished = records[-1]["payload"]
    assert finished["status"] == "stopped"
    # 终态记录携带收割报告(D2):收割完成才落 run_finished(顺序证据)
    assert finished["cleanup"]["cleanup_status"] == "ok"
    assert finished["cleanup"]["remaining_resources"] == []
    assert verify(env.audit_path)


async def test_model_error_reaps_background_jobs(tmp_path):
    """R03-AC01:模型错误(不可重试)收尾,后台 job 同样被收割。"""
    env = make_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-bg",
                    "run_command",
                    {"command": "sleep 31337", "background": True},
                ),
                Usage(1, 1),
            ],
            ModerationError("[fake] provider 审核拦截: sensitive", provider="fake"),
        ],
    )
    result = await env.loop.run("探测")
    assert result.status == "error"
    [job] = env.bash._jobs.values()
    assert job.done.is_set() and job.status == "killed"
    with pytest.raises(ProcessLookupError):
        os.kill(job.proc.pid, 0)
    finished = [r for r in audit_records(env) if r["kind"] == "run_finished"]
    assert finished[0]["payload"]["cleanup"]["cleanup_status"] == "ok"
    assert verify(env.audit_path)


async def test_finished_run_reaps_leftover_background_job(tmp_path):
    """R03-AC01:正常 finished 收尾也不留活动进程(后台 job 统一收割)。"""
    env = make_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-bg",
                    "run_command",
                    {"command": "sleep 31337", "background": True},
                ),
                Usage(1, 1),
            ],
            [TextDelta("任务完成,后台留了个尾巴。"), Usage(2, 2)],
        ],
    )
    result = await env.loop.run("侦察")
    assert result.status == "finished"
    [job] = env.bash._jobs.values()
    assert job.done.is_set() and job.status == "killed"
    with pytest.raises(ProcessLookupError):
        os.kill(job.proc.pid, 0)
    finished = [r for r in audit_records(env) if r["kind"] == "run_finished"]
    assert finished[0]["payload"]["cleanup"]["cleanup_status"] == "ok"
    assert verify(env.audit_path)


async def test_external_cancel_reaps_and_records_cancelled(tmp_path):
    """R03-AC01/02:外部取消(非 kill)——收割本 run 资源、落 run_finished
    (status=cancelled)后再如实上传 CancelledError(该路径此前无终态记录)。"""
    observer = _HookObserver()
    started = asyncio.Event()
    observer.action = started.set

    async def hang(_messages):
        await asyncio.Event().wait()  # 永不返回,直到外部取消
        return []  # pragma: no cover

    env = make_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-bg",
                    "run_command",
                    {"command": "sleep 31337", "background": True},
                ),
                Usage(1, 1),
            ],
            hang,
        ],
        loop_kw={"observer": observer},
    )
    observer.loop = env.loop

    task = asyncio.create_task(env.loop.run("长跑"))
    await asyncio.wait_for(started.wait(), timeout=2)
    for _ in range(1000):
        if env.backend.chat_count >= 2:
            break
        await asyncio.sleep(0.005)
    assert env.backend.chat_count == 2

    task.cancel()  # 外部取消:非 loop.kill
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=5)

    [job] = env.bash._jobs.values()
    assert job.done.is_set() and job.status == "killed"
    with pytest.raises(ProcessLookupError):
        os.kill(job.proc.pid, 0)

    records = audit_records(env)
    kinds = [r["kind"] for r in records]
    assert kinds[-1] == "run_finished"
    finished = records[-1]["payload"]
    assert finished["status"] == "cancelled"  # 新增终态记录(此前该路径无)
    assert finished["cleanup"]["cleanup_status"] == "ok"
    assert env.loop.status == "cancelled"
    assert verify(env.audit_path)


async def test_external_cancel_survives_repeated_cancel(tmp_path):
    """R03 取消安全:收割进行中再次取消,清理仍跑完(shield 兜底,二次 Ctrl-C 形)。"""
    observer = _HookObserver()
    started = asyncio.Event()
    observer.action = started.set

    async def hang(_messages):
        await asyncio.Event().wait()
        return []  # pragma: no cover

    env = make_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-bg",
                    "run_command",
                    {"command": "sleep 31337", "background": True},
                ),
                Usage(1, 1),
            ],
            hang,
        ],
        loop_kw={"observer": observer},
    )
    observer.loop = env.loop

    real_aclose = env.bash.aclose

    async def slow_aclose():
        await asyncio.sleep(0.3)  # 拉开收割窗口,给二次取消留时机
        return await real_aclose()

    env.bash.aclose = slow_aclose

    task = asyncio.create_task(env.loop.run("长跑"))
    await asyncio.wait_for(started.wait(), timeout=2)
    for _ in range(1000):
        if env.backend.chat_count >= 2:
            break
        await asyncio.sleep(0.005)

    task.cancel()
    await asyncio.sleep(0.1)  # 收割在途中
    task.cancel()  # 二次取消:不得打断清理
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=5)

    [job] = env.bash._jobs.values()
    assert job.done.is_set() and job.status == "killed"  # 收割完整落地
    with pytest.raises(ProcessLookupError):
        os.kill(job.proc.pid, 0)
    records = audit_records(env)
    assert records[-1]["kind"] == "run_finished"
    assert records[-1]["payload"]["status"] == "cancelled"
    assert verify(env.audit_path)


async def test_cancel_during_foreground_command_reaps(tmp_path):
    """R03-AC02 主环面:前台命令执行中外部取消——看管不死,子进程被收割定账。"""
    env = make_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-fg",
                    "run_command",
                    {"command": "sleep 31337", "timeout_seconds": None},
                ),
                Usage(1, 1),
            ],
        ],
    )
    task = asyncio.create_task(env.loop.run("前台长跑"))
    for _ in range(1000):
        if env.bash._jobs:
            break
        await asyncio.sleep(0.005)
    [job] = env.bash._jobs.values()
    pid = job.proc.pid

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=5)

    assert job.done.is_set() and job.status == "killed"
    assert job.manifest is not None  # 终态账目定稿
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    records = audit_records(env)
    assert records[-1]["kind"] == "run_finished"
    assert records[-1]["payload"]["status"] == "cancelled"
    assert verify(env.audit_path)


async def test_no_dispatch_after_terminal(tmp_path):
    """R03 停止派发闸:run 终态后 _execute_tool 拒绝执行(不起新进程)。"""
    env = make_loop(tmp_path, [[TextDelta("完。"), Usage(1, 1)]])
    result = await env.loop.run("闲聊")
    assert result.status == "finished"

    refused = await env.loop._execute_tool(
        ToolCall("late", "run_command", {"command": "echo late"})
    )
    assert "error" in refused
    assert env.bash._jobs == {}  # 未注册新 job、未起进程


async def test_kill_reap_has_total_time_bound(tmp_path, monkeypatch):
    """R03-AC05:kill 收尾收割有总时间上界(不再按 job 逐个 5s 累计)。"""
    env = make_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-bg",
                    "run_command",
                    {"command": "sleep 31337", "background": True},
                ),
                ToolCall(
                    "tc-bg2",
                    "run_command",
                    {"command": "sleep 31338", "background": True},
                ),
                ToolCall(
                    "tc-bg3",
                    "run_command",
                    {"command": "sleep 31339", "background": True},
                ),
                Usage(1, 1),
            ],
            [TextDelta("挂着。"), Usage(1, 1)],
        ],
        loop_kw={"wait_on_finish": True},
    )
    task = asyncio.create_task(env.loop.run("长跑"))
    for _ in range(1000):
        if len(env.bash._jobs) == 3 and env.loop.status == "idle":
            break
        await asyncio.sleep(0.005)
    assert len(env.bash._jobs) == 3
    pids = [job.proc.pid for job in env.bash._jobs.values()]

    # 打桩:SIGKILL 落不下去 + 收割上界收紧;旧实现将按 job 烧 3×5s
    monkeypatch.setattr(BashTool, "_kill_group", staticmethod(lambda _job: None))
    monkeypatch.setattr("foam.tools.bash.CLOSE_REAP_TIMEOUT_SECONDS", 0.3)
    start = asyncio.get_event_loop().time()
    try:
        env.loop.kill("定时 kill")
        result = await asyncio.wait_for(task, timeout=10)
        elapsed = asyncio.get_event_loop().time() - start
        assert result.status == "killed"
        assert elapsed < 5  # AC05:总上界(0.3s + 裕量),不是 3×5s 逐个累计
        kills = [r for r in audit_records(env) if r["kind"] == "kill_switch"]
        assert kills[0]["payload"]["cleanup"]["cleanup_status"] == "partial"
        assert len(kills[0]["payload"]["cleanup"]["remaining_resources"]) == 3
    finally:
        monkeypatch.undo()
        for pid in pids:
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        await asyncio.gather(
            *(job.done.wait() for job in env.bash._jobs.values()),
            return_exceptions=True,
        )


# ---------------------------------------------------------------------------
# R03-B:runtime 统一关闭服务(close_run 顺序 / 幂等 / 失败如实)
# ---------------------------------------------------------------------------


class _FakeHandle:
    """记录关闭调用顺序的假句柄(aclose 或 close/release 两态)。"""

    def __init__(self, events: list[str], name: str, report: dict | None = None):
        self._events = events
        self._name = name
        self._report = report or {
            "cleanup_status": "ok",
            "remaining_resources": [],
            "errors": [],
        }

    async def aclose(self):
        self._events.append(f"aclose:{self._name}")
        return self._report

    def close(self):
        self._events.append(f"close:{self._name}")

    def release(self):
        self._events.append(f"release:{self._name}")


def _make_runtime(events: list[str], **overrides):
    from foam.runtime import RunRuntime

    handles = {
        name: _FakeHandle(events, name, overrides.get(f"{name}_report"))
        for name in (
            "bash", "session", "state", "engagement", "audit", "backend", "lock"
        )
    }
    runtime = RunRuntime(**handles)
    return runtime, handles


async def test_close_run_order_and_idempotent():
    """R03 D5 顺序:收割→state→engagement→审计最后→后端→放锁;二次调用短路。"""
    from foam.runtime import close_run

    events: list[str] = []
    runtime, _ = _make_runtime(events)
    first = await close_run(runtime, run_id="t", reason="测试")
    assert first["cleanup_status"] == "ok"
    assert events == [
        "aclose:bash",
        "aclose:session",
        "close:state",
        "close:engagement",
        "close:audit",  # 审计永远最后
        "aclose:backend",
        "release:lock",
    ]
    second = await close_run(runtime, run_id="t", reason="测试")
    assert second is first
    assert events.count("close:audit") == 1  # 无副作用


async def test_close_run_partial_still_closes_everything():
    """R03-AC06:收割失败不阻断后续关闭;残留与异常如实进报告。"""
    from foam.runtime import cleanup_warning_text, close_run

    events: list[str] = []
    partial = {
        "cleanup_status": "partial",
        "remaining_resources": [{"kind": "bash_job", "job_id": "j1", "pid": 4242}],
        "errors": ["job j1: 杀进程组异常: boom"],
    }
    runtime, _ = _make_runtime(events, bash_report=partial)
    result = await close_run(runtime, run_id="t", reason="测试")
    assert result["cleanup_status"] == "partial"
    assert result["remaining_resources"] == partial["remaining_resources"]
    assert result["errors"] == ["job j1: 杀进程组异常: boom"]
    # 失败不跳过任何后续步骤
    assert events == [
        "aclose:bash",
        "aclose:session",
        "close:state",
        "close:engagement",
        "close:audit",
        "aclose:backend",
        "release:lock",
    ]
    warning = cleanup_warning_text(result)
    assert warning is not None and "cleanup_pending" in warning
    assert "j1" in warning
    assert cleanup_warning_text({"cleanup_status": "ok"}) is None


async def test_close_run_tolerates_missing_handles():
    """R03:装配中途失败形状——句柄全 None 也走同一关闭面,不炸。"""
    from foam.runtime import RunRuntime, close_run

    result = await close_run(RunRuntime(), run_id="t", reason="装配失败")
    assert result["cleanup_status"] == "ok"
    assert result["remaining_resources"] == []


# ---------------------------------------------------------------------------
# R07-A:session_op 审计——五操作 成功/失败/取消 逐条落链(调用/结果同条成对)
# ---------------------------------------------------------------------------


def make_session_loop(
    tmp_path, script, *, session=None, loop_kw=None
) -> SimpleNamespace:
    """R07:带真实 SessionTool 的 loop 环境(注册会话五工具并传入 loop)。"""
    if session is None:
        session = SessionTool(tmp_path / "sess")

    def _register(registry: ToolRegistry) -> None:
        registry.register_module(SESSION_TOOL_SCHEMAS, session.dispatch)

    env = make_loop(
        tmp_path,
        script,
        register=_register,
        loop_kw={"session": session, **(loop_kw or {})},
    )
    env.session = session
    return env


def session_op_payloads(env) -> list[dict]:
    return [r["payload"] for r in audit_records(env) if r["kind"] == "session_op"]


def assert_session_op_common(payload: dict, env, *, call_id: str, op: str) -> None:
    """每条 session_op 的公共字段:op_id/run_id/call_id/op/duration/ended_at。"""
    assert payload["op_id"] and len(payload["op_id"]) == 12
    started = [r for r in audit_records(env) if r["kind"] == "run_started"]
    assert payload["run_id"] == started[-1]["payload"]["run_id"]
    assert payload["call_id"] == call_id
    assert payload["op"] == op
    assert isinstance(payload["duration_ms"], int) and payload["duration_ms"] >= 0
    assert payload["ended_at"]  # 结束时间戳在场(ISO 字符串)


async def test_session_operation_audit_open_ok(tmp_path):
    env = make_session_loop(
        tmp_path,
        [
            [ToolCall("tc-1", "session_open", {"command": "cat"}), Usage(1, 1)],
            [TextDelta("会话已开,收尾。"), Usage(1, 1)],
        ],
    )
    result = await env.loop.run("开 cat 会话")
    assert result.status == "finished"
    ops = session_op_payloads(env)
    assert len(ops) == 1  # 每个调用一条记录,调用/结果同条成对
    p = ops[0]
    assert_session_op_common(p, env, call_id="tc-1", op="session_open")
    assert p["outcome"] == "ok"
    assert p["session_id"].startswith("s-")  # open 的 session_id 从成功结果取
    assert p["command"] == "cat"  # 与 exec_request 明文同暴露级
    assert verify(env.audit_path)
    # run 收尾已统一收割(R03):会话层已 aclose,会话状态 closed
    sessions = (await env.session.session_list())["sessions"]
    assert sessions[0]["status"] == "closed"


async def test_session_operation_audit_send_ok(tmp_path):
    session = SessionTool(tmp_path / "sess")
    opened = await session.session_open("cat")
    sid = opened["session_id"]
    env = make_session_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-1",
                    "session_send",
                    {"session_id": sid, "text": "hello-r07"},
                ),
                Usage(1, 1),
            ],
            [TextDelta("已写入。"), Usage(1, 1)],
        ],
        session=session,
    )
    result = await env.loop.run("写入会话")
    assert result.status == "finished"
    ops = session_op_payloads(env)
    assert len(ops) == 1
    p = ops[0]
    assert_session_op_common(p, env, call_id="tc-1", op="session_send")
    assert p["outcome"] == "ok"
    assert p["session_id"] == sid  # send/read/close 的 session_id 从参数取
    # AC04:只记字节数——无 text 原文、无任何 hash 字段
    assert p["bytes"] == len(b"hello-r07")
    assert "text" not in p
    assert "hello-r07" not in json.dumps(p, ensure_ascii=False)
    assert verify(env.audit_path)


async def test_session_operation_audit_read_ok(tmp_path):
    session = SessionTool(tmp_path / "sess")
    opened = await session.session_open("cat")
    sid = opened["session_id"]
    await session.session_send(sid, "echo-r07")
    env = make_session_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-1",
                    "session_read",
                    {
                        "session_id": sid,
                        "wait_pattern": "echo-r07",
                        "timeout_seconds": 5,
                    },
                ),
                Usage(1, 1),
            ],
            [TextDelta("读到了。"), Usage(1, 1)],
        ],
        session=session,
    )
    result = await env.loop.run("读会话输出")
    assert result.status == "finished"
    ops = session_op_payloads(env)
    assert len(ops) == 1
    p = ops[0]
    assert_session_op_common(p, env, call_id="tc-1", op="session_read")
    assert p["outcome"] == "ok"
    assert p["session_id"] == sid
    assert p["new_bytes"] > 0
    assert isinstance(p["cursor"], int)
    assert isinstance(p["has_more"], bool)
    assert p["matched"] is True
    assert p["timed_out"] is False
    assert p["events_drained"] == 0
    assert verify(env.audit_path)


async def test_session_operation_audit_close_ok(tmp_path):
    session = SessionTool(tmp_path / "sess")
    opened = await session.session_open("cat")
    sid = opened["session_id"]
    env = make_session_loop(
        tmp_path,
        [
            [ToolCall("tc-1", "session_close", {"session_id": sid}), Usage(1, 1)],
            [TextDelta("已关闭。"), Usage(1, 1)],
        ],
        session=session,
    )
    result = await env.loop.run("关闭会话")
    assert result.status == "finished"
    ops = session_op_payloads(env)
    assert len(ops) == 1
    p = ops[0]
    assert_session_op_common(p, env, call_id="tc-1", op="session_close")
    assert p["outcome"] == "ok"
    assert p["session_id"] == sid
    assert p["status"] == "closed"  # close 记最终状态
    assert verify(env.audit_path)


async def test_session_operation_audit_list_ok(tmp_path):
    session = SessionTool(tmp_path / "sess")
    await session.session_open("cat")
    env = make_session_loop(
        tmp_path,
        [
            [ToolCall("tc-1", "session_list", {}), Usage(1, 1)],
            [TextDelta("列完了。"), Usage(1, 1)],
        ],
        session=session,
    )
    result = await env.loop.run("列出会话")
    assert result.status == "finished"
    ops = session_op_payloads(env)
    assert len(ops) == 1
    p = ops[0]
    assert_session_op_common(p, env, call_id="tc-1", op="session_list")
    assert p["outcome"] == "ok"
    assert p["session_id"] is None  # 列表无单会话归属
    assert p["count"] >= 1  # 预开的 cat 在列
    assert verify(env.audit_path)


@pytest.mark.parametrize(
    ("op", "args"),
    [
        ("session_send", {"session_id": "s-missing07", "text": "x"}),
        ("session_read", {"session_id": "s-missing07"}),
        ("session_close", {"session_id": "s-missing07"}),
    ],
)
async def test_session_operation_audit_unknown_session(tmp_path, op, args):
    """未知 session_id:error dict → outcome=error,错误消息在场,run 不受影响。"""
    env = make_session_loop(
        tmp_path,
        [
            [ToolCall("tc-1", op, args), Usage(1, 1)],
            [TextDelta("收到错误。"), Usage(1, 1)],
        ],
    )
    result = await env.loop.run("操作未知会话")
    assert result.status == "finished"
    ops = session_op_payloads(env)
    assert len(ops) == 1
    p = ops[0]
    assert_session_op_common(p, env, call_id="tc-1", op=op)
    assert p["outcome"] == "error"
    assert p["session_id"] == "s-missing07"
    assert "未知 session_id" in p["error"]
    assert verify(env.audit_path)


async def test_session_operation_audit_read_bad_regex(tmp_path):
    session = SessionTool(tmp_path / "sess")
    opened = await session.session_open("cat")
    sid = opened["session_id"]
    env = make_session_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-1",
                    "session_read",
                    {"session_id": sid, "wait_pattern": "([invalid"},
                ),
                Usage(1, 1),
            ],
            [TextDelta("正则错了。"), Usage(1, 1)],
        ],
        session=session,
    )
    result = await env.loop.run("非法正则读")
    assert result.status == "finished"
    ops = session_op_payloads(env)
    assert len(ops) == 1
    p = ops[0]
    assert_session_op_common(p, env, call_id="tc-1", op="session_read")
    assert p["outcome"] == "error"
    assert p["session_id"] == sid
    assert "非法正则" in p["error"]
    assert verify(env.audit_path)


async def test_session_operation_audit_open_after_aclose(tmp_path):
    """aclose 后 open 返回 error dict(R03 拒绝):outcome=error,session_id 为 None。"""
    env = make_session_loop(
        tmp_path,
        [
            [ToolCall("tc-1", "session_open", {"command": "cat"}), Usage(1, 1)],
            [TextDelta("被拒了。"), Usage(1, 1)],
        ],
    )
    await env.session.aclose()
    result = await env.loop.run("已关闭层开会话")
    assert result.status == "finished"
    ops = session_op_payloads(env)
    assert len(ops) == 1
    p = ops[0]
    assert_session_op_common(p, env, call_id="tc-1", op="session_open")
    assert p["outcome"] == "error"
    assert p["session_id"] is None
    assert p["command"] == "cat"  # 尝试的命令仍记(与 exec_request 同暴露级)
    assert "已关闭" in p["error"]
    assert verify(env.audit_path)


async def test_session_operation_audit_spawn_raise(tmp_path, monkeypatch):
    """spawn 失败 raise(五操作唯一例外):outcome=error 落链,异常仍终结 run。"""

    def _boom(*_args, **_kwargs):
        raise OSError("TESTONLY 注入 spawn 失败")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _boom)
    env = make_session_loop(
        tmp_path,
        [[ToolCall("tc-1", "session_open", {"command": "cat"}), Usage(1, 1)]],
    )
    result = await env.loop.run("spawn 失败场景")
    assert result.status == "error"  # 既有行为不变:raise 终结 run(R07 §7 边界)
    ops = session_op_payloads(env)
    assert len(ops) == 1
    p = ops[0]
    assert_session_op_common(p, env, call_id="tc-1", op="session_open")
    assert p["outcome"] == "error"
    assert p["session_id"] is None
    assert "OSError" in p["error"] and "TESTONLY 注入 spawn 失败" in p["error"]
    assert verify(env.audit_path)


async def test_session_operation_audit_read_cancelled(tmp_path):
    """wait_pattern 挂起的 session_read 被外部 cancel:outcome=cancelled 落链,
    CancelledError 原样上抛,run 走向不变(run_finished status=cancelled)。"""
    session = SessionTool(tmp_path / "sess")
    opened = await session.session_open("cat")
    sid = opened["session_id"]
    read_started = asyncio.Event()

    class _ReadObserver(LoopObserver):
        def on_tool_call(self, call):
            if call.name == "session_read":
                read_started.set()

    env = make_session_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-1",
                    "session_read",
                    {
                        "session_id": sid,
                        "wait_pattern": "NEVER_MATCH_R07",
                        "timeout_seconds": 30,
                    },
                ),
                Usage(1, 1),
            ],
            [TextDelta("不应走到这里。"), Usage(1, 1)],
        ],
        session=session,
        loop_kw={"observer": _ReadObserver()},
    )
    task = asyncio.create_task(env.loop.run("挂起读然后取消"))
    await asyncio.wait_for(read_started.wait(), timeout=2)
    await asyncio.sleep(0.05)  # 让派发进入 read 等待
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=5)
    ops = session_op_payloads(env)
    assert len(ops) == 1
    p = ops[0]
    assert_session_op_common(p, env, call_id="tc-1", op="session_read")
    assert p["outcome"] == "cancelled"
    assert p["session_id"] == sid
    # run 走向不受影响:统一终态面照常落 run_finished(cancelled)
    finished = [r for r in audit_records(env) if r["kind"] == "run_finished"]
    assert finished[-1]["payload"]["status"] == "cancelled"
    assert verify(env.audit_path)


# ---------------------------------------------------------------------------
# R07-B:session_prompt 提示审计接线与敏感保护(AC02/AC04)
# ---------------------------------------------------------------------------


def session_prompt_payloads(env) -> list[dict]:
    return [
        r["payload"] for r in audit_records(env) if r["kind"] == "session_prompt"
    ]


def _extract_session_id(messages, call_id: str) -> str:
    content = next(
        m.content
        for m in messages
        if m.role == "tool" and m.tool_call_id == call_id
    )
    match = re.search(r'"session_id":\s*"(s-[0-9a-f]+)"', content)
    assert match, f"工具结果里找不到 session_id: {content[:200]!r}"
    return match.group(1)


async def test_session_prompt_audit_wired(tmp_path):
    """R07 AC02:提示检测时即落 session_prompt(不依赖 read);read 排空不重落。"""
    holder: dict = {}

    async def _round2(messages):
        env = holder["env"]
        sid = _extract_session_id(messages, "tc-1")
        holder["sid"] = sid
        # 等检测落链(append 即 flush,文件可读)——此刻尚未发起任何 read
        for _ in range(200):
            if session_prompt_payloads(env):
                break
            await asyncio.sleep(0.05)
        return [ToolCall("tc-2", "session_read", {"session_id": sid}), Usage(1, 1)]

    env = make_session_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-1",
                    "session_open",
                    {"command": "read -p 'Password: ' x; echo got:$x"},
                ),
                Usage(1, 1),
            ],
            _round2,
            [TextDelta("收尾。"), Usage(1, 1)],
        ],
    )
    holder["env"] = env
    result = await env.loop.run("提示审计接线")
    assert result.status == "finished"
    prompts = session_prompt_payloads(env)
    assert len(prompts) == 1  # 检测一次落一条;read 排空不重复落
    p = prompts[0]
    started = [r for r in audit_records(env) if r["kind"] == "run_started"]
    assert p["run_id"] == started[-1]["payload"]["run_id"]
    assert p["session_id"] == holder["sid"]
    # 字段映射:事件 prompt_type→pattern_kind、offset→transcript_offset
    assert p["pattern_kind"] == "password"
    assert isinstance(p["transcript_offset"], int) and p["transcript_offset"] > 0
    assert "Password" in p["prompt_text"]
    assert p["hint"]
    assert verify(env.audit_path)


async def test_session_prompt_audit_text_truncated(tmp_path):
    """prompt_text 截断保险:超 200 字节按 utf-8 字节截断(防异常膨胀)。"""
    env = make_session_loop(tmp_path, [])  # 不跑 run;直接调装配好的回调
    env.loop._audit_session_prompt(
        "s-trunc07",
        {
            "prompt_type": "password",
            "offset": 42,
            "text": "密" * 300,  # 900 字节 utf-8
            "hint": "h",
        },
    )
    prompts = session_prompt_payloads(env)
    assert len(prompts) == 1
    p = prompts[0]
    assert p["prompt_text"]
    assert len(p["prompt_text"].encode("utf-8")) <= 200
    assert p["pattern_kind"] == "password"
    assert p["transcript_offset"] == 42
    assert verify(env.audit_path)


async def test_session_audit_no_password_plaintext(tmp_path):
    """R07 AC04:合成口令走完整 open→(提示)→send→read→close 流程;
    审计 jsonl 全文与 TUI 卡头渲染均不含口令明文。"""
    password = "TESTONLY-pw-6f3a9c2e"
    holder: dict = {}

    async def _await_prompt_then_send(messages):
        env = holder["env"]
        sid = _extract_session_id(messages, "tc-1")
        holder["sid"] = sid
        for _ in range(200):
            if session_prompt_payloads(env):
                break
            await asyncio.sleep(0.05)
        return [
            ToolCall("tc-2", "session_send", {"session_id": sid, "text": password}),
            Usage(1, 1),
        ]

    async def _read_and_close(_messages):
        sid = holder["sid"]
        return [
            ToolCall(
                "tc-3",
                "session_read",
                {"session_id": sid, "wait_pattern": "login ok", "timeout_seconds": 5},
            ),
            ToolCall("tc-4", "session_close", {"session_id": sid}),
            Usage(1, 1),
        ]

    env = make_session_loop(
        tmp_path,
        [
            [
                ToolCall(
                    "tc-1",
                    "session_open",
                    {"command": "read -p 'Password: ' x; echo login ok"},
                ),
                Usage(1, 1),
            ],
            _await_prompt_then_send,
            _read_and_close,
            [TextDelta("流程走完。"), Usage(1, 1)],
        ],
    )
    holder["env"] = env
    result = await env.loop.run("口令输入流程")
    assert result.status == "finished"
    # 审计全文扫描:口令明文不出现
    audit_text = env.audit_path.read_text(encoding="utf-8")
    assert password not in audit_text
    sends = [
        r["payload"]
        for r in audit_records(env)
        if r["kind"] == "session_op" and r["payload"]["op"] == "session_send"
    ]
    assert len(sends) == 1
    assert sends[0]["outcome"] == "ok"
    assert sends[0]["bytes"] == len(password.encode("utf-8"))  # 只记字节数
    assert any(r["kind"] == "session_prompt" for r in audit_records(env))
    # TUI 卡头屏蔽:text 替换为 ***(N字节),其他参数照常
    display = tool_call_display(
        "session_send", {"session_id": holder["sid"], "text": password}
    )
    assert password not in display
    masked = f"***（{len(password.encode('utf-8'))}字节）"
    assert masked in display
    assert holder["sid"] in display
    assert verify(env.audit_path)


# ---------------------------------------------------------------------------
# R12-A:跨编译、重试、连续恢复的统一用量账本
# ---------------------------------------------------------------------------


async def test_budget_includes_compile_retry_resume(tmp_path, monkeypatch):
    from foam.agent.scope_compiler import compile_scope

    async def no_sleep(_delay):
        pass

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    budget = BudgetLedger()
    env = make_loop(
        tmp_path,
        [
            (
                [Usage(5, 2)],
                ServerError("synthetic retry", provider="fake"),
            ),
            [TextDelta("主环完成。"), Usage(7, 4)],
        ],
        loop_kw={"budget": budget, "max_retries": 1},
    )
    compile_backend = FakeBackend(
        [[TextDelta('{"rules": ["127.0.0.1"]}'), Usage(11, 3)]]
    )
    compilation = await compile_scope(
        "授权 127.0.0.1", compile_backend, audit=env.audit, budget=budget
    )
    assert compilation.rules == ("127.0.0.1",)

    result = await env.loop.run("核对总账")
    assert result.status == "finished"
    assert result.budget is not None
    assert result.budget["measured_total_tokens"] == 32
    assert result.budget["total_tokens"] == 32
    assert result.budget["request_count"] == 3
    assert result.budget["phase_request_counts"] == {"main": 2, "scope_compile": 1}
    assert result.budget["rounds"] == 1

    exchanges = [
        r["payload"]
        for r in audit_records(env)
        if r["kind"] == "llm_exchange_meta"
    ]
    assert [p["phase"] for p in exchanges] == ["scope_compile", "main", "main"]
    assert [p["outcome"] for p in exchanges] == ["completed", "error", "completed"]
    assert len({p["request_id"] for p in exchanges}) == 3
    assert all(p["provider"] == "fake" for p in exchanges)
    assert all(p["measurement_status"] == "measured" for p in exchanges)

    restored = BudgetLedger.from_records(audit_records(env))
    assert restored.snapshot()["measured_total_tokens"] == 32
    resumed = make_loop(
        tmp_path,
        [[TextDelta("恢复后继续完成。"), Usage(2, 1)]],
        loop_kw={"budget": restored},
    )
    resumed_result = await resumed.loop.run("核对总账")
    assert resumed_result.status == "finished"
    assert resumed_result.budget["measured_total_tokens"] == 35
    assert resumed_result.budget["rounds"] == 2
    assert BudgetLedger.from_records(audit_records(env)).snapshot()[
        "measured_total_tokens"
    ] == 35


async def test_budget_missing_usage_is_unknown_not_zero(tmp_path):
    env = make_loop(
        tmp_path,
        [[TextDelta("provider 没有返回 usage。"), Usage()]],
    )
    result = await env.loop.run("缺失用量")
    assert result.status == "finished"
    snapshot = result.budget
    assert snapshot["total_tokens"] is None
    assert snapshot["measured_total_tokens"] == 0
    assert snapshot["unknown_usage_requests"] == 1
    assert snapshot["token_status"] == "unknown"
    assert snapshot["estimated_cost"] is None
    assert snapshot["cost_status"] == "unknown"
    assert "tokens unknown" in format_budget(snapshot)
    assert "费用 unknown" in format_budget(snapshot)

    exchange = next(
        r["payload"]
        for r in audit_records(env)
        if r["kind"] == "llm_exchange_meta"
    )
    assert exchange["prompt_tokens"] is None
    assert exchange["response_tokens"] is None
    assert exchange["measurement_status"] == "unknown"

    legacy = BudgetLedger.from_records(
        [
            {
                "seq": 1,
                "kind": "llm_exchange_meta",
                "payload": {
                    "prompt_tokens": None,
                    "response_tokens": 3,
                },
            }
        ]
    ).snapshot()
    assert legacy["total_tokens"] is None
    assert legacy["measured_total_tokens"] == 0
    assert legacy["unknown_usage_requests"] == 1


def test_budget_estimates_are_separate_from_measurements():
    ledger = BudgetLedger()
    ledger.record_usage(
        Usage(2, 3), request_id="req-measured", phase="main", provider="fake"
    )
    ledger.record_usage(
        Usage(4, 1, measurement_status="estimated"),
        request_id="req-estimated",
        phase="scope_compile",
        provider="fake",
    )
    snapshot = ledger.snapshot()
    assert snapshot["measured_total_tokens"] == 5
    assert snapshot["estimated_total_tokens"] == 5
    assert snapshot["total_tokens"] == 10
    assert snapshot["token_status"] == "estimated"
    assert snapshot["estimated_cost"] is None


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_budget_rejects_non_finite_wall_limit(value):
    with pytest.raises(ValueError):
        BudgetLedger().change_limit("wall_time", value)


def test_budget_context_limit_is_compression_single_source(tmp_path):
    budget = BudgetLedger()
    budget.change_limit("context", 777)
    env = make_loop(tmp_path, [], loop_kw={"budget": budget})
    assert env.loop._max_context_tokens == 777


def test_budget_restores_complete_wall_segments_and_marks_crash_unknown():
    records = [
        {
            "kind": "run_started",
            "ts": "2026-11-04T00:00:00+00:00",
            "payload": {},
        },
        {
            "kind": "run_finished",
            "ts": "2026-11-04T00:00:12.500000+00:00",
            "payload": {"rounds": 1},
        },
        {
            "kind": "run_started",
            "ts": "2026-11-04T00:01:00+00:00",
            "payload": {"run_id": "crashed"},
        },
    ]
    restored = BudgetLedger.from_records(records)
    restored.change_limit("wall_time", 60)
    snapshot = restored.snapshot()
    assert snapshot["wall_time_seconds"] == 12.5
    assert snapshot["wall_time_status"] == "unknown"
    assert restored.exhaustion()["reason"] == "wall_time_unknown"


# ---------------------------------------------------------------------------
# R12-B:模型/工具/重试派发前约束
# ---------------------------------------------------------------------------


async def test_context_still_too_large(tmp_path):
    env = make_loop(
        tmp_path,
        [[TextDelta("不应请求。"), Usage(1, 1)]],
        loop_kw={"max_context_tokens": 50, "keep_recent_messages": 2},
    )
    result = await env.loop.run("X" * 400)
    assert result.status == "stopped"
    assert env.backend.chat_count == 0
    compressed = next(
        r["payload"]
        for r in audit_records(env)
        if r["kind"] == "context_compressed"
    )
    assert compressed["still_over_budget"] is True
    assert result.budget["context_tokens_estimated"] > 50


async def test_total_budget_blocks_tool_and_records_inflight_overrun(tmp_path):
    env = make_loop(
        tmp_path,
        [
            [
                ToolCall("tc-over", "run_command", {"command": "echo SHOULD_NOT_RUN"}),
                Usage(8, 8),
            ]
        ],
        loop_kw={"max_total_tokens": 10},
    )
    result = await env.loop.run("在途超额")
    assert result.status == "stopped"
    assert result.budget["total_tokens"] == 16
    assert result.budget["measured_total_tokens"] == 16
    assert env.backend.chat_count == 1
    assert not (env.outputs / "tc-over").exists()
    assert not any(
        r["kind"] in ("exec_request", "exec_result_meta")
        for r in audit_records(env)
    )
    assert "累计 token" in result.error


async def test_unknown_usage_with_finite_limit_stops_tool_dispatch(tmp_path):
    env = make_loop(
        tmp_path,
        [
            [
                ToolCall("tc-unknown", "run_command", {"command": "echo NO"}),
                Usage(),
            ]
        ],
        loop_kw={"max_total_tokens": 100},
    )
    result = await env.loop.run("未知用量")
    assert result.status == "stopped"
    assert result.budget["total_tokens"] is None
    assert result.budget["unknown_usage_requests"] == 1
    assert not any(r["kind"] == "exec_request" for r in audit_records(env))
    assert "unknown" in result.error


async def test_total_budget_blocks_retry(tmp_path, monkeypatch):
    async def no_sleep(_delay):
        pass

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    env = make_loop(
        tmp_path,
        [
            ([Usage(6, 4)], ServerError("synthetic", provider="fake")),
            [TextDelta("不应重试。"), Usage(1, 1)],
        ],
        loop_kw={"max_total_tokens": 10, "max_retries": 1},
    )
    result = await env.loop.run("重试预算")
    assert result.status == "stopped"
    assert env.backend.chat_count == 1
    assert result.budget["total_tokens"] == 10
    assert not any(r["kind"] == "llm_retry" for r in audit_records(env))


async def test_wall_time_budget_blocks_tool_with_monotonic_clock(tmp_path):
    now = [0.0]
    budget = BudgetLedger(monotonic=lambda: now[0])
    budget.change_limit("wall_time", 5)

    async def respond(_messages):
        now[0] = 6.0
        return [
            ToolCall("tc-time", "run_command", {"command": "echo NO"}),
            Usage(1, 1),
        ]

    env = make_loop(tmp_path, [respond], loop_kw={"budget": budget})
    result = await env.loop.run("墙钟预算")
    assert result.status == "stopped"
    assert result.budget["wall_time_seconds"] == 6
    assert not any(r["kind"] == "exec_request" for r in audit_records(env))
    assert "墙钟" in result.error


async def test_token_limit_response_is_error_not_completed_summary(tmp_path):
    env = make_loop(
        tmp_path,
        [
            (
                [TextDelta("不完整的末尾"), Usage(4, 2)],
                IncompleteResponseError(
                    "synthetic finish_reason=length", provider="fake"
                ),
            )
        ],
    )
    result = await env.loop.run("不完整响应")
    assert result.status == "error"
    assert result.summary == ""
    assert result.budget["measured_total_tokens"] == 6
    finished = audit_records(env)[-1]
    assert finished["kind"] == "run_finished"
    assert finished["payload"]["status"] == "error"
    assert "length" in finished["payload"]["error"]


# ---------------------------------------------------------------------------
# R12-C:连续对话、可恢复停止与显式扩容
# ---------------------------------------------------------------------------


async def test_interjection_does_not_reset_budget(tmp_path):
    env = make_loop(
        tmp_path,
        [
            [TextDelta("第一段完成。"), Usage(2, 1)],
            [TextDelta("第二段完成。"), Usage(2, 1)],
            [TextDelta("不应继续请求。"), Usage(1, 1)],
        ],
        loop_kw={"wait_on_finish": True, "max_rounds": 2},
    )
    task = asyncio.create_task(env.loop.run("连续对话"))

    async def wait_idle(rounds):
        for _ in range(100):
            at_round = env.loop._budget.snapshot()["rounds"] == rounds
            if env.loop.status == "idle" and at_round:
                return
            await asyncio.sleep(0.01)
        raise AssertionError(f"未进入第 {rounds} 轮后的 idle")

    await wait_idle(1)
    env.loop.interject("普通插话继续")
    await wait_idle(2)
    assert env.loop._budget.limits.rounds == 2
    env.loop.interject("仍不扩容")
    result = await asyncio.wait_for(task, timeout=2)
    assert result.status == "stopped"
    assert result.stop_reason == "rounds"
    assert result.budget["rounds"] == 2
    assert result.budget["limits"]["rounds"] == 2
    assert env.backend.chat_count == 2
    assert not any(
        r["kind"] == "budget_limit_changed" for r in audit_records(env)
    )


async def test_resume_preserves_limit_until_explicit_expansion(tmp_path):
    first = make_loop(
        tmp_path,
        [
            [
                ToolCall("tc-first", "run_command", {"command": "echo NO"}),
                Usage(1, 1),
            ]
        ],
        loop_kw={"max_rounds": 1},
    )
    first_result = await first.loop.run("预算恢复")
    assert first_result.status == "stopped"
    assert audit_records(first)[-1]["payload"]["goal_status"] == "unfinished"

    restored = BudgetLedger.from_records(audit_records(first))
    second = make_loop(
        tmp_path,
        [[TextDelta("不应请求。"), Usage(1, 1)]],
        loop_kw={"budget": restored},
    )
    second_result = await second.loop.run("预算恢复")
    assert second_result.status == "stopped"
    assert second.backend.chat_count == 0
    assert second_result.budget["limits"]["rounds"] == 1

    expanded = BudgetLedger.from_records(
        audit_records(first), overrides={"rounds": 3}, operator="tester"
    )
    third = make_loop(
        tmp_path,
        [[TextDelta("扩容后完成。"), Usage(1, 1)]],
        loop_kw={"budget": expanded},
    )
    third_result = await third.loop.run("预算恢复")
    assert third_result.status == "finished"
    assert third_result.budget["rounds"] == 2
    change = next(
        r["payload"]
        for r in audit_records(first)
        if r["kind"] == "budget_limit_changed"
    )
    assert change["dimension"] == "rounds"
    assert change["old_limit"] == 1
    assert change["new_limit"] == 3
    assert change["change"] == "expanded"
    assert change["operator"] == "tester"


async def test_near_budget_guides_wrap_up_without_expanding(tmp_path):
    env = make_loop(
        tmp_path,
        [
            [
                ToolCall("tc-1", "run_command", {"command": "echo one"}),
                Usage(8, 2),
            ],
            [
                ToolCall("tc-2", "run_command", {"command": "echo two"}),
                Usage(4, 2),
            ],
            [TextDelta("收尾完成。"), Usage(1, 1)],
        ],
        loop_kw={"max_total_tokens": 20},
    )
    result = await env.loop.run("接近预算")
    assert result.status == "finished"
    assert result.budget["limits"]["total_tokens"] == 20
    warnings = [
        r["payload"]
        for r in audit_records(env)
        if r["kind"] == "budget_warning"
    ]
    assert len(warnings) == 1
    assert warnings[0]["dimensions"] == ["total_tokens"]
    assert any(
        m.role == "user" and "预算提醒" in m.content
        for m in env.backend.calls[-1]
    )
    assert not any(
        r["kind"] == "budget_limit_changed" for r in audit_records(env)
    )
