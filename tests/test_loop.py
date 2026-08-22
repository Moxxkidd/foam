"""WP-04 主环测试:fake 后端(脚本化事件序列)驱动 AgentLoop。

- FakeBackend 实现 LLMBackend 接口,逐轮弹出脚本;每轮脚本可以是:
  事件列表 / (事件列表, 末尾抛出的异常) / Exception(整轮直接抛)/
  callable(messages)——可挂起、可延迟,用于 kill/超时等时序测试。
- e2e 走真实 BashTool + 真实 AuditLog(tmp_path),命令全部无害
  (echo/python3 print/nmap --version);越界用例的越界命令只到护栏为止,
  永不执行。
- fixture 凭据不出现;scope 文本为合成网段。
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from types import SimpleNamespace

from foam.agent.backends.base import (
    LLMBackend,
    MalformedToolCallError,
    Message,
    ModerationError,
    TextDelta,
    ToolCall,
    Usage,
)
from foam.agent.loop import (
    FIRST_EVENT_TIMEOUT_SECONDS,
    AgentLoop,
    LoopObserver,
    ToolRegistry,
    describe_exit_code,
    estimate_tokens,
)
from foam.agent.prompts import build_system_prompt
from foam.cli import main as cli_main
from foam.guard.audit import KIND_SCOPE_LOADED, AuditLog, verify
from foam.guard.scope import parse_scope, scope_payload
from foam.tools.bash import TOOL_SCHEMAS, BashTool

FIXED_TS = "2026-08-21T00:00:00+00:00"
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
    prompt = build_system_prompt(
        scope, source="test.scope", loaded_at=FIXED_TS, workdir=tmp_path
    )
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
                ToolCall("tc-1", "run_command", {"command": "nmap --version"}),
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
    assert exec_requests[0]["payload"]["targets"] == []  # nmap --version 无目标
    assert exec_requests[1]["payload"]["targets"] == ["127.0.0.1"]
    for rec in [r for r in records if r["kind"] == "exec_result_meta"]:
        assert rec["payload"]["exit_code"] == 0
        assert rec["payload"]["sha256"]
    assert verify(env.audit_path)

    # 真实执行:nmap 版本输出进了 tool 结果;两个 tool 结果按序配对
    tc1 = tool_messages(env, "tc-1")
    assert len(tc1) == 1 and "Nmap version" in tc1[0].content
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
        loop_kw={"max_context_tokens": 2200, "keep_recent_messages": 4},
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
# CLI(headless run 子命令)
# ---------------------------------------------------------------------------


def test_cli_run_e2e(tmp_path, capsys):
    scope_file = tmp_path / "lab.scope"
    scope_file.write_text("127.0.0.0/8\n", encoding="utf-8")
    workdir = tmp_path / "eng"
    backend = FakeBackend(
        [
            [ToolCall("tc-1", "run_command", {"command": "echo cli-ok"}), Usage(1, 1)],
            [TextDelta("命令回显正常,无进一步动作。"), Usage(2, 2)],
        ]
    )
    rc = cli_main(
        [
            "run",
            "--scope",
            str(scope_file),
            "--objective",
            "冒烟测试",
            "--workdir",
            str(workdir),
            "--backend",
            "openai_compat",
        ],
        backend_factory=lambda _args: backend,
    )
    assert rc == 0
    assert verify(workdir / "audit.jsonl")
    kinds = [
        json.loads(line)["kind"]
        for line in (workdir / "audit.jsonl").read_text().splitlines()
    ]
    assert kinds[0] == "scope_loaded"
    assert "run_started" in kinds and kinds[-1] == "run_finished"
    assert (workdir / "ENGAGEMENT.md").exists()
    assert len(list((workdir / "outputs").glob("*.log"))) == 1
    out = capsys.readouterr().out
    assert "[run finished]" in out


def test_cli_missing_scope_file(tmp_path, capsys):
    rc = cli_main(
        [
            "run",
            "--scope",
            str(tmp_path / "nope.scope"),
            "--objective",
            "x",
            "--workdir",
            str(tmp_path / "eng"),
        ],
        backend_factory=lambda _args: FakeBackend([]),
    )
    assert rc == 2
    assert "scope 加载失败" in capsys.readouterr().err


def test_cli_missing_api_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("FOAM_ANTHROPIC_API_KEY", raising=False)
    scope_file = tmp_path / "lab.scope"
    scope_file.write_text("127.0.0.0/8\n", encoding="utf-8")
    rc = cli_main(
        [
            "run",
            "--scope",
            str(scope_file),
            "--objective",
            "x",
            "--workdir",
            str(tmp_path / "eng"),
            "--backend",
            "claude",
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "FOAM_ANTHROPIC_API_KEY" in err


def test_cli_no_subcommand_prints_help(capsys):
    assert cli_main([]) == 0
    assert "run" in capsys.readouterr().out
