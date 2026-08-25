"""WP-11 任务一单测:解析层挂进 loop 的 run_command 结果钩子。

- fake 后端脚本化驱动(与 test_loop 同模式,自带一份保持自包含);
  run_command 的 dispatch 用注册表注入缝换成罐头结果(指向 tmp 落盘
  fixture 文件),不真跑 nmap——钩子逻辑与解析效果才是被测对象。
- 验收(任务一第 3 条):命中 → LLM 视图拿到解析 summary、索引
  hosts/ports 可查;未知工具命令零影响。
"""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from types import SimpleNamespace

from foam.agent.backends.base import LLMBackend, Message, TextDelta, ToolCall, Usage
from foam.agent.loop import AgentLoop, ToolRegistry
from foam.agent.prompts import build_system_prompt
from foam.guard.audit import KIND_SCOPE_LOADED, AuditLog, verify
from foam.guard.scope import parse_scope, scope_payload
from foam.state.index import Index
from foam.tools.bash import TOOL_SCHEMAS, BashTool

FIXTURES = Path(__file__).parent / "fixtures"
SCOPE_TEXT = "192.0.2.0/24\n"
FIXED_TS = "2026-08-25T00:00:00+00:00"
NMAP_CMD = "nmap -sV 192.0.2.10 192.0.2.11"
CURL_CMD = "curl -s 192.0.2.10"
GENERIC_VIEW = "GENERIC_VIEW_MARKER:head+tail 通用截断视图原文"


class FakeBackend(LLMBackend):
    """脚本化后端:calls 记录每轮 messages。"""

    provider = "fake"

    def __init__(self, script=()):
        self._script = deque(script)
        self.calls: list[list[Message]] = []

    async def aclose(self) -> None:
        pass

    def chat(self, messages, tools=None):
        self.calls.append(list(messages))
        return self._stream()

    async def _stream(self):
        events = self._script.popleft() if self._script else [Usage(1, 1)]
        for event in events:
            yield event


FINISH = [TextDelta("侦察结束,无进一步动作。"), Usage(2, 2)]


def toolcall_script(command: str) -> list:
    return [
        [ToolCall("tc-1", "run_command", {"command": command}), Usage(1, 1)],
        FINISH,
    ]


def audit_records(env) -> list[dict]:
    return [
        json.loads(line)
        for line in env.audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def tool_result_view(env, tool_call_id: str = "tc-1") -> str:
    """主环消息流里该工具调用结果的 output_view(即 LLM 看到的)。"""
    for message in env.loop.messages:
        if message.role == "tool" and message.tool_call_id == tool_call_id:
            return json.loads(message.content)["output_view"]
    raise AssertionError(f"工具结果消息不存在: {tool_call_id}")


def make_env(
    tmp_path: Path,
    canned: dict,
    *,
    with_index: bool = True,
    command: str = NMAP_CMD,
) -> SimpleNamespace:
    """搭 loop 环境:registry 注入缝把 run_command 换成罐头结果。"""
    scope = parse_scope(SCOPE_TEXT)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.append(KIND_SCOPE_LOADED, scope_payload(scope, "test.scope"))
    bash = BashTool(tmp_path / "outputs")  # 仅 kill 清理面用;dispatch 不进它
    prompt = build_system_prompt(
        scope, source="test.scope", loaded_at=FIXED_TS, workdir=tmp_path
    )
    backend = FakeBackend(toolcall_script(command))
    registry = ToolRegistry()

    async def fake_dispatch(name, arguments):
        assert name == "run_command"
        return dict(canned)

    registry.register_module(TOOL_SCHEMAS, fake_dispatch)
    index = Index(tmp_path / "index.sqlite") if with_index else None
    loop = AgentLoop(
        backend=backend,
        bash=bash,
        scope=scope,
        audit=audit,
        workdir=tmp_path,
        system_prompt=prompt,
        registry=registry,
        index=index,
    )
    return SimpleNamespace(
        loop=loop,
        backend=backend,
        index=index,
        audit_path=tmp_path / "audit.jsonl",
    )


def canned_result(tmp_path: Path, fixture: str, *, status: str = "completed") -> dict:
    """罐头 run_command 终态结果:fixture 全文落盘,视图为通用截断文本。"""
    outputs = tmp_path / "outputs"
    outputs.mkdir(exist_ok=True)
    raw = (FIXTURES / fixture).read_bytes()
    output_path = outputs / "cannedjob12.log"
    output_path.write_bytes(raw)
    return {
        "job_id": "cannedjob12",
        "status": status,
        "exit_code": 0,
        "duration_ms": 12,
        "output_view": GENERIC_VIEW,
        "output_path": str(output_path),
        "sha256": "ab" * 32,
        "stdout_path": None,
        "stdout_sha256": None,
        "stderr_path": None,
        "stderr_sha256": None,
        "total_bytes": len(raw),
        "total_lines": raw.count(b"\n"),
    }


def exec_meta_records(env) -> list[dict]:
    return [r for r in audit_records(env) if r["kind"] == "exec_result_meta"]


# ---------------------------------------------------------------------------
# 命中:LLM 视图换摘要,facts 入库(任务一第 3 条前半)
# ---------------------------------------------------------------------------


async def test_parse_hit_replaces_view_and_applies_facts(tmp_path):
    env = make_env(tmp_path, canned_result(tmp_path, "nmap_table.txt"))
    result = await env.loop.run("侦察 192.0.2.0/24")
    assert result.status == "finished"

    view = tool_result_view(env)
    assert view.startswith("[解析摘要:nmap]")
    assert "2 台存活" in view and "445/microsoft-ds" in view
    assert GENERIC_VIEW not in view  # 通用截断视图被替代
    assert "Starting Nmap" not in view  # 原文不进 LLM 视图(落盘可分页核)

    # facts 进 WP-06 索引:hosts/ports 可查
    assert env.index is not None
    counts = env.index.counts()
    assert counts["hosts"] == 2
    assert counts["ports"] == 4

    # 审计:exec_result_meta 带解析元信息与入库统计,链完整
    exec_meta = exec_meta_records(env)
    assert len(exec_meta) == 1
    parsed = exec_meta[0]["payload"]["parsed"]
    assert parsed["tool"] == "nmap"
    assert parsed["facts"] == 6  # 2 host + 4 port
    assert parsed["facts_applied"]["hosts"] == 2
    assert parsed["facts_applied"]["ports"] == 4
    assert parsed["facts_applied"]["skipped"] == 0
    assert verify(env.audit_path)


# ---------------------------------------------------------------------------
# 未知工具:零影响(任务一第 3 条后半)
# ---------------------------------------------------------------------------


async def test_unknown_tool_keeps_generic_view(tmp_path):
    """curl 无解析器:即使输出长得像 nmap 也不触发任何解析动作。"""
    env = make_env(
        tmp_path, canned_result(tmp_path, "nmap_table.txt"), command=CURL_CMD
    )
    result = await env.loop.run("看一眼 192.0.2.10")
    assert result.status == "finished"

    assert tool_result_view(env) == GENERIC_VIEW  # 原样,未被动过
    records = audit_records(env)
    assert "parsed" not in exec_meta_records(env)[0]["payload"]
    # 注册表未命中是常态:不记 parse_fallback(WP-07 语义)
    assert not [r for r in records if r["kind"] == "parse_fallback"]
    assert env.index is not None
    assert env.index.counts()["hosts"] == 0
    assert verify(env.audit_path)


# ---------------------------------------------------------------------------
# 回退:解析失败静默走通用路径,主环无恙
# ---------------------------------------------------------------------------


async def test_damaged_output_falls_back_with_debug_audit(tmp_path):
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    broken = outputs / "cannedjob12.log"
    broken.write_text("TOTAL GARBAGE {{{ 不是任何工具输出\n", encoding="utf-8")
    canned = {
        "job_id": "cannedjob12",
        "status": "completed",
        "exit_code": 0,
        "duration_ms": 3,
        "output_view": GENERIC_VIEW,
        "output_path": str(broken),
        "sha256": "cd" * 32,
        "stdout_path": None,
        "stdout_sha256": None,
        "stderr_path": None,
        "stderr_sha256": None,
        "total_bytes": broken.stat().st_size,
        "total_lines": 1,
    }
    env = make_env(tmp_path, canned)
    result = await env.loop.run("侦察 192.0.2.0/24")
    assert result.status == "finished"  # 主环不受解析失败影响

    assert tool_result_view(env) == GENERIC_VIEW
    records = audit_records(env)
    fallback = [r for r in records if r["kind"] == "parse_fallback"]
    assert len(fallback) == 1
    assert fallback[0]["payload"]["tool"] == "nmap"
    assert fallback[0]["payload"]["reason"] == "no_match"
    assert "parsed" not in exec_meta_records(env)[0]["payload"]
    assert env.index is not None
    assert env.index.counts()["hosts"] == 0
    assert verify(env.audit_path)


# ---------------------------------------------------------------------------
# 边界:无 index 只换视图;running 态不解析(防 background 噪音审计)
# ---------------------------------------------------------------------------


async def test_parse_without_index_still_swaps_view(tmp_path):
    env = make_env(
        tmp_path, canned_result(tmp_path, "nmap_table.txt"), with_index=False
    )
    result = await env.loop.run("侦察 192.0.2.0/24")
    assert result.status == "finished"
    assert env.index is None

    assert tool_result_view(env).startswith("[解析摘要:nmap]")
    parsed = exec_meta_records(env)[0]["payload"]["parsed"]
    assert parsed["tool"] == "nmap"
    assert "facts_applied" not in parsed  # 无索引:只换视图,不记入库统计


async def test_running_status_not_parsed(tmp_path):
    env = make_env(
        tmp_path,
        canned_result(tmp_path, "nmap_table.txt", status="running"),
    )
    await env.loop.run("后台侦察 192.0.2.0/24")

    assert tool_result_view(env) == GENERIC_VIEW
    records = audit_records(env)
    assert not [r for r in records if r["kind"] == "parse_fallback"]
    assert "parsed" not in exec_meta_records(env)[0]["payload"]
