"""WP-11 任务一单测:解析层挂进 loop 的 run_command 结果钩子。

- fake 后端脚本化驱动(与 test_loop 同模式,自带一份保持自包含);
  run_command 的 dispatch 用注册表注入缝换成罐头结果(指向 tmp 落盘
  fixture 文件),不真跑 nmap——钩子逻辑与解析效果才是被测对象。
- 验收(任务一第 3 条):命中 → LLM 视图拿到解析 summary、索引
  hosts/ports 可查;未知工具命令零影响。
"""

from __future__ import annotations

import asyncio
import json
import os
from collections import deque
from pathlib import Path
from types import SimpleNamespace

from foam.agent.backends.base import LLMBackend, Message, TextDelta, ToolCall, Usage
from foam.agent.loop import AgentLoop, ToolRegistry
from foam.agent.prompts import build_system_prompt
from foam.guard.audit import KIND_SCOPE_LOADED, AuditLog, verify
from foam.guard.scope import parse_scope, scope_payload
from foam.state.index import Index
from foam.tools.bash import TOOL_SCHEMAS, BashTool, JobExitEvent
from foam.tools.parse import maybe_parse

FIXTURES = Path(__file__).parent / "fixtures"
SCOPE_TEXT = "192.0.2.0/24\n"
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
    prompt = build_system_prompt(workdir=tmp_path)
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


# ---------------------------------------------------------------------------
# R06-B:后台终态事件的幂等解析消费(决策 3/4/5/8,规格 §4 R06-B)
# ---------------------------------------------------------------------------

BG_NMAP_CMD = "nmap -sV 192.0.2.10 192.0.2.11"


class DelayedBackend(FakeBackend):
    """第二轮响应前 sleep,给后台 job 留自然完成的窗口(确定性竞态注入)。"""

    def __init__(self, script=(), delay=0.6):
        super().__init__(script)
        self._delay = delay
        self._round = 0

    async def _stream(self):
        self._round += 1
        if self._round > 1 and self._delay:
            await asyncio.sleep(self._delay)
        async for event in super()._stream():
            yield event


def nmap_shim(tmp_path: Path, monkeypatch) -> Path:
    """在 tmp_path 造可执行 shim 脚本命名 nmap(cat 合成 fixture),注入 PATH 前缀。"""
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    fixture = (FIXTURES / "nmap_table.txt").resolve()
    shim = shim_dir / "nmap"
    shim.write_text(f"#!/bin/sh\ncat '{fixture}'\n", encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return shim


def make_live_env(tmp_path: Path, *, with_index: bool = True) -> SimpleNamespace:
    """真实 BashTool 的 loop 环境:run_command 走真进程(后台事件路径)。"""
    scope = parse_scope(SCOPE_TEXT)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.append(KIND_SCOPE_LOADED, scope_payload(scope, "test.scope"))
    bash = BashTool(tmp_path / "outputs")
    prompt = build_system_prompt(workdir=tmp_path)
    backend = DelayedBackend(
        [
            [
                ToolCall(
                    "tc-bg",
                    "run_command",
                    {"command": BG_NMAP_CMD, "background": True},
                ),
                Usage(1, 1),
            ],
            FINISH,
        ]
    )
    registry = ToolRegistry()
    registry.register_module(TOOL_SCHEMAS, bash.dispatch)
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
        loop=loop, bash=bash, index=index, audit_path=tmp_path / "audit.jsonl"
    )


async def _wait_job_exit_tasks(loop, within=5.0):
    """等后台终态消费任务清空(测试同步点;产品语义由 R06-C drain 保证)。"""
    deadline = asyncio.get_running_loop().time() + within
    while loop._job_exit_tasks:
        assert asyncio.get_running_loop().time() < deadline, "消费任务未清空"
        await asyncio.sleep(0.02)
        await asyncio.gather(*loop._job_exit_tasks, return_exceptions=True)


def _projection(index, table):
    """facts 行集投影(去 id/时间戳,比对业务字段)。"""
    if table == "hosts":
        sql = "SELECT ip, hostname FROM hosts"
    else:
        sql = (
            "SELECT h.ip, p.port, p.proto, p.service, p.product, p.version "
            "FROM ports p JOIN hosts h ON h.id = p.host_id"
        )
    return {tuple(row) for row in index._conn.execute(sql)}


def _replay_event(env):
    """从 bash 侧 job 重建同 event_id 的事件(模拟重复投递/恢复重放)。"""
    [job] = env.bash._jobs.values()
    manifest = job.manifest
    return JobExitEvent(
        event_id=f"job_exit:{job.job_id}",
        run_id=env.loop._run_id,
        job_id=job.job_id,
        command=job.command,
        reason=job.status,
        exit_code=job.exit_code,
        duration_ms=job.duration_ms,
        ended_at="2026-10-08T00:00:00+00:00",  # 重放时间戳不影响幂等键
        output_path=str(manifest.output_path),
        sha256=manifest.sha256,
        stdout_path=str(manifest.stdout_path),
        stdout_sha256=manifest.stdout_sha256,
        stderr_path=str(manifest.stderr_path),
        stderr_sha256=manifest.stderr_sha256,
        total_bytes=manifest.total_bytes,
        total_lines=manifest.total_lines,
    )


async def test_background_parse_matches_sync(tmp_path, monkeypatch):
    """R06-AC01/02:同一 nmap fixture,后台真实进程路径与同步罐头路径
    产出相同 facts 行集;全程不调用 list_jobs。"""
    nmap_shim(tmp_path, monkeypatch)
    live = make_live_env(tmp_path / "live")
    result = await live.loop.run("后台侦察 192.0.2.0/24")
    assert result.status == "finished"
    await _wait_job_exit_tasks(live.loop)

    canned_dir = tmp_path / "canned"
    canned_dir.mkdir()
    canned_env = make_env(canned_dir, canned_result(canned_dir, "nmap_table.txt"))
    assert (await canned_env.loop.run("侦察 192.0.2.0/24")).status == "finished"

    # AC01:两条路径 facts 行集一致(hosts 2 台、ports 4 个,与同步基线同)
    assert _projection(live.index, "hosts") == _projection(canned_env.index, "hosts")
    assert _projection(live.index, "ports") == _projection(canned_env.index, "ports")
    assert live.index.counts()["hosts"] == 2
    assert live.index.counts()["ports"] == 4

    # 消费登记:job_events 恰一行,consumed、reason=completed、审计已回写
    row = live.index._conn.execute("SELECT * FROM job_events").fetchone()
    assert row is not None
    assert row["status"] == "consumed"
    assert row["reason"] == "completed"
    assert row["event_id"] == f"job_exit:{row['job_id']}"
    assert row["run_id"] == live.loop._run_id
    assert row["audit_seq"] is not None
    assert row["parse_tool"] == "nmap"

    # 审计:job_exit 事件含 event_id 对账,链完整;run_started 携 run_id
    records = audit_records(live)
    job_exits = [r for r in records if r["kind"] == "job_exit"]
    assert len(job_exits) == 1
    assert job_exits[0]["payload"]["event_id"] == row["event_id"]
    assert job_exits[0]["payload"]["run_id"] == live.loop._run_id
    assert job_exits[0]["seq"] == row["audit_seq"]
    started = [r for r in records if r["kind"] == "run_started"]
    assert started[0]["payload"]["run_id"] == live.loop._run_id
    assert verify(live.audit_path)

    # 决策 8:即时返回的 running 记录保留,终态不双写 exec_result_meta
    exec_meta = exec_meta_records(live)
    assert len(exec_meta) == 1
    assert exec_meta[0]["payload"]["status"] == "running"
    assert "parsed" not in exec_meta[0]["payload"]  # running 态不解析


async def test_duplicate_delivery_not_double_applied(tmp_path, monkeypatch):
    """R06-AC04:重复投递同事件不重复 facts,job_events 仍一行,审计不重复。"""
    nmap_shim(tmp_path, monkeypatch)
    live = make_live_env(tmp_path / "live")
    await live.loop.run("后台侦察 192.0.2.0/24")
    await _wait_job_exit_tasks(live.loop)
    before = live.index.counts()

    await live.loop._consume_job_exit(_replay_event(live))  # 重复投递

    assert live.index.counts() == before  # facts 零增量
    rows = live.index._conn.execute("SELECT * FROM job_events").fetchall()
    assert len(rows) == 1
    job_exits = [r for r in audit_records(live) if r["kind"] == "job_exit"]
    assert len(job_exits) == 1  # 审计不重复


async def test_crash_before_audit_replay_backfills(tmp_path, monkeypatch):
    """R06-AC04 崩溃窗口:审计落链前失败 → audit_seq NULL → 重放补审计,
    不重复 facts;补写的审计可辨识(replayed 标记),不谎称恰好一次。"""
    nmap_shim(tmp_path, monkeypatch)
    live = make_live_env(tmp_path / "live")
    original_append = live.loop._audit.append

    def flaky_append(kind, payload):
        if kind == "job_exit":
            raise RuntimeError("模拟崩溃:审计不可用")
        return original_append(kind, payload)

    live.loop._audit.append = flaky_append  # 实例级打桩,仅挡 job_exit
    await live.loop.run("后台侦察 192.0.2.0/24")
    await _wait_job_exit_tasks(live.loop)

    # 崩溃窗口状态:行已 consumed、facts 已入库、audit_seq 悬空 NULL
    row = live.index._conn.execute("SELECT * FROM job_events").fetchone()
    assert row["status"] == "consumed"
    assert row["audit_seq"] is None
    before = live.index.counts()
    assert before["hosts"] == 2
    assert not [r for r in audit_records(live) if r["kind"] == "job_exit"]

    # 恢复重放:补审计、回写 audit_seq,facts 零增量
    live.loop._audit.append = original_append
    await live.loop._consume_job_exit(_replay_event(live))

    row = live.index._conn.execute("SELECT * FROM job_events").fetchone()
    assert row["audit_seq"] is not None
    assert live.index.counts() == before
    job_exits = [r for r in audit_records(live) if r["kind"] == "job_exit"]
    assert len(job_exits) == 1
    assert job_exits[0]["payload"]["replayed"] is True  # 可辨识
    assert job_exits[0]["seq"] == row["audit_seq"]
    assert verify(live.audit_path)


async def test_replay_after_index_reopen_not_double(tmp_path, monkeypatch):
    """R06-AC04:索引关闭重开后重放同事件仍幂等(持久消费记录,非内存 set)。"""
    nmap_shim(tmp_path, monkeypatch)
    live = make_live_env(tmp_path / "live")
    await live.loop.run("后台侦察 192.0.2.0/24")
    await _wait_job_exit_tasks(live.loop)
    before = live.index.counts()
    event = _replay_event(live)
    db_path = live.index.db_path
    live.index.close()

    reopened = Index(db_path)
    facts = maybe_parse(
        event.command,
        Path(event.output_path).read_text(encoding="utf-8", errors="replace"),
        output_path=event.output_path,
    ).facts
    outcome, stats = reopened.consume_job_exit(event, facts, parse_tool="nmap")
    assert outcome == "duplicate"
    assert stats is None
    assert reopened.counts() == before  # 重开重放不重复插入事实
    reopened.close()
