"""R09 证据 manifest / 结项页 / 只读核验(verify)测试。

fixture 约定(契约 §4):凭据与目标一律明显合成——TESTONLY 前缀、
RFC 5737 文档保留网段(192.0.2.0/24、198.51.100.0/24)、127.0.0.0/8 本机
与 example.com;engagement 一律建在 tmp_path,运行时产物不入库。

R09-A:build_manifest 确定性与 run/scope/终态绑定、loot 登记快照演化
(test_loot_snapshot_evolution)、并发终态 manifest 不漏项(AC06 manifest 侧)、
结项页确定性渲染与落盘权限。
R09-B:verify_engagement 只读四维判定(文件后半)。
R09-C:退出码与 CLI/TUI 终态接线(文件后半)。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import stat
from collections import deque
from pathlib import Path

import pytest

from foam.agent.backends.base import LLMBackend, TextDelta, ToolCall, Usage
from foam.cli import main as cli_main
from foam.guard.audit import (
    KIND_SCOPE_LOADED,
    AuditLog,
)
from foam.guard.scope import parse_scope, scope_payload
from foam.replay import read_records
from foam.state.files import Engagement
from foam.tools.state import StateTool

SCOPE_TEXT = "127.0.0.0/8\nlocalhost\n"
FIXED_NOW = "2026-10-12T00:00:00+00:00"  # 固定 generated_at,确定性断言用


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    """HOME 隔离到 tmp_path(与 test_cli 同模式):消除真实 ~/.foam/config.json
    的 [config] profile 行对 stdout 断言的串扰。"""
    monkeypatch.setenv("HOME", str(tmp_path))


class FakeBackend(LLMBackend):
    """脚本化后端(与 test_cli.FakeBackend 同模式,自包含一份):calls 记录
    每轮 messages,tools_seen 记录工具 specs;条目可为 callable/异常。"""

    provider = "fake"

    def __init__(self, script=()):
        self._script = deque(script)
        self.calls: list[list] = []
        self.tools_seen = None

    async def aclose(self) -> None:
        pass

    def chat(self, messages, tools=None):
        self.calls.append(list(messages))
        self.tools_seen = tools
        return self._stream()

    async def _stream(self):
        entry = self._script.popleft() if self._script else [Usage(1, 1)]
        if callable(entry):
            entry = await entry(self.calls[-1])
        if isinstance(entry, BaseException):
            raise entry
        for event in entry:
            yield event


FINISH = [TextDelta("侦察结束,无进一步动作。"), Usage(2, 2)]


def run_cli_once(tmp_path: Path, backend: FakeBackend, *, objective: str = "侦察本机"):
    """跑一次 headless run(fake 后端),返回 (rc, engagement 目录)。"""
    scope_file = tmp_path / "lab.scope"
    scope_file.write_text(SCOPE_TEXT, encoding="utf-8")
    workdir = tmp_path / "eng"
    rc = cli_main(
        [
            "run",
            "--scope",
            str(scope_file),
            "--objective",
            objective,
            "--workdir",
            str(workdir),
        ],
        backend_factory=lambda _args: backend,
    )
    return rc, workdir


def _engagement_with_terminal_run(
    tmp_path: Path, *, run_id: str = "run01a", status: str = "finished"
) -> Engagement:
    """合成终态 engagement:真实 scope 文件 + 链(scope_loaded → run_started
    → exec_result_meta → run_finished)+ 一份真实 outputs 产物。"""
    scope_file = tmp_path / "lab.scope"
    scope_file.write_text(SCOPE_TEXT, encoding="utf-8")
    engagement = Engagement.create(
        tmp_path / "engagements",
        "证据测试",
        scope_path=scope_file,
        engagement_id="ev-eng",
    )
    root = engagement.paths.root
    out = engagement.paths.outputs / "job01.log"
    payload = b"TESTONLY output bytes\n"
    out.write_bytes(payload)
    audit = AuditLog(engagement.paths.audit_jsonl)
    audit.append(
        KIND_SCOPE_LOADED,
        scope_payload(parse_scope(SCOPE_TEXT), str(scope_file)),
    )
    audit.append(
        "run_started",
        {
            "objective": "证据测试",
            "provider": "fake",
            "workdir": str(root),
            "run_id": run_id,
        },
    )
    audit.append(
        "exec_result_meta",
        {
            "job_id": "job01",
            "status": "completed",
            "exit_code": 0,
            "duration_ms": 5,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "output_path": str(out),
            "total_bytes": len(payload),
        },
    )
    audit.append(
        "run_finished",
        {
            "status": status,
            "rounds": 1,
            "input_tokens": 1,
            "output_tokens": 1,
            "error": None,
            "run_id": run_id,
        },
    )
    audit.close()
    return engagement


def _read_index_ro(db_path: Path) -> sqlite3.Connection:
    """测试侧只读连接(与 verify 同口径:URI mode=ro)。"""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# R09-A:build_manifest 确定性 / 绑定 / 无终态不补造
# ---------------------------------------------------------------------------


def test_build_manifest_deterministic(tmp_path):
    """同一输入 + 固定 generated_at → 两次构建逐字节一致(确定性)。"""
    from foam.evidence import build_manifest

    engagement = _engagement_with_terminal_run(tmp_path)
    root = engagement.paths.root
    m1 = build_manifest(root, generated_at=FIXED_NOW)
    m2 = build_manifest(root, generated_at=FIXED_NOW)
    assert m1 is not None and m1 == m2
    text1 = json.dumps(m1, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    text2 = json.dumps(m2, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    assert text1 == text2
    engagement.close()


def test_build_manifest_binds_run_scope_end_reason(tmp_path):
    """manifest 绑定 run_id / scope 修订与哈希 / 结束原因 / 链头。"""
    from foam.evidence import build_manifest

    engagement = _engagement_with_terminal_run(tmp_path, run_id="bind01")
    root = engagement.paths.root
    manifest = build_manifest(root, generated_at=FIXED_NOW)
    assert manifest is not None

    assert manifest["format"] == 1
    assert manifest["engagement_id"] == "ev-eng"
    assert manifest["run_id"] == "bind01"
    assert manifest["end_reason"]["status"] == "finished"
    assert manifest["end_reason"]["error"] is None

    expected_scope_sha = hashlib.sha256(SCOPE_TEXT.encode()).hexdigest()
    assert manifest["scope"]["sha256"] == expected_scope_sha

    records = read_records(root / "audit.jsonl")
    assert manifest["chain"]["verify"] is True
    assert manifest["chain"]["records"] == len(records)
    assert manifest["chain"]["head_seq"] == records[-1]["seq"]
    assert manifest["chain"]["head_hash"] == records[-1]["hash"]

    artifacts = {a["path"]: a for a in manifest["artifacts"]}
    assert "outputs/job01.log" in artifacts
    entry = artifacts["outputs/job01.log"]
    assert entry["sha256"] == hashlib.sha256(b"TESTONLY output bytes\n").hexdigest()
    assert entry["hash_origin"] == "recorded"
    assert manifest["external_anchor"] == "none"
    engagement.close()


def test_build_manifest_none_without_run_finished(tmp_path):
    """无 run_finished(未终态/崩溃)不补造 manifest——build 返回 None。"""
    from foam.evidence import build_manifest

    scope_file = tmp_path / "lab.scope"
    scope_file.write_text(SCOPE_TEXT, encoding="utf-8")
    engagement = Engagement.create(
        tmp_path / "engagements",
        "未终态",
        scope_path=scope_file,
        engagement_id="open-eng",
    )
    audit = AuditLog(engagement.paths.audit_jsonl)
    audit.append(
        "run_started",
        {
            "objective": "未终态",
            "provider": "fake",
            "workdir": str(engagement.paths.root),
            "run_id": "open01",
        },
    )
    audit.close()
    assert build_manifest(engagement.paths.root, generated_at=FIXED_NOW) is None
    engagement.close()


async def test_loot_snapshot_evolution(tmp_path):
    """loot 登记快照演化(规格点名场景):登记后文件增长 → manifest 检出
    登记快照与现值分叉,且登记快照不被后续登记覆盖。"""
    from foam.evidence import build_manifest

    engagement = _engagement_with_terminal_run(tmp_path)
    root = engagement.paths.root
    loot_file = engagement.paths.loot / "dump.txt"
    v1 = b"TESTONLY dump v1"
    loot_file.write_bytes(v1)
    first_hash = hashlib.sha256(v1).hexdigest()

    tool = StateTool(engagement)
    res = await tool.dispatch("state_add_loot", {"path": "loot/dump.txt"})
    tool.close()
    assert res["added"] is True and res["sha256"] == first_hash

    m1 = build_manifest(root, generated_at=FIXED_NOW)
    snap = m1["loot_snapshots"][0]
    assert snap["path"] == "loot/dump.txt"
    assert snap["registered_sha256"] == first_hash
    assert snap["current_sha256"] == first_hash
    assert snap["status"] == "match"

    # 登记后文件增长:登记快照不覆盖,分叉可检出
    grown = v1 + b" v2 growth"
    loot_file.write_bytes(grown)
    m2 = build_manifest(root, generated_at=FIXED_NOW)
    snap = m2["loot_snapshots"][0]
    assert snap["registered_sha256"] == first_hash
    assert snap["current_sha256"] == hashlib.sha256(grown).hexdigest()
    assert snap["status"] == "diverged"

    # 重复登记:首次快照仍不覆盖(索引层语义的 manifest 面复核)
    tool = StateTool(engagement)
    await tool.dispatch("state_add_loot", {"path": "loot/dump.txt", "note": "再登记"})
    tool.close()
    m3 = build_manifest(root, generated_at=FIXED_NOW)
    snap = m3["loot_snapshots"][0]
    assert snap["registered_sha256"] == first_hash
    assert snap["status"] == "diverged"
    engagement.close()


def test_manifest_covers_concurrent_terminal_background_jobs(tmp_path):
    """AC06 manifest 侧:并发终态(多个后台 job 在收尾临界完成)不漏项——
    manifest artifacts 覆盖全部 job_events 行记录的分流产物。"""
    from foam.evidence import build_manifest

    backend = FakeBackend(
        [
            [
                ToolCall(
                    "tc-1",
                    "run_command",
                    {"command": "echo TESTONLY-bg-a", "background": True},
                ),
                ToolCall(
                    "tc-2",
                    "run_command",
                    {"command": "echo TESTONLY-bg-b", "background": True},
                ),
                Usage(1, 1),
            ],
            FINISH,
        ]
    )
    rc, workdir = run_cli_once(tmp_path, backend)
    assert rc == 0

    manifest = build_manifest(workdir, generated_at=FIXED_NOW)
    assert manifest is not None
    artifact_paths = {a["path"] for a in manifest["artifacts"]}

    conn = _read_index_ro(workdir / "index.sqlite")
    rows = conn.execute("SELECT event_id, output_refs FROM job_events").fetchall()
    conn.close()
    assert len(rows) == 2  # 两个后台 job 各有终态事件
    for row in rows:
        refs = json.loads(row["output_refs"])
        for key in ("output_path", "stdout_path", "stderr_path"):
            recorded = refs.get(key)
            assert recorded, f"{row['event_id']} 缺 {key}"
            rel = Path(recorded).relative_to(workdir)  # 绝对路径记录口径
            assert str(rel) in artifact_paths, (
                f"{row['event_id']} 的 {rel} 未进 manifest artifacts"
            )
    # 记录 hash 与盘上文件一致(manifest 绑定的是真实定稿)
    for artifact in manifest["artifacts"]:
        if artifact["hash_origin"] != "recorded":
            continue
        current = hashlib.sha256((workdir / artifact["path"]).read_bytes()).hexdigest()
        assert artifact["sha256"] == current


# ---------------------------------------------------------------------------
# R09-A:结项页渲染与落盘
# ---------------------------------------------------------------------------


def test_summary_md_deterministic_and_sections(tmp_path):
    """结项页从同一 manifest dict 确定性渲染;必备节齐全。"""
    from foam.evidence import build_manifest, render_summary_md

    engagement = _engagement_with_terminal_run(tmp_path, run_id="page01")
    manifest = build_manifest(engagement.paths.root, generated_at=FIXED_NOW)
    md1 = render_summary_md(manifest)
    md2 = render_summary_md(manifest)
    assert md1 == md2  # 同 manifest 逐字节一致
    for marker in ("终态", "范围", "链", "产物", "loot", "外部锚定"):
        assert marker in md1, f"结项页缺「{marker}」节"
    assert "page01" in md1
    assert "finished" in md1
    assert "未外部锚定" in md1
    engagement.close()


def test_write_manifest_files_and_permissions(tmp_path):
    """write_manifest:evidence/ 下落 manifest+结项页两份文件,0600,
    同 generated_at 重写逐字节一致(幂等);无 run_finished 不写不留痕。"""
    from foam.evidence import build_manifest, write_manifest

    engagement = _engagement_with_terminal_run(tmp_path, run_id="w01")
    root = engagement.paths.root
    written = write_manifest(root, generated_at=FIXED_NOW)
    assert written is not None
    json_path, md_path = written
    assert json_path == root / "evidence" / "manifest-w01.json"
    assert md_path == root / "evidence" / "summary-w01.md"
    for path in (json_path, md_path):
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600, f"{path.name} 应 0o600,实际 {mode:#o}"
    manifest = json.loads(json_path.read_text(encoding="utf-8"))
    assert manifest == build_manifest(root, generated_at=FIXED_NOW)

    first_bytes = json_path.read_bytes()
    first_md = md_path.read_bytes()
    assert write_manifest(root, generated_at=FIXED_NOW) is not None
    assert json_path.read_bytes() == first_bytes  # 同输入重写逐字节一致
    assert md_path.read_bytes() == first_md
    engagement.close()


def test_write_manifest_none_without_terminal_run(tmp_path):
    """未终态(无 run_finished)不写 manifest、不建 evidence/ 文件。"""
    from foam.evidence import write_manifest

    scope_file = tmp_path / "lab.scope"
    scope_file.write_text(SCOPE_TEXT, encoding="utf-8")
    engagement = Engagement.create(
        tmp_path / "engagements",
        "未终态",
        scope_path=scope_file,
        engagement_id="open-eng2",
    )
    assert write_manifest(engagement.paths.root, generated_at=FIXED_NOW) is None
    evidence_dir = engagement.paths.root / "evidence"
    assert not evidence_dir.exists() or list(evidence_dir.iterdir()) == []
    engagement.close()

