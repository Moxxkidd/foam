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
import os
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
    tmp_path: Path,
    *,
    run_id: str = "run01a",
    status: str = "finished",
    error: str | None = None,
    extra_before_finish: list[tuple[str, dict]] | None = None,
) -> Engagement:
    """合成终态 engagement:真实 scope 文件 + 链(scope_loaded → run_started
    → exec_result_meta → [extra] → run_finished)+ 一份真实 outputs 产物。"""
    tmp_path.mkdir(parents=True, exist_ok=True)  # 允许子目录形态(如 sub/)
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
    for kind, extra_payload in extra_before_finish or []:
        audit.append(kind, extra_payload)
    audit.append(
        "run_finished",
        {
            "status": status,
            "rounds": 1,
            "input_tokens": 1,
            "output_tokens": 1,
            "error": error,
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
    json_path, md_path, written_manifest = written
    assert json_path == root / "evidence" / "manifest-w01.json"
    assert md_path == root / "evidence" / "summary-w01.md"
    assert written_manifest == build_manifest(root, generated_at=FIXED_NOW)
    for path in (json_path, md_path):
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600, f"{path.name} 应 0o600,实际 {mode:#o}"
    manifest = json.loads(json_path.read_text(encoding="utf-8"))
    assert manifest == written_manifest  # 落盘内容与返回 dict 一致

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



# ---------------------------------------------------------------------------
# R09-B:只读 verify(四维判定 / AC04 不改数据 / AC07 双渲染同源)
# ---------------------------------------------------------------------------

from foam.state.index import Index  # noqa: E402  # 装配用(非被测只读面)
from foam.tools.bash import JobExitEvent  # noqa: E402  # 合成终态事件


def _pass_fixture(tmp_path: Path) -> Engagement:
    """全过形态:终态链(含 session_op,会话覆盖 tracked)+ manifest 已生成。"""
    from foam.evidence import write_manifest

    engagement = _engagement_with_terminal_run(
        tmp_path,
        run_id="pass01",
        extra_before_finish=[
            (
                "session_op",
                {
                    "op_id": "op01",
                    "run_id": "pass01",
                    "call_id": "tc-s",
                    "op": "session_list",
                    "outcome": "ok",
                    "duration_ms": 1,
                    "ended_at": FIXED_NOW,
                    "session_id": None,
                    "count": 0,
                },
            )
        ],
    )
    assert write_manifest(engagement.paths.root, generated_at=FIXED_NOW) is not None
    return engagement


def test_verify_healthy_engagement_pass(tmp_path):
    """全过形态:四维全 pass,总判定 pass。"""
    from foam.evidence import verify_engagement

    engagement = _pass_fixture(tmp_path)
    result = verify_engagement(engagement.paths.root)
    for name in ("chain", "files", "references", "coverage"):
        dim = result.dimensions[name]
        assert dim.status == "pass", f"{name}: {dim.status} {dim.summary}"
    assert result.overall == "pass"
    assert result.engagement_id == "ev-eng"
    engagement.close()


def _tree_snapshot(root: Path) -> dict:
    """目录树快照:相对路径 → (内容 sha256, st_mode/mtime/ctime/size/ino)。

    st_atime 故意不在对比面——内容核验必须读文件,读即可能更新 atime
    (relatime),属核验语义固有(R09.md §7 决策 5 注记);其余元数据逐项钉死。
    """
    snap = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        st = path.lstat()
        entry = {
            "mode": stat.S_IMODE(st.st_mode),
            "mtime_ns": st.st_mtime_ns,
            "ctime_ns": st.st_ctime_ns,
            "size": st.st_size,
            "ino": st.st_ino,
        }
        if path.is_file() and not path.is_symlink():
            entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        snap[rel] = entry
    return snap


def test_verify_read_only(tmp_path):
    """AC04:verify 不改被检查数据——完整 engagement 核验前后目录树
    (文件清单 + 内容 hash + stat 元数据)零差异;无 journal/wal/bak/lock
    新增,不补造 evidence。"""
    from foam.evidence import verify_engagement

    engagement = _pass_fixture(tmp_path)
    root = engagement.paths.root
    engagement.close()
    # 再配一份 loot 登记(登记时快照)与 evidence_refs,让 verify 真读真算
    (root / "loot" / "dump.bin").write_bytes(b"TESTONLY loot v1")
    with Index(root / "index.sqlite") as index:
        index.add_loot(
            "loot/dump.bin",
            kind="dump",
            size_bytes=16,
            sha256=hashlib.sha256(b"TESTONLY loot v1").hexdigest(),
        )
        index.add_vuln(
            "192.0.2.10", "config", "TESTONLY 发现",
            evidence_refs=["outputs/job01.log"],
        )

    before = _tree_snapshot(root)
    result = verify_engagement(root)
    after = _tree_snapshot(root)

    assert result.overall == "pass"  # 核验本身有效(不是空转)
    assert before == after, (
        "verify 改动了被检查目录:"
        f"{[k for k in set(before) | set(after) if before.get(k) != after.get(k)]}"
    )
    names = set(before)
    assert not any(
        n.endswith(("-journal", "-wal", "-shm")) or ".bak" in n for n in names
    )
    assert "engagement.lock" not in names  # 未取锁、未建锁文件


def test_verify_locates_deleted_file(tmp_path):
    """AC01:删除已记录产物 → files fail 并定位;chain 不受影响(AC05 独立)。"""
    from foam.evidence import verify_engagement

    engagement = _pass_fixture(tmp_path)
    (engagement.paths.outputs / "job01.log").unlink()
    result = verify_engagement(engagement.paths.root)
    files = result.dimensions["files"]
    assert files.status == "fail"
    assert any(
        f.status == "fail" and f.subject == "outputs/job01.log" and "已删除" in f.detail
        for f in files.findings
    )
    assert result.dimensions["chain"].status == "pass"  # 维度独立
    assert result.overall == "fail"
    engagement.close()


def test_verify_locates_tampered_file(tmp_path):
    """AC01:篡改已记录产物(改字节)→ files fail 定位,登记/现值 hash 分列;
    manifest 侧同样检出(manifest 时点快照对照)。"""
    from foam.evidence import verify_engagement

    engagement = _pass_fixture(tmp_path)
    target = engagement.paths.outputs / "job01.log"
    target.write_bytes(b"TESTONLY tampered bytes\n")  # 改内容
    result = verify_engagement(engagement.paths.root)
    files = result.dimensions["files"]
    assert files.status == "fail"
    hits = [
        f for f in files.findings
        if f.status == "fail" and f.subject == "outputs/job01.log"
        and "hash 不符" in f.detail
    ]
    assert hits, files.findings
    assert "登记" in hits[0].detail and "现值" in hits[0].detail
    assert result.overall == "fail"
    engagement.close()


def test_verify_escape_reference_located_not_judged(tmp_path):
    """逃逸引用(绝对/界外路径)逐条定位标 unknown,不打开不跟随、不判罚
    (解析器界外 provenance 属已知合法形态)。"""
    from foam.evidence import verify_engagement

    engagement = _pass_fixture(tmp_path)
    outside = tmp_path / "outside.csv"
    outside.write_text("TESTONLY,csv", encoding="utf-8")
    with Index(engagement.paths.index_db) as index:
        # 索引层不校验路径形态(校验在工具层);解析器界外登记由此形态入库
        index.add_vuln(
            "192.0.2.10", "config", "界外证据",
            evidence_refs=[str(outside)],
        )
    result = verify_engagement(engagement.paths.root)
    refs = result.dimensions["references"]
    assert refs.status == "unknown"
    assert any(
        f.status == "unknown" and str(outside) in f.subject and "不跟随" in f.detail
        for f in refs.findings
    )
    assert result.dimensions["files"].status == "pass"  # 界外引用不进产物判罚
    assert result.overall == "unknown"  # unknown 不升格为 fail
    engagement.close()


#: v2(schema v2)DDL 冻结副本(与 test_state._LEGACY_V2_DDL 同文本,
#: 本文件自包含):verify 对 v2 旧库的 legacy/unknown 降级用。
_LEGACY_V2_DDL = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL UNIQUE,
    hostname TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS creds (
    id INTEGER PRIMARY KEY,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    username TEXT NOT NULL,
    secret TEXT NOT NULL,
    source TEXT,
    sensitive INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    UNIQUE (host_id, username, secret)
);
CREATE TABLE IF NOT EXISTS vulns (
    id INTEGER PRIMARY KEY,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    evidence_path TEXT,
    confidence TEXT,
    first_seen TEXT NOT NULL,
    UNIQUE (host_id, kind, title)
);
CREATE TABLE IF NOT EXISTS loot (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL UNIQUE,
    kind TEXT,
    note TEXT,
    size_bytes INTEGER,
    ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS job_events (
    event_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    run_id TEXT,
    reason TEXT,
    status TEXT NOT NULL,
    exit_code INTEGER,
    duration_ms INTEGER,
    ended_at TEXT,
    command TEXT,
    output_refs TEXT,
    parse_tool TEXT,
    parse_stats TEXT,
    consumed_at TEXT,
    audit_seq INTEGER
);
"""


def test_verify_legacy_v2_db_unknown_not_crash(tmp_path):
    """AC03:v2 旧库(无 loot.sha256 / 无 evidence_refs 列)→ 对应来源维度
    unknown 并标注 legacy;verify 不炸、不迁移、不写库(AC04 同覆盖)。"""
    from foam.evidence import verify_engagement, write_manifest

    engagement = _engagement_with_terminal_run(tmp_path, run_id="legacy02")
    root = engagement.paths.root
    # 把索引库替换成手写 v2 旧库(含一行旧 loot)
    db = root / "index.sqlite"
    db.unlink()
    conn = sqlite3.connect(db)
    conn.executescript(_LEGACY_V2_DDL)
    conn.execute("INSERT INTO meta(key, value) VALUES ('schema_version', '2')")
    conn.execute(
        "INSERT INTO loot(path, kind, note, size_bytes, ts) "
        "VALUES ('loot/old.bin', 'dump', NULL, 3, '2026-10-01T00:00:00+00:00')"
    )
    conn.commit()
    conn.close()
    # 旧 loot 行指向的文件真实存在(否则构成「已删除」fail,不是本例焦点)
    (root / "loot" / "old.bin").write_bytes(b"old")
    write_manifest(root, generated_at=FIXED_NOW)  # manifest 在,聚焦库内降级
    before = db.read_bytes()

    result = verify_engagement(root)
    assert result.dimensions["references"].status == "unknown"
    assert "legacy" in result.dimensions["references"].summary
    files = result.dimensions["files"]
    assert files.status == "unknown"  # loot 无登记快照列
    assert any("低于 v4" in f.detail for f in files.findings)
    assert not any(f.status == "fail" for f in files.findings)
    assert result.overall == "unknown"
    assert db.read_bytes() == before  # 只读:库字节不变、未迁移
    engagement.close()


def test_verify_running_engagement_pending(tmp_path):
    """AC02:运行中形态(run_started 无配对 run_finished + meta active)→
    coverage/files pending,总判定 pending;不试取锁、不误判 fail。"""
    from foam.evidence import verify_engagement

    scope_file = tmp_path / "lab.scope"
    scope_file.write_text(SCOPE_TEXT, encoding="utf-8")
    engagement = Engagement.create(
        tmp_path / "engagements",
        "运行中",
        scope_path=scope_file,
        engagement_id="live-eng",
    )
    root = engagement.paths.root
    out = engagement.paths.outputs / "live01.log"
    payload = b"TESTONLY live output\n"
    out.write_bytes(payload)
    audit = AuditLog(engagement.paths.audit_jsonl)
    audit.append(
        KIND_SCOPE_LOADED, scope_payload(parse_scope(SCOPE_TEXT), str(scope_file))
    )
    audit.append(
        "run_started",
        {
            "objective": "运行中",
            "provider": "fake",
            "workdir": str(root),
            "run_id": "live01",
        },
    )
    audit.append(
        "exec_result_meta",
        {
            "job_id": "live01",
            "status": "completed",
            "exit_code": 0,
            "duration_ms": 5,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "output_path": str(out),
            "total_bytes": len(payload),
        },
    )
    audit.close()

    result = verify_engagement(root)
    assert result.dimensions["coverage"].status == "pending"
    assert any(
        f.status == "pending" and "无配对" in f.detail
        for f in result.dimensions["coverage"].findings
    )
    files = result.dimensions["files"]
    assert files.status == "pending"  # 未终态 run 的产物:证据未收敛
    assert any(f.status == "pending" for f in files.findings)
    assert result.dimensions["chain"].status == "pass"  # 链本身完整
    assert result.overall == "pending"
    engagement.close()


def test_verify_pending_job_events_shown(tmp_path):
    """job_events 的 drain 未消费占位行在 coverage 维显示 pending 并点名。"""
    from foam.evidence import verify_engagement

    engagement = _pass_fixture(tmp_path)
    root = engagement.paths.root
    pending_log = root / "outputs" / "pend09.log"
    pending_log.write_bytes(b"TESTONLY pending out\n")
    event = JobExitEvent(
        event_id="job_exit:pend09",
        run_id="pass01",
        job_id="pend09",
        command="echo TESTONLY-pending",
        reason="completed",
        exit_code=0,
        duration_ms=3,
        ended_at=FIXED_NOW,
        output_path=str(pending_log),
        sha256=hashlib.sha256(b"TESTONLY pending out\n").hexdigest(),
        stdout_path=None,
        stdout_sha256=None,
        stderr_path=None,
        stderr_sha256=None,
        total_bytes=21,
        total_lines=1,
    )
    with Index(root / "index.sqlite") as index:
        assert index.register_job_exit_pending(event) is True

    result = verify_engagement(root)
    coverage = result.dimensions["coverage"]
    assert coverage.status == "pending"
    assert any(
        f.status == "pending" and "pend09" in f.detail
        for f in coverage.findings
    )
    # pending 行的产物 hash 已终态:files 维仍按记录核验(一致,不拖累)
    assert result.dimensions["files"].status == "pass"
    assert result.overall == "pending"
    engagement.close()


def test_verify_missing_manifest_unknown(tmp_path):
    """AC03:终态 run 无 manifest(旧 run 不补造)→ coverage unknown/legacy,
    不谎称已核验。"""
    from foam.evidence import verify_engagement

    engagement = _engagement_with_terminal_run(tmp_path, run_id="nomani01")
    result = verify_engagement(engagement.paths.root)
    coverage = result.dimensions["coverage"]
    assert coverage.status == "unknown"
    assert any("manifest" in f.subject for f in coverage.findings)
    assert result.overall == "unknown"
    engagement.close()


def test_verify_chain_broken_dims_independent(tmp_path):
    """AC05:链篡改 → chain fail 并定位断点;files 维照常独立判定(pass)。"""
    from foam.evidence import verify_engagement

    engagement = _pass_fixture(tmp_path)
    root = engagement.paths.root
    audit_path = root / "audit.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    target = next(i for i, line in enumerate(lines) if '"run_started"' in line)
    lines[target] = lines[target].replace("证据测试", "侦察他机")  # 等长篡改
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    from foam.guard.audit import verify as chain_verify

    assert not chain_verify(audit_path)  # 先证「真篡改了」(陷阱 14)

    result = verify_engagement(root)
    chain = result.dimensions["chain"]
    assert chain.status == "fail"
    assert any("run_started" in f.detail or "hash" in f.detail for f in chain.findings)
    assert result.dimensions["files"].status == "pass"  # 维度独立(AC05)
    assert result.overall == "fail"
    engagement.close()


def test_verify_missing_index_degrades_unknown(tmp_path):
    """索引库缺失:链上产物照样核验,库来源维度 unknown 降级,不炸。"""
    from foam.evidence import verify_engagement, write_manifest

    engagement = _engagement_with_terminal_run(tmp_path, run_id="noidx01")
    write_manifest(engagement.paths.root, generated_at=FIXED_NOW)
    (engagement.paths.root / "index.sqlite").unlink()

    result = verify_engagement(engagement.paths.root)
    assert result.dimensions["chain"].status == "pass"
    assert result.dimensions["references"].status == "unknown"
    assert "索引库" in result.dimensions["references"].summary
    assert result.dimensions["coverage"].status == "unknown"
    files = result.dimensions["files"]
    # 链来源的产物仍核验一致(无 fail);loot 快照维度因库缺失不可知 →
    # unknown(证据不足如实降级,不谎称「全核验通过」)
    assert files.status == "unknown"
    assert not any(f.status == "fail" for f in files.findings)
    assert any("索引库" in f.detail for f in files.findings)
    assert result.overall == "unknown"
    engagement.close()


def test_verify_json_human_same_source(tmp_path):
    """AC07:同一 VerifyResult 的 JSON 与人读渲染关键字段逐一一致。"""
    from foam.evidence import render_human, result_to_dict, verify_engagement

    engagement = _pass_fixture(tmp_path)
    # 制造 fail(files)+ unknown(界外引用)混合,覆盖多状态渲染
    (engagement.paths.outputs / "job01.log").write_bytes(b"TESTONLY tampered\n")
    outside = tmp_path / "outside.csv"
    outside.write_text("TESTONLY,csv", encoding="utf-8")
    with Index(engagement.paths.index_db) as index:
        index.add_vuln(
            "192.0.2.10", "config", "界外证据", evidence_refs=[str(outside)]
        )
    result = verify_engagement(engagement.paths.root)
    data = result_to_dict(result)
    human = render_human(result)

    assert data["overall"] == result.overall == "fail"
    for name in ("chain", "files", "references", "coverage"):
        dim = result.dimensions[name]
        assert data["dimensions"][name]["status"] == dim.status
        assert f"[{name}] {dim.status}" in human
        assert data["dimensions"][name]["summary"] == dim.summary
        assert len(data["dimensions"][name]["findings"]) == len(dim.findings)
        for finding in dim.findings:
            assert finding.subject in human
            assert finding.detail in human
    assert data["external_anchor"] == "none"
    assert "未外部锚定" in human and "未外部锚定" in data["external_anchor_note"]
    engagement.close()


def test_cli_verify_human_default_and_json(tmp_path, capsys):
    """verify 子命令:默认人读上 stdout;--json 上 stdout 且可整段解析。"""
    engagement = _pass_fixture(tmp_path)
    rc = cli_main(["verify", str(engagement.paths.root)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "[chain] pass" in out
    assert "[files] pass" in out
    assert "总判定:pass" in out
    assert "未外部锚定" in out

    rc = cli_main(["verify", str(engagement.paths.root), "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)  # stdout 可整段解析为 JSON
    assert data["overall"] == "pass"
    assert data["dimensions"]["chain"]["status"] == "pass"
    engagement.close()


def test_cli_verify_json_unpolluted_by_dotenv(tmp_path, capsys, monkeypatch):
    """[config] .env 注入注记对 verify 改道 stderr:--json stdout 保持纯 JSON。"""
    engagement = _pass_fixture(tmp_path / "sub")
    (tmp_path / ".env").write_text("FOAM_TESTONLY_INJ=1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = cli_main(["verify", str(engagement.paths.root), "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)  # 纯 JSON(无 [config] 行污染)
    assert data["overall"] == "pass"
    assert "[config]" in captured.err  # 注记改道 stderr
    engagement.close()


# ---------------------------------------------------------------------------
# R09-C:退出码矩阵 / run 终态自动接线(CLI+TUI)/ AC06 端到端
# ---------------------------------------------------------------------------


def test_verify_exit_code_matrix(tmp_path, capsys):
    """退出码矩阵(决策 1):rc1 fail;fail+unknown 混合仍 rc1(fail 优先);
    rc3 仅 unknown/pending。rc0/rc2 见 test_cli_verify_human_default_and_json
    与 test_cli.test_verify_usage_errors_rc2。"""
    # rc1:tamper(纯 fail)
    engagement = _pass_fixture(tmp_path / "tamper")
    (engagement.paths.outputs / "job01.log").write_bytes(b"TESTONLY tampered\n")
    rc = cli_main(["verify", str(engagement.paths.root)])
    assert rc == 1
    assert "总判定:fail" in capsys.readouterr().out
    engagement.close()

    # rc1:fail(files)+ unknown(界外引用)混合,fail 优先
    engagement = _pass_fixture(tmp_path / "mixed")
    (engagement.paths.outputs / "job01.log").unlink()
    with Index(engagement.paths.index_db) as index:
        index.add_vuln(
            "192.0.2.10", "config", "界外证据",
            evidence_refs=[str(tmp_path / "mixed" / "outside.csv")],
        )
    rc = cli_main(["verify", str(engagement.paths.root), "--json"])
    assert rc == 1
    data = json.loads(capsys.readouterr().out)
    assert data["overall"] == "fail"
    assert data["dimensions"]["files"]["status"] == "fail"
    assert data["dimensions"]["references"]["status"] == "unknown"
    engagement.close()

    # rc3:仅 unknown(无 manifest 的旧 run 形态)
    engagement = _engagement_with_terminal_run(tmp_path / "unk", run_id="u01")
    rc = cli_main(["verify", str(engagement.paths.root)])
    assert rc == 3
    out = capsys.readouterr().out
    assert "总判定:unknown" in out
    engagement.close()

    # rc3:运行中 pending
    scope_file = tmp_path / "pend" / "lab.scope"
    scope_file.parent.mkdir(parents=True)
    scope_file.write_text(SCOPE_TEXT, encoding="utf-8")
    engagement = Engagement.create(
        tmp_path / "pend" / "engagements",
        "运行中",
        scope_path=scope_file,
        engagement_id="live-eng",
    )
    audit = AuditLog(engagement.paths.audit_jsonl)
    audit.append(
        "run_started",
        {
            "objective": "运行中",
            "provider": "fake",
            "workdir": str(engagement.paths.root),
            "run_id": "live01",
        },
    )
    audit.close()
    rc = cli_main(["verify", str(engagement.paths.root)])
    assert rc == 3
    assert "总判定:pending" in capsys.readouterr().out
    engagement.close()


def test_run_terminal_generates_manifest(tmp_path, capsys):
    """run 终态(close_run 之后)自动生成 manifest + 结项页并绑定正确;
    stdout 打印摘要要点(数行,不刷屏)。"""
    backend = FakeBackend(
        [
            [
                ToolCall("tc-1", "run_command", {"command": "echo TESTONLY-c"}),
                Usage(1, 1),
            ],
            FINISH,
        ]
    )
    rc, workdir = run_cli_once(tmp_path, backend)
    assert rc == 0

    records = read_records(workdir / "audit.jsonl")
    run_id = records[-1]["payload"]["run_id"]
    manifest_path = workdir / "evidence" / f"manifest-{run_id}.json"
    summary_path = workdir / "evidence" / f"summary-{run_id}.md"
    assert manifest_path.is_file() and summary_path.is_file()
    for path in (manifest_path, summary_path):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["run_id"] == run_id
    assert manifest["end_reason"]["status"] == "finished"
    assert manifest["end_reason"]["error"] is None
    assert manifest["chain"]["verify"] is True
    assert manifest["chain"]["head_hash"] == records[-1]["hash"]
    scope_sha = hashlib.sha256(SCOPE_TEXT.encode()).hexdigest()
    assert manifest["scope"]["sha256"] == scope_sha
    artifact_paths = {a["path"] for a in manifest["artifacts"]}
    assert any(p.startswith("outputs/") and p.endswith(".log") for p in artifact_paths)
    summary = summary_path.read_text(encoding="utf-8")
    assert "未外部锚定" in summary and run_id in summary

    out = capsys.readouterr().out
    assert "[evidence] 证据清单" in out  # 摘要要点上 stdout
    assert "未外部锚定" in out


def test_run_killed_manifest_end_reason(tmp_path):
    """killed 终态同样生成 manifest,end_reason=killed 并携 kill 理由。"""
    import signal
    import threading
    import time

    async def _hang_round(_messages):
        import asyncio

        await asyncio.sleep(60)
        return [TextDelta("不应到达"), Usage(1, 1)]  # pragma: no cover

    backend = FakeBackend([_hang_round])

    def fire_sigint_when_running() -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if len(backend.calls) >= 1:  # 首轮已挂起,SIGINT handler 已装配
                os.kill(os.getpid(), signal.SIGINT)
                return
            time.sleep(0.02)

    thread = threading.Thread(target=fire_sigint_when_running, daemon=True)
    thread.start()
    rc, workdir = run_cli_once(tmp_path, backend)
    assert rc == 130  # killed 退出码契约不变

    records = read_records(workdir / "audit.jsonl")
    run_id = records[-1]["payload"]["run_id"]
    manifest_path = workdir / "evidence" / f"manifest-{run_id}.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["end_reason"]["status"] == "killed"
    assert "Ctrl-C" in (manifest["end_reason"]["kill_reason"] or "")


def test_run_manifest_failure_keeps_exit_code(tmp_path, monkeypatch, capsys):
    """manifest 生成失败不反转 run 退出码;stderr 如实警告。"""
    import foam.cli as cli_module

    def boom(_root, **_kwargs):
        raise OSError("TESTONLY 模拟 evidence 写盘失败")

    monkeypatch.setattr(cli_module, "write_manifest", boom)
    rc, workdir = run_cli_once(tmp_path, FakeBackend([FINISH]))
    assert rc == 0  # run 退出码不变
    err = capsys.readouterr().err
    assert "证据" in err and "失败" in err
    assert not list((workdir / "evidence").glob("manifest-*.json"))


def test_ac06_concurrent_terminal_manifest_e2e(tmp_path):
    """AC06 端到端:并发终态(多后台 job 收尾临界完成)→ 自动生成的
    manifest artifacts 全覆盖(接线后不经手工 build)。"""
    backend = FakeBackend(
        [
            [
                ToolCall(
                    "tc-1", "run_command",
                    {"command": "echo TESTONLY-bg-a", "background": True},
                ),
                ToolCall(
                    "tc-2", "run_command",
                    {"command": "echo TESTONLY-bg-b", "background": True},
                ),
                ToolCall(
                    "tc-3", "run_command",
                    {"command": "echo TESTONLY-bg-c", "background": True},
                ),
                Usage(1, 1),
            ],
            FINISH,
        ]
    )
    rc, workdir = run_cli_once(tmp_path, backend)
    assert rc == 0

    records = read_records(workdir / "audit.jsonl")
    run_id = records[-1]["payload"]["run_id"]
    manifest = json.loads(
        (workdir / "evidence" / f"manifest-{run_id}.json").read_text(
            encoding="utf-8"
        )
    )
    artifact_paths = {a["path"] for a in manifest["artifacts"]}
    conn = _read_index_ro(workdir / "index.sqlite")
    rows = conn.execute("SELECT event_id, output_refs FROM job_events").fetchall()
    conn.close()
    assert len(rows) == 3  # 三个并发后台 job 全部落账
    for row in rows:
        refs = json.loads(row["output_refs"])
        for key in ("output_path", "stdout_path", "stderr_path"):
            rel = str(Path(refs[key]).relative_to(workdir))
            assert rel in artifact_paths, f"{row['event_id']} 的 {rel} 漏项"
    assert manifest["pending"]["job_events"] == 0  # drain 收口干净
    assert manifest["pending"]["unpaired_runs"] == []


# ---------------------------------------------------------------------------
# R09-C:TUI 终态接线(既有 TUI harness 形态,自包含极简版)
# ---------------------------------------------------------------------------


async def _wait_for(predicate, deadline_seconds: float = 8.0):
    """轮询直到条件为真(与 test_tui 同模式;8s 上界的抖动注记见 R05)。"""
    import asyncio

    deadline = asyncio.get_event_loop().time() + deadline_seconds
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.05)
    raise AssertionError("wait_for 超时:条件未达成")


async def test_tui_run_generates_manifest(tmp_path):
    """TUI 路径:run 结束后 evidence/manifest-<run_id>.json 存在且绑定正确。"""
    from foam.tui import TuiApp, TUIConfig

    scope_file = tmp_path / "lab.scope"
    scope_file.write_text(SCOPE_TEXT, encoding="utf-8")
    config = TUIConfig(
        scope=parse_scope(SCOPE_TEXT),
        scope_source=str(scope_file),
        backend=FakeBackend([[TextDelta("完成"), Usage(1, 1)]]),
        engagements_dir=tmp_path / "engagements",
        config_home=tmp_path / "home",
        wait_on_finish=False,
    )
    app = TuiApp(config)
    async with app.run_test(headless=True, size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press(*"nightowl")
        await pilot.press("enter")
        await _wait_for(lambda: app._main is not None)
        await pilot.pause(0.2)
        await pilot.press(*"recon lab")
        await pilot.press("enter")
        await _wait_for(lambda: app._final_result is not None)
        await _wait_for(
            lambda: app._runtime is not None and app._runtime.closed
        )
        await pilot.pause(0.1)

    assert app._final_result.status == "finished"
    root = app.engagement.paths.root
    manifests = list((root / "evidence").glob("manifest-*.json"))
    assert len(manifests) == 1, f"manifest 未生成:{list((root / 'evidence').iterdir())}"
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    records = read_records(root / "audit.jsonl")
    run_id = records[-1]["payload"]["run_id"]
    assert manifest["run_id"] == run_id
    assert manifest["end_reason"]["status"] == "finished"
    assert manifest["chain"]["verify"] is True
    assert (root / "evidence" / f"summary-{run_id}.md").is_file()


# ---------------------------------------------------------------------------
# R09 评审收口(2026-10-13):B1 manifest 快照取最新 / rc0 可达面 /
# references 缺失定位 / files 计数按文件聚合 / ro 探针连接泄漏 /
# 终态四形态 manifest 专测
# ---------------------------------------------------------------------------


def _two_run_transcript_fixture(tmp_path: Path) -> Engagement:
    """两个 run 的转录合法增长场景(B1 复现基座):

    run1 终态(链 + 转录 v1)→ manifest-r1(转录快照 hash1)→ resume 起
    run2 终态(转录续写为 v2)→ manifest-r2(快照 hash2)。session 转录无
    终态账本,manifest 快照是其唯一记录面。
    """
    scope_file = tmp_path / "lab.scope"
    scope_file.write_text(SCOPE_TEXT, encoding="utf-8")
    engagement = Engagement.create(
        tmp_path / "engagements",
        "两次运行",
        scope_path=scope_file,
        engagement_id="tworun-eng",
    )
    root = engagement.paths.root
    transcript = root / "outputs" / "sessions" / "s-aa.log"
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_bytes(b"TESTONLY transcript v1\n")

    from foam.evidence import write_manifest

    audit = AuditLog(engagement.paths.audit_jsonl)
    audit.append(
        KIND_SCOPE_LOADED,
        scope_payload(parse_scope(SCOPE_TEXT), str(scope_file)),
    )
    audit.append(
        "run_started",
        {"objective": "两次运行", "provider": "fake",
         "workdir": str(root), "run_id": "run-aaa"},
    )
    audit.append(
        "run_finished",
        {"status": "finished", "rounds": 1, "input_tokens": 1,
         "output_tokens": 1, "error": None, "run_id": "run-aaa"},
    )
    audit.close()
    m1 = write_manifest(root, generated_at="2026-10-13T00:00:00+00:00")
    assert m1 is not None and m1[0].name == "manifest-run-aaa.json"

    # resume 起 run2:转录合法续写,终态生成 manifest-r2
    audit = AuditLog(engagement.paths.audit_jsonl)
    audit.append(
        "run_started",
        {"objective": "两次运行", "provider": "fake",
         "workdir": str(root), "run_id": "run-bbb"},
    )
    audit.append(
        "run_finished",
        {"status": "finished", "rounds": 2, "input_tokens": 2,
         "output_tokens": 2, "error": None, "run_id": "run-bbb"},
    )
    audit.close()
    transcript.write_bytes(b"TESTONLY transcript v1\nv2 continued\n")
    m2 = write_manifest(root, generated_at="2026-10-13T01:00:00+00:00")
    assert m2 is not None and m2[0].name == "manifest-run-bbb.json"
    # 防呆:两份 manifest 对转录的快照确实不同(否则没造出 B1 场景)
    t1 = next(
        a for a in m1[2]["artifacts"] if a["path"] == "outputs/sessions/s-aa.log"
    )
    t2 = next(
        a for a in m2[2]["artifacts"] if a["path"] == "outputs/sessions/s-aa.log"
    )
    assert t1["sha256"] != t2["sha256"]
    return engagement


def test_verify_multi_run_uses_latest_manifest_snapshot(tmp_path):
    """B1:转录合法增长(resume 后续写)只认 generated_at 最新的 manifest
    快照——旧 manifest 的旧快照不得把合法增长判成篡改(证据工具谎报
    是最坏的误报方向)。"""
    from foam.evidence import verify_engagement

    engagement = _two_run_transcript_fixture(tmp_path)
    result = verify_engagement(engagement.paths.root)
    files = result.dimensions["files"]
    assert files.status == "pass", (
        f"合法增长被误报: {files.summary} {files.findings}"
    )
    assert result.overall != "fail"
    engagement.close()


def test_verify_tamper_after_latest_manifest_still_located(tmp_path):
    """B1 不回归:最新 manifest 之后再改转录 → files fail 并定位
    (崩溃续写与篡改不可区分,如实报;定位到最新快照来源)。"""
    from foam.evidence import verify_engagement

    engagement = _two_run_transcript_fixture(tmp_path)
    transcript = engagement.paths.root / "outputs" / "sessions" / "s-aa.log"
    transcript.write_bytes(b"TESTONLY tampered after manifest\n")
    result = verify_engagement(engagement.paths.root)
    files = result.dimensions["files"]
    assert files.status == "fail"
    assert any(
        f.status == "fail" and f.subject == "outputs/sessions/s-aa.log"
        and "hash 不符" in f.detail
        for f in files.findings
    )
    engagement.close()


def test_cli_verify_rc0_healthy_run_without_sessions(tmp_path, capsys):
    """收口 2:R09 代际健康 run(终态 manifest 在场、无会话使用)→
    verify rc 0 可达(修复前 session legacy unknown 恒拖成 rc 3)。"""
    rc, workdir = run_cli_once(tmp_path, FakeBackend([FINISH]))
    assert rc == 0
    rc = cli_main(["verify", str(workdir)])
    captured = capsys.readouterr()
    assert rc == 0, captured.out + captured.err
    assert "总判定:pass" in captured.out
    assert "无会话使用" in captured.out  # 代际注记,而非 legacy unknown


def test_verify_references_missing_contained_file_fails(tmp_path):
    """收口 3:references 三态补证据——界内引用文件被删除 → fail 并定位
    (此前只测了界内存在 pass 与界外 unknown 两态)。"""
    from foam.evidence import verify_engagement, write_manifest

    engagement = _engagement_with_terminal_run(tmp_path, run_id="refmiss")
    evidence_file = engagement.paths.outputs / "ev.bin"
    evidence_file.write_bytes(b"TESTONLY evidence")
    with Index(engagement.paths.index_db) as index:
        index.add_vuln(
            "192.0.2.10", "config", "界内证据",
            evidence_refs=["outputs/ev.bin"],
        )
    write_manifest(engagement.paths.root, generated_at=FIXED_NOW)
    evidence_file.unlink()

    result = verify_engagement(engagement.paths.root)
    refs = result.dimensions["references"]
    assert refs.status == "fail"
    assert any(
        f.status == "fail" and "outputs/ev.bin" in f.subject
        and "缺失" in f.detail
        for f in refs.findings
    )
    assert result.dimensions["chain"].status == "pass"  # 维度独立
    assert result.overall == "fail"
    engagement.close()


def test_verify_files_summary_aggregates_per_file(tmp_path):
    """收口 4:同一文件多来源(链 exec_result_meta + job_events + manifest)
    被篡改——files 摘要按文件聚合,「不一致」不得超文件数、不出现负数。"""
    from foam.evidence import verify_engagement

    backend = FakeBackend(
        [
            [
                ToolCall("tc-1", "run_command", {"command": "echo TESTONLY-m"}),
                Usage(1, 1),
            ],
            FINISH,
        ]
    )
    rc, workdir = run_cli_once(tmp_path, backend)
    assert rc == 0
    log = next((workdir / "outputs").glob("*.log"))
    log.write_bytes(b"TESTONLY multi-source tamper\n")

    result = verify_engagement(workdir)
    files = result.dimensions["files"]
    assert files.status == "fail"
    rel = str(log.relative_to(workdir))
    # 定位明细逐来源保留(定位价值);计数按文件聚合
    hits = [
        f for f in files.findings
        if f.status == "fail" and f.subject == rel and "hash 不符" in f.detail
    ]
    assert len(hits) >= 2  # 至少链上与 job_events 两个来源各自定位
    # 计数按文件聚合:3 个文件(合流/stdout/stderr)中 1 个被篡改——
    # 「不一致」=1(不是按 claim 的 3),「一致」非负(修复前算出 -1)
    assert "不一致 1" in files.summary, files.summary
    assert "一致 2" in files.summary, files.summary
    assert files.extra["mismatch"] == 1 and files.extra["checked"] == 3


def test_open_index_ro_probe_failure_closes_connection(tmp_path, monkeypatch):
    """收口 5:meta 探针失败(无 meta 表的异构库)→ 返回 None 且连接已关
    (修复前探针抛错路径泄漏未关闭连接)。"""
    import foam.evidence as ev

    db = tmp_path / "bad.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE not_meta (x TEXT)")
    conn.commit()
    conn.close()

    captured: dict[str, sqlite3.Connection] = {}
    real_connect = sqlite3.connect

    def spy_connect(*args, **kwargs):
        captured["conn"] = real_connect(*args, **kwargs)
        return captured["conn"]

    monkeypatch.setattr(ev.sqlite3, "connect", spy_connect)
    assert ev._open_index_ro(db) is None
    with pytest.raises(sqlite3.ProgrammingError):  # 已关闭:execute 即抛
        captured["conn"].execute("SELECT 1")


@pytest.mark.parametrize(
    "status,error,kill_reason",
    [
        ("finished", None, None),
        ("killed", None, "操作员中止 TESTONLY"),
        ("error", "后端故障 TESTONLY", None),
        ("cancelled", "外部取消 TESTONLY", None),
    ],
)
def test_write_manifest_all_terminal_states(
    tmp_path, status, error, kill_reason
):
    """收口 6:四种终态(finished/killed/error/cancelled)都生成 manifest,
    end_reason 绑定正确;killed 携最近 kill_switch 理由。"""
    from foam.evidence import write_manifest

    extra = None
    if status == "killed":
        extra = [
            ("kill_switch", {"reason": kill_reason, "jobs": [], "cleanup": {}})
        ]
    engagement = _engagement_with_terminal_run(
        tmp_path, run_id=f"st-{status}", status=status, error=error,
        extra_before_finish=extra,
    )
    written = write_manifest(engagement.paths.root, generated_at=FIXED_NOW)
    assert written is not None, f"{status} 终态应生成 manifest"
    json_path, _md_path, manifest = written
    assert manifest["run_id"] == f"st-{status}"
    assert manifest["end_reason"]["status"] == status
    assert manifest["end_reason"]["error"] == error
    if kill_reason is not None:
        assert manifest["end_reason"]["kill_reason"] == kill_reason
    assert json_path.name == f"manifest-st-{status}.json"
    engagement.close()
