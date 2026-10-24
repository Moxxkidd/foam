"""v0.1.2/v0.1.3 发布门槛的跨条目 CLI 组合验收。

只使用 tmp_path、脚本化后端、本机无害命令与 TESTONLY 数据；不访问外部
模型或目标，也不要求 Docker/sshd/msfconsole。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import stat
import subprocess  # noqa: S403  # 固定 pgrep 探针核查测试进程收割
import threading
import time
from pathlib import Path

import pytest

from foam.agent.backends.base import ToolCall, Usage
from foam.cli import main as cli_main
from foam.guard.audit import verify
from foam.state.files import acquire_engagement_lock
from foam.state.index import Index
from tests.test_cli import (
    COMPILE_OK,
    FINISH,
    FakeBackend,
    _hang_round,
    audit_records,
    write_scope,
)
from tests.test_replay import bulk_insert_rows, make_engagement

BROAD_SCOPE = "127.0.0.0/8\nlocalhost\n"
NARROW_SCOPE = "127.0.0.1/32\n"


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))


def _command_then_finish(marker: str) -> list:
    return [
        [
            ToolCall(
                f"tc-{marker}",
                "run_command",
                {"command": f"printf '%s\\n' '{marker}'"},
            ),
            Usage(1, 1),
        ],
        FINISH,
    ]


def _verify_pass(root: Path, capsys) -> dict:
    capsys.readouterr()
    rc = cli_main(["verify", str(root), "--json"])
    captured = capsys.readouterr()
    assert rc == 0, captured.out + captured.err
    result = json.loads(captured.out)
    assert result["overall"] == "pass"
    assert all(
        dimension["status"] == "pass"
        for dimension in result["dimensions"].values()
    )
    return result


def _export_report(root: Path, destination: Path, capsys) -> str:
    capsys.readouterr()
    rc = cli_main(["report", str(root), "--out", str(destination)])
    captured = capsys.readouterr()
    assert rc == 0, captured.out + captured.err
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    return destination.read_text(encoding="utf-8")


def _latest_manifest(root: Path) -> tuple[dict, list[dict]]:
    records = audit_records(root)
    assert records[-1]["kind"] == "run_finished"
    run_id = records[-1]["payload"]["run_id"]
    manifest_path = root / "evidence" / f"manifest-{run_id}.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["run_id"] == run_id
    assert manifest["chain"]["head_hash"] == records[-1]["hash"]
    assert (root / "evidence" / f"summary-{run_id}.md").is_file()
    return manifest, records


@pytest.mark.parametrize("channel", ["file", "nl"])
def test_release_file_nl_multi_run_journey(tmp_path, capsys, channel):
    """run→report→verify→收窄 resume→plain resume→verify/report 全链。"""
    broad = tmp_path / "broad.scope"
    narrow = tmp_path / "narrow.scope"
    broad.write_text(BROAD_SCOPE, encoding="utf-8")
    narrow.write_text(NARROW_SCOPE, encoding="utf-8")
    root = tmp_path / "engagement"
    first_marker = f"TESTONLY-release-{channel}-first"
    second_marker = f"TESTONLY-release-{channel}-second"
    script = _command_then_finish(first_marker)
    if channel == "nl":
        script = [COMPILE_OK, *script]
        scope_args = ["--scope-text", "仅授权 127.0.0.0/8 与 localhost"]
    else:
        scope_args = ["--scope", str(broad)]
    backend = FakeBackend(script)

    rc = cli_main(
        [
            "run",
            *scope_args,
            "--objective",
            "TESTONLY 发布组合验收",
            "--workdir",
            str(root),
        ],
        backend_factory=lambda _args: backend,
    )
    assert rc == 0
    assert verify(root / "audit.jsonl")
    initial_report = _export_report(root, tmp_path / "initial.md", capsys)
    assert "- run 1 次 /" in initial_report
    assert first_marker in initial_report
    _verify_pass(root, capsys)

    narrowed = FakeBackend(_command_then_finish(second_marker))
    rc = cli_main(
        ["resume", str(root), "--scope", str(narrow)],
        backend_factory=lambda _args: narrowed,
    )
    assert rc == 0
    narrow_sha = hashlib.sha256(NARROW_SCOPE.encode()).hexdigest()
    meta = json.loads((root / "engagement.json").read_text(encoding="utf-8"))
    assert meta["scope"] == {"path": str(narrow.resolve()), "sha256": narrow_sha}
    confirmations = [
        record
        for record in audit_records(root)
        if record["kind"] == "scope_confirmed"
    ]
    assert len(confirmations) == 2
    assert meta["revision"] == {
        "seq": confirmations[-1]["seq"],
        "hash": confirmations[-1]["hash"],
    }
    _verify_pass(root, capsys)

    resumed = FakeBackend([FINISH])
    rc = cli_main(
        ["resume", str(root)], backend_factory=lambda _args: resumed
    )
    assert rc == 0
    final_meta = json.loads((root / "engagement.json").read_text(encoding="utf-8"))
    assert final_meta["scope"] == meta["scope"]
    assert final_meta["status"] == "closed"
    assert "127.0.0.1/32" in resumed.calls[0][1].content
    assert BROAD_SCOPE.splitlines()[0] not in resumed.calls[0][1].content

    manifest, records = _latest_manifest(root)
    assert final_meta["revision"]["seq"] > meta["revision"]["seq"]
    revision_record = next(
        record
        for record in records
        if record["seq"] == final_meta["revision"]["seq"]
    )
    assert revision_record["kind"] == "run_started"
    assert revision_record["hash"] == final_meta["revision"]["hash"]
    started = [record for record in records if record["kind"] == "run_started"]
    finished = [record for record in records if record["kind"] == "run_finished"]
    assert len(started) == len(finished) == 3
    expected_manifests = {
        f"manifest-{record['payload']['run_id']}.json" for record in finished
    }
    assert {path.name for path in (root / "evidence").glob("manifest-*.json")} == (
        expected_manifests
    )
    assert manifest["scope"]["sha256"] == narrow_sha
    assert manifest["scope"]["revision"] == final_meta["revision"]
    assert manifest["pending"] == {"job_events": 0, "unpaired_runs": []}
    command_outputs = [
        record["payload"]["output_path"]
        for record in records
        if record["kind"] == "exec_result_meta"
    ]
    assert len(command_outputs) == 2
    artifact_names = {Path(item["path"]).name for item in manifest["artifacts"]}
    assert {Path(path).name for path in command_outputs} <= artifact_names
    loaded = [record for record in records if record["kind"] == "scope_loaded"]
    assert loaded[-1]["payload"]["cidrs"] == ["127.0.0.1/32"]
    assert loaded[-1]["payload"]["hosts"] == []
    assert verify(root / "audit.jsonl")

    _verify_pass(root, capsys)
    final_report = _export_report(root, tmp_path / "final.md", capsys)
    assert "- run 3 次 /" in final_report
    assert first_marker in final_report and second_marker in final_report
    assert f"- 内容 sha256:{narrow_sha}" in final_report


def _sleep_pids(marker: str) -> list[int]:
    probe = subprocess.run(  # noqa: S603
        ["pgrep", "-f", f"sleep {marker}"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    return [int(line) for line in probe.stdout.split() if line.strip()]


@pytest.mark.parametrize(
    ("terminal", "expected_rc", "sleep_marker"),
    [("finished", 0, "41931"), ("error", 1, "41932"), ("killed", 130, "41933")],
)
def test_release_terminal_resources_and_evidence(
    tmp_path, capsys, terminal, expected_rc, sleep_marker
):
    """finished/error/killed 的退出码、资源收割与最新证据 manifest 一致。"""
    background = [
        ToolCall(
            f"tc-release-{terminal}",
            "run_command",
            {"command": f"sleep {sleep_marker}", "background": True},
        ),
        Usage(1, 1),
    ]
    if terminal == "finished":
        script = [background, FINISH]
    elif terminal == "error":
        script = [background, RuntimeError("TESTONLY-release-backend-error")]
    else:
        script = [background, _hang_round]
    backend = FakeBackend(script)
    scope = write_scope(tmp_path)
    root = tmp_path / "engagement"

    signal_thread = None
    if terminal == "killed":

        def fire_sigint() -> None:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if len(backend.calls) >= 2:
                    os.kill(os.getpid(), signal.SIGINT)
                    return
                time.sleep(0.02)
            raise AssertionError("TESTONLY 挂起轮未就位，未发送 SIGINT")

        signal_thread = threading.Thread(target=fire_sigint, daemon=True)
        signal_thread.start()
    rc = cli_main(
        [
            "run",
            "--scope",
            str(scope),
            "--objective",
            f"TESTONLY {terminal} 终态验收",
            "--workdir",
            str(root),
        ],
        backend_factory=lambda _args: backend,
    )
    if signal_thread is not None:
        signal_thread.join(timeout=5)
        assert not signal_thread.is_alive()
    assert rc == expected_rc
    assert _sleep_pids(sleep_marker) == []
    assert backend.aclose_calls == 1
    lock = acquire_engagement_lock(root)
    assert lock is not None
    lock.release()

    meta = json.loads((root / "engagement.json").read_text(encoding="utf-8"))
    assert meta["status"] == ("closed" if terminal == "finished" else "active")
    manifest, records = _latest_manifest(root)
    assert manifest["end_reason"]["status"] == terminal
    if terminal == "error":
        assert "TESTONLY-release-backend-error" in manifest["end_reason"]["error"]
    if terminal == "killed":
        assert "Ctrl-C" in manifest["end_reason"]["kill_reason"]
    assert records[-1]["payload"]["cleanup"]["cleanup_status"] == "ok"
    assert records[-1]["payload"]["cleanup"]["remaining_resources"] == []
    assert manifest["pending"] == {"job_events": 0, "unpaired_runs": []}
    assert verify(root / "audit.jsonl")
    result = _verify_pass(root, capsys)
    assert result["dimensions"]["coverage"]["extra"]["engagement_status"] == (
        meta["status"]
    )


def test_release_cli_report_1001_rows_exact_and_private(tmp_path, capsys):
    """真实 report CLI 导出 1001 条记录，token 不重不漏、统计同源、0600。"""
    root = make_engagement(tmp_path, with_index=False)
    with Index(root / "index.sqlite") as index:
        expected = bulk_insert_rows(index, "notes", 1001)
    destination = tmp_path / "report-1001.md"
    text = _export_report(root, destination, capsys)

    rendered = sorted(re.findall(r"TESTONLY-r04-notes-(\d{4})", text))
    assert rendered == [f"{i:04d}" for i in range(1001)]
    match = re.search(r"^- 索引库:(.+)$", text, re.MULTILINE)
    assert match is not None
    stats = {key: int(value) for key, value in re.findall(r"(\w+) (\d+)", match[1])}
    assert stats == expected
    assert "TESTONLY-r04-notes-0000" in text
    assert "TESTONLY-r04-notes-1000" in text
