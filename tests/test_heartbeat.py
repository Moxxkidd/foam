"""R13-C：心跳快照、真实 CLI 生命周期与写失败边界。"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

from foam.guard.audit import verify
from foam.state.files import Engagement

_NO_NETWORK_STATUS = """
import socket
import sys

def denied(*args, **kwargs):
    raise AssertionError("TESTONLY network access forbidden")

socket.socket.connect = denied
socket.getaddrinfo = denied
from foam.cli import main
raise SystemExit(main(sys.argv[1:]))
"""


def run_status(root: Path, *, cwd: Path, home: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", _NO_NETWORK_STATUS, "status", str(root), "--json"],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def wait_until(predicate, *, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError("等待条件超时")


def test_heartbeat_writer_atomic_fields_throttle_and_sensitive_exclusion(tmp_path):
    from foam.state.heartbeat import HeartbeatWriter

    engagement = Engagement.create(tmp_path / "engagements", "heartbeat")
    writer = HeartbeatWriter(
        engagement.paths.root, run_id="r13-c", entry="tui"
    )
    assert writer.start() is True
    writer.on_status("paused")
    paused_seq = json.loads(
        (engagement.paths.root / "heartbeat.json").read_text(encoding="utf-8")
    )["seq"]
    writer.on_status("running")
    throttled = json.loads(
        (engagement.paths.root / "heartbeat.json").read_text(encoding="utf-8")
    )
    assert throttled["seq"] == paused_seq
    assert throttled["loop_status"] == "paused"
    writer.on_model()
    writer.on_tool_call("run_command")
    writer.on_tool_result("run_command")
    asyncio.run(writer.aclose())
    raw = (engagement.paths.root / "heartbeat.json").read_text(encoding="utf-8")
    data = json.loads(raw)
    assert data["schema"] == "foam.heartbeat/1"
    assert data["run_id"] == "r13-c"
    assert data["entry"] == "tui"
    assert data["pid"] == os.getpid()
    assert data["interval_s"] == 10
    assert data["seq"] > paused_seq
    assert data["loop_status"] == "closed"
    assert data["last_activity"]["kind"] == "status"
    assert data["last_activity"]["at"]
    mode = (engagement.paths.root / "heartbeat.json").stat().st_mode
    assert stat.S_IMODE(mode) == 0o600
    assert "TESTONLY objective" not in raw
    assert "TESTONLY model text" not in raw
    assert "command" not in data["last_activity"]


def test_heartbeat_read_only_write_fails_once(tmp_path, capsys):
    from foam.state.heartbeat import HeartbeatWriter

    engagement = Engagement.create(tmp_path / "engagements", "readonly")
    engagement.paths.root.chmod(0o555)
    writer = HeartbeatWriter(
        engagement.paths.root, run_id="readonly", entry="cli-run"
    )
    try:
        assert writer.start() is False
        writer.on_status("running")
        writer.on_tool_call("run_command")
        asyncio.run(writer.aclose())
        captured = capsys.readouterr()
        assert captured.err.count("心跳写入失败") == 1
        assert not (engagement.paths.root / "heartbeat.json").exists()
    finally:
        engagement.paths.root.chmod(0o700)


_CLI_HOLD = """
import asyncio
import sys
from pathlib import Path
from foam.agent.backends.base import LLMBackend, TextDelta, Usage
from foam.cli import main

class Backend(LLMBackend):
    provider = "fake"
    def __init__(self):
        self.calls = 0
    async def aclose(self):
        pass
    def chat(self, messages, tools=None):
        self.calls += 1
        async def stream():
            yield TextDelta("TESTONLY model text")
            while not Path(sys.argv[2]).exists():
                await asyncio.sleep(0.1)
            yield Usage(1, 1)
        return stream()

raise SystemExit(main([
    "run", "--execution-mode", "legacy", "--scope", sys.argv[3],
    "--objective", "TESTONLY objective secret", "--workdir", sys.argv[1],
], backend_factory=lambda _args: Backend()))
"""


def start_cli(root: Path, control: Path, scope: Path, cwd: Path, home: Path):
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", _CLI_HOLD, str(root), str(control), str(scope)],
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def assert_status(root: Path, tmp_path: Path, run_state: str, liveness: str):
    result = run_status(root, cwd=tmp_path, home=tmp_path / "home")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["run_state"] == run_state
    assert data["liveness"] == liveness
    return data


def test_heartbeat_lifecycle(tmp_path):
    """真实 CLI：alive→closed；SIGSTOP 超原阈值→stale；SIGKILL→gone。"""
    home = tmp_path / "home"
    home.mkdir()
    scope = tmp_path / "lab.scope"
    scope.write_text("127.0.0.0/8\nlocalhost\n", encoding="utf-8")

    normal_root = tmp_path / "normal"
    normal_control = tmp_path / "normal.finish"
    proc = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            "-c",
            _CLI_HOLD,
            str(normal_root),
            str(normal_control),
            str(scope),
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "HOME": str(home),
            "PYTHONPATH": str(Path(__file__).parents[1] / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        wait_until(lambda: (normal_root / "heartbeat.json").exists())
        alive = assert_status(normal_root, tmp_path, "active", "alive")
        assert alive["details"]["identity_method"] in ("proc-stat", "ps-lstart")
        normal_control.touch()
        _stdout, stderr = proc.communicate(timeout=20)
        assert proc.returncode == 0, stderr
        closed = assert_status(normal_root, tmp_path, "closed", "gone")
        assert closed["last_activity"]["source"] in ("heartbeat", "audit")
        raw = (normal_root / "heartbeat.json").read_text(encoding="utf-8")
        assert "TESTONLY objective secret" not in raw
        assert "TESTONLY model text" not in raw
        assert json.loads(raw)["loop_status"] == "closed"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()

    stale_root = tmp_path / "stale"
    stale_control = tmp_path / "stale.finish"
    proc = start_cli(stale_root, stale_control, scope, tmp_path, home)
    try:
        wait_until(lambda: (stale_root / "heartbeat.json").exists())
        assert_status(stale_root, tmp_path, "active", "alive")
        proc.send_signal(signal.SIGSTOP)
        time.sleep(31)
        assert_status(stale_root, tmp_path, "interrupted", "stale")
        proc.kill()
        proc.wait(timeout=5)
        assert_status(stale_root, tmp_path, "interrupted", "gone")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


_CLI_READ_ONLY = """
import sys
from pathlib import Path
from foam.agent.backends.base import LLMBackend, TextDelta, Usage
from foam.cli import main
from foam.state.heartbeat import HeartbeatWriter

original_start = HeartbeatWriter.start

def read_only_start(self):
    self.root.chmod(0o555)
    try:
        return original_start(self)
    finally:
        self.root.chmod(0o700)

HeartbeatWriter.start = read_only_start

class Backend(LLMBackend):
    provider = "fake"
    async def aclose(self):
        pass
    def chat(self, messages, tools=None):
        async def stream():
            yield TextDelta("done")
            yield Usage(1, 1)
        return stream()

raise SystemExit(main([
    "run", "--execution-mode", "legacy", "--scope", sys.argv[2],
    "--objective", "readonly heartbeat", "--workdir", sys.argv[1],
], backend_factory=lambda _args: Backend()))
"""


def test_heartbeat_read_only_failure_does_not_change_run(tmp_path):
    """真实只读写入失败只警告一次，run/审计/退出码不变。"""
    root = tmp_path / "readonly-run"
    scope = tmp_path / "lab.scope"
    scope.write_text("127.0.0.0/8\nlocalhost\n", encoding="utf-8")
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _CLI_READ_ONLY, str(root), str(scope)],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr.count("心跳写入失败") == 1
    assert verify(root / "audit.jsonl")
    assert json.loads((root / "engagement.json").read_text())["status"] == "closed"


def test_status_never_constructs_backend(tmp_path, monkeypatch, capsys):
    """R13-AC06：status 的 fake backend factory 调用数必须为 0。"""
    from foam.cli import main as cli_main

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    engagement = Engagement.create(tmp_path / "engagements", "status-only")
    engagement.close()
    calls = []

    def forbidden_factory(_args):
        calls.append(True)
        raise AssertionError("status 不得构造 backend")

    assert cli_main(
        ["status", str(engagement.paths.root), "--json"],
        backend_factory=forbidden_factory,
    ) == 0
    assert calls == []
    assert json.loads(capsys.readouterr().out)["liveness"] == "none"
