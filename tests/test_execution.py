"""R11 执行适配器与 boundary 生命周期契约测试。"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from foam.runtime import RunRuntime, close_run
from foam.tools.bash import BashTool
from foam.tools.execution import ExecutionPaused, ToolExecutor
from foam.tools.session import SessionTool


class FakeBoundary:
    boundary_id = "b-fake"
    epoch = 7
    init_pid = 410
    helper_pid = 409

    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir

    def tool_argv(self, argv: list[str]) -> list[str]:
        return argv

    def spawn_kwargs(self) -> dict:
        return {}

    def tool_env(self, term: str | None = None) -> dict[str, str]:
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.workdir),
            "TMPDIR": str(self.workdir),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "USER": "nobody",
            "LOGNAME": "nobody",
            "NO_PROXY": "*",
        }
        if term is not None:
            env["TERM"] = term
        return env

    def capabilities(self) -> dict:
        return {
            "boundary_id": self.boundary_id,
            "epoch": self.epoch,
            "tool_uid": 65534,
            "no_new_privs": True,
        }


class CaptureBoundary(FakeBoundary):
    def tool_argv(self, argv: list[str]) -> list[str]:
        return ["wrapped", *argv]

    def spawn_kwargs(self) -> dict:
        return {"pass_fds": (4, 5)}


async def test_protected_spawn_uses_boundary_argv_fds_env_and_ctty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []

    async def fake_spawn(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(pid=123)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_spawn)
    monkeypatch.setenv("FOAM_LLM_API_KEY", "TESTONLY-NOT-FOR-CHILD")
    monkeypatch.setenv("HTTP_PROXY", "http://192.0.2.1:8080")
    boundary = CaptureBoundary(tmp_path)
    executor = ToolExecutor(boundary=boundary)

    def hook() -> None:
        pass

    proc = await executor.spawn(
        ["bash", "-c", "true"],
        stdin=1,
        stdout=2,
        stderr=3,
        preexec_fn=hook,
        term="xterm-256color",
    )
    assert proc.pid == 123
    args, kwargs = calls[0]
    assert args == ("wrapped", "bash", "-c", "true")
    assert kwargs["stdin"] == 1 and kwargs["stdout"] == 2 and kwargs["stderr"] == 3
    assert kwargs["pass_fds"] == (4, 5)
    assert kwargs["cwd"] == tmp_path
    assert kwargs["preexec_fn"] is hook
    assert kwargs["start_new_session"] is True and kwargs["close_fds"] is True
    env = kwargs["env"]
    assert env["TERM"] == "xterm-256color"
    assert "FOAM_LLM_API_KEY" not in env and "HTTP_PROXY" not in env


async def test_legacy_spawn_keeps_existing_environment(
    tmp_path: Path, monkeypatch
) -> None:
    calls = []

    async def fake_spawn(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(pid=123)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_spawn)
    monkeypatch.setenv("FOAM_LLM_API_KEY", "TESTONLY-LEGACY")
    executor = ToolExecutor()
    await executor.spawn(["bash", "-c", "true"], term="xterm-256color")
    args, kwargs = calls[0]
    assert args == ("bash", "-c", "true")
    assert kwargs["env"]["FOAM_LLM_API_KEY"] == "TESTONLY-LEGACY"
    assert kwargs["env"]["TERM"] == "xterm-256color"
    assert "cwd" not in kwargs and "pass_fds" not in kwargs


async def test_generation_pause_resume_and_close() -> None:
    executor = ToolExecutor()
    async with executor.generation() as epoch:
        assert epoch is None
    executor.pause_new()
    with pytest.raises(ExecutionPaused):
        async with executor.generation():
            pass
    executor.resume_new()
    async with executor.generation():
        pass
    executor.close()
    with pytest.raises(ExecutionPaused):
        async with executor.generation():
            pass


async def test_bash_and_pty_share_executor_and_scrub_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FOAM_LLM_API_KEY", "TESTONLY-NOT-FOR-CHILD")
    monkeypatch.setenv("HTTP_PROXY", "http://192.0.2.1:8080")
    executor = ToolExecutor(boundary=FakeBoundary(tmp_path))
    bash = BashTool(tmp_path / "outputs", executor=executor)
    sessions = SessionTool(tmp_path / "sessions", executor=executor)
    try:
        result = await bash.run_command(
            "python3 -c 'import os; print(\"key\", bool(os.environ.get("
            "\"FOAM_LLM_API_KEY\")), \"proxy\", bool(os.environ.get(\"HTTP_PROXY\")))'"
        )
        assert result["exit_code"] == 0
        assert "key False proxy False" in result["output_view"]
        assert result["boundary_id"] == "b-fake" and result["epoch"] == 7

        opened = await sessions.session_open(
            "python3 -c 'import os; print(\"tty\", os.isatty(0), "
            "\"key\", bool(os.environ.get(\"FOAM_LLM_API_KEY\")))'"
        )
        assert opened["boundary_id"] == "b-fake" and opened["epoch"] == 7
        session_id = opened["session_id"]
        for _ in range(100):
            read = await sessions.session_read(session_id)
            if "tty True key False" in read["new_output"]:
                break
            await asyncio.sleep(0.02)
        else:
            pytest.fail(f"PTY 未返回预期环境/终端证据: {read}")
    finally:
        await bash.aclose()
        await sessions.aclose()


async def test_bash_spawn_failure_does_not_leave_job_artifacts(tmp_path: Path) -> None:
    class FailingExecutor(ToolExecutor):
        async def spawn(self, *args, **kwargs):
            raise RuntimeError("injected spawn failure")

    tool = BashTool(tmp_path / "outputs", executor=FailingExecutor())
    with pytest.raises(RuntimeError, match="injected spawn failure"):
        await tool.run_command("true")
    assert tool._jobs == {}
    assert list((tmp_path / "outputs").iterdir()) == []
    await tool.aclose()


async def test_close_run_reaps_tools_before_boundary() -> None:
    order: list[str] = []

    class Tool:
        def __init__(self, name: str) -> None:
            self.name = name

        async def aclose(self):
            order.append(self.name)
            return {"cleanup_status": "ok", "remaining_resources": [], "errors": []}

    class Boundary:
        def aclose(self):
            order.append("boundary")
            return {"cleanup_status": "ok", "remaining_resources": [], "errors": []}

    runtime = RunRuntime(
        bash=Tool("bash"), session=Tool("session"), boundary=Boundary()
    )
    result = await close_run(runtime, reason="R11 test")
    assert result["cleanup_status"] == "ok"
    assert order == ["bash", "session", "boundary"]
