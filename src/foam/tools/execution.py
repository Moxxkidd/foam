"""Bash 与 PTY 共用的进程创建适配器。

缺省 adapter 保留传统执行行为；注入 boundary 后由同一份网络/环境契约
创建两类工具进程。代际闸只协调新 spawn 与注册，不代替工具的收割逻辑。
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any


async def wait_for_exit(process: asyncio.subprocess.Process) -> int:
    """等待 child watcher 收割 leader，不等待其后代持有的管道断开。"""
    # asyncio 没有与管道断开解耦的进程退出 Event，只能回读 returncode。
    while process.returncode is None:  # noqa: ASYNC110
        await asyncio.sleep(0.02)
    return process.returncode


class ExecutionPaused(RuntimeError):
    """scope 换代或执行层关闭期间拒绝创建新工具进程。"""


class ToolExecutor:
    """统一 legacy/protected spawn，不暴露特权管理命令给工具调用方。"""

    def __init__(self, *, boundary: Any | None = None) -> None:
        self.boundary = boundary
        self._accepting = True
        self._closed = False
        self._generation_lock = asyncio.Lock()

    @property
    def boundary_id(self) -> str | None:
        if self.boundary is None:
            return None
        return self.boundary.boundary_id

    @property
    def epoch(self) -> int | None:
        if self.boundary is None:
            return None
        return self.boundary.epoch

    def capabilities(self) -> dict[str, Any]:
        if self.boundary is None:
            return {
                "execution_mode": "legacy",
                "network": "unrestricted",
                "environment": "inherited",
                "scope": "bash-parameter-heuristic-only",
            }
        return {
            "execution_mode": "protected",
            **self.boundary.capabilities(),
        }

    @asynccontextmanager
    async def generation(self) -> AsyncIterator[int | None]:
        """在锁内完成 spawn 与 job/session 注册，阻止换代竞态。"""
        async with self._generation_lock:
            self._ensure_accepting()
            yield self.epoch

    @asynccontextmanager
    async def generation_transition(self) -> AsyncIterator[None]:
        """停住新注册并等待在途 spawn；仅成功退出时恢复新代际。"""
        self.pause_new()
        async with self._generation_lock:
            if self._closed:
                raise ExecutionPaused("执行层已关闭，拒绝 scope 换代")
            yield
            self.resume_new()

    def pause_new(self) -> None:
        self._accepting = False

    def resume_new(self) -> None:
        if not self._closed:
            self._accepting = True

    def close(self) -> None:
        self._closed = True
        self._accepting = False

    def _ensure_accepting(self) -> None:
        if self._closed or not self._accepting:
            raise ExecutionPaused("执行层正在换代或已关闭，拒绝创建新工具进程")

    async def spawn(
        self,
        argv: list[str],
        *,
        stdin: Any = None,
        stdout: Any = None,
        stderr: Any = None,
        preexec_fn: Any = None,
        term: str | None = None,
    ) -> asyncio.subprocess.Process:
        if self._closed:
            raise ExecutionPaused("执行层已关闭，拒绝创建新工具进程")
        kwargs: dict[str, Any] = {
            "stdin": stdin,
            "stdout": stdout,
            "stderr": stderr,
            "start_new_session": True,
            "close_fds": True,
        }
        if preexec_fn is not None:
            kwargs["preexec_fn"] = preexec_fn
        if self.boundary is None:
            spawn_argv = argv
            kwargs["env"] = (
                None if term is None else {**os.environ, "TERM": term}
            )
        else:
            spawn_argv = self.boundary.tool_argv(argv)
            kwargs["env"] = self.boundary.tool_env(term)
            kwargs["cwd"] = Path(self.boundary.workdir)
            kwargs.update(self.boundary.spawn_kwargs())
        return await asyncio.create_subprocess_exec(*spawn_argv, **kwargs)
