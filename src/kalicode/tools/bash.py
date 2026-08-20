"""自由 bash 执行面:run_command / read_output / list_jobs / kill_job。

LLM 工具 schema 以 provider 中立的 {name, description, parameters(JSON Schema)}
纯 dict 在本文件导出(TOOL_SCHEMAS)——这是 OpenAI 兼容格式与 Claude 格式的
最小公共超集,WP-03 适配层负责翻译成各家 API 形状,WP-04 直接注册并调
BashTool.dispatch。WP-06 的 state 工具与本形状同构。

本层职责边界(见 WP-01 规格):不做 scope 校验(WP-02 在上层包装)、不做
PTY(WP-05)、不定义 engagement 目录布局(WP-06;输出目录由调用方注入)。
"""

from __future__ import annotations

import asyncio
import os
import signal
import time
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .output import (
    OutputManifest,
    OutputRecorder,
    read_page,
    render_full,
    render_truncated,
    split_budget,
)

#: 默认超时(秒):有意放宽——渗透工具普遍长跑;显式传 None 表示不限时。
DEFAULT_TIMEOUT_SECONDS = 1800.0
#: LLM 输出视图的默认字节预算。
DEFAULT_OUTPUT_BUDGET_BYTES = 16 * 1024
#: read_output 单页默认字节数。
DEFAULT_PAGE_BYTES = 32 * 1024
#: 每个活动 job 的内存 ring 上限(快速 tail 用,job 完结即释放)。
DEFAULT_RING_BUFFER_BYTES = 256 * 1024
#: 流读取块大小。刻意不用行迭代:无换行的巨量单行会把行缓冲撑爆(验收 3)。
_READ_CHUNK_BYTES = 64 * 1024
#: list_jobs 里 command 的展示截断长度(全文不落 LLM 视图,防 context 浪费)。
_COMMAND_DISPLAY_LIMIT = 120

#: 区分"参数没传"(用实例默认)与"显式传 null"(如 timeout 不限时)。
_UNSET: Any = object()

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "run_command",
        "description": (
            "经 bash -c 异步执行任意 shell 命令(可用管道/重定向/变量)。默认前台"
            "等待完成并返回截断视图;background=true 立即返回 job_id 后台运行。"
            "stdout/stderr 始终全量落盘:视图超出 output_budget_bytes 只做"
            " head+tail 截断,绝不因此杀进程;完整内容用 read_output 分页读取。"
            "进程只会被 timeout_seconds 或 kill_job 终止。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "要执行的完整命令行(经 bash -c)。",
                },
                "timeout_seconds": {
                    "type": ["number", "null"],
                    "description": (
                        "超时秒数,到点整进程组强杀(status=timeout)。省略默认 "
                        "1800;null 表示不限时,仅能被 kill_job 终止。"
                    ),
                    "default": DEFAULT_TIMEOUT_SECONDS,
                },
                "output_budget_bytes": {
                    "type": "integer",
                    "description": (
                        "返回视图的字节预算,超出做 head+tail 截断;不影响全量落盘。"
                    ),
                    "default": DEFAULT_OUTPUT_BUDGET_BYTES,
                },
                "background": {
                    "type": "boolean",
                    "description": (
                        "true:立即返回 job_id 后台运行;false(默认):前台等待结果。"
                    ),
                    "default": False,
                },
            },
            "required": ["command"],
            "additionalProperties": False,
        },
    },
    {
        "name": "read_output",
        "description": (
            "按字节偏移分页读取任意 job 的完整落盘输出(合流文件,含 stdout 与 "
            "stderr 的到达顺序)。offset 从 0 起,has_more 判断是否读完;running "
            "中的 job 读到的是当前已落盘部分。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "job_id": {
                    "type": "string",
                    "description": "run_command 返回的 job id。",
                },
                "offset": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": "字节偏移。",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "default": DEFAULT_PAGE_BYTES,
                    "description": "本页最多返回的字节数。",
                },
            },
            "required": ["job_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_jobs",
        "description": (
            "列出本 engagement 的全部 job:状态、耗时、距超时剩余秒数"
            "(null 表示不限时或已结束)、已落盘字节数、输出文件路径。"
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
    },
    {
        "name": "kill_job",
        "description": (
            "立即终止指定 job(整进程组 SIGKILL,前台/后台均有效),"
            "返回最终状态与落盘信息;对未授权长跑的止损手段。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "要终止的 job id。"},
            },
            "required": ["job_id"],
            "additionalProperties": False,
        },
    },
]


async def _read_chunks(
    stream: asyncio.StreamReader, size: int = _READ_CHUNK_BYTES
) -> AsyncIterator[bytes]:
    """定长块异步迭代:EOF 结束。不按行读,内存有界与有无换行符无关。"""
    while chunk := await stream.read(size):
        yield chunk


@dataclass
class _Job:
    """一次 run_command 的全部运行时状态。"""

    job_id: str
    command: str
    proc: asyncio.subprocess.Process
    recorder: OutputRecorder
    timeout_seconds: float | None
    budget_bytes: int
    background: bool
    started_mono: float
    started_wall: float  # 墙钟时间戳(留给 WP-02 审计 / WP-10 报告消费)
    status: str = "running"  # running / completed / timeout / killed
    exit_code: int | None = None
    duration_ms: int | None = None
    output_view: str = ""
    manifest: OutputManifest | None = None
    kill_requested: bool = False
    error: str | None = None
    done: asyncio.Event = field(default_factory=asyncio.Event)
    wait_task: asyncio.Task[None] | None = None  # 仅后台模式:看管协程


class BashTool:
    """exec 层入口。一个 engagement 一个实例:输出目录与 job 表都在实例上。"""

    def __init__(
        self,
        output_dir: str | Path,
        *,
        default_timeout_seconds: float | None = DEFAULT_TIMEOUT_SECONDS,
        default_output_budget_bytes: int = DEFAULT_OUTPUT_BUDGET_BYTES,
        ring_buffer_bytes: int = DEFAULT_RING_BUFFER_BYTES,
    ) -> None:
        if default_timeout_seconds is not None and default_timeout_seconds <= 0:
            raise ValueError("默认超时必须为正数或 None(不限时)")
        if default_output_budget_bytes < 0:
            raise ValueError("默认输出预算不能为负")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._default_timeout = default_timeout_seconds
        self._default_budget = default_output_budget_bytes
        self._ring_bytes = ring_buffer_bytes
        self._jobs: dict[str, _Job] = {}

    # ---------- WP-04 唯一入口 ----------

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        handlers: dict[str, Callable[..., Any]] = {
            "run_command": self.run_command,
            "read_output": self.read_output,
            "list_jobs": self.list_jobs,
            "kill_job": self.kill_job,
        }
        handler = handlers[name]  # 未知工具名属编程错误,直接 KeyError
        return await handler(**arguments)

    # ---------- 工具实现 ----------

    async def run_command(
        self,
        command: str,
        *,
        timeout_seconds: float | None = _UNSET,
        output_budget_bytes: int = _UNSET,
        background: bool = False,
    ) -> dict[str, Any]:
        if timeout_seconds is _UNSET:
            timeout = self._default_timeout
        else:
            timeout = timeout_seconds
        if output_budget_bytes is _UNSET:
            budget = self._default_budget
        else:
            budget = output_budget_bytes
        if timeout is not None and timeout <= 0:
            raise ValueError("timeout_seconds 必须为正数或 None(不限时)")
        if budget < 0:
            raise ValueError("output_budget_bytes 不能为负")

        job_id = uuid.uuid4().hex[:12]
        recorder = OutputRecorder(
            self.output_dir, job_id, ring_buffer_bytes=self._ring_bytes, split=True
        )
        proc = await asyncio.create_subprocess_exec(
            "bash",
            "-c",
            command,
            stdin=asyncio.subprocess.DEVNULL,  # 非交互执行面;交互需求走 WP-05 PTY
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # 独立进程组:kill/timeout 整组强杀,不留孤儿
        )
        job = _Job(
            job_id=job_id,
            command=command,
            proc=proc,
            recorder=recorder,
            timeout_seconds=timeout,
            budget_bytes=budget,
            background=background,
            started_mono=time.monotonic(),
            started_wall=time.time(),
        )
        self._jobs[job_id] = job

        supervise = self._supervise(job)
        if background:
            job.wait_task = asyncio.create_task(supervise)
            return {
                "job_id": job_id,
                "status": "running",
                "exit_code": None,
                "duration_ms": None,
                "output_view": (
                    f"已转入后台运行(job_id={job_id})。用 list_jobs 查看状态与"
                    f"超时剩余时间,read_output 分页读取输出,kill_job 终止。"
                ),
                "output_path": str(recorder.combined_path),
                "sha256": None,
                "stdout_path": str(recorder.stdout_path),
                "stdout_sha256": None,
                "stderr_path": str(recorder.stderr_path),
                "stderr_sha256": None,
                "timeout_seconds": timeout,
            }
        await supervise
        return self._result(job)

    async def read_output(
        self, job_id: str, *, offset: int = 0, limit: int = DEFAULT_PAGE_BYTES
    ) -> dict[str, Any]:
        job = self._jobs.get(job_id)
        if job is None:
            return {
                "error": f"未知 job_id: {job_id!r}(用 list_jobs 查看现存 job)",
                "job_id": job_id,
            }
        try:
            page = read_page(job.recorder.combined_path, offset, limit)
        except ValueError as exc:
            return {"error": str(exc), "job_id": job_id}
        return {
            "job_id": job_id,
            "status": job.status,
            "offset": page.offset,
            "limit": limit,
            "bytes_read": page.bytes_read,
            "total_bytes": page.total_bytes,
            "has_more": page.has_more,
            "content": page.text,
            "output_path": str(job.recorder.combined_path),
            "sha256": job.manifest.sha256 if job.manifest else None,
        }

    async def list_jobs(self) -> dict[str, Any]:
        now = time.monotonic()
        entries = []
        for job in self._jobs.values():
            elapsed = (
                job.duration_ms / 1000
                if job.duration_ms is not None
                else now - job.started_mono
            )
            remaining = None
            if job.status == "running" and job.timeout_seconds is not None:
                deadline = job.started_mono + job.timeout_seconds
                remaining = round(max(0.0, deadline - now), 1)
            command = job.command
            if len(command) > _COMMAND_DISPLAY_LIMIT:
                command = command[:_COMMAND_DISPLAY_LIMIT] + "…"
            entries.append(
                {
                    "job_id": job.job_id,
                    "command": command,
                    "status": job.status,
                    "exit_code": job.exit_code,
                    "background": job.background,
                    "elapsed_seconds": round(elapsed, 1),
                    "timeout_seconds": job.timeout_seconds,
                    "timeout_remaining_seconds": remaining,
                    "output_bytes_so_far": job.recorder.bytes_total,
                    "output_path": str(job.recorder.combined_path),
                }
            )
        return {"jobs": entries, "count": len(entries)}

    async def kill_job(self, job_id: str) -> dict[str, Any]:
        job = self._jobs.get(job_id)
        if job is None:
            return {"error": f"未知 job_id: {job_id!r}", "job_id": job_id}
        if job.status != "running":
            result = self._result(job)
            result["note"] = "job 已结束,无需 kill"
            return result
        job.kill_requested = True
        self._kill_group(job)
        try:
            await asyncio.wait_for(job.done.wait(), timeout=5)
        except TimeoutError:
            return {
                "job_id": job_id,
                "status": job.status,
                "error": "SIGKILL 后 5 秒内未能收割进程,请人工核查",
            }
        return self._result(job)

    # ---------- 内部:看管、杀进程、视图渲染 ----------

    async def _supervise(self, job: _Job) -> None:
        """看管一个 job 到终态:喂 recorder、等退出/超时、收尾账目与视图。"""
        readers = [
            asyncio.create_task(self._pump(job.proc.stdout, job.recorder.feed_stdout)),
            asyncio.create_task(self._pump(job.proc.stderr, job.recorder.feed_stderr)),
        ]
        timed_out = False
        try:
            if job.timeout_seconds is None:
                await job.proc.wait()
            else:
                await asyncio.wait_for(job.proc.wait(), job.timeout_seconds)
        except TimeoutError:  # py3.11+ asyncio.TimeoutError 即内建 TimeoutError
            timed_out = True
            self._kill_group(job)
        await job.proc.wait()  # 收割(超时路径下等 SIGKILL 落地)
        reader_results = await asyncio.gather(*readers, return_exceptions=True)
        for result in reader_results:
            if isinstance(result, Exception):
                job.error = f"输出收集异常: {result!r}"
        if job.kill_requested:
            job.status = "killed"
        elif timed_out:
            job.status = "timeout"
        else:
            job.status = "completed"
        job.exit_code = job.proc.returncode
        job.duration_ms = round((time.monotonic() - job.started_mono) * 1000)
        job.manifest = job.recorder.finalize()
        job.output_view = self._render_view(job)
        job.recorder.release_ring()  # 完结 job 释放 ring:内存只随活动 job 数增长
        job.done.set()

    @staticmethod
    async def _pump(
        stream: asyncio.StreamReader, feed: Callable[[bytes], None]
    ) -> None:
        async for chunk in _read_chunks(stream):
            feed(chunk)

    @staticmethod
    def _kill_group(job: _Job) -> None:
        """整进程组 SIGKILL(kill switch 语义=立即,不做 TERM 协商)。"""
        try:
            os.killpg(os.getpgid(job.proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                job.proc.kill()
            except ProcessLookupError:
                pass

    def _render_view(self, job: _Job) -> str:
        manifest = job.manifest
        span = split_budget(manifest.total_bytes, job.budget_bytes)
        if span is None:
            return render_full(manifest.output_path.read_bytes())
        head_len, tail_len = span
        with open(manifest.output_path, "rb") as fh:
            head = fh.read(head_len)
            if tail_len <= job.recorder.ring_size:
                tail = job.recorder.tail(tail_len)  # 快速 tail:ring 命中
            else:  # 预算大于 ring 容量时回退磁盘 seek,保证账目精确
                fh.seek(-tail_len, os.SEEK_END)
                tail = fh.read(tail_len)
        return render_truncated(
            head,
            tail,
            total_bytes=manifest.total_bytes,
            total_lines=manifest.total_lines,
            output_path=manifest.output_path,
            sha256=manifest.sha256,
        )

    @staticmethod
    def _result(job: _Job) -> dict[str, Any]:
        """终态返回结构(WP-01 规格 + 三分流 optional 字段)。"""
        m = job.manifest
        stdout_path = job.recorder.stdout_path
        stderr_path = job.recorder.stderr_path
        result: dict[str, Any] = {
            "job_id": job.job_id,
            "status": job.status,
            "exit_code": job.exit_code,
            "duration_ms": job.duration_ms,
            "output_view": job.output_view,
            "output_path": str(job.recorder.combined_path),
            "sha256": m.sha256 if m else None,
            "stdout_path": str(stdout_path) if stdout_path else None,
            "stdout_sha256": m.stdout_sha256 if m else None,
            "stderr_path": str(stderr_path) if stderr_path else None,
            "stderr_sha256": m.stderr_sha256 if m else None,
            "total_bytes": m.total_bytes if m else job.recorder.bytes_total,
            "total_lines": m.total_lines if m else job.recorder.lines_total,
        }
        if job.error:
            result["error"] = job.error
        return result
