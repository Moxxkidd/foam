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
from datetime import UTC, datetime
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
#: aclose 收割等待的总时间上界(秒):与 session 层同量级;单次 close 的最坏
#: 耗时上界(R03-AC05;上界内未收割的 job 如实进 remaining_resources,不粉饰)。
CLOSE_REAP_TIMEOUT_SECONDS = 5.0
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
            "进程会被 timeout_seconds、kill_job 或 run 结束时的统一收割"
            "(整进程组 SIGKILL)终止。"
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
                        "1800;null 表示不限时,仅能被 kill_job 或 run 结束收割终止。"
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


@dataclass(frozen=True)
class JobExitEvent:
    """后台/前台 job 到达终态的完成事件(R06 决策 1/2)。

    每 job 恰生产一次:`_supervise` 在 finalize 之后、done 置位之前触发
    (`_supervise_guarded` 兜底路径同)。``event_id`` 由 job_id 确定性派生
    (``job_exit:<job_id>``),重复通知/重放天然同 ID;``run_id`` 生产方不填
    (None),由消费方(loop)接线时补。manifest 引用定稿后的落盘账目;
    兜底路径 finalize 失败时 manifest 相关字段为 None 并携带 error。
    """

    event_id: str
    run_id: str | None
    job_id: str
    command: str
    reason: str  # completed / timeout / killed(与 job.status 终态同源)
    exit_code: int | None
    duration_ms: int | None
    ended_at: str  # UTC ISO-8601
    output_path: str
    sha256: str | None
    stdout_path: str | None
    stdout_sha256: str | None
    stderr_path: str | None
    stderr_sha256: str | None
    total_bytes: int | None
    total_lines: int | None
    error: str | None = None


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
    exit_event_sent: bool = False  # R06:完成事件每 job 恰一次的守卫
    done: asyncio.Event = field(default_factory=asyncio.Event)
    wait_task: asyncio.Task[None] | None = None  # 看管任务(前台/后台一律独立任务)


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
        # R03 统一关闭:_closed 置位后 run_command 拒绝新命令(停止派发兜底);
        # _close_result 非 None 即 aclose 已完成,二次调用短路返回同一结果。
        self._closed = False
        self._close_result: dict[str, Any] | None = None
        # R06:job 终态事件回调(可选,由消费方接线;同步调用,消费方自行调度
        # 异步任务)。在 finalize 之后、done 置位之前触发,每 job 恰一次。
        self.on_job_exit: Callable[[JobExitEvent], None] | None = None

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
        if self._closed:
            # R03:aclose 后拒绝新命令(停止派发的工具层兜底;主派发闸在 loop)
            return {
                "job_id": None,
                "status": "closed",
                "error": "exec 层已关闭(run 已收尾),拒绝执行新命令",
            }
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

        # R03:看管一律为独立任务,前台经 shield 等待——前台等待者被取消不再
        # 带走看管(修复前:外部取消杀死 _supervise,子进程孤儿化、done 永不
        # 置位、manifest 丢失,kill 路径再烧 5s 报「未能收割」假阳性)。
        job.wait_task = asyncio.create_task(self._supervise_guarded(job))
        if background:
            return {
                "job_id": job_id,
                "status": "running",
                "exit_code": None,
                "duration_ms": None,
                "output_view": (
                    f"已转入后台运行(job_id={job_id})。用 list_jobs 查看状态与"
                    f"超时剩余时间,read_output 分页读取输出,kill_job 终止;"
                    f"run 结束时未终止的 job 由 harness 统一收割。"
                ),
                "output_path": str(recorder.combined_path),
                "sha256": None,
                "stdout_path": str(recorder.stdout_path),
                "stdout_sha256": None,
                "stderr_path": str(recorder.stderr_path),
                "stderr_sha256": None,
                "timeout_seconds": timeout,
            }
        await asyncio.shield(job.wait_task)
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

    async def aclose(self) -> dict[str, Any]:
        """关闭 exec 层(R03 统一关闭原语):拒绝新命令,收割全部未完结 job。

        语义:无宽限期(与 kill_job/timeout 的既有 SIGKILL 语义一致——run 结束
        时残留的 job 按定义已无人看管);只杀本工具登记 job 的进程组,不碰组外
        进程(自行 setsid/daemonize 逃逸组外的后代不在收割范围,见 R03 §7)。
        收割等待有总时间上界 ``CLOSE_REAP_TIMEOUT_SECONDS``:一次
        ``wait_for(gather(全部 done.wait()))``,不按 job 逐个累计。

        幂等:二次调用短路返回首次结果对象。返回清理报告:
        ``cleanup_status`` = "ok" / "partial";``remaining_resources`` 列出
        上界内未收割的 job(以 done.is_set()/proc.returncode 为准,不看
        job.status——诚实上报,不粉饰终态);``errors`` 收集杀组异常。
        """
        if self._close_result is not None:
            return self._close_result
        self._closed = True
        errors: list[str] = []
        for job in self._jobs.values():
            if job.done.is_set():
                continue
            job.kill_requested = True  # 看管记账为 killed(非自然完结)
            try:
                self._kill_group(job)
            except Exception as exc:  # _kill_group 已自收 Lookup/Permission;防御
                errors.append(f"job {job.job_id}: 杀进程组异常: {exc!r}")
        waits = [
            job.done.wait() for job in self._jobs.values() if not job.done.is_set()
        ]
        if waits:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*waits), timeout=CLOSE_REAP_TIMEOUT_SECONDS
                )
            except TimeoutError:
                pass  # 上界到点:下方如实上报残留(R03-AC06)
        remaining: list[dict[str, Any]] = []
        for job in self._jobs.values():
            if job.done.is_set() and job.proc.returncode is not None:
                continue
            remaining.append(
                {
                    "kind": "bash_job",
                    "job_id": job.job_id,
                    "command": job.command,
                    "pid": job.proc.pid,
                    "reaped": job.proc.returncode is not None,
                }
            )
        result: dict[str, Any] = {
            "cleanup_status": "partial" if (remaining or errors) else "ok",
            "remaining_resources": remaining,
            "errors": errors,
        }
        self._close_result = result
        return result

    # ---------- 内部:看管、杀进程、视图渲染 ----------

    async def _supervise_guarded(self, job: _Job) -> None:
        """看管任务的安全壳:内部异常不裸奔(防 done 永不置位、任务异常无人认领)。"""
        try:
            await self._supervise(job)
        except Exception as exc:  # 理论不到达(_supervise 已尽收);防御兜底
            job.error = f"看管异常: {exc!r}"
            try:
                job.manifest = job.manifest or job.recorder.finalize()
            except Exception as finalize_exc:
                # 定稿失败也至少置位 done:aclose 不因此烧上界;异常如实入账
                job.error += f";定稿异常: {finalize_exc!r}"
            self._emit_job_exit(job)  # R06:兜底路径同样生产终态事件
            job.done.set()

    def _emit_job_exit(self, job: _Job) -> None:
        """终态事件生产(R06 决策 1):finalize 之后、done 置位之前,每 job 恰一次。

        回调异常捕获进 ``job.error``,绝不影响 done 置位与收尾账目(生产
        侧不为消费方买单)。回调同步调用;异步消费由消费方自行调度。
        """
        if job.exit_event_sent:
            return
        job.exit_event_sent = True
        callback = self.on_job_exit
        if callback is None:
            return
        manifest = job.manifest
        event = JobExitEvent(
            event_id=f"job_exit:{job.job_id}",  # 决策 2:确定性派生
            run_id=None,  # 由消费方(loop)接线时补
            job_id=job.job_id,
            command=job.command,
            reason=job.status,
            exit_code=job.exit_code,
            duration_ms=job.duration_ms,
            ended_at=datetime.now(UTC).isoformat(timespec="milliseconds"),
            output_path=str(
                manifest.output_path if manifest else job.recorder.combined_path
            ),
            sha256=manifest.sha256 if manifest else None,
            stdout_path=(
                str(manifest.stdout_path) if manifest and manifest.stdout_path else None
            ),
            stdout_sha256=manifest.stdout_sha256 if manifest else None,
            stderr_path=(
                str(manifest.stderr_path) if manifest and manifest.stderr_path else None
            ),
            stderr_sha256=manifest.stderr_sha256 if manifest else None,
            total_bytes=manifest.total_bytes if manifest else None,
            total_lines=manifest.total_lines if manifest else None,
            error=job.error,
        )
        try:
            callback(event)
        except Exception as exc:
            note = f"完成事件回调异常: {exc!r}"
            job.error = f"{job.error};{note}" if job.error else note

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
        self._emit_job_exit(job)  # R06:finalize 之后、done 置位之前
        job.done.set()

    @staticmethod
    async def _pump(
        stream: asyncio.StreamReader, feed: Callable[[bytes], None]
    ) -> None:
        async for chunk in _read_chunks(stream):
            feed(chunk)

    @staticmethod
    def _kill_group(job: _Job) -> None:
        """整进程组 SIGKILL(kill switch 语义=立即,不做 TERM 协商)。

        pid/pgid 复用守卫(2026-10-06 对抗评审收口):leader 已被收割
        (returncode 非 None)时跳过 killpg——进程组一旦为空,pgid 可被 OS
        回收分配给无关新进程组(pid 同理),此时 killpg 会错杀陌生人
        (违背「不杀不属于本 run 的进程」)。取舍(见 R03.md §7):leader 已
        收割但孙代仍在组内的竞态下,本守卫漏杀该组——孙代如实进
        remaining_resources(reaped=true),宁可漏杀这一组也不杀陌生人;
        组内仍有存活成员时 pgid 不可能被回收,该情形下 killpg 本是对的,
        跳过是已接受的成本。timeout/kill_job 等既有调用点只作用于存活
        leader(returncode None),行为不变。
        """
        if job.proc.returncode is not None:
            return  # leader 已收割:pid/pgid 可能已被复用,不得 killpg
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
