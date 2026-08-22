"""智能输出层:全量落盘 + 流式 sha256 + 有界 ring buffer + head/tail 截断视图。

只管字节,不碰子进程(子进程生命周期在 bash.py)。WP-05 的 PTY 会话复用本层
(split=False 单流模式,此时分流路径与哈希一律为 None)。

账目约定:一切长度与偏移按**原始字节**计;只有给 LLM 的视图做 UTF-8
errors="replace" 解码。因此视图里"省略 X 字节"永远能与落盘文件对账,
read_output 的 offset/limit 也是字节偏移。
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path


class RingBuffer:
    """有界字节缓冲:只保留最近 cap 字节,供快速 tail;大输出不进内存。"""

    def __init__(self, cap: int) -> None:
        if cap <= 0:
            raise ValueError("ring buffer 容量必须为正")
        self.cap = cap
        self._buf = bytearray()

    def __len__(self) -> int:
        return len(self._buf)

    def feed(self, data: bytes) -> None:
        self._buf.extend(data)
        overflow = len(self._buf) - self.cap
        if overflow > 0:
            del self._buf[:overflow]

    def tail(self, n: int) -> bytes:
        """末尾 n 字节;缓冲不足 n 则返回现有全部(可能短于 n)。"""
        if n <= 0:
            return b""
        return bytes(self._buf[-n:])


@dataclass(frozen=True)
class OutputManifest:
    """落盘最终账目(finalize 后不可变)。分流字段在单流(PTY)模式下为 None。"""

    job_id: str
    output_path: Path  # 合流文件(到达顺序),始终存在
    sha256: str  # 合流文件 sha256
    total_bytes: int  # 合流总字节
    total_lines: int  # 合流换行符数
    stdout_path: Path | None
    stdout_sha256: str | None
    stdout_bytes: int
    stderr_path: Path | None
    stderr_sha256: str | None
    stderr_bytes: int


class OutputRecorder:
    """边收边写盘、边算 sha256:合流 + 可选 stdout/stderr 分流,共三个哈希。

    asyncio 单线程语义下 feed_* 是同步原子调用(内部无 await),两个流任务
    交替写合流文件即真实到达顺序,无需锁。文件无缓冲直写:running 中的
    job 也能被 read_output 立刻读到已落盘字节,崩溃也尽量少丢。
    """

    def __init__(
        self,
        output_dir: str | Path,
        job_id: str,
        *,
        ring_buffer_bytes: int = 256 * 1024,
        split: bool = True,
    ) -> None:
        self.job_id = job_id
        self.split = split
        directory = Path(output_dir)
        directory.mkdir(parents=True, exist_ok=True)
        self.combined_path = directory / f"{job_id}.log"
        self.stdout_path = directory / f"{job_id}.stdout" if split else None
        self.stderr_path = directory / f"{job_id}.stderr" if split else None
        self._combined = open(self.combined_path, "wb", buffering=0)
        self._stdout = open(self.stdout_path, "wb", buffering=0) if split else None
        self._stderr = open(self.stderr_path, "wb", buffering=0) if split else None
        self._h_combined = hashlib.sha256()
        self._h_stdout = hashlib.sha256() if split else None
        self._h_stderr = hashlib.sha256() if split else None
        self.bytes_total = 0
        self.lines_total = 0
        self.stdout_bytes = 0
        self.stderr_bytes = 0
        self._ring = RingBuffer(ring_buffer_bytes) if ring_buffer_bytes > 0 else None
        self._manifest: OutputManifest | None = None

    @property
    def finalized(self) -> bool:
        return self._manifest is not None

    def feed_stdout(self, data: bytes) -> None:
        self._feed(data, split="stdout")

    def feed_stderr(self, data: bytes) -> None:
        self._feed(data, split="stderr")

    def feed(self, data: bytes) -> None:
        """单流(PTY)入口;split=True 的 recorder 不允许调用。"""
        if self.split:
            raise RuntimeError("split 模式请用 feed_stdout/feed_stderr")
        self._feed(data, split=None)

    def _feed(self, data: bytes, *, split: str | None) -> None:
        if self.finalized:
            raise RuntimeError("recorder 已 finalize,禁止继续写入")
        if not data:
            return
        self._combined.write(data)
        self._h_combined.update(data)
        self.bytes_total += len(data)
        self.lines_total += data.count(b"\n")
        if split == "stdout":
            self._stdout.write(data)
            self._h_stdout.update(data)
            self.stdout_bytes += len(data)
        elif split == "stderr":
            self._stderr.write(data)
            self._h_stderr.update(data)
            self.stderr_bytes += len(data)
        if self._ring is not None:
            self._ring.feed(data)

    @property
    def ring_size(self) -> int:
        return 0 if self._ring is None else len(self._ring)

    def tail(self, n: int) -> bytes:
        """内存中的末尾 n 字节(ring 已释放或不足时可能短于 n)。"""
        return b"" if self._ring is None else self._ring.tail(n)

    def release_ring(self) -> None:
        """视图渲染完成后释放 ring:已完结 job 不再占内存,内存只随活动 job 数增长。"""
        self._ring = None

    def finalize(self) -> OutputManifest:
        """关闭文件并返回最终账目;幂等。"""
        if self._manifest is None:
            self._combined.close()
            if self._stdout is not None:
                self._stdout.close()
            if self._stderr is not None:
                self._stderr.close()
            self._manifest = OutputManifest(
                job_id=self.job_id,
                output_path=self.combined_path,
                sha256=self._h_combined.hexdigest(),
                total_bytes=self.bytes_total,
                total_lines=self.lines_total,
                stdout_path=self.stdout_path,
                stdout_sha256=self._h_stdout.hexdigest() if self._h_stdout else None,
                stdout_bytes=self.stdout_bytes,
                stderr_path=self.stderr_path,
                stderr_sha256=self._h_stderr.hexdigest() if self._h_stderr else None,
                stderr_bytes=self.stderr_bytes,
            )
        return self._manifest


def split_budget(total_bytes: int, budget_bytes: int) -> tuple[int, int] | None:
    """按预算切 (head 字节数, tail 字节数);total 不超预算则返回 None(不截断)。

    head 占预算一半(向下取整),tail 拿剩余;budget=0 时退化为 (0, 0) 全省略。
    """
    if budget_bytes < 0:
        raise ValueError("预算不能为负")
    if total_bytes <= budget_bytes:
        return None
    head = budget_bytes // 2
    tail = budget_bytes - head
    return head, tail


def render_full(content: bytes) -> str:
    """未超预算的全文视图:UTF-8 错误替换解码,二进制/乱码不崩。"""
    return content.decode("utf-8", errors="replace")


def render_truncated(
    head: bytes,
    tail: bytes,
    *,
    total_bytes: int,
    total_lines: int,
    output_path: str | Path,
    sha256: str,
) -> str:
    """head+tail 截断视图,格式遵循 WP-01 规格:

    [前 H 字节] … 省略 X 字节/Y 行,完整输出 <路径>(sha256:…) … [后 T 字节]
    """
    omitted = total_bytes - len(head) - len(tail)
    if omitted < 0:
        raise ValueError("head+tail 超过总字节,账目对不上")
    marker = (
        f"\n… 省略 {omitted} 字节 / 共 {total_lines} 行,"
        f"完整输出已落盘 {output_path} (sha256:{sha256}),"
        f"可用 read_output 分页读取 …\n"
    )
    return render_full(head) + marker + render_full(tail)


@dataclass(frozen=True)
class PageResult:
    """read_page 的一页:字节账目 + 解码文本。"""

    offset: int
    bytes_read: int
    total_bytes: int
    has_more: bool
    text: str


def read_page(path: str | Path, offset: int, limit: int) -> PageResult:
    """按字节偏移从落盘文件读一页。

    对 running 中的 job,读到的是调用时已落盘的部分(has_more 按当时文件大小
    计算)。页边界切断 UTF-8 字符时,切口处按错误替换解码,不崩。
    """
    if offset < 0:
        raise ValueError("offset 不能为负")
    if limit <= 0:
        raise ValueError("limit 必须为正")
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        fh.seek(offset)
        raw = fh.read(limit)
    return PageResult(
        offset=offset,
        bytes_read=len(raw),
        total_bytes=size,
        has_more=offset + len(raw) < size,
        text=raw.decode("utf-8", errors="replace"),
    )
