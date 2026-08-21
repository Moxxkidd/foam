"""持久 PTY 会话层:session_open / send / read / close / list 五工具。

重型交互工具(msfconsole / ssh / python -i / nc 监听等)的栖息地:

- 每个会话经 pty 启动持久进程,异步读循环持续收集输出,**复用 WP-01 输出层**
  (`tools/output.py`)全量落盘 + 流式 sha256;PTY 只有单流,OutputRecorder
  用 split=False,分流路径/哈希为 None(输出层已支持的情形)。
- LLM 视图默认剥离 ANSI/控制序列;**落盘永远存原文**。
- 内置提示识别正则库(sqlmap [Y/n] 系 / msf6 / password / (yes/no) 等):
  命中时经 session_read 返回结构化 waiting_for_input 事件(提示类型 +
  原文片段 + 处置建议),而不是把 ANSI 原文糊给 LLM。
- 会话数量上限(默认 8);关闭/回收走整进程组 SIGKILL(沿用 WP-01 模式)
  防孤儿;meterpreter 只保证通道可用,语义管理留给后续 WP(排除项)。

schema 形状与 WP-01 同构(provider 中立 {name, description, parameters}
纯 dict + dispatch 单入口),WP-04 直接注册;WP-12 的 msfconsole 场景
依赖本层。tmux/screen 集成按规格不做(不引入外部依赖)。
"""

from __future__ import annotations

import asyncio
import errno
import fcntl
import os
import pty
import re
import signal
import struct
import termios
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .output import OutputManifest, OutputRecorder

#: 同时存活的会话上限(含已退出未关闭的:master fd 仍占着,关了才算释放)。
DEFAULT_MAX_SESSIONS = 8
#: session_read 单次返回视图的默认原始字节预算。
DEFAULT_READ_BUDGET_BYTES = 16 * 1024
#: 每个会话的内存 ring 上限(传 WP-01 输出层;会话完结即释放)。
DEFAULT_RING_BUFFER_BYTES = 256 * 1024
#: 提示识别只在输出尾部窗口上做(提示一定出现在末尾等待输入处)。
_TAIL_DETECT_BYTES = 2048
#: 等待模式下参与 pattern 匹配的文本上限(取尾部,防超长等待输出撑爆)。
_WAIT_MATCH_BYTES = 64 * 1024
#: 等待模式下累计原始字节的上限保险(超过即提前返回,LLM 可继续分页)。
_WAIT_ACCUM_CAP = 4 * 1024 * 1024
#: 写 pty 遇阻塞时的总重试预算(正常交互输入极小,实际上永不触发)。
_SEND_RETRY_SECONDS = 5.0
#: pty 终端尺寸(传给 TIOCSWINSZ)。
_PTY_ROWS = 36
_PTY_COLS = 120
#: 读循环每块大小。
_READ_CHUNK_BYTES = 64 * 1024
#: session_list 里 command 展示截断长度。
_COMMAND_DISPLAY_LIMIT = 120

# ---------------------------------------------------------------------------
# ANSI / 控制序列清洗(只作用于 LLM 视图;落盘永远是原文)
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(
    rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC:ESC ] … BEL 或 ST
    rb"|\x1bP[^\x1b]*\x1b\\"  # DCS:ESC P … ST
    rb"|\x1b\[[0-?]*[ -/]*[@-~]"  # CSI:ESC [ 参数 中间字节 终止字节
    rb"|\x1b[()#*+][0-9A-B]?"  # 字符集选择 / 对齐测试
    rb"|\x1b[=>]"  # 小键盘模式切换
    rb"|\x1b[@-_]"  # 其余两字节 Fe 转义(注意:@–_ 不含 [ 和 ])
)
_BACKSPACE_RE = re.compile(rb".\x08")  # 字符+退格 成对消去(需循环)


def strip_ansi(data: bytes) -> bytes:
    """剥离 ANSI/控制序列,返回可打印字节流。

    处理:CSI/OSC/DCS/字符集/两字节转义;退格覆盖(`x\\x08`);CR 覆盖语义
    (进度条/重绘:行内按 \\r 分段从 0 列叠加,与终端行为一致)。
    """
    text = _ANSI_RE.sub(b"", data)
    while True:
        new = _BACKSPACE_RE.sub(b"", text)
        if new == text:
            break
        text = new
    text = text.replace(b"\x08", b"")
    if b"\r" in text:
        lines = []
        for line in text.split(b"\n"):
            if b"\r" in line:
                buf = bytearray()
                for seg in line.split(b"\r"):
                    if not seg:
                        continue  # 纯回车:光标回 0 列,不写内容
                    buf = bytearray(seg) + buf[len(seg):]
                line = bytes(buf)
            lines.append(line)
        text = b"\n".join(lines)
    return text


# ---------------------------------------------------------------------------
# 提示识别正则库(命中 → 结构化 waiting_for_input 事件)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PromptPattern:
    """一条交互提示识别规则:作用于 ANSI 清洗后的输出尾部。"""

    prompt_type: str
    regex: re.Pattern[str]
    hint: str  # 给 LLM 的处置建议


PROMPT_PATTERNS: tuple[PromptPattern, ...] = (
    PromptPattern(
        "msf6",
        re.compile(r"msf[56]?(?:\s+[\w./-]+\([^)]*\))?\s*>\s*$"),
        "msfconsole 提示符就绪,可 session_send 下一条命令(use/set/exploit 等)。",
    ),
    PromptPattern(
        "meterpreter",
        re.compile(r"meterpreter\s*>\s*$"),
        "meterpreter 通道就绪(本层只保通道,语义管理属后续 WP)。",
    ),
    PromptPattern(
        "password",
        re.compile(
            r"(?i)(?:password|passphrase)(?:\s+for\s+[^:\n]{0,64})?\s*:\s*$"
        ),
        "在询问口令:确认授权后 session_send 发送;审计/报告侧注意脱敏。",
    ),
    PromptPattern(
        "ssh_yes_no",
        re.compile(r"\(yes/no(?:/\[fingerprint\])?\)\s*\??\s*$", re.IGNORECASE),
        "ssh 主机密钥确认:目标在 scope 内才 send 'yes' 继续。",
    ),
    PromptPattern(
        "yn_bracket",
        re.compile(r"(?i)\[(?:y/n|n/y)(?:/[a-z])*\]\s*$"),
        "Y/n 类询问(sqlmap 等):send 'Y'/'n';回车取大写默认值。",
    ),
)


def detect_prompt(tail_text: str) -> PromptPattern | None:
    """在(已 ANSI 清洗的)输出尾部识别已知交互提示;未命中返回 None。

    所有规则都锚定文本末尾——正文里提到 "password"/"msf6" 不算等待输入。
    """
    for pattern in PROMPT_PATTERNS:
        if pattern.regex.search(tail_text):
            return pattern
    return None


# ---------------------------------------------------------------------------
# 同步原子小助手(协程里只做调用,不在 async 函数体内直接阻塞;见陷阱 6)
# ---------------------------------------------------------------------------


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def _acquire_ctty() -> None:
    """子进程 preexec:把 pty slave 设为控制终端(ssh 直接读 /dev/tty 需要)。

    start_new_session=True 已先执行 setsid;失败不致命(多数工具只看 isatty)。
    """
    try:
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    except OSError:
        pass


def _read_span(path: Path, offset: int, limit: int) -> bytes:
    """从落盘文件读一段原始字节;offset 越过 EOF 返回空。"""
    with open(path, "rb") as fh:
        fh.seek(offset)
        return fh.read(limit)


def _write_attempt(fd: int, data: bytes) -> int:
    return os.write(fd, data)


def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
    """整进程组 SIGKILL(与 WP-01 同模式:kill switch 语义=立即)。"""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


# ---------------------------------------------------------------------------
# 工具 schema(与 WP-01 同构,WP-04 直接注册)
# ---------------------------------------------------------------------------

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "session_open",
        "description": (
            "经 pty 启动持久交互会话(msfconsole / ssh / python -i / nc 监听等),"
            "返回 session_id。输出全量落盘(原文,含 ANSI);读用 session_read,"
            "写用 session_send,关用 session_close。会话数有上限,用完要关。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": (
                        "要执行的命令行(经 bash -c,stdin/stdout/stderr 都接 pty)。"
                    ),
                },
            },
            "required": ["command"],
            "additionalProperties": False,
        },
    },
    {
        "name": "session_send",
        "description": (
            "向会话写入文本(自动补 \\n 行尾);控制字符可直接发,如 \\x03 是 "
            "Ctrl-C。已退出/已关闭的会话返回 error。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "session_open 返回的 id。",
                },
                "text": {"type": "string", "description": "要写入的内容。"},
            },
            "required": ["session_id", "text"],
            "additionalProperties": False,
        },
    },
    {
        "name": "session_read",
        "description": (
            "读取会话增量输出(ANSI 已清洗;原文在落盘文件)。默认立即返回当前"
            "增量;给 wait_pattern(正则)则等待其出现或超时——timeout_seconds "
            "省略时默认等 30 秒,显式 0 表示不等待。命中已知交互提示时 events "
            "里带 waiting_for_input 结构化事件。has_more=true 表示还有新输出"
            "未读完,可立即再读。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "会话 id。"},
                "wait_pattern": {
                    "type": ["string", "null"],
                    "description": "等待该正则在新输出(已清洗)中出现。",
                    "default": None,
                },
                "timeout_seconds": {
                    "type": ["number", "null"],
                    "description": "等待上限秒数;null 且带 wait_pattern 时默认 30。",
                    "default": None,
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "default": DEFAULT_READ_BUDGET_BYTES,
                    "description": "本次最多返回的原始字节数(视图预算)。",
                },
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "session_close",
        "description": (
            "关闭会话:运行中的整进程组 SIGKILL,返回最终状态、落盘路径与 "
            "sha256。已自然退出的会话也可 close(释放 fd 并取出哈希)。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "会话 id。"},
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "session_list",
        "description": (
            "列出全部会话:状态(running/exited/closed)、pid、耗时、已落盘"
            "字节数、待消费的提示事件数、输出路径。"
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
    },
]


@dataclass
class _Session:
    """一个 PTY 会话的全部运行时状态。"""

    session_id: str
    command: str
    proc: asyncio.subprocess.Process
    recorder: OutputRecorder
    transport: asyncio.Transport
    master_fd: int
    started_mono: float
    started_wall: float  # 墙钟时间戳(留给审计/报告消费)
    status: str = "running"  # running / exited / closed
    closing: bool = False  # 我们主动 close 中(区分被杀 closed 与自然退出 exited)
    exit_code: int | None = None
    cursor: int = 0  # LLM 视角已读到的原始字节偏移
    detect_tail: bytes = b""  # 提示识别尾部窗口(原始字节)
    last_event_offset: int = -1  # 上次提示事件触发时的总字节数(去重)
    events: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    manifest: OutputManifest | None = None
    done: asyncio.Event = field(default_factory=asyncio.Event)
    data_event: asyncio.Event = field(default_factory=asyncio.Event)
    reader_task: asyncio.Task[None] | None = None


class SessionTool:
    """PTY 会话层入口。一个 engagement 一个实例:输出目录与会话表在实例上。"""

    def __init__(
        self,
        output_dir: str | Path,
        *,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        read_budget_bytes: int = DEFAULT_READ_BUDGET_BYTES,
        ring_buffer_bytes: int = DEFAULT_RING_BUFFER_BYTES,
    ) -> None:
        if max_sessions <= 0:
            raise ValueError("max_sessions 必须为正")
        if read_budget_bytes <= 0:
            raise ValueError("read_budget_bytes 必须为正")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._max_sessions = max_sessions
        self._read_budget = read_budget_bytes
        self._ring_bytes = ring_buffer_bytes
        self._sessions: dict[str, _Session] = {}

    # ---------- WP-04 唯一入口 ----------

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        handlers = {
            "session_open": self.session_open,
            "session_send": self.session_send,
            "session_read": self.session_read,
            "session_close": self.session_close,
            "session_list": self.session_list,
        }
        handler = handlers[name]  # 未知工具名属编程错误,直接 KeyError
        return await handler(**arguments)

    # ---------- 工具实现 ----------

    async def session_open(self, command: str) -> dict[str, Any]:
        active = [s for s in self._sessions.values() if s.status != "closed"]
        if len(active) >= self._max_sessions:
            return {
                "error": (
                    f"已达会话上限 {self._max_sessions}(未关闭会话 "
                    f"{len(active)} 个);先 session_close 释放再开。"
                )
            }
        session_id = "s-" + uuid.uuid4().hex[:10]
        master, slave = pty.openpty()
        _set_winsize(slave, _PTY_ROWS, _PTY_COLS)
        try:
            proc = await asyncio.create_subprocess_exec(
                "bash", "-c", command,
                stdin=slave, stdout=slave, stderr=slave,
                start_new_session=True,  # setsid,使 _acquire_ctty 可拿控制终端
                preexec_fn=_acquire_ctty,
                env={**os.environ, "TERM": "xterm-256color"},  # 固定 TERM,清洗规则确定
                close_fds=True,
            )
        except Exception:
            os.close(master)
            os.close(slave)
            raise
        os.close(slave)  # 父进程只留 master;留着 slave 永远等不到 EOF

        loop = asyncio.get_running_loop()
        reader: asyncio.StreamReader = asyncio.StreamReader(
            limit=_READ_CHUNK_BYTES * 4
        )
        try:
            transport, _ = await loop.connect_read_pipe(
                lambda: asyncio.StreamReaderProtocol(reader),
                os.fdopen(master, "rb", buffering=0),
            )
        except Exception:
            _kill_process_group(proc)  # 别留无主子进程
            await proc.wait()
            os.close(master)
            raise
        recorder = OutputRecorder(
            self.output_dir, session_id,
            ring_buffer_bytes=self._ring_bytes, split=False,
        )
        session = _Session(
            session_id=session_id,
            command=command,
            proc=proc,
            recorder=recorder,
            transport=transport,
            master_fd=master,
            started_mono=time.monotonic(),
            started_wall=time.time(),
        )
        self._sessions[session_id] = session
        session.reader_task = asyncio.create_task(self._reader_loop(session, reader))
        return {
            "session_id": session_id,
            "status": "running",
            "pid": proc.pid,
            "output_path": str(recorder.combined_path),
            "sha256": None,  # 会话存活期间哈希未定稿
            "note": (
                "用 session_send 写入(自动补行尾),session_read 读增量输出"
                "(可带 wait_pattern 等待),session_close 关闭并释放配额。"
            ),
        }

    def _get(self, session_id: str) -> tuple[_Session | None, dict[str, Any] | None]:
        session = self._sessions.get(session_id)
        if session is None:
            return None, {
                "error": f"未知 session_id: {session_id!r}",
                "session_id": session_id,
            }
        return session, None

    async def session_send(self, session_id: str, text: str) -> dict[str, Any]:
        session, err = self._get(session_id)
        if err is not None:
            return err
        if session.status != "running":
            return {
                "error": f"会话已结束(status={session.status}),无法写入",
                "session_id": session_id,
                "status": session.status,
            }
        data = text.encode("utf-8", errors="replace")
        if not data.endswith(b"\n"):
            data += b"\n"  # 规格:自动补行尾
        total = 0
        deadline = time.monotonic() + _SEND_RETRY_SECONDS
        view = memoryview(data)
        while total < len(data):
            try:
                total += _write_attempt(session.master_fd, view[total:])
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    return {
                        "error": "pty 写入持续阻塞(对端不读),放弃",
                        "session_id": session_id,
                        "bytes_written": total,
                    }
                await asyncio.sleep(0.01)
            except OSError as exc:
                return {
                    "error": f"写入失败: {exc}(会话可能刚退出)",
                    "session_id": session_id,
                    "bytes_written": total,
                }
        return {
            "session_id": session_id,
            "status": session.status,
            "bytes_written": total,
        }

    async def session_read(
        self,
        session_id: str,
        *,
        wait_pattern: str | None = None,
        timeout_seconds: float | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        session, err = self._get(session_id)
        if err is not None:
            return err
        if limit is None:
            limit = self._read_budget
        if limit <= 0:
            return {"error": "limit 必须为正", "session_id": session_id}
        pattern = None
        if wait_pattern is not None:
            try:
                pattern = re.compile(wait_pattern)
            except re.error as exc:
                return {
                    "error": f"wait_pattern 非法正则: {exc}",
                    "session_id": session_id,
                }
        # 带 pattern 即隐含等待意图;显式 0 = 不等待
        wait_seconds = timeout_seconds
        if pattern is not None and wait_seconds is None:
            wait_seconds = 30.0
        deadline = time.monotonic() + wait_seconds if wait_seconds else None

        acc = bytearray()
        matched: bool | None = None if pattern is None else False
        timed_out = False
        while True:
            session.data_event.clear()  # 先清再读:判定期间到达的块会重新置位,不丢唤醒
            raw = _read_span(session.recorder.combined_path, session.cursor, limit)
            if raw:
                session.cursor += len(raw)
                acc.extend(raw)
            if pattern is not None and acc:
                haystack = strip_ansi(bytes(acc[-_WAIT_MATCH_BYTES:])).decode(
                    "utf-8", errors="replace"
                )
                if pattern.search(haystack):
                    matched = True
                    break
            now = time.monotonic()
            if deadline is None:  # 非等待模式:读当前增量一次即返回
                break
            if now >= deadline:
                timed_out = True
                break
            if len(acc) >= _WAIT_ACCUM_CAP:
                break  # 保险:等待期间输出过量,先返回让 LLM 分页
            if session.status != "running" and not raw:
                break  # 会话已终结且无新数据,不必傻等
            try:
                await asyncio.wait_for(
                    session.data_event.wait(), timeout=max(0.0, deadline - now)
                )
            except TimeoutError:
                timed_out = True
                break

        view = strip_ansi(bytes(acc[-limit:])).decode("utf-8", errors="replace")
        events = session.events
        session.events = []
        return {
            "session_id": session_id,
            "status": session.status,
            "new_output": view,
            "new_bytes": len(acc),
            "cursor": session.cursor,
            "total_bytes": session.recorder.bytes_total,
            "has_more": session.cursor < session.recorder.bytes_total,
            "events": events,
            "matched": matched,
            "timed_out": timed_out,
            "output_path": str(session.recorder.combined_path),
            "sha256": session.manifest.sha256 if session.manifest else None,
        }

    async def session_close(self, session_id: str) -> dict[str, Any]:
        session, err = self._get(session_id)
        if err is not None:
            return err
        if session.status == "running":
            session.closing = True
            _kill_process_group(session.proc)
        try:
            await asyncio.wait_for(session.done.wait(), timeout=5)
        except TimeoutError:
            return {
                "session_id": session_id,
                "status": session.status,
                "error": "SIGKILL 后 5 秒内未能收割会话,请人工核查",
            }
        try:
            session.transport.close()
        except OSError:
            pass  # EOF 后 transport 可能已自闭合
        if session.status == "running":
            session.status = "closed"  # 我们杀的;自然退出的保持 exited
        result = self._result(session)
        result["note"] = "会话已关闭,配额释放;原文输出保留在 output_path"
        return result

    async def session_list(self) -> dict[str, Any]:
        now = time.monotonic()
        entries = []
        for s in self._sessions.values():
            command = s.command
            if len(command) > _COMMAND_DISPLAY_LIMIT:
                command = command[:_COMMAND_DISPLAY_LIMIT] + "…"
            entries.append(
                {
                    "session_id": s.session_id,
                    "command": command,
                    "status": s.status,
                    "pid": s.proc.pid,
                    "exit_code": s.exit_code,
                    "elapsed_seconds": round(now - s.started_mono, 1),
                    "total_bytes": s.recorder.bytes_total,
                    "pending_events": len(s.events),
                    "output_path": str(s.recorder.combined_path),
                }
            )
        return {"sessions": entries, "count": len(entries)}

    async def aclose(self) -> None:
        """关闭全部会话(WP-04 kill switch / engagement 收尾用)。"""
        for session in self._sessions.values():
            if session.status == "running":
                session.closing = True
                _kill_process_group(session.proc)
        waits = [s.done.wait() for s in self._sessions.values() if not s.done.is_set()]
        if waits:
            try:
                await asyncio.wait_for(asyncio.gather(*waits), timeout=5)
            except TimeoutError:
                pass  # 收割失败的在 close/list 里可见,不在此处抛
        for session in self._sessions.values():
            if session.status == "running":
                session.status = "closed"
            try:
                session.transport.close()
            except OSError:
                pass

    # ---------- 内部:读循环、提示识别、结果装配 ----------

    async def _reader_loop(
        self, session: _Session, reader: asyncio.StreamReader
    ) -> None:
        """持续收集输出:落盘 + 哈希 + 提示识别;EOF 后收割子进程并定稿账目。"""
        try:
            while True:
                try:
                    chunk = await reader.read(_READ_CHUNK_BYTES)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        chunk = b""  # PTY 对端全部关闭(Linux 以 EIO 报 EOF)
                    else:
                        raise
                if not chunk:
                    break
                session.recorder.feed(chunk)
                session.detect_tail = (
                    session.detect_tail + chunk
                )[-_TAIL_DETECT_BYTES:]
                self._detect_prompt(session)
                session.data_event.set()
        except Exception as exc:  # 读循环不许静默死:异常记录进会话结果
            session.error = f"读取循环异常: {exc!r}"
        finally:
            session.exit_code = await session.proc.wait()  # 输出已排空,安全收割
            if session.status == "running":
                # 我们发起 close 杀掉的记 closed;自然退出的记 exited
                session.status = "closed" if session.closing else "exited"
            session.manifest = session.recorder.finalize()
            session.recorder.release_ring()
            session.done.set()
            session.data_event.set()  # 唤醒可能在等待的 session_read

    def _detect_prompt(self, session: _Session) -> None:
        """在输出尾部窗口识别提示;同一输出位置只触发一次(防重绘重复上报)。"""
        text = strip_ansi(session.detect_tail).decode("utf-8", errors="replace")
        pattern = detect_prompt(text)
        if pattern is None:
            return
        if session.recorder.bytes_total == session.last_event_offset:
            return
        session.last_event_offset = session.recorder.bytes_total
        matched = pattern.regex.search(text)
        session.events.append(
            {
                "type": "waiting_for_input",
                "prompt_type": pattern.prompt_type,
                "text": matched.group(0).strip() if matched else "",
                "hint": pattern.hint,
                "offset": session.recorder.bytes_total,
            }
        )

    @staticmethod
    def _result(session: _Session) -> dict[str, Any]:
        m = session.manifest
        result: dict[str, Any] = {
            "session_id": session.session_id,
            "status": session.status,
            "exit_code": session.exit_code,
            "output_path": str(session.recorder.combined_path),
            "sha256": m.sha256 if m else None,
            "total_bytes": m.total_bytes if m else session.recorder.bytes_total,
            # PTY 单流:分流字段固定为 None(与 WP-01 返回结构对齐)
            "stdout_path": None,
            "stdout_sha256": None,
            "stderr_path": None,
            "stderr_sha256": None,
        }
        if session.error:
            result["error"] = session.error
        return result
