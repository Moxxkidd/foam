"""R13-C：心跳快照、平台进程身份与只读活性/锁佐证。"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HEARTBEAT_SCHEMA = "foam.heartbeat/1"
HEARTBEAT_INTERVAL_SECONDS = 10
HEARTBEAT_CLOCK_TOLERANCE_SECONDS = 5


def _now() -> datetime:
    return datetime.now(UTC)


def _linux_identity(pid: int) -> dict[str, Any]:
    result = {"proc_start": None, "boot_id": None, "identity_method": "proc-stat"}
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except FileNotFoundError:
        return {**result, "error": "missing"}
    except OSError:
        return {**result, "error": "unavailable"}
    fields = text.rsplit(") ", 1)[1].split()
    if len(fields) < 20:
        return {**result, "error": "unavailable"}
    result["proc_start"] = fields[19]
    if fields[0] == "Z":
        return {**result, "error": "zombie"}
    try:
        result["boot_id"] = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="utf-8"
        ).strip()
    except OSError:
        return {**result, "error": "unavailable"}
    return {**result, "error": None}


def _macos_identity(pid: int) -> dict[str, Any]:
    result = {"proc_start": None, "boot_id": None, "identity_method": "ps-lstart"}
    try:
        proc = subprocess.run(  # noqa: S603
            ["ps", "-o", "lstart=", "-p", str(pid)],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return {**result, "error": "unavailable"}
    if proc.returncode != 0 or not proc.stdout.strip():
        return {**result, "error": "missing"}
    result["proc_start"] = proc.stdout.strip()
    try:
        boot = subprocess.run(  # noqa: S603
            ["sysctl", "-n", "kern.boottime"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return {**result, "error": "unavailable"}
    if boot.returncode != 0 or not boot.stdout.strip():
        return {**result, "error": "unavailable"}
    result["boot_id"] = boot.stdout.strip()
    return {**result, "error": None}


def process_identity(pid: int) -> dict[str, Any]:
    """读写端共用的进程身份；PID 不存在与不可判读显式分开。"""
    if sys.platform == "linux":
        return _linux_identity(pid)
    if sys.platform == "darwin":
        return _macos_identity(pid)
    return {
        "proc_start": None,
        "boot_id": None,
        "identity_method": "none",
        "error": "unsupported",
    }


def current_process_identity() -> dict[str, Any]:
    return process_identity(os.getpid())


def process_is_active(pid: int, start: str) -> bool:
    """R11 原口径的共享实现：proc start 匹配且不是僵尸/缺失。"""
    identity = process_identity(pid)
    return identity["error"] is None and identity["proc_start"] == start


def read_heartbeat(root: str | Path) -> dict[str, Any]:
    """严格只读心跳；缺失/权限/损坏由调用方分别降级。"""
    path = Path(root) / "heartbeat.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("heartbeat.json 损坏") from exc
    if not isinstance(value, dict) or value.get("schema") != HEARTBEAT_SCHEMA:
        raise ValueError("heartbeat.json schema 非法")
    required = {
        "schema",
        "run_id",
        "entry",
        "pid",
        "proc_start",
        "boot_id",
        "platform",
        "started_at",
        "updated_at",
        "interval_s",
        "seq",
        "loop_status",
        "last_activity",
    }
    if set(value) != required:
        raise ValueError("heartbeat.json 字段不完整或含未知字段")
    if not isinstance(value["pid"], int) or isinstance(value["pid"], bool):
        raise ValueError("heartbeat.json pid 非法")
    if not isinstance(value["interval_s"], (int, float)) or value["interval_s"] <= 0:
        raise ValueError("heartbeat.json interval_s 非法")
    return value


def assess_heartbeat(
    root: str | Path, *, now: datetime | None = None
) -> dict[str, Any]:
    """按心跳新鲜度和进程身份给出活性；仅凭 PID 永不判 alive。"""
    try:
        heartbeat = read_heartbeat(root)
    except FileNotFoundError:
        return {
            "liveness": "none",
            "heartbeat": None,
            "identity_method": "none",
            "identity_note": "无心跳文件",
        }
    except (OSError, UnicodeError, ValueError):
        return {
            "liveness": "unknown",
            "heartbeat": None,
            "identity_method": "none",
            "identity_note": "心跳不可读或损坏;以运行用户查看",
        }
    now = now or _now()
    try:
        updated_at = datetime.fromisoformat(heartbeat["updated_at"])
        interval = float(heartbeat["interval_s"])
    except (TypeError, ValueError):
        return {
            "liveness": "unknown",
            "heartbeat": heartbeat,
            "identity_method": "none",
            "identity_note": "心跳时间非法",
        }
    if updated_at.tzinfo is None:
        return {
            "liveness": "unknown",
            "heartbeat": heartbeat,
            "identity_method": "none",
            "identity_note": "心跳时间缺时区",
        }
    if (updated_at - now).total_seconds() > HEARTBEAT_CLOCK_TOLERANCE_SECONDS:
        return {
            "liveness": "unknown",
            "heartbeat": heartbeat,
            "identity_method": "none",
            "identity_note": "心跳时间在未来超过 5 秒",
        }
    identity = process_identity(heartbeat["pid"])
    method = identity["identity_method"]
    note = (
        "macOS 秒级启动时间存在同秒 PID 复用残余风险"
        if method == "ps-lstart"
        else ""
    )
    if heartbeat["loop_status"] == "closed":
        state = "gone"
    elif identity["error"] in ("missing", "zombie"):
        state = "gone"
    elif identity["error"] == "unavailable":
        state = "unknown"
    elif (
        heartbeat["boot_id"] is not None
        and identity["boot_id"] is not None
        and heartbeat["boot_id"] != identity["boot_id"]
    ):
        state = "gone"
    elif (
        heartbeat["proc_start"] is not None
        and identity["proc_start"] is not None
        and heartbeat["proc_start"] != identity["proc_start"]
    ):
        state = "gone"
    else:
        age = (now - updated_at).total_seconds()
        expired = age > max(3 * interval, 30)
        if expired or identity["error"] == "unsupported":
            state = "stale"
        elif (
            heartbeat["proc_start"] is not None
            and heartbeat["proc_start"] == identity["proc_start"]
            and heartbeat["boot_id"] is not None
            and heartbeat["boot_id"] == identity["boot_id"]
        ):
            state = "alive"
        else:
            state = "stale"
    return {
        "liveness": state,
        "heartbeat": heartbeat,
        "identity_method": method,
        "identity_note": note,
    }


def lock_evidence(root: str | Path) -> dict[str, Any]:
    """Linux 按锁文件 inode 只读佐证；不试锁、不创建文件、不影响活性。"""
    if sys.platform != "linux":
        return {"supported": False}
    path = Path(root) / "engagement.lock"
    try:
        info = path.stat()
    except FileNotFoundError:
        return {"supported": True, "present": False, "held": False}
    except OSError:
        return {"supported": True, "present": True, "held": None}
    try:
        lines = Path("/proc/locks").read_text(encoding="utf-8").splitlines()
    except OSError:
        return {"supported": True, "present": True, "held": None}
    device = f"{os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}"
    inode = str(info.st_ino)
    held = any(
        len(fields) > 5 and fields[4] == device and fields[5] == inode
        for fields in (line.split() for line in lines)
    )
    return {"supported": True, "present": True, "held": held}


class HeartbeatWriter:
    """单写者原子快照；写失败仅警告一次，不影响业务 run。"""

    def __init__(
        self,
        root: str | Path,
        *,
        run_id: str,
        entry: str,
        interval_s: float = HEARTBEAT_INTERVAL_SECONDS,
    ):
        self.root = Path(root)
        self.run_id = run_id
        self.entry = entry
        self.interval_s = interval_s
        self.started_at = _now().isoformat()
        self.seq = 0
        self.loop_status = "running"
        self.last_activity = None
        self._periodic_task: asyncio.Task | None = None
        self._warned = False
        self._last_event_write = 0.0

    def observer(self, delegate: Any) -> HeartbeatObserver:
        return HeartbeatObserver(delegate, self)

    def _payload(self) -> dict[str, Any]:
        identity = current_process_identity()
        return {
            "schema": HEARTBEAT_SCHEMA,
            "run_id": self.run_id,
            "entry": self.entry,
            "pid": os.getpid(),
            "proc_start": identity["proc_start"],
            "boot_id": identity["boot_id"],
            "platform": sys.platform,
            "started_at": self.started_at,
            "updated_at": _now().isoformat(),
            "interval_s": self.interval_s,
            "seq": self.seq + 1,
            "loop_status": self.loop_status,
            "last_activity": self.last_activity,
        }

    def _write(self) -> str | None:
        temporary = None
        try:
            fd, temporary = tempfile.mkstemp(
                dir=self.root, prefix=".heartbeat-", suffix=".tmp"
            )
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(
                        self._payload(), fh, ensure_ascii=False, sort_keys=True
                    )
                    fh.write("\n")
                os.replace(temporary, self.root / "heartbeat.json")
            except BaseException:
                Path(temporary).unlink(missing_ok=True)
                raise
            self.seq += 1
            return None
        except Exception as exc:
            if not self._warned:
                self._warned = True
                print(f"[心跳] 心跳写入失败:{exc};run 继续", file=sys.stderr)
            return str(exc)

    def start(self) -> bool:
        error = self._write()
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            self._periodic_task = asyncio.create_task(self._periodic())
        return error is None

    async def _periodic(self) -> None:
        while True:
            await asyncio.sleep(self.interval_s)
            self._write()

    def _activity(self, kind: str, *, tool_name: str | None = None) -> None:
        self.last_activity = {
            "kind": kind,
            "at": _now().isoformat(),
        }
        if tool_name is not None:
            self.last_activity["tool_name"] = tool_name

    def _event_write(self) -> None:
        now = time.monotonic()
        if now - self._last_event_write >= 1:
            self._last_event_write = now
            self._write()

    def on_status(self, status: str) -> None:
        self.loop_status = status
        self._activity("status")
        self._event_write()

    def on_model(self) -> None:
        self._activity("model")

    def on_tool_call(self, name: str) -> None:
        self._activity("tool_call", tool_name=name)
        self._event_write()

    def on_tool_result(self, name: str) -> None:
        self._activity("tool_result", tool_name=name)
        self._event_write()

    async def aclose(self) -> str | None:
        if self._periodic_task is not None:
            self._periodic_task.cancel()
            try:
                await self._periodic_task
            except asyncio.CancelledError:
                pass
            self._periodic_task = None
        self.loop_status = "closed"
        self._activity("status")
        return self._write()


class HeartbeatObserver:
    """把主环粗粒度事件转发给 writer，其余观察行为原样委托。"""

    def __init__(self, delegate: Any, writer: HeartbeatWriter):
        self._delegate = delegate
        self._writer = writer

    def __getattr__(self, name: str):
        return getattr(self._delegate, name)

    def on_status(self, status: str) -> None:
        self._delegate.on_status(status)
        self._writer.on_status(status)

    def on_text_delta(self, text: str) -> None:
        self._delegate.on_text_delta(text)
        self._writer.on_model()

    def on_reasoning_delta(self, text: str) -> None:
        self._delegate.on_reasoning_delta(text)
        self._writer.on_model()

    def on_tool_call(self, call: Any) -> None:
        self._delegate.on_tool_call(call)
        self._writer.on_tool_call(call.name)

    def on_tool_result(self, name: str, result: dict[str, Any]) -> None:
        self._delegate.on_tool_result(name, result)
        self._writer.on_tool_result(name)
