"""R11 限权网络边界 helper。

此模块只在 Linux/euid=0 的 protected 路径由 root Foam 控制面启动。对外仅
接收严格 JSON；网络与进程管理命令均由本模块生成固定 argv，不接受 shell
或 nft 文本。清理成功后保留 root 私有 cleaned 标记供重启对账。真实特权
验证限隔离 Linux harness。
"""

from __future__ import annotations

import argparse
import array
import ctypes
import hashlib
import ipaddress
import json
import os
import re
import select
import signal
import socket
import stat
import subprocess  # noqa: S403  # 管理面只执行固定 argv
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_MESSAGE_SIZE = 64 * 1024
COMMAND_TIMEOUT = 10.0
# 锁定 root exec/UID 切换的兼容语义；root 子进程也只能获得最小 bounding set。
REQUIRED_SECUREBITS = 0x0A
_CAPABILITIES = (
    ("setgid", 6),
    ("kill", 5),
    ("setuid", 7),
    ("net_admin", 12),
    ("sys_admin", 21),
)
_CAPABILITY_BITS = dict(_CAPABILITIES)
_BOUNDARY_RE = re.compile(r"^fb[0-9a-f]{12}$")
_NAME_RE = re.compile(r"^[a-z][a-z0-9]{1,14}$")
_ALLOWED_KEYS = {
    "create": {"op", "policy"},
    "retire": {"op"},
    "apply": {"op", "policy"},
    "close": {"op"},
    "status": {"op"},
    "recover": {"op"},
}
_MANIFEST_KEYS = {
    "version",
    "boundary_id",
    "netns",
    "host_interface",
    "tool_interface",
    "nft_table",
    "ipv4",
    "ipv6",
    "helper_pid",
    "helper_start",
    "generation",
}
_CLEANED_MANIFEST = "cleaned.json"


class BoundaryError(RuntimeError):
    """边界无法建立、验证或清理；调用方不得降级执行。"""


class ExecutionUnsupportedError(BoundaryError):
    """当前平台或权限配置不支持 protected 执行。"""


class ProtocolError(BoundaryError):
    """管理协议不符合严格 JSON schema。"""


def require_supported() -> None:
    """protected 只支持已以 root 启动的 Linux 控制面，不自动 sudo。"""
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ExecutionUnsupportedError("protected 执行仅支持 Linux 且 euid=root")


def _reject_constant(value: str) -> None:
    raise ProtocolError(f"非法 JSON 数值 {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"重复字段 {key}")
        result[key] = value
    return result


def _validate_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"cidrs", "dns", "digest"}:
        raise ProtocolError("policy 字段不完整或含未知字段")
    cidrs = value["cidrs"]
    if not isinstance(cidrs, list) or len(cidrs) > 4096:
        raise ProtocolError("policy.cidrs 必须是有界数组")
    normalized = []
    for cidr in cidrs:
        if not isinstance(cidr, str):
            raise ProtocolError("CIDR 必须是字符串")
        try:
            normalized.append(str(ipaddress.ip_network(cidr, strict=False)))
        except ValueError as exc:
            raise ProtocolError("非法 CIDR") from exc
    dns = value["dns"]
    if dns is not None:
        if not isinstance(dns, str):
            raise ProtocolError("DNS 必须是 IP 字符串或 null")
        try:
            address = ipaddress.ip_address(dns)
        except ValueError as exc:
            raise ProtocolError("非法 DNS 地址") from exc
        if not any(address in ipaddress.ip_network(cidr) for cidr in normalized):
            raise ProtocolError("DNS 不在授权 CIDR 内")
        dns = str(address)
    if not isinstance(value["digest"], str) or len(value["digest"]) > 1024:
        raise ProtocolError("policy.digest 非法")
    return {"cidrs": normalized, "dns": dns, "digest": value["digest"]}


def decode_request(raw: bytes) -> dict[str, Any]:
    """解析唯一管理协议；拒绝重复/未知字段、非有限数和超大输入。"""
    if len(raw) > MAX_MESSAGE_SIZE:
        raise ProtocolError("管理消息过大")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("非法 JSON 管理消息") from exc
    if not isinstance(value, dict) or not isinstance(value.get("op"), str):
        raise ProtocolError("管理消息必须是含 op 的对象")
    op = value["op"]
    if op not in _ALLOWED_KEYS or set(value) != _ALLOWED_KEYS[op]:
        raise ProtocolError("未知命令或字段")
    if "policy" in value:
        value["policy"] = _validate_policy(value["policy"])
    return value


def required_capability_mask() -> int:
    return sum(1 << bit for _, bit in _CAPABILITIES)


def verify_security_status(
    status: dict[str, str], *, securebits: int
) -> dict[str, Any]:
    """回读五类 capability、securebits 与 NNP，任何偏差均拒绝监听。"""
    expected = required_capability_mask()
    expected_values = {
        "CapInh": 0,
        "CapPrm": expected,
        "CapEff": expected,
        "CapBnd": expected,
        "CapAmb": 0,
    }
    try:
        actual = {key: int(status[key], 16) for key in expected_values}
    except (KeyError, ValueError) as exc:
        raise BoundaryError("无法回读 helper capability 状态") from exc
    if actual != expected_values:
        raise BoundaryError(f"helper capability 集合不符: {actual}")
    if status.get("NoNewPrivs") != "1":
        raise BoundaryError("helper NoNewPrivs 未生效")
    if securebits != REQUIRED_SECUREBITS:
        raise BoundaryError("helper securebits 未按最小权限锁定")
    return {
        "capabilities": [name for name, _ in _CAPABILITIES],
        "capability_mask": f"{expected:016x}",
        "securebits": securebits,
        "no_new_privs": True,
    }


def _self_status() -> dict[str, str]:
    result = {}
    for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition(":")
        if separator:
            result[key] = value.strip()
    return result


def harden_process() -> dict[str, Any]:
    """清 ambient/bounding，capset 到五个实际能力，并锁 securebits+NNP。"""
    require_supported()
    libc = ctypes.CDLL(None, use_errno=True)

    def prctl(option: int, arg2: int = 0, arg3: int = 0) -> int:
        result = libc.prctl(option, arg2, arg3, 0, 0)
        if result < 0:
            error = ctypes.get_errno()
            raise BoundaryError(f"prctl({option}) 失败: {os.strerror(error)}")
        return result

    prctl(47, 4)  # PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL
    prctl(28, REQUIRED_SECUREBITS)  # PR_SET_SECUREBITS
    last_cap = int(Path("/proc/sys/kernel/cap_last_cap").read_text().strip())
    required = required_capability_mask()
    for bit in range(last_cap + 1):
        if not required & (1 << bit):
            prctl(24, bit)  # PR_CAPBSET_DROP

    class CapHeader(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class CapData(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    header = CapHeader(0x20080522, 0)
    data = (CapData * 2)()
    for index, shift in ((0, 0), (1, 32)):
        data[index].effective = (required >> shift) & 0xFFFFFFFF
        data[index].permitted = (required >> shift) & 0xFFFFFFFF
        data[index].inheritable = 0
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        error = ctypes.get_errno()
        raise BoundaryError(f"capset 失败: {os.strerror(error)}")
    prctl(38, 1)  # PR_SET_NO_NEW_PRIVS
    return verify_security_status(
        _self_status(),
        securebits=prctl(27),  # PR_GET_SECUREBITS
    )


@dataclass(frozen=True)
class ResourceConfig:
    boundary_id: str
    netns: str
    host_interface: str
    tool_interface: str
    nft_table: str
    host_ipv4: str
    ipv4: str
    host_ipv6: str
    ipv6: str

    @property
    def manifest_names(self) -> dict[str, str]:
        return {
            "netns": self.netns,
            "host_interface": self.host_interface,
            "tool_interface": self.tool_interface,
            "nft_table": self.nft_table,
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
        }


def resource_config(boundary_id: str) -> ResourceConfig:
    if not _BOUNDARY_RE.fullmatch(boundary_id):
        raise BoundaryError("非法 boundary_id")
    suffix = boundary_id[-12:]
    digest = hashlib.sha256(boundary_id.encode("ascii")).digest()
    base4 = f"10.{digest[0]}.{digest[1] & 0xFC}"
    base6 = f"fd11:{digest[2:4].hex()}::"
    return ResourceConfig(
        boundary_id=boundary_id,
        netns=f"fn{suffix}",
        host_interface=f"fh{suffix}",
        tool_interface=f"ft{suffix}",
        nft_table=f"ftb{suffix}",
        host_ipv4=f"{base4}.1",
        ipv4=f"{base4}.2",
        host_ipv6=f"{base6}1",
        ipv6=f"{base6}2",
    )


def _process_start(pid: int) -> str:
    text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    return text.rsplit(") ", 1)[1].split()[19]


def read_manifest(
    path: str | Path,
    *,
    expected_boundary_id: str,
    owner_uid: int = 0,
) -> dict[str, Any]:
    """只信 root 私有、字段完整且资源名与 boundary 精确匹配的 manifest。"""
    manifest_path = Path(path)
    try:
        info = manifest_path.lstat()
    except OSError as exc:
        raise BoundaryError(f"manifest 不可读取: {exc}") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != owner_uid
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise BoundaryError("manifest 所有权或权限不明")
    try:
        raw = manifest_path.read_bytes()
        if len(raw) > MAX_MESSAGE_SIZE:
            raise BoundaryError("manifest 过大")
        value = json.loads(raw, object_pairs_hook=_object_without_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BoundaryError("manifest 格式非法") from exc
    if not isinstance(value, dict) or set(value) != _MANIFEST_KEYS:
        raise BoundaryError("manifest 字段不完整或含未知字段")
    if value["version"] != 1 or value["boundary_id"] != expected_boundary_id:
        raise BoundaryError("manifest boundary 身份不符")
    config = resource_config(expected_boundary_id)
    if any(value[key] != expected for key, expected in config.manifest_names.items()):
        raise BoundaryError("manifest 资源归属不符")
    if (
        not isinstance(value["helper_pid"], int)
        or isinstance(value["helper_pid"], bool)
        or value["helper_pid"] <= 0
        or not isinstance(value["helper_start"], str)
        or not value["helper_start"].isdigit()
    ):
        raise BoundaryError("manifest helper 身份非法")
    generation = value["generation"]
    if generation is not None:
        if not isinstance(generation, dict) or set(generation) != {
            "pid",
            "start",
            "token",
        }:
            raise BoundaryError("manifest generation 非法")
        if (
            not isinstance(generation["pid"], int)
            or isinstance(generation["pid"], bool)
            or generation["pid"] <= 0
            or not isinstance(generation["start"], str)
            or not generation["start"].isdigit()
            or not isinstance(generation["token"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", generation["token"])
        ):
            raise BoundaryError("manifest generation 身份非法")
    return value


def write_manifest(path: str | Path, value: dict[str, Any]) -> None:
    """以 0600 原子更新 root 私有 manifest。"""
    destination = Path(path)
    temporary = destination.with_suffix(".tmp")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    fd = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
    )
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, destination)


def render_nft_rules(
    policy: Any,
    *,
    table: str,
    interface: str,
    ipv4: str,
    ipv6: str,
    replace: bool = False,
) -> str:
    """生成 per-run inet 表；无关 forward/input 默认 accept。"""
    if not _NAME_RE.fullmatch(table) or not _NAME_RE.fullmatch(interface):
        raise BoundaryError("非法 nft 资源名")
    address4 = str(ipaddress.IPv4Address(ipv4))
    address6 = str(ipaddress.IPv6Address(ipv6))
    lines = [f"delete table inet {table}"] if replace else []
    lines.extend(
        [
            f"table inet {table} {{",
            "    chain forward {",
            "        type filter hook forward priority filter; policy accept;",
            f'        oifname "{interface}" ip daddr {address4} '
            "ct state established accept",
            f'        oifname "{interface}" ip6 daddr {address6} '
            "ct state established accept",
        ]
    )
    for network in policy.cidrs:
        if network.version == 4:
            lines.extend(
                [
                    f'        iifname "{interface}" ip saddr {address4} '
                    f"ip daddr {network} meta l4proto {{ tcp, udp }} accept",
                    f'        iifname "{interface}" ip saddr {address4} '
                    f"ip daddr {network} icmp type echo-request accept",
                ]
            )
        else:
            lines.extend(
                [
                    f'        iifname "{interface}" ip6 saddr {address6} '
                    f"ip6 daddr {network} meta l4proto {{ tcp, udp }} accept",
                    f'        iifname "{interface}" ip6 saddr {address6} '
                    f"ip6 daddr {network} icmpv6 type echo-request accept",
                ]
            )
    lines.extend(
        [
            f'        iifname "{interface}" ip saddr {address4} drop',
            f'        iifname "{interface}" ip6 saddr {address6} drop',
            "    }",
            "    chain input {",
            "        type filter hook input priority filter; policy accept;",
            f'        iifname "{interface}" icmpv6 type '
            "{ nd-neighbor-solicit, nd-neighbor-advert } accept",
            f'        iifname "{interface}" drop',
            "    }",
            "    chain postrouting {",
            "        type nat hook postrouting priority srcnat; policy accept;",
            f'        iifname "{interface}" ip saddr {address4} '
            f'oifname != "{interface}" masquerade',
            f'        iifname "{interface}" ip6 saddr {address6} '
            f'oifname != "{interface}" masquerade',
            "    }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class _Policy:
    cidrs: tuple[Any, ...]
    dns: Any
    digest: str

    @classmethod
    def from_payload(cls, value: dict[str, Any]) -> _Policy:
        return cls(
            cidrs=tuple(ipaddress.ip_network(item) for item in value["cidrs"]),
            dns=ipaddress.ip_address(value["dns"]) if value["dns"] else None,
            digest=value["digest"],
        )


class CommandRunner:
    """所有管理子命令统一 capture/timeout/check，无 shell。"""

    def run(
        self,
        argv: list[str],
        *,
        input_text: str | None = None,
        check: bool = True,
        timeout: float = COMMAND_TIMEOUT,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(  # noqa: S603  # argv 由 helper 固定生成
                argv,
                input=input_text,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise BoundaryError(f"管理命令 {argv[0]} 失败: {exc}") from exc
        if check and result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise BoundaryError(
                f"管理命令 {argv[0]} 返回 {result.returncode}: {detail}"
            )
        return result


_REAPER = """\
import os
import signal
import socket
import sys
control = socket.socket(fileno=int(sys.argv[2]))
if control.recv(1) != b"R":
    raise SystemExit(1)
os.setgroups([])
os.setgid(65533)
os.setuid(65533)
control.send(b"R")
control.close()
while True:
    try:
        os.waitpid(-1, 0)
    except ChildProcessError:
        signal.pause()
    except InterruptedError:
        pass
"""


@dataclass
class _Generation:
    pid: int
    start: str
    token: str
    pidfd: int
    pid_namespace_fd: int
    mount_namespace_fd: int
    launcher: subprocess.Popen[bytes]

    def manifest(self) -> dict[str, Any]:
        return {"pid": self.pid, "start": self.start, "token": self.token}

    def close_fds(self) -> None:
        for fd in (self.pidfd, self.pid_namespace_fd, self.mount_namespace_fd):
            try:
                os.close(fd)
            except OSError:
                pass


class BoundaryHelper:
    """单个 run 的特权实现；公开 client 不需要了解这些内部资源。"""

    def __init__(
        self,
        boundary_id: str,
        state_dir: str | Path,
        workdir: str | Path,
        *,
        runner: CommandRunner | None = None,
        recover: bool = False,
    ) -> None:
        self.config = resource_config(boundary_id)
        self.state_dir = Path(state_dir)
        self.workdir = Path(workdir)
        self.manifest_path = self.state_dir / "manifest.json"
        self.runner = runner or CommandRunner()
        self.policy: _Policy | None = None
        self.generation: _Generation | None = None
        self._cleanup_result: dict[str, Any] | None = None
        self._recover = recover
        self._netns_created = False
        self._veth_created = False
        self._nft_created = False
        self._resolver_created = False
        self._resolver_dir_created = False
        if not recover:
            self._write_manifest(None)

    def _manifest_value(self, generation: dict[str, Any] | None) -> dict[str, Any]:
        return {
            "version": 1,
            "boundary_id": self.config.boundary_id,
            **self.config.manifest_names,
            "helper_pid": os.getpid(),
            "helper_start": _process_start(os.getpid()),
            "generation": generation,
        }

    def _write_manifest(self, generation: dict[str, Any] | None) -> None:
        write_manifest(self.manifest_path, self._manifest_value(generation))

    def _install_rules(self, policy: _Policy, *, replace: bool = False) -> None:
        rules = render_nft_rules(
            policy,
            table=self.config.nft_table,
            interface=self.config.host_interface,
            ipv4=self.config.ipv4,
            ipv6=self.config.ipv6,
            replace=replace,
        )
        self.runner.run(["nft", "-f", "-"], input_text=rules)

    def _delete_conntrack(self) -> None:
        for address in (self.config.ipv4, self.config.ipv6):
            result = self.runner.run(["conntrack", "-D", "-s", address], check=False)
            if result.returncode not in (0, 1):
                detail = (result.stderr or result.stdout).strip()
                raise BoundaryError(f"精确删除 conntrack 失败: {detail}")

    def _start_generation(self) -> _Generation:
        """先持有 reaper 身份与 ns FD，再降 UID 并确认 ready。"""
        token = os.urandom(16).hex()
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        argv = [
            "unshare",
            "--mount",
            "--pid",
            "--fork",
            "--kill-child=KILL",
            "--mount-proc",
            sys.executable,
            "-I",
            "-S",
            "-c",
            _REAPER,
            token,
            str(child.fileno()),
        ]
        try:
            launcher = subprocess.Popen(  # noqa: S603  # 固定 reaper argv
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=(child.fileno(),),
                start_new_session=True,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            )
        except OSError as exc:
            parent.close()
            child.close()
            raise BoundaryError(f"无法启动 PID namespace reaper: {exc}") from exc
        child.close()
        parent.settimeout(COMMAND_TIMEOUT)
        deadline = time.monotonic() + COMMAND_TIMEOUT
        owned_fds = []
        try:
            while time.monotonic() < deadline:
                found = self._find_init(token)
                if found is not None:
                    pid, start, pidfd = found
                    pidns = -1
                    try:
                        pidns = os.open(f"/proc/{pid}/ns/pid", os.O_RDONLY)
                        mntns = os.open(f"/proc/{pid}/ns/mnt", os.O_RDONLY)
                    except OSError:
                        if pidns >= 0:
                            os.close(pidns)
                        os.close(pidfd)
                        raise
                    owned_fds = [pidfd, pidns, mntns]
                    parent.send(b"R")
                    if parent.recv(1) != b"R":
                        raise BoundaryError("reaper 降权后未确认 ready")
                    owned_fds = []
                    return _Generation(pid, start, token, pidfd, pidns, mntns, launcher)
                if launcher.poll() is not None:
                    raise BoundaryError("PID namespace reaper 提前退出")
                time.sleep(0.02)
            raise BoundaryError("等待 PID namespace reaper ready 超时")
        except BaseException:
            for fd in owned_fds:
                os.close(fd)
            if launcher.poll() is None:
                launcher.kill()
            launcher.wait(timeout=COMMAND_TIMEOUT)
            raise
        finally:
            parent.close()

    def _find_init(self, token: str) -> tuple[int, str, int] | None:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            try:
                cmdline = (entry / "cmdline").read_bytes()
                if token.encode("ascii") not in cmdline:
                    continue
                status = (entry / "status").read_text(encoding="utf-8")
                nspid = next(
                    line.split()[1:]
                    for line in status.splitlines()
                    if line.startswith("NSpid:")
                )
                if not nspid or nspid[-1] != "1":
                    continue
                start = _process_start(pid)
                pidfd = os.pidfd_open(pid)
            except (FileNotFoundError, ProcessLookupError, StopIteration):
                continue
            try:
                if _process_start(pid) != start:
                    raise BoundaryError("reaper PID 启动身份发生变化")
                return pid, start, pidfd
            except BaseException:
                os.close(pidfd)
                raise
        return None

    def _signal_generation(self, generation: _Generation) -> None:
        try:
            if _process_start(generation.pid) != generation.start:
                raise BoundaryError("拒绝终止启动身份不符的 reaper")
        except FileNotFoundError:
            return
        try:
            signal.pidfd_send_signal(generation.pidfd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + COMMAND_TIMEOUT
        while time.monotonic() < deadline:
            readable, _, _ = select.select([generation.pidfd], [], [], 0.05)
            if readable:
                break
        else:
            raise BoundaryError("终止 PID namespace init 超时")

    def _stop_generation(self) -> None:
        generation = self.generation
        if generation is None:
            return
        error = None
        try:
            self._signal_generation(generation)
        except BoundaryError as exc:
            error = exc
        try:
            generation.launcher.wait(timeout=COMMAND_TIMEOUT)
        except (subprocess.SubprocessError, OSError) as exc:
            error = error or BoundaryError(f"收割 unshare wrapper 失败: {exc}")
        if error is not None:
            raise error
        generation.close_fds()
        self.generation = None
        self._write_manifest(None)

    def _generation_response(self, epoch: int) -> tuple[dict[str, Any], list[int]]:
        if self.generation is None or self.policy is None:
            raise BoundaryError("没有活动代际")
        return {
            "ok": True,
            "boundary_id": self.config.boundary_id,
            "epoch": epoch,
            "init_pid": self.generation.pid,
            "init_start": self.generation.start,
            "helper_pid": os.getpid(),
            "netns": self.config.netns,
            "scope_digest": self.policy.digest,
            "capabilities": {
                "helper": [name for name, _ in _CAPABILITIES],
                "tool": [],
                "no_new_privs": True,
            },
        }, [self.generation.pid_namespace_fd, self.generation.mount_namespace_fd]

    def create(self, policy_value: dict[str, Any]) -> tuple[dict[str, Any], list[int]]:
        if self.policy is not None:
            raise BoundaryError("boundary 已创建")
        policy = _Policy.from_payload(policy_value)
        config = self.config
        try:
            self.runner.run(["ip", "netns", "add", config.netns])
            self._netns_created = True
            self.runner.run(
                [
                    "ip",
                    "link",
                    "add",
                    config.host_interface,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    config.tool_interface,
                ]
            )
            self._veth_created = True
            self.runner.run(
                ["ip", "link", "set", config.tool_interface, "netns", config.netns]
            )
            self.runner.run(
                [
                    "ip",
                    "addr",
                    "add",
                    f"{config.host_ipv4}/30",
                    "dev",
                    config.host_interface,
                ]
            )
            self.runner.run(
                [
                    "ip",
                    "-6",
                    "addr",
                    "add",
                    f"{config.host_ipv6}/64",
                    "nodad",
                    "dev",
                    config.host_interface,
                ]
            )
            self.runner.run(["ip", "link", "set", config.host_interface, "up"])
            self.runner.run(
                [
                    "ip",
                    "-n",
                    config.netns,
                    "addr",
                    "add",
                    f"{config.ipv4}/30",
                    "dev",
                    config.tool_interface,
                ]
            )
            self.runner.run(
                [
                    "ip",
                    "-n",
                    config.netns,
                    "-6",
                    "addr",
                    "add",
                    f"{config.ipv6}/64",
                    "nodad",
                    "dev",
                    config.tool_interface,
                ]
            )
            self.runner.run(
                ["ip", "-n", config.netns, "link", "set", config.tool_interface, "up"]
            )
            self.runner.run(["ip", "-n", config.netns, "link", "set", "lo", "up"])
            self.runner.run(
                [
                    "ip",
                    "-n",
                    config.netns,
                    "route",
                    "add",
                    "default",
                    "via",
                    config.host_ipv4,
                ]
            )
            self.runner.run(
                [
                    "ip",
                    "-n",
                    config.netns,
                    "-6",
                    "route",
                    "add",
                    "default",
                    "via",
                    config.host_ipv6,
                ]
            )
            for key in ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"):
                result = self.runner.run(["sysctl", "-n", key])
                if result.stdout.strip() != "1":
                    raise BoundaryError(
                        f"宿主机未预置 {key}=1，拒绝修改全局 forwarding"
                    )
            self.runner.run(
                [
                    "ip",
                    "netns",
                    "exec",
                    config.netns,
                    "sysctl",
                    "-qw",
                    "net.ipv4.ping_group_range=0 65534",
                ]
            )
            self._write_resolver(policy)
            self._install_rules(policy)
            self._nft_created = True
            self.policy = policy
            self.generation = self._start_generation()
            self._write_manifest(self.generation.manifest())
            return self._generation_response(1)
        except BaseException:
            self.cleanup()
            raise

    def _write_resolver(self, policy: _Policy) -> None:
        directory = Path("/etc/netns") / self.config.netns
        resolver = directory / "resolv.conf"
        if not self._resolver_created:
            directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            self._resolver_dir_created = True
        nameserver = f"nameserver {policy.dns}\n" if policy.dns is not None else ""
        resolver.write_text(f"{nameserver}options ndots:0\n", encoding="utf-8")
        resolver.chmod(0o644)
        self._resolver_created = True

    def retire(self) -> dict[str, Any]:
        self._stop_generation()
        return {"ok": True}

    def apply(
        self, policy_value: dict[str, Any], epoch: int
    ) -> tuple[dict[str, Any], list[int]]:
        if self.policy is None:
            raise BoundaryError("boundary 尚未创建")
        policy = _Policy.from_payload(policy_value)
        self._stop_generation()
        try:
            self._write_resolver(policy)
            self._install_rules(policy, replace=True)
            self._delete_conntrack()
            self.generation = self._start_generation()
            self.policy = policy
            self._write_manifest(self.generation.manifest())
            return self._generation_response(epoch)
        except BaseException:
            if self.generation is not None:
                self._stop_generation()
            raise

    def _recover_generation(self) -> None:
        value = read_manifest(
            self.manifest_path, expected_boundary_id=self.config.boundary_id
        )
        generation = value["generation"]
        if generation is None:
            return
        pid = generation["pid"]
        try:
            pidfd = os.pidfd_open(pid)
        except ProcessLookupError:
            return
        try:
            if _process_start(pid) != generation["start"]:
                raise BoundaryError("recover 发现 reaper 启动身份不符")
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
            if generation["token"].encode("ascii") not in cmdline:
                raise BoundaryError("recover 发现 reaper 命令身份不符")
            owned = _Generation(
                pid, generation["start"], generation["token"], pidfd, -1, -1, None
            )
            self._signal_generation(owned)
        except FileNotFoundError:
            pass
        finally:
            os.close(pidfd)

    def cleanup(self) -> dict[str, Any]:
        if self._cleanup_result is not None:
            return dict(self._cleanup_result)
        errors = []
        remaining = []
        try:
            if self._recover:
                read_manifest(
                    self.manifest_path, expected_boundary_id=self.config.boundary_id
                )
                self._netns_created = True
                self._veth_created = True
                self._nft_created = True
                self._resolver_created = True
                self._resolver_dir_created = True
                self._recover_generation()
            else:
                self._stop_generation()
        except (BoundaryError, OSError) as exc:
            errors.append(str(exc))
        if self._nft_created:
            self._delete_conntrack_best_effort(errors)
        deletions = []
        if self._nft_created:
            deletions.append(
                (["nft", "delete", "table", "inet", self.config.nft_table], "nft")
            )
        if self._netns_created:
            deletions.append((["ip", "netns", "del", self.config.netns], "netns"))
        if self._veth_created:
            deletions.append(
                (["ip", "link", "del", self.config.host_interface], "veth")
            )
        for argv, label in deletions:
            try:
                result = self.runner.run(argv, check=False)
                if result.returncode != 0:
                    output = (result.stderr or result.stdout).lower()
                    if not self._is_absent(output):
                        errors.append(f"{label} 删除失败: {output.strip()}")
            except BoundaryError as exc:
                errors.append(str(exc))
        probes = []
        if self._nft_created:
            probes.append(
                (
                    "nft",
                    self.config.nft_table,
                    ["nft", "list", "table", "inet", self.config.nft_table],
                )
            )
        if self._veth_created:
            probes.append(
                (
                    "veth",
                    self.config.host_interface,
                    ["ip", "link", "show", self.config.host_interface],
                )
            )
        for label, resource, argv in probes:
            try:
                probe = self.runner.run(argv, check=False)
                if probe.returncode == 0:
                    remaining.append(f"{label}:{resource}")
                elif not self._is_absent((probe.stderr or probe.stdout).lower()):
                    errors.append(f"{label} 残留查询失败")
            except BoundaryError as exc:
                errors.append(str(exc))
        if self._netns_created:
            try:
                listing = self.runner.run(["ip", "netns", "list"], check=False)
                if listing.returncode != 0:
                    errors.append("无法核对 netns 残留")
                elif self.config.netns in listing.stdout.split():
                    remaining.append(f"netns:{self.config.netns}")
            except BoundaryError as exc:
                errors.append(str(exc))
        resolver = Path("/etc/netns") / self.config.netns / "resolv.conf"
        resolver_removed = not self._resolver_created
        if self._resolver_created:
            try:
                resolver.unlink(missing_ok=True)
                resolver_removed = True
            except OSError as exc:
                errors.append(f"resolver 清理失败: {exc}")
        if resolver_removed and self._resolver_dir_created:
            try:
                resolver.parent.rmdir()
            except FileNotFoundError:
                pass
            except OSError as exc:
                errors.append(f"resolver 目录清理失败: {exc}")
        result = {
            "cleanup_status": "clean" if not errors and not remaining else "failed",
            "remaining_resources": remaining,
            "errors": errors,
        }
        if result["cleanup_status"] == "clean":
            try:
                os.replace(
                    self.manifest_path, self.state_dir / _CLEANED_MANIFEST
                )
            except OSError as exc:
                result["cleanup_status"] = "failed"
                result["errors"].append(f"cleaned 标记写入失败: {exc}")
        self._cleanup_result = result
        return dict(result)

    @staticmethod
    def _is_absent(output: str) -> bool:
        return any(
            text in output
            for text in ("no such", "not found", "cannot find", "does not exist")
        )

    def _delete_conntrack_best_effort(self, errors: list[str]) -> None:
        try:
            self._delete_conntrack()
        except BoundaryError as exc:
            errors.append(str(exc))

    def handle(
        self, request: dict[str, Any], *, epoch: int = 0
    ) -> tuple[dict[str, Any], list[int]]:
        op = request["op"]
        if op == "create":
            return self.create(request["policy"])
        if op == "retire":
            return self.retire(), []
        if op == "apply":
            return self.apply(request["policy"], epoch)
        if op == "close":
            return {"ok": True, **self.cleanup()}, []
        if op == "recover":
            self._recover = True
            return {"ok": True, **self.cleanup()}, []
        return {
            "ok": True,
            "active": self.policy is not None,
            "generation": self.generation.manifest() if self.generation else None,
        }, []


def _send_message(
    connection: socket.socket, value: dict[str, Any], fds: list[int]
) -> None:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_MESSAGE_SIZE:
        raise ProtocolError("管理响应过大")
    ancillary = []
    if fds:
        values = array.array("i", fds)
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, values.tobytes())]
    connection.sendmsg([raw], ancillary)


def serve(boundary_id: str, state_dir: Path, workdir: Path, *, recover: bool) -> None:
    """单控制连接；Foam 断连 EOF 时立即进入本 helper 的清理路径。"""
    require_supported()
    for path, owner in ((state_dir, 0), (workdir, 65534)):
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != owner
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise BoundaryError(f"helper 目录所有权或权限不安全: {path}")
    security = harden_process()
    del security  # 回读验证成功才允许继续；capabilities 随 create 响应报告。
    helper = BoundaryHelper(boundary_id, state_dir, workdir, recover=recover)
    socket_path = state_dir / "control.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        socket_path.unlink(missing_ok=True)
        server.bind(str(socket_path))
        socket_path.chmod(0o600)
        server.listen(1)
        server.settimeout(COMMAND_TIMEOUT * 3)
        connection, _ = server.accept()
        with connection:
            connection.settimeout(COMMAND_TIMEOUT * 3)
            epoch = 0
            while True:
                raw = connection.recv(MAX_MESSAGE_SIZE + 1)
                if not raw:
                    break
                fds = []
                op = None
                try:
                    request = decode_request(raw)
                    op = request["op"]
                    next_epoch = epoch + 1 if op == "apply" else epoch
                    response, fds = helper.handle(request, epoch=next_epoch)
                    if op == "create":
                        epoch = 1
                    elif op == "apply":
                        epoch = next_epoch
                except (BoundaryError, OSError) as exc:
                    response = {"ok": False, "error": str(exc)}
                _send_message(connection, response, fds)
                if op in {"close", "recover"}:
                    break
    finally:
        server.close()
        helper.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--boundary-id", required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--recover", action="store_true")
    args = parser.parse_args(argv)
    serve(args.boundary_id, args.state_dir, args.workdir, recover=args.recover)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
