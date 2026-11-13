"""R11 per-run netns+nftables 边界的深而窄 client 接口。

调用方只提供已确认 Scope 和显式 DNS；创建前先对账崩溃残留，helper 启动、
权限回读、代际 FD、规则更新与清理均封装在本模块。protected 失败不回退。
"""

from __future__ import annotations

import array
import ipaddress
import json
import os
import shutil
import socket
import stat
import subprocess  # noqa: S403  # 仅启动受信绝对路径 helper
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from foam.guard import network_helper
from foam.guard.network_helper import (
    MAX_MESSAGE_SIZE,
    BoundaryError,
    ExecutionUnsupportedError,
)
from foam.state.heartbeat import process_is_active

__all__ = [
    "BoundaryError",
    "ExecutionUnsupportedError",
    "NetworkBoundary",
    "NetworkPolicy",
    "list_stale_boundaries",
    "probe_protected",
    "recover_stale",
]


@dataclass(frozen=True)
class NetworkPolicy:
    """网络层可精确强制的授权子集；空 CIDR 合法且拒绝全部目标。"""

    cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    dns: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    digest: str = ""

    @classmethod
    def from_scope(
        cls,
        scope: Any,
        *,
        dns: str | None = None,
        digest: str = "",
    ) -> NetworkPolicy:
        if scope.hosts or scope.wildcards or scope.url_prefixes:
            raise BoundaryError("protected 网络边界仅支持 CIDR；混合 scope 整体拒绝")
        if not isinstance(digest, str):
            raise BoundaryError("scope digest 必须是字符串")
        address = None
        if dns is not None:
            try:
                address = ipaddress.ip_address(dns)
            except ValueError as exc:
                raise BoundaryError("DNS 必须是显式 IP 地址") from exc
            if not any(address in network for network in scope.cidrs):
                raise BoundaryError("DNS 必须落在某个授权 CIDR 内")
        return cls(tuple(scope.cidrs), address, digest)

    def as_payload(self) -> dict[str, Any]:
        return {
            "cidrs": [str(network) for network in self.cidrs],
            "dns": str(self.dns) if self.dns is not None else None,
            "digest": self.digest,
        }


def _require_supported() -> None:
    network_helper.require_supported()


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
    ):
        raise BoundaryError(f"边界目录所有权或类型不安全: {path}")
    path.chmod(0o700)


def _private_workdir(path: Path) -> None:
    _private_directory(path)
    os.chown(path, 65534, 65534)


def _trusted_source(path: Path) -> Path:
    if not path.is_absolute():
        raise ExecutionUnsupportedError("helper 与 Python 必须使用绝对路径")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ExecutionUnsupportedError(f"受信启动路径不存在: {path}") from exc
    current = resolved
    while True:
        info = current.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ExecutionUnsupportedError(f"helper 启动路径不可信: {current}")
        if current.parent == current:
            break
        current = current.parent
    return resolved


def probe_protected() -> dict[str, Any]:
    """只读复用 protected 支持性与受信启动路径判据，不创建边界。"""
    try:
        network_helper.require_supported()
        _trusted_source(Path(sys.executable))
        _trusted_source(Path(network_helper.__file__).resolve())
    except (ExecutionUnsupportedError, OSError) as exc:
        return {"available": False, "reason": str(exc)}
    return {"available": True, "reason": ""}


class _HelperTransport:
    """受信解释器/源码、最小 env 与带 FD 的有界 SOCK_SEQPACKET 连接。"""

    def __init__(
        self,
        boundary_id: str,
        state_dir: Path,
        workdir: Path,
        *,
        recover: bool = False,
    ) -> None:
        _require_supported()
        self.boundary_id = boundary_id
        self.state_dir = state_dir
        self.workdir = workdir
        self._closed = False
        python = _trusted_source(Path(sys.executable))
        source = _trusted_source(Path(network_helper.__file__).resolve())
        argv = [
            str(python),
            "-I",
            "-S",
            str(source),
            "--boundary-id",
            boundary_id,
            "--state-dir",
            str(state_dir),
            "--workdir",
            str(workdir),
        ]
        if recover:
            argv.append("--recover")
        try:
            self._process = subprocess.Popen(  # noqa: S603  # 固定受信 helper argv
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
                env={
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                },
            )
        except OSError as exc:
            raise BoundaryError(f"无法启动限权 helper: {exc}") from exc
        try:
            self._socket = self._connect(state_dir / "control.sock")
        except BaseException:
            if self._process.poll() is None:
                self._process.terminate()
            try:
                self._process.wait(timeout=network_helper.COMMAND_TIMEOUT)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=network_helper.COMMAND_TIMEOUT)
            raise

    def _connect(self, path: Path) -> socket.socket:
        deadline = time.monotonic() + network_helper.COMMAND_TIMEOUT
        last_error: OSError | None = None
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                raise BoundaryError("helper 在权限收缩或监听前退出")
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            connection.settimeout(network_helper.COMMAND_TIMEOUT * 3)
            try:
                connection.connect(str(path))
                return connection
            except (FileNotFoundError, ConnectionRefusedError) as exc:
                last_error = exc
                connection.close()
                time.sleep(0.02)
            except OSError:
                connection.close()
                raise
        raise BoundaryError(f"连接受限 helper 超时: {last_error}")

    def request(
        self, payload: dict[str, Any], *, fd_count: int = 0
    ) -> tuple[dict[str, Any], list[int]]:
        if self._closed:
            raise BoundaryError("helper 控制连接已关闭")
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(raw) > MAX_MESSAGE_SIZE:
            raise BoundaryError("管理请求过大")
        try:
            self._socket.send(raw)
            data, ancillary, flags, _ = self._socket.recvmsg(
                MAX_MESSAGE_SIZE + 1,
                socket.CMSG_SPACE(max(1, fd_count) * array.array("i").itemsize),
            )
        except (OSError, TimeoutError) as exc:
            raise BoundaryError(f"helper 管理调用失败或超时: {exc}") from exc
        if (
            flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or len(data) > MAX_MESSAGE_SIZE
        ):
            raise BoundaryError("helper 响应或 FD 被截断")
        fds = []
        try:
            for level, kind, value in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    received = array.array("i")
                    received.frombytes(
                        value[: len(value) - (len(value) % received.itemsize)]
                    )
                    fds.extend(received)
            try:
                response = json.loads(data)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BoundaryError("helper 返回非法 JSON") from exc
            if not isinstance(response, dict) or not isinstance(
                response.get("ok"), bool
            ):
                raise BoundaryError("helper 响应形态非法")
            if not response["ok"]:
                raise BoundaryError(str(response.get("error", "helper 管理调用失败")))
            if len(fds) != fd_count:
                raise BoundaryError("helper 返回的 namespace FD 数量不符")
            return response, fds
        except BaseException:
            for fd in fds:
                os.close(fd)
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._socket.close()
        finally:
            try:
                self._process.wait(timeout=network_helper.COMMAND_TIMEOUT)
            except subprocess.TimeoutExpired:
                self._process.terminate()
                try:
                    self._process.wait(timeout=network_helper.COMMAND_TIMEOUT)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=network_helper.COMMAND_TIMEOUT)


@dataclass
class _ClientGeneration:
    init_pid: int
    init_start: str
    pid_namespace_fd: int
    mount_namespace_fd: int

    def close(self) -> None:
        for fd in (self.pid_namespace_fd, self.mount_namespace_fd):
            try:
                os.close(fd)
            except OSError:
                pass


class NetworkBoundary:
    """一个 run 的网络与代际所有权；所有管理操作同步且有超时。"""

    def __init__(
        self,
        *,
        boundary_id: str,
        transport: Any,
        workdir: Path,
        policy: NetworkPolicy,
        response: dict[str, Any],
        generation: _ClientGeneration,
    ) -> None:
        self.boundary_id = boundary_id
        self._transport = transport
        self._state_dir = Path(transport.state_dir)
        self.workdir = workdir
        self._policy = policy
        self.epoch = self._response_epoch(response)
        self.helper_pid = self._positive_int(response, "helper_pid")
        self._netns = str(response["netns"])
        self._capabilities = dict(response["capabilities"])
        self._generation: _ClientGeneration | None = generation
        self._failed = False
        self._closed_result: dict[str, Any] | None = None

    @staticmethod
    def _positive_int(response: dict[str, Any], key: str) -> int:
        value = response.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise BoundaryError(f"helper 响应 {key} 非法")
        return value

    @staticmethod
    def _response_epoch(response: dict[str, Any]) -> int:
        value = response.get("epoch")
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise BoundaryError("helper 响应 epoch 非法")
        return value

    @classmethod
    def create(
        cls,
        scope: Any,
        *,
        dns: str | None = None,
        digest: str = "",
        state_root: str | Path | None = None,
        work_root: str | Path | None = None,
    ) -> NetworkBoundary:
        policy = NetworkPolicy.from_scope(scope, dns=dns, digest=digest)
        _require_supported()
        boundary_id = f"fb{uuid.uuid4().hex[:12]}"
        state_base = Path(state_root or "/run/foam/network")
        work_base = Path(work_root or "/run/foam/tool-work")
        state_dir = state_base / boundary_id
        workdir = work_base / boundary_id
        try:
            recovered = recover_stale(state_root=state_base, work_root=work_base)
        except OSError as exc:
            raise BoundaryError(f"历史 boundary 对账失败: {exc}") from exc
        failed = [item for item in recovered if item["cleanup_status"] != "clean"]
        if failed:
            raise BoundaryError(f"历史 boundary 恢复未完成，拒绝新 run: {failed}")
        transport = None
        generation = None
        fds = []
        try:
            _private_directory(state_base)
            _private_directory(work_base)
            _private_directory(state_dir)
            _private_workdir(workdir)
            transport = _HelperTransport(boundary_id, state_dir, workdir)
            response, fds = transport.request(
                {"op": "create", "policy": policy.as_payload()}, fd_count=2
            )
            if response.get("boundary_id") != boundary_id:
                raise BoundaryError("helper 返回了错误的 boundary 身份")
            if response.get("scope_digest") != policy.digest:
                raise BoundaryError("helper 返回了错误的 scope digest")
            generation = _ClientGeneration(
                init_pid=cls._positive_int(response, "init_pid"),
                init_start=str(response["init_start"]),
                pid_namespace_fd=fds[0],
                mount_namespace_fd=fds[1],
            )
            fds = []
            return cls(
                boundary_id=boundary_id,
                transport=transport,
                workdir=workdir,
                policy=policy,
                response=response,
                generation=generation,
            )
        except BaseException as exc:
            for fd in fds:
                os.close(fd)
            if generation is not None:
                generation.close()
            if transport is not None:
                transport.close()
            cleanup_errors = []
            for path in (workdir, state_dir):
                try:
                    if path == workdir:
                        shutil.rmtree(path)
                    else:
                        (path / "control.sock").unlink(missing_ok=True)
                        (
                            path / network_helper._CLEANED_MANIFEST
                        ).unlink(missing_ok=True)
                        path.rmdir()
                except FileNotFoundError:
                    pass
                except OSError as cleanup_exc:
                    cleanup_errors.append(f"{path}: {cleanup_exc}")
            if cleanup_errors:
                raise BoundaryError(
                    f"{exc}; 创建失败后的目录清理失败: {'; '.join(cleanup_errors)}"
                ) from exc
            if isinstance(exc, PermissionError):
                raise ExecutionUnsupportedError(
                    f"protected 权限不足，无法准备执行目录: {exc}"
                ) from exc
            if isinstance(exc, OSError):
                raise BoundaryError(f"protected 目录准备失败: {exc}") from exc
            raise

    def _active_generation(self) -> _ClientGeneration:
        if self._failed:
            raise BoundaryError("边界此前操作失败，已停止新工具派发")
        if self._closed_result is not None:
            raise BoundaryError("边界已关闭")
        if self._generation is None:
            raise BoundaryError("没有活动代际")
        return self._generation

    @property
    def init_pid(self) -> int:
        return self._active_generation().init_pid

    @property
    def pid_namespace_fd(self) -> int:
        return self._active_generation().pid_namespace_fd

    @property
    def mount_namespace_fd(self) -> int:
        return self._active_generation().mount_namespace_fd

    def capabilities(self) -> dict[str, Any]:
        return dict(self._capabilities)

    def tool_argv(self, argv: list[str]) -> list[str]:
        generation = self._active_generation()
        if not argv or not all(isinstance(item, str) for item in argv):
            raise BoundaryError("工具 argv 必须是非空字符串数组")
        return [
            "nsenter",
            f"--mount=/proc/self/fd/{generation.mount_namespace_fd}",
            f"--pid=/proc/self/fd/{generation.pid_namespace_fd}",
            "ip",
            "netns",
            "exec",
            self._netns,
            "setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
            *argv,
        ]

    def spawn_kwargs(self) -> dict[str, Any]:
        generation = self._active_generation()
        return {
            "pass_fds": (
                generation.pid_namespace_fd,
                generation.mount_namespace_fd,
            ),
            "cwd": str(self.workdir),
        }

    def tool_env(self, term: str | None = None) -> dict[str, str]:
        env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.workdir),
            "TMPDIR": str(self.workdir),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "USER": "nobody",
            "LOGNAME": "nobody",
        }
        if term is not None:
            env["TERM"] = term
        return env

    def retire_generation(self) -> None:
        self._active_generation()
        try:
            self._transport.request({"op": "retire"})
        except BaseException:
            self._failed = True
            raise
        generation = self._generation
        self._generation = None
        if generation is not None:
            generation.close()

    def apply_scope(
        self, scope: Any, *, dns: str | None = None, digest: str = ""
    ) -> None:
        if self._failed or self._closed_result is not None:
            raise BoundaryError("边界已失败或关闭，拒绝恢复旧执行")
        generation = None
        fds = []
        try:
            policy = NetworkPolicy.from_scope(scope, dns=dns, digest=digest)
            response, fds = self._transport.request(
                {"op": "apply", "policy": policy.as_payload()}, fd_count=2
            )
            epoch = self._response_epoch(response)
            if (
                epoch != self.epoch + 1
                or response.get("boundary_id") != self.boundary_id
            ):
                raise BoundaryError("helper apply 返回了错误的代际或 boundary 身份")
            if response.get("scope_digest") != policy.digest:
                raise BoundaryError("helper apply 返回了错误的 scope digest")
            generation = _ClientGeneration(
                init_pid=self._positive_int(response, "init_pid"),
                init_start=str(response["init_start"]),
                pid_namespace_fd=fds[0],
                mount_namespace_fd=fds[1],
            )
            fds = []
            helper_pid = self._positive_int(response, "helper_pid")
            capabilities = dict(response["capabilities"])
        except BaseException:
            for fd in fds:
                os.close(fd)
            if generation is not None:
                generation.close()
            self._failed = True
            raise
        old = self._generation
        self._generation = generation
        self._policy = policy
        self.epoch = epoch
        self.helper_pid = helper_pid
        self._capabilities = capabilities
        if old is not None:
            old.close()

    def aclose(self) -> dict[str, Any]:
        """同步幂等清理；失败与残留显式返回，绝不伪报 clean。"""
        if self._closed_result is not None:
            return dict(self._closed_result)
        errors = []
        try:
            response, _ = self._transport.request({"op": "close"})
            result = {
                "cleanup_status": response.get("cleanup_status", "unknown"),
                "remaining_resources": list(response.get("remaining_resources", [])),
                "errors": list(response.get("errors", [])),
            }
        except (BoundaryError, OSError) as exc:
            errors.append(str(exc))
            result = {
                "cleanup_status": "unknown",
                "remaining_resources": [],
                "errors": errors,
            }
        try:
            self._transport.close()
        except (BoundaryError, OSError, subprocess.SubprocessError) as exc:
            result["cleanup_status"] = "failed"
            result["errors"].append(str(exc))
        if self._generation is not None:
            self._generation.close()
            self._generation = None
        if result["cleanup_status"] == "clean":
            for path in (self.workdir, self._state_dir):
                try:
                    if path == self.workdir:
                        shutil.rmtree(path)
                    else:
                        (path / "control.sock").unlink(missing_ok=True)
                        (
                            path / network_helper._CLEANED_MANIFEST
                        ).unlink(missing_ok=True)
                        path.rmdir()
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    result["errors"].append(f"目录清理失败 {path}: {exc}")
                if path.exists():
                    result["remaining_resources"].append(f"directory:{path}")
            if result["errors"] or result["remaining_resources"]:
                result["cleanup_status"] = "failed"
        self._closed_result = result
        return dict(result)


def _process_is_active(pid: int, start: str) -> bool:
    return process_is_active(pid, start)


def _remove_recovered_directories(state_dir: Path, workdir: Path) -> None:
    info = state_dir.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise BoundaryError("恢复目录所有权或权限不安全")
    try:
        work_info = workdir.lstat()
    except FileNotFoundError:
        work_info = None
    if work_info is not None:
        if (
            not stat.S_ISDIR(work_info.st_mode)
            or stat.S_ISLNK(work_info.st_mode)
            or work_info.st_uid != 65534
            or stat.S_IMODE(work_info.st_mode) != 0o700
        ):
            raise BoundaryError("工具工作目录所有权或权限不安全")
        shutil.rmtree(workdir)
    (state_dir / "control.sock").unlink(missing_ok=True)
    (state_dir / network_helper._CLEANED_MANIFEST).unlink(missing_ok=True)
    state_dir.rmdir()


def list_stale_boundaries(*, state_root: str | Path | None = None) -> list[str]:
    """只读列举边界目录；不读取 manifest、不清理、不调用 recover_stale。"""
    root = Path(state_root or "/run/foam/network")
    if not root.exists():
        return []
    return [
        path.name
        for path in sorted(root.iterdir())
        if path.is_dir() and network_helper._BOUNDARY_RE.fullmatch(path.name)
    ]


def recover_stale(
    *,
    state_root: str | Path | None = None,
    work_root: str | Path | None = None,
) -> list[dict[str, Any]]:
    """按 root-owned manifest/cleaned 标记对账；不承诺死亡后即时清理。"""
    _require_supported()
    root = Path(state_root or "/run/foam/network")
    work_base = Path(work_root or "/run/foam/tool-work")
    if not root.exists():
        return []
    results = []
    for state_dir in sorted(root.iterdir()):
        if not state_dir.is_dir() or not network_helper._BOUNDARY_RE.fullmatch(
            state_dir.name
        ):
            continue
        boundary_id = state_dir.name
        workdir = work_base / boundary_id
        try:
            manifest_path = state_dir / "manifest.json"
            cleaned_path = state_dir / network_helper._CLEANED_MANIFEST
            has_manifest = manifest_path.exists()
            has_cleaned = cleaned_path.exists()
            if has_manifest == has_cleaned:
                raise BoundaryError("manifest/cleaned 状态不明，拒绝 recover")
            identity_path = cleaned_path if has_cleaned else manifest_path
            manifest = network_helper.read_manifest(
                identity_path, expected_boundary_id=boundary_id
            )
            if _process_is_active(manifest["helper_pid"], manifest["helper_start"]):
                raise BoundaryError("manifest 对应 helper 仍存活，拒绝并发 recover")
            if has_cleaned:
                result = {
                    "boundary_id": boundary_id,
                    "cleanup_status": "clean",
                    "remaining_resources": [],
                    "errors": [],
                }
            else:
                transport = _HelperTransport(
                    boundary_id, state_dir, workdir, recover=True
                )
                try:
                    response, _ = transport.request({"op": "recover"})
                    result = {
                        "boundary_id": boundary_id,
                        "cleanup_status": response.get("cleanup_status", "unknown"),
                        "remaining_resources": list(
                            response.get("remaining_resources", [])
                        ),
                        "errors": list(response.get("errors", [])),
                    }
                finally:
                    transport.close()
            if result["cleanup_status"] == "clean":
                try:
                    _remove_recovered_directories(state_dir, workdir)
                except (BoundaryError, OSError) as exc:
                    result["cleanup_status"] = "failed"
                    result["errors"].append(f"恢复目录清理失败: {exc}")
                    for path in (state_dir, workdir):
                        if path.exists():
                            result["remaining_resources"].append(f"directory:{path}")
            results.append(result)
        except (BoundaryError, OSError) as exc:
            results.append(
                {
                    "boundary_id": boundary_id,
                    "cleanup_status": "rejected",
                    "remaining_resources": [],
                    "errors": [str(exc)],
                }
            )
    return results
