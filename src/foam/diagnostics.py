"""R13-A/B:doctor/status 的纯只读诊断结果、脱敏与同源渲染。"""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.metadata
import importlib.util
import json
import os
import re
import socket
import sqlite3
import ssl
import sys
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from foam import __version__
from foam.agent.toolmap import scan_tools
from foam.config import (
    dotenv_secret_values,
    inspect_config,
    sanitize_url,
)
from foam.evidence import open_index_ro
from foam.guard.network import list_stale_boundaries, probe_protected
from foam.state.heartbeat import assess_heartbeat, lock_evidence

AUDIT_TAIL_BYTES = 64 * 1024


def _generated_at() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _secret_values() -> set[str]:
    values = set()
    for key, value in os.environ.items():
        if key in ("FOAM_LLM_API_KEY", "FOAM_ANTHROPIC_API_KEY") or (
            key.startswith("FOAM_")
            and re.search("KEY|TOKEN|SECRET|PASSWORD", key)
        ):
            if value:
                values.add(value)
    values.update(dotenv_secret_values(Path.cwd() / ".env"))
    values.update(inspect_config(Path.home())["secret_values"])
    return values


def redact(text: str) -> str:
    """先替换已知秘密，再对所有 HTTP URL 做 fail-closed 脱敏。"""
    result = str(text)
    for secret in sorted(_secret_values(), key=len, reverse=True):
        result = result.replace(secret, "<已脱敏>")

    def clean_url(match: re.Match[str]) -> str:
        try:
            return sanitize_url(match.group(0))
        except ValueError:
            return "<无法解析,已脱敏>"

    return re.sub(r"https?://[^\s\"'<>]+", clean_url, result)


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {_redact_value(key): _redact_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(item) for item in value]
    return value


@dataclass(frozen=True)
class Check:
    code: str
    status: str
    message: str
    remediation: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        for item in fields(self):
            object.__setattr__(self, item.name, _redact_value(getattr(self, item.name)))

    def to_dict(self) -> dict[str, Any]:
        return _redact_value(
            {
                "code": self.code,
                "status": self.status,
                "message": self.message,
                "remediation": self.remediation,
                "details": self.details,
            }
        )


@dataclass(frozen=True)
class DoctorResult:
    checks: tuple[Check, ...]
    generated_at: str = field(default_factory=_generated_at)

    @property
    def exit_code(self) -> int:
        if any(check.status == "fail" for check in self.checks):
            return 1
        if any(check.status == "unknown" for check in self.checks):
            return 3
        return 0

    def to_dict(self) -> dict[str, Any]:
        return _redact_value(
            {
                "schema": "foam.doctor/1",
                "generated_at": self.generated_at,
                "checks": [check.to_dict() for check in self.checks],
            }
        )

    def render_human(self) -> str:
        lines = []
        for check in self.checks:
            lines.append(f"[{check.code}] {check.status}: {check.message}")
            if check.remediation:
                lines.append(f"  处置:{check.remediation}")
        return redact("\n".join(lines) + "\n")


@dataclass(frozen=True)
class StatusResult:
    root: str
    run_state: str
    liveness: str
    generated_at: str = field(default_factory=_generated_at)
    objective: str | None = None
    scope: dict[str, Any] | None = None
    created_at: str | None = None
    closed_at: str | None = None
    last_activity: dict[str, Any] | None = None
    budget: dict[str, Any] | None = None
    manifest: bool | None = None
    counts: dict[str, int | None] = field(
        default_factory=lambda: {"vulns": None, "creds": None, "loot": None}
    )
    next_action: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        for item in fields(self):
            object.__setattr__(self, item.name, _redact_value(getattr(self, item.name)))

    @property
    def exit_code(self) -> int:
        return 3 if "unknown" in (self.run_state, self.liveness) else 0

    def to_dict(self) -> dict[str, Any]:
        return _redact_value(
            {
                "schema": "foam.status/1",
                "generated_at": self.generated_at,
                "root": self.root,
                "run_state": self.run_state,
                "liveness": self.liveness,
                "objective": self.objective,
                "scope": self.scope,
                "created_at": self.created_at,
                "closed_at": self.closed_at,
                "last_activity": self.last_activity,
                "budget": self.budget,
                "manifest": self.manifest,
                "counts": self.counts,
                "next_action": self.next_action,
                "details": self.details,
            }
        )

    def render_human(self) -> str:
        lines = [
            f"engagement:{self.root}",
            f"运行结局:{self.run_state}",
            f"活性:{self.liveness}",
            f"目标:{self.objective or '(未知)'}",
        ]
        if self.scope:
            lines.append(
                f"scope:{self.scope.get('source') or '(未知)'}"
                f" sha256:{self.scope.get('sha256') or '(未知)'}"
            )
        else:
            lines.append("scope:(未知)")
        lines.extend(
            [
                f"创建时间:{self.created_at or '(未知)'}",
                f"结项时间:{self.closed_at or '(未结项)'}",
            ]
        )
        if self.last_activity:
            lines.append(
                f"最近活动:{self.last_activity.get('at') or '(未知)'}"
                f"({self.last_activity.get('source')}/"
                f"{self.last_activity.get('kind')})"
            )
        else:
            lines.append("最近活动:(未知)")
        if self.budget is not None:
            rendered_budget = json.dumps(
                self.budget, ensure_ascii=False, sort_keys=True
            )
            lines.append("预算 closing:" + rendered_budget)
        manifest = {True: "存在", False: "不存在"}.get(self.manifest, "unknown")
        lines.append(f"manifest:{manifest}")
        rendered_counts = []
        for name in ("vulns", "creds", "loot"):
            value = self.counts.get(name)
            rendered_counts.append(str(value) if value is not None else "unknown")
        lines.append("发现/凭证/loot:" + "/".join(rendered_counts))
        lines.append(f"下一步:{self.next_action}")
        lines.append("提示:status 不校验审计链完整性;请用 foam verify 核验")
        return redact("\n".join(lines) + "\n")


def _version_checks() -> tuple[Check, ...]:
    python_status = "pass" if sys.version_info >= (3, 12) else "fail"
    python_check = Check(
        code="python.version",
        status=python_status,
        message=(
            f"Python {sys.version.split()[0]}({sys.executable})"
            + ("满足 >=3.12" if python_status == "pass" else "低于 >=3.12")
        ),
        remediation="" if python_status == "pass" else "安装 Python 3.12 或更新版本",
        details={"version": sys.version.split()[0], "executable": sys.executable},
    )
    try:
        distribution = importlib.metadata.version("foam")
    except importlib.metadata.PackageNotFoundError:
        distribution = None
    foam_check = Check(
        code="foam.version",
        status="pass",
        message=(
            f"Foam {__version__};"
            + (
                f"分发元数据 {distribution}"
                if distribution
                else "无分发元数据(源码运行)"
            )
        ),
        details={
            "version": __version__,
            "distribution_version": distribution,
            "package": str(Path(__file__).parent),
        },
    )
    dependencies = []
    for name in ("httpx", "rich", "textual"):
        present = importlib.util.find_spec(name) is not None
        if present:
            try:
                version = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                version = "元数据不可用"
            dependencies.append(
                Check(
                    code=f"deps.{name}",
                    status="pass",
                    message=f"{name} 已定位;版本 {version}",
                    details={"version": version},
                )
            )
        else:
            note = ";仅影响 TUI" if name == "textual" else ""
            dependencies.append(
                Check(
                    code=f"deps.{name}",
                    status="fail",
                    message=f"依赖 {name} 缺失{note}",
                    remediation="按项目支持的安装方式安装缺失依赖后重试",
                )
            )
    return (python_check, foam_check, *dependencies)


def _config_and_backend_checks(
    args: argparse.Namespace, dotenv
) -> tuple[list[Check], Any]:
    from foam.cli import resolve_backend_values

    injected, warnings = dotenv
    dotenv_path = Path.cwd() / ".env"
    dotenv_exists = dotenv_path.is_file()
    dotenv_check = Check(
        code="config.dotenv",
        status="warn" if warnings else "pass",
        message=(
            f"{dotenv_path} 不存在,未注入"
            if not dotenv_exists
            else f"只读注入键:{', '.join(injected) or '(无新键)'}"
            + (f";畸形:{';'.join(warnings)}" if warnings else "")
        ),
        details={"injected": injected, "warnings": warnings},
    )

    config = inspect_config(Path.home())
    if not config["exists"]:
        config_check = Check(
            code="config.file",
            status="pass",
            message=f"{config['path']} 不存在(未配置)",
        )
    elif config["error"]:
        config_check = Check(
            code="config.file",
            status="fail",
            message=(
                f"{config['path']} {config['error']};当前被静默忽略,profile 不生效"
            ),
            remediation="备份后修复为合法 JSON 对象,再重跑 doctor",
        )
    else:
        problems = []
        remedies = []
        if config["mode"] != 0o600:
            problems.append(f"权限为 {config['mode']:03o},应为 0600")
            remedies.append("确认属主后执行 chmod 600")
        if config["suspicious_keys"]:
            problems.append(
                "含敏感字段 " + ", ".join(config["suspicious_keys"]) + ";会被白名单丢弃"
            )
            remedies.append("手工删除这些字段,密钥只走环境变量")
        config_check = Check(
            code="config.file",
            status="warn" if problems else "pass",
            message=(
                f"{config['path']} "
                + (";".join(problems) if problems else "合法且权限适当")
            ),
            remediation=";".join(remedies),
            details={
                "path": config["path"],
                "mode": config["mode"],
                "suspicious_keys": config["suspicious_keys"],
            },
        )

    resolution = resolve_backend_values(args)
    if resolution.missing_profile:
        profile_check = Check(
            code="config.profile",
            status="fail",
            message=f"profile '{resolution.profile_name}' 不存在或为空",
            remediation="修正 active_profile 或用 --profile 选择已保存 profile",
        )
    elif resolution.invalid_backend is not None:
        profile_check = Check(
            code="config.profile",
            status="fail",
            message=(
                f"profile '{resolution.profile_name}' 的 backend 非法:"
                f"{resolution.invalid_backend}"
            ),
            remediation="将 backend 改为 openai_compat 或 claude",
        )
    else:
        profile_check = Check(
            code="config.profile",
            status="pass",
            message=(
                f"profile '{resolution.profile_name}' 有效"
                if resolution.profile is not None
                else "未指定有效 profile,使用其余解析链"
            ),
        )

    effective_base_url = resolution.effective_base_url
    if effective_base_url:
        try:
            shown_base_url = sanitize_url(effective_base_url)
        except ValueError:
            shown_base_url = "<无法解析,已脱敏>"
    else:
        shown_base_url = None
    backend_check = Check(
        code="backend.resolved",
        status=(
            "fail"
            if resolution.backend == "openai_compat" and not effective_base_url
            else "pass"
        ),
        message=(
            f"backend={resolution.backend} model={resolution.model} "
            f"base_url={shown_base_url}"
            + (
                ";openai_compat 缺 base_url"
                if resolution.backend == "openai_compat" and not effective_base_url
                else ""
            )
        ),
        remediation=(
            "通过 --base-url 或 FOAM_LLM_BASE_URL 设置 base_url"
            if resolution.backend == "openai_compat" and not effective_base_url
            else ""
        ),
        details={
            "backend": resolution.backend,
            "model": resolution.model,
            "base_url": shown_base_url,
            "sources": resolution.sources,
            "profile": resolution.profile_name,
        },
    )
    key_name = (
        "FOAM_ANTHROPIC_API_KEY"
        if resolution.backend == "claude"
        else "FOAM_LLM_API_KEY"
    )
    key_set = bool(os.environ.get(key_name))
    key_check = Check(
        code="backend.api_key",
        status="pass" if key_set else "fail",
        message=f"{key_name} {'已设置' if key_set else '未设置'}",
        remediation="" if key_set else f"在环境中设置 {key_name} 后重试;不得写入配置",
        details={"env": key_name, "set": key_set},
    )
    return (
        [dotenv_check, config_check, profile_check, backend_check, key_check],
        resolution,
    )


def _tools_check() -> Check:
    try:
        scan = scan_tools()
        counts = scan.counts()
    except Exception as exc:
        return Check(
            code="tools.inventory",
            status="unknown",
            message=f"工具盘点失败:{exc}",
            remediation="检查本机 PATH/dpkg 查询后重试;不会自动安装",
        )
    return Check(
        code="tools.inventory",
        status="pass",
        message=(
            f"工具 {counts['available']}/{counts['total']} 可用,"
            f"缺失 {counts['missing']};dpkg={scan.dpkg_available}"
        ),
        details={**counts, "dpkg_available": scan.dpkg_available},
    )


def _workdir_check(path: Path) -> Check:
    probe = path
    try:
        while not probe.exists() and probe.parent != probe:
            probe = probe.parent
        info = probe.stat()
        writable = os.access(probe, os.W_OK)
    except OSError as exc:
        return Check(
            code="workdir.engagements",
            status="unknown",
            message=f"无法读取 {probe}:{exc}",
            remediation="检查目录权限与属主;doctor 不会创建目录",
        )
    return Check(
        code="workdir.engagements",
        status="pass" if writable else "fail",
        message=(
            f"目标 {path} "
            + ("已存在" if path.exists() else f"不存在;检查既有父目录 {probe}")
            + f";可写={writable}"
        ),
        remediation=(
            "" if writable else "调整 workdir 到当前用户可写目录;不要写探针文件"
        ),
        details={
            "path": str(path),
            "probe": str(probe),
            "exists": path.exists(),
            "writable": writable,
            "uid": info.st_uid,
            "mode": f"{info.st_mode & 0o777:03o}",
        },
    )


def _protected_check() -> Check:
    probe = probe_protected()
    if probe["available"]:
        return Check(
            code="exec.protected", status="pass", message="protected 前置条件满足"
        )
    return Check(
        code="exec.protected",
        status="warn",
        message=f"protected 不可用:{probe['reason']};仅 legacy 可用",
        remediation=(
            "按 R29-A 使用 root /opt/foam venv 安装发布 wheel,并经 sudo 白名单启动;"
            "不自动 sudo、不放宽权限"
        ),
        details=probe,
    )


def _stale_check() -> Check:
    if sys.platform != "linux":
        return Check(
            code="exec.stale_boundaries",
            status="skip",
            message="非 Linux,无 /run/foam/network 残留目录检查",
        )
    try:
        boundaries = list_stale_boundaries()
    except OSError as exc:
        return Check(
            code="exec.stale_boundaries",
            status="unknown",
            message=f"残留边界目录不可读:{exc}",
            remediation="以运行 protected 的 root 用户重试;不会自动 recover",
        )
    return Check(
        code="exec.stale_boundaries",
        status="warn" if boundaries else "pass",
        message=(
            f"发现 {len(boundaries)} 个残留边界;下一次 protected 创建会自动对账"
            if boundaries
            else "无残留边界目录"
        ),
        details={"count": len(boundaries), "boundaries": boundaries},
    )


def _online_check(base_url: str | None) -> Check:
    if not base_url:
        return Check(
            code="online.base_url",
            status="fail",
            message="online 探测缺少生效 base_url",
            remediation="先通过 --base-url 或 profile 设置 base_url",
        )
    host = None
    try:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("base_url 必须是含 host 的 http/https URL")
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            addresses = executor.submit(
                socket.getaddrinfo, host, port, type=socket.SOCK_STREAM
            ).result(timeout=5)
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        family, socktype, proto, _canonname, address = addresses[0]
        connection = socket.socket(family, socktype, proto)
        try:
            connection.settimeout(5)
            connection.connect(address)
            if parts.scheme == "https":
                connection = ssl.create_default_context().wrap_socket(
                    connection, server_hostname=host
                )
                connection.settimeout(5)
                connection.do_handshake()
        finally:
            connection.close()
        steps = "DNS/TCP/TLS" if parts.scheme == "https" else "DNS/TCP"
        return Check(
            code="online.base_url",
            status="pass",
            message=f"{steps} 成功;未发送 HTTP 请求、未携带密钥",
            details={"base_url": sanitize_url(base_url), "steps": steps},
        )
    except Exception as exc:
        return Check(
            code="online.base_url",
            status="fail",
            message=f"online DNS/TCP/TLS 探测失败:{exc}",
            remediation="检查 DNS、网络路由、对端端口与 TLS 配置后重试",
            details={"host": host},
        )


def collect_doctor(
    args: argparse.Namespace | None = None, *, dotenv=None
) -> DoctorResult:
    args = args or argparse.Namespace(
        backend=None, model=None, base_url=None, profile=None, workdir=None
    )
    config_backend, resolution = _config_and_backend_checks(args, dotenv or ([], []))
    online = (
        _online_check(resolution.effective_base_url)
        if getattr(args, "online", False)
        else Check(
            code="online.base_url",
            status="skip",
            message="未指定 --online;默认零网络",
        )
    )
    checks = (
        *_version_checks(),
        *config_backend,
        _tools_check(),
        _workdir_check(Path(args.workdir or "engagements")),
        _protected_check(),
        _stale_check(),
        online,
    )
    return DoctorResult(checks=checks)


def _read_meta(path: Path) -> tuple[dict[str, Any], str | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {}, str(exc)
    if not isinstance(value, dict):
        return {}, "engagement.json 顶层不是对象"
    return value, None


def _read_audit_tail(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    try:
        if not path.is_file():
            return [], None
        with path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            offset = max(0, size - AUDIT_TAIL_BYTES)
            fh.seek(offset)
            data = fh.read(AUDIT_TAIL_BYTES)
    except OSError as exc:
        return [], str(exc)
    lines = data.decode("utf-8", errors="replace").splitlines()
    if offset:
        lines = lines[1:]
    records = []
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            return records, f"链尾 JSON 解析失败:{exc}"
        if isinstance(record, dict):
            records.append(record)
    return records, None


def _index_counts(root: Path) -> dict[str, int | None]:
    counts: dict[str, int | None] = {"vulns": None, "creds": None, "loot": None}
    try:
        conn = open_index_ro(root / "index.sqlite")
    except OSError:
        return counts
    if conn is None:
        return counts
    try:
        for table in counts:
            try:
                row = conn.execute(
                    f"SELECT COUNT(*) FROM {table}"  # noqa: S608
                ).fetchone()
                counts[table] = row[0]
            except sqlite3.Error:
                counts[table] = None
    finally:
        conn.close()
    return counts


def _manifest_exists(root: Path) -> bool | None:
    try:
        return any((root / "evidence").glob("manifest-*.json"))
    except OSError:
        return None


def _run_state(
    meta: dict[str, Any],
    meta_error: str | None,
    records: list[dict[str, Any]],
    tail_error: str | None,
    liveness: str,
) -> str:
    if meta_error is not None:
        return "unknown"
    status = meta.get("status")
    if status == "closed":
        return "closed"
    if status != "active" or tail_error is not None:
        return "unknown"
    terminal = next(
        (
            record
            for record in reversed(records)
            if record.get("kind") == "run_finished"
        ),
        None,
    )
    if terminal is not None:
        terminal_status = (terminal.get("payload") or {}).get("status")
        if terminal_status == "stopped":
            return "stopped"
        if terminal_status in ("killed", "error"):
            return "interrupted"
        return "unknown"
    if liveness == "alive":
        return "active"
    return "unknown" if liveness == "unknown" else "interrupted"


def _next_action(root: Path, run_state: str) -> str:
    if run_state == "closed":
        return f"已结项;可用 foam verify {root} 核验证据"
    if run_state == "stopped":
        return f"用 foam resume {root} 显式扩容恢复;先用 foam verify {root} 核验"
    if run_state == "interrupted":
        return f"可用 foam resume {root} 恢复;先用 foam verify {root} 核验"
    return f"检查 engagement.json/链尾;可用 foam verify {root} 进一步核验"


def _activity_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def _latest_activity(records: list[dict[str, Any]], heartbeat: dict | None):
    activity = None
    if records:
        last = records[-1]
        activity = {
            "at": last.get("ts"),
            "source": "audit",
            "kind": last.get("kind"),
        }
    if heartbeat:
        candidate = heartbeat.get("last_activity")
        if isinstance(candidate, dict) and candidate.get("at"):
            current_time = _activity_datetime((activity or {}).get("at"))
            candidate_time = _activity_datetime(candidate.get("at"))
            if activity is None or (
                current_time is not None
                and candidate_time is not None
                and candidate_time > current_time
            ):
                activity = {
                    "at": candidate.get("at"),
                    "source": "heartbeat",
                    "kind": candidate.get("kind"),
                }
    return activity


def collect_status(root: str | Path) -> StatusResult:
    root = Path(root)
    meta, meta_error = _read_meta(root / "engagement.json")
    records, tail_error = _read_audit_tail(root / "audit.jsonl")
    assessment = assess_heartbeat(root)
    liveness = assessment["liveness"]
    run_state = _run_state(meta, meta_error, records, tail_error, liveness)
    terminal = next(
        (
            record
            for record in reversed(records)
            if record.get("kind") == "run_finished"
        ),
        None,
    )
    last_activity = _latest_activity(records, assessment["heartbeat"])
    scope = None
    scope_meta = meta.get("scope")
    if isinstance(scope_meta, dict):
        sha256 = scope_meta.get("sha256")
        scope = {
            "source": scope_meta.get("path"),
            "sha256": str(sha256)[:12] if sha256 else None,
        }
    budget = None
    if terminal is not None:
        candidate = (terminal.get("payload") or {}).get("budget")
        if isinstance(candidate, dict):
            budget = candidate
    objective = meta.get("objective")
    created_at = meta.get("created_at")
    closed_at = meta.get("closed_at")
    return StatusResult(
        root=str(root),
        run_state=run_state,
        liveness=liveness,
        objective=objective if isinstance(objective, str) else None,
        scope=scope,
        created_at=created_at if isinstance(created_at, str) else None,
        closed_at=closed_at if isinstance(closed_at, str) else None,
        last_activity=last_activity,
        budget=budget,
        manifest=_manifest_exists(root),
        counts=_index_counts(root),
        next_action=_next_action(root, run_state),
        details={
            "identity_method": assessment["identity_method"],
            "identity_note": assessment["identity_note"],
            "lock": lock_evidence(root),
        },
    )
