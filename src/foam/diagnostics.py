"""R13-A:doctor/status 的纯只读诊断结果与同源渲染。"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from foam import __version__
from foam.evidence import open_index_ro

AUDIT_TAIL_BYTES = 64 * 1024


def _generated_at() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Check:
    code: str
    status: str
    message: str
    remediation: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "status": self.status,
            "message": self.message,
            "remediation": self.remediation,
            "details": self.details,
        }


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
        return {
            "schema": "foam.doctor/1",
            "generated_at": self.generated_at,
            "checks": [check.to_dict() for check in self.checks],
        }

    def render_human(self) -> str:
        lines = []
        for check in self.checks:
            lines.append(f"[{check.code}] {check.status}: {check.message}")
            if check.remediation:
                lines.append(f"  处置:{check.remediation}")
        return "\n".join(lines) + "\n"


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

    @property
    def exit_code(self) -> int:
        return 3 if "unknown" in (self.run_state, self.liveness) else 0

    def to_dict(self) -> dict[str, Any]:
        return {
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
        }

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
        return "\n".join(lines) + "\n"


def collect_doctor() -> DoctorResult:
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
    return DoctorResult(checks=(python_check, foam_check, *dependencies))


def _read_meta(path: Path) -> tuple[dict[str, Any], str | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {}, str(exc)
    if not isinstance(value, dict):
        return {}, "engagement.json 顶层不是对象"
    return value, None


def _read_audit_tail(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    if not path.is_file():
        return [], None
    try:
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


def _liveness_without_heartbeat_reader(root: Path) -> str:
    try:
        (root / "heartbeat.json").lstat()
    except FileNotFoundError:
        return "none"
    except OSError:
        return "unknown"
    return "unknown"


def _index_counts(root: Path) -> dict[str, int | None]:
    counts: dict[str, int | None] = {"vulns": None, "creds": None, "loot": None}
    conn = open_index_ro(root / "index.sqlite")
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
    return "interrupted" if liveness == "none" else "unknown"


def _next_action(root: Path, run_state: str) -> str:
    if run_state == "closed":
        return f"已结项;可用 foam verify {root} 核验证据"
    if run_state == "stopped":
        return f"用 foam resume {root} 显式扩容恢复;先用 foam verify {root} 核验"
    if run_state == "interrupted":
        return f"可用 foam resume {root} 恢复;先用 foam verify {root} 核验"
    return f"检查 engagement.json/链尾;可用 foam verify {root} 进一步核验"


def collect_status(root: str | Path) -> StatusResult:
    root = Path(root)
    meta, meta_error = _read_meta(root / "engagement.json")
    records, tail_error = _read_audit_tail(root / "audit.jsonl")
    liveness = _liveness_without_heartbeat_reader(root)
    run_state = _run_state(meta, meta_error, records, tail_error, liveness)
    terminal = next(
        (
            record
            for record in reversed(records)
            if record.get("kind") == "run_finished"
        ),
        None,
    )
    last = records[-1] if records else None
    last_activity = None
    if last is not None:
        last_activity = {
            "at": last.get("ts"),
            "source": "audit",
            "kind": last.get("kind"),
        }
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
    )
