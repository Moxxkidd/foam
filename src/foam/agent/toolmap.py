"""工具盘点器与地图文本生成(WP-08)。

职责:对静态目录(tool_catalog.TOOL_CATALOG)逐项探测本机可用性,产出
≤2KB 的地图文本,供 WP-04 ``build_system_prompt(tool_map_text=...)`` 注入。

探测链(逐项,按序命中即停):

1. ``which``(默认 shutil.which,PATH 查找);
2. 常见目录直查(``/usr/bin`` 等;``/opt/<工具>`` 目录形态也算已装)——覆盖
   PATH 缺 /usr/sbin 等情况;
3. ``dpkg -l`` 包名兜底(命令名与包名不同的工具,如 searchsploit→exploitdb)。

缺失工具只标注(附 apt 包名),绝不自动安装——装不装是 LLM 结合任务的决定。

地图文本按细节层级降级(3 全文 → 0 只余可用名),``current_phase`` 指定的阶段
分组始终比其余组高一级细节(规格:超预算按阶段裁剪,当前阶段相关组优先)。
降级顺序:先砍 usage 提示,再砍 summary,再砍未安装清单(0 级起未安装项只在
分组标题的计数里体现)。最稀疏层级(0 级)仍保留全量可用工具名——这是地图的
核心价值;预算小到连 0 级都塞不下时按字节硬截兜底(仅理论情形)。

接线声明(cli.py 属 WP-10,本模块只提供 API 不动它):``foam run`` 启动时
``scan = scan_tools()`` → ``render_tool_map(scan)`` 传给 system prompt,
``render_startup_line(scan)`` 打一行启动日志(盘点计数)。
"""

from __future__ import annotations

import os
import shutil

# 只读查询本机包数据库,无外部输入拼接;bandit 对 subprocess 模块的泛化告警在此豁免。
import subprocess  # noqa: S404
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from foam.agent.tool_catalog import TOOL_CATALOG, ToolEntry, ToolGroup

#: 注入 system prompt 的地图文本字节预算(规格:≤2KB,按 UTF-8 字节计)。
MAP_BUDGET_BYTES = 2048

#: which 之外直查的常见安装目录(含 /opt 的目录形态)。
EXTRA_PROBE_DIRS = (
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt",
)

_DPKG_TIMEOUT_SECONDS = 15.0
_TRUNCATED_MARK = "\n…(已按预算截断)"


@dataclass(frozen=True)
class ToolStatus:
    """一个工具的盘点结果。via: "which" | "path" | "dpkg" | None(未安装)。"""

    entry: ToolEntry
    group: str  # ToolGroup.key
    available: bool
    via: str | None
    location: str | None  # which/path 命中为文件路径;dpkg 命中为 "apt:<包名>"


@dataclass(frozen=True)
class ScanResult:
    """一次盘点的完整结果;渲染与计数都从它出。"""

    catalog: tuple[ToolGroup, ...]
    statuses: tuple[ToolStatus, ...]
    dpkg_available: bool  # 本机是否有 dpkg(显式传入包集合时视为有)

    @property
    def available(self) -> list[ToolStatus]:
        return [s for s in self.statuses if s.available]

    @property
    def missing(self) -> list[ToolStatus]:
        return [s for s in self.statuses if not s.available]

    def by_group(self) -> dict[str, list[ToolStatus]]:
        """按分组归集状态,顺序与目录一致。"""
        grouped: dict[str, list[ToolStatus]] = {g.key: [] for g in self.catalog}
        for status in self.statuses:
            grouped[status.group].append(status)
        return grouped

    def counts(self) -> dict:
        """计数快照:{"total", "available", "missing", "groups": {key: {...}}}。"""
        groups = {}
        for key, statuses in self.by_group().items():
            hit = sum(1 for s in statuses if s.available)
            groups[key] = {"available": hit, "total": len(statuses)}
        total = len(self.statuses)
        available = sum(g["available"] for g in groups.values())
        return {
            "total": total,
            "available": available,
            "missing": total - available,
            "groups": groups,
        }


def parse_dpkg_l(output: str) -> set[str]:
    """解析 ``dpkg -l`` 文本,返回已安装包名集合(去掉 ``:amd64`` 等架构后缀)。

    只认状态列 ``ii``(已安装且配置完毕);``rc``(已卸载残留配置)等一律不算。
    """
    packages = set()
    for line in output.splitlines():
        if not line.startswith("ii "):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        packages.add(fields[1].split(":", 1)[0])
    return packages


def _load_dpkg_packages() -> tuple[set[str], bool]:
    """本机 ``dpkg -l`` 查询。返回 (包名集合, 本机是否有 dpkg);查询失败按空集降级。"""
    if shutil.which("dpkg") is None:
        return set(), False
    try:
        # 只读本机包数据库,参数为字面量;dpkg 经 PATH 查找(上行已 which 确认)。
        proc = subprocess.run(  # noqa: S603
            ["dpkg", "-l"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=_DPKG_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set(), True
    if proc.returncode != 0:
        return set(), True
    return parse_dpkg_l(proc.stdout), True


def _probe(
    entry: ToolEntry,
    *,
    which: Callable[[str], str | None],
    dpkg_packages: set[str],
    extra_dirs: Iterable[str],
) -> tuple[bool, str | None, str | None]:
    """探测一个工具,返回 (available, via, location)。命中即停。"""
    found = which(entry.name)
    if found:
        return True, "which", found
    for directory in extra_dirs:
        candidate = os.path.join(directory, entry.name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return True, "path", candidate
        if os.path.isdir(candidate):  # /opt/<工具> 目录形态(无单一可执行入口)
            return True, "path", candidate
    package = entry.package or entry.name
    if package in dpkg_packages:
        return True, "dpkg", f"apt:{package}"
    return False, None, None


def scan_tools(
    *,
    which: Callable[[str], str | None] = shutil.which,
    dpkg_packages: set[str] | None = None,
    extra_dirs: Iterable[str] = EXTRA_PROBE_DIRS,
    catalog: tuple[ToolGroup, ...] = TOOL_CATALOG,
) -> ScanResult:
    """盘点全目录。测试经 which/dpkg_packages/extra_dirs 注入伪环境,不碰真机。

    ``dpkg_packages`` 为 None 时真实执行 ``dpkg -l``(无 dpkg 则该项探测整体跳过)。
    """
    if dpkg_packages is None:
        dpkg_packages, dpkg_available = _load_dpkg_packages()
    else:
        dpkg_available = True
    statuses = tuple(
        ToolStatus(
            entry=entry,
            group=group.key,
            available=available,
            via=via,
            location=location,
        )
        for group in catalog
        for entry in group.tools
        for available, via, location in (
            _probe(
                entry,
                which=which,
                dpkg_packages=dpkg_packages,
                extra_dirs=extra_dirs,
            ),
        )
    )
    return ScanResult(
        catalog=catalog, statuses=statuses, dpkg_available=dpkg_available
    )


def _utf8_len(text: str) -> int:
    return len(text.encode("utf-8"))


def _missing_label(entry: ToolEntry) -> str:
    package = entry.package
    if not package or package == entry.name:
        return entry.name
    return f"{entry.name}(apt 包 {package})"


def _render_group(group: ToolGroup, statuses: list[ToolStatus], level: int) -> str:
    avail = [s for s in statuses if s.available]
    miss = [s for s in statuses if not s.available]
    lines = [f"## {group.title}({group.key}) {len(avail)}/{len(statuses)} 可用"]
    if level >= 3:
        lines.extend(
            f"- {s.entry.name} — {s.entry.summary}(`{s.entry.usage}`)" for s in avail
        )
    elif level == 2:
        lines.extend(f"- {s.entry.name} — {s.entry.summary}" for s in avail)
    elif avail:
        lines.append("  可用: " + ", ".join(s.entry.name for s in avail))
    # 未安装清单(带 apt 包名)只保到 1 级;0 级由标题计数兜底,把预算让给可用名。
    if level >= 1 and miss:
        lines.append("  未安装: " + ", ".join(_missing_label(s.entry) for s in miss))
    return "\n".join(lines)


def _render_at_level(
    scan: ScanResult, level: int, current_phase: str | None
) -> str:
    counts = scan.counts()
    parts = [
        f"本机工具盘点:已装 {counts['available']}/{counts['total']}(按渗透阶段分组;"
        "缺失项注明 apt 包,确有需要再装)。用法提示仅示意,细节请 man 或 --help 自查。"
    ]
    grouped = scan.by_group()
    for group in scan.catalog:
        # 当前阶段分组比其余组高一级细节(阶段优先裁剪);未指定则全体同级。
        group_level = min(3, level + 1) if group.key == current_phase else level
        parts.append(_render_group(group, grouped[group.key], group_level))
    return "\n\n".join(parts)


def _hard_truncate(text: str, budget_bytes: int) -> str:
    """兜底:最稀疏层级仍超预算时按字节硬截(防截断半个 UTF-8 字符)。"""
    raw = text.encode("utf-8")
    if len(raw) <= budget_bytes:
        return text
    keep = max(0, budget_bytes - _utf8_len(_TRUNCATED_MARK))
    return raw[:keep].decode("utf-8", errors="ignore") + _TRUNCATED_MARK


def render_tool_map(
    scan: ScanResult,
    *,
    budget_bytes: int = MAP_BUDGET_BYTES,
    current_phase: str | None = None,
) -> str:
    """渲染注入 system prompt 的地图正文(不含标题,标题由 prompts 层加)。

    返回文本保证 ≤ budget_bytes(UTF-8 字节)。``current_phase`` 传目录分组的
    key(如 "recon");不匹配任何分组时全体同级渲染。
    """
    if budget_bytes <= 0:
        raise ValueError("budget_bytes 必须为正")
    for level in (3, 2, 1, 0):
        text = _render_at_level(scan, level, current_phase)
        if _utf8_len(text) <= budget_bytes:
            return text
    return _hard_truncate(
        _render_at_level(scan, 0, current_phase), budget_bytes
    )


def render_startup_line(scan: ScanResult) -> str:
    """一行启动日志(供 WP-10 接线 ``foam run`` 使用):总计数 + 各分组计数。"""
    counts = scan.counts()
    groups = ", ".join(
        f"{g.key} {counts['groups'][g.key]['available']}"
        f"/{counts['groups'][g.key]['total']}"
        for g in scan.catalog
    )
    note = "" if scan.dpkg_available else "(本机无 dpkg,仅 PATH/常见路径探测)"
    return (
        f"工具盘点:{counts['available']}/{counts['total']} 可用 [{groups}]{note}"
    )
