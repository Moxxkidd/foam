"""工具地图测试(WP-08):目录完整性、伪环境盘点、dpkg 解析、预算裁剪、注入契约。

验收 2 的「fake PATH / 假 dpkg 输出」经 scan_tools 的 which/dpkg_packages/
extra_dirs 注入缝完成,不碰真机;真机只跑一致性冒烟(不断言具体工具)。
"""

from __future__ import annotations

import re

import pytest

from foam import __app_name__
from foam.agent.prompts import TOOL_MAP_PLACEHOLDER, build_system_prompt
from foam.agent.tool_catalog import TOOL_CATALOG, ToolEntry, ToolGroup
from foam.agent.toolmap import (
    MAP_BUDGET_BYTES,
    ScanResult,
    ToolStatus,
    _render_at_level,
    parse_dpkg_l,
    render_startup_line,
    render_tool_map,
    scan_tools,
)
from foam.guard.scope import parse_scope

# ---------- 目录完整性(验收 1) ----------

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")  # 命令名
_PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]*$")  # dpkg 包名一律小写


def test_catalog_groups_and_size():
    assert [g.key for g in TOOL_CATALOG] == [
        "recon",
        "vuln",
        "web",
        "password",
        "sniff",
        "post",
        "report",
    ]
    total = sum(len(g.tools) for g in TOOL_CATALOG)
    assert total >= 100, f"目录只有 {total} 个工具,不足规格 100+"


def test_catalog_entries_wellformed():
    seen = set()
    for group in TOOL_CATALOG:
        assert group.title, f"{group.key} 缺组标题"
        assert group.tools, f"{group.key} 是空组"
        for entry in group.tools:
            assert _NAME_RE.match(entry.name), f"非法命令名 {entry.name!r}"
            assert entry.summary.strip(), f"{entry.name} 缺一句话用途"
            assert entry.usage.strip(), f"{entry.name} 缺用法提示"
            if entry.package is not None:
                assert _PACKAGE_RE.match(entry.package), (
                    f"{entry.name} 的包名 {entry.package!r} 非法"
                )
            assert entry.name not in seen, f"{entry.name} 重复登记"
            seen.add(entry.name)


def test_probe_key_is_catalog_name():
    """验收 1「无死链」:逐项盘点的探测键必须就是目录里的工具名。"""
    queried = []

    def recording_which(name: str) -> str | None:
        queried.append(name)
        return None

    scan_tools(
        which=recording_which,
        dpkg_packages=set(),
        extra_dirs=(),
        catalog=TOOL_CATALOG,
    )
    assert queried == [e.name for g in TOOL_CATALOG for e in g.tools]


# ---------- dpkg -l 解析 ----------

_DPKG_SAMPLE = """\
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                    Version      Architecture Description
+++-=======================-============-============-==================
ii  nmap                    7.94+dfsg1-1 amd64        The Network Mapper
rc  oldtool                 1.0          amd64        removed, config stays
ii  libimage-exiftool-perl  12.60-1      all          exif library
un  nevertool               <none>       <none>       (no description available)
ii  foreign-pkg:amd64       1.2-3        amd64        multi-arch package
"""


def test_parse_dpkg_l():
    assert parse_dpkg_l(_DPKG_SAMPLE) == {
        "nmap",
        "libimage-exiftool-perl",
        "foreign-pkg",  # :amd64 架构后缀剥掉
    }  # rc(残留配置)与 un(从未安装)都不算已安装
    assert parse_dpkg_l("") == set()


# ---------- 伪环境盘点(验收 2) ----------

_MINI_CATALOG = (
    ToolGroup(
        key="g1",
        title="组一",
        tools=(
            ToolEntry("tool-a", "用途A", "-h"),
            ToolEntry("tool-b", "用途B", "-h"),
            ToolEntry("tool-c", "用途C", "-h"),
            ToolEntry("tool-d", "用途D", "-h", package="pkg-d"),
            ToolEntry("tool-e", "用途E", "-h"),
        ),
    ),
    ToolGroup(key="g2", title="组二", tools=(ToolEntry("tool-f", "用途F", "-h"),)),
)


def test_scan_fake_environment(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "tool-b"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    noexec = bindir / "tool-e"  # 存在但无执行位 → 不算已安装
    noexec.write_text("x")
    noexec.chmod(0o644)
    optdir = tmp_path / "opt"
    optdir.mkdir()
    (optdir / "tool-c").mkdir()  # /opt/<工具> 目录形态

    def fake_which(name: str) -> str | None:
        return "/usr/bin/tool-a" if name == "tool-a" else None

    scan = scan_tools(
        which=fake_which,
        dpkg_packages={"pkg-d"},
        extra_dirs=(str(bindir), str(optdir)),
        catalog=_MINI_CATALOG,
    )
    by_name = {s.entry.name: s for s in scan.statuses}
    assert by_name["tool-a"].via == "which"
    assert by_name["tool-a"].location == "/usr/bin/tool-a"
    assert by_name["tool-b"].via == "path"
    assert by_name["tool-c"].via == "path"  # 目录形态命中
    assert by_name["tool-d"].via == "dpkg"
    assert by_name["tool-d"].location == "apt:pkg-d"  # 命令名≠包名照查
    assert not by_name["tool-e"].available
    assert not by_name["tool-f"].available
    assert scan.dpkg_available is True

    counts = scan.counts()
    assert counts["total"] == 6
    assert counts["available"] == 4
    assert counts["missing"] == 2
    assert counts["groups"]["g1"] == {"available": 4, "total": 5}
    assert counts["groups"]["g2"] == {"available": 0, "total": 1}


def test_scan_probe_order_which_beats_dpkg():
    def fake_which(name: str) -> str | None:
        return f"/usr/bin/{name}"

    scan = scan_tools(
        which=fake_which,
        dpkg_packages={"tool-a", "pkg-d"},
        extra_dirs=(),
        catalog=_MINI_CATALOG,
    )
    # which 命中即停,不再落 dpkg(探测顺序固定:which → 路径 → dpkg)
    assert all(s.via == "which" for s in scan.statuses)


def test_scan_real_machine_smoke():
    """真机冒烟(不注入 dpkg):macOS 无 dpkg 走降级路径;只断言账目自洽。"""
    scan = scan_tools()
    counts = scan.counts()
    total = sum(len(g.tools) for g in TOOL_CATALOG)
    assert counts["total"] == total == len(scan.statuses)
    assert counts["available"] + counts["missing"] == counts["total"]
    assert len(scan.available) == counts["available"]
    assert len(scan.missing) == counts["missing"]
    assert all(s.available for s in scan.available)
    # 本开发机无 dpkg → 明确降级标记;Kali 补测时此项应翻真(验收 4 待补)
    assert scan.dpkg_available is False


# ---------- 渲染与预算(验收 3) ----------

_ALL_NAMES = {e.name for g in TOOL_CATALOG for e in g.tools}


def _fake_scan(available_names: set[str]) -> ScanResult:
    statuses = tuple(
        ToolStatus(
            entry=entry,
            group=group.key,
            available=entry.name in available_names,
            via="which" if entry.name in available_names else None,
            location=(
                f"/usr/bin/{entry.name}" if entry.name in available_names else None
            ),
        )
        for group in TOOL_CATALOG
        for entry in group.tools
    )
    return ScanResult(
        catalog=TOOL_CATALOG, statuses=statuses, dpkg_available=True
    )


def _utf8(text: str) -> int:
    return len(text.encode("utf-8"))


def test_render_budget_worst_case_all_installed():
    """极端情形:全部已安装(真实 Kali 近此),任何细节层级都必须落到 ≤2KB。"""
    scan = _fake_scan(_ALL_NAMES)
    text = render_tool_map(scan)
    assert _utf8(text) <= MAP_BUDGET_BYTES
    assert "可用" in text  # 仍有计数信息
    # 全装情形无 missing,预算够让可用名全保留 → 抽查两端各一名
    assert "nmap" in text and "keepassxc" in text


def test_render_levels_monotonic_nonincreasing():
    scan = _fake_scan(_ALL_NAMES)
    for phase in (None, "web"):
        sizes = [_utf8(_render_at_level(scan, lv, phase)) for lv in (3, 2, 1, 0)]
        assert sizes == sorted(sizes, reverse=True), f"phase={phase}: {sizes}"


def test_render_phase_priority_under_pressure():
    """预算压力下的两条地板承诺:可用名全保留;同预算下当前阶段组细节更多。"""
    scan = _fake_scan(_ALL_NAMES)
    size_boosted = _utf8(_render_at_level(scan, 1, "web"))  # web 带 summary
    size_floor = _utf8(_render_at_level(scan, 0, "web"))  # 全员只剩可用名
    assert size_floor < size_boosted

    budget = (size_boosted + size_floor) // 2  # 恰好只容得下 0 级
    text = render_tool_map(scan, budget_bytes=budget, current_phase="web")
    assert _utf8(text) <= budget
    assert "gobuster" in text  # 当前阶段组可用名在
    assert "hashcat" in text  # 非当前阶段组可用名也在(0 级地板)
    assert "目录/DNS/存储桶爆破" not in text  # 但 summary 细节已被裁掉
    assert "## Web 测试(web)" in text

    # 同一预算(刚好容下 1 级):指定阶段 → web 组保住 summary;不指定 → 全体无名细节
    boosted = render_tool_map(
        scan, budget_bytes=size_boosted, current_phase="web"
    )
    assert "目录/DNS/存储桶爆破" in boosted
    flat = render_tool_map(scan, budget_bytes=size_boosted)
    assert "目录/DNS/存储桶爆破" not in flat


def test_render_missing_marks_apt_package():
    scan = _fake_scan(_ALL_NAMES - {"searchsploit", "nmap"})
    text = render_tool_map(scan, budget_bytes=MAP_BUDGET_BYTES)
    assert "未安装" in text
    assert "searchsploit(apt 包 exploitdb)" in text  # 命令名≠包名时标注包名
    assert "nmap(apt 包" not in text  # 同名不啰嗦


def test_render_sparse_machine_keeps_available_names():
    """稀疏机(开发机情形):可用名永不被裁掉,未安装清单可以让位。"""
    scan = _fake_scan({"nmap", "curl"})
    text = render_tool_map(scan)
    assert _utf8(text) <= MAP_BUDGET_BYTES
    assert "nmap" in text and "curl" in text


def test_render_hard_truncate_and_bad_budget():
    scan = _fake_scan(_ALL_NAMES)
    text = render_tool_map(scan, budget_bytes=100)  # 连最稀疏层级都塞不下
    assert _utf8(text) <= 100
    assert text.endswith("…(已按预算截断)")
    with pytest.raises(ValueError, match="budget_bytes"):
        render_tool_map(scan, budget_bytes=0)


def test_no_brand_in_catalog_and_render():
    blob = "\n".join(
        f"{e.name} {e.summary} {e.usage} {e.package or ''}"
        for g in TOOL_CATALOG
        for e in g.tools
    )
    assert __app_name__.lower() not in blob.lower()
    scan = _fake_scan(_ALL_NAMES)
    for text in (
        render_tool_map(scan),
        render_tool_map(_fake_scan({"nmap"}), budget_bytes=200),
        render_startup_line(scan),
    ):
        assert __app_name__.lower() not in text.lower()


# ---------- 注入契约(验收 3,经 WP-04 prompts 层) ----------


def test_injection_through_build_system_prompt(tmp_path):
    scan = _fake_scan({"nmap", "gobuster"})
    text = render_tool_map(scan)
    scope = parse_scope("10.0.0.0/24\n")
    prompt = build_system_prompt(
        scope,
        source="scopes/test.txt",
        loaded_at="2026-08-22T00:00:00+00:00",
        workdir=tmp_path,
        tool_map_text=text,
    )
    assert "# 工具地图" in prompt  # 标题由 prompts 层加,正文来自本模块
    assert "nmap" in prompt  # 已安装工具进入 system prompt
    assert TOOL_MAP_PLACEHOLDER not in prompt  # 占位文本已被整段替换
    assert _utf8(text) <= MAP_BUDGET_BYTES


# ---------- 启动行(供 WP-10 接线) ----------


def test_render_startup_line():
    scan = _fake_scan({"nmap", "gobuster", "john"})
    line = render_startup_line(scan)
    assert line.startswith("工具盘点:3/")
    assert "recon 1/" in line and "web 1/" in line and "password 1/" in line
    assert "dpkg" not in line  # dpkg 可用时不加注

    degraded = ScanResult(
        catalog=scan.catalog, statuses=scan.statuses, dpkg_available=False
    )
    assert "无 dpkg" in render_startup_line(degraded)
