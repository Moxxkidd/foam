"""R10 Kali 执行边界设计验证:netns+nftables(方案 A)与独立容器(方案 B)。

实验设计与判定准则见 docs/items/R10.md §6:允许/拒绝以端点侧标记文件为
独立证据,被测侧退出码为辅;环境等效性声明(privileged docker 容器 ≈ 隔离
Linux 实验环境,非裸 Kali)同见 §6。
"""

from __future__ import annotations

import re

from .labkit import Lab, docker_exec

# ---------------------------------------------------------------------------
# R10-A · 实验基线:harness 容器自检
# ---------------------------------------------------------------------------


def _capbit(cap_hex: str, bit: int) -> int:
    return (int(cap_hex, 16) >> bit) & 1


def test_baseline_harness_selfcheck(lab: Lab, harness: str) -> None:
    """环境基线:版本采集 + netns/nft/setpriv 降权可用性断言。

    采集结果全量进入 docker 命令级实录(lab.evidence);断言覆盖 R10-B
    各实验依赖的能力:unshare -n、ip netns、nft inet 表、setpriv 摘除
    bounding set 中的 CAP_SYS_ADMIN/CAP_NET_ADMIN。
    """
    rc, out = docker_exec(
        lab,
        harness,
        "echo KERNEL=$(uname -r); echo ARCH=$(uname -m); "
        "echo DEBIAN=$(cat /etc/debian_version); "
        "nft --version; ip -V; python3 --version; "
        "curl --version | head -1; dnsmasq --version | head -1; "
        "setpriv --version; script --version",
    )
    assert rc == 0
    for needle in (
        "KERNEL=",
        "nftables v",
        "ip utility",
        "Python 3.",
        "Dnsmasq version",
        "setpriv",
        "script",
    ):
        assert needle in out, f"基线采集缺少 {needle!r}:\n{out}"

    # 特权 harness 自身应持有 CAP_SYS_ADMIN(21)/CAP_NET_ADMIN(12)
    _, caps = docker_exec(lab, harness, "grep CapBnd /proc/self/status")
    cap_hex = caps.split()[1]
    assert _capbit(cap_hex, 21) == 1
    assert _capbit(cap_hex, 12) == 1

    # 命名空间与 nftables 基础能力
    docker_exec(lab, harness, "unshare -n true")
    docker_exec(
        lab,
        harness,
        "ip netns add selfcheck && ip netns list | grep -q selfcheck && "
        "ip netns del selfcheck && ! ip netns list | grep -q selfcheck",
    )
    docker_exec(
        lab,
        harness,
        "nft add table inet selfcheck && nft delete table inet selfcheck",
    )

    # setpriv 降权路径(被测命令包装器的核心)可用:摘 bounding set 两位
    rc, out = docker_exec(
        lab,
        harness,
        "setpriv --bounding-set=-sys_admin,-net_admin "
        "--inh-caps=-all --ambient-caps=-all "
        "grep CapBnd /proc/self/status",
    )
    assert rc == 0, f"setpriv bounding-set 语法不可用:\n{out}"
    dropped_hex = out.split()[1]
    assert _capbit(dropped_hex, 21) == 0
    assert _capbit(dropped_hex, 12) == 0
    # 降权后改网络规则必须失败(EPERM)
    rc, _ = docker_exec(
        lab,
        harness,
        "setpriv --bounding-set=-sys_admin,-net_admin "
        "--inh-caps=-all --ambient-caps=-all "
        "nft add table inet should_fail",
        check=False,
    )
    assert rc != 0


def test_baseline_environment_record(lab: Lab) -> None:
    """宿主机侧环境记录:docker/内核版本(等效性声明的事实依据)。"""
    rc, out = lab.run(
        [
            "version",
            "--format",
            "client={{.Client.Version}} server={{.Server.Version}}",
        ]
    )
    assert rc == 0 and "server=" in out
    rc, info = lab.run(
        ["info", "--format", "{{.OperatingSystem}} kernel={{.KernelVersion}}"]
    )
    assert rc == 0
    assert re.search(r"kernel=\d", info), info
