"""R10 Kali 执行边界设计验证:netns+nftables(方案 A)与独立容器(方案 B)。

实验设计与判定准则见 docs/items/R10.md §6:允许/拒绝以端点侧标记文件为
独立证据,被测侧退出码为辅;环境等效性声明(privileged docker 容器 ≈ 隔离
Linux 实验环境,非裸 Kali)同见 §6。
"""

from __future__ import annotations

import re
import shlex
import time
import uuid
from collections.abc import Iterator

import pytest

from .labkit import SERVE_PY, Lab, dnsmasq_cmd, docker_exec, push_file

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
    docker_exec(
        lab,
        harness,
        "python3 -c 'import os, signal; "
        "assert hasattr(os, \"pidfd_open\"); "
        "assert hasattr(signal, \"pidfd_send_signal\")'",
    )


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


def test_cleanup_reconciles_untracked_owned_resources(
    lab: Lab, lab_image: str
) -> None:
    """模拟 daemon 已创建而客户端未登记:label 对账仍须全部回收。"""
    orphan = Lab()
    orphan.evidence = lab.evidence
    container = orphan.name("timeout-container")
    network = orphan.name("timeout-network")
    try:
        lab.run(
            [
                "run", "-d", "--name", container, "--network", "none",
                *orphan.label_args(), lab_image, "sleep", "infinity",
            ]
        )
        lab.run(
            [
                "network", "create", "--internal",
                *orphan.label_args(), network,
            ]
        )
        assert container not in orphan.containers
        assert network not in orphan.networks
        assert orphan.cleanup() == []
        for args in (
            ["container", "inspect", container],
            ["network", "inspect", network],
        ):
            rc, _ = lab.run(args, check=False)
            assert rc != 0, f"未登记资源仍有残留: {args}"
    finally:
        assert orphan.cleanup() == []


# ---------------------------------------------------------------------------
# R10-B · 方案 A:network namespace + nftables(harness 特权容器内)
# ---------------------------------------------------------------------------

EPIN_V4 = "10.10.10.11"
EPOUT_V4 = "10.10.20.11"
EPIN_V6 = "fd00:20::11"
EPOUT_V6 = "fd00:30::11"
CTRL_V4 = "10.10.0.1"  # 控制面(harness root ns)在被测腿上的地址

# dnsmasq 查询日志路径(一次性实验容器内路径,容器销毁即弃,非宿主机 /tmp)
DNS_EPIN_LOG = "/tmp/dns-epin.log"  # noqa: S108
DNS_EPOUT_LOG = "/tmp/dns-epout.log"  # noqa: S108

# 被测命令包装器:控制面完成命名空间设置,再交非 root/无 capabilities 工具。
# raw socket 不在本 PoC 支持集;非特权 ICMP 由 tested netns 的组范围提供。
TESTED_WRAP = (
    "ip netns exec tested unshare --kill-child=KILL "
    "--mount --pid --fork --mount-proc "
    "setpriv --reuid=65534 --regid=65534 --clear-groups "
    "--bounding-set=-all --inh-caps=-all --ambient-caps=-all "
    "--no-new-privs bash -c "
)

PLAN_A_SETUP = f"""\
set -euo pipefail
ip netns add tested
ip netns add epin
ip netns add epout
ip link add v-test type veth peer name v-test-r
ip link add v-epin type veth peer name v-epin-r
ip link add v-epout type veth peer name v-epout-r
ip link set v-test netns tested
ip link set v-epin netns epin
ip link set v-epout netns epout
ip addr add 10.10.0.1/30 dev v-test-r
ip addr add 10.10.10.1/28 dev v-epin-r
ip addr add 10.10.20.1/28 dev v-epout-r
ip -6 addr add fd00:10::1/64 nodad dev v-test-r
ip -6 addr add fd00:20::1/64 nodad dev v-epin-r
ip -6 addr add fd00:30::1/64 nodad dev v-epout-r
ip link set v-test-r up
ip link set v-epin-r up
ip link set v-epout-r up
ip -n tested addr add 10.10.0.2/30 dev v-test
ip -n tested -6 addr add fd00:10::2/64 nodad dev v-test
ip -n tested link set v-test up
ip -n tested link set lo up
ip -n tested route add default via 10.10.0.1
ip -n tested -6 route add default via fd00:10::1
ip -n epin addr add {EPIN_V4}/28 dev v-epin
ip -n epin -6 addr add {EPIN_V6}/64 nodad dev v-epin
ip -n epin link set v-epin up
ip -n epin link set lo up
ip -n epin route add default via 10.10.10.1
ip -n epin -6 route add default via fd00:20::1
ip -n epout addr add {EPOUT_V4}/28 dev v-epout
ip -n epout -6 addr add {EPOUT_V6}/64 nodad dev v-epout
ip -n epout link set v-epout up
ip -n epout link set lo up
ip -n epout route add default via 10.10.20.1
ip -n epout -6 route add default via fd00:30::1
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv6.conf.all.forwarding=1
ip netns exec tested sysctl -qw "net.ipv4.ping_group_range=0 65534"
mkdir -p /etc/netns/tested
touch /opt/root-netns
mount --bind /proc/1/ns/net /opt/root-netns
"""

# scope 语义 = CIDR+端口;原始方向逐条放行,仅界内回复方向接受 established。
PLAN_A_NFT = """\
table inet r10 {
    chain forward {
        type filter hook forward priority filter; policy drop;
        iifname "v-epin-r" oifname "v-test-r" ct state established accept
        iifname "v-test-r" oifname "v-epin-r" \\
            ip saddr 10.10.0.2 ip daddr 10.10.10.0/28 tcp dport 8080 accept
        iifname "v-test-r" oifname "v-epin-r" \\
            ip saddr 10.10.0.2 ip daddr 10.10.10.0/28 udp dport 53 accept
        iifname "v-test-r" oifname "v-epin-r" \\
            ip saddr 10.10.0.2 ip daddr 10.10.10.0/28 icmp type echo-request accept
        iifname "v-test-r" oifname "v-epin-r" \\
            ip6 saddr fd00:10::2 ip6 daddr fd00:20::/64 tcp dport 8080 accept
        iifname "v-test-r" oifname "v-epin-r" \\
            ip6 saddr fd00:10::2 ip6 daddr fd00:20::/64 udp dport 53 accept
        iifname "v-test-r" oifname "v-epin-r" \\
            ip6 saddr fd00:10::2 ip6 daddr fd00:20::/64 icmpv6 type echo-request accept
    }
    chain input {
        type filter hook input priority filter; policy accept;
        iifname "v-test-r" \\
            icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept
        iifname "v-test-r" drop
    }
}
"""

# 负面对照用:只写 ip 族规则(v6 无人管),证「单族规则漏另一族」。
PLAN_A_NFT_V4_ONLY = """\
table ip r10v4 {
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state { established, related } accept
        iifname "v-test-r" oifname "v-epin-r" ip daddr 10.10.10.0/28 accept
    }
}
"""

ICMP_TAP_PY = """import socket
import sys
import threading
from pathlib import Path

families = [(socket.AF_INET, socket.IPPROTO_ICMP)]
if sys.argv[1:] != ["--v4-only"]:
    families.append((socket.AF_INET6, socket.IPPROTO_ICMPV6))
sockets = [(socket.socket(family, socket.SOCK_RAW, protocol), family)
           for family, protocol in families]
lock = threading.Lock()


def record(sock, family):
    while True:
        packet = sock.recv(65535)
        offset = 0
        if family == socket.AF_INET and packet[0] >> 4 == 4:
            offset = (packet[0] & 15) * 4
        elif family == socket.AF_INET6 and packet[0] >> 4 == 6:
            offset = 40
        expected = 8 if family == socket.AF_INET else 128
        if packet[offset] == expected:
            with lock, open(f"{__file__}.hits", "a", encoding="ascii") as fh:
                fh.write(packet[offset:].hex() + "\\n")


threads = [threading.Thread(target=record, args=item, daemon=True)
           for item in sockets]
for thread in threads:
    thread.start()
Path(f"{__file__}.ready").write_text("ready\\n", encoding="ascii")
for thread in threads:
    thread.join()
"""

PIDCTL_PY = """import os
import signal
import sys
import time
from pathlib import Path


def start_time(pid):
    stat = Path(f"/proc/{pid}/stat").read_text()
    return stat.rsplit(") ", 1)[1].split()[19]


def state(pid):
    stat = Path(f"/proc/{pid}/stat").read_text()
    return stat.rsplit(") ", 1)[1].split()[0]


def open_owned(pid, expected_start, token):
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        return None
    owned = False
    try:
        try:
            if state(pid) == "Z":
                return None
            if start_time(pid) != expected_start:
                raise RuntimeError(f"PID {pid} 启动时间不符")
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
            if token.encode() not in cmdline:
                if state(pid) == "Z":
                    return None
                raise RuntimeError(f"PID {pid} 命令身份不符")
        except FileNotFoundError:
            return None
        owned = True
        return pidfd
    finally:
        if not owned:
            os.close(pidfd)


def signal_owned(pidfd):
    try:
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
    except ProcessLookupError:
        return False
    return True


def kill_owned(pid, expected_start, token):
    pidfd = open_owned(pid, expected_start, token)
    if pidfd is None:
        return False
    try:
        return signal_owned(pidfd)
    finally:
        os.close(pidfd)


def token_processes(token):
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            cmdline = (entry / "cmdline").read_bytes()
            if token not in cmdline:
                continue
            start = start_time(pid)
            status = (entry / "status").read_text()
        except FileNotFoundError:
            continue
        nsids = []
        for line in status.splitlines():
            if line.startswith("NSpid:"):
                nsids = line.split()[1:]
                break
        found.append((pid, start, nsids))
    return found


def owned_token_processes(token):
    found = []
    try:
        for pid, start, nsids in token_processes(token):
            pidfd = open_owned(pid, start, token.decode())
            if pidfd is not None:
                found.append((pidfd, pid, nsids))
    except BaseException:
        for pidfd, _, _ in found:
            os.close(pidfd)
        raise
    return found


def crash_cleanup():
    token = Path("/opt/r10-abort-token").read_text().strip().encode()
    processes = owned_token_processes(token)
    try:
        for pidfd, _, nsids in processes:
            if len(nsids) > 1 and nsids[-1] == "1":
                signal_owned(pidfd)
        for pidfd, _, _ in processes:
            signal_owned(pidfd)
    finally:
        for pidfd, _, _ in processes:
            os.close(pidfd)
    deadline = time.monotonic() + 5
    while token_processes(token):
        if time.monotonic() >= deadline:
            raise TimeoutError("crash token 进程未全部消失")
        time.sleep(0.05)


if sys.argv[1:] == ["crash-cleanup"]:
    crash_cleanup()
elif len(sys.argv) == 5 and sys.argv[1] == "kill":
    changed = kill_owned(int(sys.argv[2]), sys.argv[3], sys.argv[4])
    print("killed" if changed else "already-gone")
else:
    raise ValueError("usage: kill PID START TOKEN | crash-cleanup")
"""

PLAN_A_START = f"""\
set -euo pipefail
nft -f /opt/r10.nft
start_service() {{
    pidfile=$1
    shift
    "$@" </dev/null >"/tmp/$(basename "$pidfile").log" 2>&1 &
    pid=$!
    start=$(cut -d' ' -f22 "/proc/$pid/stat")
    printf '%s %s\\n' "$pid" "$start" >"$pidfile"
}}
start_service /opt/r10-serve-epin-8080.pid \\
    ip netns exec epin python3 /opt/serve-epin.py 8080
start_service /opt/r10-serve-epin-8081.pid \\
    ip netns exec epin python3 /opt/serve-epin.py 8081
start_service /opt/r10-serve-epout-8080.pid \\
    ip netns exec epout python3 /opt/serve-epout.py 8080
start_service /opt/r10-serve-ctrl-9090.pid python3 /opt/serve-ctrl.py 9090
start_service /opt/r10-dns-epin.pid \\
    ip netns exec epin {dnsmasq_cmd(EPIN_V4, DNS_EPIN_LOG)}
start_service /opt/r10-dns-epout.pid \\
    ip netns exec epout {dnsmasq_cmd(EPOUT_V4, DNS_EPOUT_LOG)}
start_service /opt/r10-icmp-epin.pid \\
    ip netns exec epin python3 /opt/icmp-epin.py
start_service /opt/r10-icmp-epout.pid \\
    ip netns exec epout python3 /opt/icmp-epout.py
sleep 1
cat /opt/icmp-epin.py.ready /opt/icmp-epout.py.ready
ping -c 1 -W 2 -p aa {EPIN_V4}
ping -c 1 -W 2 -p aa {EPOUT_V4}
curl --noproxy '*' -sS -m 5 -o /dev/null http://{EPIN_V4}:8080/ready-ctrl
curl --noproxy '*' -sS -m 5 -o /dev/null http://{EPIN_V4}:8081/ready-port
curl --noproxy '*' -sS -m 5 -o /dev/null http://{EPOUT_V4}:8080/ready-ctrl
curl --noproxy '*' -sS -m 5 -o /dev/null http://{CTRL_V4}:9090/ready-ctrl
curl --noproxy '*' -sS -m 5 -g -o /dev/null 'http://[{EPIN_V6}]:8080/ready-v6'
dig +time=2 +tries=2 @{EPIN_V4} ready.test +short | grep -q '{EPIN_V4}'
dig +time=2 +tries=2 @{EPOUT_V4} ready-out.test +short | grep -q '{EPOUT_V4}'
dig +tcp +time=2 +tries=2 @{EPIN_V4} ready-tcp.test +short | grep -q '{EPIN_V4}'
"""

_PLAN_A_TEARDOWN = """\
set -u
fail=0
for pidfile in /opt/r10-*.pid; do
    [ -f "$pidfile" ] || continue
    read -r pid start <"$pidfile" || fail=1
    case "$pid" in (*[!0-9]*|'') fail=1; continue;; esac
    if [ -r "/proc/$pid/stat" ]; then
        cmd=$(ps -p "$pid" -o args= 2>/dev/null || true)
        case "$cmd" in
            ""|*defunct*) expected=r10 ;;
            *serve-epin.py*) expected=serve-epin.py ;;
            *serve-epout.py*) expected=serve-epout.py ;;
            *serve-ctrl.py*) expected=serve-ctrl.py ;;
            *icmp-epin.py*) expected=icmp-epin.py ;;
            *icmp-epout.py*) expected=icmp-epout.py ;;
            *dnsmasq*) expected=dnsmasq ;;
            *r10-abort-*) expected=r10-abort- ;;
            *) echo "命令身份不符,拒绝 kill: $pidfile $cmd" >&2; fail=1; continue;;
        esac
        python3 /opt/r10-pidctl.py kill "$pid" "$start" "$expected" || fail=1
        for unused in $(seq 1 50); do
            [ ! -e "/proc/$pid" ] && break
            sleep 0.05
        done
        [ ! -e "/proc/$pid" ] || fail=1
    fi
    rm -f "$pidfile" || fail=1
done
if [ -f /opt/r10-abort-token ]; then
    python3 /opt/r10-pidctl.py crash-cleanup || fail=1
fi
if mountpoint -q /opt/root-netns; then umount /opt/root-netns || fail=1; fi
if nft list table inet r10 >/dev/null 2>&1; then
    nft delete table inet r10 || fail=1
fi
if nft list table ip r10v4 >/dev/null 2>&1; then
    nft delete table ip r10v4 || fail=1
fi
for ns in tested epin epout; do
    if [ -e "/run/netns/$ns" ]; then ip netns del "$ns" || fail=1; fi
done
for ns in tested epin epout; do
    if [ -e "/run/netns/$ns" ]; then fail=1; fi
done
if nft list table inet r10 >/dev/null 2>&1; then fail=1; fi
if nft list table ip r10v4 >/dev/null 2>&1; then fail=1; fi
if mountpoint -q /opt/root-netns; then fail=1; fi
exit "$fail"
"""


def _plan_a_teardown(lab: Lab, harness: str) -> None:
    rc, out = docker_exec(lab, harness, _PLAN_A_TEARDOWN, check=False)
    assert rc == 0, f"方案 A 清理失败:\n{out}"


@pytest.fixture
def plan_a(lab: Lab, harness: str) -> Iterator[None]:
    _plan_a_teardown(lab, harness)
    try:
        for name in ("epin", "epout"):
            push_file(lab, harness, f"/opt/serve-{name}.py", SERVE_PY)
            push_file(lab, harness, f"/opt/icmp-{name}.py", ICMP_TAP_PY)
        push_file(lab, harness, "/opt/serve-ctrl.py", SERVE_PY)
        push_file(lab, harness, "/opt/r10-pidctl.py", PIDCTL_PY)
        push_file(lab, harness, "/opt/r10.nft", PLAN_A_NFT)
        push_file(lab, harness, "/opt/escape.sh", _ESCAPE_PROBE)
        docker_exec(lab, harness, PLAN_A_SETUP)
        push_file(
            lab, harness, "/etc/netns/tested/resolv.conf",
            f"nameserver {EPIN_V4}\noptions ndots:0\n",
        )
        docker_exec(lab, harness, PLAN_A_START)
        yield
    finally:
        _plan_a_teardown(lab, harness)


def _tested(
    lab: Lab,
    harness: str,
    cmd: str,
    *,
    timeout: int = 60,
    check: bool = True,
) -> tuple[int, str]:
    """在被测 netns 的降权包装里执行命令(模拟护栏内的工具执行)。"""
    command = (
        "export NO_PROXY='*' no_proxy='*'; "
        "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; "
        + cmd
    )
    return docker_exec(
        lab, harness, TESTED_WRAP + shlex.quote(command), timeout=timeout,
        check=check,
    )


def _marker(lab: Lab, harness: str, name: str, port: int) -> str:
    _, out = docker_exec(lab, harness, f"cat /opt/serve-{name}.py.{port}.hits")
    return out


def _dnslog(lab: Lab, harness: str, name: str) -> str:
    log = DNS_EPIN_LOG if name == "epin" else DNS_EPOUT_LOG
    _, out = docker_exec(lab, harness, f"cat {log}")
    return out


def _icmp_marker(lab: Lab, harness: str, name: str) -> str:
    _, out = docker_exec(lab, harness, f"cat /opt/icmp-{name}.py.hits")
    return out


def _ruleset_hash(lab: Lab, harness: str) -> str:
    _, out = docker_exec(
        lab, harness, "set -o pipefail; nft list ruleset | sha256sum"
    )
    return out.split()[0]


def test_plan_a_bash_allow_deny(lab: Lab, harness: str, plan_a: None) -> None:
    """bash 命令:界内 CIDR+端口放行 / 界外拒绝 / 同 CIDR 异端口拒绝。"""
    token = uuid.uuid4().hex[:8]
    rc, out = _tested(
        lab, harness,
        f"curl -sS -m 5 http://{EPIN_V4}:8080/t-a-bash-in-{token}",
    )
    assert rc == 0 and "ok" in out
    assert f"/t-a-bash-in-{token}" in _marker(lab, harness, "epin", 8080)

    rc, _ = _tested(
        lab, harness,
        f"curl -sS -m 5 http://{EPOUT_V4}:8080/t-a-bash-out-{token}",
        check=False,
    )
    assert rc != 0
    assert f"/t-a-bash-out-{token}" not in _marker(lab, harness, "epout", 8080)

    rc, _ = _tested(
        lab, harness,
        f"curl -sS -m 5 http://{EPIN_V4}:8081/t-a-bash-port-{token}",
        check=False,
    )
    assert rc != 0
    assert f"/t-a-bash-port-{token}" not in _marker(lab, harness, "epin", 8081)


def test_plan_a_pty_boundary(lab: Lab, harness: str, plan_a: None) -> None:
    """PTY(script 分配伪终端)与裸 bash 同边界:边界在命名空间不在终端层。"""
    token = uuid.uuid4().hex[:8]
    rc, out = _tested(
        lab, harness,
        f"script -qec 'curl -sS -m 5 http://{EPIN_V4}:8080"
        f"/t-a-pty-in-{token}' /dev/null",
    )
    assert rc == 0 and "ok" in out
    assert f"/t-a-pty-in-{token}" in _marker(lab, harness, "epin", 8080)

    rc, _ = _tested(
        lab, harness,
        f"script -qec 'curl -sS -m 5 http://{EPOUT_V4}:8080"
        f"/t-a-pty-out-{token}' /dev/null",
        check=False,
    )
    assert rc != 0
    assert f"/t-a-pty-out-{token}" not in _marker(lab, harness, "epout", 8080)


_SUBPROCESS_PROBE = """\
echo "self=$(readlink /proc/self/ns/net) self-pidns=$(readlink /proc/self/ns/pid)"
bash -c 'echo "child-bash=$(readlink /proc/self/ns/net) \
child-bash-pidns=$(readlink /proc/self/ns/pid)"'
setsid bash -c 'echo "child-setsid=$(readlink /proc/self/ns/net) \
child-setsid-pidns=$(readlink /proc/self/ns/pid)"'
python3 -c 'import subprocess
print("child-python=" + subprocess.check_output(
    ["readlink", "/proc/self/ns/net"]).decode().strip())
print("child-python-pidns=" + subprocess.check_output(
    ["readlink", "/proc/self/ns/pid"]).decode().strip())'
"""

_ESCAPE_PROBE = """\
for cmd in \
  "unshare -n true" \
  "unshare --mount true" \
  "nsenter --net=/proc/1/ns/net true" \
  "nsenter --net=/opt/root-netns true" \
  "ip netns exec epin true" \
  "ip netns exec tested true" \
  "nft list ruleset" \
  "nft add table inet evil" \
  "ip link set v-test down" \
  "ip route replace default via 10.10.0.2" \
  "sysctl -w net.ipv4.ip_forward=0" \
; do
  out=$(bash -c "$cmd" 2>&1); rc=$?
  echo "ESCAPE rc=$rc cmd=[$cmd] out=[${out:0:80}]"
done
grep -E 'Cap(Bnd|Eff)' /proc/self/status
"""


def test_plan_a_subprocess_inherits_and_cannot_escape(
    lab: Lab, harness: str, plan_a: None
) -> None:
    """子进程(嵌套 bash/setsid/python fork)同命名空间;逃逸尝试全灭。"""
    push_file(lab, harness, "/opt/nsprobe.sh", _SUBPROCESS_PROBE)
    rc, out = _tested(lab, harness, "bash /opt/nsprobe.sh")
    assert rc == 0
    for kind in ("net", "pid"):
        namespaces = set(re.findall(rf"=({kind}:\[\d+\])", out))
        assert len(re.findall(rf"=({kind}:\[\d+\])", out)) == 4, out
        assert len(namespaces) == 1, f"子进程不在同一 {kind}ns:\n{out}"

    before = _ruleset_hash(lab, harness)
    push_file(lab, harness, "/opt/escape.sh", _ESCAPE_PROBE)
    rc, out = _tested(lab, harness, "bash /opt/escape.sh")
    assert rc == 0
    attempts = re.findall(r"ESCAPE rc=(\d+)", out)
    assert len(attempts) == 11, out
    assert all(rcode != "0" for rcode in attempts), (
        f"存在成功的逃逸/篡改尝试:\n{out}"
    )
    cap_bnd = re.search(r"CapBnd:\s*([0-9a-fA-F]+)", out)
    assert cap_bnd is not None
    assert _capbit(cap_bnd.group(1), 21) == 0  # CAP_SYS_ADMIN
    assert _capbit(cap_bnd.group(1), 12) == 0  # CAP_NET_ADMIN
    assert _ruleset_hash(lab, harness) == before, "控制面规则被改动"

    # 篡改尝试后边界仍生效
    token = uuid.uuid4().hex[:8]
    rc, _ = _tested(
        lab, harness,
        f"curl -sS -m 5 http://{EPOUT_V4}:8080/t-a-esc-{token}",
        check=False,
    )
    assert rc != 0
    assert f"/t-a-esc-{token}" not in _marker(lab, harness, "epout", 8080)


def test_plan_a_least_privilege_and_evidence_read_only(
    lab: Lab, harness: str, plan_a: None
) -> None:
    """工具不得靠 root/raw 权限改规则、伪造端点证据或绕过路由。"""
    push_file(
        lab,
        harness,
        "/opt/rawprobe.py",
        """import socket

for name, args in (
    ("inet", (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)),
    ("packet", (socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))),
):
    try:
        sock = socket.socket(*args)
    except OSError as exc:
        print(f"{name}=denied:{exc.errno}")
    else:
        print(f"{name}=allowed")
        sock.close()
""",
    )
    rc, out = _tested(
        lab,
        harness,
        "echo uid=$(id -u); grep -E 'Cap(Bnd|Prm|Eff)|NoNewPrivs' "
        "/proc/self/status; "
        "for file in /opt/r10.nft /opt/serve-epout.py.8080.hits "
        "/opt/serve-ctrl.py.9090.hits; do "
        "if [ -w \"$file\" ]; then echo writable=$file; "
        "else echo readonly=$file; fi; done; "
        "python3 /opt/rawprobe.py",
    )
    assert rc == 0, out
    assert re.search(r"^uid=65534$", out, re.MULTILINE), out
    assert re.search(r"^NoNewPrivs:\s*1$", out, re.MULTILINE), out
    caps = re.findall(r"^Cap(?:Bnd|Prm|Eff):\s*([0-9a-fA-F]+)$", out, re.MULTILINE)
    assert len(caps) == 3 and all(int(value, 16) == 0 for value in caps), out
    assert "writable=" not in out and out.count("readonly=") == 3, out
    assert "inet=denied:" in out and "packet=denied:" in out, out
    assert "allowed" not in out, out


def test_plan_a_pidfd_identity_mismatch_preserves_process(
    lab: Lab, harness: str, plan_a: None
) -> None:
    """错误 start/token 不得杀 canary;pidfd 绑定后仅终止原身份。"""
    docker_exec(lab, harness, "sleep 60 & echo $! >/tmp/r10-pidfd-canary.pid")
    _, pid_info = docker_exec(
        lab, harness,
        "pid=$(cat /tmp/r10-pidfd-canary.pid); "
        "echo \"$pid $(cut -d' ' -f22 /proc/$pid/stat)\"",
    )
    pid, start = pid_info.split()
    try:
        for wrong_start, wrong_token in (("1", "sleep"), (start, "not-canary")):
            rc, _ = docker_exec(
                lab, harness,
                f"python3 /opt/r10-pidctl.py kill {pid} "
                f"{wrong_start} {wrong_token}",
                check=False,
            )
            assert rc != 0
            docker_exec(lab, harness, f"kill -0 {pid}")
    finally:
        rc, _ = docker_exec(
            lab, harness,
            f"python3 /opt/r10-pidctl.py kill {pid} {start} sleep",
            check=False,
        )
        assert rc == 0
    deadline = time.monotonic() + 5
    while True:
        rc, _ = docker_exec(lab, harness, f"kill -0 {pid}", check=False)
        if rc != 0:
            break
        if time.monotonic() >= deadline:
            pytest.fail(f"canary 未按正确身份回收: {pid}")
        time.sleep(0.05)


def test_plan_a_icmp_boundary(lab: Lab, harness: str, plan_a: None) -> None:
    """非特权 ICMP 的允许/拒绝均由端点收到的 echo-request 判定。"""
    token = uuid.uuid4().hex[:12]
    rc, _ = _tested(lab, harness, f"ping -c 1 -W 2 -p {token} {EPIN_V4}")
    assert rc == 0
    assert token in _icmp_marker(lab, harness, "epin")
    rc, _ = _tested(
        lab, harness, f"ping -c 1 -W 2 -p {token} {EPOUT_V4}", check=False
    )
    assert rc != 0
    assert token not in _icmp_marker(lab, harness, "epout")


def test_plan_a_evidence_read_failure_is_not_denial(
    lab: Lab, harness: str, plan_a: None
) -> None:
    """marker 读取失败必须报错;服务恢复写盘后可重新取得独立证据。"""
    docker_exec(lab, harness, "rm -f /opt/serve-epout.py.8080.hits")
    with pytest.raises(RuntimeError):
        _marker(lab, harness, "epout", 8080)
    token = uuid.uuid4().hex[:8]
    rc, out = docker_exec(
        lab, harness,
        f"curl -sS -m 5 http://{EPOUT_V4}:8080/t-a-evidence-health-{token}",
    )
    assert rc == 0 and "ok" in out
    assert f"/t-a-evidence-health-{token}" in _marker(lab, harness, "epout", 8080)


def test_plan_a_ipv6_enforced(lab: Lab, harness: str, plan_a: None) -> None:
    """v6 HTTP/端口/DNS/ICMP 与 v4 同子集;界外和异端口均不到端点。"""
    token = uuid.uuid4().hex[:8]
    rc, out = _tested(
        lab, harness,
        f"curl -sS -m 5 -g 'http://[{EPIN_V6}]:8080/t-a-v6-in-{token}'",
    )
    assert rc == 0 and "ok" in out
    assert f"/t-a-v6-in-{token}" in _marker(lab, harness, "epin", 8080)
    for url, name, port in (
        (f"http://[{EPOUT_V6}]:8080/t-a-v6-out-{token}", "epout", 8080),
        (f"http://[{EPIN_V6}]:8081/t-a-v6-port-{token}", "epin", 8081),
    ):
        rc, _ = _tested(lab, harness, f"curl -sS -m 5 -g '{url}'", check=False)
        assert rc != 0
        marker = _marker(lab, harness, name, port)
        expected = "out" if name == "epout" else "port"
        assert f"/t-a-v6-{expected}-{token}" not in marker

    name = f"t-a-v6-dns-{token}.test"
    rc, out = _tested(lab, harness, f"dig +time=2 +tries=1 @{EPIN_V6} {name} +short")
    assert rc == 0 and EPIN_V4 in out, out
    lines = [
        line for line in _dnslog(lab, harness, "epin").splitlines()
        if name in line and "query" in line
    ]
    assert lines and "from fd00:10::2" in lines[0], lines

    icmp_token = uuid.uuid4().hex[:12]
    rc, _ = _tested(lab, harness, f"ping -6 -c 1 -W 2 -p {icmp_token} {EPIN_V6}")
    assert rc == 0
    assert icmp_token in _icmp_marker(lab, harness, "epin")
    rc, _ = _tested(
        lab, harness, f"ping -6 -c 1 -W 2 -p {icmp_token} {EPOUT_V6}",
        check=False,
    )
    assert rc != 0
    assert icmp_token not in _icmp_marker(lab, harness, "epout")


def test_plan_a_ipv6_single_family_leak(
    lab: Lab, harness: str, plan_a: None
) -> None:
    """负面对照:只写 ip 族规则时 v6 转发无人管 → 界外 v6 直达(泄漏)。

    这不是放行逻辑的胜利,而是设计陷阱的实证:规则必须双族(inet)书写,
    否则另一族默认无约束。结尾恢复 inet 规则并验证拒绝复原。
    """
    token = uuid.uuid4().hex[:8]
    docker_exec(lab, harness, "nft delete table inet r10")
    push_file(lab, harness, "/opt/r10v4.nft", PLAN_A_NFT_V4_ONLY)
    docker_exec(lab, harness, "nft -f /opt/r10v4.nft")

    # v4 界外仍被拒(ip 族规则在)
    rc, _ = _tested(
        lab, harness,
        f"curl -sS -m 5 http://{EPOUT_V4}:8080/t-a-v4only-{token}",
        check=False,
    )
    assert rc != 0
    assert f"/t-a-v4only-{token}" not in _marker(lab, harness, "epout", 8080)

    # v6 界外泄漏成立:端点侧 marker 为铁证
    rc, out = _tested(
        lab, harness,
        f"curl -sS -m 5 -g 'http://[{EPOUT_V6}]:8080/t-a-v6leak-{token}'",
    )
    assert rc == 0 and "ok" in out
    assert f"/t-a-v6leak-{token}" in _marker(lab, harness, "epout", 8080)

    # 恢复 inet 双族规则后同一目标再次被拒
    docker_exec(lab, harness, "nft delete table ip r10v4")
    docker_exec(lab, harness, "nft -f /opt/r10.nft")
    rc, _ = _tested(
        lab, harness,
        f"curl -sS -m 5 -g 'http://[{EPOUT_V6}]:8080/t-a-v6fix-{token}'",
        check=False,
    )
    assert rc != 0
    assert f"/t-a-v6fix-{token}" not in _marker(lab, harness, "epout", 8080)


def test_plan_a_dns_control(lab: Lab, harness: str, plan_a: None) -> None:
    """默认 libc/显式 UDP 可用;界外与 TCP/53 不到端点。"""
    token = uuid.uuid4().hex[:8]
    rc, out = _tested(lab, harness, f"getent ahostsv4 t-a-dnsd-{token}.test")
    assert rc == 0 and EPIN_V4 in out, out
    assert f"t-a-dnsd-{token}.test" in _dnslog(lab, harness, "epin")

    rc, out = _tested(
        lab, harness,
        f"dig +time=2 +tries=1 @{EPIN_V4} t-a-dns-{token}.test +short",
    )
    assert rc == 0 and EPIN_V4 in out
    assert f"t-a-dns-{token}.test" in _dnslog(lab, harness, "epin")

    rc, out = _tested(
        lab, harness,
        f"dig +tcp +time=2 +tries=1 @{EPIN_V4} t-a-dnst-{token}.test +short",
        check=False,
    )
    assert rc != 0 or "timed out" in out or "communications error" in out
    assert f"t-a-dnst-{token}.test" not in _dnslog(lab, harness, "epin")

    rc, out = _tested(
        lab, harness,
        f"dig +time=2 +tries=1 @{EPOUT_V4} t-a-dnsx-{token}.test +short",
        check=False,
    )
    assert rc != 0 or "timed out" in out or "communications error" in out
    assert f"t-a-dnsx-{token}" not in _dnslog(lab, harness, "epout")


def test_plan_a_control_plane_separation(
    lab: Lab, harness: str, plan_a: None
) -> None:
    """控制面(编排/root ns)出站通道独立于数据面:数据面受限期间控制面
    自身可达全部端点;被测侧不得触达控制面服务(root ns :9090)。"""
    token = uuid.uuid4().hex[:8]
    rc, out = docker_exec(
        lab, harness, f"curl -sS -m 5 http://{EPOUT_V4}:8080/t-a-ctrl-{token}"
    )
    assert rc == 0 and "ok" in out
    assert f"/t-a-ctrl-{token}" in _marker(lab, harness, "epout", 8080)

    rc, _ = _tested(
        lab, harness,
        f"curl -sS -m 5 http://{CTRL_V4}:9090/t-a-ctrlx-{token}",
        check=False,
    )
    assert rc != 0
    assert f"/t-a-ctrlx-{token}" not in _marker(lab, harness, "ctrl", 9090)


def _avg_rtt(ping_out: str) -> float:
    match = re.search(r"= [\d.]+/([\d.]+)/", ping_out)
    assert match is not None, ping_out
    return float(match.group(1))


def test_plan_a_perf_overhead(lab: Lab, harness: str, plan_a: None) -> None:
    """路径时延观察,不是隔离 nft 单项成本的严格性能基准。"""
    rc, out = _tested(
        lab, harness, f"ping -c 50 -i 0.02 -q {EPIN_V4}", timeout=90
    )
    assert rc == 0
    data_plane = _avg_rtt(out)
    rc, out = docker_exec(lab, harness, f"ping -c 50 -i 0.02 -q {EPIN_V4}")
    assert rc == 0
    ctrl_plane = _avg_rtt(out)

    rc, out = _tested(
        lab, harness,
        f"set -e; for i in $(seq 30); do curl -sS -m 2 -o /dev/null "
        f"-w '%{{time_total}}\\n' http://{EPIN_V4}:8080/perf; done",
        timeout=90,
    )
    assert rc == 0
    times = [float(x) for x in out.split()]
    assert len(times) == 30
    http_avg_ms = sum(times) / len(times) * 1000
    summary = (
        f"[R10 perf-A] ping avg: data={data_plane:.3f}ms "
        f"ctrl={ctrl_plane:.3f}ms;http avg(data)={http_avg_ms:.2f}ms n=30"
    )
    lab.evidence.append(f"# 路径时延观察(非严格性能基准)\n{summary}\n")
    print(f"\n{summary}")
    assert data_plane > 0 and ctrl_plane > 0


@pytest.mark.parametrize(
    "injected_failure", [False, True], ids=["normal", "setup-failure"]
)
def test_plan_a_abrupt_exit_cleanup_unrelated_ok(
    lab: Lab, harness: str, plan_a: None, injected_failure: bool
) -> None:
    """正常/异常中断都回收 setsid 后代,不影响无关流量。"""
    token = uuid.uuid4().hex[:12]
    loop_path = f"/r10-a-abort-{token}"
    parent_path = f"/opt/r10-abort-{token}.sh"
    child_path = f"/opt/r10-abort-child-{token}.sh"
    pidfile = f"/opt/r10-abort-{token}.pid"
    push_file(
        lab,
        harness,
        child_path,
        f"""printf 'pid=%s pgid=%s pidns=%s netns=%s\\n' \\
    "$$" "$(ps -o pgid= -p $$ | tr -d ' ')" \\
    "$(readlink /proc/self/ns/pid)" "$(readlink /proc/self/ns/net)" \\
    >/tmp/r10-a-abort.child
while true; do
    curl -sS -m 1 -o /dev/null http://{EPIN_V4}:8080{loop_path}
    sleep 0.05
done
""",
    )
    push_file(
        lab,
        harness,
        parent_path,
        f"""printf 'pid=%s pgid=%s pidns=%s netns=%s\\n' \\
    "$$" "$(ps -o pgid= -p $$ | tr -d ' ')" \\
    "$(readlink /proc/self/ns/pid)" "$(readlink /proc/self/ns/net)" \\
    >/tmp/r10-a-abort.leader
python3 -c 'import ctypes; value = ctypes.c_int(); \
libc = ctypes.CDLL(None); libc.prctl(2, ctypes.byref(value)); \
print("parent_deathsig=%d" % value.value)' >>/tmp/r10-a-abort.leader
setsid bash {child_path} &
wait
""",
    )
    push_file(lab, harness, "/opt/r10-abort-token", token)
    push_file(
        lab,
        harness,
        "/opt/r10-procs.py",
        """from pathlib import Path

token = Path("/opt/r10-abort-token").read_text().strip().encode()
for entry in Path("/proc").iterdir():
    if not entry.name.isdigit():
        continue
    try:
        cmdline = (entry / "cmdline").read_bytes()
        start = (entry / "stat").read_text().split()[21]
    except OSError:
        continue
    if token in cmdline:
        print(f"{entry.name}:{start}")
""",
    )
    wrapped = TESTED_WRAP + shlex.quote(f"bash {parent_path}")
    launcher = (
        f"pid=$$; start=$(cut -d' ' -f22 /proc/$pid/stat); "
        f"echo \"$pid $start\" >{pidfile}; exec {wrapped}"
    )
    lab.run(["exec", "-d", harness, "bash", "-c", launcher])

    deadline = time.monotonic() + 10
    while True:
        hit_rc, _ = docker_exec(
            lab, harness,
            f"grep -Fq '{loop_path}' /opt/serve-epin.py.8080.hits",
            check=False,
        )
        info_rc, process_info = docker_exec(
            lab, harness,
            "cat /tmp/r10-a-abort.leader /tmp/r10-a-abort.child",
            check=False,
        )
        if hit_rc == 0 and info_rc == 0:
            break
        if time.monotonic() >= deadline:
            pytest.fail(f"方案 A 后代未实际运行: {process_info}")
        time.sleep(0.1)
    assert process_info.count("pidns=") == 2, process_info
    namespaces = set(re.findall(r"pidns=(\S+)", process_info))
    assert len(namespaces) == 1, process_info
    _, root_pidns = docker_exec(lab, harness, "readlink /proc/1/ns/pid")
    assert root_pidns.strip() not in namespaces
    groups = re.findall(r"pgid=(\d+)", process_info)
    assert len(groups) == 2 and groups[0] != groups[1], process_info

    def identities() -> dict[str, str]:
        _, out = docker_exec(lab, harness, "python3 /opt/r10-procs.py")
        return dict(line.split(":", 1) for line in out.splitlines())

    before = identities()
    assert len(before) >= 2, before
    if injected_failure:
        push_file(lab, harness, "/opt/r10-unrelated-canary.py", SERVE_PY)
        docker_exec(
            lab, harness,
            "python3 /opt/r10-unrelated-canary.py 9091 & pid=$!; "
            "echo \"$pid $(cut -d' ' -f22 /proc/$pid/stat)\" "
            ">/tmp/r10-unrelated-canary.pid",
        )
        _, canary_info = docker_exec(
            lab, harness, "cat /tmp/r10-unrelated-canary.pid"
        )
        canary_pid, canary_start = canary_info.split()
        try:
            docker_exec(
                lab, harness,
                f"curl -sS -m 5 http://127.0.0.1:9091/canary-ready-{token}",
            )
            with pytest.raises(RuntimeError, match="注入"):
                try:
                    raise RuntimeError("注入 readiness 后断言失败")
                finally:
                    _plan_a_teardown(lab, harness)
            assert not identities(), identities()
            deadline = time.monotonic() + 5
            for old_pid, old_start in before.items():
                while True:
                    _, current = docker_exec(
                        lab, harness,
                        f"if [ -r /proc/{old_pid}/stat ]; then "
                        f"cut -d' ' -f22 /proc/{old_pid}/stat; fi",
                    )
                    if current.strip() != old_start:
                        break
                    if time.monotonic() >= deadline:
                        pytest.fail(f"失败清理后原身份仍存活: {old_pid}")
                    time.sleep(0.05)
            rc, out = docker_exec(
                lab, harness,
                f"curl -sS -m 5 http://127.0.0.1:9091/canary-after-{token}",
            )
            assert rc == 0 and "ok" in out
            _, marker = docker_exec(
                lab, harness, "cat /opt/r10-unrelated-canary.py.9091.hits"
            )
            assert f"/canary-after-{token}" in marker
        finally:
            rc, _ = docker_exec(
                lab, harness,
                f"python3 /opt/r10-pidctl.py kill {canary_pid} "
                f"{canary_start} r10-unrelated-canary.py",
                check=False,
            )
            assert rc == 0
        return
    nsids = {}
    for observed_pid in before:
        rc, nspid = docker_exec(
            lab, harness, f"grep NSpid /proc/{observed_pid}/status", check=False
        )
        if rc == 0:
            nsids[observed_pid] = nspid.strip()
    lab.evidence.append(
        f"# 方案 A crash 运行证据\n{process_info}\n"
        f"identities={before}\n{nsids=}\n"
    )
    init_candidates = [
        observed_pid for observed_pid, nspid in nsids.items()
        if nspid.split()[-1] == "1"
    ]
    assert len(init_candidates) == 1, nsids
    init_pid = init_candidates[0]
    push_file(
        lab, harness, f"/opt/r10-abort-init-{token}.pid",
        f"{init_pid} {before[init_pid]}\n",
    )
    _, pid_info = docker_exec(lab, harness, f"cat {pidfile}")
    pid, start = pid_info.split()
    docker_exec(
        lab, harness,
        f"python3 /opt/r10-pidctl.py kill {pid} {start} {token}",
    )
    docker_exec(
        lab, harness,
        f"python3 /opt/r10-pidctl.py kill {init_pid} "
        f"{before[init_pid]} {token}",
    )
    deadline = time.monotonic() + 5
    while True:
        remaining = identities()
        if not remaining:
            break
        if time.monotonic() >= deadline:
            for remaining_pid in remaining:
                docker_exec(
                    lab, harness,
                    f"ps -p {remaining_pid} -o pid,ppid,pgid,stat,args; "
                    f"grep NSpid /proc/{remaining_pid}/status; "
                    f"readlink /proc/{remaining_pid}/ns/pid",
                    check=False,
                )
            pytest.fail(f"crash token 进程未全部消失: {remaining}")
        time.sleep(0.05)
    deadline = time.monotonic() + 5
    for old_pid, old_start in before.items():
        while True:
            _, current = docker_exec(
                lab, harness,
                f"if [ -r /proc/{old_pid}/stat ]; then "
                f"cut -d' ' -f22 /proc/{old_pid}/stat; fi",
            )
            if current.strip() != old_start:
                break
            if time.monotonic() >= deadline:
                pytest.fail(f"原 crash 身份仍存活: {old_pid} {old_start}")
            time.sleep(0.05)

    time.sleep(0.2)
    stopped_count = _marker(lab, harness, "epin", 8080).count(loop_path)
    assert stopped_count > 0
    time.sleep(0.5)
    assert _marker(lab, harness, "epin", 8080).count(loop_path) == stopped_count

    docker_exec(lab, harness, "ip netns del tested")
    docker_exec(lab, harness, "nft delete table inet r10")
    docker_exec(
        lab, harness,
        "test ! -e /run/netns/tested && test -e /run/netns/epin"
        " && test -e /run/netns/epout",
    )
    _, out = docker_exec(lab, harness, "ip link show")
    assert "v-test" not in out
    rc, _ = docker_exec(lab, harness, "nft list table inet r10", check=False)
    assert rc != 0
    for ep, name in ((EPIN_V4, "epin"), (EPOUT_V4, "epout")):
        rc, out = docker_exec(
            lab, harness, f"curl -sS -m 5 http://{ep}:8080/t-a-after-{token}"
        )
        assert rc == 0 and "ok" in out
        assert f"/t-a-after-{token}" in _marker(lab, harness, name, 8080)


# ---------------------------------------------------------------------------
# R10-B · 方案 B:独立容器(docker 网络;过滤点在出口网关容器)
# ---------------------------------------------------------------------------

B_NET_IN = "172.30.0.0/24"
B_NET_OUT = "172.31.0.0/24"
B_NET_IN6 = "fd00:30::/64"
B_NET_OUT6 = "fd00:31::/64"
B_GW_IN = "172.30.0.2"
B_GW_OUT = "172.31.0.2"
B_GW_IN6 = "fd00:30::2"
B_GW_OUT6 = "fd00:31::2"
B_TESTED_IP = "172.30.0.10"
B_TESTED_IP6 = "fd00:30::10"
B_EPIN = "172.31.0.11"
B_EPIN6 = "fd00:31::11"
B_EPOUT = "172.31.0.12"
B_EPOUT6 = "fd00:31::12"
B_BYSTANDER = "172.31.0.20"
B_BYSTANDER6 = "fd00:31::20"
ISO_NET = "172.29.0.0/24"
ISO_EP = "172.29.0.11"
ISO_TESTED = "172.29.0.10"
NO_PROXY_ARGS = ["--env", "NO_PROXY=*", "--env", "no_proxy=*"]
# dnsmasq 查询日志(一次性实验容器内路径,容器销毁即弃)
B_DNS_LOG = "/tmp/dns.log"  # noqa: S108

# 原始方向逐条放行,仅 out→in 的 established 回包可返回;input 护 gw 控制面。
PLAN_B_GW_NFT = """\
table inet r10 {
    chain forward {
        type filter hook forward priority filter; policy drop;
        iifname "@OUT_IF@" oifname "@IN_IF@" ct state established accept
        iifname "@IN_IF@" oifname "@OUT_IF@" \\
            ip daddr @EPIN@ tcp dport 8080 accept
        iifname "@IN_IF@" oifname "@OUT_IF@" \\
            ip daddr @EPIN@ udp dport 53 accept
        iifname "@IN_IF@" oifname "@OUT_IF@" \\
            ip daddr @EPIN@ icmp type echo-request accept
        iifname "@IN_IF@" oifname "@OUT_IF@" \\
            ip6 daddr @EPIN6@ tcp dport 8080 accept
        iifname "@IN_IF@" oifname "@OUT_IF@" \\
            ip6 daddr @EPIN6@ udp dport 53 accept
        iifname "@IN_IF@" oifname "@OUT_IF@" \\
            ip6 daddr @EPIN6@ icmpv6 type echo-request accept
    }
    chain input {
        type filter hook input priority filter; policy accept;
        iifname "@IN_IF@" \\
            icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept
        iifname "@IN_IF@" drop
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "@OUT_IF@" ip saddr @NET_IN@ masquerade
        oifname "@OUT_IF@" ip6 saddr @NET_IN6@ masquerade
    }
}
"""


UNTRUSTED_CONTAINER_ARGS = [
    "--user", "65534:65534",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges:true",
    "--sysctl", "net.ipv4.ping_group_range=0 65534",
]


@pytest.fixture(scope="module")
def plan_b(lab: Lab, lab_image: str) -> Iterator[dict[str, str]]:
    # 形态 2 使用普通桥接网与独立 gw;net-in 只容纳 tested/gw。
    # 工作进程无 NET_ADMIN/NET_RAW,不能回指 Docker 网桥或构造二层帧。
    # 路由只由编排面注入;宿主网桥上不得提供管理面服务。
    net_in = lab.name("bin")
    net_out = lab.name("bout")
    lab.run(
        [
            "network", "create", "--ipv6", *lab.label_args(),
            "--subnet", B_NET_IN, "--subnet", B_NET_IN6, net_in,
        ]
    )
    lab.add_network(net_in)
    lab.run(
        [
            "network", "create", "--ipv6", *lab.label_args(),
            "--subnet", B_NET_OUT, "--subnet", B_NET_OUT6, net_out,
        ]
    )
    lab.add_network(net_out)

    gw = lab.name("gw")
    lab.run(
        [
            "run", "-d", "--name", gw, "--init", "--network", net_in,
            "--ip", B_GW_IN, "--ip6", B_GW_IN6, "--cap-add", "NET_ADMIN",
            "--sysctl", "net.ipv4.ip_forward=1",
            "--sysctl", "net.ipv6.conf.all.forwarding=1",
            *NO_PROXY_ARGS, *lab.label_args(), lab_image, "sleep", "infinity",
        ]
    )
    lab.add_container(gw)
    lab.run(
        [
            "network", "connect", net_out, "--ip", B_GW_OUT,
            "--ip6", B_GW_OUT6, gw,
        ]
    )

    names = {"gw": gw, "net_in": net_in, "net_out": net_out}
    for role, ip, ip6 in (
        ("bepin", B_EPIN, B_EPIN6),
        ("bepout", B_EPOUT, B_EPOUT6),
        ("bystander", B_BYSTANDER, B_BYSTANDER6),
    ):
        name = lab.name(role)
        lab.run(
            [
                "run", "-d", "--name", name, "--init", "--network", net_out,
                "--ip", ip, "--ip6", ip6, *NO_PROXY_ARGS, *lab.label_args(),
                lab_image, "sleep", "infinity",
            ]
        )
        lab.add_container(name)
        names[role] = name

    tested = lab.name("testedb")
    lab.run(
        [
            "run", "-d", "--name", tested, "--init", "--network", net_in,
            "--ip", B_TESTED_IP, "--ip6", B_TESTED_IP6, "--dns", B_EPIN,
            *UNTRUSTED_CONTAINER_ARGS, *NO_PROXY_ARGS, *lab.label_args(),
            lab_image, "sleep", "infinity",
        ]
    )
    lab.add_container(tested)
    names["tested"] = tested

    # 形态 1 仅证明网络成员级隔离,不承诺成员之间的 CIDR/端口过滤。
    net_iso = lab.name("iso")
    lab.run(
        [
            "network", "create", "--internal", *lab.label_args(),
            "--subnet", ISO_NET, net_iso,
        ]
    )
    lab.add_network(net_iso)
    iso_ep = lab.name("iso_ep")
    lab.run(
        [
            "run", "-d", "--name", iso_ep, "--init", "--network", net_iso,
            "--ip", ISO_EP, *NO_PROXY_ARGS, *lab.label_args(),
            lab_image, "sleep", "infinity",
        ]
    )
    lab.add_container(iso_ep)
    names["iso_ep"] = iso_ep
    iso_tested = lab.name("iso_tested")
    lab.run(
        [
            "run", "-d", "--name", iso_tested, "--init", "--network", net_iso,
            "--ip", ISO_TESTED, "--dns", B_EPIN,
            *UNTRUSTED_CONTAINER_ARGS, *NO_PROXY_ARGS, *lab.label_args(),
            lab_image, "sleep", "infinity",
        ]
    )
    lab.add_container(iso_tested)
    names["iso_tested"] = iso_tested

    for role in ("bepin", "bepout", "iso_ep"):
        push_file(lab, names[role], "/opt/serve.py", SERVE_PY)
        lab.run(
            ["exec", "-d", names[role], "python3", "/opt/serve.py", "8080"]
        )
    lab.run(["exec", "-d", names["bepin"], "python3", "/opt/serve.py", "8081"])
    lab.run(["exec", "-d", names["iso_ep"], "python3", "/opt/serve.py", "8081"])
    for role, answer in (("bepin", B_EPIN), ("bepout", B_EPOUT)):
        lab.run(
            [
                "exec", "-d", names[role], "bash", "-c",
                dnsmasq_cmd(answer, B_DNS_LOG),
            ]
        )
        push_file(lab, names[role], "/opt/icmp.py", ICMP_TAP_PY)
        lab.run(
            [
                "exec", "-d", names[role],
                "python3", "/opt/icmp.py",
            ]
        )
    push_file(lab, gw, "/opt/serve-ctrl.py", SERVE_PY)
    lab.run(["exec", "-d", gw, "python3", "/opt/serve-ctrl.py", "9090"])

    observer = lab.name("observer")
    lab.run(
        [
            "run", "-d", "--name", observer, "--init", "--network", "none",
            "--pid", "host", "--cap-add", "SYS_PTRACE",
            *NO_PROXY_ARGS, *lab.label_args(), lab_image, "sleep", "infinity",
        ]
    )
    lab.add_container(observer)
    names["observer"] = observer

    # ip -br 的 @ifN 是对端显示信息,不是内核接口名的一部分。
    _, out = docker_exec(lab, gw, "ip -4 -br addr show")
    in_if = out_if = None
    for line in out.splitlines():
        if B_GW_IN in line:
            in_if = line.split()[0].split("@", 1)[0]
        if B_GW_OUT in line:
            out_if = line.split()[0].split("@", 1)[0]
    assert in_if and out_if, out
    lab.run(
        ["exec", "-i", gw, "nft", "-f", "-"],
        input_text=(
            PLAN_B_GW_NFT.replace("@IN_IF@", in_if)
            .replace("@OUT_IF@", out_if)
            .replace("@EPIN6@", B_EPIN6)
            .replace("@EPIN@", B_EPIN)
            .replace("@NET_IN6@", B_NET_IN6)
            .replace("@NET_IN@", B_NET_IN)
        ),
    )
    lab.run(
        [
            "exec", "--privileged", "--user", "0", tested,
            "ip", "route", "replace", "default", "via", B_GW_IN,
        ]
    )
    lab.run(
        [
            "exec", "--privileged", "--user", "0", tested,
            "ip", "-6", "route", "replace", "default", "via", B_GW_IN6,
        ]
    )

    for role in ("bepin", "bepout"):
        docker_exec(lab, names[role], "cat /opt/icmp.py.ready")
    docker_exec(
        lab, names["bystander"],
        f"ping -c 1 -W 2 -p aa {B_EPIN} && ping -c 1 -W 2 -p aa {B_EPOUT}"
        f" && ping -6 -c 1 -W 2 -p aa {B_EPIN6}"
        f" && ping -6 -c 1 -W 2 -p aa {B_EPOUT6}",
    )
    docker_exec(
        lab, gw,
        f"curl --noproxy '*' -sS -m 5 -o /dev/null "
        f"http://{B_GW_IN}:9090/ready-ctrl",
    )
    docker_exec(
        lab, tested,
        f"curl --noproxy '*' -sS -m 5 -o /dev/null http://{B_EPIN}:8080/ready-b",
    )
    docker_exec(
        lab, names["iso_tested"],
        f"curl --noproxy '*' -sS -m 5 -o /dev/null http://{ISO_EP}:8080/ready-iso",
    )
    docker_exec(
        lab, names["bystander"],
        f"curl --noproxy '*' -sS -m 5 -o /dev/null http://{B_EPOUT}:8080/ready-out"
        f" && curl --noproxy '*' -sS -m 5 -o /dev/null http://{B_EPIN}:8081/ready-port",
    )
    docker_exec(
        lab, tested,
        f"dig +time=2 +tries=3 @{B_EPIN} ready.test +short"
        f" | grep -q '^{B_EPIN}$'",
    )
    docker_exec(
        lab, names["bystander"],
        f"dig +time=2 +tries=3 @{B_EPOUT} ready-out.test +short"
        f" | grep -q '^{B_EPOUT}$' && "
        f"dig +tcp +time=2 +tries=3 @{B_EPIN} ready-tcp.test +short"
        f" | grep -q '^{B_EPIN}$'",
    )
    try:
        yield names
    finally:
        errors: list[str] = []
        for role in ("tested", "gw"):
            if names[role] not in lab.containers:
                continue
            try:
                lab.run(["rm", "-f", names[role]])
                lab.containers.remove(names[role])
            except Exception as exc:
                errors.append(f"{role} 清理失败: {exc!r}")
        if net_in in lab.networks:
            try:
                lab.run(["network", "rm", net_in])
                lab.networks.remove(net_in)
            except Exception as exc:
                errors.append(f"net-in 清理失败: {exc!r}")
        token = uuid.uuid4().hex[:8]
        for ep, role in ((B_EPIN, "bepin"), (B_EPOUT, "bepout")):
            try:
                rc, out = _bexec(
                    lab, names, "bystander",
                    f"curl -sS -m 5 http://{ep}:8080/t-b-cleanup-{token}",
                )
                assert rc == 0 and "ok" in out
                assert f"/t-b-cleanup-{token}" in _bmarker(lab, names, role)
            except Exception as exc:
                errors.append(f"bystander/{role} 健康检查失败: {exc!r}")
        if errors:
            pytest.fail("\n".join(errors))


def _bexec(
    lab: Lab,
    names: dict[str, str],
    role: str,
    cmd: str,
    *,
    timeout: int = 60,
    check: bool = True,
) -> tuple[int, str]:
    return docker_exec(lab, names[role], cmd, timeout=timeout, check=check)


def _bmarker(lab: Lab, names: dict[str, str], role: str, port: int = 8080) -> str:
    _, out = _bexec(lab, names, role, f"cat /opt/serve.py.{port}.hits")
    return out


def _bdnslog(lab: Lab, names: dict[str, str], role: str) -> str:
    _, out = _bexec(lab, names, role, f"cat {B_DNS_LOG}")
    return out


def _bicmp(lab: Lab, names: dict[str, str], role: str) -> str:
    _, out = _bexec(lab, names, role, "cat /opt/icmp.py.hits")
    return out


def test_plan_b_form1_internal_isolation(lab: Lab, plan_b: dict) -> None:
    """internal 只约束网外出口;同网 8080/8081 均可达,不是端口护栏。"""
    token = uuid.uuid4().hex[:8]
    for port in (8080, 8081):
        rc, out = _bexec(
            lab, plan_b, "iso_tested",
            f"curl -sS -m 5 http://{ISO_EP}:{port}/t-b1-in-{port}-{token}",
        )
        assert rc == 0 and "ok" in out
        assert f"/t-b1-in-{port}-{token}" in _bmarker(
            lab, plan_b, "iso_ep", port
        )

    _bexec(lab, plan_b, "iso_tested", "ip route show")
    rc, _ = _bexec(
        lab, plan_b, "iso_tested",
        f"curl -sS -m 5 http://{B_EPOUT}:8080/t-b1-out-{token}",
        check=False,
    )
    assert rc != 0
    assert f"/t-b1-out-{token}" not in _bmarker(lab, plan_b, "bepout")
    rc, out = _bexec(
        lab, plan_b, "bystander",
        f"curl -sS -m 5 http://{B_EPOUT}:8080/t-b1-health-{token}",
    )
    assert rc == 0 and "ok" in out
    assert f"/t-b1-health-{token}" in _bmarker(lab, plan_b, "bepout")


def test_plan_b_form1_embedded_dns(lab: Lab, plan_b: dict) -> None:
    """internal 的 daemon DNS 拒绝外发;查询不能抵达合成上游。"""
    token = uuid.uuid4().hex[:8]
    name = f"t-b1-dnsd-{token}.test"
    rc, out = _bexec(
        lab, plan_b, "iso_tested",
        f"dig +time=3 +tries=1 @127.0.0.11 {name}",
        check=False,
    )
    assert "status: SERVFAIL" in out, out
    assert name not in _bdnslog(lab, plan_b, "bepin")
    lab.evidence.append(
        f"# 形态 1 默认 DNS:daemon 返回 SERVFAIL,合成上游无查询\n{out}\n"
    )


def test_plan_b_form2_allow_deny_bash(lab: Lab, plan_b: dict) -> None:
    """形态 2 bash:界内 /32+端口放行;界外 /32 拒绝;同 IP 异端口拒绝。"""
    token = uuid.uuid4().hex[:8]
    rc, out = _bexec(
        lab, plan_b, "tested",
        f"curl -sS -m 5 http://{B_EPIN}:8080/t-b2-bash-in-{token}",
    )
    assert rc == 0 and "ok" in out
    assert f"/t-b2-bash-in-{token}" in _bmarker(lab, plan_b, "bepin")

    rc, _ = _bexec(
        lab, plan_b, "tested",
        f"curl -sS -m 5 http://{B_EPOUT}:8080/t-b2-bash-out-{token}",
        check=False,
    )
    assert rc != 0
    assert f"/t-b2-bash-out-{token}" not in _bmarker(lab, plan_b, "bepout")

    rc, _ = _bexec(
        lab, plan_b, "tested",
        f"curl -sS -m 5 http://{B_EPIN}:8081/t-b2-bash-port-{token}",
        check=False,
    )
    assert rc != 0
    assert f"/t-b2-bash-port-{token}" not in _bmarker(
        lab, plan_b, "bepin", 8081
    )

    icmp_token = uuid.uuid4().hex[:12]
    rc, _ = _bexec(
        lab, plan_b, "tested", f"ping -c 1 -W 2 -p {icmp_token} {B_EPIN}"
    )
    assert rc == 0
    assert icmp_token in _bicmp(lab, plan_b, "bepin")
    rc, _ = _bexec(
        lab, plan_b, "tested",
        f"ping -c 1 -W 2 -p {icmp_token} {B_EPOUT}",
        check=False,
    )
    assert rc != 0
    assert icmp_token not in _bicmp(lab, plan_b, "bepout")


def test_plan_b_form2_pty_boundary(lab: Lab, plan_b: dict) -> None:
    """形态 2 PTY(docker exec -t 分配伪终端):与裸 exec 同边界。"""
    token = uuid.uuid4().hex[:8]
    rc, out = lab.run(
        [
            "exec", "-t", plan_b["tested"], "bash", "-c",
            f"curl -sS -m 5 http://{B_EPIN}:8080/t-b2-pty-in-{token}",
        ]
    )
    assert rc == 0 and "ok" in out
    assert f"/t-b2-pty-in-{token}" in _bmarker(lab, plan_b, "bepin")

    rc, _ = lab.run(
        [
            "exec", "-t", plan_b["tested"], "bash", "-c",
            f"curl -sS -m 5 http://{B_EPOUT}:8080/t-b2-pty-out-{token}",
        ],
        check=False,
    )
    assert rc != 0
    assert f"/t-b2-pty-out-{token}" not in _bmarker(lab, plan_b, "bepout")


def test_plan_b_form2_subprocess_no_escape(lab: Lab, plan_b: dict) -> None:
    """普通子进程同 netns;非 root/无 capabilities 阻止命名空间与 raw 逃逸。"""
    push_file(lab, plan_b["tested"], "/opt/nsprobe.sh", _SUBPROCESS_PROBE)
    rc, out = _bexec(lab, plan_b, "tested", "bash /opt/nsprobe.sh")
    assert rc == 0
    assert len(re.findall(r"=(net:\[\d+\])", out)) == 4, out
    assert len(set(re.findall(r"=(net:\[\d+\])", out))) == 1, out

    for command in (
        "unshare -n true",
        "unshare --mount true",
        "nsenter --net=/proc/1/ns/net true",
    ):
        rc, out = _bexec(lab, plan_b, "tested", command, check=False)
        assert rc != 0, f"命名空间操作意外成功: {command}\n{out}"
    rc, out = _bexec(
        lab, plan_b, "tested",
        "echo uid=$(id -u); grep -E 'Cap(Bnd|Prm|Eff)|NoNewPrivs' "
        "/proc/self/status",
    )
    assert rc == 0
    assert re.search(r"^uid=65534$", out, re.MULTILINE), out
    assert re.search(r"^NoNewPrivs:\s*1$", out, re.MULTILINE), out
    caps = re.findall(r"^Cap(?:Bnd|Prm|Eff):\s*([0-9a-fA-F]+)$", out, re.MULTILINE)
    assert len(caps) == 3 and all(int(value, 16) == 0 for value in caps), out

    push_file(
        lab,
        plan_b["tested"],
        "/opt/rawprobe.py",
        """import socket

for name, args in (
    ("inet", (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)),
    ("packet", (socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))),
):
    try:
        sock = socket.socket(*args)
    except OSError as exc:
        print(f"{name}=denied:{exc.errno}")
    else:
        print(f"{name}=allowed")
        sock.close()
""",
    )
    rc, out = _bexec(lab, plan_b, "tested", "python3 /opt/rawprobe.py")
    assert rc == 0
    assert "inet=denied:" in out and "packet=denied:" in out, out
    assert "allowed" not in out, out


def test_plan_b_form2_tamper_resistance(lab: Lab, plan_b: dict) -> None:
    """改本地规则/地址/路由均失败,gw 哈希与端点允许/拒绝保持不变。"""
    _, hash_before = _bexec(
        lab, plan_b, "gw", "set -o pipefail; nft list ruleset | sha256sum"
    )
    for command in (
        "nft flush ruleset",
        "nft add table inet localaccept",
        "ip addr add 172.31.99.99/24 dev eth0",
        f"ip route replace default via {B_NET_IN[:-4]}1",
    ):
        rc, out = _bexec(lab, plan_b, "tested", command, check=False)
        assert rc != 0, f"篡改操作意外成功: {command}\n{out}"

    _, route = _bexec(lab, plan_b, "tested", f"ip route get {B_EPIN}")
    assert f"via {B_GW_IN}" in route, route
    rc, _ = _bexec(
        lab, plan_b, "tested", "test -S /var/run/docker.sock", check=False
    )
    assert rc != 0
    rc, _ = _bexec(
        lab, plan_b, "tested", "test -w /etc/resolv.conf", check=False
    )
    assert rc != 0

    token = uuid.uuid4().hex[:8]
    rc, out = _bexec(
        lab, plan_b, "tested",
        f"curl -sS -m 5 http://{B_EPIN}:8080/t-b2-tamp-in-{token}",
    )
    assert rc == 0 and "ok" in out
    assert f"/t-b2-tamp-in-{token}" in _bmarker(lab, plan_b, "bepin")
    rc, _ = _bexec(
        lab, plan_b, "tested",
        f"curl -sS -m 5 http://{B_EPOUT}:8080/t-b2-tamp-out-{token}",
        check=False,
    )
    assert rc != 0
    assert f"/t-b2-tamp-out-{token}" not in _bmarker(lab, plan_b, "bepout")
    _, hash_after = _bexec(
        lab, plan_b, "gw", "set -o pipefail; nft list ruleset | sha256sum"
    )
    assert hash_before == hash_after, "gw 规则被被测容器改动"


def test_plan_b_form2_dns_paths(lab: Lab, plan_b: dict) -> None:
    """默认 Docker DNS 与显式 UDP 均实测经 gw;界外和 TCP/53 不到端点。"""
    token = uuid.uuid4().hex[:8]
    _, resolv = _bexec(lab, plan_b, "tested", "cat /etc/resolv.conf")
    assert "nameserver 127.0.0.11" in resolv, resolv
    rc, out = _bexec(
        lab, plan_b, "tested",
        f"dig +time=3 +tries=1 t-b2-dnsd-{token}.test +short",
    )
    assert rc == 0 and B_EPIN in out, out
    proxy_lines = [
        line for line in _bdnslog(lab, plan_b, "bepin").splitlines()
        if f"t-b2-dnsd-{token}.test" in line and "query" in line
    ]
    assert proxy_lines, _bdnslog(lab, plan_b, "bepin")
    proxy_src = re.search(r"from ([\d.]+)", proxy_lines[0])
    assert proxy_src is not None
    assert proxy_src.group(1) == B_GW_OUT, proxy_lines[0]
    lab.evidence.append(
        "# 默认 Docker DNS:本环境 daemon 上游仍经 gw masquerade;"
        "不推广到其他 daemon 路径\n"
        f"{proxy_lines[0]}\n"
    )

    rc, out = _bexec(
        lab, plan_b, "tested",
        f"dig +time=3 +tries=1 @{B_EPIN} t-b2-dnsq-{token}.test +short",
    )
    assert rc == 0 and B_EPIN in out, out
    direct_lines = [
        line for line in _bdnslog(lab, plan_b, "bepin").splitlines()
        if f"t-b2-dnsq-{token}.test" in line and "query" in line
    ]
    assert direct_lines, _bdnslog(lab, plan_b, "bepin")
    direct_src = re.search(r"from ([\d.]+)", direct_lines[0])
    assert direct_src is not None
    assert direct_src.group(1) == B_GW_OUT, (
        f"显式 @界内解析器 应经 gw masquerade({B_GW_OUT}):{direct_lines[0]}"
    )

    rc, out = _bexec(
        lab, plan_b, "tested",
        f"dig +tcp +time=2 +tries=1 @{B_EPIN} t-b2-dnst-{token}.test +short",
        check=False,
    )
    assert rc != 0 or "timed out" in out or "communications error" in out
    assert f"t-b2-dnst-{token}.test" not in _bdnslog(lab, plan_b, "bepin")

    rc, out = _bexec(
        lab, plan_b, "tested",
        f"dig +time=2 +tries=1 @{B_EPOUT} t-b2-dnsx-{token}.test +short",
        check=False,
    )
    assert rc != 0 or "timed out" in out or "communications error" in out
    assert f"t-b2-dnsx-{token}.test" not in _bdnslog(lab, plan_b, "bepout")


def test_plan_b_form2_control_plane_and_bystander(
    lab: Lab, plan_b: dict
) -> None:
    """gw 控制面可独立出站;tested 不可入控制面;旁观者不受回收影响。"""
    token = uuid.uuid4().hex[:8]
    for ep, role in ((B_EPIN, "bepin"), (B_EPOUT, "bepout")):
        rc, out = _bexec(
            lab, plan_b, "bystander",
            f"curl -sS -m 5 http://{ep}:8080/t-b2-by-{token}",
        )
        assert rc == 0 and "ok" in out
        assert f"/t-b2-by-{token}" in _bmarker(lab, plan_b, role)

    rc, out = _bexec(
        lab, plan_b, "gw",
        f"curl -sS -m 5 http://{B_EPOUT}:8080/t-b2-ctrl-out-{token}",
    )
    assert rc == 0 and "ok" in out
    assert f"/t-b2-ctrl-out-{token}" in _bmarker(lab, plan_b, "bepout")
    rc, _ = _bexec(
        lab, plan_b, "tested",
        f"curl -sS -m 5 http://{B_GW_IN}:9090/t-b2-ctrl-in-{token}",
        check=False,
    )
    assert rc != 0
    _, marker = _bexec(lab, plan_b, "gw", "cat /opt/serve-ctrl.py.9090.hits")
    assert f"/t-b2-ctrl-in-{token}" not in marker


def test_plan_b_ipv6_enforced(lab: Lab, plan_b: dict) -> None:
    """双栈 gw 的 v6 HTTP/端口/DNS/ICMP 与 v4 使用同一授权子集。"""
    token = uuid.uuid4().hex[:8]
    rc, out = _bexec(
        lab, plan_b, "tested",
        f"curl -sS -m 5 -g 'http://[{B_EPIN6}]:8080/t-b-v6-in-{token}'",
    )
    assert rc == 0 and "ok" in out
    assert f"/t-b-v6-in-{token}" in _bmarker(lab, plan_b, "bepin")
    for url, role, marker, path in (
        (
            f"http://[{B_EPOUT6}]:8080/t-b-v6-out-{token}",
            "bepout", 8080, f"/t-b-v6-out-{token}",
        ),
        (
            f"http://[{B_EPIN6}]:8081/t-b-v6-port-{token}",
            "bepin", 8081, f"/t-b-v6-port-{token}",
        ),
    ):
        rc, _ = _bexec(
            lab, plan_b, "tested", f"curl -sS -m 5 -g '{url}'", check=False
        )
        assert rc != 0
        assert path not in _bmarker(lab, plan_b, role, marker)

    name = f"t-b-v6-dns-{token}.test"
    rc, out = _bexec(
        lab, plan_b, "tested", f"dig +time=2 +tries=1 @{B_EPIN6} {name} +short"
    )
    assert rc == 0 and B_EPIN in out, out
    lines = [
        line for line in _bdnslog(lab, plan_b, "bepin").splitlines()
        if name in line and "query" in line
    ]
    assert lines and f"from {B_GW_OUT6}" in lines[0], lines
    rc, out = _bexec(
        lab, plan_b, "tested",
        f"dig +time=2 +tries=1 @{B_EPOUT6} t-b-v6-dnsx-{token}.test +short",
        check=False,
    )
    assert rc != 0 or "timed out" in out or "communications error" in out
    assert f"t-b-v6-dnsx-{token}.test" not in _bdnslog(lab, plan_b, "bepout")

    icmp_token = uuid.uuid4().hex[:12]
    rc, _ = _bexec(
        lab, plan_b, "tested", f"ping -6 -c 1 -W 2 -p {icmp_token} {B_EPIN6}"
    )
    assert rc == 0
    assert icmp_token in _bicmp(lab, plan_b, "bepin")
    rc, _ = _bexec(
        lab, plan_b, "tested",
        f"ping -6 -c 1 -W 2 -p {icmp_token} {B_EPOUT6}",
        check=False,
    )
    assert rc != 0
    assert icmp_token not in _bicmp(lab, plan_b, "bepout")


def test_plan_b_perf_overhead(lab: Lab, plan_b: dict) -> None:
    """路径时延观察,不是严格 isolating nft 单项成本的性能基准。"""
    rc, out = _bexec(
        lab, plan_b, "bystander", f"ping -c 50 -i 0.02 -q {B_EPIN}",
        timeout=90,
    )
    assert rc == 0
    direct = _avg_rtt(out)
    rc, out = _bexec(
        lab, plan_b, "tested", f"ping -c 50 -i 0.02 -q {B_EPIN}", timeout=90
    )
    assert rc == 0
    via_gw = _avg_rtt(out)

    def http_avg(role: str) -> float:
        rc, out = _bexec(
            lab, plan_b, role,
            f"set -e; for i in $(seq 30); do curl -sS -m 2 -o /dev/null "
            f"-w '%{{time_total}}\\n' http://{B_EPIN}:8080/perf; done",
            timeout=90,
        )
        assert rc == 0
        times = [float(x) for x in out.split()]
        assert len(times) == 30
        return sum(times) / len(times) * 1000

    direct_http = http_avg("bystander")
    via_http = http_avg("tested")
    summary = (
        f"[R10 perf-B] ping avg: direct={direct:.3f}ms "
        f"via-gw={via_gw:.3f}ms; http avg: direct={direct_http:.2f}ms "
        f"via-gw={via_http:.2f}ms n=30"
    )
    lab.evidence.append(f"# 路径时延观察(非严格性能基准)\n{summary}\n")
    print(f"\n{summary}")
    assert direct > 0 and via_gw > 0


def test_plan_b_abrupt_exit_cleanup_unrelated_ok(
    lab: Lab, plan_b: dict
) -> None:
    """独立 crash 容器的 setsid 后代随容器回收,旁观者和 gw 不受影响。"""
    token = uuid.uuid4().hex[:12]
    crash = lab.name("crash")
    lab.run(
        [
            "run", "-d", "--name", crash, "--init", "--network",
            plan_b["net_in"], "--ip", "172.30.0.11", "--ip6", "fd00:30::11",
            "--dns", B_EPIN,
            *UNTRUSTED_CONTAINER_ARGS, *NO_PROXY_ARGS, *lab.label_args(),
            lab.image, "sleep", "infinity",
        ]
    )
    lab.add_container(crash)
    crash_names = {**plan_b, "crash": crash}
    loop_path = f"/r10-b-abort-{token}"
    try:
        script_path = f"/opt/r10-b-abort-{token}.sh"
        child_path = f"/opt/r10-b-abort-child-{token}.sh"
        push_file(
            lab,
            crash,
            child_path,
            f"""printf 'pid=%s pgid=%s pidns=%s netns=%s\\n' \\
    "$$" "$(ps -o pgid= -p $$ | tr -d ' ')" \\
    "$(readlink /proc/self/ns/pid)" "$(readlink /proc/self/ns/net)" \\
    >/tmp/r10-b-abort.child
while true; do
    curl -sS -m 1 -o /dev/null http://{B_EPIN}:8080{loop_path}
    sleep 0.05
done
""",
        )
        push_file(
            lab,
            crash,
            script_path,
            f"""printf 'pid=%s pgid=%s pidns=%s netns=%s\\n' \\
    "$$" "$(ps -o pgid= -p $$ | tr -d ' ')" \\
    "$(readlink /proc/self/ns/pid)" "$(readlink /proc/self/ns/net)" \\
    >/tmp/r10-b-abort.leader
setsid bash {child_path} &
wait
""",
        )
        lab.run(
            [
                "exec", "--privileged", "--user", "0", crash,
                "ip", "route", "replace", "default", "via", B_GW_IN,
            ]
        )
        lab.run(
            [
                "exec", "--privileged", "--user", "0", crash,
                "ip", "-6", "route", "replace", "default", "via", B_GW_IN6,
            ]
        )
        lab.run(["exec", "-d", crash, "bash", script_path])

        deadline = time.monotonic() + 10
        while True:
            hit_rc, _ = docker_exec(
                lab, plan_b["bepin"],
                f"grep -Fq '{loop_path}' /opt/serve.py.8080.hits",
                check=False,
            )
            info_rc, process_info = _bexec(
                lab, crash_names, "crash",
                "cat /tmp/r10-b-abort.leader /tmp/r10-b-abort.child",
                check=False,
            )
            if hit_rc == 0 and info_rc == 0:
                break
            if time.monotonic() >= deadline:
                pytest.fail(f"crash 后代未实际运行: {process_info}")
            time.sleep(0.1)
        assert process_info.count("pidns=") == 2, process_info
        assert len(set(re.findall(r"pidns=(\S+)", process_info))) == 1
        assert len(set(re.findall(r"netns=(\S+)", process_info))) == 1
        groups = re.findall(r"pgid=(\d+)", process_info)
        assert len(groups) == 2 and groups[0] != groups[1], process_info

        _, top = lab.run(["top", crash, "-eo", "pid,ppid,pgid,args"])
        observed: dict[str, tuple[str, str]] = {}
        for line in top.splitlines():
            if token not in line:
                continue
            parts = line.split(None, 3)
            if len(parts) == 4 and parts[0].isdigit():
                _, start = docker_exec(
                    lab, plan_b["observer"], f"cut -d' ' -f22 /proc/{parts[0]}/stat"
                )
                observed[parts[0]] = (start.strip(), parts[2])
        assert len(observed) >= 2, top
        assert len({pgid for _, pgid in observed.values()}) >= 2, top
        lab.evidence.append(
            f"# crash 运行证据\n{process_info}\n{top}\nidentities={observed}\n"
        )
        _, gateway_before = _bexec(
            lab, plan_b, "gw", "set -o pipefail; nft list ruleset | sha256sum"
        )

        lab.run(["kill", "--signal", "KILL", crash])
        lab.run(["rm", "-f", crash])
        lab.containers.remove(crash)
        _, out = lab.run(["ps", "-a", "--format", "{{.Names}}"])
        assert crash not in out.split()
        deadline = time.monotonic() + 5
        for pid, (start, _) in observed.items():
            while True:
                _, current = docker_exec(
                    lab, plan_b["observer"],
                    f"if [ -r /proc/{pid}/stat ]; then "
                    f"cut -d' ' -f22 /proc/{pid}/stat; fi",
                )
                if current.strip() != start:
                    break
                if time.monotonic() >= deadline:
                    pytest.fail(f"原 crash 身份仍存活: {pid} {start}")
                time.sleep(0.05)

        time.sleep(0.2)
        stopped_count = _bmarker(lab, plan_b, "bepin").count(loop_path)
        assert stopped_count > 0
        time.sleep(0.5)
        assert _bmarker(lab, plan_b, "bepin").count(loop_path) == stopped_count
        _, gateway_after = _bexec(
            lab, plan_b, "gw", "set -o pipefail; nft list ruleset | sha256sum"
        )
        assert gateway_after == gateway_before
        for ep, role in ((B_EPIN, "bepin"), (B_EPOUT, "bepout")):
            rc, out = _bexec(
                lab, plan_b, "bystander",
                f"curl -sS -m 5 http://{ep}:8080/t-b2-after-{token}",
            )
            assert rc == 0 and "ok" in out
            assert f"/t-b2-after-{token}" in _bmarker(lab, plan_b, role)
    finally:
        if crash in lab.containers:
            lab.run(["rm", "-f", crash])
            lab.containers.remove(crash)
