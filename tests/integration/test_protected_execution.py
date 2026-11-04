"""R11 真实 Linux 受保护执行集成实验（FOAM_INTEGRATION=1 opt-in）。"""

from __future__ import annotations

from .labkit import Lab, docker_exec, push_file


def test_r11_harness_baseline(r11_lab: Lab, r11_harness: str) -> None:
    """记录真实 Python/内核/命令与受信源码环境，不把镜像当产品通过。"""
    assert r11_lab.label == "foam.r11.run"
    rc, out = docker_exec(
        r11_lab,
        r11_harness,
        "id -u; python --version; uname -sr; "
        "python -c 'import foam; print(foam.__file__)'; "
        "ip -V; nft --version; conntrack --version; "
        "nsenter --version; setpriv --version; "
        "stat -c '%u %a %n' /opt/foam-src /opt/foam-src/src; "
        "sysctl -n net.ipv4.ip_forward; sysctl -n net.ipv6.conf.all.forwarding",
    )
    assert rc == 0
    assert out.startswith("0\nPython 3.12.")
    assert "/opt/foam-src" in out
    assert "0 755 /opt/foam-src" in out
    assert out.rstrip().endswith("1\n1")


def test_r11_endpoints_positive_control(
    r11_lab: Lab, r11_endpoints: dict[str, str]
) -> None:
    """端点、旁观者与控制面健康正对照先于任何拒绝断言。"""
    docker_exec(
        r11_lab,
        r11_endpoints["harness"],
        "curl --noproxy '*' -sS -m 5 http://127.0.0.1:9090/ready-control",
    )
    for role in ("allowed", "denied"):
        _, marker = docker_exec(
            r11_lab, r11_endpoints[role], "cat /opt/serve.py.8080.hits"
        )
        assert "/ready" in marker
        assert "/by-ready" in marker
        assert "/by-final" not in marker
    _, control = docker_exec(
        r11_lab,
        r11_endpoints["harness"],
        "cat /opt/r11-control.py.9090.hits",
    )
    assert "/ready-control" in control


_CREATE_CLOSE_DRIVER = '''\
import json
from foam.guard.network import NetworkBoundary
from foam.guard.scope import parse_scope

boundary = None
try:
    boundary = NetworkBoundary.create(parse_scope(""), digest="r11-create-close")
    print("BOUNDARY_ID=" + boundary.boundary_id)
    print("CAPS=" + json.dumps(boundary.capabilities(), sort_keys=True))
    print("INIT_PID=" + str(boundary.init_pid))
finally:
    if boundary is not None:
        print("CLEANUP=" + json.dumps(boundary.aclose(), sort_keys=True))
'''


def test_r11_boundary_create_close(r11_lab: Lab, r11_harness: str) -> None:
    """真实 helper 创建/关闭必须连目录一起回收，不只是 mock clean。"""
    push_file(r11_lab, r11_harness, "/opt/r11-create-close.py", _CREATE_CLOSE_DRIVER)
    rc, out = docker_exec(
        r11_lab, r11_harness, "python /opt/r11-create-close.py", check=False
    )
    assert rc == 0, out
    boundary_id = next(
        line.removeprefix("BOUNDARY_ID=")
        for line in out.splitlines()
        if line.startswith("BOUNDARY_ID=")
    )
    assert '"cleanup_status": "clean"' in out, out
    rc, residue = docker_exec(
        r11_lab,
        r11_harness,
        f"test ! -e /run/foam/network/{boundary_id} "
        f"&& test ! -e /run/foam/tool-work/{boundary_id}",
        check=False,
    )
    assert rc == 0, f"boundary 目录残留: {residue}\n{out}"


_CHILD_DRIVER = r"""\
import asyncio
import json
from pathlib import Path

from foam.guard.network import NetworkBoundary
from foam.guard.scope import parse_scope
from foam.tools.bash import BashTool
from foam.tools.execution import ToolExecutor
from foam.tools.session import SessionTool

PROBE = r'''\
import os
import socket
import subprocess
from pathlib import Path

print("uid", os.getuid(), "gid", os.getgid())
for line in Path("/proc/self/status").read_text().splitlines():
    if line.startswith(
        ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs")
    ):
        print(line)
    elif line.startswith("Cap") and line.endswith("ffff"):
        raise AssertionError(line)
assert "FOAM_LLM_API_KEY" not in os.environ
assert "HTTP_PROXY" not in os.environ
assert "http_proxy" not in os.environ
for family, protocol in ((socket.AF_INET, socket.IPPROTO_ICMP), (socket.AF_PACKET, 3)):
    try:
        sock = socket.socket(family, socket.SOCK_RAW, protocol)
    except OSError as exc:
        print("raw-denied", family, exc.errno)
    else:
        sock.close()
        raise AssertionError("raw socket unexpectedly allowed")
for path in (
    "/run/foam/network/__BOUNDARY_ID__/control.sock",
    "/opt/foam-src/audit.jsonl",
    "/opt/foam-src/src/foam/guard/network.py",
):
    try:
        with open(path, "ab"):
            pass
    except OSError as exc:
        print("readonly", path, exc.errno)
    else:
        raise AssertionError(f"control file writable: {path}")
self_ns = (
    os.readlink("/proc/self/ns/net"),
    os.readlink("/proc/self/ns/pid"),
)
print("self-ns", *self_ns)
for argv in (
    ["bash", "-c", "readlink /proc/self/ns/net; readlink /proc/self/ns/pid"],
    ["setsid", "bash", "-c", "readlink /proc/self/ns/net; readlink /proc/self/ns/pid"],
):
    lines = subprocess.check_output(argv, text=True).splitlines()
    print("child-ns", *lines)
    assert tuple(lines) == self_ns
pid1 = Path("/proc/1/cmdline").read_bytes().replace(b"\0", b" ").decode()
print("pid1", pid1)
assert "sleep infinity" not in pid1
assert len(list(Path("/proc").glob("[0-9]*"))) < 50
print("PROBE_OK")
'''


async def main():
    boundary = NetworkBoundary.create(
        parse_scope("172.45.0.11/32\nfd00:45::11/128"),
        dns="172.45.0.11",
        digest="r11-child",
    )
    print("BOUNDARY_ID=" + boundary.boundary_id)
    Path("/tmp/r11-probe.py").write_text(
        PROBE.replace("__BOUNDARY_ID__", boundary.boundary_id), encoding="utf-8"
    )
    executor = ToolExecutor(boundary=boundary)
    bash = BashTool("/tmp/r11-bash-out", executor=executor)
    sessions = SessionTool("/tmp/r11-session-out", executor=executor)
    try:
        resolver = await bash.run_command("cat /etc/resolv.conf")
        assert resolver["exit_code"] == 0, resolver
        assert "nameserver 172.45.0.11" in resolver["output_view"], resolver
        threaded = await bash.run_command(
            "python -c 'import threading; t = threading.Thread(target=print, "
            "args=(\"THREAD_OK\",)); t.start(); t.join()'"
        )
        assert threaded["exit_code"] == 0, threaded
        assert "THREAD_OK" in threaded["output_view"], threaded
        for command in (
            "curl --noproxy '*' -sS -m 5 http://172.45.0.11:8080/r11-bash-allow",
            "curl --noproxy '*' -sS -m 5 http://172.45.0.11:8081/r11-bash-port",
            "curl --noproxy '*' -sS -m 5 -g 'http://[fd00:45::11]:8080/r11-v6-allow'",
            "getent ahostsv4 r11dns.test",
            "dig +tcp +time=2 +tries=1 @172.45.0.11 r11tcp.test +short",
        ):
            result = await bash.run_command(command)
            print("ALLOW", command, json.dumps(result, sort_keys=True))
            assert result["exit_code"] == 0, result
            assert result["boundary_id"] == boundary.boundary_id
            assert result["epoch"] == 1
        for command in (
            "curl --noproxy '*' -sS -m 5 http://172.45.0.20:8080/r11-bash-deny",
            "curl --noproxy '*' -sS -m 5 -g 'http://[fd00:45::20]:8080/r11-v6-deny'",
            "curl -sS -m 5 -x http://172.45.0.20:8080 http://172.45.0.11:8080/r11-proxy-deny",
            "nft list ruleset",
        ):
            result = await bash.run_command(command, timeout_seconds=10)
            print("DENY", command, json.dumps(result, sort_keys=True))
            assert result["exit_code"] != 0, result
        result = await bash.run_command("python /tmp/r11-probe.py")
        print("PROBE", json.dumps(result, sort_keys=True))
        assert result["exit_code"] == 0, result

        for token, target, expected in (
            ("r11-pty-allow", "172.45.0.11", 0),
            ("r11-pty-deny", "172.45.0.20", 1),
        ):
            opened = await sessions.session_open(
                f"test -t 0 && curl --noproxy '*' -sS -m 5 http://{target}:8080/{token}"
            )
            assert opened["boundary_id"] == boundary.boundary_id
            assert opened["epoch"] == 1
            session_id = opened["session_id"]
            transcript = ""
            for unused in range(150):
                read = await sessions.session_read(session_id)
                transcript += read["new_output"]
                if read["status"] != "running":
                    break
                await asyncio.sleep(0.05)
            print("PTY", token, json.dumps(read, sort_keys=True))
            if expected == 0:
                assert "ok" in transcript, read
            else:
                assert "timed out" in transcript, read
            await sessions.session_close(session_id)
        print("BOUNDARY_OK")
    finally:
        await bash.aclose()
        await sessions.aclose()
        print("CLEANUP=" + json.dumps(boundary.aclose(), sort_keys=True))


asyncio.run(main())
"""


def test_child_cannot_modify_boundary(
    r11_lab: Lab, r11_endpoints: dict[str, str]
) -> None:
    """真实 Bash/PTY/后代同边界，工具不能改规则、证据或控制面。"""
    push_file(r11_lab, r11_endpoints["harness"], "/opt/r11-child.py", _CHILD_DRIVER)
    rc, out = docker_exec(
        r11_lab,
        r11_endpoints["harness"],
        "FOAM_LLM_API_KEY=TESTONLY-R11-SECRET "
        "HTTP_PROXY=http://172.45.0.20:8080 PYTHONUNBUFFERED=1 "
        "timeout --signal=KILL 110s python /opt/r11-child.py "
        "> /tmp/r11-child.out 2>&1; rc=$?; cat /tmp/r11-child.out; exit $rc",
        timeout=130,
        check=False,
    )
    assert rc == 0, out
    assert "PROBE_OK" in out and "BOUNDARY_OK" in out, out
    assert '"cleanup_status": "clean"' in out, out
    _, allowed = docker_exec(
        r11_lab, r11_endpoints["allowed"], "cat /opt/serve.py.8080.hits"
    )
    for token in ("r11-bash-allow", "r11-v6-allow", "r11-pty-allow"):
        assert token in allowed
    for token in ("r11-bash-deny", "r11-v6-deny", "r11-pty-deny", "r11-proxy-deny"):
        assert token not in allowed
    _, allowed_port = docker_exec(
        r11_lab, r11_endpoints["allowed"], "cat /opt/serve.py.8081.hits"
    )
    assert "r11-bash-port" in allowed_port
    _, denied = docker_exec(
        r11_lab, r11_endpoints["denied"], "cat /opt/serve.py.8080.hits"
    )
    for token in ("r11-bash-deny", "r11-v6-deny", "r11-pty-deny", "r11-proxy-deny"):
        assert token not in denied
    _, dns_log = docker_exec(
        r11_lab, r11_endpoints["allowed"], "cat /tmp/r11-dns.log"
    )
    assert "r11dns.test" in dns_log and "r11tcp.test" in dns_log
    docker_exec(
        r11_lab,
        r11_endpoints["harness"],
        "curl --noproxy '*' -sS -m 5 http://172.45.0.20:8080/control-after",
    )
