"""R11 真实 Linux 受保护执行集成实验（FOAM_INTEGRATION=1 opt-in）。"""

from __future__ import annotations

import json
import time

import pytest

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


def test_r11_linux_pty_output_drain(r11_lab: Lab, r11_harness: str) -> None:
    """在真实 Linux PTY 上复核 leader 先退出与逃逸后代两个输出边界。"""
    rc, out = docker_exec(
        r11_lab,
        r11_harness,
        "cd /opt/foam-src && python -m pytest -q "
        "tests/test_session.py::test_fresh_process_output_is_drained_before_finalize "
        "tests/test_session.py::test_detached_slave_fd_does_not_block_session_eof",
        check=False,
    )
    assert rc == 0, out


_REUSE_SERVER = r"""\
import socket

with socket.socket() as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 9091))
    server.listen()
    with open("/tmp/r11-reuse-server.hits", "ab", buffering=0) as hits:
        while True:
            connection, _ = server.accept()
            with connection:
                pending = b""
                while True:
                    data = connection.recv(4096)
                    if not data:
                        break
                    pending += data
                    lines = pending.split(b"\n")
                    pending = lines.pop()
                    for line in lines:
                        hits.write(line + b"\n")
"""


_NARROW_DRIVER = r"""\
import asyncio
import hashlib
import json
from pathlib import Path

from foam.agent.loop import AgentLoop
from foam.guard.audit import AuditLog
from foam.guard.network import NetworkBoundary
from foam.guard.scope import parse_scope
from foam.tools.bash import BashTool
from foam.tools.execution import ToolExecutor
from foam.tools.session import SessionTool

CLIENT = r'''\
import socket
import time

connection = socket.create_connection(("172.45.0.11", 9091))
connection.sendall(b"connected\n")
while True:
    connection.sendall(b"tick\n")
    time.sleep(0.1)
'''


class Backend:
    provider = "r11-narrow-fake"


async def main():
    old_scope = parse_scope("172.45.0.11/32\n")
    old_digest = hashlib.sha256(b"172.45.0.11/32\n").hexdigest()
    boundary = NetworkBoundary.create(old_scope, digest=old_digest)
    executor = ToolExecutor(boundary=boundary)
    bash = BashTool("/tmp/r11-narrow-bash", executor=executor)
    sessions = SessionTool("/tmp/r11-narrow-sessions", executor=executor)
    audit = AuditLog("/tmp/r11-narrow-audit.jsonl")
    loop = AgentLoop(
        backend=Backend(),
        bash=bash,
        scope=old_scope,
        audit=audit,
        workdir="/tmp",
        system_prompt="",
        session=sessions,
    )
    Path("/tmp/r11-reuse-client.py").write_text(CLIENT, encoding="utf-8")
    try:
        old_job = await bash.run_command(
            "python /tmp/r11-reuse-client.py", background=True
        )
        assert old_job["status"] == "running", old_job
        old_session = await sessions.session_open("sleep 60")
        assert old_session["status"] == "running", old_session
        Path("/tmp/r11-old-started").touch()
        while not Path("/tmp/r11-narrow-now").exists():
            await asyncio.sleep(0.05)
        new_digest = hashlib.sha256(b"").hexdigest()
        await loop.replace_scope(parse_scope(""), digest=new_digest)
        fresh = await bash.run_command("printf fresh")
        assert fresh["exit_code"] == 0 and fresh["output_view"] == "fresh", fresh
        assert fresh["epoch"] == 2, fresh
        assert "未知 job_id" in (await bash.read_output(old_job["job_id"]))["error"]
        assert "未知 session_id" in (
            await sessions.session_read(old_session["session_id"])
        )["error"]
        print("NARROW_OK " + json.dumps(fresh, sort_keys=True))
    finally:
        await bash.aclose()
        await sessions.aclose()
        print("CLEANUP=" + json.dumps(boundary.aclose(), sort_keys=True))
        audit.close()


asyncio.run(main())
"""


def _hit_count(lab: Lab, endpoint: str) -> int:
    _, out = docker_exec(
        lab,
        endpoint,
        "python -c 'from pathlib import Path; "
        "p=Path(\"/tmp/r11-reuse-server.hits\"); "
        "print(len(p.read_text().splitlines()) if p.exists() else 0)'",
    )
    return int(out.strip())


def test_scope_narrowing_revokes_existing_connection(
    r11_lab: Lab, r11_endpoints: dict[str, str]
) -> None:
    """旧 TCP 连接与 PTY 随代际撤销；新工具只能在 fresh epoch 运行。"""
    harness = r11_endpoints["harness"]
    allowed = r11_endpoints["allowed"]
    push_file(r11_lab, allowed, "/opt/r11-reuse-server.py", _REUSE_SERVER)
    push_file(r11_lab, harness, "/opt/r11-narrow.py", _NARROW_DRIVER)
    r11_lab.run(["exec", "-d", allowed, "python", "/opt/r11-reuse-server.py"])
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            docker_exec(
                r11_lab,
                harness,
                "python -c 'import socket; "
                "s=socket.create_connection((\"172.45.0.11\", 9091), 2); "
                "s.sendall(b\"ready\\n\"); s.close()'",
            )
            break
        except AssertionError:
            time.sleep(0.1)
    else:
        pytest.fail("reuse server 未就绪")

    r11_lab.run(
        [
            "exec",
            "-d",
            harness,
            "bash",
            "-c",
            "PYTHONUNBUFFERED=1 timeout --signal=KILL 60s python /opt/r11-narrow.py "
            "> /tmp/r11-narrow.out 2>&1; echo $? > /tmp/r11-narrow.done",
        ]
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if _hit_count(r11_lab, allowed) >= 3:
            break
        if docker_exec(
            r11_lab,
            harness,
            "test -f /tmp/r11-narrow.done",
            check=False,
        )[0] == 0:
            break
        time.sleep(0.1)
    _, early_out = docker_exec(r11_lab, harness, "cat /tmp/r11-narrow.out")
    assert _hit_count(r11_lab, allowed) >= 3, early_out

    docker_exec(r11_lab, harness, "touch /tmp/r11-narrow-now")
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if docker_exec(
            r11_lab,
            harness,
            "test -f /tmp/r11-narrow.done",
            check=False,
        )[0] == 0:
            break
        time.sleep(0.1)
    _, out = docker_exec(r11_lab, harness, "cat /tmp/r11-narrow.out")
    assert "NARROW_OK" in out, out
    assert '"cleanup_status": "clean"' in out, out
    settled = _hit_count(r11_lab, allowed)
    time.sleep(0.5)
    assert _hit_count(r11_lab, allowed) == settled, out


_CLI_DRIVER = r"""\
from collections import deque
from pathlib import Path

from foam.agent.backends.base import TextDelta, ToolCall, Usage
from foam.cli import main


class Backend:
    provider = "r11-cli-fake"

    def __init__(self, marker):
        self.marker = marker
        self.round = 0

    async def aclose(self):
        return None

    def chat(self, _messages, _tools=None):
        self.round += 1
        return self._stream()

    async def _stream(self):
        if self.round == 1:
            yield ToolCall(
                "cli-call",
                "run_command",
                {
                    "command": (
                        "curl --noproxy '*' -sS -m 5 "
                        f"http://172.45.0.11:8080/{self.marker}"
                    )
                },
            )
            yield Usage(1, 1)
        else:
            yield TextDelta("done")
            yield Usage(1, 1)


scope = Path("/tmp/r11-cli.scope")
scope.write_text("172.45.0.11/32\n", encoding="utf-8")
workdir = Path("/tmp/r11-cli-eng")
run_rc = main(
    [
        "run",
        "--execution-mode",
        "protected",
        "--scope",
        str(scope),
        "--objective",
        "TESTONLY protected CLI",
        "--workdir",
        str(workdir),
    ],
    backend_factory=lambda _args: Backend("r11-cli-run"),
)
resume_rc = main(
    ["resume", "--execution-mode", "protected", str(workdir)],
    backend_factory=lambda _args: Backend("r11-cli-resume"),
)
assert run_rc == 0 and resume_rc == 0, (run_rc, resume_rc)
print("CLI_PROTECTED_OK")
"""


def test_cli_protected_run_and_resume(r11_lab: Lab, r11_endpoints) -> None:
    """真实 CLI 两次入口均创建受保护边界，工具到达独立授权端点。"""
    harness = r11_endpoints["harness"]
    push_file(r11_lab, harness, "/opt/r11-cli.py", _CLI_DRIVER)
    rc, out = docker_exec(
        r11_lab,
        harness,
        "HOME=/tmp/r11-cli-home PYTHONUNBUFFERED=1 "
        "timeout --signal=KILL 100s python /opt/r11-cli.py",
        timeout=120,
        check=False,
    )
    assert rc == 0, out
    assert "CLI_PROTECTED_OK" in out, out
    assert out.count("mode=protected") == 2, out
    assert "mode=legacy" not in out, out
    _, markers = docker_exec(
        r11_lab, r11_endpoints["allowed"], "cat /opt/serve.py.8080.hits"
    )
    assert "/r11-cli-run" in markers and "/r11-cli-resume" in markers
    rc, residue = docker_exec(
        r11_lab,
        harness,
        "python -c 'from pathlib import Path; "
        "items=list(Path(\"/run/foam/network\").glob(\"fb*\")) "
        "+ list(Path(\"/run/foam/tool-work\").glob(\"fb*\")); "
        "print(items); raise SystemExit(bool(items))'",
        check=False,
    )
    assert rc == 0, f"CLI boundary 残留: {residue}\n{out}"


_CRASH_DRIVER = r"""\
import asyncio
import hashlib
import json
import os
from pathlib import Path

from foam.guard.network import NetworkBoundary
from foam.guard.network_helper import resource_config
from foam.guard.scope import parse_scope
from foam.tools.bash import BashTool
from foam.tools.execution import ToolExecutor

CHILD = r'''\
import json
import os
import time
from pathlib import Path

fields = Path("/proc/self/stat").read_text().rsplit(") ", 1)[1].split()
Path("/tmp/r11-crash-child.ready").write_text(
    json.dumps({"pid": os.getpid(), "start": fields[19]}), encoding="utf-8"
)
time.sleep(300)
'''


def process_start(pid):
    text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    return text.rsplit(") ", 1)[1].split()[19]


def find_child(token):
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "comm").read_text().strip() != "python":
                continue
            cmdline = (entry / "cmdline").read_bytes()
            if token.encode() not in cmdline or b"r11-crash-child.py" not in cmdline:
                continue
            return int(entry.name), process_start(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return None


async def main():
    boundary = NetworkBoundary.create(
        parse_scope(""), digest=hashlib.sha256(b"").hexdigest()
    )
    executor = ToolExecutor(boundary=boundary)
    bash = BashTool("/tmp/r11-crash-output", executor=executor)
    Path("/tmp/r11-crash-child.py").write_text(CHILD, encoding="utf-8")
    job = await bash.run_command(
        f"setsid python /tmp/r11-crash-child.py {boundary.boundary_id}",
        background=True,
    )
    assert job["status"] == "running", job
    child = None
    for _ in range(500):
        child = find_child(boundary.boundary_id)
        if child is not None:
            break
        await asyncio.sleep(0.02)
    assert child is not None
    manifest = json.loads(
        Path(
            f"/run/foam/network/{boundary.boundary_id}/manifest.json"
        ).read_text(encoding="utf-8")
    )
    config = resource_config(boundary.boundary_id)
    state = {
        "boundary_id": boundary.boundary_id,
        "foam_pid": os.getpid(),
        "foam_start": process_start(os.getpid()),
        "helper_pid": boundary.helper_pid,
        "helper_start": manifest["helper_start"],
        "init_pid": boundary.init_pid,
        "init_start": manifest["generation"]["start"],
        "child_pid": child[0],
        "child_start": child[1],
        "netns": config.netns,
        "nft_table": config.nft_table,
        "veth": config.host_interface,
    }
    Path("/tmp/r11-crash-state.json").write_text(
        json.dumps(state), encoding="utf-8"
    )
    print("CRASH_READY", flush=True)
    await asyncio.Event().wait()


asyncio.run(main())
"""


_CRASH_PROBE = r"""\
import json
import subprocess
import sys
from pathlib import Path

state = json.loads(Path("/tmp/r11-crash-state.json").read_text())
mode = sys.argv[1]


def alive(pid, start):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    except (FileNotFoundError, ProcessLookupError):
        return False
    return fields[19] == start and fields[0] != "Z"


processes = {
    role: alive(state[f"{role}_pid"], state[f"{role}_start"])
    for role in ("foam", "helper", "init", "child")
}
netns = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
nft = subprocess.run(
    ["nft", "list", "table", "inet", state["nft_table"]],
    capture_output=True,
)
veth = subprocess.run(["ip", "link", "show", state["veth"]], capture_output=True)
resources = {
    "netns": state["netns"] in netns.stdout.split(),
    "nft": nft.returncode == 0,
    "veth": veth.returncode == 0,
}
manifest = Path(
    f"/run/foam/network/{state['boundary_id']}/manifest.json"
).exists()
details = {
    "processes": processes,
    "resources": resources,
    "manifest": manifest,
}
clean = not any(processes.values()) and not any(resources.values()) and not manifest
if mode == "clean":
    ok = clean
elif mode == "orphaned":
    ok = (
        processes["init"]
        and processes["child"]
        and not processes["helper"]
        and all(resources.values())
        and manifest
    )
else:
    state_dir = Path(f"/run/foam/network/{state['boundary_id']}")
    workdir = Path(f"/run/foam/tool-work/{state['boundary_id']}")
    details["directories"] = {
        "state": state_dir.exists(),
        "work": workdir.exists(),
    }
    ok = clean and not state_dir.exists() and not workdir.exists()
print(json.dumps(details, sort_keys=True))
raise SystemExit(0 if ok else 1)
"""


_CRASH_KILL = r"""\
import json
import os
import signal
import sys
from pathlib import Path

state = json.loads(Path("/tmp/r11-crash-state.json").read_text())
role = sys.argv[1]
pid = state[f"{role}_pid"]
fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
assert fields[19] == state[f"{role}_start"] and fields[0] != "Z"
os.kill(pid, signal.SIGKILL)
"""


def _start_crash_case(lab: Lab, harness: str) -> dict:
    for path, content in (
        ("/opt/r11-crash-driver.py", _CRASH_DRIVER),
        ("/opt/r11-crash-probe.py", _CRASH_PROBE),
        ("/opt/r11-crash-kill.py", _CRASH_KILL),
    ):
        push_file(lab, harness, path, content)
    docker_exec(
        lab,
        harness,
        "rm -f /tmp/r11-crash-state.json /tmp/r11-crash-child.ready "
        "/tmp/r11-crash.out && rm -rf /tmp/r11-crash-output",
    )
    lab.run(
        [
            "exec",
            "-d",
            harness,
            "bash",
            "-c",
            "PYTHONUNBUFFERED=1 python /opt/r11-crash-driver.py "
            "> /tmp/r11-crash.out 2>&1",
        ]
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        rc, _ = docker_exec(
            lab,
            harness,
            "test -s /tmp/r11-crash-state.json "
            "&& test -s /tmp/r11-crash-child.ready",
            check=False,
        )
        if rc == 0:
            _, out = docker_exec(lab, harness, "cat /tmp/r11-crash-state.json")
            return json.loads(out)
        time.sleep(0.1)
    _, out = docker_exec(lab, harness, "cat /tmp/r11-crash.out")
    pytest.fail(f"crash driver 未就绪: {out}")


def _wait_crash_probe(lab: Lab, harness: str, mode: str) -> str:
    deadline = time.monotonic() + 20
    out = ""
    while time.monotonic() < deadline:
        rc, out = docker_exec(
            lab,
            harness,
            f"python /opt/r11-crash-probe.py {mode}",
            check=False,
        )
        if rc == 0:
            return out
        time.sleep(0.1)
    pytest.fail(f"crash probe {mode} 未满足: {out}")


def _recover_crashed_boundary(lab: Lab, harness: str) -> list[dict]:
    rc, out = docker_exec(
        lab,
        harness,
        "python -c 'import json; from foam.guard.network import recover_stale; "
        "print(json.dumps(recover_stale()))'",
        check=False,
    )
    assert rc == 0, out
    return json.loads(out.strip().splitlines()[-1])


def test_foam_sigkill_helper_eof_cleans_and_recovers(
    r11_lab: Lab, r11_harness: str
) -> None:
    _start_crash_case(r11_lab, r11_harness)
    try:
        docker_exec(r11_lab, r11_harness, "python /opt/r11-crash-kill.py foam")
        _wait_crash_probe(r11_lab, r11_harness, "clean")
        results = _recover_crashed_boundary(r11_lab, r11_harness)
        assert all(item["cleanup_status"] == "clean" for item in results), results
        _wait_crash_probe(r11_lab, r11_harness, "gone")
    finally:
        docker_exec(
            r11_lab,
            r11_harness,
            "python /opt/r11-crash-kill.py foam",
            check=False,
        )


_RECOVERY_CLI_DRIVER = r"""\
from pathlib import Path

from foam.agent.backends.base import TextDelta, Usage
from foam.cli import main


class Backend:
    provider = "r11-recovery-fake"

    async def aclose(self):
        return None

    def chat(self, _messages, _tools=None):
        return self._stream()

    async def _stream(self):
        yield TextDelta("done")
        yield Usage(1, 1)


scope = Path("/tmp/r11-recovery.scope")
scope.write_text("", encoding="utf-8")
rc = main(
    [
        "run",
        "--execution-mode",
        "protected",
        "--scope",
        str(scope),
        "--objective",
        "TESTONLY recovery",
        "--workdir",
        "/tmp/r11-recovery-eng",
    ],
    backend_factory=lambda _args: Backend(),
)
assert rc == 0, rc
print("RECOVERY_CLI_OK")
"""


def test_helper_death_requires_manifest_recovery(
    r11_lab: Lab, r11_harness: str
) -> None:
    _start_crash_case(r11_lab, r11_harness)
    try:
        docker_exec(r11_lab, r11_harness, "python /opt/r11-crash-kill.py helper")
        _wait_crash_probe(r11_lab, r11_harness, "orphaned")
        push_file(
            r11_lab,
            r11_harness,
            "/opt/r11-recovery-cli.py",
            _RECOVERY_CLI_DRIVER,
        )
        rc, out = docker_exec(
            r11_lab,
            r11_harness,
            "HOME=/tmp/r11-recovery-home python /opt/r11-recovery-cli.py",
            timeout=90,
            check=False,
        )
        assert rc == 0 and "RECOVERY_CLI_OK" in out, out
        docker_exec(r11_lab, r11_harness, "python /opt/r11-crash-kill.py foam")
        _wait_crash_probe(r11_lab, r11_harness, "gone")
    finally:
        docker_exec(
            r11_lab,
            r11_harness,
            "python /opt/r11-crash-kill.py foam",
            check=False,
        )


_UNSUPPORTED_DRIVER = r"""\
import sys
from pathlib import Path

from foam.cli import main


class Backend:
    provider = "r11-unsupported-fake"

    def __init__(self):
        self.calls = 0

    async def aclose(self):
        return None

    def chat(self, _messages, _tools=None):
        self.calls += 1
        raise AssertionError("protected 失败后不得进入主环")


label = sys.argv[1]
scope = Path(f"/tmp/r11-{label}.scope")
scope.write_text("127.0.0.0/8\n", encoding="utf-8")
backend = Backend()
rc = main(
    [
        "run",
        "--execution-mode",
        "protected",
        "--scope",
        str(scope),
        "--objective",
        "TESTONLY unsupported",
        "--workdir",
        f"/tmp/r11-{label}-eng",
    ],
    backend_factory=lambda _args: backend,
)
assert rc == 1 and backend.calls == 0, (rc, backend.calls)
print(f"UNSUPPORTED_OK={label}")
"""


def test_protected_permission_failures_are_explicit_and_clean(
    r11_lab: Lab, r11_harness: str
) -> None:
    push_file(
        r11_lab, r11_harness, "/opt/r11-unsupported.py", _UNSUPPORTED_DRIVER
    )
    commands = (
        (
            "nonroot",
            "setpriv --reuid=65534 --regid=65534 --clear-groups "
            "env HOME=/tmp/r11-nonroot-home "
            "python /opt/r11-unsupported.py nonroot",
        ),
        (
            "capless",
            "setpriv --reuid=0 --regid=0 --clear-groups --bounding-set=-all "
            "--no-new-privs env HOME=/tmp/r11-capless-home "
            "python /opt/r11-unsupported.py capless",
        ),
    )
    for label, command in commands:
        rc, out = docker_exec(r11_lab, r11_harness, command, check=False)
        assert rc == 0, out
        assert f"UNSUPPORTED_OK={label}" in out, out
        assert "protected 执行边界创建失败" in out, out
        assert "未回退 legacy" in out, out
        assert "[run finished]" not in out, out
        if label == "nonroot":
            assert "仅支持 Linux 且 euid=root" in out, out
    rc, residue = docker_exec(
        r11_lab,
        r11_harness,
        "python -c 'from pathlib import Path; "
        "items=list(Path(\"/run/foam/network\").glob(\"fb*\")) "
        "+ list(Path(\"/run/foam/tool-work\").glob(\"fb*\")); "
        "print(items); raise SystemExit(bool(items))'",
        check=False,
    )
    assert rc == 0, residue
