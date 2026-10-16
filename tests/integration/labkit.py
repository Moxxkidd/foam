"""R10 集成实验的 docker 编排工具(labkit)。

只被 ``tests/integration`` 使用:以固定 argv 调 docker CLI,登记本层创建的
全部容器/网络/镜像,会话结束统一清理并留清理实证。实验完全发生在容器与
docker 网络内部,不触碰宿主机防火墙、网络全局规则与 docker daemon 配置。
"""

from __future__ import annotations

import shutil
import subprocess  # noqa: S403  # 仅固定 argv 编排 docker CLI,无 shell 拼接
import tempfile
import time
import uuid
from pathlib import Path

LAB_IMAGE = "foam-r10-lab:local"
DEBIAN_IMAGE = "debian:12-slim"

# 容器内 apt 换 TUNA 源(deb.debian.org 直连在本网络不可用,见 R10.md §6)。
# dnsmasq-base 只取 dnsmasq 二进制,不带 init 脚本;bsdutils 提供 script(PTY)。
APT_PREPARE = (
    'sed -i "s|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g;'
    "s|security.debian.org/debian-security|"
    'mirrors.tuna.tsinghua.edu.cn/debian-security|g"'
    " /etc/apt/sources.list.d/debian.sources"
    " && apt-get update -qq"
    " && apt-get install -y -qq --no-install-recommends"
    " iproute2 nftables iputils-ping dnsutils curl"
    " python3 procps bsdutils dnsmasq-base"
    " && rm -rf /var/lib/apt/lists/*"
)

# 合成 HTTP 端点:每收到一个 GET 把请求路径追加到 ``__file__.<port>.hits``
# ——允许/拒绝的端点侧独立证据,不依赖被测侧输出。v6 不可用时(plan B 的
# docker 默认网络)退化为纯 v4,不影响实验。
SERVE_PY = '''\
import contextlib
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
MARKER = f"{__file__}.{PORT}.hits"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with open(MARKER, "a", encoding="utf-8") as fh:
            fh.write(self.path + "\\n")
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class DualStack(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        with contextlib.suppress(Exception):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


try:
    DualStack(("::", PORT), Handler).serve_forever()
except OSError:
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
'''

_DOCKER = shutil.which("docker")


def docker_available() -> bool:
    """docker CLI 存在且 daemon 可达。"""
    if _DOCKER is None:
        return False
    try:
        subprocess.run(  # noqa: S603  # 固定参数探测,无外部输入
            [_DOCKER, "version"],
            capture_output=True,
            timeout=15,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def dnsmasq_cmd(answer_ip: str, log: str) -> str:
    """合成 DNS 端点:任意名字都答 ``answer_ip``,查询逐条落 ``log``。"""
    return (
        "dnsmasq --conf-file=/dev/null --keep-in-foreground"
        " --no-resolv --no-hosts --port=53"
        f" --address=/#/{answer_ip}"
        f" --log-queries --log-facility={log} --pid-file={log}.pid"
    )


class Lab:
    """实验资源台账:创建时登记,``cleanup`` 统一销毁,全程命令留证。"""

    def __init__(self) -> None:
        self.tag = uuid.uuid4().hex[:8]
        self.containers: list[str] = []
        self.networks: list[str] = []
        self.built_image = False
        self.evidence: list[str] = []

    def run(
        self,
        args: list[str],
        *,
        timeout: int = 120,
        check: bool = True,
        input_text: str | None = None,
    ) -> tuple[int, str]:
        started = time.monotonic()
        proc = subprocess.run(  # noqa: S603  # 固定 argv 编排 docker,无 shell
            [_DOCKER, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        elapsed = time.monotonic() - started
        shown = out.rstrip()
        if len(shown) > 4000:
            shown = shown[:4000] + "\n...(截断)"
        self.evidence.append(
            f"$ docker {' '.join(args)}\n"
            f"# rc={proc.returncode} ({elapsed:.1f}s)\n{shown}\n"
        )
        if check and proc.returncode != 0:
            raise RuntimeError(
                f"docker {' '.join(args)} 失败 rc={proc.returncode}:\n{out}"
            )
        return proc.returncode, out

    def name(self, role: str) -> str:
        return f"r10-{role}-{self.tag}"

    def add_container(self, name: str) -> str:
        self.containers.append(name)
        return name

    def add_network(self, name: str) -> str:
        self.networks.append(name)
        return name

    def build_image(self) -> None:
        dockerfile = f"FROM {DEBIAN_IMAGE}\nRUN {APT_PREPARE}\n"
        self.run(
            ["build", "-t", LAB_IMAGE, "-"],
            timeout=900,
            input_text=dockerfile,
        )
        self.built_image = True

    def cleanup(self) -> None:
        for name in reversed(self.containers):
            self.run(["rm", "-f", name], check=False)
        for name in reversed(self.networks):
            self.run(["network", "rm", name], check=False)
        if self.built_image:
            self.run(["rmi", LAB_IMAGE], check=False)

    def dump_evidence(self) -> Path:
        path = Path(tempfile.gettempdir()) / f"foam-r10-evidence-{self.tag}.md"
        path.write_text(
            "# R10 集成实验实录(docker 命令级)\n\n"
            + "\n---\n\n".join(self.evidence),
            encoding="utf-8",
        )
        return path


def docker_exec(
    lab: Lab,
    container: str,
    script: str,
    *,
    timeout: int = 90,
    check: bool = True,
) -> tuple[int, str]:
    """在容器内执行 bash 脚本(脚本整体作为单个 argv,不经宿主 shell)。"""
    return lab.run(
        ["exec", container, "bash", "-c", script],
        timeout=timeout,
        check=check,
    )


def push_file(lab: Lab, container: str, dest: str, content: str) -> None:
    """把文本内容写入容器内文件(经 stdin,避免引号转义层叠)。"""
    lab.run(
        ["exec", "-i", container, "bash", "-c", f"cat > {dest}"],
        input_text=content,
    )
