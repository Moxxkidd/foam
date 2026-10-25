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

DEBIAN_IMAGE = "docker.m.daocloud.io/library/debian:12-slim"

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
# ——允许/拒绝的端点侧独立证据,不依赖被测侧输出。双栈 socket 不可用时
# 退回纯 v4;各方案的 v6 验收由独立探针决定,不把退回视为 v6 通过。
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


def _output_text(output: str | bytes | None) -> str:
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode(errors="replace")
    return output


class Lab:
    """实验资源台账:创建成功后登记,``cleanup`` 统一销毁,全程命令留证。"""

    def __init__(self) -> None:
        self.tag = uuid.uuid4().hex[:8]
        self.image = f"foam-r10-lab:{self.tag}"
        self.containers: list[str] = []
        self.networks: list[str] = []
        self.built_image = False
        self.evidence: list[str] = []

    def label_args(self) -> list[str]:
        """返回供 docker create/run/build/network create 显式展开的会话标签。"""
        return ["--label", f"foam.r10.run={self.tag}"]

    def run(
        self,
        args: list[str],
        *,
        timeout: int = 120,
        check: bool = True,
        input_text: str | None = None,
    ) -> tuple[int, str]:
        started = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603  # 固定 argv 编排 docker,无 shell
                [_DOCKER, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_text,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            elapsed = time.monotonic() - started
            out = ""
            if isinstance(exc, subprocess.TimeoutExpired):
                out = _output_text(exc.output) + _output_text(exc.stderr)
            self.evidence.append(
                f"$ docker {' '.join(args)}\n"
                f"# {type(exc).__name__} ({elapsed:.1f}s): {exc}\n{out}\n"
            )
            raise
        out = (proc.stdout or "") + (proc.stderr or "")
        elapsed = time.monotonic() - started
        self.evidence.append(
            f"$ docker {' '.join(args)}\n"
            f"# rc={proc.returncode} ({elapsed:.1f}s)\n{out}\n"
        )
        if check and proc.returncode != 0:
            raise RuntimeError(
                f"docker {' '.join(args)} 失败 rc={proc.returncode}:\n{out}"
            )
        return proc.returncode, out

    def name(self, role: str) -> str:
        return f"r10-{role}-{self.tag}"

    def add_container(self, name: str) -> str:
        """仅在 docker run 成功后登记;创建失败不得登记或删除同名资源。"""
        self.containers.append(name)
        return name

    def add_network(self, name: str) -> str:
        """仅在 network create 成功后登记;创建失败不得登记或删除同名资源。"""
        self.networks.append(name)
        return name

    def build_image(self) -> None:
        rc, out = self.run(
            [
                "image", "inspect", "--format",
                "{{.Id}} {{json .RepoDigests}}", DEBIAN_IMAGE,
            ],
            check=False,
        )
        if rc != 0:
            raise RuntimeError(
                f"R10 基础镜像 {DEBIAN_IMAGE} 不在本地或无法检查;"
                f"不会自动访问 Docker Hub 拉取:\n{out}"
            )
        dockerfile = (
            f"FROM {DEBIAN_IMAGE}\nRUN {APT_PREPARE}\n"
            # 默认 ping 的权限位与 NNP 执行冲突;副本只走非特权 ICMP。
            "RUN cp /usr/bin/ping /usr/local/bin/ping"
            " && chmod 0755 /usr/local/bin/ping\n"
        )
        self.built_image = True
        self.run(
            [
                "build", "--pull=false", *self.label_args(),
                "-t", self.image, "-",
            ],
            timeout=900,
            input_text=dockerfile,
        )

    def cleanup(self) -> list[str]:
        """清理台账及本会话 label 资源;逐项留错并继续。"""
        errors: list[str] = []
        owned_images = [self.image] if self.built_image else []
        queries = (
            (
                "容器",
                [
                    "ps", "-a", "--filter", f"label=foam.r10.run={self.tag}",
                    "--format", "{{.Names}}",
                ],
                self.containers,
            ),
            (
                "网络",
                [
                    "network", "ls", "--filter", f"label=foam.r10.run={self.tag}",
                    "--format", "{{.Name}}",
                ],
                self.networks,
            ),
            (
                "镜像",
                [
                    "images", "--filter", f"label=foam.r10.run={self.tag}",
                    "--format", "{{.Repository}}:{{.Tag}}",
                ],
                owned_images,
            ),
        )
        for kind, args, owned in queries:
            try:
                rc, out = self.run(args, check=False, timeout=20)
            except Exception as exc:
                errors.append(f"{kind}归属查询异常: {type(exc).__name__}: {exc}")
                continue
            if rc != 0:
                errors.append(f"{kind}归属查询失败 rc={rc}: {out.strip()}")
                continue
            for name in out.splitlines():
                if name and name not in owned:
                    owned.append(name)

        actions = [
            ("容器", name, ["rm", "-f", name])
            for name in reversed(self.containers)
        ]
        actions.extend(
            ("网络", name, ["network", "rm", name])
            for name in reversed(self.networks)
        )
        actions.extend(
            ("镜像", name, ["rmi", name]) for name in reversed(owned_images)
        )
        for kind, name, args in actions:
            try:
                rc, out = self.run(args, check=False, timeout=20)
            except Exception as exc:
                errors.append(f"{kind} {name} 清理异常: {type(exc).__name__}: {exc}")
                continue
            absent = "no such" in out.lower() or (
                kind == "网络" and "not found" in out.lower()
            )
            if rc != 0 and not absent:
                errors.append(f"{kind} {name} 清理失败 rc={rc}: {out.strip()}")
        return errors

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
        [
            "exec", "-i", "--user", "0", container,
            "bash", "-c", 'cat > "$1"', "bash", dest,
        ],
        input_text=content,
    )
