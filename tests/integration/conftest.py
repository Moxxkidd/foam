"""R10 集成实验层入口:opt-in 开关 + docker 可用性探测 + 会话级资源台账。

默认全量 pytest(macOS/CI)一律 skip,skip 原因写明启用方式;启用::

    FOAM_INTEGRATION=1 .venv/bin/python -m pytest -q tests/integration/ -v

前置:本机 docker 可用、本地已有镜像站 ``debian:12-slim`` 镜像(见
docs/items/R10.md §6)。实验镜像按会话唯一 tag 现场构建;本会话容器/网络/
镜像在会话结束清理,并按会话 label 查询残留。
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from .labkit import (
    APT_PREPARE,
    SERVE_PY,
    Lab,
    dnsmasq_cmd,
    docker_available,
    docker_exec,
    push_file,
)

_HERE = Path(__file__).resolve().parent

_ENABLE_HINT = (
    "R10 集成实验默认关闭(需要本机 docker 与本地 "
    "docker.m.daocloud.io/library/debian:12-slim 镜像,"
    "全部实验在容器/docker 网络内完成);启用:"
    "FOAM_INTEGRATION=1 .venv/bin/python -m pytest -q tests/integration/ -v"
)


def _skip_reason() -> str | None:
    if os.environ.get("FOAM_INTEGRATION") != "1":
        return _ENABLE_HINT
    if not docker_available():
        return "FOAM_INTEGRATION=1 已设置但 docker 不可达(docker version 失败)"
    return None


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    reason = _skip_reason()
    if reason is None:
        return
    marker = pytest.mark.skip(reason=reason)
    for item in items:
        # 本子目录的 conftest 钩子在全量收集时也会收到其他目录的用例,
        # 只对本实验目录下的用例加 skip。
        if Path(str(item.fspath)).resolve().is_relative_to(_HERE):
            item.add_marker(marker)


def _finish_lab(lab: Lab) -> None:
    """逐项清理并复查本会话资源,失败必须使实验失败。"""
    cleanup_errors: list[str] = []
    query_errors: list[str] = []
    residue: list[str] = []
    try:
        cleanup_errors.extend(lab.cleanup())
    except Exception as exc:
        cleanup_errors.append(f"cleanup 异常: {type(exc).__name__}: {exc}")

    queries = (
        (
            "容器",
            [
                "ps",
                "-a",
                "--filter",
                f"label={lab.label}={lab.tag}",
                "--format",
                "{{.Names}}",
            ],
        ),
        (
            "网络",
            [
                "network",
                "ls",
                "--filter",
                f"label={lab.label}={lab.tag}",
                "--format",
                "{{.Names}}",
            ],
        ),
        (
            "镜像",
            [
                "images",
                "--filter",
                f"label={lab.label}={lab.tag}",
                "--format",
                "{{.Repository}}:{{.Tag}}",
            ],
        ),
    )
    for kind, args in queries:
        try:
            rc, out = lab.run(args, check=False, timeout=20)
        except Exception as exc:
            query_errors.append(f"{kind}查询异常: {type(exc).__name__}: {exc}")
            continue
        if rc != 0:
            query_errors.append(f"{kind}查询失败 rc={rc}")
            continue
        residue.extend(f"{kind}: {line}" for line in out.splitlines() if line.strip())

    lab.evidence.append(
        "# 清理实证(会话收尾)\n"
        f"清理错误(应为空): {cleanup_errors or '无'}\n"
        f"查询错误(应为空): {query_errors or '无'}\n"
        f"本实验残留(应为空): {residue or '无'}\n"
    )
    path = lab.dump_evidence()
    print(f"\n[{lab.prefix.upper()}] docker 命令级实验实录: {path}")
    failures = [*cleanup_errors, *query_errors]
    if residue:
        failures.append(f"实验资源未清干净: {residue}")
    if failures:
        pytest.fail("\n".join(failures))


@pytest.fixture(scope="session")
def lab() -> Iterator[Lab]:
    lab = Lab()
    try:
        yield lab
    finally:
        _finish_lab(lab)


@pytest.fixture(scope="session")
def r11_lab() -> Iterator[Lab]:
    lab = Lab(label="foam.r11.run", prefix="r11")
    try:
        yield lab
    finally:
        _finish_lab(lab)


@pytest.fixture(scope="session")
def lab_image(lab: Lab) -> str:
    lab.build_image()
    return lab.image


@pytest.fixture(scope="session")
def harness(lab: Lab, lab_image: str) -> str:
    """方案 A 的特权实验容器:netns/nftables 实验全部在它内部完成。"""
    name = lab.name("harness")
    lab.run(
        [
            "run", "-d", "--name", name, "--init", "--privileged",
            *lab.label_args(), lab_image, "sleep", "infinity",
        ]
    )
    lab.add_container(name)
    return name


@pytest.fixture(scope="session")
def r11_image(r11_lab: Lab) -> str:
    dockerfile = f"""FROM docker.m.daocloud.io/library/python:3.12-slim-bookworm
RUN {APT_PREPARE}
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends conntrack \
    && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --no-cache-dir \
    hatchling "httpx>=0.27" "rich>=13.7" "textual>=0.86" \
    "pytest>=8.0" "pytest-asyncio>=0.23"
RUN cp /usr/bin/ping /usr/local/bin/ping && chmod 0755 /usr/local/bin/ping
"""
    r11_lab.build_image_from(dockerfile)
    return r11_lab.image


@pytest.fixture(scope="session")
def r11_harness(r11_lab: Lab, r11_image: str) -> str:
    """R11 专用隔离 Linux 控制面;不修改宿主防火墙/daemon。"""
    name = r11_lab.name("protected")
    network = r11_lab.name("net")
    r11_lab.run(
        [
            "network",
            "create",
            "--ipv6",
            "--subnet",
            "172.45.0.0/24",
            "--subnet",
            "fd00:45::/64",
            *r11_lab.label_args(),
            network,
        ]
    )
    r11_lab.add_network(network)
    r11_lab.run(
        [
            "run",
            "-d",
            "--name",
            name,
            "--init",
            "--privileged",
            "--network",
            network,
            "--ip",
            "172.45.0.5",
            "--ip6",
            "fd00:45::5",
            "--sysctl",
            "net.ipv4.ip_forward=1",
            "--sysctl",
            "net.ipv6.conf.all.forwarding=1",
            *r11_lab.label_args(),
            r11_image,
            "sleep",
            "infinity",
        ]
    )
    r11_lab.add_container(name)
    r11_lab.run(["exec", name, "mkdir", "-p", "/opt/foam-src"])
    root = Path(__file__).resolve().parents[2]
    for source in ("src", "tests", "pyproject.toml", "README.md", "LICENSE"):
        r11_lab.run(["cp", str(root / source), f"{name}:/opt/foam-src/"])
    r11_lab.run(
        [
            "exec",
            name,
            "python",
            "-m",
            "pip",
            "install",
            "--no-cache-dir",
            "--no-deps",
            "/opt/foam-src",
        ],
        timeout=300,
    )
    r11_lab.run(["exec", name, "python", "--version"])
    r11_lab.run(["exec", name, "uname", "-a"])
    return name


@pytest.fixture(scope="module")
def r11_endpoints(r11_lab: Lab, r11_harness: str) -> Iterator[dict[str, str]]:
    """独立合成端点;允许/拒绝由端点 marker 而非工具自述判定。"""
    network = r11_lab.name("net")
    names = {"harness": r11_harness, "network": network}
    for role, ip, ip6 in (
        ("allowed", "172.45.0.11", "fd00:45::11"),
        ("denied", "172.45.0.20", "fd00:45::20"),
        ("bystander", "172.45.0.30", "fd00:45::30"),
    ):
        name = r11_lab.name(role)
        r11_lab.run(
            [
                "run",
                "-d",
                "--name",
                name,
                "--init",
                "--network",
                network,
                "--ip",
                ip,
                "--ip6",
                ip6,
                *r11_lab.label_args(),
                r11_lab.image,
                "sleep",
                "infinity",
            ]
        )
        r11_lab.add_container(name)
        names[role] = name

    for role in ("allowed", "denied"):
        push_file(r11_lab, names[role], "/opt/serve.py", SERVE_PY)
        r11_lab.run(
            ["exec", "-d", names[role], "python", "/opt/serve.py", "8080"]
        )
        r11_lab.run(
            [
                "exec",
                "-d",
                names[role],
                "bash",
                "-c",
                dnsmasq_cmd(
                    "172.45.0.11" if role == "allowed" else "172.45.0.20",
                    "/tmp/r11-dns.log",  # noqa: S108  # 一次性实验容器内路径
                ),
            ]
        )
    r11_lab.run(["exec", "-d", names["allowed"], "python", "/opt/serve.py", "8081"])
    push_file(r11_lab, r11_harness, "/opt/r11-control.py", SERVE_PY)
    r11_lab.run(["exec", "-d", r11_harness, "python", "/opt/r11-control.py", "9090"])

    docker_exec(
        r11_lab,
        r11_harness,
        "curl --noproxy '*' -sS -m 5 -o /dev/null http://172.45.0.11:8080/ready "
        "&& curl --noproxy '*' -sS -m 5 -o /dev/null http://172.45.0.11:8081/ready "
        "&& curl --noproxy '*' -sS -m 5 -o /dev/null http://172.45.0.20:8080/ready "
        "&& dig +time=2 +tries=2 @172.45.0.11 ready.test +short "
        "&& dig +time=2 +tries=2 @172.45.0.20 ready-out.test +short",
    )
    docker_exec(
        r11_lab,
        names["bystander"],
        "curl --noproxy '*' -sS -m 5 -o /dev/null http://172.45.0.11:8080/by-ready "
        "&& curl --noproxy '*' -sS -m 5 -o /dev/null http://172.45.0.20:8080/by-ready",
    )
    try:
        yield names
    finally:
        errors: list[str] = []
        for ip, role in (("172.45.0.11", "allowed"), ("172.45.0.20", "denied")):
            try:
                rc, out = docker_exec(
                    r11_lab,
                    names["bystander"],
                    f"curl --noproxy '*' -sS -m 5 http://{ip}:8080/by-final",
                )
                assert rc == 0 and "ok" in out
                _, marker = docker_exec(
                    r11_lab, names[role], "cat /opt/serve.py.8080.hits"
                )
                assert "/by-final" in marker
            except Exception as exc:
                errors.append(f"bystander/{role}: {exc!r}")
        if errors:
            pytest.fail("\n".join(errors))
