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

from .labkit import Lab, docker_available

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


@pytest.fixture(scope="session")
def lab() -> Iterator[Lab]:
    """会话级实验台账:逐项清理,查询与清理错误均随实录上报。"""
    lab = Lab()
    try:
        yield lab
    finally:
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
                    "ps", "-a", "--filter", f"label=foam.r10.run={lab.tag}",
                    "--format", "{{.Names}}",
                ],
            ),
            (
                "网络",
                [
                    "network", "ls", "--filter", f"label=foam.r10.run={lab.tag}",
                    "--format", "{{.Names}}",
                ],
            ),
            (
                "镜像",
                [
                    "images", "--filter", f"label=foam.r10.run={lab.tag}",
                    "--format", "{{.Repository}}:{{.Tag}}",
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
            residue.extend(
                f"{kind}: {line}" for line in out.splitlines() if line.strip()
            )

        lab.evidence.append(
            "# 清理实证(会话收尾)\n"
            f"清理错误(应为空): {cleanup_errors or '无'}\n"
            f"查询错误(应为空): {query_errors or '无'}\n"
            f"本实验残留(应为空): {residue or '无'}\n"
        )
        path = lab.dump_evidence()
        print(f"\n[R10] docker 命令级实验实录: {path}")
        failures = [*cleanup_errors, *query_errors]
        if residue:
            failures.append(f"实验资源未清干净: {residue}")
        if failures:
            pytest.fail("\n".join(failures))


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
