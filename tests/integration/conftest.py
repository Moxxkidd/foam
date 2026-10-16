"""R10 集成实验层入口:opt-in 开关 + docker 可用性探测 + 会话级资源台账。

默认全量 pytest(macOS/CI)一律 skip,skip 原因写明启用方式;启用::

    FOAM_INTEGRATION=1 .venv/bin/python -m pytest -q tests/integration/ -v

前置:本机 docker 可用、本地已有 ``debian:12-slim`` 镜像(经镜像站拉取并重
tag,见 docs/items/R10.md §6)。实验镜像 ``foam-r10-lab:local`` 由本层现场
构建;全部容器/网络/镜像在会话结束清理,清理结果断言无残留。
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from .labkit import LAB_IMAGE, Lab, docker_available

_HERE = Path(__file__).resolve().parent

_ENABLE_HINT = (
    "R10 集成实验默认关闭(需要本机 docker 与 debian:12-slim 镜像,"
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
    """会话级实验台账:建销全部 docker 资源,结尾留清理实证并断言无残留。"""
    lab = Lab()
    yield lab
    lab.cleanup()
    rc_ps, ps = lab.run(["ps", "-a", "--format", "{{.Names}}"], check=False)
    rc_net, nets = lab.run(
        ["network", "ls", "--format", "{{.Names}}"], check=False
    )
    rc_img, imgs = lab.run(
        ["images", "--format", "{{.Repository}}:{{.Tag}}"], check=False
    )
    residue = [
        line
        for line in (ps + nets + imgs).splitlines()
        if lab.tag in line or LAB_IMAGE in line
    ]
    lab.evidence.append(
        "# 清理实证(会话收尾)\n"
        f"docker ps -a rc={rc_ps}; docker network ls rc={rc_net}; "
        f"docker images rc={rc_img}\n"
        f"本实验残留(应为空): {residue or '无'}\n"
    )
    path = lab.dump_evidence()
    print(f"\n[R10] docker 命令级实验实录: {path}")
    assert not residue, f"实验资源未清干净: {residue}"


@pytest.fixture(scope="session")
def lab_image(lab: Lab) -> str:
    lab.build_image()
    return LAB_IMAGE


@pytest.fixture(scope="session")
def harness(lab: Lab, lab_image: str) -> str:
    """方案 A 的特权实验容器:netns/nftables 实验全部在它内部完成。"""
    name = lab.add_container(lab.name("harness"))
    lab.run(
        [
            "run", "-d", "--name", name, "--privileged",
            lab_image, "sleep", "infinity",
        ]
    )
    return name
