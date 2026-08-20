"""bash 执行面测试:工具 schema 契约、前台/后台生命周期、timeout、kill、
截断账目、分页一致、乱码不崩、100MB 大输出内存有界。

pyproject 已设 asyncio_mode = "auto",异步用例无需 marker。
"""

import asyncio
import hashlib
import json
import os
import signal
import time
import tracemalloc
from pathlib import Path

import pytest

from kalicode.tools.bash import (
    DEFAULT_OUTPUT_BUDGET_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    TOOL_SCHEMAS,
    BashTool,
)


@pytest.fixture
def tool(tmp_path):
    return BashTool(tmp_path / "outputs")


# ---------- 工具 schema 导出契约(WP-03/04/06 依赖的形状) ----------


def test_tool_schemas_shape():
    assert {s["name"] for s in TOOL_SCHEMAS} == {
        "run_command",
        "read_output",
        "list_jobs",
        "kill_job",
    }
    for schema in TOOL_SCHEMAS:
        assert set(schema) == {"name", "description", "parameters"}
        assert schema["parameters"]["type"] == "object"
        assert schema["parameters"]["additionalProperties"] is False
        assert isinstance(schema["description"], str) and schema["description"]
    run = next(s for s in TOOL_SCHEMAS if s["name"] == "run_command")
    assert run["parameters"]["required"] == ["command"]
    # timeout 允许显式 null(不限时),默认放宽到 1800
    timeout = run["parameters"]["properties"]["timeout_seconds"]
    assert timeout["type"] == ["number", "null"]
    assert timeout["default"] == DEFAULT_TIMEOUT_SECONDS == 1800.0
    # 必须可直接 JSON 序列化(WP-03 适配层 translate 的前提)
    json.dumps(TOOL_SCHEMAS)


# ---------- 前台执行与落盘账目 ----------


async def test_echo_foreground_full_view(tool):
    res = await tool.run_command("printf 'hello\\nworld\\n'")
    assert res["status"] == "completed"
    assert res["exit_code"] == 0
    assert res["duration_ms"] >= 0
    assert res["output_view"] == "hello\nworld\n"  # 未超预算:全文视图
    assert res["total_bytes"] == len(b"hello\nworld\n")
    assert res["total_lines"] == 2

    combined = Path(res["output_path"]).read_bytes()
    assert combined == b"hello\nworld\n"
    assert hashlib.sha256(combined).hexdigest() == res["sha256"]
    # 三分流:stdout 有内容,stderr 空文件但路径/哈希都在
    stdout_bytes = Path(res["stdout_path"]).read_bytes()
    assert stdout_bytes == combined
    assert hashlib.sha256(stdout_bytes).hexdigest() == res["stdout_sha256"]
    assert Path(res["stderr_path"]).read_bytes() == b""
    assert res["stderr_sha256"] == hashlib.sha256(b"").hexdigest()

    # 完结 job 已释放 ring(内存只随活动 job 增长)
    job = tool._jobs[res["job_id"]]
    assert job.recorder.ring_size == 0


async def test_nonzero_exit_keeps_completed(tool):
    res = await tool.run_command("echo partial; exit 3")
    assert res["status"] == "completed"
    assert res["exit_code"] == 3
    assert "partial" in res["output_view"]


async def test_stderr_split_files(tool):
    res = await tool.run_command("echo out-line; echo err-line >&2")
    assert res["status"] == "completed"
    stdout_text = Path(res["stdout_path"]).read_bytes()
    stderr_text = Path(res["stderr_path"]).read_bytes()
    assert stdout_text == b"out-line\n"
    assert stderr_text == b"err-line\n"
    combined = Path(res["output_path"]).read_bytes()
    assert set(combined.splitlines()) == {b"out-line", b"err-line"}


async def test_truncation_accounting_exact(tool):
    total = 100_000
    res = await tool.run_command(
        f"head -c {total} /dev/zero | tr '\\000' 'x'",
        output_budget_bytes=1000,
    )
    view = res["output_view"]
    assert res["total_bytes"] == total
    assert res["total_lines"] == 0  # 全程无换行,账目独立成立
    # head 500 + tail 500,省略 99000,三者相加恰好等于总字节
    assert view.startswith("x" * 500)
    assert view.endswith("x" * 500)
    assert f"省略 {total - 1000} 字节" in view
    assert "共 0 行" in view
    assert f"sha256:{res['sha256']}" in view
    assert res["output_path"] in view
    # 落盘文件与哈希复算一致
    on_disk = Path(res["output_path"]).read_bytes()
    assert len(on_disk) == total
    assert hashlib.sha256(on_disk).hexdigest() == res["sha256"]


# ---------- timeout / 后台 / kill ----------


async def test_timeout_kills_process_group(tool):
    start = time.monotonic()
    res = await tool.run_command("sleep 30", timeout_seconds=0.3)
    elapsed = time.monotonic() - start
    assert res["status"] == "timeout"
    assert res["exit_code"] == -signal.SIGKILL
    assert elapsed < 5  # 30 秒命令被快速终止
    # 进程真的死了(白盒取 pid 验证)
    pid = tool._jobs[res["job_id"]].proc.pid
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


async def test_background_does_not_block_and_kill_works(tool):
    start = time.monotonic()
    bg = await tool.run_command("sleep 30", background=True, timeout_seconds=None)
    assert time.monotonic() - start < 2  # 后台化立即返回
    assert bg["status"] == "running"
    assert bg["sha256"] is None  # 未完结,哈希未出
    assert bg["output_path"].endswith(".log")
    assert Path(bg["output_path"]).exists()

    # 前台不被后台长跑命令阻塞(验收 2)
    fg = await tool.run_command("echo still-alive")
    assert fg["status"] == "completed"
    assert fg["output_view"] == "still-alive\n"

    killed = await tool.kill_job(bg["job_id"])
    assert killed["status"] == "killed"
    assert killed["exit_code"] == -signal.SIGKILL
    assert killed["sha256"] is not None  # 完结后哈希已出


async def test_kill_running_foreground_job(tool):
    task = asyncio.create_task(tool.run_command("sleep 30", timeout_seconds=60))
    await asyncio.sleep(0.3)
    [running] = [
        j for j in (await tool.list_jobs())["jobs"] if j["status"] == "running"
    ]
    res = await tool.kill_job(running["job_id"])
    assert res["status"] == "killed"
    final = await task  # 前台协程同样看到 killed 终态
    assert final["status"] == "killed"
    assert final["exit_code"] == -signal.SIGKILL


async def test_kill_finished_job_is_noop(tool):
    res = await tool.run_command("true")
    again = await tool.kill_job(res["job_id"])
    assert again["status"] == "completed"
    assert "无需 kill" in again["note"]


async def test_default_timeout_and_explicit_null(tmp_path):
    fast = BashTool(tmp_path / "o", default_timeout_seconds=0.3)
    res = await fast.run_command("sleep 5")  # 省略参数 → 实例默认
    assert res["status"] == "timeout"
    ok = await fast.run_command("sleep 0.1", timeout_seconds=None)  # 显式不限时
    assert ok["status"] == "completed"


# ---------- list_jobs / read_output ----------


async def test_list_jobs_remaining_time(tool):
    bounded = await tool.run_command("sleep 30", background=True, timeout_seconds=30)
    unbounded = await tool.run_command(
        "sleep 30", background=True, timeout_seconds=None
    )
    done = await tool.run_command("true")

    jobs = {j["job_id"]: j for j in (await tool.list_jobs())["jobs"]}
    remaining = jobs[bounded["job_id"]]["timeout_remaining_seconds"]
    assert 0 < remaining <= 30
    assert jobs[unbounded["job_id"]]["timeout_remaining_seconds"] is None
    assert jobs[done["job_id"]]["timeout_remaining_seconds"] is None
    assert jobs[bounded["job_id"]]["background"] is True
    assert jobs[done["job_id"]]["background"] is False

    await tool.kill_job(bounded["job_id"])
    await tool.kill_job(unbounded["job_id"])


async def test_read_output_pagination_matches_file(tool):
    res = await tool.run_command("seq 1 2000")
    expected = Path(res["output_path"]).read_bytes().decode()

    chunks, offset, pages = [], 0, 0
    while True:
        page = await tool.read_output(res["job_id"], offset=offset, limit=997)
        assert page["status"] == "completed"
        assert page["sha256"] == res["sha256"]
        assert page["total_bytes"] == len(expected.encode())
        chunks.append(page["content"])
        offset += page["bytes_read"]
        pages += 1
        if not page["has_more"]:
            break
        assert pages < 100  # 防死循环
    assert "".join(chunks) == expected  # 分页重组 == 全量落盘(验收 1)


async def test_read_output_running_job_partial(tool):
    bg = await tool.run_command(
        "for i in 1 2 3; do echo line$i; sleep 0.2; done",
        background=True,
        timeout_seconds=10,
    )
    page = await tool.read_output(bg["job_id"], offset=0, limit=1024)
    assert page["status"] == "running"
    assert page["sha256"] is None  # 未完结没有最终哈希
    assert page["bytes_read"] >= 0  # 内容随到达量,不断言具体值(防时序 flake)
    await tool.kill_job(bg["job_id"])


async def test_unknown_job_errors(tool):
    assert "error" in await tool.read_output("no-such-job")
    assert "error" in await tool.kill_job("no-such-job")


async def test_read_output_bad_args(tool):
    res = await tool.run_command("echo x")
    assert "error" in await tool.read_output(res["job_id"], offset=-1)
    assert "error" in await tool.read_output(res["job_id"], limit=0)


# ---------- 健壮性:乱码与大输出 ----------


async def test_binary_output_no_crash(tool):
    res = await tool.run_command("printf '\\000\\377\\376\\375\\n'")
    assert res["status"] == "completed"
    raw = Path(res["output_path"]).read_bytes()
    assert raw == b"\x00\xff\xfe\xfd\n"  # 落盘是原始字节
    assert hashlib.sha256(raw).hexdigest() == res["sha256"]
    assert "�" in res["output_view"]  # 视图错误替换,不崩


async def test_hundred_mb_output_memory_bounded(tool):
    size = 100 * 1024 * 1024
    tracemalloc.start()
    res = await tool.run_command(f"head -c {size} /dev/zero | tr '\\000' 'y'")
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert res["status"] == "completed"
    assert res["total_bytes"] == size
    assert Path(res["output_path"]).stat().st_size == size
    # 视图按默认预算截断,省略字节数精确
    assert f"省略 {size - DEFAULT_OUTPUT_BUDGET_BYTES} 字节" in res["output_view"]
    # Python 侧峰值有界(定长块 + ring),远小于 100MB 文件本身
    assert peak < 32 * 1024 * 1024, f"峰值内存 {peak / 1024 / 1024:.1f}MB 超界"
    # 哈希复算
    digest = hashlib.sha256(Path(res["output_path"]).read_bytes())
    assert digest.hexdigest() == res["sha256"]


# ---------- dispatch 入口 ----------


async def test_dispatch_roundtrip(tool):
    res = await tool.dispatch("run_command", {"command": "echo via-dispatch"})
    assert res["status"] == "completed"
    assert "via-dispatch" in res["output_view"]
    listed = await tool.dispatch("list_jobs", {})
    assert listed["count"] == 1


async def test_dispatch_unknown_tool_raises(tool):
    with pytest.raises(KeyError):
        await tool.dispatch("not-a-tool", {})
