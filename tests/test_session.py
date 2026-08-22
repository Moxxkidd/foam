"""WP-05 持久 PTY 会话层测试。

验收对照:
1. python -i 多轮 send/read、cat 回显、超时、关闭 → 本文件交互单测全绿;
   提示识别对 fixture 命中/不误报(test_prompt_fixtures_*)。
2. 全量落盘 + 哈希可校验、LLM 视图 ANSI 已清洗 → test_view_stripped_disk_raw
   及各交互用例的 sha256 复算。
3. ssh localhost 集成:环境允许才跑,否则 skip(本机实测记录见开发日志)。
4. msfconsole:非 Kali 环境 skip,待 Kali 实测(见开发日志)。
5. 会话上限与孤儿进程回收:test_max_sessions / test_orphan_grandchild_killed。

pyproject 已设 asyncio_mode = "auto",异步用例无需 marker。
"""

import asyncio
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import time
from pathlib import Path

import pytest

from foam.tools.session import (
    PROMPT_PATTERNS,
    TOOL_SCHEMAS,
    SessionTool,
    detect_prompt,
    strip_ansi,
)


@pytest.fixture
async def tool(tmp_path):
    t = SessionTool(tmp_path / "sess")
    yield t
    await t.aclose()  # 用例失败也不留孤儿会话


# ---------- 工具 schema 导出契约(与 WP-01 同构,WP-04 直接注册) ----------


def test_tool_schemas_shape():
    assert {s["name"] for s in TOOL_SCHEMAS} == {
        "session_open",
        "session_send",
        "session_read",
        "session_close",
        "session_list",
    }
    for schema in TOOL_SCHEMAS:
        assert set(schema) == {"name", "description", "parameters"}
        assert schema["parameters"]["type"] == "object"
        assert schema["parameters"]["additionalProperties"] is False
    send = next(s for s in TOOL_SCHEMAS if s["name"] == "session_send")
    assert send["parameters"]["required"] == ["session_id", "text"]
    json.dumps(TOOL_SCHEMAS)  # 必须可直接序列化(WP-03 适配层前提)


# ---------- ANSI 清洗(纯函数;落盘原文在交互用例里验证) ----------


def test_strip_ansi_colors_and_csi():
    assert strip_ansi(b"\x1b[1;31mRED\x1b[0m plain") == b"RED plain"
    assert strip_ansi(b"\x1b[2K\x1b[Ghello") == b"hello"  # 清行 + 光标回列
    assert strip_ansi(b"\x1b[?25lshow\x1b[?25h") == b"show"  # 隐私标序列


def test_strip_ansi_osc_title():
    assert strip_ansi(b"\x1b]0;window title\x07rest") == b"rest"
    assert strip_ansi(b"\x1b]0;t\x1b\\rest") == b"rest"  # ST 结尾变体


def test_strip_ansi_cr_overlay():
    assert strip_ansi(b"aaaa\rbb") == b"bbaa"  # 终端覆盖语义:bb 覆写前两列
    assert strip_ansi(b"abc\r") == b"abc"  # 行尾纯回车不清空
    assert strip_ansi(b"10%\r50%\r99%") == b"99%"  # 进度条重绘取最后一帧
    assert strip_ansi(b"line1\r\nline2") == b"line1\nline2"  # CRLF 正常


def test_strip_ansi_backspace():
    assert strip_ansi(b"ab\x08c") == b"ac"
    assert strip_ansi(b"abc\x08\x08X") == b"aX"  # 连续退格


# ---------- 提示识别 fixture:命中(验收 1 后半) ----------

@pytest.mark.parametrize(
    ("text", "ptype"),
    [
        ("msf6 > ", "msf6"),
        ("msf6 exploit(multi/handler) > ", "msf6"),
        ("msf6 auxiliary(scanner/ssh/ssh_login) > ", "msf6"),
        ("msf > ", "msf6"),
        ("meterpreter > ", "meterpreter"),
        ("[sudo] password for an:", "password"),
        ("an@192.168.56.10's password:", "password"),
        ("Enter passphrase for key '/home/an/.ssh/id_rsa':", "password"),
        ("(yes/no)?", "ssh_yes_no"),
        ("Are you sure you want to continue connecting (yes/no/[fingerprint])?",
         "ssh_yes_no"),
        ("do you want to keep testing? [Y/n]", "yn_bracket"),
        ("do you want to quit? [y/N]", "yn_bracket"),
        ("how many threads? [Y/n/q]", "yn_bracket"),
    ],
)
def test_prompt_fixtures_hit(text, ptype):
    hit = detect_prompt(text)
    assert hit is not None, f"未命中: {text!r}"
    assert hit.prompt_type == ptype


@pytest.mark.parametrize(
    "text",
    [
        "the password field is present in the page",  # 正文提及而非询问
        "nmap done: 1 IP address (1 host up)",
        "usage: prog [options] file",
        "msf6 is starting, please wait...",  # 提及 msf6 但非提示符
        "Loaded 2000 exploits\nmsf6 banner printed",
        ">>> ",  # python 提示符不在规格四类库内
        "ratio [3/4] done",  # 方括号但非 y/n
        "answer: yes/no",  # 无括号
        "continue? [Y/n]\nloaded 2000 requests and done",  # 提示不在尾部
        "sqlite> ",  # 未收录的交互提示不误报
    ],
)
def test_prompt_fixtures_no_false_positive(text):
    assert detect_prompt(text) is None


def test_prompt_library_covers_spec_families():
    # 规格点名:sqlmap [Y/n] 系、msf6 系、password 系、(yes/no) 系
    assert {p.prompt_type for p in PROMPT_PATTERNS} >= {
        "msf6",
        "password",
        "ssh_yes_no",
        "yn_bracket",
    }


# ---------- 交互单测:python -i 多轮 / cat 回显 / 超时 / 关闭(验收 1) ----------


async def test_python_interactive_multi_round(tool):
    s = await tool.session_open("python3 -i")
    sid = s["session_id"]
    r = await tool.session_read(sid, wait_pattern=r">>> ", timeout_seconds=10)
    assert r["matched"] is True
    assert "Python" in r["new_output"]  # banner 进了增量视图

    await tool.session_send(sid, "1+1")
    r = await tool.session_read(sid, wait_pattern=r">>> ", timeout_seconds=10)
    assert r["matched"] is True
    assert "2" in r["new_output"]

    await tool.session_send(sid, "x = 40 + 1")
    r = await tool.session_read(sid, wait_pattern=r">>> ", timeout_seconds=10)
    assert r["matched"] is True
    await tool.session_send(sid, "x + 1")
    r = await tool.session_read(sid, wait_pattern=r">>> ", timeout_seconds=10)
    assert "42" in r["new_output"]

    done = await tool.session_close(sid)
    assert done["status"] == "closed"
    assert done["sha256"] is not None
    raw = Path(done["output_path"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == done["sha256"]
    assert b"42" in raw  # 原文落盘


async def test_cat_echo(tool):
    s = await tool.session_open("cat")
    sid = s["session_id"]
    await tool.session_send(sid, "hello-pty-456")
    r = await tool.session_read(sid, wait_pattern="hello-pty-456", timeout_seconds=5)
    assert r["matched"] is True
    await tool.session_close(sid)


async def test_send_auto_appends_newline(tool):
    # canonical 模式下 cat 收不到不带换行的输入;tty 回显一份、cat 输出一份,
    # 两处都出现即证明行尾被自动补上(验收 1:send 自动补行尾)。
    s = await tool.session_open("cat")
    sid = s["session_id"]
    sent = await tool.session_send(sid, "probe-no-newline")
    assert sent["bytes_written"] == len(b"probe-no-newline\n")
    r = await tool.session_read(
        sid, wait_pattern=r"probe-no-newline[\s\S]*probe-no-newline",
        timeout_seconds=5,
    )
    assert r["matched"] is True
    await tool.session_close(sid)


async def test_read_wait_timeout(tool):
    s = await tool.session_open("cat")
    start = time.monotonic()
    r = await tool.session_read(
        s["session_id"], wait_pattern="NEVER_MATCH_XYZ", timeout_seconds=0.5
    )
    elapsed = time.monotonic() - start
    assert r["matched"] is False
    assert r["timed_out"] is True
    assert 0.4 <= elapsed < 5
    await tool.session_close(s["session_id"])


async def test_close_kills_process(tool):
    s = await tool.session_open("cat")
    pid = s["pid"]
    done = await tool.session_close(s["session_id"])
    assert done["status"] == "closed"
    assert done["exit_code"] == -signal.SIGKILL
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)  # 进程真死,非仅标记
    # 已关闭会话拒绝写入
    rejected = await tool.session_send(s["session_id"], text="x")
    assert "error" in rejected


async def test_natural_exit_becomes_exited(tool):
    s = await tool.session_open("echo done-marker-xyz")
    sid = s["session_id"]
    output = ""
    for _ in range(50):  # 最多等 5s
        r = await tool.session_read(sid)
        output += r["new_output"]
        if r["status"] != "running":
            break
        await asyncio.sleep(0.1)
    assert r["status"] == "exited"
    assert r["sha256"] is not None  # 自然退出也会定稿哈希
    assert "done-marker-xyz" in output
    listed = {e["session_id"]: e for e in (await tool.session_list())["sessions"]}
    assert listed[sid]["exit_code"] == 0
    rejected = await tool.session_send(sid, text="x")
    assert "error" in rejected
    done = await tool.session_close(sid)  # exited 也可 close(释放配额/fd)
    assert done["status"] == "exited"
    assert done["sha256"] is not None


async def test_unknown_session_errors(tool):
    assert "error" in await tool.session_send("no-such", text="x")
    assert "error" in await tool.session_read("no-such")
    assert "error" in await tool.session_close("no-such")


# ---------- 验收 2:视图清洗 vs 落盘原文 ----------


async def test_view_stripped_disk_raw(tool):
    s = await tool.session_open("printf '\\033[1;32mGREEN-TAG\\033[0m\\n'; cat")
    sid = s["session_id"]
    r = await tool.session_read(sid, wait_pattern="GREEN-TAG", timeout_seconds=5)
    assert r["matched"] is True
    assert "GREEN-TAG" in r["new_output"]
    assert "\x1b" not in r["new_output"]  # LLM 视图无 ANSI
    done = await tool.session_close(sid)
    raw = Path(done["output_path"]).read_bytes()
    assert b"\x1b[1;32m" in raw  # 落盘保留原文
    assert hashlib.sha256(raw).hexdigest() == done["sha256"]


# ---------- 结构化提示事件 E2E(命中 + 去重) ----------

async def test_prompt_event_password_e2e(tool):
    s = await tool.session_open("read -p 'admin password: ' x; echo got:$x")
    sid = s["session_id"]
    await asyncio.sleep(0.5)  # 等提示打印
    r = await tool.session_read(sid)
    hits = [e for e in r["events"] if e["prompt_type"] == "password"]
    assert hits, f"未识别 password 提示: {r['new_output']!r}"
    assert hits[0]["type"] == "waiting_for_input"
    assert "password" in hits[0]["text"]
    # 同一输出位置不重复触发,且事件已被上次 read 取走
    r2 = await tool.session_read(sid)
    assert r2["events"] == []
    await tool.session_send(sid, "hunter2")  # 合成凭据,TESTONLY 语境
    r3 = await tool.session_read(sid, wait_pattern=r"got:hunter2", timeout_seconds=5)
    assert r3["matched"] is True
    await tool.session_close(sid)


async def test_prompt_event_sqlmap_yn_e2e(tool):
    s = await tool.session_open(
        "printf 'do you want to continue? [Y/n] '; read a; echo ans:$a"
    )
    sid = s["session_id"]
    await asyncio.sleep(0.5)
    r = await tool.session_read(sid)
    assert any(e["prompt_type"] == "yn_bracket" for e in r["events"])
    await tool.session_send(sid, "Y")
    r = await tool.session_read(sid, wait_pattern="ans:Y", timeout_seconds=5)
    assert r["matched"] is True
    await tool.session_close(sid)


async def test_prompt_event_msf6_like_e2e(tool):
    s = await tool.session_open(
        "printf 'msf6 exploit(multi/handler) > '; read c; echo ran:$c"
    )
    sid = s["session_id"]
    await asyncio.sleep(0.5)
    r = await tool.session_read(sid)
    hits = [e for e in r["events"] if e["prompt_type"] == "msf6"]
    assert hits
    assert hits[0]["text"] == "msf6 exploit(multi/handler) >"
    await tool.session_send(sid, "help")
    r = await tool.session_read(sid, wait_pattern="ran:help", timeout_seconds=5)
    assert r["matched"] is True
    await tool.session_close(sid)


# ---------- 验收 5:会话上限与孤儿回收 ----------

async def test_max_sessions(tmp_path):
    t = SessionTool(tmp_path / "s", max_sessions=2)
    try:
        a = await t.session_open("cat")
        b = await t.session_open("cat")
        assert a["status"] == b["status"] == "running"
        c = await t.session_open("cat")
        assert "error" in c and "上限" in c["error"]
        await t.session_close(a["session_id"])
        d = await t.session_open("cat")  # 释放后可再开
        assert d["status"] == "running"
    finally:
        await t.aclose()


async def test_orphan_grandchild_killed(tool):
    # bash -c 起孙进程 sleep;整组 SIGKILL 后孙进程必须同死(防孤儿)
    s = await tool.session_open("sleep 60 & echo BGPID:$!; exec cat")
    sid = s["session_id"]
    r = await tool.session_read(sid, wait_pattern=r"BGPID:\d+", timeout_seconds=5)
    assert r["matched"] is True
    grandchild = int(re.search(r"BGPID:(\d+)", r["new_output"]).group(1))
    done = await tool.session_close(sid)
    assert done["status"] == "closed"
    await asyncio.sleep(0.1)  # SIGKILL 落地
    with pytest.raises(ProcessLookupError):
        os.kill(grandchild, 0)


# ---------- 增量读取预算 / has_more ----------

async def test_read_budget_and_has_more(tmp_path):
    t = SessionTool(tmp_path / "s", read_budget_bytes=1000)
    try:
        s = await t.session_open("python3 -c 'print(\"A\" * 50000, end=\"\")'; cat")
        sid = s["session_id"]
        await asyncio.sleep(0.6)  # 50KB 一次写不完 pty 缓冲,给足产出时间
        total = 0
        for _ in range(200):
            r = await t.session_read(sid)
            assert r["new_bytes"] <= 1000  # 单次视图受预算约束
            total += r["new_bytes"]
            if not r["has_more"]:
                break
            await asyncio.sleep(0.02)
        assert total == 50000
        assert r["total_bytes"] == 50000
    finally:
        await t.aclose()


# ---------- session_list / dispatch / aclose ----------

async def test_session_list_fields(tool):
    s = await tool.session_open("cat")
    sid = s["session_id"]
    listed = await tool.session_list()
    assert listed["count"] == 1
    entry = listed["sessions"][0]
    assert entry["session_id"] == sid
    assert entry["status"] == "running"
    assert entry["pid"] == s["pid"]
    assert entry["pending_events"] == 0
    assert entry["output_path"].endswith(".log")
    await tool.session_close(sid)
    listed = await tool.session_list()
    assert listed["sessions"][0]["status"] == "closed"


async def test_dispatch_roundtrip_and_unknown(tool):
    s = await tool.dispatch("session_open", {"command": "cat"})
    assert s["status"] == "running"
    listed = await tool.dispatch("session_list", {})
    assert listed["count"] == 1
    done = await tool.dispatch("session_close", {"session_id": s["session_id"]})
    assert done["status"] == "closed"
    with pytest.raises(KeyError):
        await tool.dispatch("not-a-tool", {})


async def test_aclose_all(tmp_path):
    t = SessionTool(tmp_path / "s")
    a = await t.session_open("cat")
    b = await t.session_open("cat")
    await t.aclose()
    for pid in (a["pid"], b["pid"]):
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
    listed = await t.session_list()
    assert {e["status"] for e in listed["sessions"]} == {"closed"}


# ---------- 验收 3:ssh localhost 集成(环境允许才跑) ----------


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


async def _ssh_would_prompt_password() -> bool:
    """BatchMode + 仅密码探测:返回非 0 说明会走到交互口令提示。"""
    try:
        proc = await asyncio.create_subprocess_exec(
            "ssh", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=3",
            "localhost", "true",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=10)
    except (OSError, TimeoutError):
        return False
    return proc.returncode != 0


async def test_ssh_localhost_password_prompt(tool):
    if shutil.which("ssh") is None:
        pytest.skip("无 ssh 客户端")
    if not _port_open(22):
        pytest.skip("本机 sshd 未运行(集成项按规格 skip)")
    if not await _ssh_would_prompt_password():
        pytest.skip("本机 ssh 免密/拒口令登录,触发不了 password 提示")
    s = await tool.session_open(
        "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o PreferredAuthentications=password -o PubkeyAuthentication=no "
        "-o ConnectTimeout=5 localhost true"
    )
    r = await tool.session_read(
        s["session_id"], wait_pattern=r"(?i)password\s*:", timeout_seconds=20
    )
    assert r["matched"] is True
    assert any(e["prompt_type"] == "password" for e in r["events"])
    await tool.session_close(s["session_id"])


# ---------- 验收 4:msfconsole(非 Kali skip,待 Kali 实测补跑) ----------

_MSFCONSOLE = shutil.which("msfconsole")


@pytest.mark.skipif(
    _MSFCONSOLE is None,
    reason="非 Kali 环境无 msfconsole——验收 4 待 Kali 实测补跑(见开发日志)",
)
async def test_msfconsole_full_flow(tool):
    # wait_pattern 必须两代提示符通吃:6.x 早期是 "msf6 > ",6.4.84 起实测改回
    # "msf > "(Kali 补测落盘原文实证,见 docs/dev-logs/WP-05.md「补测」)。
    # harness 的 PROMPT_PATTERNS 用 msf[56]? 本就兼容,是这里原先写死了旧字面量。
    s = await tool.session_open("msfconsole -q")  # -q 抑制启动 banner
    sid = s["session_id"]
    r = await tool.session_read(sid, wait_pattern=r"msf[56]? >", timeout_seconds=180)
    assert r["matched"] is True
    assert any(e["prompt_type"] == "msf6" for e in r["events"])

    await tool.session_send(sid, "use exploit/multi/handler")
    r = await tool.session_read(
        sid, wait_pattern=r"msf[56]? exploit\(multi/handler\) >", timeout_seconds=60
    )
    assert r["matched"] is True
    assert any(e["prompt_type"] == "msf6" for e in r["events"])

    await tool.session_send(sid, "info")
    r = await tool.session_read(
        sid, wait_pattern=r"msf[56]? exploit", timeout_seconds=60
    )
    assert "Payload options" in r["new_output"] or "Name:" in r["new_output"]

    await tool.session_send(sid, "exit")
    done = await tool.session_close(sid)
    assert done["sha256"] is not None
