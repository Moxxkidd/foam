"""R13-A:doctor/status 的真实 CLI、同源输出与零副作用契约。"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from foam.cli import main as cli_main
from foam.guard.audit import AuditLog
from foam.guard.scope import parse_scope, scope_payload
from foam.state.files import Engagement
from foam.tools.state import StateTool

SCOPE_TEXT = "127.0.0.0/8\nlocalhost\n"

_NO_NETWORK_CLI = """
import socket
import sys

def denied(*args, **kwargs):
    raise AssertionError("TESTONLY network access forbidden")

socket.socket.connect = denied
socket.getaddrinfo = denied
from foam.cli import main
raise SystemExit(main(sys.argv[1:]))
"""


def run_cli(args: list[str], *, cwd: Path, home: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", _NO_NETWORK_CLI, *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def tree_snapshot(root: Path) -> dict[str, dict]:
    snapshot = {}
    for path in [root, *sorted(root.rglob("*"))]:
        rel = "." if path == root else str(path.relative_to(root))
        info = path.lstat()
        entry = {
            "kind": (
                "dir"
                if stat.S_ISDIR(info.st_mode)
                else "file"
                if stat.S_ISREG(info.st_mode)
                else "other"
            ),
            "mode": stat.S_IMODE(info.st_mode),
            "size": info.st_size,
            "mtime_ns": info.st_mtime_ns,
        }
        if entry["kind"] == "file":
            entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        snapshot[rel] = entry
    return snapshot


def populate_engagement(base: Path) -> Engagement:
    engagement = Engagement.create(
        base / "engagements",
        "recon lab",
        scope_path=base / "lab.scope",
        scope_bytes=SCOPE_TEXT.encode(),
    )
    audit = AuditLog(engagement.paths.audit_jsonl)
    scope = parse_scope(SCOPE_TEXT)
    audit.append("scope_loaded", scope_payload(scope, "lab.scope"))
    audit.append("run_started", {"run_id": "r13-a", "objective": "recon lab"})
    budget = {"closing": {"tokens": 7}, "goal_status": "unfinished"}
    audit.append(
        "run_finished",
        {
            "run_id": "r13-a",
            "status": "stopped",
            "stop_reason": "rounds",
            "goal_status": "unfinished",
            "budget": budget,
        },
    )
    audit.close()

    loot = engagement.paths.loot / "sample.txt"
    loot.write_text("TESTONLY loot", encoding="utf-8")

    async def populate():
        tool = StateTool(engagement)
        await tool.dispatch(
            "state_add_vuln",
            {"host": "192.0.2.10", "kind": "config", "title": "TESTONLY finding"},
        )
        await tool.dispatch(
            "state_add_cred",
            {
                "host": "192.0.2.10",
                "username": "TESTONLY",
                "secret": "TESTONLY synthetic secret",
            },
        )
        await tool.dispatch(
            "state_add_loot", {"path": "loot/sample.txt", "kind": "dump"}
        )
        tool.close()

    asyncio.run(populate())
    manifest = engagement.paths.evidence / "manifest-r13-a.json"
    manifest.write_text("{}\n", encoding="utf-8")
    engagement.close()

    audit_path = engagement.paths.audit_jsonl
    existing = audit_path.read_bytes()
    audit_path.write_bytes(b"X" * 70000 + b"\n" + existing)
    return engagement


@pytest.mark.parametrize(
    "bad_config", [False, True], ids=["missing-config", "bad-config"]
)
def test_doctor_no_side_effects(tmp_path, bad_config):
    home = tmp_path / "home"
    cwd = tmp_path / "cwd"
    home.mkdir()
    cwd.mkdir()
    (cwd / ".env").write_text("FOAM_TESTONLY_INJ=1\n", encoding="utf-8")
    if bad_config:
        config = home / ".foam" / "config.json"
        config.parent.mkdir()
        config.write_text("{bad json\n", encoding="utf-8")

    before = tree_snapshot(tmp_path)
    human = run_cli(["doctor"], cwd=cwd, home=home)
    assert human.returncode == 0, human.stderr
    assert tree_snapshot(tmp_path) == before

    machine = run_cli(["doctor", "--json"], cwd=cwd, home=home)
    assert machine.returncode == 0, machine.stderr
    assert "[config] .env 注入" in machine.stderr
    data = json.loads(machine.stdout)
    assert data["schema"] == "foam.doctor/1"
    assert data["generated_at"].endswith("+00:00")
    assert [c["code"] for c in data["checks"]] == [
        "python.version",
        "foam.version",
        "deps.httpx",
        "deps.rich",
        "deps.textual",
    ]
    assert all(c["status"] == "pass" for c in data["checks"])
    for check in data["checks"]:
        assert f"[{check['code']}] {check['status']}" in human.stdout
        assert check["message"] in human.stdout
    assert tree_snapshot(tmp_path) == before


def test_status_no_side_effects(tmp_path):
    home = tmp_path / "home"
    cwd = tmp_path / "cwd"
    home.mkdir()
    cwd.mkdir()
    (cwd / ".env").write_text("FOAM_TESTONLY_INJ=1\n", encoding="utf-8")
    engagement = populate_engagement(tmp_path)
    root = engagement.paths.root
    root.chmod(0o555)
    before = tree_snapshot(tmp_path)

    human = run_cli(["status", str(root)], cwd=cwd, home=home)
    assert human.returncode == 0, human.stderr
    assert tree_snapshot(tmp_path) == before
    assert not list(root.glob("index.sqlite-*"))

    machine = run_cli(["status", str(root), "--json"], cwd=cwd, home=home)
    assert machine.returncode == 0, machine.stderr
    assert "[config] .env 注入" in machine.stderr
    data = json.loads(machine.stdout)
    assert data["schema"] == "foam.status/1"
    assert data["generated_at"].endswith("+00:00")
    assert data["run_state"] == "stopped"
    assert data["liveness"] == "none"
    assert data["objective"] == "recon lab"
    assert data["scope"]["sha256"] == hashlib.sha256(
        SCOPE_TEXT.encode()
    ).hexdigest()[:12]
    assert data["manifest"] is True
    assert data["counts"] == {"vulns": 1, "creds": 1, "loot": 1}
    assert data["budget"]["closing"]["tokens"] == 7
    assert data["last_activity"]["source"] == "audit"
    assert data["last_activity"]["kind"] == "run_finished"
    assert "resume" in data["next_action"]
    assert "verify" in data["next_action"]
    for text in (
        "运行结局:stopped",
        "活性:none",
        "目标:recon lab",
        "manifest:存在",
        "发现/凭证/loot:1/1/1",
        data["next_action"],
    ):
        assert text in human.stdout
    assert tree_snapshot(tmp_path) == before
    assert not list(root.glob("index.sqlite-*"))


def test_status_bad_meta_and_unreadable_heartbeat_degrade_unknown(tmp_path):
    home = tmp_path / "home"
    cwd = tmp_path / "cwd"
    home.mkdir()
    cwd.mkdir()
    bad = cwd / "bad"
    bad.mkdir()
    (bad / "engagement.json").write_text("{bad\n", encoding="utf-8")
    (bad / "audit.jsonl").touch()
    before = tree_snapshot(tmp_path)
    result = run_cli(["status", str(bad), "--json"], cwd=cwd, home=home)
    assert result.returncode == 3, result.stderr
    data = json.loads(result.stdout)
    assert data["run_state"] == "unknown"
    assert data["liveness"] == "none"
    assert tree_snapshot(tmp_path) == before

    heartbeat = Engagement.create(cwd / "engagements", "heartbeat")
    (heartbeat.paths.root / "heartbeat.json").write_text("{}\n", encoding="utf-8")
    heartbeat.close()
    before = tree_snapshot(tmp_path)
    result = run_cli(
        ["status", str(heartbeat.paths.root), "--json"], cwd=cwd, home=home
    )
    assert result.returncode == 3, result.stderr
    data = json.loads(result.stdout)
    assert data["liveness"] == "unknown"
    assert data["run_state"] == "unknown"
    assert tree_snapshot(tmp_path) == before


def test_status_usage_errors_rc2(tmp_path):
    home = tmp_path / "home"
    cwd = tmp_path / "cwd"
    home.mkdir()
    cwd.mkdir()
    before = tree_snapshot(tmp_path)
    missing = run_cli(["status", str(cwd / "missing")], cwd=cwd, home=home)
    assert missing.returncode == 2
    assert "不存在" in missing.stderr
    plain = run_cli(["status", str(cwd)], cwd=cwd, home=home)
    assert plain.returncode == 2
    assert "不是 engagement" in plain.stderr
    assert tree_snapshot(tmp_path) == before


def test_doctor_missing_dependency_rc1(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    original = importlib.util.find_spec

    def missing_rich(name):
        if name == "rich":
            return None
        return original(name)

    monkeypatch.setattr(importlib.util, "find_spec", missing_rich)
    assert cli_main(["doctor", "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    rich = next(c for c in data["checks"] if c["code"] == "deps.rich")
    assert rich["status"] == "fail"
    assert "缺失" in rich["message"]
