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


def run_cli(
    args: list[str], *, cwd: Path, home: Path, env_changes: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    for key in (
        "FOAM_LLM_API_KEY",
        "FOAM_ANTHROPIC_API_KEY",
        "FOAM_LLM_BASE_URL",
        "FOAM_LLM_MODEL",
    ):
        env.pop(key, None)
    env["FOAM_LLM_API_KEY"] = "sk-TESTONLY-doctor"
    env["FOAM_LLM_BASE_URL"] = "https://example.com"
    if env_changes:
        env.update(env_changes)
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
    expected_rc = 1 if bad_config else 0
    human = run_cli(["doctor"], cwd=cwd, home=home)
    assert human.returncode == expected_rc, human.stderr
    assert tree_snapshot(tmp_path) == before

    machine = run_cli(["doctor", "--json"], cwd=cwd, home=home)
    assert machine.returncode == expected_rc, machine.stderr
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
        "config.dotenv",
        "config.file",
        "config.profile",
        "backend.resolved",
        "backend.api_key",
        "tools.inventory",
        "workdir.engagements",
        "exec.protected",
        "exec.stale_boundaries",
        "online.base_url",
    ]
    assert all(c["status"] == "pass" for c in data["checks"][:5])
    assert next(c for c in data["checks"] if c["code"] == "online.base_url")[
        "status"
    ] == "skip"
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


@pytest.mark.parametrize(
    "case",
    [
        "bad-json",
        "non-object",
        "non-0600",
        "api-key-field",
        "profile-missing",
        "illegal-backend",
        "missing-key",
        "missing-base-url",
    ],
)
def test_doctor_bad_config_remediation(tmp_path, monkeypatch, capsys, case):
    """R13-B:八类配置/后端问题均给出可执行的中文处置。"""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("FOAM_LLM_API_KEY", "sk-TESTONLY")
    monkeypatch.setenv("FOAM_ANTHROPIC_API_KEY", "sk-TESTONLY")
    monkeypatch.setenv("FOAM_LLM_BASE_URL", "https://example.com")
    monkeypatch.delenv("FOAM_LLM_MODEL", raising=False)
    config_path = tmp_path / ".foam" / "config.json"
    args = ["doctor", "--json"]
    expected = "config.file"

    if case in {"bad-json", "non-object", "non-0600", "api-key-field"}:
        config_path.parent.mkdir()
        if case == "bad-json":
            config_path.write_text("{bad\n", encoding="utf-8")
        elif case == "non-object":
            config_path.write_text("[]\n", encoding="utf-8")
        elif case == "non-0600":
            config_path.write_text("{}\n", encoding="utf-8")
            config_path.chmod(0o644)
        else:
            config_path.write_text(
                json.dumps({"api_key": "TESTONLY-CONFIG-SECRET"}), encoding="utf-8"
            )
    elif case == "profile-missing":
        args += ["--profile", "missing"]
        expected = "config.profile"
    elif case == "illegal-backend":
        config_path.parent.mkdir()
        config_path.write_text(
            json.dumps(
                {
                    "active_profile": "bad",
                    "profiles": {
                        "bad": {
                            "backend": "invalid",
                            "model": "k3",
                            "base_url": "https://example.com",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        expected = "config.profile"
    elif case == "missing-key":
        monkeypatch.delenv("FOAM_LLM_API_KEY")
        monkeypatch.delenv("FOAM_ANTHROPIC_API_KEY")
        args += ["--backend", "claude"]
        expected = "backend.api_key"
    else:
        monkeypatch.delenv("FOAM_LLM_BASE_URL")
        args += ["--backend", "openai_compat"]
        expected = "backend.resolved"

    expected_rc = 0 if case in {"non-0600", "api-key-field"} else 1
    assert cli_main(args) == expected_rc
    data = json.loads(capsys.readouterr().out)
    check = next(c for c in data["checks"] if c["code"] == expected)
    assert check["remediation"]
    if case in {"bad-json", "non-object"}:
        assert check["status"] == "fail"
        assert "静默忽略" in check["message"]
        assert "profile 不生效" in check["message"]
        assert "修复" in check["remediation"]
    elif case == "non-0600":
        assert check["status"] == "warn"
        assert "0600" in check["message"]
        assert "chmod 600" in check["remediation"]
    elif case == "api-key-field":
        assert check["status"] == "warn"
        assert "api_key" in check["message"]
        assert "白名单" in check["message"]
        assert "删除" in check["remediation"]
    elif case == "profile-missing":
        assert check["status"] == "fail"
        assert "missing" in check["message"]
        assert "--profile" in check["remediation"]
    elif case == "illegal-backend":
        assert check["status"] == "fail"
        assert "非法" in check["message"]
        assert "openai_compat" in check["remediation"]
        assert "claude" in check["remediation"]
    elif case == "missing-key":
        assert check["status"] == "fail"
        assert "未设置" in check["message"]
        assert "FOAM_ANTHROPIC_API_KEY" in check["remediation"]
    else:
        assert check["status"] == "fail"
        assert "base_url" in check["message"]
        assert "--base-url" in check["remediation"]


def test_diagnostics_redacts_secrets(tmp_path, monkeypatch, capsys):
    """R13-B:env/.env/config、URL、异常与 stderr 三路均不泄漏合成秘密。"""
    import foam.cli as cli
    import foam.diagnostics as diagnostics

    secrets = {
        "sk-TESTONLY-env-secret",
        "sk-TESTONLY-dotenv-secret",
        "TESTONLY-CONFIG-SECRET",
        "TESTONLY-URL-PASSWORD",
        "TESTONLY-QUERY-SECRET",
    }
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("FOAM_LLM_API_KEY", "sk-TESTONLY-env-secret")
    (tmp_path / ".env").write_text(
        "FOAM_TEST_TOKEN=sk-TESTONLY-dotenv-secret\n", encoding="utf-8"
    )
    config = tmp_path / ".foam" / "config.json"
    config.parent.mkdir()
    config.write_text(
        json.dumps({"api_key": "TESTONLY-CONFIG-SECRET"}), encoding="utf-8"
    )
    base_url = (
        "https://user:TESTONLY-URL-PASSWORD@example.com/v1"
        "?api_key=TESTONLY-QUERY-SECRET&ok=1"
    )

    def fail_inventory():
        raise RuntimeError(
            "TESTONLY exception sk-TESTONLY-env-secret TESTONLY-CONFIG-SECRET"
        )

    monkeypatch.setattr(diagnostics, "scan_tools", fail_inventory, raising=False)
    original_dotenv = cli.load_dotenv

    def warning_with_secret(path):
        injected, warnings = original_dotenv(path)
        return injected, [*warnings, "TESTONLY stderr sk-TESTONLY-env-secret"]

    monkeypatch.setattr(cli, "load_dotenv", warning_with_secret)
    args = ["doctor", "--base-url", base_url]
    assert cli_main(args) == 3
    human = capsys.readouterr()
    assert cli_main([*args, "--json"]) == 3
    machine = capsys.readouterr()
    combined = human.out + human.err + machine.out + machine.err
    for secret in secrets:
        assert secret not in combined
    assert "<已脱敏>" in combined
    assert "https://example.com/v1?api_key=***&ok=1" in combined
    data = json.loads(machine.out)
    inventory = next(c for c in data["checks"] if c["code"] == "tools.inventory")
    assert inventory["status"] == "unknown"
    assert "TESTONLY exception" in inventory["message"]


def test_doctor_never_writes(tmp_path):
    """R13-B：坏配置、畸形 .env 与不存在的嵌套 workdir 均零落盘。"""
    home = tmp_path / "home"
    cwd = tmp_path / "cwd"
    config = home / ".foam" / "config.json"
    config.parent.mkdir(parents=True)
    config.write_text("{bad\n", encoding="utf-8")
    cwd.mkdir()
    (cwd / ".env").write_text("BROKEN\n", encoding="utf-8")
    before = tree_snapshot(tmp_path)
    result = run_cli(
        ["doctor", "--json", "--workdir", str(tmp_path / "missing" / "nested")],
        cwd=cwd,
        home=home,
    )
    assert result.returncode == 1, result.stderr
    data = json.loads(result.stdout)
    dotenv = next(c for c in data["checks"] if c["code"] == "config.dotenv")
    assert dotenv["status"] == "warn"
    assert "第 1 行" in dotenv["message"]
    assert tree_snapshot(tmp_path) == before


def test_doctor_backend_sources_and_sanitized_url(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("FOAM_LLM_MODEL", "env-model")
    monkeypatch.setenv("FOAM_ANTHROPIC_API_KEY", "sk-TESTONLY")
    config = tmp_path / ".foam" / "config.json"
    config.parent.mkdir()
    config.write_text(
        json.dumps(
            {
                "active_profile": "saved",
                "profiles": {
                    "saved": {
                        "backend": "openai_compat",
                        "model": "profile-model",
                        "base_url": "https://profile.example.com",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    assert (
        cli_main(
            [
                "doctor",
                "--json",
                "--backend",
                "claude",
                "--base-url",
                "https://user:TESTONLY@example.com?api_key=TESTONLY",
            ]
        )
        == 0
    )
    data = json.loads(capsys.readouterr().out)
    backend = next(c for c in data["checks"] if c["code"] == "backend.resolved")
    assert backend["details"]["sources"] == {
        "backend": "flag",
        "model": "env",
        "base_url": "flag",
    }
    assert backend["details"]["base_url"] == "https://example.com?api_key=***"


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_doctor_online_only_dns_tcp_and_tls(
    tmp_path, monkeypatch, capsys, scheme
):
    """R13-B D2:online 仅 DNS/TCP/(https)TLS,无 HTTP 读写。"""
    import socket

    import foam.diagnostics as diagnostics

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("FOAM_LLM_API_KEY", "sk-TESTONLY")
    calls = {"dns": 0, "connect": 0, "tls": 0}

    class FakeSocket:
        def __init__(self):
            self.timeouts = []

        def settimeout(self, value):
            self.timeouts.append(value)

        def connect(self, address):
            calls["connect"] += 1
            assert address == ("192.0.2.10", 8443)

        def do_handshake(self):
            calls["tls"] += 1

        def close(self):
            pass

    sockets = []

    def fake_socket(*_args, **_kwargs):
        sock = FakeSocket()
        sockets.append(sock)
        return sock

    def fake_getaddrinfo(*_args, **_kwargs):
        calls["dns"] += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 8443))]

    class FakeContext:
        def wrap_socket(self, sock, *, server_hostname):
            assert server_hostname == "example.com"
            return sock

    monkeypatch.setattr(diagnostics.socket, "socket", fake_socket, raising=False)
    monkeypatch.setattr(
        diagnostics.socket, "getaddrinfo", fake_getaddrinfo, raising=False
    )
    monkeypatch.setattr(
        diagnostics.ssl, "create_default_context", lambda: FakeContext(), raising=False
    )
    assert (
        cli_main(
            [
                "doctor",
                "--json",
                "--online",
                "--backend",
                "openai_compat",
                "--base-url",
                f"{scheme}://example.com:8443/v1",
            ]
        )
        == 0
    )
    data = json.loads(capsys.readouterr().out)
    online = next(c for c in data["checks"] if c["code"] == "online.base_url")
    assert online["status"] == "pass"
    assert calls == {"dns": 1, "connect": 1, "tls": int(scheme == "https")}
    assert sockets and all(5 in sock.timeouts for sock in sockets)


def test_doctor_protected_and_stale_remediation(tmp_path, monkeypatch, capsys):
    import foam.diagnostics as diagnostics

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("FOAM_LLM_API_KEY", "sk-TESTONLY")
    monkeypatch.setenv("FOAM_LLM_BASE_URL", "https://example.com")
    monkeypatch.setattr(
        diagnostics,
        "probe_protected",
        lambda: {"available": False, "reason": "TESTONLY unsupported"},
        raising=False,
    )
    monkeypatch.setattr(
        diagnostics,
        "list_stale_boundaries",
        lambda: ["fb0123456789ab"],
        raising=False,
    )
    monkeypatch.setattr(diagnostics.sys, "platform", "linux")
    assert cli_main(["doctor", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    protected = next(c for c in data["checks"] if c["code"] == "exec.protected")
    stale = next(c for c in data["checks"] if c["code"] == "exec.stale_boundaries")
    assert protected["status"] == "warn"
    assert "仅 legacy 可用" in protected["message"]
    assert "/opt/foam" in protected["remediation"]
    assert stale["status"] == "warn"
    assert stale["details"]["count"] == 1
    assert "自动对账" in stale["message"]


def test_status_pid_reuse_and_stale(tmp_path):
    """R13-C：新鲜+身份才 alive；过期/复用/boot/时钟/权限分别降级。"""
    from datetime import UTC, datetime, timedelta

    from foam.state.heartbeat import current_process_identity

    home = tmp_path / "home"
    cwd = tmp_path / "cwd"
    home.mkdir()
    cwd.mkdir()
    identity = current_process_identity()
    assert identity["identity_method"] in ("proc-stat", "ps-lstart")
    cases = [
        ("fresh", "alive", "active", 0),
        ("expired", "stale", "interrupted", 0),
        ("pid-reuse", "gone", "interrupted", 0),
        ("boot-change", "gone", "interrupted", 0),
        ("pid-missing", "gone", "interrupted", 0),
        ("future", "unknown", "unknown", 3),
        ("corrupt", "unknown", "unknown", 3),
        ("permission", "unknown", "unknown", 3),
    ]
    for name, expected_liveness, expected_run_state, expected_rc in cases:
        now = datetime.now(UTC)
        engagement = Engagement.create(cwd / "engagements", name)
        root = engagement.paths.root
        audit = AuditLog(root / "audit.jsonl")
        audit.append("run_started", {"run_id": "r13-c", "objective": name})
        audit.close()
        heartbeat = {
            "schema": "foam.heartbeat/1",
            "run_id": "r13-c",
            "entry": "cli-run",
            "pid": os.getpid(),
            "proc_start": identity["proc_start"],
            "boot_id": identity["boot_id"],
            "platform": sys.platform,
            "started_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "interval_s": 10,
            "seq": 1,
            "loop_status": "running",
            "last_activity": {
                "kind": "status",
                "at": (now + timedelta(seconds=2)).isoformat(),
            },
        }
        if name == "expired":
            heartbeat["updated_at"] = (now - timedelta(seconds=31)).isoformat()
            heartbeat["last_activity"]["at"] = heartbeat["updated_at"]
        elif name == "pid-reuse":
            heartbeat["proc_start"] = "TESTONLY-different-start"
        elif name == "boot-change":
            heartbeat["boot_id"] = "TESTONLY-different-boot"
        elif name == "pid-missing":
            heartbeat["pid"] = 99999999
        elif name == "future":
            heartbeat["updated_at"] = (now + timedelta(seconds=60)).isoformat()
        path = root / "heartbeat.json"
        if name == "corrupt":
            path.write_text("{bad\n", encoding="utf-8")
        else:
            path.write_text(json.dumps(heartbeat), encoding="utf-8")
        if name == "permission":
            path.chmod(0)
        before_lock = (root / "engagement.lock").exists()
        result = run_cli(["status", str(root), "--json"], cwd=cwd, home=home)
        assert result.returncode == expected_rc, (
            name,
            result.stdout,
            result.stderr,
        )
        data = json.loads(result.stdout)
        assert data["liveness"] == expected_liveness
        assert data["run_state"] == expected_run_state
        assert (root / "engagement.lock").exists() == before_lock
        assert "lock" in data["details"]
        if name == "fresh":
            assert data["details"]["identity_method"] == identity["identity_method"]
            assert data["last_activity"]["source"] == "heartbeat"
        if name == "permission":
            path.chmod(0o600)
        engagement.close()
