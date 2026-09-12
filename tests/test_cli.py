"""WP-10 CLI 闭环测试:run 收尾接线 / resume / tui 占位 / --help 全覆盖。

- fake 后端脚本化驱动(与 test_loop 同模式,本文件自带一份保持自包含);
  engagement 全部落在 tmp_path,不碰仓库内真实 engagement。
- autouse fixture 把 HOME 隔离到 tmp_path(2026-09-12 第三轮):消除真实
  ~/.foam/config.json 串扰(active_profile 会往 stdout 混入 [config] 行)。
- 验收 3:resume 后 system 消息含 ENGAGEMENT.md 内容;缺 audit.jsonl 报错明确。
- 验收 4:全子命令 --help 可用;品牌名只经 __app_name__ 常量,源码无硬编码。
"""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path

import pytest

from foam import __app_name__
from foam.agent.backends.base import LLMBackend, TextDelta, ToolCall, Usage
from foam.cli import main as cli_main
from foam.guard.audit import verify

SCOPE_TEXT = "127.0.0.0/8\nlocalhost\n"


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    """HOME 隔离到 tmp_path(2026-09-12 第三轮,autouse)。

    消除真实 ~/.foam/config.json 串扰隐患:在配了 active_profile 的机器上,
    resolve_backend_args 会把 [config] profile 行混进 stdout,污染本文件
    多处 stdout 断言;隔离后每个测试都是干净 HOME。
    """
    monkeypatch.setenv("HOME", str(tmp_path))


class FakeBackend(LLMBackend):
    """脚本化后端:calls 记录每轮 messages,tools_seen 记录工具 specs。"""

    provider = "fake"

    def __init__(self, script=()):
        self._script = deque(script)
        self.calls: list[list] = []
        self.tools_seen = None

    async def aclose(self) -> None:
        pass

    def chat(self, messages, tools=None):
        self.calls.append(list(messages))
        self.tools_seen = tools
        return self._stream()

    async def _stream(self):
        events = self._script.popleft() if self._script else [Usage(1, 1)]
        for event in events:
            yield event


def write_scope(tmp_path: Path, text: str = SCOPE_TEXT) -> Path:
    scope_file = tmp_path / "lab.scope"
    scope_file.write_text(text, encoding="utf-8")
    return scope_file


def audit_kinds(root: Path) -> list[str]:
    return [
        json.loads(line)["kind"]
        for line in (root / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def run_once(tmp_path: Path, backend: FakeBackend, *, objective: str = "侦察本机"):
    """跑一次 run(fake 后端),返回 (rc, engagement 目录)。"""
    scope_file = write_scope(tmp_path)
    workdir = tmp_path / "eng"
    rc = cli_main(
        [
            "run",
            "--scope",
            str(scope_file),
            "--objective",
            objective,
            "--workdir",
            str(workdir),
        ],
        backend_factory=lambda _args: backend,
    )
    return rc, workdir


FINISH = [TextDelta("侦察结束,无进一步动作。"), Usage(2, 2)]


# ---------------------------------------------------------------------------
# run 收尾(WP-10 接线点①③):WP-06 布局 + 三组工具注册
# ---------------------------------------------------------------------------


def test_run_creates_wp06_layout_and_registers_all_tools(tmp_path):
    backend = FakeBackend(
        [
            [ToolCall("tc-1", "run_command", {"command": "echo cli-ok"}), Usage(1, 1)],
            FINISH,
        ]
    )
    rc, workdir = run_once(tmp_path, backend)
    assert rc == 0

    # ① WP-06 布局:engagement.json / ENGAGEMENT.md / index.sqlite / 子目录
    meta = json.loads((workdir / "engagement.json").read_text(encoding="utf-8"))
    assert meta["objective"] == "侦察本机"
    assert meta["status"] == "closed"  # finished 后 mark_closed
    assert meta["scope"]["sha256"]
    engagement_md = (workdir / "ENGAGEMENT.md").read_text(encoding="utf-8")
    assert engagement_md.startswith("# Engagement eng")  # WP-06 初始文件
    assert (workdir / "index.sqlite").is_file()
    assert (workdir / "loot").is_dir() and (workdir / "notes").is_dir()
    assert (workdir / "outputs" / "sessions").is_dir()  # 会话输出子目录

    # ③ 三组工具全部注册进主环(WP-01 exec + WP-05 会话 + WP-06 状态)
    names = [spec.name for spec in backend.tools_seen]
    for expected in (
        "run_command",
        "read_output",
        "list_jobs",
        "kill_job",
        "session_open",
        "session_send",
        "session_read",
        "session_close",
        "session_list",
        "state_query",
        "state_add_note",
        "state_add_loot",
    ):
        assert expected in names, f"工具未注册: {expected}"

    # system prompt 与工具面一致(占位句已换真实说明;WP-08 工具地图已注入)
    system_prompt = backend.calls[0][0].content
    assert "session_open" in system_prompt
    assert "state_query" in system_prompt
    assert "占位" not in system_prompt.split("# 工具地图")[0]  # 纪律段无占位句
    from foam.agent.prompts import TOOL_MAP_PLACEHOLDER

    assert TOOL_MAP_PLACEHOLDER not in system_prompt  # 注入真实盘点,占位被替换
    assert "# 工具地图" in system_prompt

    kinds = audit_kinds(workdir)
    assert kinds[0] == "scope_loaded"
    assert "run_started" in kinds and kinds[-1] == "run_finished"
    assert verify(workdir / "audit.jsonl")


def test_run_idempotent_reopen_and_conflict(tmp_path, capsys):
    scope_file = write_scope(tmp_path)
    workdir = tmp_path / "eng"
    argv = [
        "run",
        "--scope",
        str(scope_file),
        "--objective",
        "侦察本机",
        "--workdir",
        str(workdir),
    ]
    assert cli_main(argv, backend_factory=lambda _a: FakeBackend([FINISH])) == 0
    # 同参数复跑:幂等复开,审计链续写(run_started 两条,链仍完整)
    assert cli_main(argv, backend_factory=lambda _a: FakeBackend([FINISH])) == 0
    assert audit_kinds(workdir).count("run_started") == 2
    assert verify(workdir / "audit.jsonl")
    # 参数冲突(同目录不同 objective):明确报错
    conflict = [
        "run",
        "--scope",
        str(scope_file),
        "--objective",
        "另一个目标",
        "--workdir",
        str(workdir),
    ]
    rc = cli_main(conflict, backend_factory=lambda _a: FakeBackend([FINISH]))
    assert rc == 2
    assert "参数冲突" in capsys.readouterr().err


def test_run_missing_scope_file(tmp_path, capsys):
    rc = cli_main(
        [
            "run",
            "--scope",
            str(tmp_path / "nope.scope"),
            "--objective",
            "x",
            "--workdir",
            str(tmp_path / "eng"),
        ],
        backend_factory=lambda _args: FakeBackend([]),
    )
    assert rc == 2
    assert "scope 加载失败" in capsys.readouterr().err


def test_run_missing_api_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("FOAM_ANTHROPIC_API_KEY", raising=False)
    scope_file = write_scope(tmp_path)
    rc = cli_main(
        [
            "run",
            "--scope",
            str(scope_file),
            "--objective",
            "x",
            "--workdir",
            str(tmp_path / "eng"),
            "--backend",
            "claude",
        ]
    )
    assert rc == 2
    assert "FOAM_ANTHROPIC_API_KEY" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# resume(验收 3)
# ---------------------------------------------------------------------------


def test_resume_rebuilds_context(tmp_path, capsys):
    """验收 3 前半:resume 后 system 消息含 ENGAGEMENT.md 当前内容;简报注入。"""
    rc, workdir = run_once(tmp_path, FakeBackend([FINISH]))
    assert rc == 0
    # 模拟模型历史笔记:resume 必须把它重新载进上下文
    with open(workdir / "ENGAGEMENT.md", "a", encoding="utf-8") as fh:
        fh.write("\n## 发现\n- 端口 23 曾开放(历史)\n")

    resumed = FakeBackend([FINISH])
    rc = cli_main(
        ["resume", str(workdir)],
        backend_factory=lambda _args: resumed,
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "[resume]" in out and "链完整" in out

    first_call = resumed.calls[0]
    assert first_call[0].role == "system"
    assert "授权声明" in first_call[0].content  # system prompt 重建
    assert first_call[1].role == "system"
    assert "端口 23 曾开放(历史)" in first_call[1].content  # ENGAGEMENT.md 必载
    user_texts = [m.content for m in first_call if m.role == "user"]
    assert any(m == "侦察本机" for m in user_texts)  # objective 从 engagement.json 恢复
    briefing = [m for m in user_texts if "resume 简报" in m]
    assert len(briefing) == 1
    assert "恢复自历史审计链" in briefing[0]
    assert "run 1 次" in briefing[0]

    kinds = audit_kinds(workdir)
    assert kinds.count("run_started") == 2  # 续跑在同一链上
    assert verify(workdir / "audit.jsonl")


def test_resume_missing_audit_jsonl(tmp_path, capsys):
    """验收 3 后半:目录缺 audit.jsonl 时报错明确。"""
    empty = tmp_path / "empty-eng"
    empty.mkdir()
    rc = cli_main(["resume", str(empty)], backend_factory=lambda _args: FakeBackend([]))
    assert rc == 2
    err = capsys.readouterr().err
    assert "audit.jsonl" in err
    assert "无法恢复" in err


def test_resume_broken_chain_refused(tmp_path, capsys):
    rc, workdir = run_once(tmp_path, FakeBackend([FINISH]))
    assert rc == 0
    # 篡改:把审计链中间一条的命令改一个字(等长替换,JSON 仍合法,哈希不符)
    audit_path = workdir / "audit.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    target = next(i for i, line in enumerate(lines) if '"run_started"' in line)
    lines[target] = lines[target].replace("侦察本机", "侦察他机")
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    rc = cli_main(
        ["resume", str(workdir)], backend_factory=lambda _args: FakeBackend([])
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "校验未通过" in err
    assert "seq=" in err  # 报断点位置


def test_resume_scope_drift_detected(tmp_path, capsys):
    """scope 文件在 engagement 之后被改动 → sha256 对账不符,拒绝并提示。"""
    scope_file = write_scope(tmp_path)
    rc, workdir = run_once(tmp_path, FakeBackend([FINISH]))
    assert rc == 0
    scope_file.write_text(SCOPE_TEXT + "10.0.0.0/8\n", encoding="utf-8")

    rc = cli_main(
        ["resume", str(workdir)], backend_factory=lambda _args: FakeBackend([])
    )
    assert rc == 2
    assert "sha256 不符" in capsys.readouterr().err

    # 显式 --scope 覆盖 = 操作员重新授权,放行并续链
    resumed = FakeBackend([FINISH])
    rc = cli_main(
        ["resume", str(workdir), "--scope", str(scope_file)],
        backend_factory=lambda _args: resumed,
    )
    assert rc == 0
    assert verify(workdir / "audit.jsonl")


def test_resume_missing_dir(tmp_path, capsys):
    rc = cli_main(
        ["resume", str(tmp_path / "nope")],
        backend_factory=lambda _args: FakeBackend([]),
    )
    assert rc == 2
    assert "不存在" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# tui 入口(WP-09 已接线)/ --help(验收 4)
# ---------------------------------------------------------------------------


def test_tui_entry_wired_config_error(tmp_path, capsys, monkeypatch):
    """WP-09 已提供 foam.tui.app:main;缺 base_url 时 rc 2 + 明确报错。

    (原为 tui 占位报错测试;WP-09 关闭时按入口约定更新——monkeypatch 清
    env 防开发机 FOAM_LLM_BASE_URL 泄漏导致真拉起 TUI。)
    """
    monkeypatch.delenv("FOAM_LLM_BASE_URL", raising=False)
    scope_file = write_scope(tmp_path)
    rc = cli_main(["tui", "--scope", str(scope_file)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "FOAM_LLM_BASE_URL" in err  # 到达 main():scope 通过、后端装配报错


def test_help_all_subcommands(capsys):
    """验收 4:--help 全子命令可用(argparse SystemExit(0))。"""
    for argv in (
        ["--help"],
        ["run", "--help"],
        ["resume", "--help"],
        ["replay", "--help"],
        ["report", "--help"],
        ["tui", "--help"],
    ):
        with pytest.raises(SystemExit) as excinfo:
            cli_main(argv)
        assert excinfo.value.code == 0
        assert "usage" in capsys.readouterr().out.lower()
    # 顶层 help 经 __app_name__ 渲染品牌与版本(常量接线有效)
    with pytest.raises(SystemExit):
        cli_main(["--help"])
    assert f"{__app_name__} " in capsys.readouterr().out


def test_no_hardcoded_brand_in_sources():
    """品牌纪律:cli.py / replay.py 源码不出现品牌字面量,只走 __app_name__。"""
    import foam.cli
    import foam.replay

    for module in (foam.cli, foam.replay):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert __app_name__ not in source, f"{module.__name__} 硬编码品牌名"
    cli_source = Path(foam.cli.__file__).read_text(encoding="utf-8")
    assert "__app_name__" in cli_source  # 证明走的是常量


def test_cli_no_subcommand_prints_help(capsys):
    assert cli_main([]) == 0
    assert "run" in capsys.readouterr().out
