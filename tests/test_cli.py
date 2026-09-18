"""WP-10 CLI 闭环测试:run 收尾接线 / resume / tui 占位 / --help 全覆盖。

- fake 后端脚本化驱动(与 test_loop 同模式,本文件自带一份保持自包含);
  engagement 全部落在 tmp_path,不碰仓库内真实 engagement。
- autouse fixture 把 HOME 隔离到 tmp_path(2026-09-12 第三轮):消除真实
  ~/.foam/config.json 串扰(active_profile 会往 stdout 混入 [config] 行)。
- 验收 3:resume 后 system 消息含 ENGAGEMENT.md 内容;缺 audit.jsonl 报错明确。
- 验收 4:全子命令 --help 可用;品牌名只经 __app_name__ 常量,源码无硬编码。

WP-14b(2026-09-18)追加:run --scope/--scope-text 互斥组;--scope-text
一次性编译+自动冻结(成功 canonical 上屏+审计链序/空 rules Q9/失败 rc 2
无重试/同目录已冻结拒绝 W14b-1);file 流装配后补 scope_confirmed
(source="file",Q8/W14b-2 payload 语义,既有 kinds 断言按例外条款补位);
resume 双来源零适配(NL engagement meta 路径/纯链 scope_confirmed 回退
D13/纯链恢复逐键相等);tui --scope 改可选(过 argparse 关);cli.py 两写入点
(file 流装配时、resume 对账完成时)动态段落盘。
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from pathlib import Path

import pytest

from foam import __app_name__
from foam.agent.backends.base import LLMBackend, TextDelta, ToolCall, Usage
from foam.agent.loop import KIND_RUN_STARTED
from foam.agent.prompts import render_scope_section
from foam.agent.scope_compiler import scope_event_payload
from foam.cli import main as cli_main
from foam.guard.audit import KIND_SCOPE_CONFIRMED, AuditLog, verify
from foam.guard.scope import load_scope, parse_scope
from foam.replay import read_records, recover_scope_record
from foam.state.files import SCOPE_SECTION_BEGIN, SCOPE_SECTION_END, Engagement

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


def audit_records(root: Path) -> list[dict]:
    return read_records(root / "audit.jsonl")


def extract_scope_section(md: str) -> str:
    """取出 markers 之间的动态段内容(含首尾换行),与 14a 测试同口径。"""
    begin = md.index(SCOPE_SECTION_BEGIN)
    content_start = md.index("\n", begin) + 1
    end = md.index(SCOPE_SECTION_END, content_start)
    end_line_start = md.rfind("\n", content_start, end) + 1
    return md[content_start:end_line_start]


def section_frozen_at(section: str) -> str:
    match = re.search(r"^- 冻结时间:(.+)$", section, re.MULTILINE)
    assert match is not None
    return match.group(1)


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
    # Q8(WP-14b 例外条款,有意行为变化):file 流装配后补确认记录,位次与
    # scope_loaded 相邻、run_started 之前
    assert kinds[1] == "scope_confirmed"
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
    # W14b-3:plain resume 不补确认记录(计数保持 run 时的 1 条)
    assert kinds.count("scope_confirmed") == 1
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
    # W14b-3(WP-14b 例外条款):--scope 覆盖 resume 补写确认记录,计数 +1,
    # canonical_sha256 = 新文件字节 sha256,path = as-given 原串
    confirms = [r for r in audit_records(workdir) if r["kind"] == "scope_confirmed"]
    assert len(confirms) == 2
    payload = confirms[-1]["payload"]
    assert payload["source"] == "file"
    assert payload["path"] == str(scope_file)
    assert payload["canonical_sha256"] == hashlib.sha256(
        scope_file.read_bytes()
    ).hexdigest()
    assert "10.0.0.0/8" in payload["cidrs"]  # 新文件内容生效
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
    # WP-14b 验收 1:run --help 含 --scope-text(互斥组上屏)
    with pytest.raises(SystemExit):
        cli_main(["run", "--help"])
    assert "--scope-text" in capsys.readouterr().out


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


# ---------------------------------------------------------------------------
# WP-14b:headless 双通道(--scope / --scope-text)与 resume 对账
# ---------------------------------------------------------------------------

COMPILE_OK = [TextDelta('{"rules": ["127.0.0.0/8", "localhost"]}'), Usage(5, 3)]
NL_TEXT = "对本机 127.0.0.0/8 与 localhost 做侦察"


def run_nl_once(
    tmp_path: Path,
    backend: FakeBackend,
    *,
    nl: str = NL_TEXT,
    objective: str = "侦察本机",
    workdir: Path | None = None,
):
    """跑一次 run --scope-text(fake 后端,脚本=编译应答+主环应答)。"""
    workdir = workdir or tmp_path / "eng"
    rc = cli_main(
        [
            "run",
            "--scope-text",
            nl,
            "--objective",
            objective,
            "--workdir",
            str(workdir),
        ],
        backend_factory=lambda _args: backend,
    )
    return rc, workdir


def test_run_scope_mutex_group(tmp_path, capsys):
    """验收 1:--scope 与 --scope-text 两给/两缺均 argparse 退出码 2。"""
    scope_file = write_scope(tmp_path)
    with pytest.raises(SystemExit) as excinfo:
        cli_main(
            [
                "run",
                "--scope",
                str(scope_file),
                "--scope-text",
                "侦察",
                "--objective",
                "x",
            ]
        )
    assert excinfo.value.code == 2
    # argparse 互斥组专属报错形态(旧 parser 的 unrecognized arguments 不含此句)
    assert "not allowed with argument" in capsys.readouterr().err

    with pytest.raises(SystemExit) as excinfo:
        cli_main(["run", "--objective", "x"])
    assert excinfo.value.code == 2
    assert "--scope" in capsys.readouterr().err  # 必给其一


def test_run_scope_text_success(tmp_path, capsys):
    """验收 2:--scope-text 一次性编译+自动冻结,canonical 上屏+审计链序。"""
    backend = FakeBackend([COMPILE_OK, FINISH])
    rc, workdir = run_nl_once(tmp_path, backend)
    assert rc == 0

    # canonical 全文上屏([scope] 行 + 规则逐行)
    out = capsys.readouterr().out
    assert "[scope]" in out
    assert "  127.0.0.0/8" in out and "  localhost" in out

    # scope.confirmed 落盘;meta/payload 路径与 sha 三方一致(绝对路径)
    confirmed = workdir / "scope.confirmed"
    assert confirmed.is_file()
    expected_path = str(confirmed.resolve())
    sha = hashlib.sha256(confirmed.read_bytes()).hexdigest()
    meta = json.loads((workdir / "engagement.json").read_text(encoding="utf-8"))
    assert meta["scope"] == {"path": expected_path, "sha256": sha}
    assert Path(meta["scope"]["path"]).is_absolute()

    # 链序(D9 同构):llm_exchange_meta → scope_confirmed → scope_loaded
    records = audit_records(workdir)
    kinds = [r["kind"] for r in records]
    assert kinds[0] == "llm_exchange_meta"  # D7:编译先于冻结
    assert kinds[1] == "scope_confirmed"
    assert kinds[2] == "scope_loaded"
    payload = records[1]["payload"]
    assert payload["source"] == "nl"
    assert payload["path"] == expected_path
    assert payload["canonical_sha256"] == sha
    assert payload["cidrs"] == ["127.0.0.0/8"]
    assert payload["hosts"] == ["localhost"]
    assert payload["wildcards"] == [] and payload["url_prefixes"] == []
    assert payload["nl_sha256"] == hashlib.sha256(NL_TEXT.encode()).hexdigest()
    assert payload["nl_chars"] == len(NL_TEXT)
    assert payload["compile_attempts"] == 1
    # 一致性请求 4:meta path / scope_confirmed payload path / 装配 scope_source
    # (scope_loaded.source)三处同串
    assert records[2]["payload"]["source"] == expected_path
    assert verify(workdir / "audit.jsonl")
    assert len(backend.calls) == 2  # 编译一次 + 主环一次,无多轮仪式


def test_run_scope_text_empty_rules(tmp_path, capsys):
    """验收 3(Q9):空 rules 合法冻结,stdout 醒目行,payload 四键皆空。"""
    backend = FakeBackend([[TextDelta('{"rules": []}'), Usage(1, 1)], FINISH])
    rc, workdir = run_nl_once(tmp_path, backend, nl="只是聊聊")
    assert rc == 0
    out = capsys.readouterr().out
    assert "(空——任何网络目标都会被拒)" in out

    payload = [
        r for r in audit_records(workdir) if r["kind"] == "scope_confirmed"
    ][0]["payload"]
    assert payload["cidrs"] == [] and payload["hosts"] == []
    assert payload["wildcards"] == [] and payload["url_prefixes"] == []
    assert (workdir / "scope.confirmed").read_bytes() == b""
    assert payload["canonical_sha256"] == hashlib.sha256(b"").hexdigest()


def test_run_scope_text_compile_failure_no_retry(tmp_path, capsys):
    """验收 4:编译失败 → rc 2 中文报错、无进程内重试(Q6)、无半冻结态。"""
    backend = FakeBackend([[TextDelta("好的,这不是 JSON"), Usage(1, 1)]])
    rc, workdir = run_nl_once(tmp_path, backend)
    assert rc == 2
    assert "scope 编译失败" in capsys.readouterr().err
    assert len(backend.calls) == 1  # 无进程内重试

    kinds = audit_kinds(workdir)
    assert "llm_exchange_meta" in kinds  # D7:失败路径仍由编译器现场落审计
    assert "scope_confirmed" not in kinds and "run_started" not in kinds
    meta = json.loads((workdir / "engagement.json").read_text(encoding="utf-8"))
    assert meta["scope"] is None  # 未冻结
    assert not (workdir / "scope.confirmed").exists()


def test_run_scope_text_refuses_already_frozen(tmp_path, capsys):
    """验收 5(W14b-1):同目录已有冻结 scope → NL 流拒绝,fail-closed。"""
    rc, workdir = run_once(tmp_path, FakeBackend([FINISH]))  # file 流先冻结
    assert rc == 0

    backend = FakeBackend([COMPILE_OK, FINISH])
    rc, _ = run_nl_once(tmp_path, backend, workdir=workdir)
    assert rc == 2
    err = capsys.readouterr().err
    assert "已有冻结 scope" in err
    assert "--workdir" in err  # 可行动指引
    assert backend.calls == []  # 未发起编译(拒绝在 LLM 调用之前)
    kinds = audit_kinds(workdir)
    assert "scope_updated" not in kinds
    assert kinds.count("scope_confirmed") == 1  # 仅 file 流那一条
    assert not (workdir / "scope.confirmed").exists()


def test_run_file_flow_appends_scope_confirmed(tmp_path):
    """验收 6(W14b-2):file 流补确认,payload=as-given 路径+文件字节 sha。"""
    scope_file = write_scope(tmp_path)
    rc, workdir = run_once(tmp_path, FakeBackend([FINISH]))
    assert rc == 0

    records = audit_records(workdir)
    kinds = [r["kind"] for r in records]
    assert kinds[0] == "scope_loaded"
    assert kinds[1] == "scope_confirmed"  # 相邻、run_started 之前
    assert kinds[2] == "run_started"
    payload = records[1]["payload"]
    expected_sha = hashlib.sha256(scope_file.read_bytes()).hexdigest()
    assert payload == {
        "path": str(scope_file),  # as-given 原串(与 scope_loaded.source 同串)
        "cidrs": ["127.0.0.0/8"],
        "hosts": ["localhost"],
        "wildcards": [],
        "url_prefixes": [],
        "canonical_sha256": expected_sha,
        "source": "file",
    }
    meta = json.loads((workdir / "engagement.json").read_text(encoding="utf-8"))
    assert payload["canonical_sha256"] == meta["scope"]["sha256"]
    assert records[0]["payload"]["source"] == payload["path"]


def test_resume_nl_engagement_via_metadata(tmp_path):
    """验收 7a:NL engagement plain resume 走 meta 路径,四键与冻结时相等。"""
    backend = FakeBackend([COMPILE_OK, FINISH])
    rc, workdir = run_nl_once(tmp_path, backend)
    assert rc == 0

    rc = cli_main(
        ["resume", str(workdir)], backend_factory=lambda _a: FakeBackend([FINISH])
    )
    assert rc == 0
    records = audit_records(workdir)
    frozen = [r for r in records if r["kind"] == "scope_confirmed"][0]["payload"]
    loaded = [r for r in records if r["kind"] == "scope_loaded"]
    assert loaded[-1]["payload"]["source"] == frozen["path"]
    for key in ("cidrs", "hosts", "wildcards", "url_prefixes"):
        assert loaded[-1]["payload"][key] == frozen[key]
    assert verify(workdir / "audit.jsonl")


def test_resume_chain_only_scope_confirmed(tmp_path):
    """验收 7b:链上仅 scope_confirmed(无 scope_loaded)→ 归一化零适配恢复。"""
    engagement = Engagement.create(
        tmp_path / "engagements", "链上确认恢复", engagement_id="eng-c"
    )
    root = engagement.paths.root
    canonical = "127.0.0.0/8\nlocalhost\n"
    confirmed = root / "scope.confirmed"
    confirmed.write_text(canonical, encoding="utf-8")
    scope = parse_scope(canonical)
    sha = hashlib.sha256(canonical.encode()).hexdigest()
    audit = AuditLog(root / "audit.jsonl")
    audit.append(
        KIND_SCOPE_CONFIRMED,
        scope_event_payload(
            scope,
            source="nl",
            path=str(confirmed.resolve()),
            canonical_sha256=sha,
            nl_text="侦察本机网段",
            compile_attempts=1,
        ),
    )
    audit.append(
        KIND_RUN_STARTED,
        {"objective": "链上确认恢复", "provider": "fake", "workdir": str(root)},
    )
    audit.close()
    engagement.close()
    (root / "engagement.json").unlink()

    # 归一化记录(D13 映射):source=scope.confirmed 绝对路径、origin="nl"
    record = recover_scope_record(read_records(root / "audit.jsonl"))
    assert record["source"] == str(confirmed.resolve())
    assert record["origin"] == "nl"

    rc = cli_main(
        ["resume", str(root)], backend_factory=lambda _a: FakeBackend([FINISH])
    )
    assert rc == 0  # _resolve_scope 链上回退零适配消费,无新分支
    loaded = [
        r for r in audit_records(root) if r["kind"] == "scope_loaded"
    ]
    assert loaded[-1]["payload"]["source"] == str(confirmed.resolve())
    for key in ("cidrs", "hosts", "wildcards", "url_prefixes"):
        assert loaded[-1]["payload"][key] == scope.summary()[key]
    assert verify(root / "audit.jsonl")


def test_resume_pure_chain_recovery_scope_equal(tmp_path):
    """验收 8:删 engagement.json 纯链恢复,恢复出的 Scope 与冻结时逐键相等。"""
    backend = FakeBackend([COMPILE_OK, FINISH])
    rc, workdir = run_nl_once(tmp_path, backend)
    assert rc == 0
    frozen = [
        r for r in audit_records(workdir) if r["kind"] == "scope_confirmed"
    ][0]["payload"]
    # 归一化记录(D13 映射,对链上真实 scope_confirmed 记录):source=绝对路径、
    # origin="nl"(8 的场景末条 scope 记录为 scope_loaded 无 origin 键;映射
    # 断言落在 7b 与本例的 confirmed 记录上)
    normalized = recover_scope_record(
        [r for r in audit_records(workdir) if r["kind"] == "scope_confirmed"]
    )
    assert normalized["source"] == frozen["path"]
    assert normalized["origin"] == "nl"
    (workdir / "engagement.json").unlink()

    rc = cli_main(
        ["resume", str(workdir)], backend_factory=lambda _a: FakeBackend([FINISH])
    )
    assert rc == 0
    records = audit_records(workdir)
    new_loaded = [r for r in records if r["kind"] == "scope_loaded"][-1]["payload"]
    assert new_loaded["source"] == frozen["path"]  # scope.confirmed 绝对路径
    # 以 resume 新落 scope_loaded 的 source 重载,与冻结时逐键相等
    recovered = load_scope(new_loaded["source"])
    for key in ("cidrs", "hosts", "wildcards", "url_prefixes"):
        assert recovered.summary()[key] == frozen[key]
    assert recovered.rules == ("127.0.0.0/8", "localhost")
    assert verify(workdir / "audit.jsonl")


def test_tui_without_scope_passes_argparse(tmp_path, capsys, monkeypatch):
    """验收 9:tui 不给 --scope 过 argparse 关,到达后端预检才报配置错。"""
    monkeypatch.delenv("FOAM_LLM_BASE_URL", raising=False)
    rc = cli_main(["tui"])
    assert rc == 2
    # 报的是后端配置错(而非 argparse usage 错)即证明 --scope 已可选
    assert "FOAM_LLM_BASE_URL" in capsys.readouterr().err


def test_file_flow_run_writes_scope_section(tmp_path):
    """验收 10 前半(D6 写入点①):file 流装配时动态段落盘,markers 外字节不变。"""
    scope_file = write_scope(tmp_path)
    workdir = tmp_path / "eng"
    # 预建目录拿写前快照(幂等复开不动 ENGAGEMENT.md),对照 14a 同措辞
    # 「markers 外字节不变」的 prefix/suffix 全字节比对
    Engagement.create(
        tmp_path, "侦察本机", scope_path=str(scope_file), engagement_id="eng"
    ).close()
    md_before = (workdir / "ENGAGEMENT.md").read_text(encoding="utf-8")
    prefix = md_before[: md_before.index(SCOPE_SECTION_BEGIN)]
    suffix = md_before[
        md_before.index(SCOPE_SECTION_END) + len(SCOPE_SECTION_END) :
    ]

    rc, _ = run_once(tmp_path, FakeBackend([FINISH]))
    assert rc == 0

    md = (workdir / "ENGAGEMENT.md").read_text(encoding="utf-8")
    section = extract_scope_section(md)
    expected = render_scope_section(
        ("127.0.0.0/8", "localhost"),
        source=str(scope_file),  # as-given 原串(与 meta/审计同串)
        sha256=hashlib.sha256(scope_file.read_bytes()).hexdigest(),
        frozen_at=section_frozen_at(section),
    )
    assert section == expected + "\n"
    # markers 外字节逐字节不变(引用块/meta 行/进展标题全覆盖,非抽样锚)
    assert md.startswith(prefix)
    assert md.endswith(suffix)


def test_resume_rewrites_scope_section(tmp_path):
    """验收 10 后半(D6 写入点②):resume 对账完成时幂等重写动态段。"""
    scope_file = write_scope(tmp_path)
    rc, workdir = run_once(tmp_path, FakeBackend([FINISH]))
    assert rc == 0
    # 模拟段内容过期(模型手改),resume 对账后应重写回当前 scope 渲染
    engagement = Engagement.open(workdir)
    engagement.update_scope_section("过期内容")
    engagement.close()
    assert "过期内容" in (workdir / "ENGAGEMENT.md").read_text(encoding="utf-8")

    rc = cli_main(
        ["resume", str(workdir)], backend_factory=lambda _a: FakeBackend([FINISH])
    )
    assert rc == 0
    md = (workdir / "ENGAGEMENT.md").read_text(encoding="utf-8")
    section = extract_scope_section(md)
    assert "过期内容" not in md
    expected = render_scope_section(
        ("127.0.0.0/8", "localhost"),
        source=str(scope_file),  # plain resume:meta 路径 = 建目录时 as-given 串
        sha256=hashlib.sha256(scope_file.read_bytes()).hexdigest(),
        frozen_at=section_frozen_at(section),
    )
    assert section == expected + "\n"
