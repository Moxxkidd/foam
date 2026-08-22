"""WP-10 replay/report 测试。

- 验收 1:篡改 audit.jsonl 任意字节 → replay 报告断链位置(断点 seq),中止回放。
- 验收 2:合成 engagement 目录 → 报告含全部必备节(目标/范围/过程时间线/
  发现清单含证据路径/loot 清单/操作员插话记录),凭证为全值(LLM 视图才掩码)。
- 合成目录全部在 tmp_path;不碰仓库内真实 engagement。
"""

from __future__ import annotations

from pathlib import Path

from foam.agent.loop import KIND_RUN_FINISHED, KIND_RUN_STARTED
from foam.cli import main as cli_main
from foam.guard.audit import (
    KIND_EXEC_REQUEST,
    KIND_EXEC_RESULT_META,
    KIND_LLM_EXCHANGE_META,
    KIND_OPERATOR_INTERJECT,
    KIND_SCOPE_LOADED,
    AuditLog,
    llm_meta,
    verify,
)
from foam.guard.scope import parse_scope, scope_payload
from foam.replay import (
    build_report,
    build_resume_briefing,
    find_chain_break,
    read_records,
    recover_objective,
    recover_scope_record,
)
from foam.state.files import Engagement
from foam.state.index import Index

OBJECTIVE = "演练:侦察 127.0.0.1 并确认 80 端口"
SECRET_VALUE = "Sup3rSecret!"
MASKED_FORM = "Su********t!"  # mask_secret(SECRET_VALUE) 的形态,报告里不得出现


def make_engagement(tmp_path: Path, *, with_index: bool = True) -> Path:
    """合成一个完整 engagement:WP-06 布局 + 一条合法审计链 + 索引数据。"""
    engagement = Engagement.create(
        base_dir=tmp_path, objective=OBJECTIVE, engagement_id="eng-r"
    )
    scope = parse_scope("127.0.0.0/8\nlocalhost\n")
    audit = AuditLog(engagement.paths.audit_jsonl)
    audit.append(KIND_SCOPE_LOADED, scope_payload(scope, "scopes/lab.scope"))
    audit.append(
        KIND_RUN_STARTED,
        {"objective": OBJECTIVE, "provider": "fake", "workdir": str(tmp_path)},
    )
    audit.append(
        KIND_LLM_EXCHANGE_META,
        llm_meta("p1", "r1", prompt_tokens=100, response_tokens=20),
    )
    audit.append(
        KIND_EXEC_REQUEST,
        {
            "command": "nmap -Pn --top-ports 100 127.0.0.1",
            "targets": ["127.0.0.1"],
            "decision": "allowed",
            "warnings": [],
        },
    )
    audit.append(
        KIND_EXEC_RESULT_META,
        {
            "job_id": "j-1",
            "status": "completed",
            "exit_code": 0,
            "duration_ms": 42,
            "sha256": "cd" * 32,
            "output_path": "outputs/scan1.log",
            "total_bytes": 512,
        },
    )
    audit.append(
        KIND_OPERATOR_INTERJECT, {"text": "先看 80 端口的标题", "operator": "op1"}
    )
    audit.append(
        KIND_LLM_EXCHANGE_META,
        llm_meta("p2", "r2", prompt_tokens=200, response_tokens=30),
    )
    audit.append(
        KIND_RUN_FINISHED,
        {
            "status": "finished",
            "rounds": 2,
            "input_tokens": 300,
            "output_tokens": 50,
            "error": None,
            "final_text_sha256": "ab" * 32,
            "final_text_chars": 40,
        },
    )
    audit.close()

    if with_index:
        with Index(engagement.paths.index_db) as index:
            index.upsert_host("127.0.0.1", "localhost")
            index.upsert_port(
                "127.0.0.1", 80, service="http", product="nginx", version="1.25"
            )
            index.add_cred("127.0.0.1", "admin", SECRET_VALUE, source="config 泄漏")
            index.add_vuln(
                "127.0.0.1",
                "cve",
                "示例 CVE-2026-0001",
                evidence_path="outputs/scan1.log",
                confidence="high",
            )
            index.add_loot(
                "loot/flag.txt", kind="flag", note="演示战利品", size_bytes=18
            )
            index.add_note("第一天笔记:80 端口重点看")
    return engagement.paths.root


def tamper_line(root: Path, lineno: int, old: str, new: str) -> None:
    """等长替换审计链第 lineno 行(1 起)里的子串:JSON 仍合法,哈希不符。"""
    audit_path = root / "audit.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert old in lines[lineno - 1]
    lines[lineno - 1] = lines[lineno - 1].replace(old, new)
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# replay:verify 先行,链断报断点 seq(验收 1)
# ---------------------------------------------------------------------------


def test_replay_clean_chain_prints_timeline(tmp_path, capsys):
    root = make_engagement(tmp_path)
    rc = cli_main(["replay", str(root)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "审计链完整" in out
    assert "nmap -Pn --top-ports 100 127.0.0.1" in out
    assert "[目标: 127.0.0.1]" in out
    assert "操作员插话:先看 80 端口的标题" in out
    assert "run 结束:finished,2 轮" in out


def test_replay_tampered_byte_reports_breakpoint_seq(tmp_path, capsys):
    """验收 1:改掉 seq 4(exec_request)命令的一个字符 → 报断点 seq=4,中止。"""
    root = make_engagement(tmp_path)
    tamper_line(root, 4, "nmap", "Xmap")
    assert not verify(root / "audit.jsonl")

    rc = cli_main(["replay", str(root)])
    assert rc == 1
    captured = capsys.readouterr()
    assert "校验未通过" in captured.err
    assert "seq=4" in captured.err  # 断点位置明确
    assert "篡改" in captured.err
    assert "[replay]" not in captured.out  # 中止:不做时间线回放


def test_replay_deleted_record_reports_breakpoint(tmp_path, capsys):
    """删掉中间一条(seq 4)→ 断点报「应为 seq=4」(缺条)。"""
    root = make_engagement(tmp_path)
    audit_path = root / "audit.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    del lines[3]  # seq 4
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    rc = cli_main(["replay", str(root)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "校验未通过" in err
    assert "seq=4" in err  # 链上应为 seq=4


def test_replay_missing_audit_or_dir(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli_main(["replay", str(empty)]) == 2
    assert "audit.jsonl" in capsys.readouterr().err
    assert cli_main(["replay", str(tmp_path / "nope")]) == 2
    assert "不存在" in capsys.readouterr().err


def test_find_chain_break_stops_at_first(tmp_path):
    """多处篡改只报首个断点;find_chain_break 与 WP-02 verify 同语义。"""
    root = make_engagement(tmp_path)
    tamper_line(root, 4, "nmap", "Xmap")
    tamper_line(root, 6, "先看", "后看")
    brk = find_chain_break(root / "audit.jsonl")
    assert brk is not None
    assert brk.seq == 4
    assert brk.expected_seq == 4
    assert any("篡改" in reason for reason in brk.reasons)


# ---------------------------------------------------------------------------
# report:必备节快照(验收 2)
# ---------------------------------------------------------------------------


def test_report_contains_all_required_sections(tmp_path):
    root = make_engagement(tmp_path)
    text = build_report(root)

    # 头部与必备节
    assert text.startswith("# Engagement 报告:eng-r")
    assert "审计链:完整(8 条记录" in text
    assert "## 目标" in text and OBJECTIVE in text
    assert "## 范围(scope)" in text
    assert "scopes/lab.scope" in text and "127.0.0.0/8" in text
    assert "## 过程时间线" in text
    assert "nmap -Pn --top-ports 100 127.0.0.1" in text
    # 发现清单含证据路径
    assert "## 发现清单(漏洞)" in text
    assert "示例 CVE-2026-0001" in text
    assert "证据:outputs/scan1.log" in text
    # 凭证全值(WP-06 契约:报告导出可见;LLM 视图才掩码)
    assert "## 凭证(全值)" in text
    assert SECRET_VALUE in text
    assert MASKED_FORM not in text
    # loot 清单 / 插话记录 / 统计
    assert "## 战利品(loot)清单" in text
    assert "loot/flag.txt" in text and "演示战利品" in text
    assert "## 操作员插话记录" in text
    assert "先看 80 端口的标题" in text
    assert "## 统计" in text
    assert "命令 1 条" in text
    # 笔记节(有数据时)
    assert "第一天笔记:80 端口重点看" in text


def test_report_cli_writes_file(tmp_path, capsys):
    root = make_engagement(tmp_path)
    out_path = tmp_path / "report.md"
    rc = cli_main(["report", str(root), "--out", str(out_path)])
    assert rc == 0
    assert "已写入" in capsys.readouterr().out
    text = out_path.read_text(encoding="utf-8")
    assert "## 目标" in text and SECRET_VALUE in text


def test_report_legacy_dir_degrades(tmp_path):
    """无 engagement.json / index.sqlite 的 legacy 目录:降级标注,不炸。"""
    root = tmp_path / "legacy"
    root.mkdir()
    audit = AuditLog(root / "audit.jsonl")
    scope = parse_scope("127.0.0.0/8\n")
    audit.append(KIND_SCOPE_LOADED, scope_payload(scope, "scopes/lab.scope"))
    audit.append(
        KIND_RUN_STARTED,
        {"objective": "旧目录目标", "provider": "fake", "workdir": str(root)},
    )
    audit.close()

    text = build_report(root)
    assert "(无 engagement.json)" in text
    assert "旧目录目标" in text  # objective 从审计链恢复
    assert "scopes/lab.scope" in text  # scope 从审计链恢复
    assert "索引库 index.sqlite 缺失" in text
    assert "(全程无操作员插话)" in text


def test_report_broken_chain_marks_integrity(tmp_path):
    root = make_engagement(tmp_path)
    tamper_line(root, 4, "nmap", "Xmap")
    text = build_report(root)
    assert "校验未通过" in text
    assert "无时间线" in text  # 链不可信则时间线略去


# ---------------------------------------------------------------------------
# resume 简报(replay.py 的恢复面单元)
# ---------------------------------------------------------------------------


def test_resume_helpers(tmp_path):
    root = make_engagement(tmp_path)
    records = read_records(root / "audit.jsonl")

    assert recover_objective(records) == OBJECTIVE
    scope_record = recover_scope_record(records)
    assert scope_record["source"] == "scopes/lab.scope"
    assert scope_record["cidrs"] == ["127.0.0.0/8"]

    briefing = build_resume_briefing(records, recent_rounds=2)
    assert "恢复自历史审计链" in briefing
    assert "run 1 次" in briefing and "LLM 交换 2 轮" in briefing
    assert "nmap -Pn --top-ports 100 127.0.0.1" in briefing  # 最近 2 轮窗口含命令
    assert "先看 80 端口的标题" in briefing

    # 最近 1 轮窗口:只有第二条 LLM 交换之后的事件(run_finished)
    briefing_one = build_resume_briefing(records, recent_rounds=1)
    assert "run 结束" in briefing_one
    assert "nmap -Pn" not in briefing_one  # 第一轮的动作在窗口外
