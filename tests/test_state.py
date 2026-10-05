"""状态层测试(WP-06 验收 1/2/3/4)。

fixture 约定(契约 §4):凭据一律明显合成——TESTONLY 前缀口令、
RFC 5737 文档保留网段(192.0.2.0/24、198.51.100.0/24)与 example.com。
engagement 目录一律建在 tmp_path,运行时产物不入库。

R02(2026-10-06)追加:engagement.json 全量原子写、单写者锁(engagement.lock)、
scope/objective 修订提交协议与崩溃恢复(AC06/AC08)、状态生命周期迁移。
"""

import fcntl
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

import foam.state.files as files_module
from foam.agent.prompts import render_engagement_template
from foam.agent.scope_compiler import scope_event_payload
from foam.guard.audit import (
    KIND_SCOPE_CONFIRMED,
    KIND_SCOPE_LOADED,
    AuditLog,
    verify,
)
from foam.guard.scope import parse_scope, scope_payload
from foam.replay import read_records
from foam.state.files import (
    LAYOUT,
    SCOPE_SECTION_BEGIN,
    SCOPE_SECTION_END,
    Engagement,
    EngagementLockedError,
    acquire_engagement_lock,
)
from foam.state.index import Index
from foam.tools.state import TOOL_SCHEMAS, StateTool, mask_secret

TEST_SECRET = "TESTONLY-s3cr3t-P@ssw0rd"  # 合成 fixture 凭据,见契约 §4


@pytest.fixture()
def scope_file(tmp_path):
    path = tmp_path / "lab.scope"
    path.write_text("192.0.2.0/24\n*.example.com\n", encoding="utf-8")
    return path


@pytest.fixture()
def engagement(tmp_path, scope_file):
    return Engagement.create(
        tmp_path / "engagements",
        "测试目标 objective",
        scope_path=scope_file,
        engagement_id="test-eng",
    )


@pytest.fixture()
def state_tool(engagement):
    with StateTool(engagement) as tool:
        yield tool


# ================================================================ 验收 1
# 目录创建 / 校验 / 幂等

def test_create_layout_complete(engagement):
    root = engagement.paths.root
    for name, kind in LAYOUT.items():
        target = root / name
        assert target.is_dir() if kind == "d" else target.is_file(), name
    assert engagement.validate() == []


def test_metadata_records_objective_and_scope_hash(engagement, scope_file):
    meta = engagement.metadata()
    assert meta["id"] == "test-eng"
    assert meta["objective"] == "测试目标 objective"
    assert meta["status"] == "active"
    assert meta["closed_at"] is None
    expected = hashlib.sha256(scope_file.read_bytes()).hexdigest()
    assert meta["scope"] == {"path": str(scope_file), "sha256": expected}


def test_create_idempotent(tmp_path, scope_file):
    kwargs = {
        "objective": "幂等测试",
        "scope_path": scope_file,
        "engagement_id": "idem-eng",
    }
    first = Engagement.create(tmp_path / "engagements", **kwargs)
    # 往已有内容里写标记
    marker = "手工标记,幂等 init 不得抹掉"
    first.paths.progress_md.write_text(marker, encoding="utf-8")
    created_before = first.metadata()["created_at"]

    second = Engagement.create(tmp_path / "engagements", **kwargs)
    assert second.paths.progress_md.read_text(encoding="utf-8") == marker
    assert second.metadata()["created_at"] == created_before
    assert second.validate() == []


def test_create_conflict_raises(tmp_path, scope_file):
    Engagement.create(tmp_path / "engagements", "原始目标", engagement_id="c-eng")
    with pytest.raises(ValueError, match="objective 不一致"):
        Engagement.create(tmp_path / "engagements", "另一个目标", engagement_id="c-eng")

    other_scope = tmp_path / "other.scope"
    other_scope.write_text("198.51.100.0/24\n", encoding="utf-8")
    with pytest.raises(ValueError, match="scope"):
        Engagement.create(
            tmp_path / "engagements",
            "原始目标",
            scope_path=other_scope,
            engagement_id="c-eng",
        )


def test_create_missing_scope_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="scope 文件不存在"):
        Engagement.create(
            tmp_path / "engagements",
            "x",
            scope_path=tmp_path / "nope.scope",
            engagement_id="s-eng",
        )


def test_validate_detects_missing_and_id_mismatch(engagement):
    loot_dir = engagement.paths.loot
    loot_dir.rmdir()
    problems = engagement.validate()
    assert any("loot" in p for p in problems)

    engagement = Engagement.create(
        engagement.paths.root.parent, "测试目标 objective", engagement_id="test-eng"
    )
    meta = engagement.metadata()
    meta["id"] = "tampered-id"
    engagement.paths.metadata.write_text(
        json.dumps(meta, ensure_ascii=False), encoding="utf-8"
    )
    problems = engagement.validate()
    assert any("目录名不符" in p for p in problems)


def test_open_existing(engagement):
    reopened = Engagement.open(engagement.paths.root)
    assert reopened.validate() == []
    with pytest.raises(FileNotFoundError):
        Engagement.open(engagement.paths.root.parent / "no-such-dir")


def test_mark_closed(engagement):
    meta = engagement.mark_closed()
    assert meta["status"] == "closed"
    assert meta["closed_at"] is not None
    # 幂等:重复关闭 closed_at 不变
    assert engagement.mark_closed()["closed_at"] == meta["closed_at"]


def test_initial_progress_md(engagement):
    text = engagement.read_progress()
    assert "test-eng" in text
    assert "尚未写入进展" in text


# ================================================================ 验收 2
# 索引 upsert 与关系查询

@pytest.fixture()
def index(tmp_path):
    with Index(tmp_path / "index.sqlite") as idx:
        yield idx


def test_upsert_host_dedup_and_hostname_update(index):
    first = index.upsert_host("192.0.2.10")
    second = index.upsert_host("192.0.2.10", "web.example.com")
    assert first == second
    third = index.upsert_host("192.0.2.10")  # 空 hostname 不覆盖已有
    assert third == first
    host = index.query("hosts", {"ip": "192.0.2.10"})["rows"][0]
    assert host["hostname"] == "web.example.com"


def test_upsert_port_dedup_and_enrichment(index):
    index.upsert_port("192.0.2.10", 445, "tcp")
    index.upsert_port("192.0.2.10", 445, "tcp", service="smb", product="Samba")
    index.upsert_port("192.0.2.10", 445, "udp")  # 不同 proto 是另一行
    rows = index.query("ports", {"host_ip": "192.0.2.10"})["rows"]
    assert len(rows) == 2
    tcp = next(r for r in rows if r["proto"] == "tcp")
    assert tcp["service"] == "smb" and tcp["product"] == "Samba"


def test_hosts_with_port_reverse_lookup(index):
    index.upsert_port("192.0.2.10", 445, "tcp", service="smb")
    index.upsert_port("192.0.2.11", 445, "tcp")
    index.upsert_port("192.0.2.12", 22, "tcp", service="ssh")
    rows = index.hosts_with_port(445)
    assert {r["ip"] for r in rows} == {"192.0.2.10", "192.0.2.11"}
    assert index.hosts_with_port(445, proto="udp") == []


def test_attack_surface_aggregates_without_secret(index):
    index.upsert_port("192.0.2.10", 22, "tcp", service="ssh")
    index.upsert_port("192.0.2.10", 445, "tcp", service="smb")
    index.add_cred("192.0.2.10", "admin", TEST_SECRET, source="TESTONLY-smbrelay")
    index.add_vuln(
        "192.0.2.10", "cve", "MS17-010",
        confidence="high", evidence_path="outputs/x.log",
    )
    surface = index.attack_surface("192.0.2.10")
    assert surface["host"]["ip"] == "192.0.2.10"
    assert [p["port"] for p in surface["ports"]] == [22, 445]
    assert surface["creds_count"] == 1
    assert surface["creds"][0]["username"] == "admin"
    # 索引层红线:攻击面汇总不带 secret(连字段都没有)
    assert "secret" not in surface["creds"][0]
    assert TEST_SECRET not in json.dumps(surface, ensure_ascii=False)
    assert surface["vulns"][0]["title"] == "MS17-010"


def test_attack_surface_unknown_host(index):
    assert index.attack_surface("203.0.113.99") is None


def test_add_cred_dedup(index):
    index.add_cred("192.0.2.10", "admin", TEST_SECRET, source="TESTONLY-a")
    index.add_cred("192.0.2.10", "admin", TEST_SECRET, source="TESTONLY-b")
    index.add_cred("192.0.2.10", "guest", "TESTONLY-guest", source="TESTONLY-a")
    assert index.counts()["creds"] == 2
    row = index.query("creds", {"username": "admin"})["rows"][0]
    assert row["source"] == "TESTONLY-b"  # 重复上报更新 source


def test_vuln_loot_note_roundtrip(index):
    index.add_vuln("192.0.2.10", "config", "匿名 FTP 可写", confidence="medium")
    index.add_vuln("192.0.2.10", "config", "匿名 FTP 可写", confidence="high")
    assert index.counts()["vulns"] == 1  # 同 (host,kind,title) 去重
    assert index.query("vulns")["rows"][0]["confidence"] == "high"

    index.add_loot("loot/dump.txt", kind="dump", note="TESTONLY 战利品", size_bytes=3)
    index.add_loot("loot/dump.txt", kind="dump", note="更新备注", size_bytes=3)
    assert index.counts()["loot"] == 1
    assert index.query("loot")["rows"][0]["note"] == "更新备注"

    index.add_note("第一条笔记")
    index.add_note("第二条笔记")
    assert index.counts()["notes"] == 2  # notes 不去重


def test_query_rejects_unknown_kind_and_filter(index):
    with pytest.raises(ValueError, match="未知查询类别"):
        index.query("passwords")
    with pytest.raises(ValueError, match="不支持的过滤字段"):
        index.query("ports", {"secret": "x"})


def test_query_pagination(index):
    for i in range(7):
        index.upsert_host(f"192.0.2.{10 + i}")
    page1 = index.query("hosts", limit=3)
    page2 = index.query("hosts", limit=3, offset=3)
    page3 = index.query("hosts", limit=3, offset=6)
    assert (page1["total"], page1["truncated"]) == (7, True)
    assert (page2["total"], page2["truncated"]) == (7, True)
    assert (page3["count"], page3["truncated"]) == (1, False)
    ips = [r["ip"] for r in page1["rows"] + page2["rows"] + page3["rows"]]
    assert len(set(ips)) == 7


# ================================================================ 验收 3
# 脱敏专项:LLM 视图拿不到完整 secret

async def test_state_query_creds_masked(state_tool):
    state_tool._index.add_cred(
        "192.0.2.10", "admin", TEST_SECRET, source="TESTONLY-smb"
    )
    response = await state_tool.dispatch(
        "state_query", {"kind": "creds", "filters": {"host_ip": "192.0.2.10"}}
    )
    wire = json.dumps(response, ensure_ascii=False)  # 模拟发给 LLM 的序列化全文
    assert TEST_SECRET not in wire, "完整 secret 泄漏进 LLM 视图"
    row = response["rows"][0]
    assert row["secret"] == mask_secret(TEST_SECRET)
    assert row["secret"].startswith("TE") and row["secret"].endswith("rd")
    assert row["secret_masked"] is True
    assert response["masking_note"]


async def test_attack_surface_via_tool_never_contains_secret(state_tool):
    state_tool._index.add_cred("192.0.2.10", "root", TEST_SECRET, source="TESTONLY-x")
    response = await state_tool.dispatch(
        "state_query", {"kind": "attack_surface", "filters": {"host_ip": "192.0.2.10"}}
    )
    assert response["found"] is True
    assert TEST_SECRET not in json.dumps(response, ensure_ascii=False)


def test_index_keeps_full_secret_on_disk(state_tool):
    """脱敏只影响 LLM 视图;落盘(index.sqlite)必须完整,WP-10 报告要取。"""
    state_tool._index.add_cred("192.0.2.10", "admin", TEST_SECRET)
    raw = sqlite3.connect(state_tool._engagement.paths.index_db)
    secret = raw.execute("SELECT secret FROM creds").fetchone()[0]
    assert secret == TEST_SECRET
    raw.close()


def test_mask_secret_rules():
    assert mask_secret("abcd") == "****"  # ≤4 全掩
    assert mask_secret("ab") == "****"
    assert mask_secret("abcde") == "ab********de"
    long_masked = mask_secret("x" * 100)
    assert long_masked == "xx********xx"
    # 掩码符数量固定,不泄露精确长度:长度 5 与 100 的掩码等长
    assert len(mask_secret("abcde")) == len(long_masked)


# ================================================================ 验收 4
# schema 与 WP-01 同构,可被 WP-04 直接注册

def test_tool_schemas_shape():
    assert {s["name"] for s in TOOL_SCHEMAS} == {
        "state_query",
        "state_add_note",
        "state_add_loot",
    }
    for schema in TOOL_SCHEMAS:
        assert set(schema) == {"name", "description", "parameters"}
        assert schema["parameters"]["type"] == "object"
        assert schema["parameters"]["additionalProperties"] is False
        assert isinstance(schema["description"], str) and schema["description"]
        assert schema["description"].isascii() is False  # 中文描述,与 WP-01 一致
    json.dumps(TOOL_SCHEMAS)  # 必须可 JSON 序列化(provider 中立纯 dict)


async def test_dispatch_roundtrip(state_tool):
    note = await state_tool.dispatch("state_add_note", {"text": "roundtrip 笔记"})
    assert note["added"] is True

    loot_file = state_tool._engagement.paths.loot / "sample.txt"
    loot_file.write_text("TESTONLY loot", encoding="utf-8")
    loot = await state_tool.dispatch(
        "state_add_loot", {"path": "loot/sample.txt", "kind": "dump", "note": "n"}
    )
    assert loot["added"] is True and loot["size_bytes"] == len("TESTONLY loot")

    query = await state_tool.dispatch("state_query", {"kind": "loot"})
    assert query["rows"][0]["path"] == "loot/sample.txt"
    notes = await state_tool.dispatch("state_query", {"kind": "notes"})
    assert notes["rows"][0]["text"] == "roundtrip 笔记"


async def test_dispatch_unknown_tool_raises(state_tool):
    with pytest.raises(KeyError):
        await state_tool.dispatch("not-a-tool", {})


async def test_dispatch_business_error_returns_error_dict(state_tool):
    res = await state_tool.dispatch("state_query", {"kind": "unknown-kind"})
    assert "error" in res
    res = await state_tool.dispatch("state_add_note", {"text": "  "})
    assert "error" in res
    res = await state_tool.dispatch(
        "state_query", {"kind": "attack_surface", "filters": {}}
    )
    assert "error" in res


async def test_add_loot_rejects_outside_and_missing(state_tool):
    res = await state_tool.dispatch(
        "state_add_loot", {"path": "../outside.txt"}
    )
    assert res["added"] is False and "不在 engagement 目录内" in res["error"]
    res = await state_tool.dispatch(
        "state_add_loot", {"path": "loot/not-there.bin"}
    )
    assert res["added"] is False and "不存在" in res["error"]


# ================================================================ ENGAGEMENT.md

def test_update_progress_renders_counts(engagement):
    tool = StateTool(engagement)
    tool._index.upsert_port("192.0.2.10", 445, "tcp")
    tool._index.add_cred("192.0.2.10", "admin", TEST_SECRET)
    tool._index.add_note("进展测试笔记")
    tool.close()

    text = engagement.update_progress(
        phase="枚举", current_objective="摸清 SMB 攻击面", note="下一步试空会话"
    )
    assert "最近阶段:枚举" in text
    assert "当前目标:摸清 SMB 攻击面" in text
    assert "hosts 1" in text and "ports 1" in text
    assert "creds 1" in text and "notes 1" in text
    assert "下一步试空会话" in text
    assert engagement.read_progress() == text
    # ENGAGEMENT.md 走 LLM context,同样不得带完整 secret
    assert TEST_SECRET not in text


def test_update_progress_after_close(engagement):
    engagement.mark_closed()
    text = engagement.update_progress(phase="收尾", current_objective="写报告")
    assert "状态:closed" in text


# ================================================================ WP-14a
# scope 动态段:markers / update_scope_section / update_scope_metadata /
# update_objective(验收 7/4 助手级 + 元数据)


def _scope_block(text: str) -> str:
    """取「## 授权范围」标题到说明引用块末尾的整段(两处初始形态合一比对用)。"""
    start = text.index("## 授权范围")
    tail = "影响执行且会被下次写入覆盖。"
    return text[start : text.index(tail) + len(tail)]


def _section_between_markers(text: str) -> str:
    begin = text.index(SCOPE_SECTION_BEGIN)
    start = text.index("\n", begin) + 1
    end = text.index(SCOPE_SECTION_END, start)
    return text[start : text.rfind("\n", start, end) + 1]


def test_initial_md_has_paired_scope_markers(engagement):
    """验收 7:create 路径 _render_initial_md 产物开箱即含 markers 成对。"""
    text = engagement.read_progress()
    assert text.count(SCOPE_SECTION_BEGIN) == 1
    assert text.count(SCOPE_SECTION_END) == 1
    assert text.index(SCOPE_SECTION_BEGIN) < text.index(SCOPE_SECTION_END)
    # 初始形态:标题 + 占位行 + 「harness 维护,勿手改」说明引用块
    assert "(scope 尚未冻结——确认后由 harness 写入当前生效的范围规则)" in text
    assert "> 以上「授权范围」段由 harness 维护,勿手改" in text


def test_initial_md_scope_block_matches_prompts_template():
    """验收 7:初始形态与 14d _ENGAGEMENT_TEMPLATE 动态段逐字合一
    (14d 一致性请求 2「两处初始形态合一」)。"""
    from_template = render_engagement_template(
        objective="合一比对", started_at="2026-09-18T00:00:00+00:00"
    )
    meta = {
        "id": "cmp-eng",
        "objective": "合一比对",
        "created_at": "2026-09-18T00:00:00+00:00",
        "scope": None,
    }
    from_files = Engagement._render_initial_md(meta)
    assert _scope_block(from_files) == _scope_block(from_template)


def test_update_scope_metadata_idempotent_and_absolute(tmp_path, scope_file):
    engagement = Engagement.create(
        tmp_path / "engagements", "meta 测试", engagement_id="meta-eng"
    )
    assert engagement.metadata()["scope"] is None  # create 无 scope 行为不变

    meta = engagement.update_scope_metadata(scope_file)
    expected = hashlib.sha256(scope_file.read_bytes()).hexdigest()
    assert meta["scope"] == {"path": str(scope_file.resolve()), "sha256": expected}
    assert Path(meta["scope"]["path"]).is_absolute()
    # 幂等:重复调用结果一致
    assert engagement.update_scope_metadata(scope_file)["scope"] == meta["scope"]
    assert engagement.metadata()["scope"] == meta["scope"]

    with pytest.raises(FileNotFoundError, match="scope 文件不存在"):
        engagement.update_scope_metadata(tmp_path / "nope.scope")


def test_update_scope_section_rewrite_preserves_outside_bytes(engagement):
    """验收 4:单形态——markers 间重写,markers 外内容字节不变(含模型手写段)。"""
    path = engagement.paths.progress_md
    before = path.read_text(encoding="utf-8") + "\n## 模型手写笔记\n\n这段要保留\n"
    path.write_text(before, encoding="utf-8")

    section = "- 来源:/x/scope.confirmed\n- 规则(每行一条):\n  192.0.2.0/24"
    engagement.update_scope_section(section)
    after = engagement.read_progress()

    prefix = before[: before.index(SCOPE_SECTION_BEGIN)]
    suffix = before[before.index(SCOPE_SECTION_END) + len(SCOPE_SECTION_END) :]
    assert after.startswith(prefix)
    assert after.endswith(suffix)
    assert _section_between_markers(after) == section + "\n"
    assert "(scope 尚未冻结" not in after  # 占位行被替换
    assert "这段要保留" in after  # markers 外模型手写内容原样保留

    # 连续两次写入幂等(同内容再写,文件不变)
    engagement.update_scope_section(section)
    assert engagement.read_progress() == after


def test_update_scope_section_empty_section_rewrite(engagement):
    """markers 间为空段(BEGIN 行紧邻 END 行)时重写不复制文件(下标边界)。"""
    path = engagement.paths.progress_md
    text = path.read_text(encoding="utf-8")
    empty_md = (
        text[: text.index(SCOPE_SECTION_BEGIN) + len(SCOPE_SECTION_BEGIN)]
        + "\n"
        + text[text.index(SCOPE_SECTION_END) :]
    )
    path.write_text(empty_md, encoding="utf-8")
    engagement.update_scope_section("- 来源:empty")
    after = engagement.read_progress()
    assert _section_between_markers(after) == "- 来源:empty\n"
    assert after.count("# Engagement") == 1  # 文件未被复制
    assert after.count(SCOPE_SECTION_BEGIN) == 1


def test_update_scope_section_same_line_markers_converge(engagement):
    """BEGIN/END 同行(模型手改)也属于 markers 间重写:一次写入即规整,
    幂等收敛,不再每次追加新块导致文件无界增长。"""
    path = engagement.paths.progress_md
    text = path.read_text(encoding="utf-8")
    begin = text.index(SCOPE_SECTION_BEGIN)
    end = text.index(SCOPE_SECTION_END) + len(SCOPE_SECTION_END)
    path.write_text(
        text[:begin] + SCOPE_SECTION_BEGIN + SCOPE_SECTION_END + text[end:],
        encoding="utf-8",
    )

    engagement.update_scope_section("- 来源:a")
    once = engagement.read_progress()
    assert _section_between_markers(once) == "- 来源:a\n"
    assert once.count("## 授权范围") == 1  # 未追加新块

    engagement.update_scope_section("- 来源:a")
    assert engagement.read_progress() == once  # 幂等
    engagement.update_scope_section("- 来源:b")
    thrice = engagement.read_progress()
    assert _section_between_markers(thrice) == "- 来源:b\n"
    assert len(thrice) == len(once)  # 无界增长修复的直接证据
    assert thrice.count("## 授权范围") == 1


def test_update_scope_section_end_line_prefix_replaced(engagement):
    """END 所在行有前置文本时,前缀属 markers 间内容,一并替换不留渣。"""
    path = engagement.paths.progress_md
    text = path.read_text(encoding="utf-8")
    old = (
        SCOPE_SECTION_BEGIN
        + "\n(scope 尚未冻结——确认后由 harness 写入当前生效的范围规则)\n"
        + SCOPE_SECTION_END
    )
    mangled = SCOPE_SECTION_BEGIN + "\n模型乱写的同行残留 " + SCOPE_SECTION_END
    assert old in text
    path.write_text(text.replace(old, mangled), encoding="utf-8")

    engagement.update_scope_section("- 来源:clean")
    after = engagement.read_progress()
    assert _section_between_markers(after) == "- 来源:clean\n"
    assert "模型乱写的同行残留" not in after


def test_update_scope_section_unpaired_begin_recovers(engagement):
    """markers 不成对(只剩 BEGIN,END 被模型删掉)→ 剥离游离 marker 后
    容错附加恢复完整对,并收敛回单形态。"""
    path = engagement.paths.progress_md
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text[: text.index(SCOPE_SECTION_END)] + text[text.index("> 以上") :],
        encoding="utf-8",
    )
    assert SCOPE_SECTION_END not in path.read_text(encoding="utf-8")

    engagement.update_scope_section("- 来源:recovered")
    recovered = engagement.read_progress()
    assert recovered.count(SCOPE_SECTION_BEGIN) == 1  # 游离 BEGIN 已剥离
    assert recovered.count(SCOPE_SECTION_END) == 1
    assert _section_between_markers(recovered) == "- 来源:recovered\n"

    # 恢复后收敛回单形态:再次写入走 markers 间重写
    engagement.update_scope_section("- 来源:final")
    final = engagement.read_progress()
    assert _section_between_markers(final) == "- 来源:final\n"
    assert final.count(SCOPE_SECTION_BEGIN) == 1
    assert final.count(SCOPE_SECTION_END) == 1


def test_update_scope_section_fault_append_restores_markers(engagement):
    """验收 4 容错分支:markers 缺失时完整段附加到末尾一次以恢复 markers。"""
    path = engagement.paths.progress_md
    text = path.read_text(encoding="utf-8")
    # 模型误删整段(markers 缺失,信息面容错场景)
    path.write_text(
        text[: text.index("## 授权范围")] + text[text.index("## 进展") :],
        encoding="utf-8",
    )
    engagement.update_scope_section("- 来源:y")
    recovered = engagement.read_progress()
    assert SCOPE_SECTION_BEGIN in recovered and SCOPE_SECTION_END in recovered
    assert _section_between_markers(recovered) == "- 来源:y\n"

    # 恢复后收敛回单形态:再次写入走 markers 间重写,markers 仍各一处
    engagement.update_scope_section("- 来源:z")
    again = engagement.read_progress()
    assert again.count(SCOPE_SECTION_BEGIN) == 1
    assert again.count(SCOPE_SECTION_END) == 1
    assert _section_between_markers(again) == "- 来源:z\n"


def test_update_objective_replaces_md_line(engagement):
    engagement.update_objective("新目标:复核边界")
    assert engagement.metadata()["objective"] == "新目标:复核边界"
    text = engagement.read_progress()
    assert "- 目标:新目标:复核边界" in text
    assert "- 目标:测试目标 objective" not in text


def test_update_objective_matches_parenthesized_form(engagement):
    """prompts 模板形态 ``- 目标(objective):`` 同样匹配替换。"""
    path = engagement.paths.progress_md
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "- 目标:测试目标 objective", "- 目标(objective):测试目标 objective"
        ),
        encoding="utf-8",
    )
    engagement.update_objective("统一形态")
    text = engagement.read_progress()
    assert "- 目标:统一形态" in text
    assert "目标(objective)" not in text


# ================================================================ R02
# 原子写 / 单写者锁 / 修订提交协议与崩溃恢复(AC06/AC07/AC08)/ 状态生命周期


def _revision_fixture(base: Path, engagement_id: str):
    """带修订史 engagement:A 起步 → B 已提交修订(含 marker)+ 备份。

    链:scope_loaded(A) → scope_confirmed(A) → run_started(旧目标)
    → scope_confirmed(B);commit_revision(scope=B, objective=新目标,
    marker=B 记录)。再备一份 C scope 供注入新修订。审计句柄已关闭。
    """
    base.mkdir(parents=True, exist_ok=True)
    scope_a = base / "a.scope"
    scope_a.write_text("192.0.2.0/24\n", encoding="utf-8")
    scope_b = base / "b.scope"
    scope_b.write_text("192.0.2.7/32\n", encoding="utf-8")
    scope_c = base / "c.scope"
    scope_c.write_text("198.51.100.0/24\n", encoding="utf-8")
    engagement = Engagement.create(
        base / "engagements",
        "旧目标",
        scope_path=scope_a,
        engagement_id=engagement_id,
    )
    digests = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in (("a", scope_a), ("b", scope_b), ("c", scope_c))
    }
    audit = AuditLog(engagement.paths.audit_jsonl)
    audit.append(
        KIND_SCOPE_LOADED,
        scope_payload(parse_scope(scope_a.read_text(encoding="utf-8")), str(scope_a)),
    )
    audit.append(
        KIND_SCOPE_CONFIRMED,
        scope_event_payload(
            parse_scope(scope_a.read_text(encoding="utf-8")),
            source="file",
            path=str(scope_a),
            canonical_sha256=digests["a"],
        ),
    )
    audit.append(
        "run_started",
        {
            "objective": "旧目标",
            "provider": "fake",
            "workdir": str(engagement.paths.root),
        },
    )
    record_b = audit.append(
        KIND_SCOPE_CONFIRMED,
        scope_event_payload(
            parse_scope(scope_b.read_text(encoding="utf-8")),
            source="file",
            path=str(scope_b),
            canonical_sha256=digests["b"],
        ),
    )
    audit.close()
    engagement.commit_revision(
        scope={"path": str(scope_b.resolve()), "sha256": digests["b"]},
        objective="新目标",
        marker=record_b,
    )
    return engagement, scope_c, digests


def _append_c_confirm(engagement: Engagement, scope_c: Path, c_digest: str) -> dict:
    """把 C 的 scope_confirmed 落审计链(模拟 resume --scope C 的确认记录)。"""
    audit = AuditLog(engagement.paths.audit_jsonl)
    record = audit.append(
        KIND_SCOPE_CONFIRMED,
        scope_event_payload(
            parse_scope(scope_c.read_text(encoding="utf-8")),
            source="file",
            path=str(scope_c),
            canonical_sha256=c_digest,
        ),
    )
    audit.close()
    return record


def test_metadata_write_failure_keeps_original_bytes(tmp_path, scope_file, monkeypatch):
    """R02-A:engagement.json 一律原子写——写中途失败(注入 OSError)时
    原文件字节不变,不留半截 JSON(修复前 _write_metadata 是裸 write_text)。"""
    engagement = Engagement.create(
        tmp_path / "engagements",
        "原子写测试",
        scope_path=scope_file,
        engagement_id="atomic-eng",
    )
    original = engagement.paths.metadata.read_bytes()

    def broken_write(path, text):
        # 模拟崩溃:tmp 写了一半,rename 前进程死亡
        path.with_name(path.name + ".tmp").write_text(text[:10], encoding="utf-8")
        raise OSError("注入:写盘中途失败")

    monkeypatch.setattr(files_module, "_atomic_write_text", broken_write)
    with pytest.raises(OSError, match="注入"):
        engagement.mark_closed()
    assert engagement.paths.metadata.read_bytes() == original
    assert engagement.metadata()["status"] == "active"  # 旧内容仍可解析


def test_create_first_write_failure_leaves_no_torn_json(
    tmp_path, scope_file, monkeypatch
):
    """R02-A:create 首写同样原子——失败时 engagement.json 不存在(无半截文件)。"""

    def broken_write(path, text):
        path.with_name(path.name + ".tmp").write_text(text[:10], encoding="utf-8")
        raise OSError("注入:首写失败")

    monkeypatch.setattr(files_module, "_atomic_write_text", broken_write)
    with pytest.raises(OSError, match="注入"):
        Engagement.create(
            tmp_path / "engagements",
            "x",
            scope_path=scope_file,
            engagement_id="torn-eng",
        )
    assert not (tmp_path / "engagements" / "torn-eng" / "engagement.json").exists()


def test_engagement_lock_single_writer(tmp_path):
    """R02-AC07:同一 engagement 目录同时只允许一个写者;释放后可再取。"""
    engagement = Engagement.create(
        tmp_path / "engagements", "锁测试", engagement_id="lock-eng"
    )
    lock = acquire_engagement_lock(engagement.paths.root)
    with pytest.raises(EngagementLockedError, match="另一个运行中的写者"):
        acquire_engagement_lock(engagement.paths.root)
    lock.release()
    again = acquire_engagement_lock(engagement.paths.root)
    again.release()


def test_engagement_lock_refused_while_externally_held(tmp_path):
    """模拟另一进程持锁(直接 flock 锁文件):持锁期间拒绝、解锁后放行。

    进程死亡(含崩溃)时内核自动回收 flock——本测试的 holder 即「外部写者」。
    """
    engagement = Engagement.create(
        tmp_path / "engagements", "锁测试", engagement_id="lock-eng2"
    )
    lock_path = engagement.paths.root / "engagement.lock"
    holder = open(lock_path, "a+b")  # noqa: SIM115
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(EngagementLockedError):
            acquire_engagement_lock(engagement.paths.root)
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()
    acquire_engagement_lock(engagement.paths.root).release()


def test_mark_active_reactivates_and_reclose_refreshes(engagement, monkeypatch):
    """R02-A 状态迁移:start/resume 置 active(清 closed_at);re-finish 时
    mark_closed 刷新 closed_at(修复旧 guard 下重复 finish 不刷新的问题)。
    killed/crash 不经 mark_closed,保持 active=中断可恢复(文档化边界)。"""
    times = iter(["2026-10-05T01:00:00+00:00", "2026-10-05T02:00:00+00:00"])
    monkeypatch.setattr(files_module, "_utc_now_iso", lambda: next(times))
    engagement.mark_closed()
    assert engagement.metadata()["closed_at"] == "2026-10-05T01:00:00+00:00"
    # start/resume:重新置 active,closed_at 清空
    engagement.mark_active()
    meta = engagement.metadata()
    assert meta["status"] == "active" and meta["closed_at"] is None
    before = engagement.paths.metadata.read_bytes()
    engagement.mark_active()  # 幂等:已 active 不落盘
    assert engagement.paths.metadata.read_bytes() == before
    # re-finish:closed_at 刷新为新值(旧实现被 status guard 挡住不刷新)
    engagement.mark_closed()
    assert engagement.metadata()["closed_at"] == "2026-10-05T02:00:00+00:00"


def test_commit_revision_backs_up_legacy_meta_once(engagement):
    """R02-A:legacy 目录(无 revision 键)首次提交前,engagement.json 原样
    备份为 engagement.json.pre-r02.bak;后续提交不覆盖备份;audit.jsonl 不动。"""
    original = engagement.paths.metadata.read_bytes()
    audit_before = engagement.paths.audit_jsonl.read_bytes()
    first = {"seq": 7, "hash": "ab" * 32}
    engagement.commit_revision(
        scope={"path": "/abs/b.scope", "sha256": "cd" * 32},
        objective="新目标",
        marker=first,
    )
    bak = engagement.paths.root / "engagement.json.pre-r02.bak"
    assert bak.read_bytes() == original  # 备份 = 升级前原文
    meta = engagement.metadata()
    assert meta["scope"] == {"path": "/abs/b.scope", "sha256": "cd" * 32}
    assert meta["objective"] == "新目标"
    assert meta["revision"] == first
    # ENGAGEMENT.md 目标行同步更新(信息面与 meta 一致)
    assert "- 目标:新目标" in engagement.read_progress()
    # 第二次提交:备份不覆盖,marker 推进,未给的维度不动
    second = {"seq": 9, "hash": "ef" * 32}
    engagement.commit_revision(objective="再改", marker=second)
    assert bak.read_bytes() == original
    meta = engagement.metadata()
    assert meta["objective"] == "再改"
    assert meta["revision"] == second
    assert meta["scope"] == {"path": "/abs/b.scope", "sha256": "cd" * 32}
    assert engagement.paths.audit_jsonl.read_bytes() == audit_before  # 不动链


def test_update_scope_metadata_bytes_binds_given_bytes(tmp_path):
    """R02-A:单次读盘绑定——sha256 取调用方提供字节,不二次读盘(TOCTOU 收口);
    path 按给定串落盘(as-given/absolute 口径由调用方定)。"""
    engagement = Engagement.create(
        tmp_path / "engagements", "bytes 绑定", engagement_id="bytes-eng"
    )
    data = b"192.0.2.0/24\n"
    meta = engagement.update_scope_metadata_bytes("relative/lab.scope", data)
    assert meta["scope"] == {
        "path": "relative/lab.scope",  # 不 resolve:调用方口径原样落盘
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    # 文件不存在也不读盘(与 update_scope_metadata 的 FileNotFoundError 区分)
    engagement.update_scope_metadata_bytes(tmp_path / "nope.scope", data)


def test_scope_revision_crash_recovery(tmp_path, monkeypatch):
    """R02-AC06/AC08:对修订提交各写入阶段注入故障,重开后只接受完整提交的
    修订或明确拒绝;既有审计字节逐字节不动。

    阶段:① 审计追加失败 → 修订未发生,状态原样;② 审计已追加、提交标记
    未写(崩溃窗口)→ 重开从链重建投影;③ metadata 投影写中途失败 → 原文
    不变、重开仍可从链重建;④ 完整提交 → 接受且幂等。
    (file 流无「快照写入」阶段——as-given 裁定不存 scope 字节快照;NL 冻结
    scope.confirmed 的崩溃窗口由 freeze_scope 既有 D13 drift 兜底覆盖,
    在 test_scope_compiler 钉死。)
    """
    # ---- 阶段①:审计追加失败 → 修订未发生
    eng1, scope_c1, digests1 = _revision_fixture(tmp_path / "s1", "s1-eng")
    base_audit = eng1.paths.audit_jsonl.read_bytes()
    base_meta = eng1.paths.metadata.read_bytes()

    def broken_append(self, kind, payload):
        raise OSError("注入:审计落盘失败")

    monkeypatch.setattr(AuditLog, "append", broken_append)
    with pytest.raises(OSError, match="注入"):
        _append_c_confirm(eng1, scope_c1, digests1["c"])
    monkeypatch.undo()
    assert eng1.paths.audit_jsonl.read_bytes() == base_audit  # AC08:链不动
    assert eng1.paths.metadata.read_bytes() == base_meta
    meta = Engagement.open(eng1.paths.root).reconcile_with_chain(
        read_records(eng1.paths.audit_jsonl)
    )
    assert meta["revision"]["seq"] == json.loads(base_meta)["revision"]["seq"]
    assert meta["scope"]["sha256"] == digests1["b"]  # 仍是已提交的 B

    # ---- 阶段②:审计已追加、提交标记未写(崩溃窗口)→ 从链重建
    eng2, scope_c2, digests2 = _revision_fixture(tmp_path / "s2", "s2-eng")
    base2 = eng2.paths.audit_jsonl.read_bytes()
    record_c = _append_c_confirm(eng2, scope_c2, digests2["c"])
    # 模拟崩溃:不写 engagement.json,直接重开对账
    reopened = Engagement.open(eng2.paths.root)
    meta = reopened.reconcile_with_chain(read_records(eng2.paths.audit_jsonl))
    assert meta["scope"] == {"path": str(scope_c2), "sha256": digests2["c"]}
    assert meta["objective"] == "新目标"  # run_started 未更新,目标不动
    assert meta["revision"] == {"seq": record_c["seq"], "hash": record_c["hash"]}
    after2 = eng2.paths.audit_jsonl.read_bytes()
    assert after2[: len(base2)] == base2  # AC08:对账不改链,前缀逐字节不动
    assert verify(eng2.paths.audit_jsonl)
    # 幂等:再对账不再重写
    committed_meta = reopened.paths.metadata.read_bytes()
    assert (
        reopened.reconcile_with_chain(read_records(eng2.paths.audit_jsonl)) == meta
    )
    assert reopened.paths.metadata.read_bytes() == committed_meta

    # ---- 阶段③:metadata 投影写中途失败 → 原文不变,重开仍可重建
    eng3, scope_c3, digests3 = _revision_fixture(tmp_path / "s3", "s3-eng")
    record_c3 = _append_c_confirm(eng3, scope_c3, digests3["c"])
    meta_before3 = eng3.paths.metadata.read_bytes()

    def torn_write(path, text):
        path.with_name(path.name + ".tmp").write_text(text[:5], encoding="utf-8")
        raise OSError("注入:投影写中途失败")

    monkeypatch.setattr(files_module, "_atomic_write_text", torn_write)
    with pytest.raises(OSError, match="注入"):
        eng3.commit_revision(
            scope={"path": str(scope_c3.resolve()), "sha256": digests3["c"]},
            marker={"seq": record_c3["seq"], "hash": record_c3["hash"]},
        )
    monkeypatch.undo()
    assert eng3.paths.metadata.read_bytes() == meta_before3  # 原子写:原文不变
    # 重开对账:从链完整重建崩溃丢失的修订
    meta = Engagement.open(eng3.paths.root).reconcile_with_chain(
        read_records(eng3.paths.audit_jsonl)
    )
    assert meta["scope"]["sha256"] == digests3["c"]
    assert meta["revision"] == {"seq": record_c3["seq"], "hash": record_c3["hash"]}

    # ---- 阶段④:完整提交 → 接受且幂等
    eng4, scope_c4, digests4 = _revision_fixture(tmp_path / "s4", "s4-eng")
    record_c4 = _append_c_confirm(eng4, scope_c4, digests4["c"])
    eng4.commit_revision(
        scope={"path": str(scope_c4.resolve()), "sha256": digests4["c"]},
        objective="再改目标",
        marker={"seq": record_c4["seq"], "hash": record_c4["hash"]},
    )
    committed4 = eng4.paths.metadata.read_bytes()
    meta = Engagement.open(eng4.paths.root).reconcile_with_chain(
        read_records(eng4.paths.audit_jsonl)
    )
    assert meta["scope"]["sha256"] == digests4["c"]
    assert meta["objective"] == "再改目标"
    assert eng4.paths.metadata.read_bytes() == committed4  # 接受且不再重写
    assert "- 目标:再改目标" in eng4.read_progress()  # md 目标行同步


def test_reconcile_rejects_fork_and_truncated_chain(tmp_path):
    """R02-AC06(拒绝面):marker 所指 seq 在链上不存在(截尾/缺条)或同 seq
    异 hash(分叉)→ 明确拒绝(ValueError),绝不猜;修复字节后可再对账。"""
    eng, scope_c, digests = _revision_fixture(tmp_path, "guard-eng")
    record_c = _append_c_confirm(eng, scope_c, digests["c"])
    eng.commit_revision(
        scope={"path": str(scope_c.resolve()), "sha256": digests["c"]},
        marker={"seq": record_c["seq"], "hash": record_c["hash"]},
    )
    good_bytes = eng.paths.audit_jsonl.read_bytes()

    # 分叉:整条链被换成另一条内部自洽的链(同 seq 处 hash 不同)——
    # 链自验发现不了(它确实合法),marker 是唯一的跨文件对账点
    other = tmp_path / "other.jsonl"
    audit = AuditLog(other)
    audit.append(
        KIND_SCOPE_LOADED,
        {
            "source": "fake",
            "cidrs": [],
            "hosts": [],
            "wildcards": [],
            "url_prefixes": [],
        },
    )
    for _ in range(record_c["seq"] - 1):
        audit.append(
            "run_started",
            {"objective": "fake", "provider": "fake", "workdir": "fake"},
        )
    audit.close()
    assert len(read_records(other)) >= record_c["seq"]
    eng.paths.audit_jsonl.write_bytes(other.read_bytes())
    with pytest.raises(ValueError, match="分叉|不符"):
        Engagement.open(eng.paths.root).reconcile_with_chain(
            read_records(eng.paths.audit_jsonl)
        )

    # 截尾:删掉末条(C 记录)→ marker 所指 seq 不存在
    lines = good_bytes.decode("utf-8").splitlines(keepends=True)
    eng.paths.audit_jsonl.write_bytes("".join(lines[:-1]).encode("utf-8"))
    with pytest.raises(ValueError, match="截尾|缺条|不存在"):
        Engagement.open(eng.paths.root).reconcile_with_chain(
            read_records(eng.paths.audit_jsonl)
        )

    # 修复:恢复链字节 → 对账接受(AC08:全程未改链,篡改/截尾都是测试替写)
    eng.paths.audit_jsonl.write_bytes(good_bytes)
    meta = Engagement.open(eng.paths.root).reconcile_with_chain(
        read_records(eng.paths.audit_jsonl)
    )
    assert meta["scope"]["sha256"] == digests["c"]


def test_reconcile_legacy_dir_without_marker_keeps_existing_behavior(tmp_path):
    """R02 边界钉死:无 marker 的 legacy 目录(含 E03 时代 fork:链上有更新的
    scope_confirmed 但 meta 未同步)——对账原样返回 meta,不从链重建、不猜;
    既有 meta-first + drift + 链回退路径不变。"""
    scope_a = tmp_path / "a.scope"
    scope_a.write_text("192.0.2.0/24\n", encoding="utf-8")
    scope_b = tmp_path / "b.scope"
    scope_b.write_text("192.0.2.7/32\n", encoding="utf-8")
    engagement = Engagement.create(
        tmp_path / "engagements",
        "旧目标",
        scope_path=scope_a,
        engagement_id="legacy-eng",
    )
    a_digest = hashlib.sha256(scope_a.read_bytes()).hexdigest()
    b_digest = hashlib.sha256(scope_b.read_bytes()).hexdigest()
    audit = AuditLog(engagement.paths.audit_jsonl)
    audit.append(
        KIND_SCOPE_LOADED,
        scope_payload(parse_scope(scope_a.read_text(encoding="utf-8")), str(scope_a)),
    )
    audit.close()
    # 模拟 E03 时代:resume --scope B 只落了确认记录,meta 未提交(无 marker)
    audit = AuditLog(engagement.paths.audit_jsonl)
    audit.append(
        KIND_SCOPE_CONFIRMED,
        scope_event_payload(
            parse_scope(scope_b.read_text(encoding="utf-8")),
            source="file",
            path=str(scope_b),
            canonical_sha256=b_digest,
        ),
    )
    audit.close()

    meta_before = engagement.paths.metadata.read_bytes()
    meta = Engagement.open(engagement.paths.root).reconcile_with_chain(
        read_records(engagement.paths.audit_jsonl)
    )
    assert meta.get("revision") is None  # 仍 legacy
    assert meta["scope"]["sha256"] == a_digest  # meta-first 原样,未采纳 B
    assert engagement.paths.metadata.read_bytes() == meta_before  # 未重写
