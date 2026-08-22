"""状态层测试(WP-06 验收 1/2/3/4)。

fixture 约定(契约 §4):凭据一律明显合成——TESTONLY 前缀口令、
RFC 5737 文档保留网段(192.0.2.0/24、198.51.100.0/24)与 example.com。
engagement 目录一律建在 tmp_path,运行时产物不入库。
"""

import hashlib
import json
import sqlite3

import pytest

from theform.state.files import LAYOUT, Engagement
from theform.state.index import Index
from theform.tools.state import TOOL_SCHEMAS, StateTool, mask_secret

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
