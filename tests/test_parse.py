"""parse 增强库测试(WP-07 验收 1/2/3)。

fixture 全合成(RFC 5737 文档段 / example.com / TESTONLY 凭据),
不含任何真实目标数据。快照逐字锁定 summary 文本与 facts 列表。
"""

import json
import sqlite3
from pathlib import Path

import pytest

from foam.guard import audit as audit_mod
from foam.guard.audit import AuditLog
from foam.state.index import Index
from foam.tools.parse import (
    PARSERS,
    SUMMARY_LIMIT_BYTES,
    apply_facts,
    maybe_parse,
)

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


# ================================================================ 验收 1
# 每个解析器配合成 fixture,summary/facts 快照单测

NMAP_HOSTS_PORTS_SUMMARY = (
    "nmap:2 台存活,开放端口 4 个。"
    "192.0.2.10(web.example.com): 22/ssh, 80/http, 445/microsoft-ds"
    " | 192.0.2.11: 22/ssh"
)


def test_nmap_xml_snapshot():
    result = maybe_parse("nmap -sV -oX - 192.0.2.10-12", fixture_text("nmap_xml.xml"))
    assert result is not None and result.tool == "nmap"
    assert result.summary == NMAP_HOSTS_PORTS_SUMMARY
    assert result.facts == [
        {"kind": "host", "ip": "192.0.2.10", "hostname": "web.example.com"},
        {
            "kind": "port", "host": "192.0.2.10", "port": 22, "proto": "tcp",
            "service": "ssh", "product": "OpenSSH", "version": "8.9p1 Debian 5",
        },
        {
            "kind": "port", "host": "192.0.2.10", "port": 80, "proto": "tcp",
            "service": "http", "product": "Apache httpd", "version": "2.4.49",
        },
        {
            "kind": "port", "host": "192.0.2.10", "port": 445, "proto": "tcp",
            "service": "microsoft-ds", "product": "Samba smbd", "version": "4.6.2",
        },
        {"kind": "host", "ip": "192.0.2.11"},
        {
            "kind": "port", "host": "192.0.2.11", "port": 22, "proto": "tcp",
            "service": "ssh", "product": "OpenSSH", "version": "7.4",
        },
    ]
    # closed 端口(3389)与 down 主机(192.0.2.12)不得出现
    assert not any(f.get("port") == 3389 for f in result.facts)
    assert not any(f.get("ip") == "192.0.2.12" for f in result.facts)


def test_nmap_grepable_snapshot():
    result = maybe_parse(
        "nmap -sV -oG - 192.0.2.10-11", fixture_text("nmap_grepable.txt")
    )
    assert result is not None
    assert result.summary == NMAP_HOSTS_PORTS_SUMMARY
    ssh10 = next(
        f for f in result.facts
        if f.get("port") == 22 and f["host"] == "192.0.2.10"
    )
    assert ssh10["version"] == "OpenSSH 8.9p1 Debian 5"
    assert ssh10["product"] is None  # grepable 不分 product/version
    http = next(f for f in result.facts if f.get("port") == 80)
    assert http["version"] == "Apache httpd 2.4.49"


def test_nmap_table_snapshot():
    result = maybe_parse("nmap -sV 192.0.2.10-11", fixture_text("nmap_table.txt"))
    assert result is not None
    assert result.summary == NMAP_HOSTS_PORTS_SUMMARY
    ssh10 = next(
        f for f in result.facts
        if f.get("port") == 22 and f["host"] == "192.0.2.10"
    )
    assert ssh10["version"] == "OpenSSH 8.9p1 Debian 5 (protocol 2.0)"
    assert not any(f.get("port") == 3389 for f in result.facts)  # closed 排除


def test_sqlmap_snapshot():
    result = maybe_parse(
        "sqlmap -u http://www.example.com/?id=1 --batch",
        fixture_text("sqlmap_stdout.txt"),
        output_path="outputs/abc123.log",
    )
    assert result is not None and result.tool == "sqlmap"
    assert result.summary == (
        "sqlmap:确认 2 个注入点(目标 www.example.com),后端 DBMS MySQL >= 5.0:"
        "id(GET):AND boolean-based blind - WHERE or HAVING clause;"
        "id(GET):MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY "
        "or GROUP BY clause (BIGINT UNSIGNED)"
    )
    assert len(result.facts) == 2
    first = result.facts[0]
    assert first["kind"] == "vuln" and first["vkind"] == "sqli"
    assert first["host"] == "www.example.com"
    assert first["confidence"] == "confirmed"
    assert first["evidence_path"] == "outputs/abc123.log"
    assert "boolean-based blind" in first["title"]


def test_gobuster_snapshot():
    result = maybe_parse(
        "gobuster dir -u http://192.0.2.10/ -w /usr/share/wordlists/dirb/common.txt",
        fixture_text("gobuster.txt"),
    )
    assert result is not None and result.tool == "gobuster"
    assert result.summary == (
        "gobuster:命中 8 条路径(200×1 301×3 403×4);"
        "亮点:/admin(301), /images(301), /index.php(200), /uploads(301)"
    )
    assert len(result.facts) == 8
    assert result.facts[0] == {"kind": "endpoint", "path": "/.hta", "status": 403}
    admin = next(f for f in result.facts if f["path"] == "/admin")
    assert admin["redirect"] == "http://192.0.2.10/admin/"


def test_nikto_snapshot():
    result = maybe_parse(
        "nikto -h http://web.example.com/", fixture_text("nikto.txt"),
        output_path="outputs/def456.log",
    )
    assert result is not None and result.tool == "nikto"
    # 逐字快照(291 字节,不触发 cap)
    assert result.summary == (
        "nikto:web.example.com Server Apache/2.4.49 (Unix);6 项发现:"
        "/: The anti-clickjacking X-Frame-Options header is not present.;"
        "/: The X-Content-Type-Options header is not set. This could allow "
        "the user agent to render the content of the site in a different "
        "fashion to the MIME type. 等 6 项"
    )
    assert len(result.summary.encode("utf-8")) <= SUMMARY_LIMIT_BYTES
    # facts 归属输出自带的 Target IP(与 nmap 的 IP 行合一),
    # 主机名经 host fact 挂到 IP 上而不是另起一台 host
    assert result.facts[0] == {
        "kind": "host", "ip": "192.0.2.10", "hostname": "web.example.com",
    }
    port_facts = [f for f in result.facts if f["kind"] == "port"]
    assert port_facts == [
        {
            "kind": "port", "host": "192.0.2.10", "port": 80,
            "proto": "tcp", "service": "http",
            "product": "Apache", "version": "2.4.49 (Unix)",
        }
    ]
    vulns = [f for f in result.facts if f["kind"] == "vuln"]
    assert len(vulns) == 6
    assert all(v["vkind"] == "nikto" for v in vulns)
    assert all(v["host"] == "192.0.2.10" for v in vulns)
    titles = json.dumps([v["title"] for v in vulns], ensure_ascii=False)
    assert "/admin/" in titles and "OSVDB-3092" in titles
    # 统计行/头部行不得混入 findings
    assert "7915 requests" not in titles and "Target IP" not in titles


def test_hydra_snapshot():
    result = maybe_parse(
        "hydra -L users.txt -P passes.txt 192.0.2.10 ssh",
        fixture_text("hydra.txt"),
    )
    assert result is not None and result.tool == "hydra"
    # facts 带完整 secret(进索引落盘,WP-10 报告可见)
    assert result.facts == [
        {
            "kind": "cred", "host": "192.0.2.10", "username": "admin",
            "secret": "TESTONLY-passw0rd", "source": "hydra",
        },
        {
            "kind": "cred", "host": "192.0.2.10", "username": "root",
            "secret": "TESTONLY-toor", "source": "hydra",
        },
    ]
    # 红线:summary 是 LLM 视图,完整 secret 不得出现,只有掩码形式
    assert "TESTONLY-passw0rd" not in result.summary
    assert "TESTONLY-toor" not in result.summary
    assert result.summary == (
        "hydra:2 组有效凭据(192.0.2.10):admin/TE********rd, root/TE********or"
        "——完整值已入索引,报告可见"
    )


def test_whatweb_snapshot():
    result = maybe_parse("whatweb http://192.0.2.10/", fixture_text("whatweb.txt"))
    assert result is not None and result.tool == "whatweb"
    assert result.summary == (
        "whatweb:1 个站点 — http://192.0.2.10/ → 200;"
        "Apache 2.4.49 + PHP 7.4.3;标题《Test Lab Home》"
    )
    assert result.facts == [
        {
            "kind": "port", "host": "192.0.2.10", "port": 80, "proto": "tcp",
            "service": "http", "product": "Apache", "version": "2.4.49",
        }
    ]


def test_registry_covers_six_tools():
    assert set(PARSERS) == {
        "nmap", "sqlmap", "gobuster", "nikto", "hydra", "whatweb",
    }


# ----------------------------- 对抗审查(ultracode workflow)确认项的回归用例:
# SSL Info 吞行 / 连字符模块 / JSON 参数归属 / DBMS 全名 /
# 存活无开放端口主机 / 服务名修饰符

def test_nikto_https_ssl_info_not_a_vuln():
    """HTTPS 扫描必出的 + SSL Info: 证书元数据行不得进 vulns 表。"""
    output = (
        "- Nikto v2.5.0\n"
        "+ Target IP:          192.0.2.10\n"
        "+ Target Hostname:    web.example.com\n"
        "+ Target Port:        443\n"
        "+ SSL Info:        Subject:  /CN=web.example.com\n"
        "                   Ciphers:  TLS_AES_256_GCM_SHA384\n"
        "                   Issuer:   /CN=example-ca\n"
        "+ Server: Apache/2.4.49 (Unix)\n"
        "+ /: The anti-clickjacking X-Frame-Options header is not present.\n"
        "+ 7915 requests: 0 error(s) and 1 item(s) reported on remote host\n"
        "+ 1 host(s) tested\n"
    )
    result = maybe_parse("nikto -h https://web.example.com/", output)
    assert result is not None
    port_facts = [f for f in result.facts if f["kind"] == "port"]
    assert port_facts[0]["port"] == 443
    assert [v["title"] for v in result.facts if v["kind"] == "vuln"] == [
        "/: The anti-clickjacking X-Frame-Options header is not present."
    ]
    assert "1 项发现" in result.summary and "SSL Info" not in result.summary


def test_hydra_hyphenated_module():
    """http-get-form 等连字符模块名命中行同样收凭据(Web 表单爆破主场景)。"""
    output = (
        "[80][http-get-form] host: 192.0.2.10   login: admin   "
        "password: TESTONLY-s3cret\n"
    )
    result = maybe_parse(
        "hydra -L u.txt -P p.txt 192.0.2.10 http-get-form /login:u=^USER^&p=^PASS^",
        output,
    )
    assert result is not None
    assert result.facts == [
        {
            "kind": "cred", "host": "192.0.2.10", "username": "admin",
            "secret": "TESTONLY-s3cret", "source": "hydra",
        }
    ]
    assert "TESTONLY-s3cret" not in result.summary


def test_sqlmap_json_param_and_dbms_full_name():
    """`Parameter: JSON search ((custom) POST)`:归属正确,不误挂前一参数;
    `the back-end DBMS is Microsoft SQL Server` 抓全名不截断。"""
    output = (
        "Parameter: id (GET)\n"
        "    Type: boolean-based blind\n"
        "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
        "Parameter: JSON search ((custom) POST)\n"
        "    Type: error-based\n"
        "    Title: MySQL >= 5.0 AND error-based - WHERE or HAVING clause\n"
        "[10:00:15] [INFO] the back-end DBMS is Microsoft SQL Server\n"
    )
    result = maybe_parse("sqlmap -u http://www.example.com/?id=1 --batch", output)
    assert result is not None
    assert [f["title"] for f in result.facts] == [
        "SQL 注入 id(GET):AND boolean-based blind - WHERE or HAVING clause",
        "SQL 注入 JSON search((custom) POST):"
        "MySQL >= 5.0 AND error-based - WHERE or HAVING clause",
    ]
    assert "后端 DBMS Microsoft SQL Server" in result.summary


def test_nmap_grepable_host_without_open_ports():
    """真实 -oG:存活但无开放端口的主机只有 Status 行,host fact 与计数不丢。"""
    output = (
        "Host: 192.0.2.10 ()\tStatus: Up\n"
        "Host: 192.0.2.10 (web.example.com)\tPorts: "
        "80/open/tcp//http//Apache httpd 2.4.49/\n"
        "Host: 192.0.2.13 ()\tStatus: Up\n"
    )
    result = maybe_parse("nmap -oG - 192.0.2.10-13", output)
    assert result is not None
    assert result.summary == (
        "nmap:2 台存活,开放端口 1 个。"
        "192.0.2.10(web.example.com): 80/http | 192.0.2.13: 无开放端口"
    )
    hosts = [f for f in result.facts if f["kind"] == "host"]
    assert [h["ip"] for h in hosts] == ["192.0.2.10", "192.0.2.13"]
    # Status 行常无主机名,Ports 行的 rDNS 要回填到同一 host fact
    assert hosts[0]["hostname"] == "web.example.com"


def test_nmap_service_name_modifiers_cleaned():
    """`ajp13?` 去问号、`ssl|http` 取隧道后段:服务列只放可查询裸名。"""
    table = (
        "Nmap scan report for 192.0.2.10\n"
        "PORT     STATE SERVICE  VERSION\n"
        "8009/tcp open  ajp13?\n"
        "443/tcp  open  ssl|http Apache httpd 2.4.49\n"
    )
    result = maybe_parse("nmap -sV 192.0.2.10", table)
    assert result is not None
    services = {
        f["port"]: f["service"] for f in result.facts if f["kind"] == "port"
    }
    assert services == {8009: "ajp13", 443: "http"}
    grepable = (
        "Host: 192.0.2.10 ()\tPorts: "
        "443/open/tcp//ssl|http//Apache httpd 2.4.49/\n"
    )
    g_result = maybe_parse("nmap -oG - 192.0.2.10", grepable)
    assert g_result is not None
    assert g_result.facts[1]["service"] == "http"
    assert g_result.facts[1]["version"] == "Apache httpd 2.4.49"


# ================================================================ 验收 2
# facts 进 WP-06 索引的集成单测

def test_nmap_facts_into_index(tmp_path):
    result = maybe_parse("nmap -sV -oX - 192.0.2.10-12", fixture_text("nmap_xml.xml"))
    with Index(tmp_path / "index.sqlite") as index:
        stats = apply_facts(index, result.facts)
        assert stats == {
            "hosts": 2, "ports": 4, "creds": 0,
            "vulns": 0, "loot": 0, "skipped": 0,
        }
        # 445 反查(验收 2 原话:nmap fixture → hosts/ports 可查)
        smb_hosts = index.hosts_with_port(445)
        assert [r["ip"] for r in smb_hosts] == ["192.0.2.10"]
        assert smb_hosts[0]["service"] == "microsoft-ds"
        surface = index.attack_surface("192.0.2.10")
        assert [p["port"] for p in surface["ports"]] == [22, 80, 445]
        ssh = next(p for p in surface["ports"] if p["port"] == 22)
        assert ssh["product"] == "OpenSSH" and ssh["version"] == "8.9p1 Debian 5"
        assert surface["host"]["hostname"] == "web.example.com"


def test_apply_facts_skips_unknown_kind(tmp_path):
    facts = [
        {"kind": "endpoint", "path": "/admin", "status": 301},
        {"kind": "host", "ip": "192.0.2.20"},
        {"kind": "port"},  # 畸形:缺 host/port
    ]
    with Index(tmp_path / "index.sqlite") as index:
        stats = apply_facts(index, facts)
        assert stats == {
            "hosts": 1, "ports": 0, "creds": 0,
            "vulns": 0, "loot": 0, "skipped": 2,
        }
        assert index.counts()["hosts"] == 1


async def test_hydra_cred_facts_into_index_and_masked_via_tool(tmp_path):
    """闭环:hydra facts 完整值进索引;WP-06 工具视图仍掩码。"""
    from foam.state.files import Engagement
    from foam.tools.state import StateTool

    result = maybe_parse("hydra 192.0.2.10 ssh", fixture_text("hydra.txt"))
    engagement = Engagement.create(
        tmp_path / "engagements", "闭环测试", engagement_id="parse-e2e"
    )
    with Index(engagement.paths.index_db) as index:
        apply_facts(index, result.facts)
    with StateTool(engagement) as tool:
        response = await tool.dispatch("state_query", {"kind": "creds"})
    wire = json.dumps(response, ensure_ascii=False)
    assert "TESTONLY-passw0rd" not in wire  # LLM 视图掩码
    assert response["rows"][0]["secret_masked"] is True
    # 红线另一面:完整值必须真实落库(掩码只作用 LLM 视图,
    # 若有人把掩码提前到存储侧,WP-10 报告将只剩掩码——此断言拦截)
    conn = sqlite3.connect(engagement.paths.index_db)
    try:
        stored = dict(conn.execute("SELECT username, secret FROM creds"))
    finally:
        conn.close()
    assert stored == {"admin": "TESTONLY-passw0rd", "root": "TESTONLY-toor"}


def test_sqlmap_vuln_facts_into_index(tmp_path):
    """vuln 分支集成:sqlmap facts 真进索引可反查(此前该分支零覆盖)。"""
    result = maybe_parse(
        "sqlmap -u http://www.example.com/?id=1 --batch",
        fixture_text("sqlmap_stdout.txt"),
        output_path="outputs/abc123.log",
    )
    with Index(tmp_path / "index.sqlite") as index:
        stats = apply_facts(index, result.facts)
        assert stats["vulns"] == 2
        rows = index.query("vulns")["rows"]
        assert len(rows) == 2
        assert all(r["kind"] == "sqli" for r in rows)
        assert all(r["confidence"] == "confirmed" for r in rows)
        assert {r["evidence_path"] for r in rows} == {"outputs/abc123.log"}


def test_sqlmap_loot_csv(tmp_path):
    """规格「stdout 关键段 + loot CSV」:dump 目录存在时登记 loot 并提凭据。"""
    out_dir = tmp_path / "output" / "www.example.com"
    dump_dir = out_dir / "dump" / "testdb"
    dump_dir.mkdir(parents=True)
    csv_path = dump_dir / "users.csv"
    csv_path.write_text(
        "id,user,password,email\n"
        "1,admin,TESTONLY-hash5,admin@example.com\n"
        "2,guest,TESTONLY-hash9,guest@example.com\n",
        encoding="utf-8",
    )
    stdout = fixture_text("sqlmap_stdout.txt").replace(
        "/home/TESTONLY/.sqlmap/output/www.example.com", str(out_dir)
    )
    result = maybe_parse("sqlmap -u http://www.example.com/?id=1 --batch", stdout)
    assert result is not None
    loot = [f for f in result.facts if f["kind"] == "loot"]
    assert loot == [
        {
            "kind": "loot", "path": str(csv_path), "lkind": "sqlmap-dump",
            "note": "users:2 行,列 id,user,password,email",
            "size_bytes": csv_path.stat().st_size,
        }
    ]
    assert result.facts[-2:] == [
        {
            "kind": "cred", "host": "www.example.com", "username": "admin",
            "secret": "TESTONLY-hash5", "source": "sqlmap-dump",
        },
        {
            "kind": "cred", "host": "www.example.com", "username": "guest",
            "secret": "TESTONLY-hash9", "source": "sqlmap-dump",
        },
    ]
    assert "dump 已登记 1 个 CSV(含 2 条凭据,完整值已入索引)" in result.summary
    # 明文只进索引,不进 summary(LLM 视图红线与 hydra 一致)
    assert "TESTONLY-hash5" not in result.summary
    with Index(tmp_path / "index.sqlite") as index:
        stats = apply_facts(index, result.facts)
        assert stats["loot"] == 1 and stats["creds"] == 2
        loot_rows = index.query("loot")["rows"]
        assert loot_rows[0]["kind"] == "sqlmap-dump"


def test_sqlmap_loot_dir_missing_keeps_stdout_result():
    """output 目录不存在(sqlmap 在别的机器/容器跑):只丢 loot,
    stdout 注入确认照常——loot 扫描绝不影响主解析。"""
    result = maybe_parse(
        "sqlmap -u http://www.example.com/?id=1 --batch",
        fixture_text("sqlmap_stdout.txt"),
    )
    assert result is not None
    assert not [f for f in result.facts if f["kind"] == "loot"]
    assert len([f for f in result.facts if f["kind"] == "vuln"]) == 2
    assert "dump" not in result.summary


# ================================================================ 验收 3
# 未知工具 / 格式损坏 两条回退路径

def test_unknown_tool_falls_back_silently(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    with AuditLog(log_path) as log:
        result = maybe_parse("fping -a 192.0.2.0/24", "192.0.2.1 is alive", audit=log)
    assert result is None
    # 注册表未命中是常态不是异常:不记审计
    assert log_path.read_text(encoding="utf-8").strip() == ""


def test_damaged_output_falls_back_with_debug_audit(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    with AuditLog(log_path) as log:
        result = maybe_parse("nmap -sV 192.0.2.10", "这根本不是 nmap 输出", audit=log)
    assert result is None
    records = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(records) == 1
    assert records[0]["kind"] == "parse_fallback"
    assert records[0]["payload"]["tool"] == "nmap"
    assert records[0]["payload"]["reason"] == "no_match"
    assert audit_mod.verify(log_path)


def test_truncated_xml_falls_back(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    truncated = '<?xml version="1.0"?>\n<nmaprun><host><status state="up"/'
    with AuditLog(log_path) as log:
        result = maybe_parse("nmap -oX - 192.0.2.10", truncated, audit=log)
    assert result is None
    record = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert record["payload"]["reason"] == "no_match"  # XML 损坏后文本路径也无获


def test_parser_exception_falls_back_with_audit(tmp_path):
    """XML 合法但结构畸形(缺 portid)→ 解析器内部异常 → exception 回退。"""
    log_path = tmp_path / "audit.jsonl"
    malformed = (
        '<?xml version="1.0"?>\n<nmaprun>'
        '<host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>'
        '<ports><port protocol="tcp">'
        "<state state=\"open\"/></port></ports></host></nmaprun>"
    )
    with AuditLog(log_path) as log:
        result = maybe_parse("nmap -oX - 192.0.2.10", malformed, audit=log)
    assert result is None
    record = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert record["payload"]["reason"] == "exception"
    assert "detail" in record["payload"]


def test_no_audit_still_falls_back():
    """不传 audit:回退同样静默,绝不抛给调用方。"""
    assert maybe_parse("nmap 192.0.2.10", "垃圾输出 {乱码 \x00\x01") is None


def test_maybe_parse_bad_parser_result_falls_back(tmp_path):
    """后续 WP 注册的解析器返回畸形形状(非 ParsedOutput / summary 非 str):
    同样走 exception 回退,绝不上抛给 loop(审查确认的真实逃逸面)。"""
    from foam.tools.parse import ParsedOutput, register

    @register("badtool")
    def _parse_badtool(command, output_text, output_path):
        return {"summary": "x"}  # 非 ParsedOutput

    @register("nonstrtool")
    def _parse_nonstrtool(command, output_text, output_path):
        return ParsedOutput("nonstrtool", None, [])  # summary 非 str

    log_path = tmp_path / "audit.jsonl"
    try:
        with AuditLog(log_path) as log:
            assert maybe_parse("badtool 192.0.2.10", "out", audit=log) is None
            assert maybe_parse("nonstrtool 192.0.2.10", "out", audit=log) is None
    finally:
        del PARSERS["badtool"]
        del PARSERS["nonstrtool"]
    records = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [r["payload"]["reason"] for r in records] == ["exception", "exception"]


@pytest.mark.parametrize(
    "tool", ["nmap", "sqlmap", "gobuster", "nikto", "hydra", "whatweb"]
)
def test_every_parser_no_match_falls_back(tool, tmp_path):
    """产品底线逐家验证:格式损坏 → 静默回退 + no_match 审计,六家全覆盖。"""
    log_path = tmp_path / "audit.jsonl"
    command = f"{tool} --weird-flag 192.0.2.10"
    with AuditLog(log_path) as log:
        result = maybe_parse(command, "完全无关的输出\n{乱码 \x00", audit=log)
    assert result is None
    record = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert record["payload"]["tool"] == tool
    assert record["payload"]["reason"] == "no_match"
    assert record["payload"]["command"] == command


def test_apply_facts_malformed_and_db_errors_skipped(tmp_path):
    """非 dict 元素、必填字段 None(触发 NOT NULL 约束)——全归 skipped,
    索引层 sqlite 错误同样不为门槛。"""
    facts = [
        None,
        "oops",
        {"kind": "cred", "host": "192.0.2.9", "username": "u", "secret": None},
        {"kind": "host", "ip": None},
        {"kind": "loot", "path": "outputs/x.csv", "lkind": "sqlmap-dump"},
    ]
    with Index(tmp_path / "index.sqlite") as index:
        stats = apply_facts(index, facts)
        assert stats == {
            "hosts": 0, "ports": 0, "creds": 0,
            "vulns": 0, "loot": 1, "skipped": 4,
        }


# ================================================================ summary 预算

def test_cap_summary_byte_budget_and_multibyte():
    from foam.tools.parse import cap_summary

    long_text = "扫描结果" * 200  # 2400 字节,远超预算
    capped = cap_summary(long_text)
    assert len(capped.encode("utf-8")) <= SUMMARY_LIMIT_BYTES
    assert capped.endswith("…")
    # 不截半多字节字符:去掉省略号后必须是原文的完整前缀
    assert long_text.startswith(capped[:-1])
    # 短文本与恰好在边界上的文本原样返回
    assert cap_summary("短摘要") == "短摘要"
    exact = "a" * SUMMARY_LIMIT_BYTES
    assert cap_summary(exact) == exact


def test_maybe_parse_caps_parser_summary():
    """解析器返回超长 summary 时,maybe_parse 统一截进预算。"""
    from foam.tools.parse import ParsedOutput, register

    @register("bigtool")
    def _parse_bigtool(command, output_text, output_path):
        return ParsedOutput("bigtool", "噪音数据" * 500, [])

    try:
        result = maybe_parse("bigtool --loud 192.0.2.10", "raw output")
        assert result is not None
        assert len(result.summary.encode("utf-8")) <= SUMMARY_LIMIT_BYTES
        assert result.summary.endswith("…")
    finally:
        del PARSERS["bigtool"]  # 不污染其他用例


def test_cap_summary_tiny_limit_clamped():
    """limit<4 夹紧到 4:负索引切片不会让预算失效(此前 limit=0 返回全文)。"""
    from foam.tools.parse import cap_summary

    assert len(cap_summary("扫描" * 100, limit=0).encode("utf-8")) <= 4
    assert len(cap_summary("abcdef" * 100, limit=2).encode("utf-8")) <= 4
    assert cap_summary("abc", limit=2) == "abc"  # 未超限原样返回


def test_tool_name_wrapper_and_basename():
    table = fixture_text("nmap_table.txt")
    assert maybe_parse("sudo nmap -sV 192.0.2.10", table) is not None
    assert maybe_parse("/usr/bin/nmap 192.0.2.10", table) is not None
    assert maybe_parse("", "whatever") is None
    # shlex 未闭合引号 ValueError → None(不解析、不记审计、不抛)
    assert maybe_parse('nmap "未闭合引号', table) is None


def test_register_extends_registry():
    from foam.tools.parse import register

    @register("mytool")
    def _parse_mytool(command, output_text, output_path):
        from foam.tools.parse import ParsedOutput

        return ParsedOutput("mytool", "自定义摘要", [])

    try:
        result = maybe_parse("mytool --scan x", "any output")
        assert result is not None and result.summary == "自定义摘要"
    finally:
        del PARSERS["mytool"]  # 不污染其他用例
