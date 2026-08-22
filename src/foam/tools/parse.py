"""parse 增强库(WP-07):把高频工具输出变成「LLM 摘要 + 索引事实」二元组。

**增强而非门槛**(产品底线):
- 注册表未命中(冷门工具)→ 返回 None,loop 走 WP-01 通用输出路径,
  LLM 用任何工具都不被挡;
- 解析失败(输出格式变了/被截断)→ 同样返回 None 静默回退,**绝不把
  异常抛给 LLM**;若传入 WP-02 的 AuditLog,记一条 ``parse_fallback``
  debug 审计(reason 区分 exception / no_match)。

产出二元组:``summary``(≤ ``SUMMARY_LIMIT_BYTES`` 字节的紧凑中文摘要,
给 LLM)+ ``facts``(原子事实 dict 列表,经 :func:`apply_facts` 喂
WP-06 索引)。fact 形状:

- ``{"kind": "host", "ip", "hostname"?}``
- ``{"kind": "port", "host", "port", "proto"?, "service"?, "product"?, "version"?}``
- ``{"kind": "cred", "host", "username", "secret", "source"?}``
- ``{"kind": "vuln", "host", "vkind", "title", "evidence_path"?, "confidence"?}``
- ``{"kind": "loot", "path", "lkind"?, "note"?, "size_bytes"?}``(sqlmap
  dump CSV 登记;``lkind`` 避开 ``kind`` 判别键)
- 其余 kind(如 gobuster 的 ``endpoint``):apply_facts 跳过并计数,
  留给未来索引扩展。

接线形状与 WP-01 同构:``PARSERS`` 注册表(后续 WP 加解析器 =
``PARSERS["tool"] = fn`` 或 ``@register("tool")``)+ :func:`maybe_parse`
单入口(相当于 dispatch),loop 接线不在本 WP 范围。

敏感红线:hydra 等解析器的 facts 带完整 secret(落盘进索引,WP-10 报告
可见),但 **summary 里一律掩码**(复用 WP-06 ``mask_secret``)——summary
是 LLM 视图。
"""

from __future__ import annotations

import csv
import re
import shlex
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit
from xml.etree import ElementTree

from foam.guard.scope import extract_targets
from foam.tools.state import mask_secret

if TYPE_CHECKING:
    from foam.guard.audit import AuditLog
    from foam.state.index import Index

#: 解析回退的 debug 审计 kind(WP-02 审计链允许扩展新 kind)。
KIND_PARSE_FALLBACK = "parse_fallback"

#: summary 字节预算(规格:≤500 字节)。
SUMMARY_LIMIT_BYTES = 500

#: 常见提权/环境包装命令:识别工具名时跳过(裸包装,不带选项)。
_WRAPPER_COMMANDS = frozenset({"sudo", "doas", "env"})


@dataclass
class ParsedOutput:
    """解析器产出:summary(LLM 视图)+ facts(索引事实)。"""

    tool: str
    summary: str
    facts: list[dict[str, Any]] = field(default_factory=list)


#: 注册表:工具名(命令首 token 的 basename)→ 解析函数,
#: 签名 (command, output_text, output_path) -> ParsedOutput | None。
PARSERS: dict[str, Any] = {}


def register(tool: str):
    """注册解析器装饰器(后续 WP 扩充解析器的标准方式)。"""

    def _decorator(fn):
        PARSERS[tool] = fn
        return fn

    return _decorator


def cap_summary(text: str, limit: int = SUMMARY_LIMIT_BYTES) -> str:
    """把 summary 截进字节预算(含省略号 3 字节;不截断半个多字节字符)。

    limit 最小有效值 4(再小连省略号都放不下),小于 4 按 4 处理。
    """
    limit = max(limit, 4)
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    truncated = encoded[: limit - 3].decode("utf-8", errors="ignore")
    return truncated.rstrip() + "…"


def _tool_name(command: str) -> str | None:
    """取命令行首个有效 token 的 basename;裸 sudo/doas/env 包装跳过一层。"""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not tokens:
        return None
    name = tokens[0]
    if name in _WRAPPER_COMMANDS and len(tokens) > 1:
        name = tokens[1]
    return name.rsplit("/", 1)[-1]


def maybe_parse(
    command: str,
    output_text: str,
    *,
    output_path: str | None = None,
    audit: AuditLog | None = None,
) -> ParsedOutput | None:
    """增强入口(相当于 dispatch):命中注册表就解析,任何失败静默回退 None。

    loop 接线示意(后续 WP 负责):``result = maybe_parse(cmd, output, ...)``;
    result 为 None 时走 WP-01 通用截断视图,否则把 summary 给 LLM、
    facts 经 :func:`apply_facts` 进索引。
    """
    tool = _tool_name(command)
    if tool is None:
        return None
    parser = PARSERS.get(tool)
    if parser is None:
        return None  # 注册表未命中:通用路径(不记审计——这是常态,不是异常)
    try:
        result = parser(command, output_text, output_path)
    except Exception as exc:  # 解析器永不为门槛:任何异常静默回退
        _audit_fallback(audit, tool, command, "exception", repr(exc))
        return None
    if result is None:
        _audit_fallback(audit, tool, command, "no_match", None)
        return None
    # 解析器是后续 WP 的扩展点:畸形返回形状同样走回退,绝不上抛
    if not isinstance(result, ParsedOutput) or not isinstance(result.summary, str):
        _audit_fallback(
            audit, tool, command, "exception",
            f"bad parser result type: {type(result).__name__}",
        )
        return None
    try:
        result.summary = cap_summary(result.summary)
    except Exception as exc:  # 孤代理字符等触发 UnicodeEncodeError
        _audit_fallback(audit, tool, command, "exception", repr(exc))
        return None
    return result


def _audit_fallback(
    audit: AuditLog | None, tool: str, command: str, reason: str, detail: str | None
) -> None:
    if audit is None:
        return
    payload: dict[str, Any] = {"tool": tool, "reason": reason, "command": command}
    if detail:
        payload["detail"] = detail
    audit.append(KIND_PARSE_FALLBACK, payload)


def apply_facts(index: Index, facts: list[dict[str, Any]]) -> dict[str, int]:
    """把 facts 喂进 WP-06 索引。畸形/未知 kind 跳过计数——增强永不为门槛。

    返回各表写入计数(含 skipped),供 loop 记 exec_result_meta 或调试。
    sqlite 约束错误(如必填字段为 None)与其余 DB 故障同样归 skipped:
    索引问题不该打断 loop,调用方可对 stats 与 Index.counts() 对账。
    """
    stats = {
        "hosts": 0, "ports": 0, "creds": 0, "vulns": 0, "loot": 0, "skipped": 0,
    }
    for fact in facts:
        if not isinstance(fact, dict):
            stats["skipped"] += 1
            continue
        kind = fact.get("kind")
        try:
            if kind == "host":
                index.upsert_host(fact["ip"], fact.get("hostname"))
                stats["hosts"] += 1
            elif kind == "port":
                index.upsert_port(
                    fact["host"],
                    int(fact["port"]),
                    fact.get("proto", "tcp"),
                    service=fact.get("service"),
                    product=fact.get("product"),
                    version=fact.get("version"),
                )
                stats["ports"] += 1
            elif kind == "cred":
                index.add_cred(
                    fact["host"],
                    fact["username"],
                    fact["secret"],
                    source=fact.get("source", "parse"),
                )
                stats["creds"] += 1
            elif kind == "vuln":
                index.add_vuln(
                    fact["host"],
                    fact.get("vkind", "finding"),
                    fact["title"],
                    evidence_path=fact.get("evidence_path"),
                    confidence=fact.get("confidence"),
                )
                stats["vulns"] += 1
            elif kind == "loot":
                index.add_loot(
                    fact["path"],
                    kind=fact.get("lkind"),
                    note=fact.get("note"),
                    size_bytes=fact.get("size_bytes"),
                )
                stats["loot"] += 1
            else:
                stats["skipped"] += 1
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            stats["skipped"] += 1
    return stats


# ================================================================ 工具函数

def _host_port_from_url(url: str) -> tuple[str | None, int | None]:
    """从 URL 取 (host, port);无显式端口按 scheme 默认。非法返回 (None, None)。"""
    try:
        parts = urlsplit(url if "://" in url else f"http://{url}")
        host = parts.hostname
        port = parts.port  # 惰性求值:非数字端口在这里才抛 ValueError
    except ValueError:
        return None, None
    if host is None:
        return None, None
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return host, port


def _target_host_from_command(command: str) -> str | None:
    """从命令行借 WP-02 提取器拿第一个目标的主机部分(供 nikto/hydra 等
    输出里不重复出现目标的工具确定 fact 归属 host)。"""
    try:
        targets = extract_targets(command)
    except ValueError:
        return None
    if not targets:
        return None
    first = targets[0]
    if "://" in first:
        host, _ = _host_port_from_url(first)
        return host
    return first


# ================================================================ nmap

_NMAP_REPORT_RE = re.compile(
    r"^Nmap scan report for (?P<name>\S+)(?: \((?P<ip>\S+)\))?$"
)
_NMAP_PORT_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp|sctp)\s+(?P<state>\S+)\s+(?P<service>\S+)(?:\s+(?P<version>.*))?$"
)


def _nmap_summary(hosts: list[dict], ports: list[dict]) -> str:
    per_host: dict[str, list[str]] = {}
    for p in ports:
        label = f"{p['port']}/{p.get('service') or '?'}"
        per_host.setdefault(p["host"], []).append(label)
    host_bits = []
    for h in hosts:
        open_ports = per_host.get(h["ip"], [])
        name = f"({h['hostname']})" if h.get("hostname") else ""
        joined = ", ".join(open_ports) if open_ports else "无开放端口"
        host_bits.append(f"{h['ip']}{name}: {joined}")
    return (
        f"nmap:{len(hosts)} 台存活,开放端口 {len(ports)} 个。"
        + " | ".join(host_bits)
    )


@register("nmap")
def parse_nmap(
    command: str, output_text: str, output_path: str | None = None
) -> ParsedOutput | None:
    """nmap:-oX XML 优先;容忍 grepable(-oG)与默认文本表格。"""
    text = output_text.lstrip()
    result = None
    if text.startswith(("<?xml", "<nmaprun")):
        try:
            result = _parse_nmap_xml(text)
        except ElementTree.ParseError:
            result = None  # 截断/损坏的 XML:落回文本路径再试一次
    if result is None:
        result = _parse_nmap_grepable(output_text) or _parse_nmap_table(output_text)
    return result


def _parse_nmap_xml(text: str) -> ParsedOutput | None:
    # noqa 说明:解析对象是本地执行的授权工具 stdout;规格限定只用标准库,
    # defusedxml 不可用;Python 3.12 捆绑的 expat 默认抑制实体放大攻击。
    root = ElementTree.fromstring(text)  # noqa: S314
    if root.tag != "nmaprun":
        return None
    facts: list[dict[str, Any]] = []
    hosts: list[dict] = []
    ports: list[dict] = []
    for host_el in root.iter("host"):
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue
        addr_el = host_el.find("address")
        if addr_el is None or not addr_el.get("addr"):
            continue
        ip = addr_el.get("addr")
        hostname_el = host_el.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None
        host_fact: dict[str, Any] = {"kind": "host", "ip": ip}
        if hostname:
            host_fact["hostname"] = hostname
        facts.append(host_fact)
        hosts.append({"ip": ip, "hostname": hostname})
        for port_el in host_el.iter("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            port_fact: dict[str, Any] = {
                "kind": "port",
                "host": ip,
                "port": int(port_el.get("portid")),
                "proto": port_el.get("protocol", "tcp"),
            }
            if service_el is not None:
                port_fact["service"] = service_el.get("name")
                port_fact["product"] = service_el.get("product")
                port_fact["version"] = service_el.get("version")
            facts.append(port_fact)
            ports.append(port_fact)
    if not hosts:
        return None
    return ParsedOutput("nmap", _nmap_summary(hosts, ports), facts)


_NMAP_G_HOST_RE = re.compile(r"^Host: (?P<ip>\S+)(?: \((?P<hn>[^)]*)\))?")
_NMAP_G_STATUS_UP_RE = re.compile(r"\tStatus: Up\s*$")


def _nmap_clean_service(name: str | None) -> str | None:
    """清洗 nmap 服务名修饰符:`ajp13?`(-sV 不确定)→ ajp13;
    `ssl|http`(SSL 隧道前缀)→ http——索引服务列只放可查询的裸名。"""
    if not name:
        return None
    if "|" in name:
        name = name.rsplit("|", 1)[-1]
    return name.rstrip("?") or None


def _parse_nmap_grepable(text: str) -> ParsedOutput | None:
    facts: list[dict[str, Any]] = []
    host_records: dict[str, dict[str, Any]] = {}  # ip → 回填用记录
    hosts: list[dict] = []
    ports: list[dict] = []

    def record_host(ip: str, hostname: str | None) -> None:
        rec = host_records.get(ip)
        if rec is None:
            fact: dict[str, Any] = {"kind": "host", "ip": ip}
            if hostname:
                fact["hostname"] = hostname
            summary_entry = {"ip": ip, "hostname": hostname}
            host_records[ip] = {"fact": fact, "summary": summary_entry}
            facts.append(fact)
            hosts.append(summary_entry)
        elif hostname and not rec["summary"].get("hostname"):
            # 真实 -oG:Status 行常无主机名,Ports 行才带 rDNS——回填
            rec["fact"]["hostname"] = hostname
            rec["summary"]["hostname"] = hostname

    for line in text.splitlines():
        if not line.startswith("Host: "):
            continue
        match = _NMAP_G_HOST_RE.match(line)
        if not match:
            continue
        ip = match.group("ip")
        hostname = match.group("hn") or None
        if "Ports:" not in line:
            # `Host: <ip> ()\tStatus: Up` 行:补录「存活但无开放端口」主机
            if _NMAP_G_STATUS_UP_RE.search(line):
                record_host(ip, hostname)
            continue
        record_host(ip, hostname)
        segments = line.split("\t")
        ports_seg = next((s for s in segments[1:] if s.startswith("Ports: ")), None)
        if ports_seg is None:
            continue
        for item in ports_seg[len("Ports: "):].split(","):
            fields = item.strip().split("/")
            if len(fields) < 5 or fields[1] != "open":
                continue
            # 段式:port/state/proto/owner/service/[version…];version 内
            # 可能含斜杠(不转义),把 service 之后的非空段 join 回 version
            tail = [seg for seg in fields[5:] if seg]
            port_fact = {
                "kind": "port",
                "host": ip,
                "port": int(fields[0]),
                "proto": fields[2] or "tcp",
                "service": _nmap_clean_service(fields[4]),
                "product": None,
                "version": "/".join(tail) or None,
            }
            facts.append(port_fact)
            ports.append(port_fact)
    if not hosts:
        return None
    return ParsedOutput("nmap", _nmap_summary(hosts, ports), facts)


def _parse_nmap_table(text: str) -> ParsedOutput | None:
    facts: list[dict[str, Any]] = []
    hosts: list[dict] = []
    ports: list[dict] = []
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        line = line.rstrip()
        report = _NMAP_REPORT_RE.match(line)
        if report:
            name, ip = report.group("name"), report.group("ip")
            if ip is None:
                ip, hostname = name, None  # 无括号形式:报告名即 IP(或仅主机名)
                if not re.fullmatch(r"[\d.]+", name):
                    ip, hostname = None, name
            else:
                hostname = name
            if ip is None:
                current = None  # 只有主机名的报告:host 归属不明,跳过其端口
                continue
            current = {"ip": ip, "hostname": hostname}
            fact: dict[str, Any] = {"kind": "host", "ip": ip}
            if hostname:
                fact["hostname"] = hostname
            facts.append(fact)
            hosts.append(current)
            continue
        port_match = _NMAP_PORT_RE.match(line.strip())
        if port_match and current is not None:
            if port_match.group("state") != "open":
                continue
            port_fact = {
                "kind": "port",
                "host": current["ip"],
                "port": int(port_match.group("port")),
                "proto": port_match.group("proto"),
                "service": _nmap_clean_service(port_match.group("service")),
                "product": None,
                "version": (port_match.group("version") or "").strip() or None,
            }
            facts.append(port_fact)
            ports.append(port_fact)
    if not hosts:
        return None
    return ParsedOutput("nmap", _nmap_summary(hosts, ports), facts)


# ================================================================ sqlmap

_SQLMAP_PARAM_RE = re.compile(r"^Parameter: (?P<param>.+?) \((?P<ptype>.+)\)$")
_SQLMAP_TITLE_RE = re.compile(r"^\s+Title: (?P<title>.+)$")
_SQLMAP_DBMS_RES = [
    re.compile(r"back-end DBMS(?: is)?: (?P<dbms>\S[^\n]*)", re.IGNORECASE),
    re.compile(r"the back-end DBMS is (?P<dbms>\S[^\n]*)", re.IGNORECASE),
]
_SQLMAP_OUTPUT_DIR_RE = re.compile(r"logged to text files under '(?P<dir>[^']+)'")

#: dump CSV 口令/用户名列名启发式(小写子串匹配);命中才提 cred,否则只登记 loot。
_SQLMAP_SECRET_COLS = ("pass", "pwd", "hash")
_SQLMAP_USER_COLS = ("user", "login")
_SQLMAP_MAX_CSV = 20
_SQLMAP_MAX_ROWS = 1000
_SQLMAP_MAX_CREDS_PER_CSV = 50


def _sqlmap_loot_facts(
    output_text: str, host: str | None
) -> tuple[list[dict[str, Any]], int]:
    """best-effort 扫 sqlmap output 目录下的 dump CSV:逐份登记 loot fact,
    列名像口令/用户的行提 cred fact(完整 secret 进索引,与 hydra 同红线)。

    任何 IO/格式问题只丢 loot 部分,绝不影响 stdout 主解析(增强非门槛)。
    返回 (facts, cred_count)。
    """
    match = _SQLMAP_OUTPUT_DIR_RE.search(output_text)
    if not match:
        return [], 0
    facts: list[dict[str, Any]] = []
    cred_count = 0
    try:
        root = Path(match.group("dir"))
        if not root.is_dir():
            return [], 0
        for csv_path in sorted(root.rglob("*.csv"))[:_SQLMAP_MAX_CSV]:
            try:
                size = csv_path.stat().st_size
                with csv_path.open(
                    newline="", encoding="utf-8", errors="replace"
                ) as fh:
                    rows = list(csv.reader(fh))[:_SQLMAP_MAX_ROWS]
            except (OSError, csv.Error):
                continue
            if not rows:
                continue
            header = [str(col).strip() for col in rows[0]]
            data = rows[1:]
            facts.append(
                {
                    "kind": "loot",
                    "path": str(csv_path),
                    "lkind": "sqlmap-dump",
                    "note": f"{csv_path.stem}:{len(data)} 行,列 {','.join(header[:6])}",
                    "size_bytes": size,
                }
            )
            if not host:
                continue
            lowered = [col.lower() for col in header]
            secret_idx = next(
                (i for i, c in enumerate(lowered)
                 if any(tag in c for tag in _SQLMAP_SECRET_COLS)),
                None,
            )
            user_idx = next(
                (i for i, c in enumerate(lowered)
                 if any(tag in c for tag in _SQLMAP_USER_COLS)),
                None,
            )
            if secret_idx is None or user_idx is None:
                continue
            per_csv = 0
            for row in data:
                if per_csv >= _SQLMAP_MAX_CREDS_PER_CSV:
                    break
                if max(secret_idx, user_idx) >= len(row):
                    continue
                username, secret = row[user_idx].strip(), row[secret_idx].strip()
                if not username or not secret:
                    continue
                facts.append(
                    {
                        "kind": "cred",
                        "host": host,
                        "username": username,
                        "secret": secret,
                        "source": "sqlmap-dump",
                    }
                )
                per_csv += 1
                cred_count += 1
    except OSError:
        return facts, cred_count
    return facts, cred_count


@register("sqlmap")
def parse_sqlmap(
    command: str, output_text: str, output_path: str | None = None
) -> ParsedOutput | None:
    """sqlmap:stdout 注入确认段(Parameter/Type/Title)+ DBMS 识别 + loot CSV。

    loot CSV 经 stdout 的 output 目录行定位,本地存在才扫(规格:stdout
    关键段 + loot CSV);目录不存在只丢 loot,注入确认不受影响。
    """
    host = _target_host_from_command(command)
    facts: list[dict[str, Any]] = []
    findings: list[str] = []
    current_param: str | None = None
    for line in output_text.splitlines():
        if line.startswith("Parameter:"):
            param_match = _SQLMAP_PARAM_RE.match(line)
            # 不匹配( exotic 形态)也要重置:宁可丢该条,也不把后续
            # Title 误归属到上一个参数(错误 facts 比丢失更糟)。
            current_param = None
            if param_match:
                current_param = (
                    f"{param_match.group('param')}({param_match.group('ptype')})"
                )
            continue
        title_match = _SQLMAP_TITLE_RE.match(line)
        if title_match and current_param:
            title = title_match.group("title").strip()
            findings.append(f"{current_param}:{title}")
            if host:
                facts.append(
                    {
                        "kind": "vuln",
                        "host": host,
                        "vkind": "sqli",
                        "title": f"SQL 注入 {current_param}:{title}",
                        "evidence_path": output_path,
                        "confidence": "confirmed",
                    }
                )
    dbms = None
    for dbms_re in _SQLMAP_DBMS_RES:
        match = dbms_re.search(output_text)
        if match:
            dbms = match.group("dbms").strip()
            break
    loot_facts, loot_cred_count = _sqlmap_loot_facts(output_text, host)
    facts.extend(loot_facts)
    loot_csv_count = sum(1 for f in loot_facts if f["kind"] == "loot")
    if not findings and not loot_facts:
        return None
    summary = f"sqlmap:确认 {len(findings)} 个注入点(目标 {host or '见命令行'})"
    if dbms:
        summary += f",后端 DBMS {dbms}"
    if findings:
        summary += ":" + ";".join(findings[:3])
        if len(findings) > 3:
            summary += f" 等 {len(findings)} 项"
    if loot_csv_count:
        summary += f";dump 已登记 {loot_csv_count} 个 CSV"
        if loot_cred_count:
            summary += f"(含 {loot_cred_count} 条凭据,完整值已入索引)"
    return ParsedOutput("sqlmap", summary, facts)


# ================================================================ gobuster

_GOBUSTER_RE = re.compile(
    r"^(?P<path>/\S*)\s+\(Status: (?P<status>\d{3})\)"
    r"(?:\s+\[Size: (?P<size>\d+)\])?(?:\s+\[--> (?P<redirect>\S+)\])?"
)
_GOBUSTER_INTERESTING = ("200", "301", "302", "401", "403")


@register("gobuster")
def parse_gobuster(
    command: str, output_text: str, output_path: str | None = None
) -> ParsedOutput | None:
    """gobuster 目录爆破:逐行 (Status: NNN);facts 为 endpoint(索引暂不收)。"""
    facts: list[dict[str, Any]] = []
    by_status: dict[str, int] = {}
    highlights: list[str] = []
    for line in output_text.splitlines():
        match = _GOBUSTER_RE.match(line.strip())
        if not match:
            continue
        status = match.group("status")
        path = match.group("path")
        fact: dict[str, Any] = {"kind": "endpoint", "path": path, "status": int(status)}
        if match.group("redirect"):
            fact["redirect"] = match.group("redirect")
        facts.append(fact)
        by_status[status] = by_status.get(status, 0) + 1
        if status in _GOBUSTER_INTERESTING and status != "403":
            highlights.append(f"{path}({status})")
    if not facts:
        return None
    dist = " ".join(f"{s}×{n}" for s, n in sorted(by_status.items()))
    summary = f"gobuster:命中 {len(facts)} 条路径({dist})"
    if highlights:
        summary += ";亮点:" + ", ".join(highlights[:6])
        if len(highlights) > 6:
            summary += f" 等 {len(highlights)} 条"
    return ParsedOutput("gobuster", summary, facts)


# ================================================================ nikto

_NIKTO_TARGET_IP_RE = re.compile(r"^\+\s+Target IP:\s+(?P<ip>\S+)")
_NIKTO_TARGET_HOSTNAME_RE = re.compile(r"^\+\s+Target Hostname:\s+(?P<hn>\S+)")
_NIKTO_TARGET_PORT_RE = re.compile(r"^\+\s+Target Port:\s+(?P<port>\d+)")
_NIKTO_SERVER_RE = re.compile(r"^\+\s+Server:\s+(?P<server>.+)$")
# 注意:skip 前缀必须带冒号精确到头行,宽泛的 "+ Target" 会把
# "+ Target Port:" 行一并吞掉,端口永远解析不出来。
_NIKTO_SKIP_PREFIXES = (
    "+ Start Time:",
    "+ End Time:",
    "+ SSL Info:",  # 证书元数据(Ciphers/Issuer 续行无 "+ " 前缀不会误中)
    "+-",
)
_NIKTO_STATS_RES = (
    re.compile(r"^\+\s+\d+ requests:"),
    re.compile(r"^\+\s+\d+ host\(s\)"),
)


@register("nikto")
def parse_nikto(
    command: str, output_text: str, output_path: str | None = None
) -> ParsedOutput | None:
    """nikto:Target IP 定 facts 归属(避免与 nmap 的 IP 行分裂成两台 host);
    Server 指纹进 port facts;findings 行进 vuln facts(统计/SSL 信息行剔除)。"""
    cli_host = _target_host_from_command(command)
    target_ip: str | None = None
    target_hostname: str | None = None
    port: int | None = None
    server: str | None = None
    findings: list[str] = []
    for line in output_text.splitlines():
        if any(line.startswith(p) for p in _NIKTO_SKIP_PREFIXES):
            continue
        ip_match = _NIKTO_TARGET_IP_RE.match(line)
        if ip_match:
            target_ip = ip_match.group("ip")
            continue
        hn_match = _NIKTO_TARGET_HOSTNAME_RE.match(line)
        if hn_match:
            target_hostname = hn_match.group("hn")
            continue
        port_match = _NIKTO_TARGET_PORT_RE.match(line)
        if port_match:
            port = int(port_match.group("port"))
            continue
        server_match = _NIKTO_SERVER_RE.match(line)
        if server_match:
            server = server_match.group("server").strip()
            continue
        if any(stats_re.match(line) for stats_re in _NIKTO_STATS_RES):
            continue  # 统计行(requests 汇总 / host(s) tested)
        if line.startswith("+ ") and line[2:].strip():
            findings.append(line[2:].strip())
    if server is None and not findings:
        return None
    # facts 归属:输出自带 Target IP 时以 IP 为准(与 nmap host 行合一);
    # 只有主机名时回退命令行目标。
    host = target_ip or cli_host
    facts: list[dict[str, Any]] = []
    if target_ip:
        host_fact: dict[str, Any] = {"kind": "host", "ip": target_ip}
        if target_hostname:
            host_fact["hostname"] = target_hostname
        facts.append(host_fact)
    if host and port and server:
        product, _, version = server.partition("/")
        facts.append(
            {
                "kind": "port",
                "host": host,
                "port": port,
                "proto": "tcp",
                "service": "http",
                "product": product,
                "version": version or None,
            }
        )
    for finding in findings:
        if host:
            facts.append(
                {
                    "kind": "vuln",
                    "host": host,
                    "vkind": "nikto",
                    "title": finding,
                    "evidence_path": output_path,
                    "confidence": "medium",
                }
            )
    display = target_hostname or cli_host or target_ip or "目标见命令行"
    summary = f"nikto:{display}"
    if server:
        summary += f" Server {server}"
    summary += f";{len(findings)} 项发现"
    if findings:
        summary += ":" + ";".join(findings[:2])
        if len(findings) > 2:
            summary += f" 等 {len(findings)} 项"
    return ParsedOutput("nikto", summary, facts)


# ================================================================ hydra

_HYDRA_RE = re.compile(
    r"^\[(?P<port>\d+)\]\[(?P<proto>[\w-]+)\] host: (?P<host>\S+)\s+"
    r"login: (?P<login>\S+)\s+password: (?P<password>.*)$"
)


@register("hydra")
def parse_hydra(
    command: str, output_text: str, output_path: str | None = None
) -> ParsedOutput | None:
    """hydra:有效凭据行进 cred facts(完整 secret 进索引);summary 掩码。"""
    facts: list[dict[str, Any]] = []
    masked_pairs: list[str] = []
    for line in output_text.splitlines():
        match = _HYDRA_RE.match(line.strip())
        if not match:
            continue
        password = match.group("password").strip()
        facts.append(
            {
                "kind": "cred",
                "host": match.group("host"),
                "username": match.group("login"),
                "secret": password,
                "source": "hydra",
            }
        )
        masked_pairs.append(f"{match.group('login')}/{mask_secret(password)}")
    if not facts:
        return None
    first = facts[0]
    summary = (
        f"hydra:{len(facts)} 组有效凭据({first['host']}):"
        + ", ".join(masked_pairs[:4])
        + "——完整值已入索引,报告可见"
    )
    if len(facts) > 4:
        summary += f" 等 {len(facts)} 组"
    return ParsedOutput("hydra", summary, facts)


# ================================================================ whatweb

_WHATWEB_LINE_RE = re.compile(r"^(?P<url>https?://\S+) \[(?P<status>\d{3})")


def _whatweb_plugin_values(line: str, name: str) -> list[str]:
    """抓 whatweb 行里某插件的全部 [值] 段(HTTPServer[Unix][Apache/2.4.49]
    这类多段写法 → ['Unix', 'Apache/2.4.49'])。"""
    match = re.search(re.escape(name) + r"((?:\[[^\]]*\])+)", line)
    if not match:
        return []
    return re.findall(r"\[([^\]]*)\]", match.group(1))


@register("whatweb")
def parse_whatweb(
    command: str, output_text: str, output_path: str | None = None
) -> ParsedOutput | None:
    """whatweb:单行汇总格式(URL [status] 插件[值]...);技术栈进 port facts。"""
    facts: list[dict[str, Any]] = []
    summaries: list[str] = []
    for line in output_text.splitlines():
        line_match = _WHATWEB_LINE_RE.match(line.strip())
        if not line_match:
            continue
        url = line_match.group("url")
        host, port = _host_port_from_url(url)
        if host is None:
            continue
        product = version = None
        server_segs = _whatweb_plugin_values(line, "HTTPServer")
        if server_segs:
            product, _, version = server_segs[-1].partition("/")
        else:
            apache = _whatweb_plugin_values(line, "Apache")
            if apache:
                product, version = "Apache", apache[0]
        php = _whatweb_plugin_values(line, "PHP")
        title = _whatweb_plugin_values(line, "Title")
        if port is not None and product:
            facts.append(
                {
                    "kind": "port",
                    "host": host,
                    "port": port,
                    "proto": "tcp",
                    "service": "http",
                    "product": product,
                    "version": version or None,
                }
            )
        bit = f"{url} → {line_match.group('status')}"
        if product:
            bit += f";{product} {version or ''}".rstrip()
        if php:
            bit += f" + PHP {php[0]}"
        if title:
            bit += f";标题《{title[0]}》"
        summaries.append(bit)
    if not summaries:
        return None
    summary = f"whatweb:{len(summaries)} 个站点 — " + " | ".join(summaries[:3])
    if len(summaries) > 3:
        summary += f" 等 {len(summaries)} 个"
    return ParsedOutput("whatweb", summary, facts)
