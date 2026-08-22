"""SQLite 自动索引层:渗透状态的结构化家(WP-06)。

六张表:hosts / ports / creds / vulns / loot / notes。文件为主、索引加速:
原始输出在 engagement 目录,本层只做可查询的关系索引;WP-07 解析器与
tools/state.py 的 LLM 工具都走这层统一的 upsert/查询接口。

设计要点:
- 标准库 sqlite3,无 ORM;DDL 幂等(CREATE TABLE IF NOT EXISTS)。
- upsert 语义:hosts 按 ip、ports 按 (host_id, port, proto)、creds 按
  (host_id, username, secret)、vulns 按 (host_id, kind, title) 去重,
  重复上报更新易变字段(service/product/version、source、confidence 等)。
- creds.secret 在本层**完整落盘**(供 WP-10 报告);给 LLM 的脱敏在
  tools/state.py 工具层做,本层不涉及——attack_surface 汇总只返回
  username/source,不带 secret。
- 通用 query(kind, filters) 的 filter 字段走表白名单 + 参数化查询,
  列名不拼接外部输入。
- 同步实现:所有操作是毫秒级小 IO;async 包装在 tools/state.py 的
  dispatch 薄壳(与 WP-01 _render_view 同模式)。
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

_DDL = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL UNIQUE,
    hostname TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    port INTEGER NOT NULL,
    proto TEXT NOT NULL DEFAULT 'tcp',
    service TEXT,
    product TEXT,
    version TEXT,
    UNIQUE (host_id, port, proto)
);
CREATE TABLE IF NOT EXISTS creds (
    id INTEGER PRIMARY KEY,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    username TEXT NOT NULL,
    secret TEXT NOT NULL,
    source TEXT,
    sensitive INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    UNIQUE (host_id, username, secret)
);
CREATE TABLE IF NOT EXISTS vulns (
    id INTEGER PRIMARY KEY,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    evidence_path TEXT,
    confidence TEXT,
    first_seen TEXT NOT NULL,
    UNIQUE (host_id, kind, title)
);
CREATE TABLE IF NOT EXISTS loot (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL UNIQUE,
    kind TEXT,
    note TEXT,
    size_bytes INTEGER,
    ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    text TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port);
CREATE INDEX IF NOT EXISTS idx_creds_host ON creds(host_id);
CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulns(host_id);
"""

#: query() 通用接口允许的 kind 及各自可过滤字段(白名单)。
QUERY_KINDS: dict[str, dict[str, Any]] = {
    "hosts": {"filters": {"ip", "hostname"}},
    "ports": {"filters": {"port", "proto", "service", "host_ip"}},
    "creds": {"filters": {"host_ip", "username", "source"}},
    "vulns": {"filters": {"host_ip", "kind", "confidence"}},
    "loot": {"filters": {"kind"}},
    "notes": {"filters": set()},
}

DEFAULT_QUERY_LIMIT = 50
MAX_QUERY_LIMIT = 500


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


class Index:
    """一个 engagement 一个实例:持有 index.sqlite 连接。"""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_DDL)
        self._conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES (?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Index:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ---------- upsert(解析器与工具共用) ----------

    def upsert_host(self, ip: str, hostname: str | None = None) -> int:
        """按 ip 去重;传入新 hostname 时覆盖旧的(以最新观测为准)。返回 host_id。"""
        now = _utc_now_iso()
        self._conn.execute(
            """
            INSERT INTO hosts(ip, hostname, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                hostname = COALESCE(excluded.hostname, hosts.hostname),
                last_seen = excluded.last_seen
            """,
            (ip, hostname, now, now),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT id FROM hosts WHERE ip = ?", (ip,)
        ).fetchone()
        return int(row["id"])

    def _host_id(self, host: int | str) -> int:
        """接受 host_id(int)或 ip(str,自动 upsert)。"""
        if isinstance(host, int):
            return host
        return self.upsert_host(host)

    def upsert_port(
        self,
        host: int | str,
        port: int,
        proto: str = "tcp",
        *,
        service: str | None = None,
        product: str | None = None,
        version: str | None = None,
    ) -> int:
        """按 (host, port, proto) 去重;非空新值覆盖旧的 service/product/version。"""
        host_id = self._host_id(host)
        self._conn.execute(
            """
            INSERT INTO ports(host_id, port, proto, service, product, version)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_id, port, proto) DO UPDATE SET
                service = COALESCE(excluded.service, ports.service),
                product = COALESCE(excluded.product, ports.product),
                version = COALESCE(excluded.version, ports.version)
            """,
            (host_id, port, proto, service, product, version),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT id FROM ports WHERE host_id = ? AND port = ? AND proto = ?",
            (host_id, port, proto),
        ).fetchone()
        return int(row["id"])

    def add_cred(
        self,
        host: int | str,
        username: str,
        secret: str,
        *,
        source: str | None = None,
        sensitive: bool = True,
    ) -> int:
        """按 (host, username, secret) 去重;重复上报更新 source/sensitive。"""
        host_id = self._host_id(host)
        self._conn.execute(
            """
            INSERT INTO creds(host_id, username, secret, source, sensitive, first_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_id, username, secret) DO UPDATE SET
                source = COALESCE(excluded.source, creds.source),
                sensitive = excluded.sensitive
            """,
            (host_id, username, secret, source, int(sensitive), _utc_now_iso()),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT id FROM creds WHERE host_id = ? AND username = ? AND secret = ?",
            (host_id, username, secret),
        ).fetchone()
        return int(row["id"])

    def add_vuln(
        self,
        host: int | str,
        kind: str,
        title: str,
        *,
        evidence_path: str | None = None,
        confidence: str | None = None,
    ) -> int:
        """按 (host, kind, title) 去重;重复上报更新 evidence/confidence。"""
        host_id = self._host_id(host)
        self._conn.execute(
            """
            INSERT INTO vulns(host_id, kind, title, evidence_path,
                              confidence, first_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_id, kind, title) DO UPDATE SET
                evidence_path = COALESCE(excluded.evidence_path, vulns.evidence_path),
                confidence = COALESCE(excluded.confidence, vulns.confidence)
            """,
            (host_id, kind, title, evidence_path, confidence, _utc_now_iso()),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT id FROM vulns WHERE host_id = ? AND kind = ? AND title = ?",
            (host_id, kind, title),
        ).fetchone()
        return int(row["id"])

    def add_loot(
        self,
        path: str,
        *,
        kind: str | None = None,
        note: str | None = None,
        size_bytes: int | None = None,
    ) -> int:
        """登记战利品文件(按 path 去重,重复登记更新 kind/note/size)。"""
        self._conn.execute(
            """
            INSERT INTO loot(path, kind, note, size_bytes, ts)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                kind = COALESCE(excluded.kind, loot.kind),
                note = COALESCE(excluded.note, loot.note),
                size_bytes = COALESCE(excluded.size_bytes, loot.size_bytes)
            """,
            (path, kind, note, size_bytes, _utc_now_iso()),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT id FROM loot WHERE path = ?", (path,)
        ).fetchone()
        return int(row["id"])

    def add_note(self, text: str, ts: str | None = None) -> int:
        """追加一条自由笔记(不去重,每次调用一行)。"""
        cursor = self._conn.execute(
            "INSERT INTO notes(ts, text) VALUES (?, ?)",
            (ts or _utc_now_iso(), text),
        )
        self._conn.commit()
        return int(cursor.lastrowid)

    # ---------- 关系查询 ----------

    def hosts_with_port(self, port: int, proto: str | None = None) -> list[dict]:
        """按端口反查 host:「哪些 host 开了 445」。"""
        if proto is None:
            rows = self._conn.execute(
                """
                SELECT h.ip, h.hostname, p.port, p.proto, p.service,
                       p.product, p.version
                FROM ports p JOIN hosts h ON h.id = p.host_id
                WHERE p.port = ?
                ORDER BY h.ip
                """,
                (port,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT h.ip, h.hostname, p.port, p.proto, p.service,
                       p.product, p.version
                FROM ports p JOIN hosts h ON h.id = p.host_id
                WHERE p.port = ? AND p.proto = ?
                ORDER BY h.ip
                """,
                (port, proto),
            ).fetchall()
        return _rows_to_dicts(rows)

    def attack_surface(self, host: int | str) -> dict[str, Any] | None:
        """按 host 汇总攻击面:开放端口 + 漏洞 + 凭据(username/source,**不含
        secret**——脱敏红线在索引层就守住,工具层与 WP-10 各取所需)。"""
        if isinstance(host, int):
            host_row = self._conn.execute(
                "SELECT * FROM hosts WHERE id = ?", (host,)
            ).fetchone()
        else:
            host_row = self._conn.execute(
                "SELECT * FROM hosts WHERE ip = ?", (host,)
            ).fetchone()
        if host_row is None:
            return None
        host_id = int(host_row["id"])
        ports = self._conn.execute(
            "SELECT port, proto, service, product, version FROM ports "
            "WHERE host_id = ? ORDER BY port",
            (host_id,),
        ).fetchall()
        vulns = self._conn.execute(
            "SELECT kind, title, evidence_path, confidence FROM vulns "
            "WHERE host_id = ? ORDER BY kind, title",
            (host_id,),
        ).fetchall()
        creds = self._conn.execute(
            "SELECT username, source, sensitive FROM creds WHERE host_id = ? "
            "ORDER BY username",
            (host_id,),
        ).fetchall()
        return {
            "host": dict(host_row),
            "ports": _rows_to_dicts(ports),
            "vulns": _rows_to_dicts(vulns),
            "creds": _rows_to_dicts(creds),
            "creds_count": len(creds),
        }

    # ---------- 通用查询(state_query 用) ----------

    def query(
        self,
        kind: str,
        filters: dict[str, Any] | None = None,
        *,
        limit: int = DEFAULT_QUERY_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        """通用查询入口。filter 字段表白名单,值参数化;返回
        {kind, count, total, truncated, rows}(count 为本页行数)。"""
        if kind not in QUERY_KINDS:
            raise ValueError(
                f"未知查询类别 {kind!r};可选:{sorted(QUERY_KINDS)}"
            )
        allowed = QUERY_KINDS[kind]["filters"]
        filters = dict(filters or {})
        unknown = set(filters) - allowed
        if unknown:
            raise ValueError(
                f"{kind} 不支持的过滤字段 {sorted(unknown)};可选:{sorted(allowed)}"
            )
        limit = max(1, min(int(limit), MAX_QUERY_LIMIT))
        offset = max(0, int(offset))

        # noqa 说明:from_clause/where/order_by 全部来自本模块白名单常量与
        # 内部构造,外部值一律经参数化绑定,S608 为字符串构造的静态误报。
        where, params = self._build_where(kind, filters)
        from_clause = self._from_clause(kind)
        total = self._conn.execute(
            f"SELECT COUNT(*) AS n FROM {from_clause} {where}",  # noqa: S608
            params,
        ).fetchone()["n"]
        rows = self._conn.execute(
            f"SELECT * FROM {from_clause} {where} "  # noqa: S608
            f"ORDER BY {self._order_by(kind)} LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        return {
            "kind": kind,
            "total": int(total),
            "count": len(rows),
            "truncated": offset + len(rows) < int(total),
            "rows": _rows_to_dicts(rows),
        }

    @staticmethod
    def _from_clause(kind: str) -> str:
        # ports/creds/vulns 预 join hosts,host_ip 过滤与展示都靠它
        if kind in ("ports", "creds", "vulns"):
            return f"{kind} t JOIN hosts h ON h.id = t.host_id"
        return f"{kind} t"

    @staticmethod
    def _build_where(kind: str, filters: dict[str, Any]) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for field_name, value in filters.items():
            column = "h.ip" if field_name == "host_ip" else f"t.{field_name}"
            clauses.append(f"{column} = ?")
            params.append(value)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, params

    @staticmethod
    def _order_by(kind: str) -> str:
        return {
            "hosts": "t.ip",
            "ports": "h.ip, t.port",
            "creds": "h.ip, t.username",
            "vulns": "h.ip, t.kind",
            "loot": "t.ts DESC",
            "notes": "t.ts DESC",
        }[kind]

    # ---------- 汇总(ENGAGEMENT.md / 报告用) ----------

    def counts(self) -> dict[str, int]:
        """各表行数,供 ENGAGEMENT.md 进展段与报告头部使用(表名均为上方白名单
        常量,故 f-string 构造安全)。"""
        result = {}
        for table in ("hosts", "ports", "creds", "vulns", "loot", "notes"):
            row = self._conn.execute(
                f"SELECT COUNT(*) AS n FROM {table}"  # noqa: S608
            ).fetchone()
            result[table] = int(row["n"])
        return result
