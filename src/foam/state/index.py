"""SQLite 自动索引层:渗透状态的结构化家(WP-06)。

六张表:hosts / ports / creds / vulns / loot / notes。文件为主、索引加速:
原始输出在 engagement 目录,本层只做可查询的关系索引;WP-07 解析器与
tools/state.py 的 LLM 工具都走这层统一的 upsert/查询接口。

设计要点:
- 标准库 sqlite3,无 ORM;DDL 幂等(CREATE TABLE IF NOT EXISTS)。
- upsert 语义:hosts 按 ip、ports 按 (host_id, port, proto)、creds 按
  (host_id, username, secret)、vulns 按 (host_id, kind, title) 去重,
  重复上报更新易变字段(service/product/version、source、confidence 等)。
- R08(schema v3):vulns/creds 增证据模型列(source/evidence_refs(JSON
  数组)/verification_status/observed_at/reproduction);add_vuln/add_cred
  改为单事务 read-modify-write(refs 并集追加不丢、verified 不被登记
  路径降级),返回 ``(id, created)``;验证状态枚举冻结:
  unknown(迁移默认)/unverified(登记默认)/verified(仅 R09 独立验证
  流程可置,登记路径拒绝)。
- creds.secret 在本层**完整落盘**(供 WP-10 报告);给 LLM 的脱敏在
  tools/state.py 工具层做,本层不涉及——attack_surface 汇总只返回
  username/source,不带 secret。
- 通用 query(kind, filters) 的 filter 字段走表白名单 + 参数化查询,
  列名不拼接外部输入。
- 同步实现:所有操作是毫秒级小 IO;async 包装在 tools/state.py 的
  dispatch 薄壳(与 WP-01 _render_view 同模式)。
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from foam.tools.bash import JobExitEvent

logger = logging.getLogger(__name__)

#: v2(R06):追加 job_events 表(后台 job 终态事件的持久消费记录)。
#: v3(R08):vulns/creds 证据模型补列(来源/证据引用/验证状态/观测时间/
#: 复现步骤)——新库走 _DDL 一次成型,旧库经 _MIGRATION_V3_COLUMNS 探测
#: 缺列后 ALTER 补齐(迁移前备份 index.sqlite.pre-v3.bak,失败回滚可重试)。
#: v4(R09):loot 增 sha256 登记时快照列(可空,旧行 NULL=unknown)——
#: 经 _MIGRATION_V4_COLUMNS 同机制迁移(备份 index.sqlite.pre-v4.bak)。
#: meta 版本号只升不降;旧程序显式列名 INSERT 对新库不受影响(新列可空
#: 或有常量默认)。
SCHEMA_VERSION = 4

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
    evidence_refs TEXT,
    verification_status TEXT NOT NULL DEFAULT 'unknown',
    observed_at TEXT,
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
    source TEXT,
    evidence_refs TEXT,
    verification_status TEXT NOT NULL DEFAULT 'unknown',
    observed_at TEXT,
    reproduction TEXT,
    UNIQUE (host_id, kind, title)
);
CREATE TABLE IF NOT EXISTS loot (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL UNIQUE,
    kind TEXT,
    note TEXT,
    size_bytes INTEGER,
    ts TEXT NOT NULL,
    sha256 TEXT
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    text TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port);
CREATE INDEX IF NOT EXISTS idx_creds_host ON creds(host_id);
CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulns(host_id);
-- R06(schema v2):后台 job 终态事件的持久消费记录。event_id 主键幂等;
-- status: consumed(已消费) / pending(drain 超时登记的未消费占位);
-- audit_seq 可空:NULL = 审计未落链(崩溃窗口),恢复重放据此补审计。
CREATE TABLE IF NOT EXISTS job_events (
    event_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    run_id TEXT,
    reason TEXT,
    status TEXT NOT NULL,
    exit_code INTEGER,
    duration_ms INTEGER,
    ended_at TEXT,
    command TEXT,
    output_refs TEXT,
    parse_tool TEXT,
    parse_stats TEXT,
    consumed_at TEXT,
    audit_seq INTEGER
);
"""

#: R08(schema v3):vulns/creds 证据模型补列。SQLite 限制:ALTER 新增
#: NOT NULL 列必须有常量默认——旧行由此迁移为 'unknown'(旧记录无从
#: 判断,不臆造,决策 2)。新库走 _DDL 一次成型,探测不到缺列不触发迁移。
_MIGRATION_V3_COLUMNS: dict[str, tuple[tuple[str, str], ...]] = {
    "vulns": (
        ("source", "TEXT"),
        ("evidence_refs", "TEXT"),
        ("verification_status", "TEXT NOT NULL DEFAULT 'unknown'"),
        ("observed_at", "TEXT"),
        ("reproduction", "TEXT"),
    ),
    "creds": (
        ("evidence_refs", "TEXT"),
        ("verification_status", "TEXT NOT NULL DEFAULT 'unknown'"),
        ("observed_at", "TEXT"),
    ),
}

#: v3 迁移前的一次性备份文件名后缀(存在不覆盖,保留最初升级前状态)。
PRE_V3_BACKUP_SUFFIX = ".pre-v3.bak"

#: R09(schema v4):loot 登记时快照补列(可空,旧行 NULL=登记时无快照,
#: 不臆造)。新库走 _DDL 一次成型,旧库探测缺列后 ALTER 补齐。
_MIGRATION_V4_COLUMNS: dict[str, tuple[tuple[str, str], ...]] = {
    "loot": (("sha256", "TEXT"),),
}

#: v4 迁移前的一次性备份文件名后缀(同 v3 语义:存在不覆盖)。
PRE_V4_BACKUP_SUFFIX = ".pre-v4.bak"

#: R08 决策 2:验证状态枚举冻结。unknown=旧记录无从判断(迁移默认);
#: unverified=已登记未独立验证(解析器/手工登记默认);verified=仅 R09
#: 独立验证流程可置——登记路径(add_vuln/add_cred/state_add_*/apply_facts)
#: 一律拒绝 verified,模型自述不升级。
VERIFICATION_STATES = frozenset({"unknown", "unverified", "verified"})

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


# ---------- R08:证据引用与验证状态的合并原子 ----------

def _normalize_refs(evidence_refs: Any) -> list[str] | None:
    """规范化证据引用列表:非空字符串、保序去重;空输入归 None(存 NULL)。"""
    if not evidence_refs:
        return None
    refs: list[str] = []
    for ref in evidence_refs:
        if not isinstance(ref, str) or not ref:
            raise ValueError("evidence_refs 元素须为非空字符串")
        if ref not in refs:
            refs.append(ref)
    return refs or None


def _dump_refs(refs: list[str] | None) -> str | None:
    return json.dumps(refs, ensure_ascii=False) if refs else None


def _merge_refs(existing: str | None, new: list[str] | None) -> list[str] | None:
    """既有 JSON 串与新列表的并集(既有顺序在前,追加不丢,决策 1)。"""
    merged: list[str] = []
    if existing:
        try:
            old_refs = json.loads(existing)
        except (json.JSONDecodeError, TypeError):
            old_refs = None
        if isinstance(old_refs, list):
            for ref in old_refs:
                if isinstance(ref, str) and ref and ref not in merged:
                    merged.append(ref)
        else:
            merged.append(existing)  # 非 JSON 旧值:原样保留不丢
    for ref in new or []:
        if ref not in merged:
            merged.append(ref)
    return merged or None


def _check_verification_status(value: str | None) -> None:
    """登记路径的验证状态闸门:枚举外与 verified 一律拒绝(决策 2)。"""
    if value is None:
        return
    if value not in VERIFICATION_STATES - {"verified"}:
        raise ValueError(
            f"登记路径不接受 verification_status={value!r}:可选 unknown/"
            "unverified;verified 仅独立验证流程(R09)可置,模型自述不升级"
        )


def _merge_verification_status(existing: str | None, new: str | None) -> str | None:
    """冲突合并:verified 不被登记路径降级;无新值保留原值。"""
    if existing == "verified":
        return "verified"
    return new if new is not None else existing


class Index:
    """一个 engagement 一个实例:持有 index.sqlite 连接。"""

    def __init__(self, db_path: str | Path, *, timeout: float = 5.0):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, timeout=timeout)
        self._tx_depth = 0  # R06:显式事务深度;>0 时 upsert 不各自 commit
        try:
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.executescript(_DDL)
            # R08(schema v3)/R09(schema v4):缺列探测 → 迁移前一次性备份 →
            # 单事务逐列 ALTER(executescript 会隐式提交先行事务,不能把它包
            # 进去;ALTER 序列本身用 _transaction 包裹)。失败回滚保留可读
            # 旧库,下次打开自动重试(AC06)。逐版本依序迁移:探测不到缺列
            # 的版本静默跳过(不备份不动)。
            for columns_map, backup_suffix in (
                (_MIGRATION_V3_COLUMNS, PRE_V3_BACKUP_SUFFIX),
                (_MIGRATION_V4_COLUMNS, PRE_V4_BACKUP_SUFFIX),
            ):
                missing = self._missing_columns(columns_map)
                if missing:
                    self._backup_pre_migration(backup_suffix)
                    with self._transaction():
                        self._apply_columns(missing)
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION)),
            )
            # 版本号只升不降(R06 沿用);UPDATE 在迁移提交之后——列已补齐、
            # 版本未升的半成品状态(如 meta commit 被拒)重开自愈:
            # 缺列探测为空则跳过迁移,版本号在这里补升。
            self._conn.execute(
                "UPDATE meta SET value = ? WHERE key = 'schema_version' "
                "AND CAST(value AS INTEGER) < ?",
                (str(SCHEMA_VERSION), SCHEMA_VERSION),
            )
            self._conn.commit()
            # R08(规格 §1):索引库含完整凭证,权限钉 0600(幂等,每次打开
            # 都钉)。chmod 失败只记 warning 不阻断——纵深加固不是可用性
            # 闸门:库是既有核心状态,阻断会锁死既有 engagement(与 R07
            # 转录「失败即失败」的差异理由见 R08.md §7 决策 9)。
            try:
                os.chmod(self.db_path, 0o600)
            except OSError as exc:
                logger.warning("索引库权限钉 0600 失败(不阻断打开):%s", exc)
        except BaseException:
            # R04:初始化被拒(如报告快照期间 DDL/元信息 commit 拿不到
            # EXCLUSIVE)时关闭连接——不留持 RESERVED 的僵尸连接阻塞后续
            # 写者。timeout 透传 sqlite3(默认 5.0 不变):busy 重试上界。
            self._conn.close()
            raise

    # ---------- R08/R09:schema 迁移(决策 3,v3/v4 同机制) ----------

    def _missing_columns(
        self, columns_map: dict[str, tuple[tuple[str, str], ...]]
    ) -> dict[str, list[tuple[str, str]]]:
        """探测缺列(PRAGMA table_info);返回 {表: [(列名, 声明)]}。"""
        missing: dict[str, list[tuple[str, str]]] = {}
        for table, columns in columns_map.items():
            existing = {
                row[1] for row in self._conn.execute(f"PRAGMA table_info({table})")
            }
            delta = [(name, decl) for name, decl in columns if name not in existing]
            if delta:
                missing[table] = delta
        return missing

    def _backup_pre_migration(self, suffix: str) -> Path:
        """迁移前一次性备份(已存在不覆盖),并打开快速读校验。

        校验失败(坏备份等于没备份)如实抛错中止迁移——原始库此时尚未
        被 ALTER 触碰,保持可读旧状态。评审收口:既有备份不「存在即
        信任」——早退路径同样过读校验(首次 copyfile 中途失败的截断
        备份会被拒绝)并补钉 0600(copyfile 后 chmod 前崩溃留 0644 的
        窗口,重开补正)。
        """
        backup = self.db_path.with_name(self.db_path.name + suffix)
        if not backup.exists():
            shutil.copyfile(self.db_path, backup)
        try:
            os.chmod(backup, 0o600)
        except OSError as exc:
            logger.warning("迁移备份权限钉 0600 失败(不阻断):%s", exc)
        check = sqlite3.connect(backup)
        try:
            row = check.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None:
                raise sqlite3.Error(f"迁移备份 {backup} 缺少 schema_version")
        finally:
            check.close()
        return backup

    def _apply_columns(self, missing: dict[str, list[tuple[str, str]]]) -> None:
        """逐列 ALTER ADD COLUMN(调用方须已包 ``_transaction``)。"""
        for table, columns in missing.items():
            for name, decl in columns:
                # noqa 说明:表名/列名/声明全部来自本模块常量
                # _MIGRATION_V*_COLUMNS,无外部输入拼接。
                self._conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {name} {decl}"  # noqa: S608
                )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Index:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ---------- R06:显式事务(consume_job_exit 用) ----------

    def _maybe_commit(self) -> None:
        """事务感知提交点:显式事务内不提交(由事务出口统一 COMMIT);
        事务外保持既有逐条 commit 语义,公开方法签名/语义不变。"""
        if self._tx_depth == 0:
            self._conn.commit()

    @contextmanager
    def _transaction(self) -> Iterator[Index]:
        """显式写事务(BEGIN IMMEDIATE … COMMIT/ROLLBACK)。

        事务内 upsert 经 ``_maybe_commit`` 不各自提交;busy(如报告快照
        持读锁期间 COMMIT 拿不到 EXCLUSIVE)如实上抛 sqlite3.Error 并
        ROLLBACK——调用方据此保持事件未消费,不静默丢。不支持嵌套。
        """
        if self._tx_depth > 0:
            raise RuntimeError("Index 写事务不支持嵌套")
        prior = self._conn.isolation_level
        self._conn.isolation_level = None  # 显式事务,关掉隐式 BEGIN
        self._tx_depth += 1
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self
            except BaseException:
                self._conn.rollback()
                raise
            else:
                try:
                    self._conn.commit()
                except BaseException:
                    # COMMIT 失败(如 busy 被读锁挡)不回滚会毒化连接:
                    # 滞留开事务,后续 BEGIN 报 cannot start a transaction
                    # within a transaction(2026-10-08 评审坐实,实测钉死)。
                    self._conn.rollback()
                    raise
        finally:
            self._tx_depth -= 1
            self._conn.isolation_level = prior

    @contextmanager
    def _write_tx(self) -> Iterator[None]:
        """事务感知的读-改-写包裹(R08):已在显式事务内(consume_job_exit)
        则并入外层事务(_transaction 不支持嵌套);否则开独立事务——
        add_vuln/add_cred 的 refs 并集合并需要原子读-改-写。"""
        if self._tx_depth > 0:
            yield
        else:
            with self._transaction():
                yield

    # ---------- R06:job 终态事件的幂等消费(决策 3/4) ----------

    @staticmethod
    def _job_event_refs(event: JobExitEvent) -> str:
        return json.dumps(
            {
                "output_path": event.output_path,
                "sha256": event.sha256,
                "stdout_path": event.stdout_path,
                "stdout_sha256": event.stdout_sha256,
                "stderr_path": event.stderr_path,
                "stderr_sha256": event.stderr_sha256,
                "total_bytes": event.total_bytes,
                "total_lines": event.total_lines,
            },
            ensure_ascii=False,
            sort_keys=True,
        )

    def consume_job_exit(
        self,
        event: JobExitEvent,
        facts: list[dict[str, Any]],
        *,
        parse_tool: str | None = None,
    ) -> tuple[str, dict[str, int] | None]:
        """幂等消费 job 终态事件:登记行与 facts 写入在同一事务提交。

        返回 ``(outcome, stats)``:

        - ``"consumed"``:首次消费(或补完 drain 登记的 pending 占位行),
          facts 已同事务应用,stats 为 apply_facts 计数;
        - ``"duplicate"``:重复投递(行已 consumed 且审计已回写),
          未动 facts,stats 为 None;
        - ``"replay_audit"``:行已 consumed 但 ``audit_seq`` NULL(崩溃
          窗口),未动 facts——调用方应补审计再 ``mark_job_event_audited``;
          补写产生同 event_id 的可辨识重复审计(规格 §7 允许)。

        busy(报告快照持锁期间)如实以 sqlite3.Error 上抛并 ROLLBACK:
        事件保持未消费,不静默丢。
        """
        from foam.tools.parse import apply_facts  # 延迟导入:避免 tools↔state 环

        refs = self._job_event_refs(event)
        with self._transaction():
            cursor = self._conn.execute(
                """
                INSERT OR IGNORE INTO job_events(
                    event_id, job_id, run_id, reason, status, exit_code,
                    duration_ms, ended_at, command, output_refs,
                    parse_tool, parse_stats, consumed_at, audit_seq
                ) VALUES (?, ?, ?, ?, 'consumed', ?, ?, ?, ?, ?, ?, NULL, ?, NULL)
                """,
                (
                    event.event_id,
                    event.job_id,
                    event.run_id,
                    event.reason,
                    event.exit_code,
                    event.duration_ms,
                    event.ended_at,
                    event.command,
                    refs,
                    parse_tool,
                    _utc_now_iso(),
                ),
            )
            if cursor.rowcount == 0:
                row = self._conn.execute(
                    "SELECT status, audit_seq FROM job_events WHERE event_id = ?",
                    (event.event_id,),
                ).fetchone()
                if row["status"] == "pending":
                    # drain 登记的占位行:补完正式消费(同事务 apply facts)
                    stats = apply_facts(self, facts)
                    self._conn.execute(
                        """
                        UPDATE job_events SET
                            status = 'consumed', reason = ?, exit_code = ?,
                            duration_ms = ?, ended_at = ?, command = ?,
                            output_refs = ?, parse_tool = ?, parse_stats = ?,
                            consumed_at = ?
                        WHERE event_id = ?
                        """,
                        (
                            event.reason,
                            event.exit_code,
                            event.duration_ms,
                            event.ended_at,
                            event.command,
                            refs,
                            parse_tool,
                            json.dumps(stats, sort_keys=True),
                            _utc_now_iso(),
                            event.event_id,
                        ),
                    )
                    return "consumed", stats
                return (
                    "replay_audit" if row["audit_seq"] is None else "duplicate"
                ), None
            stats = apply_facts(self, facts)
            self._conn.execute(
                "UPDATE job_events SET parse_stats = ? WHERE event_id = ?",
                (json.dumps(stats, sort_keys=True), event.event_id),
            )
            return "consumed", stats

    def register_job_exit_pending(self, event: JobExitEvent) -> bool:
        """登记未消费事件占位行(status='pending',AC06 明确登记)。

        已存在任意状态行时不动(返回 False);登记成功返回 True。
        busy/已关闭如实上抛,由调用方记入报告。
        """
        with self._transaction():
            cursor = self._conn.execute(
                """
                INSERT OR IGNORE INTO job_events(
                    event_id, job_id, run_id, reason, status, exit_code,
                    duration_ms, ended_at, command, output_refs,
                    parse_tool, parse_stats, consumed_at, audit_seq
                ) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL)
                """,
                (
                    event.event_id,
                    event.job_id,
                    event.run_id,
                    event.reason,
                    event.exit_code,
                    event.duration_ms,
                    event.ended_at,
                    event.command,
                    self._job_event_refs(event),
                ),
            )
            return cursor.rowcount == 1

    def mark_job_event_audited(self, event_id: str, audit_seq: int) -> None:
        """审计落链后回写 ``job_events.audit_seq``(独立小事务,决策 3c)。

        回写失败(崩溃/已关)时 audit_seq 保持 NULL——恢复重放补一条
        同 event_id 的可辨识重复审计(规格 §7 允许,不谎称恰好一次)。
        """
        self._conn.execute(
            "UPDATE job_events SET audit_seq = ? WHERE event_id = ?",
            (audit_seq, event_id),
        )
        self._conn.commit()

    def job_event(self, event_id: str) -> dict[str, Any] | None:
        """按 event_id 查消费记录(只读;报告/调试/测试对账用)。"""
        row = self._conn.execute(
            "SELECT * FROM job_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        return dict(row) if row is not None else None

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
        self._maybe_commit()
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
        self._maybe_commit()
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
        evidence_refs: list[str] | None = None,
        verification_status: str | None = None,
        observed_at: str | None = None,
    ) -> tuple[int, bool]:
        """按 (host, username, secret) 去重登记;返回 ``(cred_id, created)``。

        R08(决策 1/2):重复登记合并——source 取非空新值、sensitive 无条件
        覆盖(既有例外语义不变)、evidence_refs 并集追加不丢(单事务
        read-modify-write)、verification_status 不可经本路径降级(已有
        verified 保持);新行默认 verification_status='unverified'、
        observed_at=当前 UTC。登记路径拒绝 verified(决策 2)。
        """
        _check_verification_status(verification_status)
        host_id = self._host_id(host)
        refs = _normalize_refs(evidence_refs)
        with self._write_tx():
            row = self._conn.execute(
                "SELECT * FROM creds WHERE host_id = ? AND username = ? "
                "AND secret = ?",
                (host_id, username, secret),
            ).fetchone()
            if row is None:
                cursor = self._conn.execute(
                    """
                    INSERT INTO creds(host_id, username, secret, source,
                                      sensitive, first_seen, evidence_refs,
                                      verification_status, observed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        host_id, username, secret, source, int(sensitive),
                        _utc_now_iso(), _dump_refs(refs),
                        verification_status or "unverified",
                        observed_at or _utc_now_iso(),
                    ),
                )
                return int(cursor.lastrowid), True
            merged = _merge_refs(row["evidence_refs"], refs)
            self._conn.execute(
                """
                UPDATE creds SET
                    source = COALESCE(?, creds.source),
                    sensitive = ?,
                    evidence_refs = COALESCE(?, creds.evidence_refs),
                    verification_status = ?,
                    observed_at = COALESCE(?, creds.observed_at)
                WHERE id = ?
                """,
                (
                    source, int(sensitive), _dump_refs(merged),
                    _merge_verification_status(
                        row["verification_status"], verification_status
                    ),
                    observed_at, row["id"],
                ),
            )
            return int(row["id"]), False

    def add_vuln(
        self,
        host: int | str,
        kind: str,
        title: str,
        *,
        evidence_path: str | None = None,
        confidence: str | None = None,
        source: str | None = None,
        evidence_refs: list[str] | None = None,
        verification_status: str | None = None,
        observed_at: str | None = None,
        reproduction: str | None = None,
    ) -> tuple[int, bool]:
        """按 (host, kind, title) 去重登记;返回 ``(vuln_id, created)``。

        R08(决策 1/2/6):evidence_refs 为新证据模型列(JSON 数组);给了
        refs 而没给 legacy evidence_path 时回填首个 ref(报告旧渲染兼容)。
        重复登记合并:refs 并集追加不丢(单事务 read-modify-write),
        confidence/source/observed_at/reproduction 显式新值覆盖、None
        保留;verification_status 不可经本路径降级。登记路径拒绝
        verified(决策 2)。
        """
        _check_verification_status(verification_status)
        host_id = self._host_id(host)
        refs = _normalize_refs(evidence_refs)
        if refs and evidence_path is None:
            evidence_path = refs[0]  # legacy 列回填首个 ref(决策 6/7)
        with self._write_tx():
            row = self._conn.execute(
                "SELECT * FROM vulns WHERE host_id = ? AND kind = ? AND title = ?",
                (host_id, kind, title),
            ).fetchone()
            if row is None:
                cursor = self._conn.execute(
                    """
                    INSERT INTO vulns(host_id, kind, title, evidence_path,
                                      confidence, first_seen, source,
                                      evidence_refs, verification_status,
                                      observed_at, reproduction)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        host_id, kind, title, evidence_path, confidence,
                        _utc_now_iso(), source, _dump_refs(refs),
                        verification_status or "unverified",
                        observed_at or _utc_now_iso(), reproduction,
                    ),
                )
                return int(cursor.lastrowid), True
            merged = _merge_refs(row["evidence_refs"], refs)
            self._conn.execute(
                """
                UPDATE vulns SET
                    evidence_path = COALESCE(?, vulns.evidence_path),
                    confidence = COALESCE(?, vulns.confidence),
                    source = COALESCE(?, vulns.source),
                    evidence_refs = COALESCE(?, vulns.evidence_refs),
                    verification_status = ?,
                    observed_at = COALESCE(?, vulns.observed_at),
                    reproduction = COALESCE(?, vulns.reproduction)
                WHERE id = ?
                """,
                (
                    evidence_path, confidence, source, _dump_refs(merged),
                    _merge_verification_status(
                        row["verification_status"], verification_status
                    ),
                    observed_at, reproduction, row["id"],
                ),
            )
            return int(row["id"]), False

    def add_loot(
        self,
        path: str,
        *,
        kind: str | None = None,
        note: str | None = None,
        size_bytes: int | None = None,
        sha256: str | None = None,
    ) -> int:
        """登记战利品文件(按 path 去重,重复登记更新 kind/note/size)。

        R09(schema v4):``sha256`` 为登记时快照(与校验同一次打开算出,
        见 tools/state.py ``_resolve_contained_file_hashed``)。**首次登记
        快照不可覆盖**:重复登记时已有非空 sha256 保持不动(快照语义:
        登记时点的事实);旧行 sha256 为 NULL(v3 前登记,无快照)时允许
        填入首个真实快照——NULL 不是快照,不算覆盖。
        """
        self._conn.execute(
            """
            INSERT INTO loot(path, kind, note, size_bytes, ts, sha256)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                kind = COALESCE(excluded.kind, loot.kind),
                note = COALESCE(excluded.note, loot.note),
                size_bytes = COALESCE(excluded.size_bytes, loot.size_bytes),
                sha256 = COALESCE(loot.sha256, excluded.sha256)
            """,
            (path, kind, note, size_bytes, _utc_now_iso(), sha256),
        )
        self._maybe_commit()
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
        self._maybe_commit()
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
        # R04(D1):末尾 t.id 兜底——并列(同端口 tcp/udp、同用户不同 secret、
        # 同 kind 不同标题、秒级 ts 并列)时排序确定,分页跨页不重不漏;
        # 只影响并列行的相对顺序,输出字段与签名不变。
        return {
            "hosts": "t.ip, t.id",
            "ports": "h.ip, t.port, t.id",
            "creds": "h.ip, t.username, t.id",
            "vulns": "h.ip, t.kind, t.id",
            "loot": "t.ts DESC, t.id",
            "notes": "t.ts DESC, t.id",
        }[kind]

    # ---------- 汇总(ENGAGEMENT.md / 报告用) ----------

    @contextmanager
    def snapshot(self) -> Iterator[Index]:
        """同一连接上的显式只读事务(BEGIN … COMMIT/ROLLBACK):事务内全部
        query 看到同一个数据库快照(R04-AC04,报告分页用)。

        rollback-journal 模式下,快照期间并发写者的 COMMIT 拿不到
        EXCLUSIVE 锁:pysqlite 默认 timeout=5.0 的 busy 重试耗尽后以
        SQLITE_BUSY 明确失败(快照很短时,写者也可能只是被延迟到快照结束
        后才提交成功——两种结果下读者看到的都是同一快照,报告一致)。拒绝
        只发生在快照期间,快照结束后写入恢复。注意 Index.__init__ 的
        DDL/元信息写入发生在进入快照之前,不属于快照内容;快照期间新建
        Index 的初始化 commit 同样会被拒。新增接口,纯叠加不改既有方法语义。
        """
        prior = self._conn.isolation_level
        self._conn.isolation_level = None  # 显式事务,关掉隐式 BEGIN
        try:
            self._conn.execute("BEGIN")
            try:
                yield self
            except BaseException:
                self._conn.rollback()
                raise
            else:
                self._conn.commit()
        finally:
            self._conn.isolation_level = prior

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
