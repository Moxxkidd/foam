"""证据 manifest 与结项页(R09-A);只读核验(verify)在 R09-B 落地。

- **manifest / 结项页**(run 终态,``close_run`` 之后):``build_manifest``
  从纯读源(审计链文件 + ``mode=ro`` SQLite + engagement.json)构建
  **确定性**证据清单——同输入与固定 ``generated_at`` 逐字节一致(数组
  排序、JSON ``sort_keys``、``generated_at`` 由调用方注入);
  ``write_manifest`` 落盘 ``evidence/manifest-<run_id>.json``(机读)与
  ``evidence/summary-<run_id>.md``(结项页,同一 manifest dict 渲染),
  0600 原子写。无 run_finished(未终态/崩溃)返回 None——**不补造**。
- **只读核验**(``foam verify``,R09-B):``verify_engagement`` 对
  chain/files/references/coverage 四维独立判定
  pass/fail/unknown/pending;不开写连接、不取单写者锁、不创建/修改任何
  文件、不执行旧命令、不跟随目录外引用。

红线:本地哈希链仅供篡改检测;**截尾/整体重写不可检测**——一切输出
恒显示「未外部锚定」,不声称外部不可抵赖。
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from foam.agent.loop import KIND_RUN_FINISHED, KIND_RUN_STARTED
from foam.guard.audit import KIND_EXEC_RESULT_META, KIND_KILL_SWITCH
from foam.replay import chain_errors, read_records, session_coverage
from foam.state.files import EngagementPaths

#: manifest JSON 的格式版本(结构演进时递增)。
MANIFEST_FORMAT = 1

#: 外部锚定声明(一切输出恒显示;决策 1/9:本地链仅供篡改检测)。
EXTERNAL_ANCHOR = "none"
EXTERNAL_ANCHOR_NOTE = (
    "未外部锚定——本地哈希链仅供篡改检测,截尾/整体重写不可检测,"
    "不构成外部不可抵赖。"
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# 只读索引访问(verify 与 manifest 共用;绝不触发写/迁移/chmod)
# ---------------------------------------------------------------------------


def _open_index_ro(db_path: Path) -> sqlite3.Connection | None:
    """``mode=ro`` URI 只读连接:无 journal、无迁移、无 chmod。

    库缺失/无法只读打开返回 None——调用方按「该来源不可用」降级
    (unknown),不炸。连接后做一次 meta 探针读:崩溃残留热日志(-journal)
    在只读模式下无法回滚,首个读才报错,探针把这种形态一并归入「不可用」。
    """
    if not db_path.is_file():
        return None
    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(
            f"file:{quote(str(db_path))}?mode=ro", uri=True
        )
        conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    except sqlite3.Error:
        # 评审收口:探针失败路径同样关闭连接,不泄漏(connect 失败时
        # conn 尚不存在,条件守卫区分)
        if conn is not None:
            conn.close()
        return None
    conn.row_factory = sqlite3.Row
    return conn


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    """PRAGMA table_info 探测列面(ro 连接可用);表不存在返回空集。"""
    try:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return set()


def _query_dicts(
    conn: sqlite3.Connection, sql: str, params: tuple = ()
) -> list[dict[str, Any]]:
    rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# 记录口径路径归一(界内才消费;界外/不可归一 → None,不跟随)
# ---------------------------------------------------------------------------


def _relocate(root: Path, recorded: str) -> tuple[str, Path] | None:
    """把记录口径的路径归一为 ``(相对 root 的规范化串, 解析后绝对路径)``。

    记录口径有三种真实形态:绝对路径(生产主口径)、相对 root
    (``outputs/x.log``)、相对 root 父级且首段为 root 名(as-given 相对
    workdir 形态,如 ``eng/outputs/x.log``)。逐个候选 resolve 后必须仍
    在 root 内(符号链接逃逸在此被挡);全部不命中返回 None——调用方
    按「界外/不可定位」处理,绝不打开界外路径。
    """
    if not recorded:
        return None
    root_res = root.resolve()
    p = Path(recorded)
    candidates: list[Path] = []
    if p.is_absolute():
        candidates.append(p)
    else:
        candidates.append(root / p)
        if p.parts and p.parts[0] == root.name:
            candidates.append(root.parent / p)
    for cand in candidates:
        try:
            resolved = cand.resolve()
        except (OSError, RuntimeError):
            continue
        if resolved.is_relative_to(root_res):
            return str(resolved.relative_to(root_res)), resolved
    return None


# ---------------------------------------------------------------------------
# run 配对(manifest 绑定与 verify coverage 共用)
# ---------------------------------------------------------------------------


def _pair_runs(
    records: list[dict[str, Any]],
) -> list[tuple[dict[str, Any], dict[str, Any] | None]]:
    """run_started/run_finished 配对:优先按 run_id,legacy 缺 run_id 按序。

    返回 [(run_started, run_finished | None)] 按 run_started seq 升序;
    未配对(无 run_finished)的 run_finished=None。多 run 单链顺序执行
    (单写者锁),run_id 缺失仅出现在 pre-R06 旧链。
    """
    open_runs: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    pairs: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    for rec in records:
        kind = rec.get("kind")
        payload = rec.get("payload") or {}
        if kind == KIND_RUN_STARTED:
            rid = payload.get("run_id") or f"seq{rec.get('seq')}"
            open_runs[rid] = rec
            order.append(rid)
        elif kind == KIND_RUN_FINISHED:
            rid = payload.get("run_id")
            key: str | None = None
            if rid is not None and rid in open_runs:
                key = rid
            elif rid is None and order:
                key = order[-1]  # legacy 无 run_id:按序配最近一次 open
            if key is not None:
                pairs.append((open_runs.pop(key), rec))
                order.remove(key)
            else:
                pairs.append(({"seq": None, "payload": {}}, rec))  # 孤儿 finished
    for key in order:
        pairs.append((open_runs[key], None))
    pairs.sort(key=lambda pair: pair[0].get("seq") or 0)
    return pairs


def _run_id_of(record: dict[str, Any]) -> str | None:
    return (record.get("payload") or {}).get("run_id")


# ---------------------------------------------------------------------------
# manifest 构建
# ---------------------------------------------------------------------------


def _read_meta(paths: EngagementPaths) -> dict[str, Any]:
    try:
        return json.loads(paths.metadata.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _read_records_tolerant(paths: EngagementPaths) -> tuple[list[dict], str | None]:
    """读审计链;坏行让 read_records 抛 ValueError 时降级为空并注明。"""
    if not paths.audit_jsonl.is_file():
        return [], "audit.jsonl 缺失"
    try:
        return read_records(paths.audit_jsonl), None
    except ValueError as exc:
        return [], f"审计链解析失败:{exc}"


def _collect_artifacts(
    root: Path, records: list[dict[str, Any]], conn: sqlite3.Connection | None
) -> list[dict[str, Any]]:
    """汇总有记录的产物:链 exec_result_meta → job_events → loot → session
    转录目录扫描。同一路径多来源时合并(首个 recorded 来源为主,其余进
    ``also``);每项携 path/sha256/size/source/ref_id/hash_origin/present。
    """
    entries: dict[str, dict[str, Any]] = {}

    def add(
        recorded_path: str | None,
        sha256: str | None,
        source: str,
        ref_id: str,
        hash_origin: str,
    ) -> None:
        if not recorded_path:
            return
        located = _relocate(root, recorded_path)
        if located is None:
            # 界外/不可归一:不进产物清单(verify 的 references 维度另行
            # 报告界外引用;manifest 只盘点界内产物)
            return
        rel, abs_path = located
        present = abs_path.is_file()
        size: int | None = None
        if present:
            try:
                size = abs_path.stat().st_size
            except OSError:
                size = None
        entry = entries.get(rel)
        if entry is None:
            entries[rel] = {
                "path": rel,
                "sha256": sha256,
                "size": size,
                "source": source,
                "ref_id": ref_id,
                "hash_origin": hash_origin,
                "present": present,
                "also": [],
            }
            return
        # 合并:快照来源不顶掉记录来源;其余来源留痕
        note = f"{source}:{ref_id}"
        if (
            entry["hash_origin"] == "manifest_snapshot"
            and hash_origin != "manifest_snapshot"
        ):
            entry["also"].append(f"{entry['source']}:{entry['ref_id']}")
            entry.update(
                {"source": source, "ref_id": ref_id, "hash_origin": hash_origin}
            )
            if sha256:
                entry["sha256"] = sha256
        if note not in entry["also"]:
            entry["also"].append(note)

    for rec in records:
        if rec.get("kind") != KIND_EXEC_RESULT_META:
            continue
        payload = rec.get("payload") or {}
        if payload.get("output_path") and payload.get("sha256"):
            add(
                payload["output_path"],
                payload["sha256"],
                "exec_result_meta",
                f"audit seq {rec.get('seq')}",
                "recorded",
            )

    if conn is not None and "output_refs" in _table_columns(conn, "job_events"):
        for row in _query_dicts(
            conn, "SELECT event_id, output_refs FROM job_events ORDER BY event_id"
        ):
            try:
                refs = json.loads(row["output_refs"] or "{}")
            except json.JSONDecodeError:
                refs = {}
            for path_key, sha_key in (
                ("output_path", "sha256"),
                ("stdout_path", "stdout_sha256"),
                ("stderr_path", "stderr_sha256"),
            ):
                if refs.get(path_key):
                    add(
                        refs[path_key],
                        refs.get(sha_key),
                        "job_events",
                        str(row["event_id"]),
                        "recorded" if refs.get(sha_key) else "none",
                    )

    if conn is not None and _table_columns(conn, "loot"):
        loot_has_hash = "sha256" in _table_columns(conn, "loot")
        for row in _query_dicts(conn, "SELECT * FROM loot ORDER BY path"):
            registered = row.get("sha256") if loot_has_hash else None
            add(
                row.get("path"),
                registered,
                "loot",
                f"loot/{row.get('id')}",
                "recorded" if registered else "none",
            )

    # session 转录:无登记 hash(已知缺口)——manifest 时点快照,如实标注
    sessions_dir = root / "outputs" / "sessions"
    if sessions_dir.is_dir():
        for path in sorted(sessions_dir.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            rel = str(path.relative_to(root))
            if rel in entries:
                continue  # 已有记录来源(loot 登记等),快照不顶位
            try:
                digest = _sha256_file(path)
            except OSError:
                digest = None
            add(rel, digest, "session_transcript", rel, "manifest_snapshot")

    return [entries[key] for key in sorted(entries)]


def _loot_snapshots(
    root: Path, conn: sqlite3.Connection | None
) -> list[dict[str, Any]]:
    """loot 登记快照 vs manifest 时点现值,分列对照。"""
    if conn is None or not _table_columns(conn, "loot"):
        return []
    has_hash = "sha256" in _table_columns(conn, "loot")
    snapshots = []
    for row in _query_dicts(conn, "SELECT * FROM loot ORDER BY path"):
        registered = row.get("sha256") if has_hash else None
        located = _relocate(root, row.get("path") or "")
        present = False
        current_sha: str | None = None
        current_size: int | None = None
        if located is not None:
            _rel, abs_path = located
            if abs_path.is_file():
                present = True
                try:
                    current_sha = _sha256_file(abs_path)
                    current_size = abs_path.stat().st_size
                except OSError:
                    present = False
        if not present:
            status = "missing"
        elif registered is None:
            status = "no_registered_hash"
        elif registered == current_sha:
            status = "match"
        else:
            status = "diverged"
        snapshots.append(
            {
                "path": row.get("path"),
                "registered_sha256": registered,
                "registered_size": row.get("size_bytes"),
                "registered_ts": row.get("ts"),
                "current_sha256": current_sha,
                "current_size": current_size,
                "status": status,
            }
        )
    return snapshots


def _evidence_refs_section(conn: sqlite3.Connection | None) -> list[dict[str, Any]]:
    """vulns/creds 的 evidence_refs 汇总清单(ref → 来源行)。"""
    if conn is None:
        return []
    refs: dict[str, set[str]] = {}
    for table in ("vulns", "creds"):
        if "evidence_refs" not in _table_columns(conn, table):
            continue
        for row in _query_dicts(
            conn,
            f"SELECT id, evidence_refs FROM {table} "  # noqa: S608  # 表名为本模块常量
            "WHERE evidence_refs IS NOT NULL ORDER BY id",
        ):
            try:
                decoded = json.loads(row["evidence_refs"])
            except (json.JSONDecodeError, TypeError):
                decoded = None
            items = decoded if isinstance(decoded, list) else [row["evidence_refs"]]
            for ref in items:
                if isinstance(ref, str) and ref:
                    refs.setdefault(ref, set()).add(f"{table}/{row['id']}")
    return [
        {"ref": ref, "sources": sorted(refs[ref])} for ref in sorted(refs)
    ]


def build_manifest(
    root: str | Path, *, generated_at: str | None = None
) -> dict[str, Any] | None:
    """构建 run 终态证据 manifest(确定性;无 run_finished 返回 None)。

    绑定:终末 run(链上最后一条 run_finished)的 run_id 与结束原因、
    scope 修订与哈希、链头。产物清单盘点全 engagement(job_events 全部行
    + 链 exec_result_meta + loot 行 + session 转录目录扫描)。只读数据源,
    不写不改被检查目录。
    """
    root = Path(root)
    paths = EngagementPaths(root)
    generated_at = generated_at or _utc_now_iso()
    meta = _read_meta(paths)
    records, read_error = _read_records_tolerant(paths)
    problems = chain_errors(paths.audit_jsonl)

    pairs = _pair_runs(records)
    terminal = next(
        (pair for pair in reversed(pairs) if pair[1] is not None), None
    )
    if terminal is None:
        return None  # 无终态不补造(崩溃/未终态由 verify 显示 unknown/pending)
    started, finished = terminal
    finished_payload = finished.get("payload") or {}
    run_id = (
        finished_payload.get("run_id")
        or _run_id_of(started)
        or f"legacy-seq{finished.get('seq')}"
    )
    kill_reason = None
    if finished_payload.get("status") == "killed":
        start_seq = started.get("seq") or 0
        end_seq = finished.get("seq") or 0
        kill_reason = next(
            (
                (rec.get("payload") or {}).get("reason")
                for rec in reversed(records)
                if rec.get("kind") == KIND_KILL_SWITCH
                and start_seq < (rec.get("seq") or 0) < end_seq
            ),
            None,
        )

    conn = _open_index_ro(paths.index_db)
    try:
        artifacts = _collect_artifacts(root, records, conn)
        loot_snapshots = _loot_snapshots(root, conn)
        evidence_refs = _evidence_refs_section(conn)
        pending_jobs = 0
        if conn is not None and _table_columns(conn, "job_events"):
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM job_events WHERE status = 'pending'"
            ).fetchone()
            pending_jobs = int(row["n"])
    finally:
        if conn is not None:
            conn.close()

    scope_meta = meta.get("scope") or {}
    chain: dict[str, Any] = {
        "records": len(records),
        "head_seq": records[-1].get("seq") if records else 0,
        "head_hash": records[-1].get("hash") if records else None,
        "verify": not problems,
    }
    if read_error is not None:
        chain["read_error"] = read_error
    return {
        "format": MANIFEST_FORMAT,
        "engagement_id": meta.get("id") or root.name,
        "run_id": run_id,
        "end_reason": {
            "status": finished_payload.get("status"),
            "error": finished_payload.get("error"),
            "kill_reason": kill_reason,
        },
        "generated_at": generated_at,
        "scope": {
            "path": scope_meta.get("path"),
            "sha256": scope_meta.get("sha256"),
            "revision": meta.get("revision"),
        }
        if scope_meta or meta.get("revision")
        else None,
        "chain": chain,
        "artifacts": artifacts,
        "loot_snapshots": loot_snapshots,
        "evidence_refs": evidence_refs,
        "pending": {
            "job_events": pending_jobs,
            "unpaired_runs": [
                _run_id_of(started) or f"seq{started.get('seq')}"
                for started, fin in pairs
                if fin is None and started.get("seq") is not None
            ],
        },
        "external_anchor": EXTERNAL_ANCHOR,
    }


# ---------------------------------------------------------------------------
# 结项页(同一 manifest dict 的确定性人读渲染)
# ---------------------------------------------------------------------------


def _short(value: Any, head: int = 12) -> str:
    text = str(value) if value else "(无)"
    return text if len(text) <= head else text[:head] + "…"


def render_summary_md(manifest: dict[str, Any]) -> str:
    """把 manifest dict 渲染为结项页 markdown(确定性:只依赖输入 dict)。"""
    end = manifest["end_reason"]
    error_note = f"(error:{end['error']})" if end.get("error") else ""
    lines = [
        f"# 结项证据摘要:{manifest['engagement_id']}(run {manifest['run_id']})",
        "",
        f"- 生成时间:{manifest['generated_at']}",
        f"- 终态:{end.get('status')}{error_note}",
    ]
    if end.get("kill_reason"):
        lines.append(f"- kill 理由:{end['kill_reason']}")
    lines.append(f"- 外部锚定:{EXTERNAL_ANCHOR_NOTE}")
    lines.append("")

    lines += ["## 范围(scope)", ""]
    scope = manifest.get("scope")
    if scope:
        lines.append(f"- 文件:{scope.get('path')}")
        lines.append(f"- 内容 sha256:{scope.get('sha256')}")
        revision = scope.get("revision")
        if revision:
            lines.append(
                f"- 修订标记:seq {revision.get('seq')} / "
                f"hash {_short(revision.get('hash'))}"
            )
        else:
            lines.append("- 修订标记:无(legacy 或未提交)")
    else:
        lines.append("(无 scope 记录)")
    lines.append("")

    chain = manifest["chain"]
    lines += ["## 审计链", ""]
    lines.append(
        f"- 记录数:{chain['records']}(头 seq {chain['head_seq']},"
        f"hash {_short(chain.get('head_hash'))})"
    )
    lines.append(f"- 完整性:{'通过' if chain.get('verify') else '**未通过**'}")
    if chain.get("read_error"):
        lines.append(f"- 读取异常:{chain['read_error']}")
    lines.append("")

    artifacts = manifest["artifacts"]
    lines += [f"## 产物清单({len(artifacts)} 项)", ""]
    if not artifacts:
        lines.append("(无记录产物)")
    for item in artifacts:
        present = "" if item.get("present") else "(盘上缺失)"
        snapshot = (
            "(manifest 时点快照)"
            if item["hash_origin"] == "manifest_snapshot"
            else ""
        )
        lines.append(
            f"- `{item['path']}` sha256:{_short(item.get('sha256'))}"
            f"({item.get('size') if item.get('size') is not None else '?'} 字节,"
            f"{item['source']} {item['ref_id']}){present}{snapshot}"
        )
    lines.append("")

    lines += [f"## loot 快照对照({len(manifest['loot_snapshots'])} 项)", ""]
    if not manifest["loot_snapshots"]:
        lines.append("(无 loot 登记)")
    status_label = {
        "match": "一致",
        "diverged": "**分叉**",
        "missing": "**缺失**",
        "no_registered_hash": "无登记快照",
    }
    for snap in manifest["loot_snapshots"]:
        lines.append(
            f"- `{snap['path']}` 登记 {_short(snap.get('registered_sha256'))}"
            f"({snap.get('registered_size')} 字节 @ {snap.get('registered_ts')})"
            f" ↔ 现值 {_short(snap.get('current_sha256'))}"
            f"({snap.get('current_size')} 字节):"
            f"{status_label.get(snap['status'], snap['status'])}"
        )
    lines.append("")

    refs = manifest["evidence_refs"]
    lines += [f"## 证据引用({len(refs)} 条)", ""]
    if not refs:
        lines.append("(无证据引用登记)")
    for item in refs:
        lines.append(f"- `{item['ref']}`(来源:{', '.join(item['sources'])})")
    lines.append("")

    pending = manifest["pending"]
    lines += ["## 未收口项(pending)", ""]
    lines.append(f"- job_events 未消费占位:{pending['job_events']} 条")
    if pending["unpaired_runs"]:
        lines.append("- 未配对 run_started:" + ", ".join(pending["unpaired_runs"]))
    else:
        lines.append("- 未配对 run_started:无")
    lines.append("")

    lines += ["## 外部锚定声明", "", EXTERNAL_ANCHOR_NOTE, ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 落盘(0600 原子写;run 终态由 CLI/TUI 在 close_run 之后调用)
# ---------------------------------------------------------------------------


def _atomic_write_secret(path: Path, text: str) -> None:
    """0600 原子写:同目录 mkstemp(默认 0600)+ os.replace;失败清理临时
    文件,已有目标逐字节不动(与 cli._atomic_write_report 同形态)。"""
    import os
    import tempfile

    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=path.name + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def write_manifest(
    root: str | Path, *, generated_at: str | None = None
) -> tuple[Path, Path, dict[str, Any]] | None:
    """构建并落盘 manifest + 结项页(0600);无 run_finished 返回 None。

    返回 ``(manifest_json 路径, summary_md 路径, manifest dict)``——调用方
    (CLI/TUI 终态接线)用返回的 dict 打印摘要要点,不二次构建。同输入与
    固定 ``generated_at`` 重写逐字节一致(幂等覆盖)。
    """
    manifest = build_manifest(root, generated_at=generated_at)
    if manifest is None:
        return None
    run_id = _SAFE_NAME_RE.sub("-", str(manifest["run_id"]))
    evidence_dir = EngagementPaths(Path(root)).evidence
    evidence_dir.mkdir(exist_ok=True)
    json_path = evidence_dir / f"manifest-{run_id}.json"
    md_path = evidence_dir / f"summary-{run_id}.md"
    text = json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    _atomic_write_secret(json_path, text)
    _atomic_write_secret(md_path, render_summary_md(manifest))
    return json_path, md_path, manifest



# ---------------------------------------------------------------------------
# 只读核验(``foam verify``;R09-B)
# ---------------------------------------------------------------------------

#: 维度状态词表(决策 1):pass/fail/unknown/pending。
STATUSES = frozenset({"pass", "fail", "unknown", "pending"})
#: 维度名固定四键(AC05:各自独立判定)。
DIMENSIONS = ("chain", "files", "references", "coverage")

#: findings 人读渲染的状态符号。
_STATUS_MARK = {"pass": "✓", "fail": "✗", "unknown": "?", "pending": "…"}


@dataclass(frozen=True)
class Finding:
    """一条定位明细:状态 + 定位对象(路径/引用/记录)+ 说明。"""

    status: str
    subject: str
    detail: str


@dataclass
class DimensionResult:
    """一个维度的判定:总状态 + 一句话摘要 + 定位明细 + 机读附加数据。"""

    status: str = "pass"
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class VerifyResult:
    """verify 的四维结果与总判定;人读渲染与 JSON 渲染共用同一对象(AC07)。"""

    root: str
    engagement_id: str | None
    generated_at: str
    dimensions: dict[str, DimensionResult]
    overall: str  # pass/fail/unknown/pending(fail > pending > unknown > pass)


def _worst(dimensions: dict[str, DimensionResult]) -> str:
    """总判定:任一 fail → fail;否则任一 pending → pending;否则任一
    unknown → unknown;全 pass 才 pass(决策 1:fail 优先于 unknown)。"""
    statuses = {dim.status for dim in dimensions.values()}
    for status in ("fail", "pending", "unknown"):
        if status in statuses:
            return status
    return "pass"


def _decode_refs(raw: Any) -> list[str]:
    """evidence_refs 列(JSON 数组串)解码;空值归 [],坏值原样单条保留
    (不丢不臆造——与 replay._decode_evidence_refs 同语义;两处各自实现,
    口径变更须同步)。"""
    if not raw:
        return []
    try:
        refs = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return [str(raw)]
    if not isinstance(refs, list):
        return [str(raw)]
    return [str(ref) for ref in refs]


def _verify_chain(paths: EngagementPaths) -> tuple[DimensionResult, list[dict]]:
    """chain 维:哈希链完整性 + 断点定位;返回 (维度结果, 记录列表)。"""
    dim = DimensionResult()
    if not paths.audit_jsonl.is_file():
        dim.status = "fail"
        dim.summary = "audit.jsonl 缺失"
        dim.findings.append(
            Finding("fail", "audit.jsonl", "审计链文件缺失(engagement 必有)")
        )
        return dim, []
    problems = chain_errors(paths.audit_jsonl)
    records, read_error = _read_records_tolerant(paths)
    if problems:
        dim.status = "fail"
        dim.summary = f"审计链校验未通过({len(problems)} 处)"
        for problem in problems:
            dim.findings.append(Finding("fail", "audit.jsonl", problem))
        return dim, records
    dim.status = "pass"
    head = records[-1] if records else {}
    dim.summary = (
        f"审计链完整({len(records)} 条记录,头 hash {_short(head.get('hash'))})"
    )
    dim.extra = {
        "records": len(records),
        "head_seq": head.get("seq"),
        "head_hash": head.get("hash"),
    }
    if read_error is not None:
        dim.findings.append(Finding("unknown", "audit.jsonl", read_error))
    return dim, records


def _verify_files(
    root: Path,
    records: list[dict[str, Any]],
    conn: sqlite3.Connection | None,
    open_runs: list[tuple[int, str | None]],
) -> DimensionResult:
    """files 维:有记录产物逐一重算 sha256 对照;删除/篡改分别定位。

    - 无登记 hash(旧 loot 行 NULL 等)→ unknown;
    - 未终态 run(链尾 run_started 无配对)期间记录的产物 → pending;
    - 盘上存在但无任何记录(outputs//loot/ 扫描)→ unknown(不 fail);
    - 界外/不可归一记录 → unknown,不打开不跟随(不判罚)。
    """
    dim = DimensionResult()
    findings: list[Finding] = []
    # rel → [(source, ref_id, recorded_sha256, in_open_run)]
    recorded: dict[str, list[tuple[str, str, str | None, bool]]] = {}
    open_since = min((seq for seq, _rid in open_runs), default=None)
    open_run_ids = {rid for _seq, rid in open_runs if rid}

    def add(
        recorded_path: str | None,
        sha256: str | None,
        source: str,
        ref_id: str,
        in_open_run: bool,
    ) -> None:
        if not recorded_path:
            return
        located = _relocate(root, recorded_path)
        if located is None:
            findings.append(
                Finding(
                    "unknown",
                    recorded_path,
                    f"{source} {ref_id} 记录的路径在 engagement 界外/不可归一,"
                    "不跟随不判罚",
                )
            )
            return
        rel, _abs = located
        recorded.setdefault(rel, []).append(
            (source, ref_id, sha256, in_open_run)
        )

    job_event_rows: list[dict[str, Any]] = []
    terminal_job_ids: set[str] = set()
    if conn is not None and _table_columns(conn, "job_events"):
        job_event_rows = _query_dicts(
            conn,
            "SELECT event_id, job_id, run_id, status, output_refs FROM job_events "
            "ORDER BY event_id",
        )
        terminal_job_ids = {str(row["job_id"]) for row in job_event_rows}

    for rec in records:
        if rec.get("kind") != KIND_EXEC_RESULT_META:
            continue
        payload = rec.get("payload") or {}
        if (
            payload.get("status") == "running"
            and payload.get("job_id") in terminal_job_ids
        ):
            continue
        seq = rec.get("seq") or 0
        add(
            payload.get("output_path"),
            payload.get("sha256"),
            "exec_result_meta",
            f"audit seq {seq}",
            open_since is not None and seq >= open_since,
        )

    for row in job_event_rows:
        try:
            refs = json.loads(row["output_refs"] or "{}")
        except json.JSONDecodeError:
            refs = {}
        in_open = bool(row.get("run_id")) and row["run_id"] in open_run_ids
        for path_key, sha_key in (
            ("output_path", "sha256"),
            ("stdout_path", "stdout_sha256"),
            ("stderr_path", "stderr_sha256"),
        ):
            if refs.get(path_key):
                add(
                    refs[path_key],
                    refs.get(sha_key),
                    "job_events",
                    str(row["event_id"]),
                    in_open,
                )

    if conn is None:
        findings.append(
            Finding(
                "unknown",
                "index.sqlite",
                "索引库缺失/无法只读打开,loot 登记快照无从核验",
            )
        )
    elif not _table_columns(conn, "loot"):
        findings.append(
            Finding("unknown", "loot", "索引库缺 loot 表(legacy),无法核验")
        )
    else:
        loot_has_hash = "sha256" in _table_columns(conn, "loot")
        if not loot_has_hash:
            findings.append(
                Finding(
                    "unknown",
                    "loot.sha256",
                    "索引库 schema 低于 v4(legacy),loot 无登记快照列",
                )
            )
        for row in _query_dicts(conn, "SELECT * FROM loot ORDER BY path"):
            registered = row.get("sha256") if loot_has_hash else None
            add(row.get("path"), registered, "loot", f"loot/{row.get('id')}", False)

    # manifest 里记录的产物(时点快照;**同一 path 只保留 generated_at
    # 最新一份**——转录类「合法增长」(resume 后续写)会产生新 manifest,
    # 旧快照不构成冲突;B1 评审实测:不取最新会把合法增长谎报成篡改。
    # 逐来源判定规则(§7 决策 11):终态 exec_result_meta/job_events/loot
    # 逐来源独立判定,冲突即真异常;running 即时快照在同 job 终态事件
    # 在场时不重复计 unknown,未接替的旧快照仍保留 unknown。manifest
    # 快照是账本之外的唯一记录面(session 转录无终态账本),只认最新一份。
    evidence_dir = root / "evidence"
    manifests: list[dict[str, Any]] = []
    if evidence_dir.is_dir():
        for path in sorted(evidence_dir.glob("manifest-*.json")):
            try:
                manifests.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError) as exc:
                findings.append(
                    Finding("unknown", path.name, f"manifest 解析失败:{exc}")
                )
    # rel → (generated_at, ref_id, sha256)
    latest_snapshots: dict[str, tuple[str, str, str]] = {}
    for manifest in manifests:
        manifest_at = str(manifest.get("generated_at") or "")
        ref_id = f"manifest:{manifest.get('run_id')}"
        for item in manifest.get("artifacts") or []:
            if not item.get("sha256"):
                continue
            located = _relocate(root, str(item.get("path") or ""))
            if located is None:
                continue
            rel = located[0]
            existing = latest_snapshots.get(rel)
            if existing is None or (manifest_at, ref_id) > (
                existing[0],
                existing[1],
            ):
                latest_snapshots[rel] = (manifest_at, ref_id, item["sha256"])
    for rel, (_at, ref_id, sha256) in latest_snapshots.items():
        recorded.setdefault(rel, []).append(("manifest", ref_id, sha256, False))

    # 逐文件核验(每文件重算一次 sha256;定位明细逐来源保留,
    # 计数按文件聚合——同文件多来源不重复计「不一致」,摘要不出负数)
    checked = mismatch = missing = unknown_claims = 0
    for rel in sorted(recorded):
        claims = recorded[rel]
        located = _relocate(root, rel)
        if located is None:  # 防御:add 已归一,理论不可达
            continue
        _rel, abs_path = located
        if not abs_path.is_file():
            missing += 1
            sources = ", ".join(f"{s} {r}" for s, r, _h, _o in claims)
            findings.append(
                Finding("fail", rel, f"文件已删除(记录来源:{sources})")
            )
            continue
        try:
            current = _sha256_file(abs_path)
        except OSError as exc:
            unknown_claims += 1
            findings.append(Finding("unknown", rel, f"读取失败:{exc}"))
            continue
        has_hash_claim = False
        file_mismatch = False
        for source, ref_id, recorded_sha, in_open_run in claims:
            if not recorded_sha:
                unknown_claims += 1
                findings.append(
                    Finding(
                        "unknown",
                        rel,
                        f"{source} {ref_id} 无登记 hash(旧行/运行中记录),"
                        "无法对照",
                    )
                )
                continue
            has_hash_claim = True
            if recorded_sha != current:
                file_mismatch = True  # 计数按文件聚合;定位明细逐来源保留
                findings.append(
                    Finding(
                        "fail",
                        rel,
                        f"hash 不符({source} {ref_id} 登记 "
                        f"{_short(recorded_sha)} ≠ 现值 {_short(current)})",
                    )
                )
            elif in_open_run:
                findings.append(
                    Finding(
                        "pending",
                        rel,
                        f"{source} {ref_id} 属未终态 run,证据未收敛"
                        "(当前 hash 一致)",
                    )
                )
        if file_mismatch:
            mismatch += 1
        if has_hash_claim:
            checked += 1

    # 盘上存在但无任何记录的文件(outputs//loot/ 扫描)——unknown,不判罚
    unrecorded: list[str] = []
    for sub in ("outputs", "loot"):
        base = root / sub
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            rel = str(path.relative_to(root))
            if rel not in recorded:
                unrecorded.append(rel)
    for rel in unrecorded:
        findings.append(
            Finding("unknown", rel, "盘上存在但无任何记录(未登记产物)")
        )

    if open_runs:
        findings.append(
            Finding(
                "pending",
                "run",
                "存在未终态 run(run_started seq "
                + ",".join(str(seq) for seq, _rid in open_runs)
                + " 无配对 run_finished),产物证据未收敛",
            )
        )

    fail_count = sum(1 for f in findings if f.status == "fail")
    pending_count = sum(1 for f in findings if f.status == "pending")
    unknown_count = sum(1 for f in findings if f.status == "unknown")
    if fail_count:
        dim.status = "fail"
    elif pending_count:
        dim.status = "pending"
    elif unknown_count:
        dim.status = "unknown"
    else:
        dim.status = "pass"
    dim.summary = (
        f"产物核验:一致 {checked - mismatch} / 不一致 {mismatch} / "
        f"缺失 {missing} / 无登记或不可核验 {unknown_count}"
        + (f" / 未收口 {pending_count}" if pending_count else "")
    )
    dim.findings = findings
    dim.extra = {
        "checked": checked,
        "mismatch": mismatch,
        "missing": missing,
        "unknown": unknown_count,
        "unrecorded_on_disk": unrecorded,
    }
    return dim


def _verify_references(
    root: Path, conn: sqlite3.Connection | None
) -> DimensionResult:
    """references 维:evidence_refs 逐条——界内查存在性;界外/绝对路径
    不打开不跟随,标 unknown 并逐条定位(不判罚:解析器界外 provenance
    属已知合法形态,决策 6;不核验内容,无登记 hash 可对照)。"""
    dim = DimensionResult()
    findings: list[Finding] = []
    if conn is None:
        dim.status = "unknown"
        dim.summary = "索引库不可用(缺失/无法只读打开),证据引用无从核验"
        return dim
    has_refs_col = any(
        "evidence_refs" in _table_columns(conn, table)
        for table in ("vulns", "creds")
    )
    if not has_refs_col:
        dim.status = "unknown"
        dim.summary = "索引库 schema 低于 v3(legacy),无证据引用列"
        return dim
    total = passed = failed = external = 0
    for table in ("vulns", "creds"):
        if "evidence_refs" not in _table_columns(conn, table):
            continue
        for row in _query_dicts(
            conn,
            f"SELECT id, evidence_refs FROM {table} "  # noqa: S608  # 表名为本模块常量
            "WHERE evidence_refs IS NOT NULL ORDER BY id",
        ):
            for ref in _decode_refs(row["evidence_refs"]):
                total += 1
                subject = f"{table}/{row['id']} → {ref}"
                located = _relocate(root, ref)
                if located is None:
                    external += 1
                    findings.append(
                        Finding(
                            "unknown",
                            subject,
                            "界外/绝对路径引用,不打开不跟随(可定位,不判罚)",
                        )
                    )
                    continue
                _rel, abs_path = located
                if abs_path.is_file():
                    passed += 1
                else:
                    failed += 1
                    findings.append(
                        Finding("fail", subject, "证据文件缺失(界内引用)")
                    )
    if failed:
        dim.status = "fail"
    elif external:
        dim.status = "unknown"
    else:
        dim.status = "pass"
    dim.summary = (
        f"证据引用 {total} 条:存在 {passed} / 缺失 {failed} / "
        f"界外不跟随 {external}"
    )
    dim.findings = findings
    dim.extra = {
        "total": total,
        "present": passed,
        "missing": failed,
        "external": external,
    }
    return dim


def _verify_coverage(
    root: Path,
    records: list[dict[str, Any]],
    conn: sqlite3.Connection | None,
    meta: dict[str, Any],
    pairs: list[tuple[dict[str, Any], dict[str, Any] | None]],
) -> DimensionResult:
    """coverage 维:run 配对 / job_events pending / 会话覆盖 / manifest
    在场性;外部锚定声明恒在人读与 JSON 输出层呈现(EXTERNAL_ANCHOR_NOTE)。"""
    dim = DimensionResult()
    findings: list[Finding] = []
    unpaired = [
        started
        for started, finished in pairs
        if finished is None and started.get("seq") is not None
    ]
    for started in unpaired:
        findings.append(
            Finding(
                "pending",
                f"run seq {started.get('seq')}",
                f"run_started(run_id {_run_id_of(started) or '(无)'})"
                "无配对 run_finished——run 未终态或进程崩溃",
            )
        )

    pending_jobs: list[str] = []
    if conn is None:
        findings.append(
            Finding("unknown", "index.sqlite", "索引库缺失/无法只读打开")
        )
    elif not _table_columns(conn, "job_events"):
        findings.append(
            Finding("unknown", "job_events", "索引库缺 job_events 表(legacy)")
        )
    else:
        for row in _query_dicts(
            conn,
            "SELECT event_id FROM job_events WHERE status = 'pending' "
            "ORDER BY event_id",
        ):
            pending_jobs.append(str(row["event_id"]))
        if pending_jobs:
            findings.append(
                Finding(
                    "pending",
                    "job_events",
                    f"{len(pending_jobs)} 条未消费占位(drain 超时登记):"
                    + ", ".join(pending_jobs),
                )
            )

    coverage = session_coverage(records)

    terminal = next(
        (pair for pair in reversed(pairs) if pair[1] is not None), None
    )
    manifest_status = "none_required"
    if terminal is not None:
        finished_payload = terminal[1].get("payload") or {}
        run_id = (
            finished_payload.get("run_id")
            or _run_id_of(terminal[0])
            or f"legacy-seq{terminal[1].get('seq')}"
        )
        safe = _SAFE_NAME_RE.sub("-", str(run_id))
        if (root / "evidence" / f"manifest-{safe}.json").is_file():
            manifest_status = "present"
        else:
            manifest_status = "missing"
            findings.append(
                Finding(
                    "unknown",
                    f"evidence/manifest-{safe}.json",
                    "终末 run 无证据 manifest(旧 run 不补造;R09 前的终态"
                    "或崩溃路径本无 manifest)",
                )
            )

    if coverage == "legacy":
        if manifest_status == "present":
            # 评审收口(rc0 可达面):R09 代际新链(终末 run 已有 manifest)
            # 且无 session_op = 无会话使用,非证据缺失——pass 注记,不拖
            # unknown。无 manifest 且无 session_op(pre-R09/pre-R07 旧链)
            # 保持 legacy unknown(设计口径:旧链保持 rc 3,见 §7)。
            findings.append(
                Finding(
                    "pass",
                    "session_op",
                    "链无会话操作记录且终末 run 已有证据 manifest:"
                    "无会话使用(R09 代际),非旧链证据缺失",
                )
            )
            session_note = "无会话使用"
        else:
            findings.append(
                Finding("unknown", "session_op", "旧链无会话审计记录(legacy)")
            )
            session_note = "legacy"
    else:
        session_note = "tracked"

    pend = sum(1 for f in findings if f.status == "pending")
    unk = sum(1 for f in findings if f.status == "unknown")
    if pend:
        dim.status = "pending"
    elif unk:
        dim.status = "unknown"
    else:
        dim.status = "pass"
    dim.summary = (
        f"覆盖:run {len(pairs)} 个(未配对 {len(unpaired)})/ "
        f"job_events 未消费 {len(pending_jobs)} 条 / 会话审计 {session_note} / "
        f"manifest {manifest_status}"
    )
    dim.findings = findings
    dim.extra = {
        "runs": len(pairs),
        "unpaired_runs": len(unpaired),
        "pending_job_events": pending_jobs,
        "session_coverage": coverage,
        "manifest": manifest_status,
        "engagement_status": meta.get("status"),
    }
    return dim


def verify_engagement(root: str | Path) -> VerifyResult:
    """只读核验 engagement:chain/files/references/coverage 四维独立判定。

    只读契约(决策 5):``EngagementPaths`` 纯实例化;索引库
    ``mode=ro`` URI 连接(无 journal/迁移/chmod);不取单写者锁;不创建
    任何文件;不执行旧命令;不跟随目录外引用。
    """
    root = Path(root)
    paths = EngagementPaths(root)
    generated_at = _utc_now_iso()
    meta = _read_meta(paths)

    chain_dim, records = _verify_chain(paths)
    pairs = _pair_runs(records)
    open_runs = [
        (int(started["seq"]), _run_id_of(started))
        for started, finished in pairs
        if finished is None and started.get("seq") is not None
    ]
    conn = _open_index_ro(paths.index_db)
    try:
        files_dim = _verify_files(root, records, conn, open_runs)
        references_dim = _verify_references(root, conn)
        coverage_dim = _verify_coverage(root, records, conn, meta, pairs)
    finally:
        if conn is not None:
            conn.close()

    dimensions = {
        "chain": chain_dim,
        "files": files_dim,
        "references": references_dim,
        "coverage": coverage_dim,
    }
    return VerifyResult(
        root=str(root),
        engagement_id=meta.get("id") or (root.name if meta else None),
        generated_at=generated_at,
        dimensions=dimensions,
        overall=_worst(dimensions),
    )


# ---------------------------------------------------------------------------
# verify 结果渲染(人读与 JSON 共用同一 VerifyResult,AC07)
# ---------------------------------------------------------------------------


def result_to_dict(result: VerifyResult) -> dict[str, Any]:
    """VerifyResult 的机读形态(``--json`` 输出)。"""
    return {
        "format": 1,
        "engagement": result.root,
        "engagement_id": result.engagement_id,
        "generated_at": result.generated_at,
        "overall": result.overall,
        "dimensions": {
            name: {
                "status": dim.status,
                "summary": dim.summary,
                "findings": [
                    {"status": f.status, "subject": f.subject, "detail": f.detail}
                    for f in dim.findings
                ],
                "extra": dim.extra,
            }
            for name, dim in result.dimensions.items()
        },
        "external_anchor": EXTERNAL_ANCHOR,
        "external_anchor_note": EXTERNAL_ANCHOR_NOTE,
    }


_OVERALL_LABEL = {
    "pass": "pass(所请求检查均通过且无未知项)",
    "fail": "fail(已确认不一致)",
    "unknown": "unknown(证据不足)",
    "pending": "pending(运行未完成/证据未收敛)",
}


def render_human(result: VerifyResult) -> str:
    """VerifyResult 的人读形态(默认 stdout)。"""
    lines = [
        f"核验 engagement:{result.root}"
        + (f"(id {result.engagement_id})" if result.engagement_id else ""),
        f"核验时间:{result.generated_at}",
    ]
    for name in DIMENSIONS:
        dim = result.dimensions[name]
        lines.append(f"[{name}] {dim.status}:{dim.summary}")
        for finding in dim.findings:
            mark = _STATUS_MARK.get(finding.status, "?")
            lines.append(f"  {mark} {finding.subject}:{finding.detail}")
    lines.append(f"总判定:{_OVERALL_LABEL.get(result.overall, result.overall)}")
    lines.append(f"声明:{EXTERNAL_ANCHOR_NOTE}")
    return "\n".join(lines) + "\n"
