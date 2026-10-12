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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from foam.agent.loop import KIND_RUN_FINISHED, KIND_RUN_STARTED
from foam.guard.audit import KIND_EXEC_RESULT_META, KIND_KILL_SWITCH
from foam.replay import chain_errors, read_records
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

    库缺失/无法只读打开(如热日志待回滚)返回 None——调用方按「该来源
    不可用」降级(unknown),不炸。
    """
    if not db_path.is_file():
        return None
    try:
        conn = sqlite3.connect(
            f"file:{quote(str(db_path))}?mode=ro", uri=True
        )
    except sqlite3.Error:
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
) -> tuple[Path, Path] | None:
    """构建并落盘 manifest + 结项页(0600);无 run_finished 返回 None。

    返回 ``(manifest_json 路径, summary_md 路径)``。同输入与固定
    ``generated_at`` 重写逐字节一致(幂等覆盖)。
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
    return json_path, md_path

