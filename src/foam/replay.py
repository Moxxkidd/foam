"""审计链回放与报告(WP-10)。

replay:先用 WP-02 官方语义(:func:`foam.guard.audit.explain`)校验哈希链;
链断则报告首个断点 seq 并中止;链完整才按时间线只读重放——谁、何时、
什么命令、什么结果元信息(审计本就不记 LLM 全文,只有哈希与 token 数,
故 replay 呈现的是元信息时间线,不是对话回放)。

report:中文 markdown —— 目标 / 范围 / 过程时间线 / 发现清单(含证据路径)/
凭证(全值,WP-06 契约:LLM 视图掩码,报告导出可见)/ loot 清单 / 操作员
插话记录 / 统计 / 审计链完整性。数据源:engagement.json + ENGAGEMENT.md +
index.sqlite + audit.jsonl;缺任一源给明确标注(legacy 目录降级,不炸)。

本模块是审计链的「读侧」:全部函数只读,不写 engagement 目录任何文件。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from foam.agent.loop import (
    KIND_CONTEXT_COMPRESSED,
    KIND_LLM_RETRY,
    KIND_LOOP_CORRECTION,
    KIND_RUN_FINISHED,
    KIND_RUN_STARTED,
)
from foam.guard.audit import (
    KIND_EXEC_DENIED,
    KIND_EXEC_REQUEST,
    KIND_EXEC_RESULT_META,
    KIND_KILL_SWITCH,
    KIND_LLM_EXCHANGE_META,
    KIND_OPERATOR_INTERJECT,
    KIND_SCOPE_LOADED,
    ZERO_HASH,
    compute_hash,
    explain,
)
from foam.state.files import Engagement
from foam.state.index import Index

#: 时间线里命令/文本的展示截断长度。
_CLIP = 120


def _clip(text: Any, limit: int = _CLIP) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# 记录读取与断点定位
# ---------------------------------------------------------------------------


def read_records(audit_path: str | Path) -> list[dict[str, Any]]:
    """解析 audit.jsonl 为记录列表(空行跳过;坏行抛 ValueError 带行号)。

    调用方通常先用 :func:`chain_errors` 校验;本函数面向链完整后的消费。
    """
    records: list[dict[str, Any]] = []
    path = Path(audit_path)
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path} 第 {lineno} 行 JSON 解析失败:{exc}") from exc
            records.append(record)
    return records


def chain_errors(audit_path: str | Path) -> list[str]:
    """WP-02 官方校验语义(空清单 = 链完整;文件不存在也在清单里说明)。"""
    return explain(audit_path)


@dataclass(frozen=True)
class ChainBreak:
    """首个断点位置。seq 为记录自报值(记录不可解析时为 None)。"""

    line: int  # 文件行号(1 起)
    expected_seq: int  # 链上此处应有的 seq
    seq: int | None
    reasons: list[str] = field(default_factory=list)

    def describe(self) -> str:
        seq_text = str(self.seq) if self.seq is not None else "不可解析"
        return (
            f"首个断点:第 {self.line} 行(记录 seq={seq_text},"
            f"链上应为 seq={self.expected_seq})——{'; '.join(self.reasons)}"
        )


def find_chain_break(audit_path: str | Path) -> ChainBreak | None:
    """逐行重算哈希链(复用 WP-02 compute_hash),返回首个断点;完整返回 None。

    与 :func:`chain_errors` 同语义但停在第一处——replay 的「断点 seq」由它给出。
    """
    expected_seq = 1
    prev_hash = ZERO_HASH
    with open(audit_path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                return ChainBreak(lineno, expected_seq, None, [f"JSON 解析失败:{exc}"])
            reasons: list[str] = []
            seq = record.get("seq") if isinstance(record, dict) else None
            if not isinstance(record, dict) or any(
                f not in record
                for f in ("seq", "ts", "kind", "payload", "prev_hash", "hash")
            ):
                return ChainBreak(lineno, expected_seq, seq, ["记录字段不全"])
            if seq != expected_seq:
                reasons.append(f"seq={seq},应为 {expected_seq}(缺条或乱序)")
            if record["prev_hash"] != prev_hash:
                reasons.append("prev_hash 与前条 hash 不符(链断裂)")
            recomputed = compute_hash(
                record["prev_hash"],
                record["seq"],
                record["ts"],
                record["kind"],
                record["payload"],
            )
            if recomputed != record["hash"]:
                reasons.append("hash 重算不符(记录被篡改)")
            if reasons:
                return ChainBreak(lineno, expected_seq, seq, reasons)
            prev_hash = record["hash"]
            expected_seq += 1
    return None


# ---------------------------------------------------------------------------
# 时间线(replay 主体)
# ---------------------------------------------------------------------------


def format_record(record: dict[str, Any]) -> str:
    """一条审计记录 → 一行中文时间线(谁、何时、什么动作、什么结果元信息)。"""
    seq = record.get("seq", "?")
    ts = record.get("ts", "?")
    kind = record.get("kind", "?")
    payload = record.get("payload") or {}
    head = f"[seq {seq:>3}] {ts} "

    if kind == KIND_SCOPE_LOADED:
        summary = {
            key: len(payload.get(key) or [])
            for key in ("cidrs", "hosts", "wildcards", "url_prefixes")
        }
        return head + f"scope 加载:{payload.get('source')}(规则 {summary})"
    if kind == KIND_RUN_STARTED:
        return head + (
            f"run 启动:provider={payload.get('provider')} "
            f"objective={_clip(payload.get('objective', ''))}"
        )
    if kind == KIND_RUN_FINISHED:
        return head + (
            f"run 结束:{payload.get('status')},{payload.get('rounds')} 轮,"
            f"tokens 输入 {payload.get('input_tokens')} / 输出 "
            f"{payload.get('output_tokens')}"
            + (f",error={_clip(payload['error'])}" if payload.get("error") else "")
        )
    if kind == KIND_EXEC_REQUEST:
        targets = ",".join(payload.get("targets") or []) or "(无网络目标)"
        return head + f"$ {_clip(payload.get('command', ''))}  [目标: {targets}]"
    if kind == KIND_EXEC_DENIED:
        violations = ",".join(payload.get("violations") or []) or payload.get(
            "reason", ""
        )
        return (
            head + f"护栏拒绝:{_clip(payload.get('command', ''))}  [越界: {violations}]"
        )
    if kind == KIND_EXEC_RESULT_META:
        sha = str(payload.get("sha256") or "")[:12]
        return head + (
            f"结果:{payload.get('status')} exit={payload.get('exit_code')} "
            f"{payload.get('duration_ms')}ms bytes={payload.get('total_bytes')} "
            f"sha256={sha}… 输出 {payload.get('output_path')}"
        )
    if kind == KIND_LLM_EXCHANGE_META:
        return head + (
            f"LLM 交换:prompt {payload.get('prompt_chars')} 字符/"
            f"{payload.get('prompt_tokens')} tokens → response "
            f"{payload.get('response_chars')} 字符/{payload.get('response_tokens')} "
            "tokens(全文只记哈希)"
        )
    if kind == KIND_OPERATOR_INTERJECT:
        return head + f"操作员插话:{_clip(payload.get('text', ''))}"
    if kind == KIND_KILL_SWITCH:
        jobs = payload.get("jobs") or []
        return head + (
            f"kill switch:{payload.get('reason') or '(无理由)'}"
            f"(杀 job {len(jobs)} 个,sessions_aclose={payload.get('sessions_aclose')})"
        )
    if kind == KIND_LOOP_CORRECTION:
        reason = payload.get("reason")
        return head + f"主环纠正:{reason} {_clip(payload.get('excerpt', ''), 60)}"
    if kind == KIND_LLM_RETRY:
        attempt = payload.get("attempt")
        return head + f"LLM 重试:第 {attempt} 次 {_clip(payload.get('error', ''), 80)}"
    if kind == KIND_CONTEXT_COMPRESSED:
        return head + (
            f"context 压缩:{payload.get('estimated_tokens_before')}→"
            f"{payload.get('estimated_tokens_after')} tokens(预算 "
            f"{payload.get('budget')})"
        )
    # 未知 kind(KNOWN_KINDS 允许后续 WP 扩展):通用摘要,不炸。
    summary = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return head + f"{kind}:{_clip(summary)}"


def format_timeline(records: list[dict[str, Any]]) -> list[str]:
    return [format_record(record) for record in records]


# ---------------------------------------------------------------------------
# resume 用的恢复与简报(审计链是唯一可信史)
# ---------------------------------------------------------------------------


def recover_objective(records: list[dict[str, Any]]) -> str | None:
    """从最后一条 run_started 恢复 objective(legacy 目录无 engagement.json 时)。"""
    for record in reversed(records):
        if record.get("kind") == KIND_RUN_STARTED:
            objective = (record.get("payload") or {}).get("objective")
            if objective:
                return str(objective)
    return None


def recover_scope_record(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    """最后一条 scope_loaded 的 payload(source + 规则摘要),供 resume 对账。"""
    for record in reversed(records):
        if record.get("kind") == KIND_SCOPE_LOADED:
            return dict(record.get("payload") or {})
    return None


def audit_stats(records: list[dict[str, Any]]) -> dict[str, int]:
    """run 次数 / LLM 轮数 / 命令数 / 拒绝数 / 插话数 / kill 数(报告与简报共用)。"""
    stats = {
        "runs": 0,
        "rounds": 0,
        "commands": 0,
        "denied": 0,
        "interjects": 0,
        "kills": 0,
    }
    for record in records:
        kind = record.get("kind")
        if kind == KIND_RUN_STARTED:
            stats["runs"] += 1
        elif kind == KIND_LLM_EXCHANGE_META:
            stats["rounds"] += 1
        elif kind == KIND_EXEC_REQUEST:
            stats["commands"] += 1
        elif kind == KIND_EXEC_DENIED:
            stats["denied"] += 1
        elif kind == KIND_OPERATOR_INTERJECT:
            stats["interjects"] += 1
        elif kind == KIND_KILL_SWITCH:
            stats["kills"] += 1
    return stats


def summarize_recent_rounds(records: list[dict[str, Any]], n: int) -> list[str]:
    """最近 n 轮(LLM 交换计轮)的动作摘要行:命令/拒绝/插话/纠正/收尾。"""
    if n <= 0 or not records:
        return []
    round_seqs = [r["seq"] for r in records if r.get("kind") == KIND_LLM_EXCHANGE_META]
    if not round_seqs:
        return []
    window_start = round_seqs[max(0, len(round_seqs) - n)]
    interesting = {
        KIND_EXEC_REQUEST,
        KIND_EXEC_DENIED,
        KIND_EXEC_RESULT_META,
        KIND_OPERATOR_INTERJECT,
        KIND_LOOP_CORRECTION,
        KIND_KILL_SWITCH,
        KIND_RUN_FINISHED,
    }
    lines = []
    for record in records:
        if record.get("seq", 0) >= window_start and record.get("kind") in interesting:
            lines.append("- " + format_record(record))
    return lines


def build_resume_briefing(records: list[dict[str, Any]], *, recent_rounds: int) -> str:
    """resume 注入的简报(经 loop.interject 作为操作员消息进上下文)。

    明确告知模型:这不是全量对话回放,是审计链元信息摘要;原始输出在盘上。
    """
    stats = audit_stats(records)
    lines = [
        "【resume 简报】本 engagement 恢复自历史审计链(仅元信息摘要,不是全量"
        "对话回放;此前的对话上下文不随 resume 恢复)。",
        (
            f"历史概览:run {stats['runs']} 次,LLM 交换 {stats['rounds']} 轮,"
            f"执行命令 {stats['commands']} 条(护栏拒绝 {stats['denied']} 条),"
            f"操作员插话 {stats['interjects']} 条,kill {stats['kills']} 次。"
        ),
    ]
    recent = summarize_recent_rounds(records, recent_rounds)
    if recent:
        lines.append(f"最近 {min(recent_rounds, stats['rounds'])} 轮动作:")
        lines.extend(recent)
    lines.append(
        "完整原始输出在 engagement 目录 outputs/(哈希见审计链,可用 read_output "
        "分页读取);工作笔记 ENGAGEMENT.md 已随 system 消息全量加载,以它为准。"
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------


def _scope_lines_from_summary(payload: dict[str, Any]) -> list[str]:
    lines = []
    for key, label in (
        ("cidrs", "网段"),
        ("hosts", "主机"),
        ("wildcards", "通配域"),
        ("url_prefixes", "URL 前缀"),
    ):
        for value in payload.get(key) or []:
            lines.append(f"- {label}:{value}")
    return lines


def build_report(root: str | Path, *, generated_at: str | None = None) -> str:
    """从 engagement 目录生成中文 markdown 报告(只读;缺源降级标注)。

    必备节:目标 / 范围 / 过程时间线 / 发现清单(含证据路径)/ 凭证(全值)/
    loot 清单 / 操作员插话记录 / 统计 / 审计链完整性。
    """
    root = Path(root)
    generated_at = generated_at or datetime.now(UTC).isoformat(timespec="seconds")
    engagement = Engagement.open(root)
    meta: dict[str, Any] = {}
    if engagement.paths.metadata.is_file():
        try:
            meta = engagement.metadata()
        except json.JSONDecodeError:
            meta = {}

    records: list[dict[str, Any]] = []
    audit_problems: list[str] = []
    if engagement.paths.audit_jsonl.is_file():
        audit_problems = chain_errors(engagement.paths.audit_jsonl)
        if not audit_problems:
            records = read_records(engagement.paths.audit_jsonl)
    stats = audit_stats(records)

    lines: list[str] = [
        f"# Engagement 报告:{meta.get('id') or root.name}",
        "",
        f"- 生成时间:{generated_at}",
        f"- engagement 目录:{root}",
        f"- 状态:{meta.get('status', '(无 engagement.json)')}",
    ]
    if not engagement.paths.audit_jsonl.is_file():
        lines.append("- 审计链:**缺失**(audit.jsonl 不存在)")
    elif audit_problems:
        first = audit_problems[0]
        lines.append(f"- 审计链:**校验未通过**——{first}(共 {len(audit_problems)} 处)")
    else:
        lines.append(f"- 审计链:完整({len(records)} 条记录,全链哈希校验通过)")
    lines.append("")

    # ---- 目标 ----
    lines += ["## 目标", ""]
    objective = meta.get("objective") or recover_objective(records)
    lines.append(objective or "(未记录:engagement.json 缺失且审计链无 run_started)")
    lines.append("")

    # ---- 范围 ----
    lines += ["## 范围(scope)", ""]
    scope_meta = meta.get("scope")
    if scope_meta:
        lines.append(f"- scope 文件:{scope_meta.get('path')}")
        lines.append(f"- 内容 sha256:{scope_meta.get('sha256')}")
    scope_record = recover_scope_record(records)
    if scope_record:
        if not scope_meta:
            lines.append(f"- scope 文件(审计链恢复):{scope_record.get('source')}")
        rule_lines = _scope_lines_from_summary(scope_record)
        if rule_lines:
            lines.append("- 规则:")
            lines.extend("  " + rule for rule in rule_lines)
    if not scope_meta and not scope_record:
        lines.append("(无 scope 记录)")
    lines.append("")

    # ---- 过程时间线 ----
    lines += ["## 过程时间线", ""]
    if records:
        lines.extend(format_timeline(records))
    else:
        lines.append("(审计链缺失或未通过校验,无时间线)")
    lines.append("")

    # ---- 索引库各节(缺库降级) ----
    index_rows: dict[str, list[dict[str, Any]]] = {}
    index_missing = not engagement.paths.index_db.is_file()
    if not index_missing:
        with Index(engagement.paths.index_db) as index:
            for kind in ("hosts", "ports", "creds", "vulns", "loot", "notes"):
                index_rows[kind] = index.query(kind, limit=10000)["rows"]

    lines += ["## 发现清单(漏洞)", ""]
    if index_missing:
        lines.append("(索引库 index.sqlite 缺失——本 engagement 未经状态层入库)")
    elif not index_rows["vulns"]:
        lines.append("(无漏洞记录)")
    else:
        for row in index_rows["vulns"]:
            lines.append(
                f"- **{row.get('title')}**({row.get('kind')},主机 {row.get('ip')},"
                f"置信 {row.get('confidence') or '未标'})"
            )
            lines.append(f"  - 证据:{row.get('evidence_path') or '(未登记证据路径)'}")
    lines.append("")

    lines += ["## 凭证(全值)", ""]
    lines.append(
        "> 本节为报告导出,secret 为完整值(WP-06 契约:仅 LLM 视图掩码);"
        "按红线处理,勿外发。"
    )
    lines.append("")
    if index_missing:
        lines.append("(索引库缺失)")
    elif not index_rows["creds"]:
        lines.append("(无凭证记录)")
    else:
        for row in index_rows["creds"]:
            lines.append(
                f"- 主机 {row.get('ip')} 用户 `{row.get('username')}` "
                f"secret `{row.get('secret')}`(来源:{row.get('source') or '未标'},"
                f"sensitive={row.get('sensitive')})"
            )
    lines.append("")

    lines += ["## 战利品(loot)清单", ""]
    if index_missing:
        lines.append("(索引库缺失)")
    elif not index_rows["loot"]:
        lines.append("(无 loot 登记)")
    else:
        for row in index_rows["loot"]:
            size = row.get("size_bytes")
            note = f"——{row['note']}" if row.get("note") else ""
            lines.append(
                f"- `{row.get('path')}`({row.get('kind') or '未分类'},"
                f"{size if size is not None else '?'} 字节,{row.get('ts')}){note}"
            )
    lines.append("")

    # ---- 操作员插话 ----
    lines += ["## 操作员插话记录", ""]
    interjects = [r for r in records if r.get("kind") == KIND_OPERATOR_INTERJECT]
    if not records:
        lines.append("(审计链缺失或未通过校验)")
    elif not interjects:
        lines.append("(全程无操作员插话)")
    else:
        for record in interjects:
            lines.append(
                f"- [seq {record['seq']}] {record['ts']}:"
                f"{(record.get('payload') or {}).get('text', '')}"
            )
    lines.append("")

    # ---- 笔记 ----
    if not index_missing and index_rows["notes"]:
        lines += ["## 笔记(notes)", ""]
        for row in index_rows["notes"]:
            lines.append(f"- {row.get('ts')}:{row.get('text')}")
        lines.append("")

    # ---- 统计 ----
    lines += ["## 统计", ""]
    lines.append(
        f"- run {stats['runs']} 次 / LLM {stats['rounds']} 轮 / 命令 "
        f"{stats['commands']} 条(拒绝 {stats['denied']})/ 插话 "
        f"{stats['interjects']} 条 / kill {stats['kills']} 次"
    )
    if not index_missing:
        counts = {
            kind: len(index_rows[kind])
            for kind in ("hosts", "ports", "creds", "vulns", "loot", "notes")
        }
        lines.append(
            "- 索引库:"
            + " / ".join(f"{kind} {count}" for kind, count in counts.items())
        )
    lines.append("")
    return "\n".join(lines)
