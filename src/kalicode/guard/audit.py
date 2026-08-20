"""哈希链审计(append-only JSONL)。

每条记录一个 JSON 对象,字段:

    {seq, ts, kind, payload, prev_hash, hash}

- ``seq``:从 1 开始严格递增;重开已有文件时从末条 seq 续号。
- ``ts``:UTC ISO-8601 字符串。
- ``kind``:事件类型,见 ``KNOWN_KINDS``(允许后续 WP 扩展新 kind)。
- ``payload``:事件内容(dict)。LLM 内容只记哈希与 token 数,不记全文
  (用 :func:`llm_meta` 构造 payload);工具输出原文在 engagement 目录。
- ``prev_hash``:前一条记录的 ``hash``;首条为 64 个 ``'0'``(``ZERO_HASH``)。
- ``hash``:``sha256(prev_hash + canonical(除 hash 外的整条记录))``,
  canonical 为 ``json.dumps(sort_keys=True, separators=(",", ":"))``。

  说明:WP-02 规格把哈希输入写作 ``prev_hash + canonical(payload)``,
  此处把 seq/ts/kind 一并纳入——否则篡改这三个字段不会断链,
  无法满足验收「篡改任一记录任意字节,verify 必失败」。

校验::

    verify(path) -> bool        # 全链重算,任一环节不符即 False
    explain(path) -> list[str]  # 与 verify 同逻辑,返回人类可读的错误清单

已知限制(防不住的攻击,写入开发日志):
- **截尾攻击**:删掉末尾若干条后,剩余链 verify 仍通过。需要把最新 hash
  定期锚定到外部信道才能发现,v0 不做。
- 本模块只保证「落盘后不被静默改写」,不防「写入前 payload 就造假」。
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ZERO_HASH = "0" * 64

# 已知事件类型;后续 WP 可扩展,append 不强制校验(避免跨 WP 耦合)。
KIND_SCOPE_LOADED = "scope_loaded"
KIND_EXEC_REQUEST = "exec_request"
KIND_EXEC_DENIED = "exec_denied"
KIND_EXEC_RESULT_META = "exec_result_meta"
KIND_OPERATOR_INTERJECT = "operator_interject"
KIND_KILL_SWITCH = "kill_switch"
KIND_LLM_EXCHANGE_META = "llm_exchange_meta"

KNOWN_KINDS = frozenset(
    {
        KIND_SCOPE_LOADED,
        KIND_EXEC_REQUEST,
        KIND_EXEC_DENIED,
        KIND_EXEC_RESULT_META,
        KIND_OPERATOR_INTERJECT,
        KIND_KILL_SWITCH,
        KIND_LLM_EXCHANGE_META,
    }
)

_RECORD_FIELDS = ("seq", "ts", "kind", "payload", "prev_hash", "hash")


def canonical(obj: Any) -> str:
    """JSON 规范化串:键排序、无空白、UTF-8 不转义,保证同对象同串。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(prev_hash: str, seq: int, ts: str, kind: str, payload: Any) -> str:
    """按链式公式重算记录哈希(覆盖除 hash 外的全部字段)。"""
    body = {
        "seq": seq,
        "ts": ts,
        "kind": kind,
        "payload": payload,
        "prev_hash": prev_hash,
    }
    return hashlib.sha256((prev_hash + canonical(body)).encode("utf-8")).hexdigest()


def llm_meta(
    prompt: str,
    response: str,
    *,
    prompt_tokens: int | None = None,
    response_tokens: int | None = None,
) -> dict:
    """构造 ``llm_exchange_meta`` 的 payload:只含哈希与 token 数,不记全文。"""
    return {
        "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "response_sha256": hashlib.sha256(response.encode("utf-8")).hexdigest(),
        "prompt_chars": len(prompt),
        "response_chars": len(response),
        "prompt_tokens": prompt_tokens,
        "response_tokens": response_tokens,
    }


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


class AuditLog:
    """append-only 审计链写入器。

    重开已有文件时扫描到末条记录,从其 seq/hash 继续;末行 JSON 损坏
    (半行写入或人为破坏)时抛 ``ValueError``,拒绝在可疑链上静默续写。
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._prev_hash = self._recover_tail()
        self._fh = open(self.path, "a", encoding="utf-8")  # noqa: SIM115

    def _recover_tail(self) -> tuple[int, str]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, ZERO_HASH
        last_line = ""
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last_line = line
        try:
            record = json.loads(last_line)
            return int(record["seq"]), str(record["hash"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                f"审计链末行损坏,拒绝续写(需人工核查):{self.path}: {exc}"
            ) from exc

    @property
    def next_seq(self) -> int:
        return self._seq + 1

    def append(self, kind: str, payload: dict) -> dict:
        """追加一条记录并立即 flush(不 fsync;崩溃至多丢末条缓冲)。返回该记录。"""
        seq = self._seq + 1
        ts = _utc_now_iso()
        record = {
            "seq": seq,
            "ts": ts,
            "kind": kind,
            "payload": payload,
            "prev_hash": self._prev_hash,
        }
        record["hash"] = compute_hash(self._prev_hash, seq, ts, kind, payload)
        line = json.dumps(record, sort_keys=True, ensure_ascii=False)
        self._fh.write(line + "\n")
        self._fh.flush()
        self._seq, self._prev_hash = seq, record["hash"]
        return record

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _check_chain(path: str | Path) -> list[str]:
    """全链校验,返回错误清单(空列表 = 通过)。"""
    errors: list[str] = []
    expected_seq = 1
    prev_hash = ZERO_HASH
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"第 {lineno} 行:JSON 解析失败({exc})")
                continue
            if not isinstance(record, dict) or any(
                f not in record for f in _RECORD_FIELDS
            ):
                errors.append(f"第 {lineno} 行:字段不全(需要 {list(_RECORD_FIELDS)})")
                continue
            if record["seq"] != expected_seq:
                errors.append(
                    f"第 {lineno} 行:seq={record['seq']},"
                    f"应为 {expected_seq}(缺条或乱序)"
                )
            if record["prev_hash"] != prev_hash:
                errors.append(f"第 {lineno} 行:prev_hash 与前条 hash 不符(链断裂)")
            recomputed = compute_hash(
                record["prev_hash"],
                record["seq"],
                record["ts"],
                record["kind"],
                record["payload"],
            )
            if recomputed != record["hash"]:
                errors.append(f"第 {lineno} 行:hash 重算不符(记录被篡改)")
            prev_hash = record["hash"] if isinstance(record["hash"], str) else prev_hash
            expected_seq += 1
    return errors


def verify(path: str | Path) -> bool:
    """全链重算校验:篡改任一记录的任一字段、删改中间记录、乱序都会失败。

    空文件(尚无任何记录)视为通过。截尾删除末尾记录不在可检测范围内,
    见模块 docstring「已知限制」。
    """
    path = Path(path)
    if not path.exists():
        return False
    return not _check_chain(path)


def explain(path: str | Path) -> list[str]:
    """与 verify 同逻辑,返回人类可读错误清单;空列表表示链完整。"""
    path = Path(path)
    if not path.exists():
        return [f"文件不存在:{path}"]
    return _check_chain(path)
