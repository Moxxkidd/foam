"""run 可恢复预算总账；审计事件是跨进程持久化事实源。"""

from __future__ import annotations

import math
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from foam.agent.backends.base import Usage

DEFAULT_CONTEXT_TOKEN_LIMIT = 120_000
_MEASUREMENT_STATUSES = frozenset({"measured", "estimated", "unknown"})
_ROUND_OUTCOMES = frozenset({"completed", "malformed"})
_LIMIT_FIELDS = {
    "context": "context_tokens",
    "context_tokens": "context_tokens",
    "tokens": "total_tokens",
    "total_tokens": "total_tokens",
    "rounds": "rounds",
    "wall_time": "wall_time_seconds",
    "wall_time_seconds": "wall_time_seconds",
}


@dataclass(frozen=True)
class BudgetLimits:
    context_tokens: int = DEFAULT_CONTEXT_TOKEN_LIMIT
    total_tokens: int | None = None
    rounds: int | None = None
    wall_time_seconds: float | None = None

    def __post_init__(self) -> None:
        for value in (
            self.context_tokens,
            self.total_tokens,
            self.rounds,
            self.wall_time_seconds,
        ):
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("预算上限必须是有限数值")
        if self.context_tokens <= 0:
            raise ValueError("context 预算必须为正")
        for value in (self.total_tokens, self.rounds, self.wall_time_seconds):
            if value is not None and value <= 0:
                raise ValueError("累计预算上限必须为正；None 表示不限")

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> BudgetLimits:
        return cls(
            context_tokens=int(data.get("context_tokens", DEFAULT_CONTEXT_TOKEN_LIMIT)),
            total_tokens=_optional_number(data.get("total_tokens")),
            rounds=_optional_number(data.get("rounds")),
            wall_time_seconds=_optional_number(data.get("wall_time_seconds")),
        )

    def as_dict(self) -> dict[str, int | float | None]:
        return {
            "context_tokens": self.context_tokens,
            "total_tokens": self.total_tokens,
            "rounds": self.rounds,
            "wall_time_seconds": self.wall_time_seconds,
        }


def _optional_number(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"预算上限必须是数字或 null: {value!r}")
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


class BudgetLedger:
    """汇总精确、估算和缺失用量，并恢复 opening 之后的新事件。"""

    def __init__(
        self,
        limits: BudgetLimits | None = None,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limits = limits or BudgetLimits()
        self._monotonic = monotonic
        self._input_tokens = 0
        self._output_tokens = 0
        self._estimated_input_tokens = 0
        self._estimated_output_tokens = 0
        self._unknown_usage_requests = 0
        self._request_count = 0
        self._phase_request_counts: Counter[str] = Counter()
        self._rounds = 0
        self._wall_time_seconds = 0.0
        self._wall_time_unknown = False
        self._started_mono: float | None = None
        self._request_ids: set[str] = set()
        self._pending_limit_changes: list[dict[str, Any]] = []

    @property
    def limits(self) -> BudgetLimits:
        return self._limits

    @classmethod
    def from_records(
        cls,
        records: Sequence[Mapping[str, Any]],
        *,
        overrides: Mapping[str, Any] | None = None,
        operator: str = "cli",
        monotonic: Callable[[], float] = time.monotonic,
    ) -> BudgetLedger:
        ledger = cls(monotonic=monotonic)
        anchor = -1
        for index, record in enumerate(records):
            if record.get("kind") != "run_started":
                continue
            payload = record.get("payload") or {}
            if isinstance(payload.get("budget_opening"), Mapping):
                anchor = index
        if anchor >= 0:
            opening = (records[anchor].get("payload") or {})["budget_opening"]
            ledger._load_snapshot(opening)
            ledger._restore_usage(records[anchor + 1 :], require_phase=True)
            ledger._restore_wall(records[anchor:])
        else:
            ledger._restore_usage(records, require_phase=False)
            ledger._restore_legacy_rounds(records)
            ledger._restore_wall(records)
        for record in records:
            if record.get("kind") != "budget_limit_changed":
                continue
            payload = record.get("payload") or {}
            dimension = payload.get("dimension")
            if dimension in _LIMIT_FIELDS:
                ledger._limits = dataclass_replace(
                    ledger._limits,
                    _LIMIT_FIELDS[str(dimension)],
                    payload.get("new_limit"),
                )
        for dimension, value in (overrides or {}).items():
            ledger.change_limit(dimension, value, operator=operator)
        return ledger

    def _load_snapshot(self, snapshot: Mapping[str, Any]) -> None:
        self._limits = BudgetLimits.from_mapping(snapshot.get("limits") or {})
        self._input_tokens = int(snapshot.get("input_tokens") or 0)
        self._output_tokens = int(snapshot.get("output_tokens") or 0)
        self._estimated_input_tokens = int(snapshot.get("estimated_input_tokens") or 0)
        self._estimated_output_tokens = int(
            snapshot.get("estimated_output_tokens") or 0
        )
        self._unknown_usage_requests = int(snapshot.get("unknown_usage_requests") or 0)
        self._request_count = int(snapshot.get("request_count") or 0)
        self._phase_request_counts = Counter(
            {
                str(key): int(value)
                for key, value in (snapshot.get("phase_request_counts") or {}).items()
            }
        )
        self._rounds = int(snapshot.get("rounds") or 0)
        self._wall_time_seconds = float(snapshot.get("wall_time_seconds") or 0.0)
        self._wall_time_unknown = snapshot.get("wall_time_status") == "unknown"

    def _restore_usage(
        self, records: Sequence[Mapping[str, Any]], *, require_phase: bool
    ) -> None:
        for index, record in enumerate(records):
            if record.get("kind") != "llm_exchange_meta":
                continue
            payload = record.get("payload") or {}
            phase = payload.get("phase")
            if require_phase and phase not in ("main", "scope_compile"):
                continue
            input_tokens = payload.get("prompt_tokens")
            output_tokens = payload.get("response_tokens")
            status = payload.get("measurement_status")
            if status not in _MEASUREMENT_STATUSES:
                status = (
                    "measured"
                    if isinstance(input_tokens, int) and isinstance(output_tokens, int)
                    else "unknown"
                )
            request_id = str(
                payload.get("request_id") or f"legacy-{record.get('seq', index)}"
            )
            self.record_usage(
                Usage(
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    measurement_status=status,
                ),
                request_id=request_id,
                phase=str(phase or "main"),
                provider=str(payload.get("provider") or "unknown"),
                attempt=int(payload.get("attempt") or 0),
                outcome=str(payload.get("outcome") or "legacy"),
            )

    def _restore_legacy_rounds(self, records: Sequence[Mapping[str, Any]]) -> None:
        for record in records:
            if record.get("kind") != "run_finished":
                continue
            payload = record.get("payload") or {}
            if "budget" in payload:
                continue
            rounds = payload.get("rounds")
            if isinstance(rounds, int) and rounds >= 0:
                self._rounds += rounds
            else:
                self._wall_time_unknown = True

    def _restore_wall(self, records: Sequence[Mapping[str, Any]]) -> None:
        starts: dict[str, Mapping[str, Any]] = {}
        anonymous_starts: list[Mapping[str, Any]] = []
        for record in records:
            kind = record.get("kind")
            payload = record.get("payload") or {}
            run_id = payload.get("run_id")
            if kind == "run_started":
                if run_id is None:
                    anonymous_starts.append(record)
                else:
                    starts[str(run_id)] = record
            elif kind == "run_finished":
                if run_id is None:
                    start = anonymous_starts.pop(0) if anonymous_starts else None
                else:
                    start = starts.pop(str(run_id), None)
                if start is None:
                    self._wall_time_unknown = True
                    continue
                elapsed = _elapsed_seconds(str(start.get("ts")), str(record.get("ts")))
                if elapsed is None:
                    self._wall_time_unknown = True
                else:
                    self._wall_time_seconds += elapsed
        if starts or anonymous_starts:
            self._wall_time_unknown = True

    def start_run(self) -> None:
        if self._started_mono is None:
            self._started_mono = self._monotonic()

    def finish_run(self) -> None:
        if self._started_mono is None:
            return
        self._wall_time_seconds += max(0.0, self._monotonic() - self._started_mono)
        self._started_mono = None

    def record_usage(
        self,
        usage: Usage,
        *,
        request_id: str,
        phase: str,
        provider: str,
        attempt: int = 0,
        outcome: str = "completed",
    ) -> None:
        if request_id in self._request_ids:
            return
        self._request_ids.add(request_id)
        self._request_count += 1
        self._phase_request_counts[phase] += 1
        status = usage.measurement_status
        if usage.input_tokens is None or usage.output_tokens is None:
            status = "unknown"
        if status == "unknown":
            self._unknown_usage_requests += 1
        elif status == "estimated":
            self._estimated_input_tokens += usage.input_tokens or 0
            self._estimated_output_tokens += usage.output_tokens or 0
        else:
            self._input_tokens += usage.input_tokens or 0
            self._output_tokens += usage.output_tokens or 0
        if phase == "main" and outcome in _ROUND_OUTCOMES:
            self._rounds += 1

    def snapshot(self, *, context_tokens: int | None = None) -> dict[str, Any]:
        wall_time = self._wall_time_seconds
        if self._started_mono is not None:
            wall_time += max(0.0, self._monotonic() - self._started_mono)
        measured_total = self._input_tokens + self._output_tokens
        estimated_total = self._estimated_input_tokens + self._estimated_output_tokens
        total = (
            None
            if self._unknown_usage_requests
            else measured_total + estimated_total
        )
        measurement = "measured"
        if self._unknown_usage_requests:
            measurement = "unknown"
        elif estimated_total:
            measurement = "estimated"
        return {
            "input_tokens": self._input_tokens,
            "output_tokens": self._output_tokens,
            "estimated_input_tokens": self._estimated_input_tokens,
            "estimated_output_tokens": self._estimated_output_tokens,
            "measured_total_tokens": measured_total,
            "estimated_total_tokens": estimated_total,
            "total_tokens": total,
            "token_status": measurement,
            "unknown_usage_requests": self._unknown_usage_requests,
            "request_count": self._request_count,
            "phase_request_counts": dict(sorted(self._phase_request_counts.items())),
            "rounds": self._rounds,
            "wall_time_seconds": wall_time,
            "wall_time_status": "unknown" if self._wall_time_unknown else "measured",
            "context_tokens_estimated": context_tokens,
            "estimated_cost": None,
            "cost_status": "unknown",
            "limits": self._limits.as_dict(),
        }

    def exhaustion(self, *, context_tokens: int | None = None) -> dict[str, Any] | None:
        snapshot = self.snapshot(context_tokens=context_tokens)
        if (
            context_tokens is not None
            and context_tokens > self._limits.context_tokens
        ):
            return _budget_stop("context", "context_still_too_large", snapshot)
        total_limit = self._limits.total_tokens
        if total_limit is not None:
            if snapshot["total_tokens"] is None:
                return _budget_stop("total_tokens", "token_usage_unknown", snapshot)
            if snapshot["total_tokens"] >= total_limit:
                return _budget_stop("total_tokens", "total_tokens", snapshot)
        if self._limits.rounds is not None and self._rounds >= self._limits.rounds:
            return _budget_stop("rounds", "rounds", snapshot)
        if self._limits.wall_time_seconds is not None:
            if snapshot["wall_time_status"] == "unknown":
                return _budget_stop("wall_time", "wall_time_unknown", snapshot)
            if snapshot["wall_time_seconds"] >= self._limits.wall_time_seconds:
                return _budget_stop("wall_time", "wall_time", snapshot)
        return None

    def approaching(self, *, context_tokens: int | None = None) -> list[str]:
        snapshot = self.snapshot(context_tokens=context_tokens)
        dimensions: list[str] = []
        values = {
            "context": context_tokens,
            "total_tokens": snapshot["total_tokens"],
            "rounds": self._rounds,
            "wall_time": (
                snapshot["wall_time_seconds"]
                if snapshot["wall_time_status"] == "measured"
                else None
            ),
        }
        for dimension, used in values.items():
            field = _LIMIT_FIELDS[dimension]
            limit = getattr(self._limits, field)
            if used is not None and limit is not None and 0.8 * limit <= used < limit:
                dimensions.append(dimension)
        return dimensions

    @staticmethod
    def limit_field(dimension: str) -> str:
        field = _LIMIT_FIELDS.get(dimension)
        if field is None:
            raise ValueError(f"未知预算维度 {dimension!r}")
        return field

    def change_limit(
        self, dimension: str, value: Any, *, operator: str = "operator"
    ) -> dict[str, Any] | None:
        field = self.limit_field(dimension)
        if field == "context_tokens" and value is None:
            raise ValueError("context 容量不能设为不限")
        value = _optional_number(value)
        if value == 0 and field != "context_tokens":
            value = None
        if value is not None and value <= 0:
            raise ValueError("预算上限必须为正；累计维度的 0 表示不限")
        old = getattr(self._limits, field)
        if old == value:
            return None
        direction = (
            "expanded"
            if old is not None and (value is None or value > old)
            else "tightened"
        )
        self._limits = dataclass_replace(self._limits, field, value)
        payload = {
            "dimension": field,
            "old_limit": old,
            "new_limit": value,
            "change": direction,
            "operator": operator,
        }
        self._pending_limit_changes.append(payload)
        return payload

    def pop_limit_changes(self) -> list[dict[str, Any]]:
        changes = self._pending_limit_changes
        self._pending_limit_changes = []
        return changes


def dataclass_replace(limits: BudgetLimits, field: str, value: Any) -> BudgetLimits:
    values = limits.as_dict()
    values[field] = value
    return BudgetLimits.from_mapping(values)


def _budget_stop(
    dimension: str, reason: str, snapshot: Mapping[str, Any]
) -> dict[str, Any]:
    return {"dimension": dimension, "reason": reason, "snapshot": dict(snapshot)}


def _elapsed_seconds(started: str, finished: str) -> float | None:
    try:
        start = datetime.fromisoformat(started)
        finish = datetime.fromisoformat(finished)
    except ValueError:
        return None
    if start.tzinfo is None or finish.tzinfo is None:
        return None
    return max(0.0, (finish - start).total_seconds())


def _format_limit(value: int | float | None, suffix: str = "") -> str:
    return "不限" if value is None else f"{value}{suffix}"


def format_budget(snapshot: Mapping[str, Any]) -> str:
    limits = snapshot["limits"]
    total = snapshot["total_tokens"]
    total_text = "unknown" if total is None else str(total)
    wall = (
        "unknown"
        if snapshot["wall_time_status"] == "unknown"
        else f"{snapshot['wall_time_seconds']:.1f}s"
    )
    return (
        f"tokens {total_text}/{_format_limit(limits['total_tokens'])}"
        f"(实测 {snapshot['measured_total_tokens']} · 估算 "
        f"{snapshot['estimated_total_tokens']} · unknown 请求 "
        f"{snapshot['unknown_usage_requests']}) · "
        f"轮数 {snapshot['rounds']}/{_format_limit(limits['rounds'])} · "
        f"墙钟 {wall}/{_format_limit(limits['wall_time_seconds'], 's')} · "
        "费用 unknown(无本地定价表)"
    )
