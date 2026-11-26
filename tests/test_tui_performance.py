"""R20-A 性能基线与叙述流有界视图回归。

固定合成负载（10,000 事件 = 1,000 轮 × 10 事件/轮）：
每轮向真实 ``MainScreen`` 消息处理链投递：
- 2× ThinkingMsg
- 2× NarrativeMsg
- 1× ToolCallMsg + 1× GuardMsg + 1× ToolResultMsg（含 256B output_view）
- 2× NarrativeMsg
- 1× PhaseMsg（每 50 轮）或 NarrativeMsg

可通过 ``PYTHONPATH=src .venv/bin/python tests/test_tui_performance.py`` 直接运行，
输出单次 10,000 事件基准 JSON 以便对比基线与后续变更。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import platform
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Any

import textual

from foam.agent.backends.base import LLMBackend, Usage
from foam.guard.audit import KIND_EXEC_REQUEST, AuditLog, verify
from foam.guard.scope import parse_scope
from foam.state.files import Engagement
from foam.tui.app import TuiApp, TUIConfig
from foam.tui.bridge import (
    GuardMsg,
    NarrativeMsg,
    PhaseMsg,
    ThinkingMsg,
    ToolCallMsg,
    ToolResultMsg,
)
from foam.tui.widgets import (
    NarrativeView,
    NoticeBlock,
    PhaseDivider,
    ScopeConfirmCard,
    StreamBlock,
    ThinkingBlock,
    ToolCard,
    WelcomeBanner,
)

SYNTHETIC_CYCLES = 1_000
EVENTS_PER_CYCLE = 10
SYNTHETIC_EVENT_COUNT = SYNTHETIC_CYCLES * EVENTS_PER_CYCLE
FIXED_OUTPUT_BYTES = 256
TERMINAL_SIZE = (120, 40)
EXPECTED_TOTAL_BLOCKS = 4_020

_MANAGED_TYPES = (
    StreamBlock,
    ThinkingBlock,
    ToolCard,
    PhaseDivider,
    NoticeBlock,
)


class _BenchmarkBackend(LLMBackend):
    """零网络基准桩后端。"""

    provider = "fake-benchmark"

    async def aclose(self) -> None:
        pass

    def chat(self, messages, tools=None):
        async def _stream():
            yield Usage(1, 1)

        return _stream()


def _managed_dom_widgets(narrative: NarrativeView) -> list[Any]:
    return [w for w in narrative.children if isinstance(w, _MANAGED_TYPES)]


async def run_synthetic_replay_benchmark(
    base_dir: Path,
    *,
    cycles: int = SYNTHETIC_CYCLES,
    yield_every: int = 50,
) -> dict[str, Any]:
    """运行固定合成事件重放并采集耗时、内存、DOM 与输入延迟指标。"""
    cfg = TUIConfig(
        scope=parse_scope("127.0.0.0/8\n"),
        scope_source="synthetic",
        backend=_BenchmarkBackend(),
        model_label="fake-bench",
        engagements_dir=base_dir / "engagements",
        config_home=base_dir / "home",
        wait_on_finish=False,
        show_landing=False,
    )
    app = TuiApp(cfg)
    payload = "x" * FIXED_OUTPUT_BYTES
    digest = "a" * 64

    async with app.run_test(headless=True, size=TERMINAL_SIZE) as pilot:
        await pilot.pause(0.1)
        main = app._main
        assert main is not None
        narrative = main.narrative

        tracemalloc.start()
        try:
            t0 = time.perf_counter()
            events = 0
            for i in range(cycles):
                main.on_thinking_msg(ThinkingMsg(f"plan-{i}-a " + "t" * 48))
                main.on_thinking_msg(ThinkingMsg(f"plan-{i}-b " + "t" * 48))
                main.on_narrative_msg(NarrativeMsg(f"step-{i}-a " + "n" * 48))
                main.on_narrative_msg(NarrativeMsg(f"step-{i}-b " + "n" * 48))
                main.on_tool_call_msg(
                    ToolCallMsg(
                        "run_command",
                        {"command": f"echo probe-{i} 127.0.0.1"},
                    )
                )
                main.on_guard_msg(
                    GuardMsg(
                        allowed=True,
                        targets=["127.0.0.1"],
                        violations=[],
                        reason="ok",
                    )
                )
                main.on_tool_result_msg(
                    ToolResultMsg(
                        "run_command",
                        {
                            "status": "completed",
                            "exit_code": 0,
                            "duration_ms": 12,
                            "total_bytes": FIXED_OUTPUT_BYTES,
                            "output_view": payload,
                            "output_path": f"outputs/job-{i}.log",
                            "sha256": digest,
                        },
                    )
                )
                main.on_narrative_msg(NarrativeMsg(f"done-{i}-a " + "r" * 48))
                main.on_narrative_msg(NarrativeMsg(f"done-{i}-b " + "r" * 48))
                if i % 50 == 0:
                    main.on_phase_msg(PhaseMsg(f"phase-{i // 50}"))
                else:
                    main.on_narrative_msg(NarrativeMsg(f"tail-{i}\n"))
                events += EVENTS_PER_CYCLE
                if yield_every and (i + 1) % yield_every == 0:
                    await asyncio.sleep(0)

            if hasattr(narrative, "flush_pruning"):
                await narrative.flush_pruning()
            await pilot.pause(0.05)
            elapsed_seconds = time.perf_counter() - t0
            current_bytes, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        input_box = main.input_dock.input_box
        input_box.focus()
        latencies_ms: list[float] = []
        for ch in "benchinput":
            ks = time.perf_counter()
            await pilot.press(ch)
            latencies_ms.append((time.perf_counter() - ks) * 1000.0)

        ordered = sorted(latencies_ms)
        p50_ms = ordered[len(ordered) // 2]
        p95_idx = min(len(ordered) - 1, math.ceil(0.95 * len(ordered)) - 1)
        p95_ms = ordered[p95_idx]

        dom_managed = len(_managed_dom_widgets(narrative))
        mounted_blocks = getattr(narrative, "mounted_block_count", dom_managed)
        total_entries = getattr(narrative, "total_entry_count", dom_managed)
        archived_older = getattr(narrative, "archived_older_count", 0)

        return {
            "events": events,
            "cycles": cycles,
            "output_bytes": FIXED_OUTPUT_BYTES,
            "terminal_size": list(TERMINAL_SIZE),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
            "textual_version": textual.__version__,
            "elapsed_seconds": round(elapsed_seconds, 4),
            "current_memory_mb": round(current_bytes / (1024 * 1024), 3),
            "peak_memory_mb": round(peak_bytes / (1024 * 1024), 3),
            "mounted_children": len(narrative.children),
            "mounted_blocks": mounted_blocks,
            "dom_managed_blocks": dom_managed,
            "total_entries": total_entries,
            "archived_older": archived_older,
            "input_latency_ms": [round(v, 3) for v in latencies_ms],
            "input_latency_p50_ms": round(p50_ms, 3),
            "input_latency_p95_ms": round(p95_ms, 3),
            "input_latency_max_ms": round(max(ordered), 3),
        }


async def test_card_window_is_bounded(tmp_path: Path) -> None:
    """R20-AC02：DOM 窗口上限为 200，按 100 条向前加载不丢事件且不删思考红线。"""
    from foam.tui.widgets import (
        DEFAULT_HISTORY_PAGE_SIZE,
        DEFAULT_MAX_MOUNTED_BLOCKS,
        HistoryLoadBar,
    )

    assert DEFAULT_MAX_MOUNTED_BLOCKS == 200
    assert DEFAULT_HISTORY_PAGE_SIZE == 100

    cfg = TUIConfig(
        scope=parse_scope("127.0.0.0/8\n"),
        scope_source="synthetic",
        backend=_BenchmarkBackend(),
        model_label="fake-bench",
        engagements_dir=tmp_path / "engagements",
        config_home=tmp_path / "home",
        wait_on_finish=False,
        show_landing=False,
    )
    app = TuiApp(cfg)
    async with app.run_test(headless=True, size=TERMINAL_SIZE) as pilot:
        await pilot.pause(0.1)
        main = app._main
        assert main is not None
        narrative = main.narrative

        scope_card = ScopeConfirmCard()
        narrative.mount_scope_card(scope_card)

        expected: list[tuple[type, str, bool | None]] = []
        for i in range(100):
            narrative.feed_thinking(f"think-{i:03d}")
            expected.append((ThinkingBlock, f"think-{i:03d}", False))

            narrative.feed_text(f"stream-{i:03d}")
            expected.append((StreamBlock, f"stream-{i:03d}", None))

            exit_code = 2 if i % 10 == 0 else 0
            narrative.open_card(
                "run_command", {"command": f"echo cmd-{i:03d} 127.0.0.1"}
            )
            narrative.close_card(
                "run_command",
                {
                    "status": "completed",
                    "exit_code": exit_code,
                    "duration_ms": 5,
                    "total_bytes": 16,
                    "output_view": f"out-{i:03d}",
                    "output_path": f"outputs/c-{i:03d}.log",
                    "sha256": f"{i:064x}",
                },
            )
            expected.append((ToolCard, f"echo cmd-{i:03d} 127.0.0.1", exit_code != 0))

            narrative.add_phase(f"phase-{i:03d}")
            expected.append((PhaseDivider, f"phase-{i:03d}", None))

            narrative.add_notice("info", f"notice-{i:03d}")
            expected.append((NoticeBlock, f"notice-{i:03d}", None))

        for j in range(20):
            narrative.add_notice("info", f"extra-{j:03d}")
            expected.append((NoticeBlock, f"extra-{j:03d}", None))

        assert len(expected) == 520
        await narrative.flush_pruning()
        await pilot.pause(0.05)

        assert narrative.total_entry_count == 520
        assert narrative.mounted_block_count == 200
        assert narrative.archived_older_count == 320
        assert len(_managed_dom_widgets(narrative)) == 200
        assert main.query_one("#welcome-banner", WelcomeBanner) in narrative.children
        assert scope_card in narrative.children

        bar = narrative.history_bar
        assert isinstance(bar, HistoryLoadBar)
        assert bar in narrative.children
        bar_text = str(bar.content)
        assert "320" in bar_text
        assert "100" in bar_text

        # 通过键盘交互聚焦历史栏并回车加载第一页（100 条）。
        bar.focus()
        await pilot.press("enter")
        await pilot.pause(0.05)
        assert narrative.archived_older_count == 220
        assert narrative.mounted_block_count == 300
        assert len(_managed_dom_widgets(narrative)) == 300

        # 继续加载剩余 320 - 100 = 220 条（100, 100, 20, 0）。
        assert narrative.load_older() == 100
        assert narrative.load_older() == 100
        assert narrative.load_older() == 20
        assert narrative.load_older() == 0
        await pilot.pause(0.05)

        assert narrative.archived_older_count == 0
        assert narrative.mounted_block_count == 520
        assert narrative.history_bar is None
        assert not any(isinstance(w, HistoryLoadBar) for w in narrative.children)

        restored = _managed_dom_widgets(narrative)
        assert len(restored) == 520
        for idx, (widget, (exp_cls, marker, exp_expanded)) in enumerate(
            zip(restored, expected, strict=True)
        ):
            assert isinstance(widget, exp_cls), f"index {idx} type mismatch"
            if exp_cls is ThinkingBlock:
                assert widget.text == marker
                assert widget.done is True
                assert widget.expanded is False
                assert widget._timer is None
            elif exp_cls is StreamBlock:
                assert widget.text == marker
            elif exp_cls is ToolCard:
                assert marker in widget.card_display
                assert widget.running is False
                assert widget.expanded is bool(exp_expanded)
                assert widget._timer is None
            elif exp_cls is PhaseDivider:
                assert widget.phase == marker
            elif exp_cls is NoticeBlock:
                assert marker in str(widget.content)

        # 守住思考内容不落明文盘红线：tmp_path 下无思考文本文件。
        for file_path in tmp_path.rglob("*"):
            if file_path.is_file():
                assert "think-000" not in file_path.read_text(
                    encoding="utf-8", errors="ignore"
                )

        # 收起历史窗口后回到最近 200 条。
        collapsed = narrative.collapse_history()
        await narrative.flush_pruning()
        await pilot.pause(0.05)
        assert collapsed == 320
        assert narrative.mounted_block_count == 200
        assert narrative.archived_older_count == 320
        assert len(_managed_dom_widgets(narrative)) == 200
        assert narrative.history_bar is not None


async def test_small_session_has_no_history_bar(tmp_path: Path) -> None:
    """短会话不超过上限时不挂载历史加载栏。"""
    from foam.tui.widgets import HistoryLoadBar

    cfg = TUIConfig(
        scope=parse_scope("127.0.0.0/8\n"),
        scope_source="synthetic",
        backend=_BenchmarkBackend(),
        model_label="fake-bench",
        engagements_dir=tmp_path / "engagements",
        config_home=tmp_path / "home",
        wait_on_finish=False,
        show_landing=False,
    )
    app = TuiApp(cfg)
    async with app.run_test(headless=True, size=TERMINAL_SIZE) as pilot:
        await pilot.pause(0.1)
        main = app._main
        assert main is not None
        narrative = main.narrative
        for i in range(10):
            narrative.add_notice("info", f"short-{i}")
        await narrative.flush_pruning()
        await pilot.pause(0.05)

        assert narrative.total_entry_count == 10
        assert narrative.mounted_block_count == 10
        assert narrative.archived_older_count == 0
        assert narrative.history_bar is None
        assert not any(isinstance(w, HistoryLoadBar) for w in narrative.children)


async def test_pruning_preserves_disk_evidence_and_audit(tmp_path: Path) -> None:
    """UI 窗口裁剪绝不删除或修改审计链与落盘输出产物。"""
    engagement = Engagement.create(tmp_path, "evidence preservation test")
    audit = AuditLog(engagement.paths.audit_jsonl)
    sample_output = engagement.paths.outputs / "sample.log"
    sample_bytes = b"port 80/tcp open http\n"
    sample_output.write_bytes(sample_bytes)
    sample_sha = hashlib.sha256(sample_bytes).hexdigest()
    audit.append(
        KIND_EXEC_REQUEST,
        {"command": "echo scan 127.0.0.1", "targets": ["127.0.0.1"]},
    )
    audit.close()

    audit_before = engagement.paths.audit_jsonl.read_bytes()
    output_before = sample_output.read_bytes()

    cfg = TUIConfig(
        scope=parse_scope("127.0.0.0/8\n"),
        scope_source="synthetic",
        backend=_BenchmarkBackend(),
        model_label="fake-bench",
        engagements_dir=tmp_path,
        config_home=tmp_path / "home",
        wait_on_finish=False,
        show_landing=False,
    )
    app = TuiApp(cfg)
    async with app.run_test(headless=True, size=TERMINAL_SIZE) as pilot:
        await pilot.pause(0.1)
        bounded = NarrativeView(max_mounted=20, history_page_size=10)
        assert app._main is not None
        await app._main.mount(bounded)
        for i in range(60):
            bounded.open_card("run_command", {"command": f"echo scan-{i} 127.0.0.1"})
            bounded.close_card(
                "run_command",
                {
                    "status": "completed",
                    "exit_code": 0,
                    "duration_ms": 3,
                    "total_bytes": len(sample_bytes),
                    "output_view": sample_bytes.decode("utf-8"),
                    "output_path": str(sample_output),
                    "sha256": sample_sha,
                },
            )
        await bounded.flush_pruning()
        await pilot.pause(0.05)

        assert bounded.mounted_block_count == 20
        assert bounded.archived_older_count == 40

    assert engagement.paths.audit_jsonl.read_bytes() == audit_before
    assert sample_output.read_bytes() == output_before
    assert verify(engagement.paths.audit_jsonl) is True
    engagement.close()


async def test_synthetic_10000_event_replay_records_metrics(tmp_path: Path) -> None:
    """R20-AC01/AC02：固定 10,000 合成事件重放记录耗时、内存与输入延迟。"""
    from foam.tui.widgets import DEFAULT_MAX_MOUNTED_BLOCKS

    metrics = await run_synthetic_replay_benchmark(tmp_path, cycles=SYNTHETIC_CYCLES)
    assert metrics["events"] == SYNTHETIC_EVENT_COUNT
    assert metrics["total_entries"] == EXPECTED_TOTAL_BLOCKS
    assert metrics["mounted_blocks"] == DEFAULT_MAX_MOUNTED_BLOCKS
    assert metrics["dom_managed_blocks"] == DEFAULT_MAX_MOUNTED_BLOCKS
    assert (
        metrics["archived_older"] == EXPECTED_TOTAL_BLOCKS - DEFAULT_MAX_MOUNTED_BLOCKS
    )
    assert metrics["elapsed_seconds"] > 0
    assert metrics["peak_memory_mb"] > 0
    assert len(metrics["input_latency_ms"]) == 10
    assert metrics["input_latency_p50_ms"] > 0
    assert metrics["input_latency_p95_ms"] > 0
    assert metrics["input_latency_max_ms"] >= metrics["input_latency_p95_ms"]


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        metrics = asyncio.run(run_synthetic_replay_benchmark(Path(td)))
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
