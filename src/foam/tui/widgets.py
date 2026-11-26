"""主界面组件(WP-09):工具卡紧凑流、折叠思考块、阶段分隔条、侧栏、输入坞。

观感纪律(规格 + 2026-08-22 定案):

- 工具卡紧凑流(Q2):运行中 spinner + 命令一行;完成折叠为
  「文字标记 + 命令 + 状态摘要」一行;Enter/点击展开 WP-01 head+tail 截断视图;
  护栏拒绝 / 非零退出 / 错误 / 待输入提示一律自动展开。
- 思考块(Q6):动态旋转指示 + 流式微缩预览(最多 3 行),完成后默认折叠为
  「▸ 思考 Ns · M 字符 · 摘要」,Enter/点击展开原文。
- 语义色 + 文字标记双通道(D4):不只靠颜色传达状态。
- 模型文本一律 ``markup=False`` 渲染(方括号等内容不得被当作 console 标记)。

挂载时序约定:textual 的 ``mount()`` 异步完成(compose 子节点稍后才有),
因此可交互组件一律走「状态先进内存、``_ready`` 后才落 DOM」模式——
消息处理函数里 mount 完立刻 feed/finalize 也安全。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import Click
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Button, Input, Label, ListItem, ListView, Static

from foam import __app_name__
from foam.agent.scope_compiler import ScopeCompilation
from foam.tui.banner import render_animated_wordmark
from foam.tui.bridge import tool_call_display

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 展示辅助
# ---------------------------------------------------------------------------

#: spinner 帧(braille 逐帧旋转;仅运行中卡片使用)。
_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
#: 卡片头命令展示上限:一行预算 ≈ 主区宽(≥108)− 标记 − 摘要(~22 列),
#: 超长此限的命令截断显示,全文在展开体/落盘文件。
_CARD_DISPLAY_LIMIT = 88
#: 卡片展开体字符上限(模型视图已被 WP-01 head+tail 截断,这里再兜一道)。
_CARD_BODY_LIMIT = 6_000


def format_bytes(n: int | None) -> str:
    """字节数的人性化格式(卡片摘要/侧栏用)。"""
    if n is None:
        return "-"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(value)}{unit}"
            return f"{value:.1f}{unit}"
        value /= 1024
    return f"{n}B"  # pragma: no cover - 不可达


def format_tokens(n: int) -> str:
    """token 估算值的紧凑格式:12345 → 12.3k。"""
    if n >= 1000:
        return f"{n / 1000:.1f}k"
    return str(n)


def format_duration_ms(ms: int | None) -> str:
    if ms is None:
        return "-"
    return f"{ms / 1000:.1f}s"


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


# ---------------------------------------------------------------------------
# 叙述流块:模型正文 / 思考 / 阶段分隔 / 通知 / 插话
# ---------------------------------------------------------------------------


class StreamBlock(Static):
    """模型正文流式块:增量累积,纯文本渲染(markup 关闭)。"""

    def __init__(self, text: str = "") -> None:
        super().__init__(text, markup=False, classes="stream")
        self._text = text

    @property
    def text(self) -> str:
        return self._text

    def feed(self, delta: str) -> None:
        self._text += delta
        self.update(self._text)  # update 在挂载前调用安全(只写内容置脏)


_THINKING_SPINNER = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
_THINKING_TICK_SECONDS = 0.10


def _thinking_preview_lines(
    text: str, *, max_lines: int = 3, max_chars: int = 76
) -> str:
    """提取思考流尾部最多 ``max_lines`` 非空行供实时预览;末行附 `↳` 前缀。"""
    if not text.strip():
        return ""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    tail = lines[-max_lines:]
    rendered: list[str] = []
    for idx, line in enumerate(tail):
        if idx == len(tail) - 1:
            clipped = (
                "…" + line[-(max_chars - 1) :]
                if len(line) > max_chars
                else line
            )
            rendered.append(f"↳ {clipped}")
        else:
            clipped = (
                line[: max_chars - 1] + "…"
                if len(line) > max_chars
                else line
            )
            rendered.append(f"  {clipped}")
    return "\n".join(rendered)


def _thinking_summary_excerpt(text: str, max_chars: int = 28) -> str:
    """将思考内容压成单行短摘要供完成折叠态头部展示。"""
    collapsed = " ".join(text.split())
    if not collapsed:
        return ""
    if len(collapsed) <= max_chars:
        return collapsed
    return collapsed[: max_chars - 1] + "…"


def _render_thinking_header(
    *,
    done: bool,
    expanded: bool,
    elapsed: float,
    chars: int,
    tick: int,
    text: str,
) -> Text:
    """渲染 ThinkingBlock 标题行(全程用 Text.append 免疫 Rich markup 注入)。"""
    out = Text()
    if not done:
        spinner = _THINKING_SPINNER[tick % len(_THINKING_SPINNER)]
        out.append(f"{spinner} ", style="bold #56d4dd")
        wave = tick % 6
        for i, ch in enumerate("思考中"):
            if i == wave:
                style = "bold #e6edf3"
            elif abs(i - wave) == 1:
                style = "#56d4dd"
            else:
                style = "#8b949e"
            out.append(ch, style=style)
        dots = "." * ((tick // 3) % 4)
        out.append(f"{dots:<3}", style="#56d4dd")
        out.append(f" {elapsed:.1f}s · {chars} 字符", style="#8b949e")
        out.append("  [Enter 收起]" if expanded else "  [Enter 展开全文]", style="dim")
        return out

    out.append("▾ " if expanded else "▸ ", style="#56d4dd")
    out.append(f"思考 {elapsed:.1f}s · {chars} 字符", style="#8b949e")
    if not expanded:
        excerpt = _thinking_summary_excerpt(text, 28)
        if excerpt:
            out.append(f" · {excerpt}", style="dim italic")
    out.append("  [Enter 收起]" if expanded else "  [Enter 展开]", style="dim")
    return out


class ThinkingBlock(Vertical):
    """动态思考块:生成期显示旋转指示与实时尾部预览,结束后折叠为摘要一行。

    内容只进界面与 loop 的审计哈希,不落任何明文文件。
    """

    can_focus = True
    BINDINGS = [Binding("enter", "toggle", "展开/折叠思考", show=False)]

    def __init__(
        self,
        *,
        text: str = "",
        done: bool = False,
        elapsed: float = 0.0,
        expanded: bool = False,
    ) -> None:
        classes = "thinking done" if done else "thinking active"
        super().__init__(classes=classes)
        self._text = text
        self._started = time.monotonic()
        self._elapsed = elapsed
        self._done = done
        self._expanded = expanded
        self._ready = False
        self._tick = 0
        self._timer = None

    def compose(self):
        yield Static(classes="thinking-header")
        yield Static("", markup=False, classes="thinking-preview")
        yield Static("", markup=False, classes="thinking-body")

    def on_mount(self) -> None:
        if self._pruning:
            return
        self._ready = True
        if not self._done:
            self._timer = self.set_interval(_THINKING_TICK_SECONDS, self._on_tick)
        else:
            self.remove_class("active", "pulse")
            self.add_class("done")
        self._redraw()

    def stop_timers(self) -> None:
        """停止思考流定时器（卸载与窗口裁剪前调用）。"""
        if self._timer is not None:
            self._timer.stop()
            self._timer = None

    def on_unmount(self) -> None:
        self.stop_timers()

    @property
    def text(self) -> str:
        return self._text

    @property
    def done(self) -> bool:
        return self._done

    @property
    def elapsed(self) -> float:
        return self._elapsed

    @property
    def expanded(self) -> bool:
        return self._expanded

    def _on_tick(self) -> None:
        if self._done:
            self.stop_timers()
            return
        self._tick += 1
        self.set_class((self._tick // 5) % 2 == 1, "pulse")
        self._redraw()

    def feed(self, delta: str) -> None:
        self._text += delta
        self._redraw()

    def finish(self) -> None:
        """思考流结束(后续出现正文/工具等其他事件时由叙述流调用)。"""
        if self._done:
            return
        self._done = True
        self._elapsed = time.monotonic() - self._started
        self.stop_timers()
        self.remove_class("active", "pulse")
        self.add_class("done")
        self._redraw()

    def _redraw(self) -> None:
        if not self._ready or self._pruning:
            return
        elapsed = (
            self._elapsed if self._done else time.monotonic() - self._started
        )
        self.query_one(".thinking-header", Static).update(
            _render_thinking_header(
                done=self._done,
                expanded=self._expanded,
                elapsed=elapsed,
                chars=len(self._text),
                tick=self._tick,
                text=self._text,
            )
        )
        preview_text = (
            _thinking_preview_lines(self._text)
            if not self._done and not self._expanded
            else ""
        )
        preview = self.query_one(".thinking-preview", Static)
        preview.update(preview_text)
        preview.display = bool(preview_text)
        body = self.query_one(".thinking-body", Static)
        body.update(self._text)
        body.display = self._expanded

    def action_toggle(self) -> None:
        self._expanded = not self._expanded
        self._redraw()

    def on_click(self, event: Click) -> None:
        event.stop()
        self.action_toggle()


class PhaseDivider(Static):
    """阶段分隔条(Q3):ENGAGEMENT.md 阶段字段变化时由主界面挂载。"""

    def __init__(self, phase: str) -> None:
        super().__init__(f"── {phase} ──", classes="phase-divider")
        self.phase = phase


#: 通知/事件块的「文字标记 + CSS 类」双通道表(D4)。
_NOTICE_KINDS: dict[str, tuple[str, str]] = {
    "correction": ("⚠", "warn"),
    "retry": ("↻", "warn"),
    "compressed": ("▣", "dim"),
    "error": ("✗", "fail"),
    "info": ("ℹ", "dim"),
    "help": ("?", "phase"),
    "success": ("✓", "ok"),
    "objective": ("❯", "blue"),
    "interject": ("❯", "blue"),
    "final": ("─", "phase"),
}


class NoticeBlock(Static):
    """叙述流里的单行/多行事件块(纠正、重试、压缩、插话回显、帮助等)。"""

    def __init__(self, kind: str, text: str) -> None:
        marker, tone = _NOTICE_KINDS.get(kind, ("·", "dim"))
        super().__init__(
            f"{marker} {text}", markup=False, classes=f"notice {tone} {kind}"
        )
        self.kind = kind


# ---------------------------------------------------------------------------
# 工具卡(Q2 紧凑流)
# ---------------------------------------------------------------------------


def summarize_result(name: str, result: dict[str, Any]) -> tuple[str, str, str, bool]:
    """工具结果 → (文字标记, 色调类, 一行摘要, 是否自动展开)。

    自动展开(Q2):护栏拒绝 / 非零退出 / error 字段 / 会话待输入提示。
    """
    if result.get("status") == "denied_by_scope_guard":
        violations = "、".join(str(v) for v in result.get("violations", []))
        return "⊘", "denied", f"护栏拒绝:越界目标 {violations}", True
    if "error" in result:
        return "✗", "fail", f"error: {_clip(str(result['error']), 80)}", True
    if name == "run_command":
        status = str(result.get("status", ""))
        exit_code = result.get("exit_code")
        duration = format_duration_ms(result.get("duration_ms"))
        size = format_bytes(result.get("total_bytes"))
        if status == "completed" and exit_code == 0:
            return "✓", "ok", f"exit 0 · {duration} · {size}", False
        if status == "timeout":
            reason = result.get("timeout_reason") or "wall_clock_deadline"
            deadline = result.get("timeout_seconds")
            detail = f" · deadline {deadline}s" if deadline is not None else ""
            return (
                "⏱",
                "warn",
                f"超时强杀({reason}){detail} · {duration} · {size}",
                True,
            )
        if status == "killed":
            return "⚠", "warn", f"被终止 · {duration} · {size}", True
        note = result.get("exit_note") or ""
        summary = f"exit {exit_code} · {duration} · {size}"
        if note:
            summary += f"({_clip(str(note), 40)})"
        return "✗", "fail", summary, True
    if name == "read_output":
        more = ",还有" if result.get("has_more") else ""
        return (
            "✓",
            "ok",
            f"{format_bytes(result.get('bytes_read'))} "
            f"@ {result.get('offset', 0)}{more}",
            False,
        )
    if name == "list_jobs":
        return "✓", "ok", f"{result.get('count', 0)} 个 job", False
    if name == "session_open":
        return "✓", "ok", f"会话 {result.get('session_id')} 已开", False
    if name == "session_read":
        events = result.get("events") or []
        if events:
            kinds = "、".join(str(e.get("type", "?")) for e in events)
            return "⏳", "warn", f"会话等待输入({kinds})", True
        return (
            "✓",
            "ok",
            f"{format_bytes(result.get('new_bytes'))} 新输出",
            False,
        )
    if name == "session_send":
        return "✓", "ok", f"已写入 {result.get('session_id', '?')}", False
    if name == "session_close":
        return "✓", "ok", f"会话 {result.get('session_id')} 已关", False
    if name == "session_list":
        return "✓", "ok", f"{result.get('count', 0)} 个会话", False
    if name == "state_query":
        return "✓", "ok", f"{result.get('total', 0)} 行", False
    if name in ("state_add_note", "state_add_loot"):
        return "✓", "ok", "已记录", False
    return "✓", "ok", "完成", False


def build_card_body(name: str, result: dict[str, Any]) -> str:
    """卡片展开体:优先 WP-01 截断视图,其余工具给紧凑 JSON(双截断兜底)。"""
    parts: list[str] = []
    if result.get("status") == "denied_by_scope_guard":
        parts.append(str(result.get("reason", "")))
    if isinstance(result.get("output_view"), str) and result["output_view"]:
        parts.append(str(result["output_view"]))
    elif isinstance(result.get("text"), str) and result["text"]:
        parts.append(str(result["text"]))
    elif isinstance(result.get("new_output"), str) and result["new_output"]:
        parts.append(str(result["new_output"]))
    if not parts:
        parts.append(json.dumps(result, ensure_ascii=False, indent=2))
    meta: list[str] = []
    if result.get("output_path"):
        meta.append(f"落盘 {result['output_path']}")
    if result.get("sha256"):
        meta.append(f"sha256:{str(result['sha256'])[:12]}…")
    if result.get("exit_note"):
        meta.append(str(result["exit_note"]))
    body = "\n".join(parts)
    if meta:
        body += "\n[" + " · ".join(meta) + "]"
    if len(body) > _CARD_BODY_LIMIT:
        body = body[:_CARD_BODY_LIMIT] + "\n…(卡片内截断,完整内容见落盘文件)…"
    return body


class ToolCard(Vertical):
    """工具卡:运行中 spinner 一行 → 完成折叠一行;Enter/点击展开。"""

    can_focus = True
    BINDINGS = [Binding("enter", "toggle", "展开/折叠", show=False)]

    def __init__(self, name: str, display: str) -> None:
        super().__init__(classes="toolcard running")
        self.tool_name = name
        self.card_display = _clip(display, _CARD_DISPLAY_LIMIT)
        # 注意:不能叫 _running——那是 textual MessagePump 的泵状态字段,
        # 挂载时会被框架覆写(实测:finalize 先于 mount 完成时被盖回 True)。
        self._spinning = True
        self._expanded = False
        #: 护栏拒绝时由主界面置 True(on_guard 先于结果到达),自动展开。
        self.force_expand = False
        self._ready = False
        self._timer = None
        self._frame = 0
        self._tone = "running"
        self._output_path: str | None = None
        self._sha256: str | None = None
        self.summary = ""
        self._header = f"⠋ {self.card_display}"
        self._body = ""

    @classmethod
    def from_archive(
        cls,
        *,
        name: str,
        display: str,
        tone: str,
        summary: str,
        header: str,
        body: str,
        expanded: bool,
        force_expand: bool = False,
        output_path: str | None = None,
        sha256: str | None = None,
    ) -> ToolCard:
        """从归档记录重建已完成工具卡（不启动 spinner 定时器）。"""
        card = cls.__new__(cls)
        classes = f"toolcard {tone}" + (" expanded" if expanded else "")
        Vertical.__init__(card, classes=classes)
        card.tool_name = name
        card.card_display = display
        card._spinning = False
        card._expanded = expanded
        card.force_expand = force_expand
        card._ready = False
        card._timer = None
        card._frame = 0
        card._tone = tone
        card._output_path = output_path
        card._sha256 = sha256
        card.summary = summary
        card._header = header
        card._body = body
        return card

    def compose(self):
        yield Static(self._header, classes="card-header")
        yield Static("", markup=False, classes="card-body")

    def on_mount(self) -> None:
        if self._pruning:
            return
        self._ready = True
        self._redraw()
        if self._spinning:
            self._timer = self.set_interval(0.12, self._spin)

    def stop_timers(self) -> None:
        """停止卡片旋转定时器（卸载与窗口裁剪前调用）。"""
        if self._timer is not None:
            self._timer.stop()
            self._timer = None

    def on_unmount(self) -> None:
        self.stop_timers()

    @property
    def running(self) -> bool:
        return self._spinning

    @property
    def expanded(self) -> bool:
        return self._expanded

    def _redraw(self) -> None:
        if not self._ready or self._pruning:
            return
        self.query_one(".card-header", Static).update(self._header)
        body = self.query_one(".card-body", Static)
        body.update(self._body)
        body.display = self._expanded

    def _spin(self) -> None:
        if not self._spinning:
            return  # finalize 后滞留在消息队列里的最后一帧不得盖回 spinner
        frame = _SPINNER_FRAMES[self._frame % len(_SPINNER_FRAMES)]
        self._frame += 1
        self._header = f"{frame} {self.card_display}"
        self._redraw()

    def finalize(self, result: dict[str, Any]) -> None:
        """收卡:停 spinner、折叠为一行摘要,异常自动展开。"""
        self._spinning = False
        self.stop_timers()
        marker, tone, summary, auto_expand = summarize_result(self.tool_name, result)
        self._tone = tone
        self.summary = summary
        self._output_path = (
            str(result["output_path"]) if result.get("output_path") else None
        )
        self._sha256 = str(result["sha256"]) if result.get("sha256") else None
        self.remove_class("running")
        self.add_class(tone)
        self._header = f"{marker} {self.card_display} — {summary}"
        self._body = build_card_body(self.tool_name, result)
        self._expanded = bool(auto_expand or self.force_expand)
        self.set_class(self._expanded, "expanded")
        self._redraw()

    def action_toggle(self) -> None:
        if not self._spinning:
            self._expanded = not self._expanded
            self.set_class(self._expanded, "expanded")
            self._redraw()

    def on_click(self, event: Click) -> None:
        event.stop()
        self.action_toggle()


# ---------------------------------------------------------------------------
# 叙述流容器（R20-A: 有界 UI 实例窗口 + 按需向前加载）
# ---------------------------------------------------------------------------

#: 叙述流默认保留的最近受管块数量上限。
DEFAULT_MAX_MOUNTED_BLOCKS = 200
#: 按需向前加载历史时的默认单页条数。
DEFAULT_HISTORY_PAGE_SIZE = 100


@dataclass
class NarrativeEntry:
    """叙述流中单条受管块的内存归档记录（思考文本绝不落明文盘）。"""

    seq: int
    kind: str  # "stream" | "thinking" | "tool" | "phase" | "notice"
    text: str = ""
    done: bool = True
    elapsed: float = 0.0
    expanded: bool = False
    tool_name: str = ""
    display: str = ""
    tone: str = "running"
    summary: str = ""
    header: str = ""
    body: str = ""
    running: bool = False
    force_expand: bool = False
    output_path: str | None = None
    sha256: str | None = None
    phase: str = ""
    notice_kind: str = "info"


class HistoryLoadBar(Static):
    """归档历史按需加载栏:显示已归档条数,Enter 或点击向前加载一页。"""

    can_focus = True
    BINDINGS = [Binding("enter", "load_older", "加载更早历史", show=False)]

    def __init__(self) -> None:
        super().__init__("", markup=False, classes="history-load-bar")

    def update_counts(
        self, hidden: int, page_size: int, max_mounted: int
    ) -> None:
        next_batch = min(hidden, page_size)
        self.update(
            f"▲ 另有 {hidden} 条更早记录已归档"
            f"（视图保留最近 {max_mounted} 条；"
            f"Enter / 点击加载前 {next_batch} 条）"
        )

    def action_load_older(self) -> None:
        if isinstance(self.parent, NarrativeView):
            self.parent.load_older()

    def on_click(self, event: Click) -> None:
        event.stop()
        self.action_load_older()


class NarrativeView(VerticalScroll):
    """主区叙述流:管理「当前正文块 / 当前思考块 / 在飞工具卡」与有界 DOM 窗口。

    loop 单线程语义保证任何时刻至多一张在飞工具卡(逐个执行);思考块与
    正文块互斥——任一其他事件到达都会为思考块收尾。受管块超出窗口上限时
    自动从顶部卸载旧 UI 实例并保留内存归档记录，可通过顶部提示栏按需加载；
    裁剪绝不删除底层审计或落盘工具产物，也不把思考文本落盘。
    """

    def __init__(
        self,
        *,
        max_mounted: int = DEFAULT_MAX_MOUNTED_BLOCKS,
        history_page_size: int = DEFAULT_HISTORY_PAGE_SIZE,
    ) -> None:
        if max_mounted < 1:
            raise ValueError("max_mounted 必须大于等于 1")
        if history_page_size < 1:
            raise ValueError("history_page_size 必须大于等于 1")
        super().__init__(id="narrative")
        self._max_mounted = int(max_mounted)
        self._history_page_size = int(history_page_size)
        self._live_window_limit = self._max_mounted
        self._entries: list[NarrativeEntry] = []
        self._mounted: deque[tuple[NarrativeEntry, Widget]] = deque()
        self._window_start = 0
        self._next_seq = 1
        self._history_bar: HistoryLoadBar | None = None
        self._pending_removals: list[Widget] = []
        self._inflight_remove_tasks: set[asyncio.Task[None]] = set()

        self.stream: StreamBlock | None = None
        self.thinking: ThinkingBlock | None = None
        self.pending_card: ToolCard | None = None
        self._stream_entry: NarrativeEntry | None = None
        self._thinking_entry: NarrativeEntry | None = None
        self._pending_entry: NarrativeEntry | None = None

    def on_mount(self) -> None:
        if self._pending_removals:
            self._dispatch_removals()

    @property
    def max_mounted(self) -> int:
        return self._max_mounted

    @property
    def history_page_size(self) -> int:
        return self._history_page_size

    @property
    def mounted_block_count(self) -> int:
        return len(self._mounted)

    @property
    def archived_older_count(self) -> int:
        return self._window_start

    @property
    def total_entry_count(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> list[NarrativeEntry]:
        return list(self._entries)

    @property
    def mounted_blocks(self) -> list[Widget]:
        return [widget for _, widget in self._mounted]

    @property
    def history_bar(self) -> HistoryLoadBar | None:
        return self._history_bar

    def _new_entry(self, kind: str, **fields: Any) -> NarrativeEntry:
        entry = NarrativeEntry(seq=self._next_seq, kind=kind, **fields)
        self._next_seq += 1
        return entry

    def _mount_block(self, widget: Widget) -> None:
        self.mount(widget)
        self.call_after_refresh(self._scroll_to_end)

    def _mount_managed(self, entry: NarrativeEntry, widget: Widget) -> None:
        self._entries.append(entry)
        self._mounted.append((entry, widget))
        self._mount_block(widget)
        self._trim_mounted()

    @staticmethod
    def _sync_entry_from_widget(entry: NarrativeEntry, widget: Widget) -> None:
        if isinstance(widget, StreamBlock):
            entry.text = widget.text
        elif isinstance(widget, ThinkingBlock):
            entry.text = widget.text
            entry.done = widget.done
            entry.elapsed = widget.elapsed
            entry.expanded = widget.expanded
        elif isinstance(widget, ToolCard):
            entry.tool_name = widget.tool_name
            entry.display = widget.card_display
            entry.tone = widget._tone
            entry.summary = widget.summary
            entry.header = widget._header
            entry.body = widget._body
            entry.running = widget.running
            entry.expanded = widget.expanded
            entry.force_expand = widget.force_expand
            entry.output_path = widget._output_path
            entry.sha256 = widget._sha256

    @staticmethod
    def _build_widget(entry: NarrativeEntry) -> Widget:
        if entry.kind == "stream":
            return StreamBlock(entry.text)
        if entry.kind == "thinking":
            return ThinkingBlock(
                text=entry.text,
                done=entry.done,
                elapsed=entry.elapsed,
                expanded=entry.expanded,
            )
        if entry.kind == "tool":
            return ToolCard.from_archive(
                name=entry.tool_name,
                display=entry.display,
                tone=entry.tone,
                summary=entry.summary,
                header=entry.header,
                body=entry.body,
                expanded=entry.expanded,
                force_expand=entry.force_expand,
                output_path=entry.output_path,
                sha256=entry.sha256,
            )
        if entry.kind == "phase":
            return PhaseDivider(entry.phase)
        return NoticeBlock(entry.notice_kind, entry.text)

    def _dispatch_removals(self) -> None:
        if not self.is_mounted or not self._pending_removals:
            return
        batch = [w for w in self._pending_removals if w.parent is self]
        self._pending_removals.clear()
        if not batch:
            return
        await_remove = self.remove_children(batch)
        try:
            task = asyncio.create_task(self._await_remove(await_remove))
        except RuntimeError:
            return
        self._inflight_remove_tasks.add(task)
        task.add_done_callback(self._inflight_remove_tasks.discard)

    @staticmethod
    async def _await_remove(await_remove: Any) -> None:
        try:
            await await_remove
        except Exception as exc:
            logger.debug("卸载归档组件收尾异常: %r", exc)

    async def flush_pruning(self) -> None:
        """等待所有待卸载旧卡片与历史提示栏从 DOM 移除完成。"""
        self._dispatch_removals()
        while self._inflight_remove_tasks:
            tasks = list(self._inflight_remove_tasks)
            await asyncio.gather(*tasks, return_exceptions=True)
            self._dispatch_removals()

    def _sync_history_bar(self) -> None:
        hidden = self._window_start
        if hidden > 0:
            if self._history_bar is None:
                if not self._mounted:
                    return
                bar = HistoryLoadBar()
                self._history_bar = bar
                self.mount(bar, before=self._mounted[0][1])
            self._history_bar.update_counts(
                hidden, self._history_page_size, self._max_mounted
            )
            return
        if self._history_bar is not None:
            old_bar = self._history_bar
            self._history_bar = None
            self._pending_removals.append(old_bar)
            self._dispatch_removals()

    def _trim_mounted(self) -> int:
        removed = 0
        while len(self._mounted) > self._live_window_limit:
            oldest_entry, oldest_widget = self._mounted[0]
            if oldest_widget in (self.stream, self.thinking, self.pending_card):
                break
            self._mounted.popleft()
            self._window_start += 1
            self._sync_entry_from_widget(oldest_entry, oldest_widget)
            if hasattr(oldest_widget, "stop_timers"):
                oldest_widget.stop_timers()
            self._pending_removals.append(oldest_widget)
            removed += 1
        if removed:
            self._dispatch_removals()
        self._sync_history_bar()
        return removed

    def load_older(self, limit: int | None = None) -> int:
        """从内存归档向前加载一页已卸载块到顶部历史栏下方，返回加载条数。"""
        if self._window_start <= 0:
            return 0
        page = (
            self._history_page_size
            if limit is None
            else max(1, int(limit))
        )
        new_start = max(0, self._window_start - page)
        slice_entries = self._entries[new_start : self._window_start]
        if not slice_entries:
            return 0
        restored = [
            (entry, self._build_widget(entry)) for entry in slice_entries
        ]
        widgets = [widget for _, widget in restored]
        if self._mounted:
            self.mount(*widgets, before=self._mounted[0][1])
        else:
            self.mount(*widgets)
        for entry, widget in reversed(restored):
            self._mounted.appendleft((entry, widget))
        self._window_start = new_start
        self._live_window_limit = max(
            self._live_window_limit, len(self._mounted)
        )
        self._sync_history_bar()
        return len(restored)

    def collapse_history(self) -> int:
        """将已展开的历史窗口重新收窄到默认最近上限，返回卸载条数。"""
        self._live_window_limit = self._max_mounted
        return self._trim_mounted()

    def _scroll_to_end(self) -> None:
        self.scroll_end(animate=False)

    def _close_thinking(self) -> None:
        if self.thinking is not None:
            self.thinking.finish()
            if self._thinking_entry is not None:
                self._sync_entry_from_widget(self._thinking_entry, self.thinking)
            self.thinking = None
            self._thinking_entry = None

    def feed_text(self, delta: str) -> None:
        self._close_thinking()
        if self.stream is None:
            self.stream = StreamBlock()
            entry = self._new_entry("stream")
            self._stream_entry = entry
            self._mount_managed(entry, self.stream)
        self.stream.feed(delta)
        if self._stream_entry is not None:
            self._stream_entry.text = self.stream.text
        self.call_after_refresh(self._scroll_to_end)

    def feed_thinking(self, delta: str) -> None:
        self.stream = None
        self._stream_entry = None
        if self.thinking is None:
            self.thinking = ThinkingBlock()
            entry = self._new_entry("thinking", done=False)
            self._thinking_entry = entry
            self._mount_managed(entry, self.thinking)
        self.thinking.feed(delta)
        if self._thinking_entry is not None:
            self._thinking_entry.text = self.thinking.text
        self.call_after_refresh(self._scroll_to_end)

    def open_card(self, name: str, arguments: dict[str, Any]) -> ToolCard:
        self.stream = None
        self._stream_entry = None
        self._close_thinking()
        card = ToolCard(name, tool_call_display(name, arguments))
        entry = self._new_entry(
            "tool",
            tool_name=name,
            display=card.card_display,
            header=card._header,
            running=True,
        )
        self.pending_card = card
        self._pending_entry = entry
        self._mount_managed(entry, card)
        return card

    def close_card(self, name: str, result: dict[str, Any]) -> ToolCard | None:
        card = self.pending_card
        entry = self._pending_entry
        self.pending_card = None
        self._pending_entry = None
        if card is None:
            return None  # 契约外序列(如无卡结果):调用方落通知块,不炸渲染
        card.finalize(result)
        if entry is not None:
            self._sync_entry_from_widget(entry, card)
        self.call_after_refresh(self._scroll_to_end)
        return card

    def mark_pending_denied(self) -> None:
        if self.pending_card is not None:
            self.pending_card.force_expand = True
        if self._pending_entry is not None:
            self._pending_entry.force_expand = True

    def add_phase(self, phase: str) -> PhaseDivider:
        self.stream = None
        self._stream_entry = None
        self._close_thinking()
        divider = PhaseDivider(phase)
        entry = self._new_entry("phase", phase=phase)
        self._mount_managed(entry, divider)
        return divider

    def add_notice(self, kind: str, text: str) -> NoticeBlock:
        self.stream = None
        self._stream_entry = None
        self._close_thinking()
        block = NoticeBlock(kind, text)
        entry = self._new_entry("notice", notice_kind=kind, text=text)
        self._mount_managed(entry, block)
        return block

    def mount_scope_card(self, card: ScopeConfirmCard) -> None:
        """挂载 scope 确认卡(WP-14c:仪式 worker 唯一挂载点;与正文/思考块互斥)。"""
        self.stream = None
        self._stream_entry = None
        self._close_thinking()
        self._mount_block(card)

    def mount_model_card(self, card: ModelPickerCard) -> None:
        """挂载模型选择器卡(与正文/思考块互斥)。"""
        self.stream = None
        self._stream_entry = None
        self._close_thinking()
        self._mount_block(card)


# ---------------------------------------------------------------------------
# 侧栏(D3):阶段 → 索引计数 → token 预算 → jobs → sessions
# ---------------------------------------------------------------------------

#: 侧栏状态摘要各表的行首标签(与 WP-06 六表对应)。
_COUNT_LABELS = ("hosts", "ports", "creds", "vulns", "loot", "notes")


def _budget_text(used: int | None, budget: int) -> Text:
    """token 预算条(D2):10 格块条 + 数值;用量走高变色(配文字数值)。"""
    if used is None:
        return Text("—(run 未开始)", style="dim")
    cells = 10
    ratio = min(1.0, used / budget) if budget > 0 else 1.0
    filled = round(ratio * cells)
    style = "green" if ratio < 0.7 else ("yellow" if ratio < 0.95 else "red")
    text = Text()
    text.append("▓" * filled + "░" * (cells - filled), style=style)
    text.append(f" {format_tokens(used)}/{format_tokens(budget)}", style=style)
    return text


class AnimatedWordmark(Static):
    """迎宾屏动态大号字标:海沫波纹扫光 + 立体投影 + 上浮微气泡。"""

    def __init__(
        self, *, id: str = "landing-logo", interval: float = 0.11
    ) -> None:
        super().__init__(render_animated_wordmark(__app_name__, 0), id=id)
        self._frame = 0
        self._interval = interval
        self._timer = None

    @property
    def frame(self) -> int:
        return self._frame

    def on_mount(self) -> None:
        self._timer = self.set_interval(self._interval, self.advance_frame)

    def on_unmount(self) -> None:
        self.stop_animation()

    def stop_animation(self) -> None:
        timer = self._timer
        self._timer = None
        if timer is not None:
            timer.stop()

    def advance_frame(self) -> None:
        self._frame += 1
        self.update(render_animated_wordmark(__app_name__, self._frame))


class WelcomeBanner(Vertical):
    """主界面内联紧凑欢迎条(Strix 对齐:不阻塞首屏,仅占数行高度)。"""

    DEFAULT_CSS = """
    WelcomeBanner {
        height: auto;
    }
    """

    def __init__(self, *, title: str, meta: str, hint: str) -> None:
        super().__init__(id="welcome-banner")
        self._title = title
        self._meta = meta
        self._hint = hint

    def compose(self):
        yield Static(self._title, id="banner-title", markup=False)
        meta = Static(self._meta, id="banner-meta", markup=False)
        meta.display = bool(self._meta)
        yield meta
        if self._hint:
            yield Static(self._hint, id="banner-hint", markup=False)

    def set_meta(self, meta: str) -> None:
        self._meta = meta
        widget = self.query_one("#banner-meta", Static)
        widget.update(meta)
        widget.display = bool(meta)


class SidebarPane(VerticalScroll):
    """右侧栏(~30 列):全部内容为本项目生成的结构化文本(可放心用样式)。"""

    def __init__(self) -> None:
        super().__init__(id="sidebar")
        self.model_label = ""
        self.phase = ""
        self.targets: list[str] = []
        self.instruction = ""
        self.counts: dict[str, int] = {}
        self.jobs: list[dict[str, Any]] = []
        self.sessions: list[dict[str, Any]] = []

    def compose(self):
        yield Static("模型", classes="side-title")
        yield Static(Text("—", style="dim"), id="side-model")
        yield Static("目标", classes="side-title")
        yield Static(Text("—", style="dim"), id="side-targets")
        yield Static("阶段", classes="side-title")
        yield Static(Text("—", style="dim"), id="side-phase")
        yield Static("索引", classes="side-title")
        yield Static(Text("—", style="dim"), id="side-counts")
        yield Static("预算", classes="side-title")
        yield Static(_budget_text(None, 1), id="side-budget")
        yield Static("jobs", classes="side-title")
        yield Static(Text("—", style="dim"), id="side-jobs")
        yield Static("sessions", classes="side-title")
        yield Static(Text("—", style="dim"), id="side-sessions")

    def set_model(self, label: str) -> None:
        self.model_label = label
        widget = self.query_one("#side-model", Static)
        if not label:
            widget.update(Text("—", style="dim"))
            return
        if " · " in label:
            provider, model_id = label.split(" · ", 1)
            widget.update(
                Text.assemble(
                    (_clip(model_id, 27), "bold cyan"),
                    "\n",
                    (_clip(provider, 27), "dim"),
                )
            )
            return
        widget.update(Text(_clip(label, 27), style="bold cyan"))

    def set_targets(self, targets: list[str], instruction: str = "") -> None:
        self.targets = [t.strip() for t in targets if t and t.strip()]
        self.instruction = instruction.strip()
        widget = self.query_one("#side-targets", Static)
        if not self.targets and not self.instruction:
            widget.update(Text("—", style="dim"))
            return
        text = Text()
        for idx, item in enumerate(self.targets):
            if idx:
                text.append("\n")
            text.append(f"• {_clip(item, 26)}", style="cyan")
        if self.instruction:
            if self.targets:
                text.append("\n")
            text.append(f"» {_clip(self.instruction, 26)}", style="dim")
        widget.update(text)

    def set_phase(self, phase: str) -> None:
        self.phase = phase
        self.query_one("#side-phase", Static).update(
            Text(phase or "—", style="bold cyan")
        )

    def set_counts(self, counts: dict[str, int]) -> None:
        self.counts = dict(counts)
        text = Text()
        for index, name in enumerate(_COUNT_LABELS):
            value = counts.get(name, 0)
            if index:
                text.append("\n")
            style = "dim" if value == 0 else "bold"
            text.append(f"{name} {value}", style=style)
        self.query_one("#side-counts", Static).update(text)

    def set_budget(self, used: int | None, budget: int) -> None:
        self.query_one("#side-budget", Static).update(_budget_text(used, budget))

    def set_jobs(self, jobs: list[dict[str, Any]]) -> None:
        self.jobs = list(jobs)
        target = self.query_one("#side-jobs", Static)
        if not jobs:
            target.update(Text("(无)", style="dim"))
            return
        text = Text()
        for index, job in enumerate(jobs):
            marker, style = {
                "running": ("●", "cyan"),
                "completed": ("✓", "green"),
                "timeout": ("⏱", "yellow"),
                "killed": ("⚠", "yellow"),
            }.get(str(job.get("status")), ("✗", "red"))
            command = _clip(str(job.get("command", "")), 20)
            elapsed = job.get("elapsed_seconds", "?")
            remaining = job.get("timeout_remaining_seconds")
            tail = f" 剩{remaining:.0f}s" if isinstance(remaining, float) else ""
            quiet = job.get("quiet_seconds")
            quiet_tail = (
                f" · 静默{quiet}s(非 idle timeout)"
                if job.get("status") == "running"
                and isinstance(quiet, int | float)
                else ""
            )
            if index:
                text.append("\n")
            text.append(f"{marker} {command}", style=style)
            text.append(f"  {elapsed}s{tail}{quiet_tail}", style="dim")
        target.update(text)

    def set_sessions(self, sessions: list[dict[str, Any]]) -> None:
        self.sessions = list(sessions)
        target = self.query_one("#side-sessions", Static)
        if not sessions:
            target.update(Text("(无)", style="dim"))
            return
        text = Text()
        for index, session in enumerate(sessions):
            marker, style = {
                "running": ("◆", "green"),
                "exited": ("○", "dim"),
                "closed": ("□", "dim"),
            }.get(str(session.get("status")), ("?", "red"))
            command = _clip(str(session.get("command", "")), 20)
            if index:
                text.append("\n")
            text.append(f"{marker} {command}", style=style)
            if session.get("pending_events"):
                # WP-05 提示识别有待处置事件:黄色文字标记高亮(D4 双通道)
                text.append(" ⏳待输入", style="bold yellow")
        target.update(text)


# ---------------------------------------------------------------------------
# 顶栏状态条
# ---------------------------------------------------------------------------

#: run 状态的「文字标记 + 色调」表(D4;侧栏/通知块同理)。
#: idle = loop 待命态(WP-09 更正当:终答后等插话续段);run 前的初始
#: 状态在 compose 里写死「待机」,不走本表——两者文案有意区分。
_STATUS_STYLES: dict[str, tuple[str, str]] = {
    "idle": ("○ 待命", "dim"),
    "running": ("● 运行中", "green"),
    "paused": ("⏸ 已暂停", "yellow"),
    "stopped": ("■ 预算停止", "yellow"),
    "killed": ("■ 已 kill", "red"),
    "finished": ("✓ 已完成", "cyan"),
    "error": ("✗ 出错", "red"),
}


class StatusBar(Horizontal):
    """顶栏:左=字标/版本/后端,中=engagement 与呼号,右=run 状态。"""

    def __init__(self, left: str) -> None:
        super().__init__(id="statusbar")
        self._left = left
        self._engagement = ""
        self._operator = ""
        self.status = "idle"

    def compose(self):
        yield Static(self._left, id="sb-left", markup=False)
        yield Static("", id="sb-center", markup=False)
        # run 前初始态写死「待机」;loop 的 idle 是待命态(_STATUS_STYLES)。
        yield Static(Text("○ 待机", style="dim"), id="sb-right")

    def set_left(self, left: str) -> None:
        self._left = left
        self.query_one("#sb-left", Static).update(left)

    def set_engagement(self, engagement_id: str, operator: str) -> None:
        self._engagement = engagement_id
        self._operator = operator
        self.query_one("#sb-center", Static).update(
            f"{engagement_id} · 呼号 {operator}"
        )

    def set_status(self, status: str) -> None:
        self.status = status
        label, style = _STATUS_STYLES.get(status, (status, "dim"))
        self.query_one("#sb-right", Static).update(Text(label, style=style))


# ---------------------------------------------------------------------------
# scope 确认卡(WP-14c:启动与 /scope 共用同一仪式实现,定案 Q5)
# ---------------------------------------------------------------------------


class ScopeCardAction(Message):
    """operator 在 scope 确认卡上的动作:confirm / correct(带修正文本)/ cancel。

    修正文本只进编译上下文(corrections 重编译),**不经过主输入坞、不进主环
    模型上下文**(定案 D4 隔离:主环模型只能经 ENGAGEMENT.md 动态段看到确认后
    的规则)。
    """

    def __init__(self, action: str, correction: str = "") -> None:
        super().__init__()
        self.action = action
        self.correction = correction


class ScopeConfirmCard(Vertical):
    """scope 确认卡:canonical 规则逐行 + 计数 + sha256 短哈希 + 来源 +
    三操作(确认冻结 / NL 修正重编译 / 取消)。

    - 状态先进内存、``_ready`` 后才落 DOM(与工具卡同一挂载时序约定:worker
      mount 后立刻 set_compiling/update_compilation 也安全);
    - 编译中按钮与修正框禁用并示「编译中…」;
    - 空 rules 醒目文案「(空——任何网络目标都会被拒)」(定案 Q9,文字 + CSS
      类双通道);
    - 编译失败进错误态:确认禁用(无合法产物可确认),修正/取消可用,
      中文可行动报错原文上卡;
    - 关闭后由主界面留通知块摘要(仪式 worker 负责)。
    """

    def __init__(self) -> None:
        super().__init__(id="scopecard")
        self._ready = False
        self._compiling = True
        self._attempts = 0
        self._compilation: ScopeCompilation | None = None
        self._error = ""
        self._hint = ""

    def compose(self):
        yield Static("", id="scope-card-title", markup=False)
        yield Static("", id="scope-card-body", markup=False)
        yield Static("", id="scope-card-status", markup=False)
        with Horizontal(id="scope-card-buttons"):
            yield Button("确认冻结", id="scope-confirm", variant="success")
            yield Button("按修正重编译", id="scope-correct", variant="primary")
            yield Button("取消", id="scope-cancel")
        yield Input(
            placeholder="修正意见(自然语言;只进编译上下文,不进主对话)",
            id="scope-correction",
        )

    def on_mount(self) -> None:
        self._ready = True
        self._redraw()

    # ---------- 仪式 worker 驱动的三态 ----------

    def set_compiling(self) -> None:
        """进入编译中状态(初次与每次重编译前):按钮/修正框禁用。"""
        self._compiling = True
        self._hint = ""
        self._redraw()

    def update_compilation(
        self, compilation: ScopeCompilation, attempts: int
    ) -> None:
        """编译成功:重渲染规则/计数/短哈希并清空修正框。"""
        self._compilation = compilation
        self._attempts = attempts
        self._error = ""
        self._compiling = False
        self._hint = ""
        if self._ready:
            self.query_one("#scope-correction", Input).value = ""
        self._redraw()

    def update_error(self, message: str, attempts: int) -> None:
        """编译失败:错误态上卡(确认禁用),引导修正或取消。"""
        self._error = message
        self._attempts = attempts
        self._compiling = False
        self._hint = ""
        self._redraw()

    # ---------- 内部 ----------

    @staticmethod
    def _sha12(compilation: ScopeCompilation) -> str:
        data = compilation.canonical_text.encode("utf-8")
        return hashlib.sha256(data).hexdigest()[:12]

    def _redraw(self) -> None:
        if not self._ready or self._pruning:
            return
        title = self.query_one("#scope-card-title", Static)
        body = self.query_one("#scope-card-body", Static)
        status = self.query_one("#scope-card-status", Static)
        body.set_class(False, "scope-empty", "scope-error")
        if self._compiling:
            title.update("scope 确认仪式——编译中…")
            if self._compilation is None and not self._error:
                body.update("(等待编译结果…)")
            status.update(f"编译中…(第 {self._attempts + 1} 次编译)")
        elif self._error:
            title.update("scope 编译失败——请填修正意见重编译,或取消")
            body.set_class(True, "scope-error")
            body.update(self._error)
            status.update(f"第 {self._attempts} 次编译失败;修正意见只进编译上下文")
        else:
            compilation = self._compilation
            if compilation is None:
                return  # 三态之一必有产物;防御兜底(初始必为编译中态)
            title.update(f"确认授权 scope(第 {self._attempts} 次编译结果)")
            if compilation.rules:
                body.update("\n".join(compilation.rules))
            else:
                # 定案 Q9:空规则集合法(fail-closed),醒目双通道
                body.set_class(True, "scope-empty")
                body.update("(空——任何网络目标都会被拒)")
            status.update(
                f"来源:自然语言声明(NL 编译)· 共 {len(compilation.rules)} 条"
                f" · canonical sha256:{self._sha12(compilation)}"
                + (f"\n⚠ {self._hint}" if self._hint else "")
            )
        confirm = self.query_one("#scope-confirm", Button)
        confirm.disabled = (
            self._compiling or self._compilation is None or bool(self._error)
        )
        self.query_one("#scope-correct", Button).disabled = self._compiling
        self.query_one("#scope-cancel", Button).disabled = self._compiling
        self.query_one("#scope-correction", Input).disabled = self._compiling

    def _post_action(self, action: str, correction: str = "") -> None:
        if self._compiling:
            return  # 编译中按钮虽禁用,快捷键/消息路径同样拦一道
        if action == "confirm" and (self._compilation is None or self._error):
            return  # 无合法产物可确认
        if action == "correct" and not correction.strip():
            self._hint = "先填修正意见再点「按修正重编译」"
            self._redraw()
            return
        self.post_message(ScopeCardAction(action, correction.strip()))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        button_id = event.button.id
        if button_id == "scope-confirm":
            self._post_action("confirm")
        elif button_id == "scope-correct":
            correction = self.query_one("#scope-correction", Input).value
            self._post_action("correct", correction)
        elif button_id == "scope-cancel":
            self._post_action("cancel")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        # 修正框内回车 = 按修正重编译(D4:不经过主输入坞)
        event.stop()
        if event.input.id == "scope-correction":
            self._post_action("correct", event.value)


# ---------------------------------------------------------------------------
# 模型选择器卡(/model 交互选择与自定义模型 ID 输入)
# ---------------------------------------------------------------------------


class ModelPickerAction(Message):
    """模型选择器回传给 MainScreen 的动作。"""

    def __init__(self, action: str, value: str = "") -> None:
        super().__init__()
        self.action = action
        self.value = value


class ModelOptionItem(ListItem):
    """模型选择列表单条候选项(`kind`: 'model' 或 'profile')。"""

    def __init__(self, kind: str, value: str, label: str) -> None:
        super().__init__(Label(label, markup=False))
        self.kind = kind
        self.value = value


class ModelPickerCard(Vertical):
    """内联交互式模型/profile 选择卡;支持方向键选择、自定义输入与 Esc 取消。"""

    BINDINGS = [Binding("escape", "cancel", "取消", show=False)]

    def __init__(self) -> None:
        super().__init__(id="modelcard")
        self.mounted_event = asyncio.Event()

    def on_mount(self) -> None:
        self.mounted_event.set()

    def compose(self):
        yield Static("模型与 Profile 选择", id="model-card-title")
        yield Static(
            "正在读取本地与后端模型列表…", id="model-card-status", markup=False
        )
        yield ListView(id="model-list")
        yield Input(
            placeholder="或直接输入模型 ID / @profile 回车切换",
            id="model-custom-input",
        )
        with Horizontal(id="model-card-buttons"):
            yield Button("切换", id="model-apply", variant="primary")
            yield Button("取消", id="model-cancel")

    async def set_options(
        self, options: list[tuple[str, str, str]], *, status: str
    ) -> None:
        self.query_one("#model-card-status", Static).update(status)
        lv = self.query_one("#model-list", ListView)
        await lv.clear()
        if options:
            await lv.extend(
                ModelOptionItem(kind, value, label) for kind, value, label in options
            )
            lv.index = 0

    def _emit_selection(self, item: ModelOptionItem) -> None:
        action = "select_profile" if item.kind == "profile" else "select_model"
        self.post_message(ModelPickerAction(action, item.value))

    def _emit_raw(self, raw: str) -> None:
        cleaned = raw.strip()
        if not cleaned:
            return
        if cleaned.startswith("@") and len(cleaned) > 1:
            self.post_message(ModelPickerAction("select_profile", cleaned[1:].strip()))
        else:
            self.post_message(ModelPickerAction("select_model", cleaned))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        event.stop()
        if isinstance(event.item, ModelOptionItem):
            self._emit_selection(event.item)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "model-custom-input":
            event.stop()
            self._emit_raw(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "model-cancel":
            self.action_cancel()
            return
        if event.button.id == "model-apply":
            custom = self.query_one("#model-custom-input", Input).value.strip()
            if custom:
                self._emit_raw(custom)
                return
            child = self.query_one("#model-list", ListView).highlighted_child
            if isinstance(child, ModelOptionItem):
                self._emit_selection(child)

    def action_cancel(self) -> None:
        self.post_message(ModelPickerAction("cancel", ""))


# ---------------------------------------------------------------------------
# 输入坞:斜杠命令补全 + 输入框(Q4 双通道)
# ---------------------------------------------------------------------------

#: 斜杠命令表;描述进补全候选与 /help。
SLASH_COMMANDS: list[tuple[str, str]] = [
    ("/help", "命令与快捷键帮助"),
    ("/pause", "暂停 agent(turn 边界生效)"),
    ("/resume", "继续运行"),
    ("/kill", "kill switch(二次确认)"),
    ("/jobs", "列出后台 job"),
    ("/sessions", "列出 PTY 会话"),
    ("/status", "run 状态与索引摘要"),
    ("/budget", "查看/显式修改总预算"),
    ("/model", "查看/切换模型或 profile"),
    ("/target", "查看/设定授权目标(-t)"),
    ("/scope", "查看/启用可选 scope 护栏"),
]


class CompletionItem(ListItem):
    """一条补全候选;``command`` 为接受后填入输入框的命令名。"""

    def __init__(self, command: str, description: str) -> None:
        super().__init__(Label(f"{command}  {description}"))
        self.command = command


class CommandInput(Input):
    """底部输入框:补全弹层可见时接管 ↑/↓/Tab/Enter/Esc。"""

    def __init__(self) -> None:
        super().__init__(id="input", placeholder="输入目标或对话开始(/ 查看命令)")
        #: 由 InputDock 挂载时注入;弹层可见时按键先给弹层。
        self.dock: InputDock | None = None

    async def _on_key(self, event) -> None:
        dock = self.dock
        if dock is not None and dock.popup_visible:
            if event.key == "up":
                dock.move_highlight(-1)
            elif event.key == "down":
                dock.move_highlight(1)
            elif event.key == "tab":
                dock.accept_highlight()
            elif event.key == "escape":
                dock.hide_popup()
            elif event.key == "enter" and not dock.exact_command(self.value):
                dock.accept_highlight()
            else:
                await super()._on_key(event)
                return
            event.stop()
            return
        await super()._on_key(event)


class InputDock(Vertical):
    """输入坞:补全弹层(上) + 输入框(下);补全数据源为 SLASH_COMMANDS。

    弹层规则(Q4):值以 ``/`` 开头且不含空格时按前缀过滤展示;Enter 在
    「已是完整命令」时直接提交,否则接受高亮候选;Esc 收起。
    """

    class Submitted(Message):
        """操作员提交了一行文本(普通插话/objective 或斜杠命令)。"""

        def __init__(self, text: str) -> None:
            super().__init__()
            self.text = text

    def __init__(self) -> None:
        super().__init__(id="inputdock")
        self.popup_visible = False

    def compose(self):
        yield ListView(id="completion")
        yield CommandInput()

    def on_mount(self) -> None:
        popup = self.popup
        popup.display = False
        self.input_box.dock = self

    @property
    def input_box(self) -> CommandInput:
        return self.query_one("#input", CommandInput)

    @property
    def popup(self) -> ListView:
        return self.query_one("#completion", ListView)

    @staticmethod
    def exact_command(value: str) -> bool:
        """输入是否已是一条完整命令(整串或带参首词命中命令表)。"""
        head = value.strip().split(maxsplit=1)[0] if value.strip() else ""
        return any(head == command for command, _ in SLASH_COMMANDS)

    async def on_input_changed(self, event: Input.Changed) -> None:
        value = event.value
        if (
            value.startswith("/")
            and " " not in value.strip()
            and not self.exact_command(value)  # 已是完整命令:收起,Enter 直接提交
        ):
            matches = [
                (command, description)
                for command, description in SLASH_COMMANDS
                if command.startswith(value)
            ]
            if matches:
                await self._show_popup(matches)
                return
        self.hide_popup()

    async def _show_popup(self, matches: list[tuple[str, str]]) -> None:
        # clear/extend 返回 AwaitComplete:await 后子节点才真实就位,
        # index 高亮才不落空(快速连续打字时消息泵串行处理,无乱序)。
        popup = self.popup
        await popup.clear()
        await popup.extend(
            CompletionItem(command, description)
            for command, description in matches
        )
        popup.index = 0
        popup.display = True
        self.popup_visible = True

    def hide_popup(self) -> None:
        self.popup.display = False
        self.popup_visible = False

    def move_highlight(self, delta: int) -> None:
        popup = self.popup
        count = len(popup.children)
        if count:
            popup.index = ((popup.index or 0) + delta) % count

    def accept_highlight(self) -> None:
        item = self.popup.highlighted_child
        if isinstance(item, CompletionItem):
            input_box = self.input_box
            input_box.value = item.command
            input_box.action_end()
        self.hide_popup()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.hide_popup()
        text = event.value.strip()
        if text:
            event.input.value = ""
            self.post_message(self.Submitted(text))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, CompletionItem):
            self.input_box.value = event.item.command
            self.input_box.action_end()
            self.hide_popup()
            self.input_box.focus()


class KillConfirmBar(Static):
    """kill 二次确认条(Ctrl-X/Ctrl-C 第一次按下时出现;红色,文字明示)。"""

    def __init__(self) -> None:
        super().__init__(
            "⚠ 再次按 Ctrl-X 确认 KILL:立即中断当前 turn、杀全部活动 job、"
            "写 kill_switch 审计 · Esc 取消",
            id="killbar",
        )
        self.display = False
