"""主界面组件(WP-09):工具卡紧凑流、折叠思考块、阶段分隔条、侧栏、输入坞。

观感纪律(规格 + 2026-08-22 定案):

- 工具卡紧凑流(Q2):运行中 spinner + 命令一行;完成折叠为
  「文字标记 + 命令 + 状态摘要」一行;Enter/点击展开 WP-01 head+tail 截断视图;
  护栏拒绝 / 非零退出 / 错误 / 待输入提示一律自动展开。
- 思考块(Q6):灰色可折叠,默认折叠为「🧠 思考 Ns · M 字符」。
- 语义色 + 文字标记双通道(D4):不只靠颜色传达状态。
- 模型文本一律 ``markup=False`` 渲染(方括号等内容不得被当作 console 标记)。

挂载时序约定:textual 的 ``mount()`` 异步完成(compose 子节点稍后才有),
因此可交互组件一律走「状态先进内存、``_ready`` 后才落 DOM」模式——
消息处理函数里 mount 完立刻 feed/finalize 也安全。
"""

from __future__ import annotations

import json
import time
from typing import Any

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import Click
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Input, Label, ListItem, ListView, Static

from foam.tui.bridge import tool_call_display

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

    def __init__(self) -> None:
        super().__init__("", markup=False, classes="stream")
        self._text = ""

    @property
    def text(self) -> str:
        return self._text

    def feed(self, delta: str) -> None:
        self._text += delta
        self.update(self._text)  # update 在挂载前调用安全(只写内容置脏)


class ThinkingBlock(Vertical):
    """折叠思考块(Q6):默认折叠为一行摘要,Enter/点击展开原文。

    内容只进界面与 loop 的审计哈希,不落任何明文文件。
    """

    can_focus = True
    BINDINGS = [Binding("enter", "toggle", "展开/折叠思考", show=False)]

    def __init__(self) -> None:
        super().__init__(classes="thinking")
        self._text = ""
        self._started = time.monotonic()
        self._elapsed = 0.0
        self._done = False
        self._expanded = False
        self._ready = False
        self._timer = None

    def compose(self):
        yield Static(classes="thinking-header")
        yield Static("", markup=False, classes="thinking-body")

    def on_mount(self) -> None:
        self._ready = True
        self._timer = self.set_interval(0.5, self._redraw)
        self._redraw()

    @property
    def text(self) -> str:
        return self._text

    @property
    def done(self) -> bool:
        return self._done

    @property
    def expanded(self) -> bool:
        return self._expanded

    def feed(self, delta: str) -> None:
        self._text += delta
        self._redraw()

    def finish(self) -> None:
        """思考流结束(后续出现正文/工具等其他事件时由叙述流调用)。"""
        if self._done:
            return
        self._done = True
        self._elapsed = time.monotonic() - self._started
        if self._timer is not None:
            self._timer.stop()
        self._redraw()

    def _redraw(self) -> None:
        if not self._ready:
            return
        elapsed = (
            self._elapsed if self._done else time.monotonic() - self._started
        )
        state = "思考" if self._done else "思考中…"
        hint = "" if self._expanded else "  [Enter 展开]"
        self.query_one(".thinking-header", Static).update(
            f"🧠 {state} {elapsed:.0f}s · {len(self._text)} 字符{hint}"
        )
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
    "objective": ("◆", "blue"),
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
            return "⏱", "warn", f"超时强杀 · {duration} · {size}", True
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
        self.summary = ""
        self._header = f"⠋ {self.card_display}"
        self._body = ""

    def compose(self):
        yield Static(self._header, classes="card-header")
        yield Static("", markup=False, classes="card-body")

    def on_mount(self) -> None:
        self._ready = True
        self._redraw()
        if self._spinning:
            self._timer = self.set_interval(0.12, self._spin)

    @property
    def running(self) -> bool:
        return self._spinning

    @property
    def expanded(self) -> bool:
        return self._expanded

    def _redraw(self) -> None:
        if not self._ready:
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
        if self._timer is not None:
            self._timer.stop()
        marker, tone, summary, auto_expand = summarize_result(self.tool_name, result)
        self.summary = summary
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
# 叙述流容器
# ---------------------------------------------------------------------------


class NarrativeView(VerticalScroll):
    """主区叙述流:管理「当前正文块 / 当前思考块 / 在飞工具卡」的开闭。

    loop 单线程语义保证任何时刻至多一张在飞工具卡(逐个执行);思考块与
    正文块互斥——任一其他事件到达都会为思考块收尾。
    """

    def __init__(self) -> None:
        super().__init__(id="narrative")
        self.stream: StreamBlock | None = None
        self.thinking: ThinkingBlock | None = None
        self.pending_card: ToolCard | None = None

    def _mount_block(self, widget: Widget) -> None:
        self.mount(widget)
        self.call_after_refresh(self._scroll_to_end)

    def _scroll_to_end(self) -> None:
        self.scroll_end(animate=False)

    def _close_thinking(self) -> None:
        if self.thinking is not None:
            self.thinking.finish()
            self.thinking = None

    def feed_text(self, delta: str) -> None:
        self._close_thinking()
        if self.stream is None:
            self.stream = StreamBlock()
            self._mount_block(self.stream)
        self.stream.feed(delta)
        self.call_after_refresh(self._scroll_to_end)

    def feed_thinking(self, delta: str) -> None:
        self.stream = None
        if self.thinking is None:
            self.thinking = ThinkingBlock()
            self._mount_block(self.thinking)
        self.thinking.feed(delta)

    def open_card(self, name: str, arguments: dict[str, Any]) -> ToolCard:
        self.stream = None
        self._close_thinking()
        card = ToolCard(name, tool_call_display(name, arguments))
        self._mount_block(card)
        self.pending_card = card
        return card

    def close_card(self, name: str, result: dict[str, Any]) -> ToolCard | None:
        card = self.pending_card
        self.pending_card = None
        if card is None:
            return None  # 契约外序列(如无卡结果):调用方落通知块,不炸渲染
        card.finalize(result)
        self.call_after_refresh(self._scroll_to_end)
        return card

    def mark_pending_denied(self) -> None:
        if self.pending_card is not None:
            self.pending_card.force_expand = True

    def add_phase(self, phase: str) -> PhaseDivider:
        self.stream = None
        self._close_thinking()
        divider = PhaseDivider(phase)
        self._mount_block(divider)
        return divider

    def add_notice(self, kind: str, text: str) -> NoticeBlock:
        self.stream = None
        self._close_thinking()
        block = NoticeBlock(kind, text)
        self._mount_block(block)
        return block


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


class SidebarPane(VerticalScroll):
    """右侧栏(~30 列):全部内容为本项目生成的结构化文本(可放心用样式)。"""

    def __init__(self) -> None:
        super().__init__(id="sidebar")
        self.phase = ""
        self.counts: dict[str, int] = {}
        self.jobs: list[dict[str, Any]] = []
        self.sessions: list[dict[str, Any]] = []

    def compose(self):
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
            if index:
                text.append("\n")
            text.append(f"{marker} {command}", style=style)
            text.append(f"  {elapsed}s{tail}", style="dim")
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
_STATUS_STYLES: dict[str, tuple[str, str]] = {
    "idle": ("○ 待机", "dim"),
    "running": ("● 运行中", "green"),
    "paused": ("⏸ 已暂停", "yellow"),
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
        yield Static(Text(_STATUS_STYLES["idle"][0], style="dim"), id="sb-right")

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
# 输入坞:斜杠命令补全 + 输入框(Q4 双通道)
# ---------------------------------------------------------------------------

#: v0 斜杠命令表(定案 Q4);描述进补全候选与 /help。
SLASH_COMMANDS: list[tuple[str, str]] = [
    ("/help", "命令与快捷键帮助"),
    ("/pause", "暂停 agent(turn 边界生效)"),
    ("/resume", "继续运行"),
    ("/kill", "kill switch(二次确认)"),
    ("/jobs", "列出后台 job"),
    ("/sessions", "列出 PTY 会话"),
    ("/status", "run 状态与索引摘要"),
]


class CompletionItem(ListItem):
    """一条补全候选;``command`` 为接受后填入输入框的命令名。"""

    def __init__(self, command: str, description: str) -> None:
        super().__init__(Label(f"{command}  {description}"))
        self.command = command


class CommandInput(Input):
    """底部输入框:补全弹层可见时接管 ↑/↓/Tab/Enter/Esc。"""

    def __init__(self) -> None:
        super().__init__(id="input", placeholder="输入目标(objective)开始")
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
