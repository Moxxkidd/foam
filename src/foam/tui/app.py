"""TUI 应用与启动约定(WP-09):迎宾屏(纯呼号门)→ 主界面。

启动约定(WP-10 的 ``foam tui`` 子命令占位即按此接线)::

    # cli.py _cmd_tui:from foam.tui.app import main as tui_main
    raise SystemExit(main(args))   # args 携带 --scope/--backend/--model 等

- 呼号门(Q1):scope/backend 都来自 CLI 参数,迎宾屏只收操作员呼号;
  objective = 主界面输入框首条消息,loop 此前不启动、engagement 目录此前不建。
- 呼号去向(D1):engagement.json ``operator`` 字段 + loop 的 operator_interject
  审计载荷;另存 ``~/.foam/config.json``,下次启动预填。
- 生命周期:首条消息时建 Engagement(WP-06)→ AuditLog(scope_loaded)→
  loop_factory 装配 → asyncio 任务跑 loop;退出时若 run 在活动先 kill
  (走 loop 的正常清理:杀 job/写 kill_switch 审计),再收 backend/会话。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import Screen
from textual.widgets import Input, Static

from foam import __app_name__, __version__
from foam.agent.backends.base import ConfigError, LLMBackend
from foam.agent.loop import (
    DEFAULT_MAX_CONTEXT_TOKENS,
    FIRST_EVENT_TIMEOUT_SECONDS,
    AgentLoop,
    LoopObserver,
    RunResult,
    ToolRegistry,
    estimate_tokens,
)
from foam.agent.prompts import build_system_prompt
from foam.agent.toolmap import render_tool_map, scan_tools
from foam.guard.audit import KIND_SCOPE_LOADED, AuditLog
from foam.guard.scope import Scope, scope_payload
from foam.state.files import DEFAULT_ENGAGEMENTS_DIR, Engagement
from foam.tools.bash import TOOL_SCHEMAS, BashTool
from foam.tools.session import TOOL_SCHEMAS as SESSION_TOOL_SCHEMAS
from foam.tools.session import SessionTool
from foam.tools.state import TOOL_SCHEMAS as STATE_TOOL_SCHEMAS
from foam.tools.state import StateTool
from foam.tui.banner import render_wordmark
from foam.tui.bridge import (
    CompressedMsg,
    CorrectionMsg,
    GuardMsg,
    NarrativeMsg,
    PhaseMsg,
    RetryMsg,
    StatusMsg,
    ThinkingMsg,
    ToolCallMsg,
    ToolResultMsg,
    TuiObserver,
)
from foam.tui.widgets import (
    InputDock,
    KillConfirmBar,
    NarrativeView,
    SidebarPane,
    StatusBar,
)

#: 侧栏自动隐藏阈值(D3:终端宽度 <110 列时默认隐藏,F2 唤出)。
SIDEBAR_MIN_WIDTH = 110
#: kill 二次确认的武装时长(超时自动解除,防误触也防卡死)。
KILL_CONFIRM_SECONDS = 5.0
#: 侧栏/预算轮询间隔(秒)。
PANEL_REFRESH_SECONDS = 2.0

#: 主环纠正原因的中文标签(叙述流警告块用)。
_CORRECTION_LABELS = {
    "no_tool_call_action_claim": (
        "幻觉执行纠正:模型声称执行动作但未发 tool_call,已回灌纠正说明"
    ),
    "malformed_tool_call": "工具参数非法 JSON:已回灌纠正(连续 3 次将终止 run)",
}

_HELP_TEXT = """斜杠命令(输入 / 有补全):
  /help     本帮助
  /pause    暂停 agent(当前 turn 跑完后停住)
  /resume   继续运行
  /kill     kill switch(二次确认;杀活动 job、写审计)
  /jobs     列出后台 job
  /sessions 列出 PTY 会话(只读;干预请插话,由 agent 经 session_send 操作)
  /status   run 状态与索引摘要
快捷键:
  Ctrl-X / Ctrl-C  kill(二次确认,Esc 取消)
  Ctrl-P           暂停/继续切换
  F2               侧栏显隐(终端 <110 列时自动隐藏)
  Enter            提交;聚焦卡片/思考块时展开/折叠
普通文本 = 插话(首条消息为 objective,发出后 loop 启动)。"""


# ---------------------------------------------------------------------------
# 启动配置与装配契约
# ---------------------------------------------------------------------------


@dataclass
class TUIConfig:
    """TUI 启动配置:全部由调用方(CLI 子命令)显式装配。

    - ``scope``/``scope_source``:授权范围与来源路径(迎宾屏展示 + 审计 +
      system prompt 授权声明);加载失败应在 CLI 层直接报掉。
    - ``backend``:已构造的后端实例(API key 只走环境变量,本层不接触)。
    - ``model_label``:展示用模型名(迎宾屏/顶栏);空串显示 provider 默认。
    - ``config_home``:本地配置目录(呼号预填),默认 ``~/.foam/``。
    - ``loop_factory``:loop 装配钩子,None 用 :func:`default_loop_factory`
      (与 headless 一致的 exec 层装配);WP-10 挂会话/状态工具时传入自定义
      factory,无需改动本包任何文件。
    """

    scope: Scope
    scope_source: str
    backend: LLMBackend
    model_label: str = ""
    engagements_dir: str | Path = DEFAULT_ENGAGEMENTS_DIR
    max_context_tokens: int = DEFAULT_MAX_CONTEXT_TOKENS
    first_event_timeout: float = FIRST_EVENT_TIMEOUT_SECONDS
    max_rounds: int = 0
    loop_factory: LoopFactory | None = None
    config_home: str | Path | None = None

    @property
    def home_path(self) -> Path:
        return Path(self.config_home) if self.config_home else Path.home() / ".foam"


@dataclass
class RunContext:
    """首条消息时 TUI 备好的运行环境,交给 loop_factory 装配 AgentLoop。"""

    objective: str
    operator: str
    engagement: Engagement
    audit: AuditLog
    observer: LoopObserver
    config: TUIConfig


@dataclass
class RunHandle:
    """loop_factory 的返回:loop 本体 + 侧栏数据源(可选)与资源句柄。"""

    loop: AgentLoop
    bash: BashTool | None = None
    sessions: Any | None = None  # WP-05 SessionTool;None = 会话层未接线
    engagement: Engagement | None = None


LoopFactory = Callable[[RunContext], RunHandle]


def default_loop_factory(ctx: RunContext) -> RunHandle:
    """默认装配:与 headless ``run`` 同构的全工具面(exec/会话/状态 + 工具地图)。

    会话层在此接线(定案 Q5:侧栏只读展示,干预走插话由 agent 操作);
    自定义 factory 可照此 shape 调 ``ToolRegistry.register_module`` 增减工具。
    """
    config = ctx.config
    engagement = ctx.engagement
    bash = BashTool(engagement.paths.outputs)
    session = SessionTool(engagement.paths.outputs / "sessions")
    state = StateTool(engagement)
    registry = ToolRegistry()
    registry.register_module(TOOL_SCHEMAS, bash.dispatch)
    registry.register_module(SESSION_TOOL_SCHEMAS, session.dispatch)
    registry.register_module(STATE_TOOL_SCHEMAS, state.dispatch)
    prompt = build_system_prompt(
        config.scope,
        source=config.scope_source,
        loaded_at=datetime.now(UTC).isoformat(timespec="seconds"),
        workdir=engagement.paths.root,
        tool_map_text=render_tool_map(scan_tools()),
    )
    loop = AgentLoop(
        backend=config.backend,
        bash=bash,
        scope=config.scope,
        audit=ctx.audit,
        workdir=engagement.paths.root,
        system_prompt=prompt,
        registry=registry,
        observer=ctx.observer,
        session=session,
        engagement=engagement,
        operator=ctx.operator,
        max_context_tokens=config.max_context_tokens,
        first_event_timeout=config.first_event_timeout,
        max_rounds=config.max_rounds,
    )
    return RunHandle(loop=loop, bash=bash, sessions=session, engagement=engagement)


# ---------------------------------------------------------------------------
# 呼号本地配置(D1:~/.foam/config.json,下次启动预填)
# ---------------------------------------------------------------------------

_CONFIG_FILENAME = "config.json"


def load_operator(home: Path) -> str:
    """读本地配置里的呼号;任何读取/解析问题都按「无预填」处理。"""
    try:
        data = json.loads((home / _CONFIG_FILENAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    value = data.get("operator")
    return value.strip() if isinstance(value, str) else ""


def save_operator(home: Path, operator: str) -> None:
    """合并写入呼号(保留配置里未来可能存在的其他键);文件 0600。"""
    home.mkdir(parents=True, exist_ok=True)
    path = home / _CONFIG_FILENAME
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    data["operator"] = operator
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    os.chmod(path, 0o600)


# ---------------------------------------------------------------------------
# 内部消息
# ---------------------------------------------------------------------------


class RunFinishedMsg(Message):
    """run 任务收尾(loop 正常返回;``fatal`` 为自定义 loop 兜底的异常 repr)。"""

    def __init__(self, result: RunResult | None, fatal: str | None) -> None:
        super().__init__()
        self.result = result
        self.fatal = fatal


# ---------------------------------------------------------------------------
# 迎宾屏(Q1 纯呼号门)
# ---------------------------------------------------------------------------


def _hex_to_rgb(value: str) -> tuple[int, int, int]:
    value = value.lstrip("#")
    return (
        int(value[0:2], 16),
        int(value[2:4], 16),
        int(value[4:6], 16),
    )


def _gradient_wordmark(lines: list[str], start: str, end: str) -> Text:
    """给点阵字标上横向渐变(迎宾屏主视觉;对齐 strix 的海报感)。"""
    c1 = _hex_to_rgb(start)
    c2 = _hex_to_rgb(end)
    width = max((len(line) for line in lines), default=1)
    text = Text()
    for row in lines:
        for col, ch in enumerate(row):
            if ch == " ":
                text.append(" ")
                continue
            ratio = col / max(1, width - 1)
            rgb = tuple(round(a + (b - a) * ratio) for a, b in zip(c1, c2, strict=True))
            text.append(ch, style=f"bold #{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}")
        if row is not lines[-1]:
            text.append("\n")
    return text


@dataclass
class WelcomeInfo:
    """迎宾屏展示数据(品牌名只经 __app_name__ 进来,验收 5)。"""

    wordmark: Text
    version: str
    backend_label: str
    scope_path: str
    scope_rules: int
    scope_sha: str
    prefill: str


class WelcomeScreen(Screen):
    """全屏迎宾:字标 + 版本 + 后端/scope 状态 + 呼号输入门。"""

    def __init__(self, info: WelcomeInfo) -> None:
        super().__init__()
        self.info = info

    def compose(self) -> ComposeResult:
        with Vertical(id="gate"):
            yield Static(self.info.wordmark, id="wm-logo")
            yield Static(f"v{self.info.version}", id="wm-version")
            yield Static(
                f"后端  {self.info.backend_label}\n"
                f"scope {self.info.scope_path} · {self.info.scope_rules} 条规则"
                f" · sha256:{self.info.scope_sha}",
                id="wm-meta",
                markup=False,
            )
            yield Static(
                "仅服务明确授权目标 · 每条命令过 scope 护栏\n全程哈希链审计",
                id="wm-redline",
            )
            yield Input(
                value=self.info.prefill,
                placeholder="操作员呼号(如 nightowl)",
                id="callsign",
            )
            yield Static("", id="gate-error")
            yield Static("Enter 进入 · Ctrl-Q 退出", id="wm-hint")

    def on_mount(self) -> None:
        self.query_one("#callsign", Input).focus()

    def show_error(self, text: str) -> None:
        error = self.query_one("#gate-error", Static)
        error.update(text)
        error.display = True

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        # 换屏走 worker:若在本处理器内直接 await switch_screen,拆除本屏需等
        # 本屏消息泵跑完当前消息,而当前消息又在等换屏——自死锁(实测)。
        self.app.run_worker(self.app.confirm_operator(event.value))  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# 主界面
# ---------------------------------------------------------------------------


class MainScreen(Screen):
    """主界面:顶栏 + 叙述流 + 侧栏 + 输入坞 + kill 确认条。"""

    # Ctrl-X/Ctrl-C/Ctrl-P 必须 priority:输入框聚焦时 textual 的 Input 把
    # ctrl+x/ctrl+c 绑给 cut/copy、App 把 ctrl+p 绑给命令面板——kill/暂停是
    # 安全控制面(定案 Q4),无论焦点在哪都要压过编辑类快捷键(编辑功能让位,
    # 选择文本仍可用鼠标复制)。
    BINDINGS = [
        Binding("ctrl+x", "kill_confirm", "Kill", show=False, priority=True),
        Binding("ctrl+c", "kill_confirm", "Kill", show=False, priority=True),
        Binding("ctrl+p", "pause_toggle", "Pause/Resume", show=False, priority=True),
        Binding("f2", "toggle_sidebar", "侧栏", show=False),
        Binding("escape", "dismiss", "取消", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._kill_armed = False
        self._kill_timer = None
        self._sidebar_override: bool | None = None  # None=按宽度自动(D3)

    # ---------- 布局 ----------

    def compose(self) -> ComposeResult:
        yield StatusBar(self.tui.status_line)
        with Horizontal(id="main"):
            yield NarrativeView()
            yield SidebarPane()
        yield KillConfirmBar()
        yield InputDock()

    def on_mount(self) -> None:
        self.set_interval(PANEL_REFRESH_SECONDS, self.refresh_panels)
        self._apply_sidebar_visibility()
        self.input_dock.input_box.focus()

    # ---------- 部件速取 ----------

    @property
    def tui(self) -> TuiApp:
        return self.app  # type: ignore[return-value]

    @property
    def narrative(self) -> NarrativeView:
        return self.query_one("#narrative", NarrativeView)

    @property
    def sidebar(self) -> SidebarPane:
        return self.query_one("#sidebar", SidebarPane)

    @property
    def statusbar(self) -> StatusBar:
        return self.query_one("#statusbar", StatusBar)

    @property
    def input_dock(self) -> InputDock:
        return self.query_one("#inputdock", InputDock)

    @property
    def killbar(self) -> KillConfirmBar:
        return self.query_one("#killbar", KillConfirmBar)

    # ---------- loop 事件渲染(契约:bridge 消息 → 部件) ----------

    def on_status_msg(self, msg: StatusMsg) -> None:
        self.statusbar.set_status(msg.status)

    def on_narrative_msg(self, msg: NarrativeMsg) -> None:
        self.narrative.feed_text(msg.text)

    def on_thinking_msg(self, msg: ThinkingMsg) -> None:
        self.narrative.feed_thinking(msg.text)

    def on_tool_call_msg(self, msg: ToolCallMsg) -> None:
        self.narrative.open_card(msg.name, msg.arguments)

    def on_guard_msg(self, msg: GuardMsg) -> None:
        if not msg.allowed:
            # 护栏拒绝(Q2 自动展开);结果随后到,卡片自带拒绝原因
            self.narrative.mark_pending_denied()

    def on_tool_result_msg(self, msg: ToolResultMsg) -> None:
        card = self.narrative.close_card(msg.name, msg.result)
        if card is None:
            self.narrative.add_notice(
                "error", f"收到无对应卡片的工具结果:{msg.name}(契约外序列)"
            )
        self.run_worker(self.refresh_panels())

    def on_correction_msg(self, msg: CorrectionMsg) -> None:
        label = _CORRECTION_LABELS.get(msg.reason, msg.reason)
        self.narrative.add_notice("correction", label)

    def on_retry_msg(self, msg: RetryMsg) -> None:
        self.narrative.add_notice(
            "retry", f"后端第 {msg.attempt} 次重试:{msg.error[:160]}"
        )

    def on_compressed_msg(self, msg: CompressedMsg) -> None:
        info = msg.info
        self.narrative.add_notice(
            "compressed",
            "context 压缩:估算 "
            f"{info['estimated_tokens_before']}→{info['estimated_tokens_after']}"
            f" tokens(预算 {info['budget']};压 tool 结果 "
            f"{info['tool_results_compressed']} 条、对话 "
            f"{info['conversation_compressed']} 条)",
        )
        self.run_worker(self.refresh_panels())

    def on_phase_msg(self, msg: PhaseMsg) -> None:
        self.narrative.add_phase(msg.phase)
        self.sidebar.set_phase(msg.phase)

    def on_run_finished_msg(self, msg: RunFinishedMsg) -> None:
        if msg.result is not None:
            result = msg.result
            label = {"finished": "已完成", "killed": "已 kill", "error": "出错"}.get(
                result.status, result.status
            )
            self.narrative.add_notice(
                "final",
                f"run {label} · {result.rounds} 轮 · tokens 输入 "
                f"{result.input_tokens} / 输出 {result.output_tokens}",
            )
            if result.error:
                self.narrative.add_notice("error", f"run 结束原因:{result.error}")
        else:
            self.statusbar.set_status("error")
            self.narrative.add_notice("error", f"run 异常终止:{msg.fatal}")
        self.input_dock.input_box.placeholder = (
            "run 已结束;/status 回顾,Ctrl-Q 退出"
        )
        self.run_worker(self.refresh_panels())

    # ---------- 操作员输入(Q4 双通道) ----------

    def on_input_dock_submitted(self, msg: InputDock.Submitted) -> None:
        self.tui.submit_text(msg.text)

    def execute_command(self, raw: str) -> None:
        """斜杠命令分派(v0 七条;未知命令如实报错,不静默)。"""
        command = raw.split(maxsplit=1)[0].lower()
        loop = self.tui.active_loop
        if command == "/help":
            self.narrative.add_notice("help", _HELP_TEXT)
        elif command == "/pause":
            if loop is None:
                self.narrative.add_notice("info", "当前无活动 run")
            else:
                loop.pause()
                self.narrative.add_notice("info", "已请求暂停(当前 turn 跑完后停住)")
        elif command == "/resume":
            if loop is None:
                self.narrative.add_notice("info", "当前无活动 run")
            else:
                loop.resume()
                self.narrative.add_notice("info", "已请求继续")
        elif command == "/kill":
            self.action_kill_confirm()
        elif command == "/jobs":
            self.run_worker(self._show_jobs())
        elif command == "/sessions":
            self.run_worker(self._show_sessions())
        elif command == "/status":
            self._show_status()
        else:
            self.narrative.add_notice(
                "error", f"未知命令 {command};/help 查看可用命令"
            )

    async def _show_jobs(self) -> None:
        bash = self.tui.run_handle.bash if self.tui.run_handle else None
        if bash is None:
            self.narrative.add_notice("info", "尚无 run(exec 层未接线)")
            return
        try:
            data = await bash.list_jobs()
        except (OSError, RuntimeError) as exc:
            self.narrative.add_notice("error", f"list_jobs 失败:{exc!r}")
            return
        jobs = data.get("jobs", [])
        if not jobs:
            self.narrative.add_notice("info", "(无 job)")
            return
        lines = [f"jobs({data.get('count', len(jobs))}):"]
        for job in jobs:
            lines.append(
                f"  {job.get('job_id')}  [{job.get('status')}]"
                f"  {job.get('elapsed_seconds')}s  {job.get('command')}"
            )
        self.narrative.add_notice("info", "\n".join(lines))

    async def _show_sessions(self) -> None:
        handle = self.tui.run_handle
        sessions = handle.sessions if handle else None
        if sessions is None:
            self.narrative.add_notice(
                "info", "会话层未接线(WP-10 接线后可用);当前无 PTY 会话"
            )
            return
        try:
            data = await sessions.session_list()
        except (OSError, RuntimeError) as exc:
            self.narrative.add_notice("error", f"session_list 失败:{exc!r}")
            return
        entries = data.get("sessions", [])
        if not entries:
            self.narrative.add_notice("info", "(无会话)")
            return
        lines = [f"sessions({data.get('count', len(entries))}):"]
        for entry in entries:
            waiting = "  ⏳待输入" if entry.get("pending_events") else ""
            lines.append(
                f"  {entry.get('session_id')}  [{entry.get('status')}]"
                f"  {entry.get('command')}{waiting}"
            )
        self.narrative.add_notice("info", "\n".join(lines))

    def _show_status(self) -> None:
        app = self.tui
        handle = app.run_handle
        lines = [
            f"呼号 {app.operator} · 后端 {app.backend_label}",
            f"状态 {self.statusbar.status}",
        ]
        if handle is not None:
            loop = handle.loop
            used = estimate_tokens(loop.messages)
            lines.append(
                f"context 估算 {used}/{app.config.max_context_tokens} tokens"
            )
            engagement = handle.engagement or app.engagement
            if engagement is not None:
                lines.append(f"engagement {engagement.paths.root}")
                try:
                    counts = engagement.index.counts()
                except (OSError, RuntimeError, ValueError):
                    counts = None
                if counts:
                    lines.append(
                        "索引 "
                        + " · ".join(
                            f"{name} {counts[name]}"
                            for name in ("hosts", "ports", "creds", "vulns")
                        )
                    )
        else:
            lines.append("run 未开始(首条消息为 objective)")
        self.narrative.add_notice("info", "\n".join(lines))

    # ---------- 侧栏显隐(D3) ----------

    def on_resize(self, event) -> None:
        if self._sidebar_override is None:
            self._apply_sidebar_visibility()

    def _apply_sidebar_visibility(self) -> None:
        if self._sidebar_override is None:
            visible = self.app.size.width >= SIDEBAR_MIN_WIDTH
        else:
            visible = self._sidebar_override
        self.sidebar.display = visible

    def action_toggle_sidebar(self) -> None:
        self._sidebar_override = not self.sidebar.display
        self._apply_sidebar_visibility()

    # ---------- kill 二次确认状态机(验收 1) ----------

    @property
    def kill_armed(self) -> bool:
        return self._kill_armed

    def action_kill_confirm(self) -> None:
        """Ctrl-X/Ctrl-C 或 /kill:第一次武装(亮红条),第二次执行,Esc 取消。"""
        loop = self.tui.active_loop
        if loop is None:
            self.narrative.add_notice("info", "当前无活动 run(kill 无对象)")
            return
        if not self._kill_armed:
            self._kill_armed = True
            self.killbar.display = True
            self._kill_timer = self.set_timer(
                KILL_CONFIRM_SECONDS, self._disarm_kill
            )
            return
        self._disarm_kill()
        loop.kill("操作员 Ctrl-X(TUI)")
        self.narrative.add_notice(
            "correction", "已触发 kill switch:中断当前 turn、杀活动 job、写审计…"
        )

    def _disarm_kill(self) -> None:
        self._kill_armed = False
        self.killbar.display = False
        if self._kill_timer is not None:
            self._kill_timer.stop()
            self._kill_timer = None

    def action_dismiss(self) -> None:
        """Esc:优先解除 kill 武装(补全弹层已由输入框先拦)。"""
        if self._kill_armed:
            self._disarm_kill()

    def action_pause_toggle(self) -> None:
        """Ctrl-P:暂停/继续切换(以 loop 当前状态为准)。"""
        loop = self.tui.active_loop
        if loop is None:
            self.narrative.add_notice("info", "当前无活动 run")
            return
        if loop.status == "paused":
            loop.resume()
            self.narrative.add_notice("info", "已请求继续")
        else:
            loop.pause()
            self.narrative.add_notice("info", "已请求暂停(当前 turn 跑完后停住)")

    # ---------- 侧栏轮询(D2/D3) ----------

    async def refresh_panels(self) -> None:
        """轮询侧栏数据源;任何数据源故障都不得炸 UI(保留上次好值)。"""
        app = self.tui
        handle = app.run_handle
        if handle is None:
            return
        if handle.bash is not None:
            try:
                data = await handle.bash.list_jobs()
                self.sidebar.set_jobs(data.get("jobs", []))
            except (OSError, RuntimeError):
                pass  # 保留上次好值;数据源抖动不打扰叙述流
        if handle.sessions is not None:
            try:
                data = await handle.sessions.session_list()
                self.sidebar.set_sessions(data.get("sessions", []))
            except (OSError, RuntimeError):
                pass
        engagement = handle.engagement or app.engagement
        if engagement is not None:
            try:
                self.sidebar.set_counts(engagement.index.counts())
            except (OSError, RuntimeError, ValueError):
                pass
        try:
            used = estimate_tokens(handle.loop.messages)
            self.sidebar.set_budget(used, app.config.max_context_tokens)
        except (TypeError, ValueError):
            pass


# ---------------------------------------------------------------------------
# 应用
# ---------------------------------------------------------------------------


class TuiApp(App[None]):
    """TUI 应用:迎宾屏(呼号门)→ 主界面;单 run 会话。

    启动约定见模块 docstring;``run_tui`` 为 WP-10 的入口函数。
    """

    CSS_PATH = "styles.tcss"
    #: 命令面板用不上(控制面是斜杠命令),且其默认键 Ctrl-P 已让位给暂停。
    ENABLE_COMMAND_PALETTE = False

    def __init__(self, config: TUIConfig) -> None:
        super().__init__()
        self.config = config
        self.operator = ""
        self.engagement: Engagement | None = None
        self.run_handle: RunHandle | None = None
        self._audit: AuditLog | None = None
        self._run_task: asyncio.Task[None] | None = None
        self._final_result: RunResult | None = None
        self._fatal: str | None = None
        self._main: MainScreen | None = None

    # ---------- 展示数据 ----------

    @property
    def backend_label(self) -> str:
        provider = self.config.backend.provider
        return (
            f"{provider} · {self.config.model_label}"
            if self.config.model_label
            else provider
        )

    @property
    def status_line(self) -> str:
        return f"{__app_name__} v{__version__} · {self.backend_label}"

    @property
    def active_loop(self) -> AgentLoop | None:
        """处于活动态(running/paused/idle 未收尾)的 loop;终态返回 None。"""
        handle = self.run_handle
        if handle is None:
            return None
        if handle.loop.status in ("finished", "killed", "error"):
            return None
        return handle.loop

    # ---------- 屏幕流 ----------

    async def on_mount(self) -> None:
        scope_sha = self._scope_sha()
        info = WelcomeInfo(
            wordmark=_gradient_wordmark(
                render_wordmark(__app_name__), "#56d4dd", "#58a6ff"
            ),
            version=__version__,
            backend_label=self.backend_label,
            scope_path=self.config.scope_source,
            scope_rules=len(self.config.scope.rules),
            scope_sha=scope_sha,
            prefill=load_operator(self.config.home_path),
        )
        await self.push_screen(WelcomeScreen(info))

    def _scope_sha(self) -> str:
        try:
            data = Path(self.config.scope_source).read_bytes()
        except OSError:
            return "(不可读)"
        return hashlib.sha256(data).hexdigest()[:12]

    async def confirm_operator(self, name: str) -> None:
        """呼号门:非空校验 → 落本地配置 → 切主界面(loop 此时尚未启动)。"""
        name = name.strip()
        if not name:
            screen = self.screen
            if isinstance(screen, WelcomeScreen):
                screen.show_error("呼号不能为空——输入你的名字再回车")
            return
        self.operator = name
        try:
            save_operator(self.config.home_path, name)
        except OSError:
            pass  # 本地配置预填失败不阻断 engagement(审计侧仍有呼号)
        self._main = MainScreen()
        await self.switch_screen(self._main)

    # ---------- 输入分派(Q4) ----------

    def submit_text(self, text: str) -> None:
        """输入框提交:斜杠命令 / objective(首条)/ 插话。"""
        main = self._main
        if main is None:
            return
        text = text.strip()
        if not text:
            return
        if text.startswith("/"):
            main.execute_command(text)
            return
        if self.run_handle is None:
            main.narrative.add_notice(
                "objective", f"目标(呼号 {self.operator}):{text}"
            )
            self.start_run(text)
            return
        loop = self.active_loop
        if loop is None:
            main.narrative.add_notice(
                "info", "run 已结束;/status 回顾,Ctrl-Q 退出"
            )
            return
        loop.interject(text)
        main.narrative.add_notice(
            "interject", f"插话(呼号 {self.operator}):{text}"
        )

    # ---------- run 生命周期(Q1:首条消息才启动) ----------

    def start_run(self, objective: str) -> None:
        """首条消息触发:建 engagement → 审计链 → 装配 loop → 异步开跑。"""
        if self.run_handle is not None or self._main is None:
            return  # 单 run 会话:重复触发直接忽略
        main = self._main
        try:
            engagement = Engagement.create(
                self.config.engagements_dir,
                objective,
                scope_path=self.config.scope_source,
            )
        except (OSError, ValueError) as exc:
            main.narrative.add_notice("error", f"engagement 创建失败:{exc}")
            return
        engagement.set_operator(self.operator)
        audit = AuditLog(engagement.paths.audit_jsonl)
        audit.append(
            KIND_SCOPE_LOADED,
            scope_payload(self.config.scope, self.config.scope_source),
        )
        ctx = RunContext(
            objective=objective,
            operator=self.operator,
            engagement=engagement,
            audit=audit,
            observer=TuiObserver(main),
            config=self.config,
        )
        factory = self.config.loop_factory or default_loop_factory
        try:
            handle = factory(ctx)
        except Exception as exc:  # 装配失败:如实呈现并收口资源
            audit.close()
            engagement.close()
            main.narrative.add_notice("error", f"loop 装配失败:{exc!r}")
            return
        self.engagement = engagement
        self._audit = audit
        self.run_handle = handle
        main.statusbar.set_engagement(engagement.paths.root.name, self.operator)
        main.input_dock.input_box.placeholder = "插话进队列,或 / 命令"
        self._run_task = asyncio.create_task(self._run_to_end(handle, objective))

    async def _run_to_end(self, handle: RunHandle, objective: str) -> None:
        fatal: str | None = None
        try:
            result = await handle.loop.run(objective)
        except asyncio.CancelledError:
            raise  # 退出路径:如实向上
        except Exception as exc:  # 兜底:AgentLoop 自身已尽收,防自定义 loop
            result = None
            fatal = repr(exc)
        self._final_result = result
        self._fatal = fatal
        if self._audit is not None:
            self._audit.close()
        if self._main is not None:
            self._main.post_message(RunFinishedMsg(result, fatal))

    # ---------- 退出 ----------

    async def action_quit(self) -> None:
        """统一退出路径:run 在活动先走 kill switch 清理,再收资源。"""
        loop = self.active_loop
        if loop is not None:
            loop.kill("操作员退出 TUI")
            if self._run_task is not None:
                try:
                    await asyncio.wait_for(self._run_task, timeout=5.0)
                except (TimeoutError, asyncio.CancelledError):
                    pass  # 清理超时也照常退出(审计每条已 flush,不丢)
        await self._cleanup_resources()
        self.exit(self._exit_code())

    async def _cleanup_resources(self) -> None:
        if self._audit is not None:
            self._audit.close()
            self._audit = None
        handle = self.run_handle
        if handle is not None and handle.sessions is not None:
            try:
                await handle.sessions.aclose()  # WP-05 aclose 幂等
            except (OSError, RuntimeError):
                pass
        if self.engagement is not None:
            self.engagement.close()
        try:
            await self.config.backend.aclose()
        except (OSError, RuntimeError):
            pass

    def _exit_code(self) -> int:
        """与 headless 对齐:finished/未开始 0,killed 130,error 1。"""
        if self._final_result is not None:
            return {"finished": 0, "killed": 130, "error": 1}.get(
                self._final_result.status, 1
            )
        if self._fatal is not None:
            return 1
        return 0


def run_tui(config: TUIConfig) -> int:
    """同步运行 TUI,返回进程退出码(0/130/1);WP-10 的入口走 :func:`main`。"""
    app = TuiApp(config)
    app.run()
    return app._exit_code()


def main(args) -> int:
    """``foam tui`` 子命令入口(WP-10 占位约定的接线点)。

    args 携带 ``--scope/--workdir/--backend/--model/--base-url`` 与 loop
    参数(``--max-context-tokens/--max-rounds/--first-event-timeout``);
    objective 由主界面输入框首条消息提供(定案 Q1)。scope/后端装配复用
    cli 的公开构件与其 ``_build_backend``(cli 注释明示「tui 就绪后也可
    复用」);密钥只由后端从环境变量读取,本层不接触。
    """
    from foam.cli import ENV_MODEL, EXIT_USAGE, _build_backend
    from foam.guard.scope import load_scope

    try:
        scope = load_scope(args.scope)
    except (OSError, ValueError) as exc:
        print(f"[错误] scope 加载失败: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        backend = _build_backend(args)
    except ConfigError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return EXIT_USAGE
    kwargs: dict[str, Any] = {}
    if getattr(args, "max_context_tokens", None) is not None:
        kwargs["max_context_tokens"] = args.max_context_tokens
    if getattr(args, "first_event_timeout", None) is not None:
        kwargs["first_event_timeout"] = args.first_event_timeout
    config = TUIConfig(
        scope=scope,
        scope_source=str(args.scope),
        backend=backend,
        model_label=args.model or os.environ.get(ENV_MODEL) or "",
        engagements_dir=args.workdir or DEFAULT_ENGAGEMENTS_DIR,
        max_rounds=getattr(args, "max_rounds", 0) or 0,
        **kwargs,
    )
    return run_tui(config)
