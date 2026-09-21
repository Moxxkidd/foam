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
- 连续对话(WP-09 更正当 2026-08-24):``TUIConfig.wait_on_finish`` 默认
  True——模型终答后 loop 转 idle 待命(不收尾、不写 run_finished),
  输入框普通文本经 ``loop.interject`` 唤醒续段;顶栏显「待命」,
  placeholder 随之切换。真终态(killed/error)的「run 已结束」提示
  只发一次,placeholder 更新在一处。
- WP-14c scope 确认仪式(定案 Q5/D8/D9):``config.scope is None`` 时首条
  消息承载 objective+NL scope → 仪式 worker 两段结构(编译 → 确认卡 →
  冻结,完成后才调既有 ``start_run``,其同步方法体一字不动);engagement
  在首条消息到达即建(``scope_path=None``)。``/scope`` 裸命令只读展示
  (数据源为 TUI 侧权威引用 ``TUIConfig.scope``,D10),带参经同一仪式
  热换(确认后 ``loop.replace_scope`` 原子换,D2)。file 流零仪式照旧,
  唯一有意变更:链上 ``scope_loaded`` 之后补一条
  ``scope_confirmed(source="file")``(Q8,payload 语义对齐 14b W14b-2)。
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
from textual.worker import Worker

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
from foam.agent.prompts import build_system_prompt, render_scope_section
from foam.agent.scope_compiler import (
    ScopeCompilation,
    ScopeCompileError,
    compile_scope,
    freeze_scope,
    scope_event_payload,
)
from foam.agent.toolmap import render_tool_map, scan_tools
from foam.guard.audit import (
    KIND_SCOPE_CONFIRMED,
    KIND_SCOPE_LOADED,
    KIND_SCOPE_UPDATED,
    AuditLog,
)
from foam.guard.scope import Scope, render_canonical_rules, scope_payload
from foam.state.files import (
    DEFAULT_ENGAGEMENTS_DIR,
    Engagement,
    _default_engagement_id,
)
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
    ScopeCardAction,
    ScopeConfirmCard,
    SidebarPane,
    StatusBar,
)

#: 侧栏自动隐藏阈值(D3:终端宽度 <110 列时默认隐藏,F2 唤出)。
SIDEBAR_MIN_WIDTH = 110
#: kill 二次确认的武装时长(超时自动解除,防误触也防卡死)。
KILL_CONFIRM_SECONDS = 5.0
#: 侧栏/预算轮询间隔(秒)。
PANEL_REFRESH_SECONDS = 2.0

#: 输入框 placeholder 三态(WP-09 更正当:文案只在这一处定义,状态驱动切换)。
#: run 活动(插话/命令)。
_PLACEHOLDER_RUNNING = "插话进队列,或 / 命令"
#: idle 待命(连续对话:输入即插话唤醒续段)。
_PLACEHOLDER_IDLE = "待命;输入继续,/status 回顾,Ctrl-X kill"
#: 真终态(killed/error;wait_on_finish 下 finished 不经过此处)。
_PLACEHOLDER_ENDED = "run 已结束;/status 回顾,Ctrl-Q 退出"

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
  /scope    裸命令=查看当前授权 scope;/scope <描述> 经确认仪式修改
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

    - ``scope``/``scope_source``:授权范围与来源路径(迎宾屏展示 + 审计)。
      WP-14c 起 ``scope`` 可为 None(定案 D9/D10):None = NL 确认仪式流,
      冻结后赋值、``scope_source`` 置 scope.confirmed 绝对路径;``/scope``
      确认后同步更新(TUI 侧权威引用,AgentLoop 无公开读取面)。file 流照旧
      非 None 零仪式;加载失败应在 CLI 层直接报掉。
    - ``backend``:已构造的后端实例(API key 只走环境变量,本层不接触)。
    - ``model_label``:展示用模型名(迎宾屏/顶栏);空串显示 provider 默认。
    - ``config_home``:本地配置目录(呼号预填),默认 ``~/.foam/``。
    - ``loop_factory``:loop 装配钩子,None 用 :func:`default_loop_factory`
      (与 headless 一致的 exec 层装配);WP-10 挂会话/状态工具时传入自定义
      factory,无需改动本包任何文件。
    - ``wait_on_finish``:传给 loop 的待命开关(WP-09 更正当);TUI 是连续
      对话场景,默认 True——终答转 idle 待命,插话续段;headless 默认
      False 不受影响。
    """

    scope: Scope | None
    scope_source: str
    backend: LLMBackend
    model_label: str = ""
    engagements_dir: str | Path = DEFAULT_ENGAGEMENTS_DIR
    max_context_tokens: int = DEFAULT_MAX_CONTEXT_TOKENS
    first_event_timeout: float = FIRST_EVENT_TIMEOUT_SECONDS
    max_rounds: int = 0
    wait_on_finish: bool = True
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
        index=state.index,  # WP-11 声明的一行接线:解析层 facts 入库(TUI 同享)
        operator=ctx.operator,
        max_context_tokens=config.max_context_tokens,
        first_event_timeout=config.first_event_timeout,
        max_rounds=config.max_rounds,
        wait_on_finish=config.wait_on_finish,  # WP-09 更正当:连续对话待命
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
    """迎宾屏展示数据(品牌名只经 __app_name__ 进来,验收 5)。

    ``scope_declared=False``(WP-14c NL 仪式流)时 compose 渲染单行
    「scope 待声明(主界面确认)」,规则计数与 sha 给占位「—」;
    file 流(True)渲染逐字节不变。
    """

    wordmark: Text
    version: str
    backend_label: str
    scope_path: str
    scope_rules: int
    scope_sha: str
    prefill: str
    scope_declared: bool = True


class WelcomeScreen(Screen):
    """全屏迎宾:字标 + 版本 + 后端/scope 状态 + 呼号输入门。"""

    def __init__(self, info: WelcomeInfo) -> None:
        super().__init__()
        self.info = info

    def compose(self) -> ComposeResult:
        with Vertical(id="gate"):
            yield Static(self.info.wordmark, id="wm-logo")
            yield Static(f"v{self.info.version}", id="wm-version")
            if self.info.scope_declared:
                meta_text = (
                    f"后端  {self.info.backend_label}\n"
                    f"scope {self.info.scope_path} · {self.info.scope_rules} 条规则"
                    f" · sha256:{self.info.scope_sha}"
                )
            else:
                # WP-14c NL 仪式流(D9):scope 待声明,计数与 sha 占位「—」
                meta_text = (
                    f"后端  {self.info.backend_label}\n"
                    "scope 待声明(主界面确认) · 规则 — · sha256:—"
                )
            yield Static(meta_text, id="wm-meta", markup=False)
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
        self._end_hint_shown = False  # 「run 已结束」提示只发一次(更正当)

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
        # WP-09 更正当:placeholder 随 loop 状态切换(待命↔活动);终态文案
        # 由 on_run_finished_msg 一次落定,这里不碰。
        if msg.status == "idle":
            self.input_dock.input_box.placeholder = _PLACEHOLDER_IDLE
        elif msg.status == "running":
            self.input_dock.input_box.placeholder = _PLACEHOLDER_RUNNING

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
        self.input_dock.input_box.placeholder = _PLACEHOLDER_ENDED
        self.run_worker(self.refresh_panels())

    # ---------- 操作员输入(Q4 双通道) ----------

    def on_input_dock_submitted(self, msg: InputDock.Submitted) -> None:
        self.tui.submit_text(msg.text)

    def execute_command(self, raw: str) -> None:
        """斜杠命令分派(v0 八条;未知命令如实报错,不静默)。"""
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
        elif command == "/scope":
            parts = raw.split(maxsplit=1)
            argument = parts[1].strip() if len(parts) > 1 else ""
            if argument:
                self._request_scope_change(argument)
            else:
                self._show_scope()
        else:
            self.narrative.add_notice(
                "error", f"未知命令 {command};/help 查看可用命令"
            )

    # ---------- /scope(WP-14c:裸=只读展示 D3/D10;带参=同一仪式热换 Q5) ----------

    def _show_scope(self) -> None:
        """裸 /scope:canonical 逐行 + 计数 + 来源 + canonical sha256 短哈希
        12 位(只读;数据源为 TUI 侧权威引用 ``TUIConfig.scope``,不回读 loop)。"""
        app = self.tui
        scope = app.config.scope
        if scope is None:
            self.narrative.add_notice(
                "info",
                "尚未声明授权 scope——发送首条消息(自然语言描述目标与范围),"
                "或 /scope <描述> 启动确认仪式",
            )
            return
        canonical = render_canonical_rules(scope.rules)
        # 哈希口径与链上记录/迎宾屏/engagement meta 对齐(第二轮对抗审查
        # 修复):NL 冻结物即 canonical 字节(两口径恒等);file 流取文件字节
        # sha256(W14b-2 同口径),免同一「canonical sha256」标签两个值。
        try:
            digest = hashlib.sha256(
                Path(app.config.scope_source).read_bytes()
            ).hexdigest()
        except OSError:
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        sha = digest[:12]
        lines = [
            f"当前授权 scope · 来源:{app.config.scope_source} · "
            f"canonical sha256:{sha}"
        ]
        if scope.rules:
            lines.extend(f"  {rule}" for rule in scope.rules)
        else:
            lines.append("  (空——任何网络目标都会被拒)")
        lines.append(f"共 {len(scope.rules)} 条;修改经 /scope <描述> 确认仪式")
        self.narrative.add_notice("info", "\n".join(lines))

    def _request_scope_change(self, argument: str) -> None:
        """带参 /scope 状态机(Q5 三路共用同一仪式实现;D2 终态拒绝)。"""
        app = self.tui
        if app.ceremony_running:
            self.narrative.add_notice(
                "info", "scope 确认仪式进行中,请先完成确认卡"
            )
            return
        if app.run_handle is not None and app.active_loop is None:
            self.narrative.add_notice("info", "run 已结束,scope 不可更改(D2)")
            return
        if app.active_loop is not None:
            app.start_scope_ceremony(argument, mode="update")
            return
        if app.config.scope is None or app.scope_frozen_via_nl:
            # 未启动 + 未声明 → 预声明;未启动 + 已 NL 冻结 → 同一仪式重新声明
            app.start_scope_ceremony(argument, mode="predeclare")
            return
        self.narrative.add_notice(
            "info",
            "scope 已由 --scope 指定;改用 NL 声明请不带 --scope 重启",
        )

    def on_scope_card_action(self, msg: ScopeCardAction) -> None:
        """确认卡动作 → 回填仪式 worker 的 future(编译循环继续)。"""
        self.tui.resolve_scope_card_action(msg)

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
        # WP-14c scope 仪式单例守卫(D9,与 start_run 单 run 守卫同构):
        # worker 引用 + 卡动作回填 future(None = 当前无仪式/无待答卡)。
        self._ceremony: Worker[None] | None = None
        self._ceremony_action: asyncio.Future[ScopeCardAction] | None = None
        # scope 来源谱系(D10 配套):NL 仪式冻结过 → 未启动时可再 /scope 重声明
        # (file 流未启动带参 /scope 一律拒并指引,见 _request_scope_change)。
        self._scope_frozen_via_nl = False

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

    @property
    def ceremony_running(self) -> bool:
        """scope 确认仪式是否在进行中(D9 单例守卫的读取面)。"""
        return self._ceremony is not None

    @property
    def scope_frozen_via_nl(self) -> bool:
        """本会话的 scope 是否经 NL 仪式冻结(/scope 状态机分支依据)。"""
        return self._scope_frozen_via_nl

    # ---------- 屏幕流 ----------

    async def on_mount(self) -> None:
        declared = self.config.scope is not None
        info = WelcomeInfo(
            wordmark=_gradient_wordmark(
                render_wordmark(__app_name__), "#56d4dd", "#58a6ff"
            ),
            version=__version__,
            backend_label=self.backend_label,
            # NL 仪式流(D9):scope 待声明,占位值不进 compose(渲染分支钉死)
            scope_path=self.config.scope_source if declared else "",
            scope_rules=len(self.config.scope.rules) if declared else 0,
            scope_sha=self._scope_sha(),
            prefill=load_operator(self.config.home_path),
            scope_declared=declared,
        )
        await self.push_screen(WelcomeScreen(info))

    def _scope_sha(self) -> str:
        if self.config.scope is None:
            return "—"  # NL 仪式流(D9):冻结前无文件可哈希
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
        if self.ceremony_running:
            # D9 worker 单例守卫(与 start_run 单 run 守卫同构):仪式中再发
            # 普通文本提示并忽略,不重复启动 worker。
            main.narrative.add_notice(
                "info", "scope 确认仪式进行中,请先完成确认卡"
            )
            return
        if self.run_handle is None:
            main.narrative.add_notice(
                "objective", f"目标(呼号 {self.operator}):{text}"
            )
            if self.config.scope is None:
                # NL 仪式流(Q5):首条消息承载 objective+NL scope,冻结完成前
                # loop 不启动(「scope 冻结前 loop 不启动」)。
                self.start_scope_ceremony(text, mode="startup")
                return
            if self._scope_frozen_via_nl:
                # NL 冻结后首条消息:先把 run engagement 预备齐(meta 对账+
                # 动态段),再 start_run 幂等复开——生产 eager_task_factory
                # 下 create_task 同步开跑,开跑后再写段首轮上下文只剩占位
                # (第二轮对抗审查修复)。
                self._prepare_nl_run_engagement(text)
            self.start_run(text)
            if not self._scope_frozen_via_nl:
                self._append_file_scope_confirm()
            return
        loop = self.active_loop
        if loop is None:
            # 真终态后的文本:提示只发一次(更正当,截图级观感——重复刷屏),
            # 常态指引由 placeholder(_PLACEHOLDER_ENDED)承担。
            if not main._end_hint_shown:
                main._end_hint_shown = True
                main.narrative.add_notice("info", _PLACEHOLDER_ENDED)
            return
        loop.interject(text)
        main.narrative.add_notice(
            "interject", f"插话(呼号 {self.operator}):{text}"
        )

    def _append_file_scope_confirm(self) -> None:
        """Q8:file 流补写 ``scope_confirmed(source="file")``(``start_run``
        返回后、``scope_loaded`` 相邻之后;start_run 失败则 ``_audit`` 未就绪,
        不补)。payload 经 14a ``scope_event_payload`` 单源构造,语义对齐 14b
        W14b-2:``path`` = as-given 原串、``canonical_sha256`` = scope 文件字节
        sha256(取刚写入的 engagement.json meta,免二次读盘的 TOCTOU)。

        scope 由 NL 仪式冻结(``_scope_frozen_via_nl``)时不补:确认事实已在
        仪式 engagement 链上以 ``source="nl"`` 落账,此处补 ``source="file"``
        会错标来源(第一轮对抗审查修复)。
        """
        if self._scope_frozen_via_nl:
            return
        if self._audit is None or self.engagement is None:
            return
        scope = self.config.scope
        if scope is None:
            return  # 防御:file 流恒非 None
        file_sha256 = self.engagement.metadata()["scope"]["sha256"]
        payload = scope_event_payload(
            scope,
            source="file",
            path=self.config.scope_source,
            canonical_sha256=file_sha256,
        )
        try:
            self._audit.append(KIND_SCOPE_CONFIRMED, payload)
        except ValueError:
            # 第二轮对抗审查修复:生产 eager_task_factory 下,同步完结的 run
            # 可能在 start_run 返回前已收尾并关闭共享句柄;链已封口即无
            # 竞态写者,重开补写(AuditLog 重开恢复尾序 seq/prev_hash)。
            audit = AuditLog(self.engagement.paths.audit_jsonl)
            try:
                audit.append(KIND_SCOPE_CONFIRMED, payload)
            finally:
                audit.close()

    def _prepare_nl_run_engagement(self, text: str) -> None:
        """NL 冻结(predeclare/重新声明)后首条消息开跑前的 run engagement
        预备(第二轮对抗审查修复;两段结构 D9 的预声明变体,start_run 本体
        一字不动,其后的幂等复开因本预备而同参通过):

        - 目录不存在:按当前冻结 scope 创建(meta.scope 随 create 一步写齐)
          + 动态段写入——loop 首轮读到的即是已确认规则(生产 eager 调度下
          create_task 同步开跑,事后再写段只剩「尚未冻结」占位);
        - 目录已存在(同 objective 此前跑过旧 scope):meta.scope 对账为当前
          冻结 scope——否则 start_run 的 create 幂等复开撞 scope 一致性
          检查,该 objective 当天永久无法启动(冲突物是内部路径,NL 用户
          无可行动指引);漂移在 run 链上留痕:旧值有 sha256 →
          ``scope_updated``(old/new 键,D13),旧值为空(曾取消的仪式目录)
          → ``scope_confirmed(source="nl")`` 指针记录;动态段同步重写。
          对账 = startup 仪式 freeze_scope ② 写 meta 的同义动作,确认事实
          与 NL 出处键在仪式 engagement 链上,本片不重复。

        create/open/对账失败时不重复报错:start_run 将以同参重试 create
        并给出自己的「engagement 创建失败」指引。
        """
        scope = self.config.scope
        main = self._main
        if scope is None or main is None:
            return
        root = Path(self.config.engagements_dir) / _default_engagement_id(text)
        engagement: Engagement
        sha256 = ""
        try:
            if (root / "engagement.json").exists():
                engagement = Engagement.open(root)
                old_scope_meta = engagement.metadata().get("scope") or {}
                new_scope_meta = engagement.update_scope_metadata(
                    self.config.scope_source
                )["scope"]
                sha256 = new_scope_meta["sha256"]
                if old_scope_meta != new_scope_meta:
                    audit = AuditLog(engagement.paths.audit_jsonl)
                    try:
                        audit.append(
                            KIND_SCOPE_UPDATED
                            if old_scope_meta.get("sha256")
                            else KIND_SCOPE_CONFIRMED,
                            scope_event_payload(
                                scope,
                                source="nl",
                                path=self.config.scope_source,
                                canonical_sha256=sha256,
                                old_sha256=old_scope_meta.get("sha256"),
                            ),
                        )
                    finally:
                        audit.close()
            else:
                engagement = Engagement.create(
                    self.config.engagements_dir,
                    text,
                    scope_path=self.config.scope_source,
                )
                sha256 = (engagement.metadata().get("scope") or {}).get(
                    "sha256", ""
                )
        except (OSError, ValueError):
            return  # start_run 同参重试 create 时给出自己的报错指引
        try:
            engagement.update_scope_section(
                render_scope_section(
                    scope.rules,
                    source=self.config.scope_source,
                    sha256=sha256,
                    frozen_at=datetime.now(UTC).isoformat(timespec="seconds"),
                )
            )
        except OSError as exc:
            main.narrative.add_notice("error", f"scope 动态段写入失败:{exc}")

    # ---------- scope 确认仪式(WP-14c:Q5 三路共用同一实现) ----------

    def start_scope_ceremony(self, text: str, *, mode: str) -> None:
        """启动 scope 仪式 worker(单例守卫,D9)。

        ``mode``:``startup``=首条消息承载 objective+NL scope(冻结后才调
        ``start_run``);``predeclare``=run 前 /scope 先声明(不启动 loop);
        ``update``=运行中 /scope 热换(确认后 ``loop.replace_scope``,D2)。
        """
        if self._ceremony is not None or self._main is None:
            return  # 仪式单例:调用方负责提示,这里直接忽略
        worker = self.run_worker(self._scope_ceremony(text, mode=mode))
        if worker.is_finished:
            # textual 在 Python≥3.12 下设 eager_task_factory:协程可能在
            # run_worker 内同步跑完(如同步失败早退),其 finally 已清守卫
            # 字段;此时把已完成 worker 赋回 _ceremony 会让单例守卫永久
            # 锁死(第一轮对抗审查修复,勿回归)。
            self._ceremony = None
        else:
            self._ceremony = worker

    def _ceremony_engagement(
        self, text: str, *, predeclare: bool = False
    ) -> Engagement | None:
        """D8 engagement 获取:以当前文本 derive id——``engagement.json`` 存在
        走 ``Engagement.open``(绕过 create 的 objective 冲突检查:取消后重发
        可换文本),不存在才 ``Engagement.create(objective=text, scope_path=None)``
        (meta["scope"] 记 None,使仪式期编译调用有审计链可落)。

        ``predeclare=True`` 时 derive id 加 ``scope-predeclare-`` 前缀(第一
        轮对抗审查修复):预声明 engagement 的 objective 是 scope 文本,若与
        首条消息派生同目录(纯中文输入 slug 恒为 "engagement",必然相碰),
        ``start_run`` 的 create 幂等复开会因 objective 冲突永远拒绝启动;
        前缀把预声明目录与 objective 派生目录隔开命名空间,而同文本→同
        目录的复用语义(D8 初衷)不变。
        """
        engagement_id = (
            _default_engagement_id(f"scope-predeclare-{text}")
            if predeclare
            else None
        )
        root = Path(self.config.engagements_dir) / (
            engagement_id or _default_engagement_id(text)
        )
        try:
            if (root / "engagement.json").exists():
                return Engagement.open(root)
            return Engagement.create(
                self.config.engagements_dir,
                text,
                scope_path=None,
                engagement_id=engagement_id,
            )
        except (OSError, ValueError) as exc:
            if self._main is not None:
                self._main.narrative.add_notice(
                    "error", f"engagement 创建失败:{exc}"
                )
            return None

    async def _scope_ceremony(self, text: str, *, mode: str) -> None:
        """仪式本体:engagement 获取(D8)→ 编译循环(确认卡)→ 冻结 → 两段
        结构(D9)。worker 自开 AuditLog 续链(update 除外:直接用运行中句柄);
        任何异常如实上屏收口,不炸 app(run_worker 默认 exit_on_error)。
        """
        main = self._main
        if main is None:  # start_scope_ceremony 已守卫;防御兜底
            self._ceremony = None
            return
        audit: AuditLog | None = None
        own_audit = False
        card = ScopeConfirmCard()
        card_mounted = False
        try:
            if mode == "update":
                engagement = self.engagement
                audit = self._audit
                if engagement is None or audit is None:
                    main.narrative.add_notice(
                        "error", "运行中 engagement/审计句柄缺失,无法热换 scope"
                    )
                    return
            else:
                engagement = self._ceremony_engagement(
                    text, predeclare=mode == "predeclare"
                )
                if engagement is None:
                    return  # 报错已上屏
                engagement.set_operator(self.operator)
                audit = AuditLog(engagement.paths.audit_jsonl)
                own_audit = True

            main.narrative.mount_scope_card(card)
            card_mounted = True

            # 编译循环:每次调用(含修正、失败路径)由 14a 编译器经 audit 形参
            # 现场落 llm_exchange_meta(D7),本片不重复 append。
            corrections: list[str] = []
            attempts = 0
            compilation: ScopeCompilation | None = None
            while True:
                card.set_compiling()
                try:
                    compilation = await compile_scope(
                        text,
                        self.config.backend,  # D5:复用同一后端实例
                        corrections=corrections,
                        current=(
                            list(self.config.scope.rules)
                            if mode == "update" and self.config.scope is not None
                            else None
                        ),
                        audit=audit,
                    )
                    attempts += 1
                    card.update_compilation(compilation, attempts)
                except ScopeCompileError as exc:
                    attempts += 1
                    card.update_error(str(exc), attempts)
                except ValueError:
                    # 第二轮对抗审查修复:update 仪式编译在途(含修正重编译)
                    # 期间 run 终态化——_run_to_end 已关闭共享审计句柄,
                    # compile_scope 的落账 finally 在已关句柄上炸 ValueError
                    # (该次 D7 记录随句柄关闭而缺,链本身完整可验);按 D2
                    # 收口而非裸抛内部异常。
                    if mode == "update" and self.active_loop is None:
                        main.narrative.add_notice(
                            "info",
                            "run 已结束,scope 不可更改(D2);仪式终止",
                        )
                        return
                    raise
                action = await self._await_card_action()
                if action.action == "cancel":
                    main.narrative.add_notice(
                        "info",
                        "已取消 scope 修改,现状不变"
                        if mode == "update"
                        else "已取消;重发首条消息可重新声明",
                    )
                    return
                if action.action == "correct":
                    corrections.append(action.correction)
                    continue
                break  # confirm:卡在无合法产物时不发 confirm,此处必有 compilation

            if compilation is None:
                # 卡侧已保证 confirm 只在有合法产物时发出;防御兜底不收冻结
                main.narrative.add_notice(
                    "error", "scope 仪式内部状态异常:无编译产物,未冻结"
                )
                return

            # 冻结(14a freeze_scope 唯一入口,D13 写序)→ 两段结构(D9)
            if mode == "update" and self.active_loop is None:
                # 第一轮对抗审查修复:仪式挂起等卡期间 run 可能已终态
                # (_run_to_end 收尾并关闭共享审计句柄)——此时 freeze_scope
                # 尾步 audit.append 会在已关句柄上炸 ValueError,落出半冻结
                # 态(链上无 scope_updated);D2 终态拒绝,不冻结。本检查与
                # freeze_scope 同步体之间无 await,单线程原子。
                main.narrative.add_notice(
                    "info", "run 已结束,scope 不可更改(D2);未冻结"
                )
                return
            old_sha256 = None
            if mode == "update" and self.config.scope is not None:
                # 谱系口径(第一轮对抗审查修复):与链上最近一条 scope 记录的
                # canonical_sha256 对齐——取 engagement.json meta 的 sha256
                # (NL 冻结物即 canonical 渲染字节,二者恒等;file 流则为
                # 文件字节哈希,与链上 source="file" 记录同口径),免注释与
                # 换行的渲染差异断谱系。
                old_sha256 = (engagement.metadata().get("scope") or {}).get(
                    "sha256"
                )
                if old_sha256 is None:  # 防御:meta 缺 scope 段退回渲染口径
                    old_sha256 = hashlib.sha256(
                        render_canonical_rules(
                            self.config.scope.rules
                        ).encode("utf-8")
                    ).hexdigest()
            frozen_sha = freeze_scope(
                engagement,
                audit,
                compilation,
                source="nl",
                nl_text=text,
                old_sha256=old_sha256,
                objective=text if mode != "update" else None,  # D8 最新文本
                compile_attempts=attempts,
            )
            if own_audit:
                # 先关 worker 自有链句柄,start_run 重开续链(seq 不断)
                audit.close()
                own_audit = False
                audit = None
            # D10:TUI 侧权威引用同步更新(path 取冻结刚落盘的 meta,单源)
            meta_scope = engagement.metadata()["scope"]
            self.config.scope = compilation.scope
            self.config.scope_source = meta_scope["path"]
            self._scope_frozen_via_nl = True
            summary = (
                f"scope 已确认冻结:{len(compilation.rules)} 条规则 · "
                f"canonical sha256:{frozen_sha[:12]}"
            )
            if mode == "startup":
                main.narrative.add_notice("success", summary)
                # D9 两段结构:冻结完成后才调既有 start_run(其方法体不动;
                # 幂等复开同参目录——objective/scope meta 已由冻结写齐)。
                self.start_run(text)
            elif mode == "update":
                loop = self.active_loop
                if loop is not None:
                    loop.replace_scope(compilation.scope)  # D2 原子换
                main.narrative.add_notice(
                    "success", summary + "(下一条命令即生效)"
                )
            else:  # predeclare:不启动 loop
                main.narrative.add_notice(
                    "success", summary + ";发送首条消息启动 run"
                )
        except Exception as exc:  # 仪式异常:如实上屏收口,不炸 app
            main.narrative.add_notice("error", f"scope 仪式异常:{exc!r}")
        finally:
            if own_audit and audit is not None:
                audit.close()
            if card_mounted:
                await card.remove()
            self._ceremony_action = None
            self._ceremony = None

    async def _await_card_action(self) -> ScopeCardAction:
        """挂起仪式 worker,等 operator 的确认卡动作(MainScreen 回填)。"""
        future: asyncio.Future[ScopeCardAction] = (
            asyncio.get_running_loop().create_future()
        )
        self._ceremony_action = future
        try:
            return await future
        finally:
            self._ceremony_action = None

    def resolve_scope_card_action(self, action: ScopeCardAction) -> None:
        """卡动作回填仪式 future(MainScreen.on_scope_card_action 转发至此)。"""
        future = self._ceremony_action
        if future is not None and not future.done():
            future.set_result(action)

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
        main.input_dock.input_box.placeholder = _PLACEHOLDER_RUNNING
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

    WP-14c:``--scope`` 由 CLI 侧改可选(cli.py 归属 14b);``args.scope``
    为 None 时跳过 ``load_scope``,以 ``scope=None, scope_source=""`` 进 NL
    确认仪式流;给定时逐字节照旧。
    """
    from foam.cli import ENV_MODEL, EXIT_USAGE, _build_backend
    from foam.guard.scope import load_scope

    scope: Scope | None = None
    scope_source = ""
    if args.scope is not None:
        try:
            scope = load_scope(args.scope)
        except (OSError, ValueError) as exc:
            print(f"[错误] scope 加载失败: {exc}", file=sys.stderr)
            return EXIT_USAGE
        scope_source = str(args.scope)
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
        scope_source=scope_source,
        backend=backend,
        model_label=args.model or os.environ.get(ENV_MODEL) or "",
        engagements_dir=args.workdir or DEFAULT_ENGAGEMENTS_DIR,
        max_rounds=getattr(args, "max_rounds", 0) or 0,
        **kwargs,
    )
    return run_tui(config)
