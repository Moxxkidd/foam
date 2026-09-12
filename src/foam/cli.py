"""命令行入口(WP-10 闭环):run / resume / replay / report / tui。

职责:加载 scope → 建/开 engagement 目录(WP-06 布局)→ 装配 exec/会话/
状态三组工具(WP-01/05/06,经 ToolRegistry.register_module)→ 主环(WP-04)
跑完一个 objective;replay/report 只读审计链与索引库(实现见 replay.py)。

- resume:重建 system prompt + ENGAGEMENT.md(每轮必载机制)+ 最近 N 轮
  审计元信息简报(经 loop.interject 注入);明确不做全量对话回放恢复。
- replay:先校验哈希链(WP-02 语义),链断报断点 seq 并中止;完整才只读
  重放元信息时间线。
- report:中文 markdown(目标/范围/时间线/发现含证据/凭证全值/loot/插话)。
- tui:全屏 TUI(WP-09 已交付)——模块不可导入时给明确报错;入口约定
  ``foam.tui.app:main(args)``(args 含 --scope/--backend/--model/--base-url/
  --workdir;objective 由 TUI 主界面输入框首条消息提供,见 WP-09 定案 Q1)。

退出码:0 = finished/成功;130 = killed(含 Ctrl-C);1 = error(含审计链
校验未通过);2 = 参数/配置/前置条件错误(缺文件、TUI 依赖缺失等)。
密钥只走环境变量(各后端自己的 env key);本文件不接触 key 本体。

配置持久化(P1-1,2026-09-12 冻结契约):入口只读加载 ./.env(注入缺省
环境变量,绝不写它);run/resume/tui 装配前经 resolve_backend_args 就地回填
backend/model/base_url,优先级(每键独立):CLI flag > 环境变量
(FOAM_LLM_MODEL/FOAM_LLM_BASE_URL)> profile(--profile 指定,否则
active_profile)> 内置默认(k3/claude-sonnet-5);backend 无 env 通道。
env base_url 对 claude 同样生效(经 resolve_backend_args 回填进
args.base_url;P1-1 起的行为改进,README 已文档化)。
--save-profile 在装配成功后落盘(~/.foam/config.json,0600,白名单仅
backend/model/base_url——密钥永不落盘);坏配置(ConfigError)不落盘。
2026-09-12 对抗审查修复:profile 名先过 validate_profile_name(非法→
ConfigError 路径,退出码 2);落盘副本与上屏副本的 base_url 经
sanitize_url 脱敏(剥 userinfo、敏感 query 打码),运行时传给后端的
args.base_url 原值不动;tui 在 --save-profile 落盘前先 _build_backend
预检(与 run/resume 口径拉齐)。
2026-09-12 第三轮(fail-closed 反转):sanitize_url 改 fail-closed——
畸形或含凭证却剥不出干净 host 的 base_url 抛 ValueError;--save-profile
路径捕获后转 ConfigError(stderr 中文「base_url 无法解析,为防凭证泄漏
已拒绝保存 profile」+ 退出码 2,不回显原 URL,零落盘);[config] 可见性行
的 base_url 脱敏失败时显示占位符 <无法解析,已脱敏>,profile 名两条回显
路径(--profile 指定名 / active_profile 名)统一过 _printable 可打印过滤
(非可打印字符转义,防 ANSI 染色与换行伪造日志行)。

本文件所有权:WP-04 初版 → WP-10 接管(两 WP 开发日志均有声明)。
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import signal
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from foam import __app_name__, __version__
from foam.agent.backends.base import ConfigError, LLMBackend, ToolCall
from foam.agent.backends.claude import DEFAULT_BASE_URL, ClaudeBackend
from foam.agent.backends.openai_compat import OpenAICompatBackend
from foam.agent.loop import AgentLoop, LoopObserver, RunResult, ToolRegistry
from foam.agent.prompts import build_system_prompt
from foam.agent.toolmap import render_startup_line, render_tool_map, scan_tools
from foam.config import (
    active_profile,
    get_profile,
    load_config,
    load_dotenv,
    put_profile,
    sanitize_url,
    validate_profile_name,
)
from foam.guard.audit import KIND_SCOPE_LOADED, AuditLog
from foam.guard.scope import GuardDecision, Scope, load_scope, scope_payload
from foam.replay import (
    build_report,
    build_resume_briefing,
    chain_errors,
    find_chain_break,
    format_timeline,
    read_records,
    recover_objective,
    recover_scope_record,
)
from foam.state.files import Engagement
from foam.tools.bash import TOOL_SCHEMAS as BASH_TOOL_SCHEMAS
from foam.tools.bash import BashTool
from foam.tools.session import TOOL_SCHEMAS as SESSION_TOOL_SCHEMAS
from foam.tools.session import SessionTool
from foam.tools.state import TOOL_SCHEMAS as STATE_TOOL_SCHEMAS
from foam.tools.state import StateTool

#: openai_compat 的默认模型(WP-03 实测模型);可用 --model 或 env 覆盖。
DEFAULT_OPENAI_MODEL = "k3"
#: claude 后端的默认模型;可用 --model 或 env 覆盖。
DEFAULT_CLAUDE_MODEL = "claude-sonnet-5"
#: 非密钥配置环境变量(API key 由各后端自己的 env 读取,不经本文件)。
ENV_BASE_URL = "FOAM_LLM_BASE_URL"
ENV_MODEL = "FOAM_LLM_MODEL"

#: 退出码
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_KILLED = 130

#: resume 注入简报的「最近 N 轮」默认值。
DEFAULT_RECENT_ROUNDS = 5

BackendFactory = Callable[[argparse.Namespace], LLMBackend]


class _CliObserver(LoopObserver):
    """headless 渲染:模型文本流式上屏,工具/护栏/纠正各一行摘要。"""

    def __init__(self, out: Any = None) -> None:
        self._out = out or sys.stdout

    def _line(self, text: str) -> None:
        print(text, file=self._out, flush=True)

    def on_text_delta(self, text: str) -> None:
        print(text, end="", file=self._out, flush=True)

    def on_tool_call(self, call: ToolCall) -> None:
        args = json.dumps(call.arguments, ensure_ascii=False)
        if len(args) > 200:
            args = args[:200] + "…"
        self._line(f"\n[tool→] {call.name} {args}")

    def on_guard(self, decision: GuardDecision) -> None:
        if decision.allowed:
            targets = ", ".join(decision.targets) or "(无网络目标)"
            self._line(f"[guard] 放行:{targets}")
        else:
            self._line(f"[guard] 拒绝:越界目标 {list(decision.violations)}")

    def on_tool_result(self, name: str, result: dict[str, Any]) -> None:
        if "error" in result:
            self._line(f"[result] {name}: error={result['error'][:160]}")
            return
        parts = [f"[result] {name}:"]
        for key in ("status", "exit_code", "duration_ms", "total_bytes"):
            if result.get(key) is not None:
                parts.append(f"{key}={result[key]}")
        if result.get("sha256"):
            parts.append(f"sha256={str(result['sha256'])[:12]}…")
        if result.get("exit_note"):
            parts.append(f"({result['exit_note']})")
        self._line(" ".join(parts))

    def on_correction(self, reason: str) -> None:
        self._line(f"[纠正] {reason}:已向模型回灌纠正说明")

    def on_retry(self, attempt: int, error: str) -> None:
        self._line(f"[重试] 第 {attempt} 次:{error[:160]}")

    def on_compressed(self, info: dict[str, Any]) -> None:
        self._line(
            "[context] 压缩:估算 "
            f"{info['estimated_tokens_before']}→{info['estimated_tokens_after']} "
            f"tokens(预算 {info['budget']},压 tool 结果 "
            f"{info['tool_results_compressed']} 条、对话 "
            f"{info['conversation_compressed']} 条)"
        )

    def on_status(self, status: str) -> None:
        if status in ("paused", "killed", "error"):
            self._line(f"[status] {status}")


# ---------------------------------------------------------------------------
# 参数面
# ---------------------------------------------------------------------------


def _add_backend_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--backend",
        choices=["openai_compat", "claude"],
        default=None,
        help="LLM 后端(不给时按解析链:--profile / 上次保存的 profile > "
        "内置默认 openai_compat;backend 无环境变量通道,维持现状)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=f"模型 id(解析链:flag > env {ENV_MODEL} > profile > 内置默认:"
        f"openai_compat={DEFAULT_OPENAI_MODEL} / claude={DEFAULT_CLAUDE_MODEL})",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help=f"API base url(解析链:flag > env {ENV_BASE_URL} > profile;"
        "openai_compat 必填,claude 缺省为官方端点)",
    )
    parser.add_argument(
        "--profile",
        default=None,
        metavar="NAME",
        help="使用指定 profile(~/.foam/config.json 里保存的 backend/model/"
        "base-url;不给时用 active_profile,即上次 --save-profile 记住的选择)",
    )
    parser.add_argument(
        "--save-profile",
        default=None,
        metavar="NAME",
        help="本次装配成功后,把解析出的 backend/model/base-url 存为 profile "
        "并设为 active(下次启动自动生效;密钥永不落盘,仍只走环境变量;"
        "base-url 落盘副本脱敏——剥 userinfo、敏感 query 打码,运行时原值不动)",
    )


def _add_loop_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--max-context-tokens",
        type=int,
        default=None,
        help="context 压缩预算(token 粗估,默认 120000)",
    )
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=0,
        help="LLM 轮数上限,0 为不限(默认 0;headless 兜底阀)",
    )
    parser.add_argument(
        "--first-event-timeout",
        type=float,
        default=None,
        help="等 LLM 首事件的超时秒数(默认 30,实测最慢 16.24s)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=__app_name__.lower(),
        description=f"{__app_name__} {__version__} —— 授权渗透测试 harness",
    )
    parser.add_argument(
        "--version", action="version", version=f"{__app_name__} {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser(
        "run",
        help="headless 跑一个 objective(新 engagement)",
        epilog="Ctrl-C 一次触发 kill switch(杀活动 job 与会话、写审计、退出码 "
        "130);再按一次立即强制退出。",
    )
    run.add_argument("--scope", required=True, help="scope 授权范围文件路径")
    run.add_argument("--objective", required=True, help="本次 engagement 的目标描述")
    run.add_argument(
        "--workdir",
        default=None,
        help="engagement 目录(默认 engagements/<日期>-<目标 slug>;"
        "已存在且参数一致时幂等复开)",
    )
    _add_backend_args(run)
    _add_loop_args(run)

    resume = sub.add_parser(
        "resume",
        help="从 engagement 目录恢复继续跑(最近 N 轮简报,非全量回放)",
        description="重建 system prompt + ENGAGEMENT.md(每轮必载)+ 最近 N 轮 "
        "审计元信息简报。objective/scope 依次取:命令行覆盖 > engagement.json "
        "> 审计链恢复;审计链校验未通过则拒绝 resume。",
    )
    resume.add_argument("engagement_dir", help="engagement 目录路径")
    resume.add_argument("--scope", default=None, help="scope 文件(覆盖恢复值)")
    resume.add_argument("--objective", default=None, help="目标描述(覆盖恢复值)")
    resume.add_argument(
        "--recent-rounds",
        type=int,
        default=DEFAULT_RECENT_ROUNDS,
        help=f"简报携带的最近轮数(默认 {DEFAULT_RECENT_ROUNDS})",
    )
    _add_backend_args(resume)
    _add_loop_args(resume)

    replay = sub.add_parser(
        "replay",
        help="校验哈希链并只读重放审计时间线(链断报断点 seq)",
    )
    replay.add_argument("engagement_dir", help="engagement 目录路径")

    report = sub.add_parser(
        "report",
        help="生成中文 markdown 报告(索引库 + ENGAGEMENT.md + 审计链)",
    )
    report.add_argument("engagement_dir", help="engagement 目录路径")
    report.add_argument(
        "--out",
        default=None,
        help="报告输出文件(默认打印到 stdout;凭证节为全值,注意去向)",
    )

    tui = sub.add_parser(
        "tui",
        help="全屏 TUI(textual 界面;依赖缺失时给出明确报错)",
        description="TUI 入口(WP-09 定案):scope/backend 走本命令参数,"
        "objective 由主界面输入框首条消息提供。",
    )
    tui.add_argument("--scope", required=True, help="scope 授权范围文件路径")
    tui.add_argument("--workdir", default=None, help="engagement 目录(同 run)")
    _add_backend_args(tui)
    _add_loop_args(tui)
    return parser


# ---------------------------------------------------------------------------
# 装配(run/resume 共用;tui 亦可复用)
# ---------------------------------------------------------------------------


#: profile 中 backend 的合法值;其余值忽略并警告(配置文件可手编,读侧防线)。
_VALID_BACKENDS = ("openai_compat", "claude")

#: 启动可见性行的键序(与 config 模块白名单同序,只含非密钥三元组)。
_PROFILE_DISPLAY_KEYS = ("backend", "model", "base_url")

#: [config] 可见性行上 base_url 脱敏失败时的占位符(fail-closed:绝不原样上屏)。
_UNPARSEABLE_BASE_URL_PLACEHOLDER = "<无法解析,已脱敏>"


def _printable(text: str) -> str:
    """上屏用可打印过滤:非可打印字符一律转义(\\n、\\x1b 形态,2026-09-12 第三轮)。

    profile 名来自可手编的 config.json 或命令行,原样上屏会被控制字符
    利用(ANSI 染色、换行伪造 [config] 日志行);两条回显路径(--profile
    指定名与 active_profile 名)统一先过本函数。
    """
    return "".join(
        ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii")
        for ch in text
    )


def _select_profile(args: argparse.Namespace) -> tuple[str | None, dict | None]:
    """取本次生效的 (profile 名, profile):--profile 指定,否则 active_profile。

    配置文件全容错(load_config 口径):任何读取问题按「无 profile」处理,
    绝不阻断启动;--profile 指名却不存在时警告并按解析链继续。
    """
    config = load_config(Path.home())
    name = getattr(args, "profile", None)
    if name:
        profile = get_profile(config, name)
        if profile is None:
            print(
                f"[config] 警告:profile '{_printable(name)}' 不存在或为空"
                "(已忽略,按优先级链继续解析)",
                file=sys.stderr,
            )
            return None, None
        return name, profile
    active_name = config.get("active_profile")
    if isinstance(active_name, str) and active_name:
        profile = active_profile(config)
        if profile is not None:
            return active_name, profile
    return None, None


def resolve_backend_args(args: argparse.Namespace) -> None:
    """就地回填 args.backend/args.model/args.base_url(P1-1 冻结契约)。

    优先级(每键独立):CLI flag > 环境变量(FOAM_LLM_MODEL/FOAM_LLM_BASE_URL)
    > profile(--profile 指定,否则 active_profile)> 内置默认
    (k3/claude-sonnet-5)。backend 无 env 通道(维持现状);env base_url 对
    claude 同样生效(经本函数回填,P1-1 起的行为改进)。profile 中 backend
    非法值忽略并警告,其余键不受影响。profile 生效时打印一行启动可见性
    (只含非密钥三元组,base_url 过 sanitize_url 上屏副本脱敏,脱敏失败
    显示占位符;profile 名过 _printable 可打印过滤);无 profile 时零
    额外输出(回归底线)。
    """
    name, profile = _select_profile(args)
    if profile is not None:
        raw_backend = profile.get("backend")
        if raw_backend is not None and raw_backend not in _VALID_BACKENDS:
            print(
                f"[config] 警告:profile '{_printable(name)}' 的 backend 值"
                f"「{_printable(str(raw_backend))}」非法(仅支持 {'/'.join(_VALID_BACKENDS)},"
                "已忽略该键)",
                file=sys.stderr,
            )
            profile = {k: v for k, v in profile.items() if k != "backend"}
        if profile:
            # 上屏副本脱敏(Fix-2,2026-09-12 第三轮起 fail-closed):
            # config.json 可手编,base_url 即使混入 userinfo/敏感 query
            # 也不原样上屏;sanitize 解析不出(畸形且可能藏凭证)时显示
            # 占位符,绝不回原值。下方解析进 args 的仍是 profile 原值
            # (运行时不动)。profile 名过 _printable(防 ANSI/换行伪造
            # 日志行)。
            display = {}
            for key, value in profile.items():
                if key == "base_url":
                    try:
                        display[key] = sanitize_url(value)
                    except ValueError:
                        display[key] = _UNPARSEABLE_BASE_URL_PLACEHOLDER
                else:
                    display[key] = value
            details = " ".join(
                f"{key}={display[key]}"
                for key in _PROFILE_DISPLAY_KEYS
                if key in display
            )
            print(f"[config] profile '{_printable(name)}':{details}", flush=True)
        else:
            profile = None
    resolved = profile or {}

    # backend:flag > profile > 内置默认(无 env 通道,维持现状)。
    if args.backend is None:
        args.backend = resolved.get("backend") or "openai_compat"
    # model:flag > env > profile > 内置默认(按已解析的 backend 取)。
    if args.model is None:
        args.model = (
            os.environ.get(ENV_MODEL)
            or resolved.get("model")
            or (
                DEFAULT_CLAUDE_MODEL
                if args.backend == "claude"
                else DEFAULT_OPENAI_MODEL
            )
        )
    # base_url:flag > env > profile;无内置默认——openai_compat 缺失报错、
    # claude 退官方端点,两处兜底仍在 _build_backend。env 通道对 claude
    # 同样生效(经此处回填进 args.base_url;P1-1 起的行为改进,README
    # 已文档化)——这是与 P1-1 前「claude 不看 FOAM_LLM_BASE_URL」的行为差。
    if args.base_url is None:
        args.base_url = os.environ.get(ENV_BASE_URL) or resolved.get("base_url")


def _save_profile_if_requested(args: argparse.Namespace) -> None:
    """--save-profile:装配成功后落盘解析结果并设为 active(0600)。

    只在后端装配成功之后调用(坏配置不落盘)。profile 名先过
    validate_profile_name(Fix-1):非法抛 ConfigError——与装配失败同一条
    报错路径(stderr 中文报错 + 退出码 2);报错文案绝不回现名字本身
    (名字可能正是 key 值,回显即二次泄漏)。put_profile 白名单是红线
    防线——base_url 为 None 自动剔除,任何 key/token/secret 字样的键
    即使混入也绝不落盘;落盘副本的 base_url 过 sanitize_url(Fix-2:
    剥 userinfo、敏感 query 打码),args.base_url 运行时原值不动。
    2026-09-12 第三轮 fail-closed:sanitize_url 对畸形/含凭证却剥不出
    干净 host 的 base_url 抛 ValueError,在此转 ConfigError( stderr
    中文 + 退出码 2,文案不回显原 URL,且零落盘)。
    """
    name = getattr(args, "save_profile", None)
    if not name:
        return
    reason = validate_profile_name(name)
    if reason is not None:
        raise ConfigError(f"--save-profile 的 profile 名非法:{reason}")
    try:
        # 落盘副本脱敏(fail-closed):畸形/藏凭证的 base_url 抛 ValueError,
        # 绝不原样落盘(凭证串落盘即红线事故);put_profile 内还有一层。
        sanitized_base_url = sanitize_url(args.base_url) if args.base_url else None
        put_profile(
            Path.home(),
            name,
            {
                "backend": args.backend,
                "model": args.model,
                "base_url": sanitized_base_url,
            },
        )
    except ValueError as exc:
        # exc 为 config 模块的中文原因(不回显 URL);原 URL 绝不进报错文案。
        raise ConfigError(
            f"base_url 无法解析,为防凭证泄漏已拒绝保存 profile({exc})"
        ) from None
    print(
        f"[config] profile '{name}' 已保存并设为 active(下次启动自动生效)",
        flush=True,
    )


def _build_backend(args: argparse.Namespace) -> LLMBackend:
    """按参数构造后端;密钥由后端自己从 env 读取(缺失抛 ConfigError)。"""
    model = args.model or os.environ.get(ENV_MODEL)
    if args.backend == "claude":
        # args.base_url 已含 env 回填(resolve_backend_args):
        # FOAM_LLM_BASE_URL 对 claude 同样生效(P1-1 起的行为改进,
        # README 已文档化);都不给时退官方端点。
        return ClaudeBackend(
            model=model or DEFAULT_CLAUDE_MODEL,
            base_url=args.base_url or DEFAULT_BASE_URL,
        )
    base_url = args.base_url or os.environ.get(ENV_BASE_URL)
    if not base_url:
        raise ConfigError(
            f"openai_compat 需要 base url:--base-url 或环境变量 {ENV_BASE_URL}",
            provider="openai_compat",
        )
    return OpenAICompatBackend(base_url=base_url, model=model or DEFAULT_OPENAI_MODEL)


@dataclass
class _Runtime:
    """一次 run/resume 的装配产物(finally 里按序关停)。"""

    engagement: Engagement
    audit: AuditLog
    session: SessionTool
    state: StateTool
    loop: AgentLoop
    toolmap_line: str


def _assemble_runtime(
    args: argparse.Namespace,
    *,
    engagement: Engagement,
    scope: Scope,
    scope_source: str,
    backend: LLMBackend,
    observer: LoopObserver,
) -> _Runtime:
    """engagement 布局 + 三组工具 + 主环的一次性装配(WP-10 接线点①③)。"""
    audit = AuditLog(engagement.paths.audit_jsonl)
    audit.append(KIND_SCOPE_LOADED, scope_payload(scope, scope_source))
    bash = BashTool(engagement.paths.outputs)
    session = SessionTool(engagement.paths.outputs / "sessions")
    state = StateTool(engagement)
    registry = ToolRegistry()
    registry.register_module(BASH_TOOL_SCHEMAS, bash.dispatch)
    registry.register_module(SESSION_TOOL_SCHEMAS, session.dispatch)
    registry.register_module(STATE_TOOL_SCHEMAS, state.dispatch)
    loaded_at = datetime.now(UTC).isoformat(timespec="seconds")
    # WP-08 接线:启动盘点一次(~137 次 which,毫秒级),地图注入 prompt;
    # 阶段跟踪主环尚无,current_phase 一律 None(见 WP-08 日志接线节)。
    scan = scan_tools()
    system_prompt = build_system_prompt(
        scope,
        source=scope_source,
        loaded_at=loaded_at,
        workdir=engagement.paths.root,
        tool_map_text=render_tool_map(scan),
    )
    loop_kwargs: dict[str, Any] = {}
    if args.max_context_tokens is not None:
        loop_kwargs["max_context_tokens"] = args.max_context_tokens
    if args.first_event_timeout is not None:
        loop_kwargs["first_event_timeout"] = args.first_event_timeout
    loop = AgentLoop(
        backend=backend,
        bash=bash,
        scope=scope,
        audit=audit,
        workdir=engagement.paths.root,
        system_prompt=system_prompt,
        registry=registry,
        observer=observer,
        session=session,
        engagement=engagement,
        index=state.index,  # WP-11:解析层 facts 与 state 工具共用同一连接
        max_rounds=args.max_rounds,
        **loop_kwargs,
    )
    return _Runtime(
        engagement=engagement,
        audit=audit,
        session=session,
        state=state,
        loop=loop,
        toolmap_line=render_startup_line(scan),
    )


async def _drive(
    runtime: _Runtime,
    *,
    objective: str,
    backend: LLMBackend,
    interject: str | None = None,
) -> int:
    """驱动主环到底:SIGINT 两次语义、收尾关停、退出码映射。"""
    loop = runtime.loop
    if interject:
        loop.interject(interject)
    print(f"[{runtime.toolmap_line}]", flush=True)

    # Ctrl-C:第一次走 kill switch;第二次立即强制退出(审计每条已 flush,不丢)。
    running_loop = asyncio.get_running_loop()
    sigint_seen = False

    def _on_sigint() -> None:
        nonlocal sigint_seen
        if loop.status in ("finished", "error", "killed"):
            return
        if sigint_seen:
            os._exit(EXIT_KILLED)
        sigint_seen = True
        print(
            "\n[操作员] Ctrl-C:触发 kill switch(再按一次强制退出)",
            file=sys.stderr,
            flush=True,
        )
        loop.kill("操作员 Ctrl-C")

    running_loop.add_signal_handler(signal.SIGINT, _on_sigint)
    try:
        result: RunResult = await loop.run(objective)
    finally:
        running_loop.remove_signal_handler(signal.SIGINT)
        runtime.audit.close()
        runtime.state.close()
        runtime.engagement.close()
        # 会话关停幂等:kill 路径 loop 已 aclose,此处兜底 finished/error 路径。
        await runtime.session.aclose()
        await backend.aclose()

    if result.status == "finished":
        runtime.engagement.mark_closed()
    print(
        f"\n[run {result.status}] {result.rounds} 轮,"
        f"tokens 输入 {result.input_tokens} / 输出 {result.output_tokens}",
        flush=True,
    )
    if result.error:
        print(f"[error] {result.error}", file=sys.stderr)
    return {
        "finished": EXIT_OK,
        "killed": EXIT_KILLED,
        "error": EXIT_ERROR,
    }.get(result.status, EXIT_ERROR)


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def _create_engagement(args: argparse.Namespace) -> Engagement:
    """WP-10 接线点①:目录创建走 WP-06 Engagement.create(幂等复开)。"""
    if args.workdir:
        root = Path(args.workdir)
        return Engagement.create(
            base_dir=root.parent if str(root.parent) else Path("."),
            objective=args.objective,
            scope_path=args.scope,
            engagement_id=root.name,
        )
    return Engagement.create(objective=args.objective, scope_path=args.scope)


async def _cmd_run(args: argparse.Namespace, backend_factory: BackendFactory) -> int:
    resolve_backend_args(args)  # P1-1:flag > env > profile > 内置默认,就地回填
    try:
        scope = load_scope(args.scope)
    except (OSError, ValueError) as exc:
        print(f"[错误] scope 加载失败: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        backend = backend_factory(args)
        _save_profile_if_requested(args)  # 装配成功才落盘:坏配置/坏名不留痕
    except ConfigError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        engagement = _create_engagement(args)
    except (OSError, ValueError) as exc:
        print(f"[错误] engagement 目录创建失败: {exc}", file=sys.stderr)
        return EXIT_USAGE

    print(
        f"[run] engagement={engagement.paths.root} backend={args.backend}",
        flush=True,
    )
    print(
        f"[scope] {len(scope.rules)} 条规则已加载({args.scope});"
        "越界命令将被护栏拒绝并记审计",
        flush=True,
    )
    runtime = _assemble_runtime(
        args,
        engagement=engagement,
        scope=scope,
        scope_source=str(args.scope),
        backend=backend,
        observer=_CliObserver(),
    )
    return await _drive(runtime, objective=args.objective, backend=backend)


# ---------------------------------------------------------------------------
# resume
# ---------------------------------------------------------------------------


def _resolve_objective(
    args: argparse.Namespace, meta: dict[str, Any], records: list[dict[str, Any]]
) -> str | None:
    """objective 恢复顺序:--objective > engagement.json > 审计链 run_started。"""
    if args.objective:
        return args.objective
    if meta.get("objective"):
        return str(meta["objective"])
    return recover_objective(records)


def _resolve_scope(
    args: argparse.Namespace, meta: dict[str, Any], records: list[dict[str, Any]]
) -> tuple[Scope, str]:
    """scope 恢复:--scope > engagement.json(sha256 对账) > 审计链(摘要对账)。

    成功返回 (scope, source);失败抛 ValueError(调用方转明确报错)。
    """
    if args.scope:
        return load_scope(args.scope), str(args.scope)

    scope_meta = meta.get("scope")
    if scope_meta:
        path = Path(scope_meta["path"])
        if not path.is_file():
            raise ValueError(
                f"engagement.json 记录的 scope 文件不存在:{path};"
                "请用 --scope 显式指定(将重新记审计)"
            )
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != scope_meta.get("sha256"):
            raise ValueError(
                f"scope 文件 {path} 与 engagement.json 记录的 sha256 不符"
                "(文件已变更);如确为重新授权,请用 --scope 显式指定"
            )
        return load_scope(path), str(path)

    record = recover_scope_record(records)
    if record is None:
        raise ValueError(
            "无法确定 scope:无 engagement.json 记录且审计链无 scope_loaded;"
            "请用 --scope 显式指定"
        )
    path = Path(str(record.get("source") or ""))
    if not path.is_file():
        raise ValueError(f"审计链记录的 scope 文件不存在:{path};请用 --scope 显式指定")
    scope = load_scope(path)
    summary = scope.summary()
    mismatched = [
        key
        for key in ("cidrs", "hosts", "wildcards", "url_prefixes")
        if summary[key] != list(record.get(key) or [])
    ]
    if mismatched:
        raise ValueError(
            f"scope 文件 {path} 的解析结果与审计链记录不符(字段 {mismatched});"
            "如确为重新授权,请用 --scope 显式指定"
        )
    return scope, str(path)


def _resume_preflight(
    args: argparse.Namespace,
) -> tuple[Engagement, Scope, str, str, str, int] | int:
    """resume 的同步前置:目录/审计链校验、objective/scope 恢复、legacy 修复。

    成功返回 (engagement, scope, scope_source, objective, briefing, 历史记录数);
    失败打印明确报错并返回退出码(小文件 IO 集中在此同步函数,不进协程)。
    """
    root = Path(args.engagement_dir)
    if not root.is_dir():
        print(f"[错误] engagement 目录不存在:{root}", file=sys.stderr)
        return EXIT_USAGE
    audit_path = root / "audit.jsonl"
    if not audit_path.is_file():
        print(
            f"[错误] 缺 audit.jsonl:{root} 不是可恢复的 engagement 目录"
            "(审计链是 resume 的唯一可信史;缺它无法恢复)",
            file=sys.stderr,
        )
        return EXIT_USAGE

    problems = chain_errors(audit_path)
    if problems:
        brk = find_chain_break(audit_path)
        print(
            "[错误] 审计链校验未通过,拒绝 resume(完整性存疑的历史不能作为恢复基准):",
            file=sys.stderr,
        )
        print(f"  {brk.describe() if brk else problems[0]}", file=sys.stderr)
        print("  可用 `replay` 子命令查看断点前的记录。", file=sys.stderr)
        return EXIT_ERROR
    records = read_records(audit_path)

    meta: dict[str, Any] = {}
    metadata_path = root / "engagement.json"
    if metadata_path.is_file():
        try:
            meta = json.loads(metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"[错误] engagement.json 无法解析:{exc}", file=sys.stderr)
            return EXIT_USAGE

    objective = _resolve_objective(args, meta, records)
    if not objective:
        print(
            "[错误] 无法确定 objective(无 engagement.json 且审计链无 "
            "run_started);请用 --objective 显式给出",
            file=sys.stderr,
        )
        return EXIT_USAGE
    try:
        scope, scope_source = _resolve_scope(args, meta, records)
    except (OSError, ValueError) as exc:
        print(f"[错误] scope 恢复失败: {exc}", file=sys.stderr)
        return EXIT_USAGE

    # 目录完整性:有 engagement.json 严格校验;legacy 目录(无元数据)用恢复
    # 出的 objective/scope 走 create 幂等补齐布局(不动任何已有文件)。
    if metadata_path.is_file():
        engagement = Engagement.open(root)
        layout_problems = engagement.validate()
        if layout_problems:
            print(
                "[错误] engagement 目录不完整:" + ";".join(layout_problems),
                file=sys.stderr,
            )
            return EXIT_USAGE
    else:
        try:
            engagement = Engagement.create(
                base_dir=root.parent if str(root.parent) else Path("."),
                objective=objective,
                scope_path=scope_source,
                engagement_id=root.name,
            )
        except (OSError, ValueError) as exc:
            print(f"[错误] legacy 目录修复失败: {exc}", file=sys.stderr)
            return EXIT_USAGE

    briefing = build_resume_briefing(records, recent_rounds=args.recent_rounds)
    return engagement, scope, scope_source, objective, briefing, len(records)


async def _cmd_resume(args: argparse.Namespace, backend_factory: BackendFactory) -> int:
    resolve_backend_args(args)  # P1-1:与 run 同一条解析链,就地回填
    prepared = _resume_preflight(args)
    if isinstance(prepared, int):
        return prepared
    engagement, scope, scope_source, objective, briefing, record_count = prepared
    try:
        backend = backend_factory(args)
        _save_profile_if_requested(args)  # 装配成功才落盘:坏配置/坏名不留痕
    except ConfigError as exc:
        engagement.close()
        print(f"[错误] {exc}", file=sys.stderr)
        return EXIT_USAGE

    print(
        f"[resume] engagement={engagement.paths.root} backend={args.backend} "
        f"(历史 {record_count} 条审计记录,链完整;简报取最近 "
        f"{args.recent_rounds} 轮)",
        flush=True,
    )
    runtime = _assemble_runtime(
        args,
        engagement=engagement,
        scope=scope,
        scope_source=scope_source,
        backend=backend,
        observer=_CliObserver(),
    )
    return await _drive(
        runtime, objective=objective, backend=backend, interject=briefing
    )


# ---------------------------------------------------------------------------
# replay / report / tui
# ---------------------------------------------------------------------------


def _cmd_replay(args: argparse.Namespace) -> int:
    """先校验哈希链;链断报断点 seq 并中止,链完整才只读重放。"""
    root = Path(args.engagement_dir)
    if not root.is_dir():
        print(f"[错误] engagement 目录不存在:{root}", file=sys.stderr)
        return EXIT_USAGE
    audit_path = root / "audit.jsonl"
    if not audit_path.is_file():
        print(
            f"[错误] 缺 audit.jsonl:{root} 下没有审计链,无可回放内容",
            file=sys.stderr,
        )
        return EXIT_USAGE

    problems = chain_errors(audit_path)
    if problems:
        brk = find_chain_break(audit_path)
        print("[错误] 审计链校验未通过,中止回放:", file=sys.stderr)
        print(f"  {brk.describe() if brk else problems[0]}", file=sys.stderr)
        if len(problems) > 1:
            print(f"  (共 {len(problems)} 处问题,仅报首个断点)", file=sys.stderr)
        return EXIT_ERROR

    records = read_records(audit_path)
    print(f"[replay] {root}:审计链完整,{len(records)} 条记录,只读回放:")
    for line in format_timeline(records):
        print(line)
    return EXIT_OK


def _cmd_report(args: argparse.Namespace) -> int:
    root = Path(args.engagement_dir)
    if not root.is_dir():
        print(f"[错误] engagement 目录不存在:{root}", file=sys.stderr)
        return EXIT_USAGE
    text = build_report(root)
    if args.out:
        out_path = Path(args.out)
        try:
            out_path.write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"[错误] 报告写入失败: {exc}", file=sys.stderr)
            return EXIT_USAGE
        print(f"[report] 已写入 {out_path}(含凭证全值,按红线处理)", flush=True)
    else:
        print(text)
    return EXIT_OK


def _cmd_tui(args: argparse.Namespace) -> int:
    """TUI 入口接线(WP-09 定案):入口约定 foam.tui.app:main(args)。

    ImportError 兜底为合理防御(2026-09-11 注):TUI 已交付,此处失败意味
    textual 依赖缺失或安装损坏,按可行动指引报错。
    """
    try:
        from foam.tui.app import main as tui_main
    except ImportError:
        print(
            "[错误] TUI 模块不可导入:foam.tui.app 加载失败"
            "(textual 依赖缺失或安装损坏)。\n"
            "处置:重装本项目及其依赖(如 pip install --force-reinstall .),"
            "确认 textual 可导入后重试。\n"
            f"当前可用:`{__app_name__.lower()} run` 的 headless 模式。",
            file=sys.stderr,
        )
        return EXIT_USAGE
    # P1-1:同一解析链就地回填(app.py 零改动,经 args 自然生效)。
    resolve_backend_args(args)
    # Fix-4(坏配置不落盘):--save-profile 落盘前先 _build_backend 预检——
    # 构造即读 key env,ConfigError(缺 key/缺 base_url/坏 profile 名)在此
    # 提前暴露,与 run/resume 口径拉齐;预检成功才保存。该构造无副作用
    # (不发起网络,httpx 客户端首请求才建连),TUI 内装配会自行再构造;
    # 预检产物随即关停,不带进 TUI。
    try:
        preflight = _build_backend(args)
        _save_profile_if_requested(args)
    except ConfigError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return EXIT_USAGE
    asyncio.run(preflight.aclose())
    return int(tui_main(args))


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def main(
    argv: Sequence[str] | None = None, *, backend_factory: BackendFactory | None = None
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # P1-1:只读加载 ./.env(永不写它,红线)。只上屏键名,值绝不上屏;
    # 畸形行中文警告(带行号)走 stderr;文件不存在静默。
    injected, dotenv_warnings = load_dotenv(Path.cwd() / ".env")
    for warning in dotenv_warnings:
        print(f"[config] .env {warning}", file=sys.stderr)
    if injected:
        print(
            f"[config] .env 注入 {len(injected)} 个变量:{', '.join(injected)}",
            flush=True,
        )
    factory = backend_factory or _build_backend
    if args.command in ("run", "resume"):
        try:
            if args.command == "run":
                return asyncio.run(_cmd_run(args, factory))
            return asyncio.run(_cmd_resume(args, factory))
        except KeyboardInterrupt:
            return EXIT_KILLED
    if args.command == "replay":
        return _cmd_replay(args)
    if args.command == "report":
        return _cmd_report(args)
    if args.command == "tui":
        return _cmd_tui(args)
    parser.print_help()
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
