"""命令行入口(WP-10 闭环):run / resume / replay / report / tui。

职责:加载 scope → 建/开 engagement 目录(WP-06 布局)→ 装配 exec/会话/
状态三组工具(WP-01/05/06,经 ToolRegistry.register_module)→ 主环(WP-04)
跑完一个 objective;replay/report 只读审计链与索引库(实现见 replay.py)。

- resume:重建 system prompt + ENGAGEMENT.md(每轮必载机制)+ 最近 N 轮
  审计元信息简报(经 loop.interject 注入);明确不做全量对话回放恢复。
- replay:先校验哈希链(WP-02 语义),链断报断点 seq 并中止;完整才只读
  重放元信息时间线。
- report:中文 markdown(目标/范围/时间线/发现含证据/凭证全值/loot/插话)。
- tui:WP-09 在飞——占位接线,包未就绪给明确报错;入口约定
  ``foam.tui.app:main(args)``(args 含 --scope/--backend/--model/--base-url/
  --workdir;objective 由 TUI 主界面输入框首条消息提供,见 WP-09 定案 Q1)。

退出码:0 = finished/成功;130 = killed(含 Ctrl-C);1 = error(含审计链
校验未通过);2 = 参数/配置/前置条件错误(缺文件、TUI 未就绪等)。
密钥只走环境变量(各后端自己的 env key);本文件不接触 key 本体。

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
        default="openai_compat",
        help="LLM 后端(默认 openai_compat)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=f"模型 id(默认取 env {ENV_MODEL},再退内置默认:openai_compat="
        f"{DEFAULT_OPENAI_MODEL} / claude={DEFAULT_CLAUDE_MODEL})",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help=f"API base url(openai_compat 必填,可取 env {ENV_BASE_URL};"
        "claude 默认为官方端点)",
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
        help="全屏 TUI(WP-09 在飞;未就绪时给出明确报错)",
        description="TUI 入口(WP-09):scope/backend 走本命令参数,objective "
        "由主界面输入框首条消息提供。",
    )
    tui.add_argument("--scope", required=True, help="scope 授权范围文件路径")
    tui.add_argument("--workdir", default=None, help="engagement 目录(同 run)")
    _add_backend_args(tui)
    _add_loop_args(tui)
    return parser


# ---------------------------------------------------------------------------
# 装配(run/resume 共用;tui 就绪后也可复用)
# ---------------------------------------------------------------------------


def _build_backend(args: argparse.Namespace) -> LLMBackend:
    """按参数构造后端;密钥由后端自己从 env 读取(缺失抛 ConfigError)。"""
    model = args.model or os.environ.get(ENV_MODEL)
    if args.backend == "claude":
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
    try:
        scope = load_scope(args.scope)
    except (OSError, ValueError) as exc:
        print(f"[错误] scope 加载失败: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        backend = backend_factory(args)
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
    prepared = _resume_preflight(args)
    if isinstance(prepared, int):
        return prepared
    engagement, scope, scope_source, objective, briefing, record_count = prepared
    try:
        backend = backend_factory(args)
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
    """WP-09 占位接线:包未就绪给明确报错;入口约定 foam.tui.app:main(args)。"""
    try:
        from foam.tui.app import main as tui_main
    except ImportError:
        print(
            "[错误] TUI 尚未就绪:foam.tui.app 不存在(WP-09 在飞)。\n"
            "入口约定:foam.tui.app:main(args)——args 携带 --scope/--backend/"
            "--model/--base-url/--workdir 与 loop 参数;objective 由 TUI 主界面"
            "输入框首条消息提供(WP-09 定案 Q1)。\n"
            f"当前可用:`{__app_name__.lower()} run` 的 headless 模式。",
            file=sys.stderr,
        )
        return EXIT_USAGE
    return int(tui_main(args))


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def main(
    argv: Sequence[str] | None = None, *, backend_factory: BackendFactory | None = None
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
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
